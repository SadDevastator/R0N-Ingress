//! Kubernetes integration errors

use std::fmt;

/// Kubernetes integration error type
#[derive(Debug, Clone)]
pub enum K8sError {
    /// API server connection error
    ApiConnectionError(String),

    /// Authentication error
    AuthenticationError(String),

    /// Authorization error (RBAC)
    AuthorizationError(String),

    /// Resource not found
    NotFound {
        /// Resource kind
        kind: String,
        /// Resource name
        name: String,
        /// Namespace (if applicable)
        namespace: Option<String>,
    },

    /// Resource already exists
    AlreadyExists {
        /// Resource kind
        kind: String,
        /// Resource name
        name: String,
    },

    /// Invalid resource
    InvalidResource(String),

    /// Watch error
    WatchError(String),

    /// Serialization error
    SerializationError(String),

    /// Configuration error
    ConfigError(String),

    /// Namespace error
    NamespaceError(String),

    /// Secret decoding error
    SecretDecodeError(String),

    /// ConfigMap error
    ConfigMapError(String),

    /// Ingress error
    IngressError(String),

    /// Service error
    ServiceError(String),

    /// Endpoint error
    EndpointError(String),

    /// Timeout error
    Timeout(String),

    /// Rate limited
    RateLimited {
        /// Retry after (seconds)
        retry_after: Option<u64>,
    },

    /// Conflict (optimistic locking)
    Conflict(String),

    /// Internal error
    Internal(String),

    /// I/O error
    Io(String),
}

impl K8sError {
    /// Check if error is retryable
    pub fn is_retryable(&self) -> bool {
        matches!(
            self,
            Self::ApiConnectionError(_)
                | Self::Timeout(_)
                | Self::RateLimited { .. }
                | Self::WatchError(_)
        )
    }

    /// Check if error is a not found error
    pub fn is_not_found(&self) -> bool {
        matches!(self, Self::NotFound { .. })
    }

    /// Check if error is an auth error
    pub fn is_auth_error(&self) -> bool {
        matches!(
            self,
            Self::AuthenticationError(_) | Self::AuthorizationError(_)
        )
    }

    /// Get retry delay for rate limited errors
    pub fn retry_after(&self) -> Option<u64> {
        if let Self::RateLimited { retry_after } = self {
            *retry_after
        } else {
            None
        }
    }
}

impl fmt::Display for K8sError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::ApiConnectionError(msg) => write!(f, "API connection error: {}", msg),
            Self::AuthenticationError(msg) => write!(f, "authentication error: {}", msg),
            Self::AuthorizationError(msg) => write!(f, "authorization error: {}", msg),
            Self::NotFound {
                kind,
                name,
                namespace,
            } => {
                if let Some(ns) = namespace {
                    write!(f, "{} '{}' not found in namespace '{}'", kind, name, ns)
                } else {
                    write!(f, "{} '{}' not found", kind, name)
                }
            },
            Self::AlreadyExists { kind, name } => {
                write!(f, "{} '{}' already exists", kind, name)
            },
            Self::InvalidResource(msg) => write!(f, "invalid resource: {}", msg),
            Self::WatchError(msg) => write!(f, "watch error: {}", msg),
            Self::SerializationError(msg) => write!(f, "serialization error: {}", msg),
            Self::ConfigError(msg) => write!(f, "configuration error: {}", msg),
            Self::NamespaceError(msg) => write!(f, "namespace error: {}", msg),
            Self::SecretDecodeError(msg) => write!(f, "secret decode error: {}", msg),
            Self::ConfigMapError(msg) => write!(f, "configmap error: {}", msg),
            Self::IngressError(msg) => write!(f, "ingress error: {}", msg),
            Self::ServiceError(msg) => write!(f, "service error: {}", msg),
            Self::EndpointError(msg) => write!(f, "endpoint error: {}", msg),
            Self::Timeout(msg) => write!(f, "timeout: {}", msg),
            Self::RateLimited { retry_after } => {
                if let Some(secs) = retry_after {
                    write!(f, "rate limited, retry after {} seconds", secs)
                } else {
                    write!(f, "rate limited")
                }
            },
            Self::Conflict(msg) => write!(f, "conflict: {}", msg),
            Self::Internal(msg) => write!(f, "internal error: {}", msg),
            Self::Io(msg) => write!(f, "I/O error: {}", msg),
        }
    }
}

impl std::error::Error for K8sError {}

impl From<std::io::Error> for K8sError {
    fn from(err: std::io::Error) -> Self {
        Self::Io(err.to_string())
    }
}

/// Kubernetes result type
pub type K8sResult<T> = Result<T, K8sError>;

/// HTTP status code mapping to K8sError
impl K8sError {
    /// Create error from HTTP status code
    pub fn from_status_code(code: u16, message: String) -> Self {
        match code {
            401 => Self::AuthenticationError(message),
            403 => Self::AuthorizationError(message),
            404 => Self::NotFound {
                kind: "Resource".to_string(),
                name: message,
                namespace: None,
            },
            409 => Self::Conflict(message),
            429 => Self::RateLimited { retry_after: None },
            500..=599 => Self::ApiConnectionError(message),
            _ => Self::Internal(format!("HTTP {}: {}", code, message)),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_error_display() {
        let err = K8sError::NotFound {
            kind: "Service".to_string(),
            name: "my-service".to_string(),
            namespace: Some("default".to_string()),
        };
        assert_eq!(
            err.to_string(),
            "Service 'my-service' not found in namespace 'default'"
        );
    }

    #[test]
    fn test_error_retryable() {
        assert!(K8sError::Timeout("test".to_string()).is_retryable());
        assert!(K8sError::RateLimited {
            retry_after: Some(5)
        }
        .is_retryable());
        assert!(!K8sError::NotFound {
            kind: "Pod".to_string(),
            name: "test".to_string(),
            namespace: None,
        }
        .is_retryable());
    }

    #[test]
    fn test_error_from_status_code() {
        assert!(K8sError::from_status_code(401, "unauthorized".to_string()).is_auth_error());
        assert!(K8sError::from_status_code(404, "not found".to_string()).is_not_found());
    }

    #[test]
    fn test_rate_limited_retry_after() {
        let err = K8sError::RateLimited {
            retry_after: Some(30),
        };
        assert_eq!(err.retry_after(), Some(30));
    }
}
