//! ACME error types

use std::fmt;
use std::io;

/// ACME-specific errors
#[derive(Debug)]
pub enum AcmeError {
    /// Configuration error
    Config(String),

    /// Account creation/retrieval failed
    Account(String),

    /// Order creation failed
    Order(String),

    /// Authorization failed
    Authorization(String),

    /// Challenge failed
    Challenge {
        /// Challenge type that failed
        challenge_type: String,
        /// Error message
        message: String,
    },

    /// Certificate request failed
    Certificate(String),

    /// HTTP request failed
    Http(String),

    /// JSON parsing/serialization error
    Json(String),

    /// Cryptographic operation failed
    Crypto(String),

    /// Rate limit exceeded
    RateLimited {
        /// When the rate limit resets
        retry_after: Option<u64>,
        /// Error message
        message: String,
    },

    /// Storage error
    Storage(String),

    /// I/O error
    Io(io::Error),

    /// Domain validation failed
    DomainValidation(String),

    /// Certificate expired
    CertificateExpired {
        /// Domain name
        domain: String,
        /// Expiry time
        expired_at: String,
    },

    /// Renewal failed
    RenewalFailed(String),

    /// Invalid response from ACME server
    InvalidResponse(String),

    /// Timeout waiting for challenge
    Timeout(String),

    /// Internal error
    Internal(String),
}

impl fmt::Display for AcmeError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Config(msg) => write!(f, "ACME config error: {}", msg),
            Self::Account(msg) => write!(f, "ACME account error: {}", msg),
            Self::Order(msg) => write!(f, "ACME order error: {}", msg),
            Self::Authorization(msg) => write!(f, "ACME authorization error: {}", msg),
            Self::Challenge {
                challenge_type,
                message,
            } => {
                write!(f, "ACME {} challenge failed: {}", challenge_type, message)
            },
            Self::Certificate(msg) => write!(f, "ACME certificate error: {}", msg),
            Self::Http(msg) => write!(f, "ACME HTTP error: {}", msg),
            Self::Json(msg) => write!(f, "ACME JSON error: {}", msg),
            Self::Crypto(msg) => write!(f, "ACME crypto error: {}", msg),
            Self::RateLimited {
                message,
                retry_after,
            } => {
                if let Some(secs) = retry_after {
                    write!(
                        f,
                        "ACME rate limited: {} (retry after {} secs)",
                        message, secs
                    )
                } else {
                    write!(f, "ACME rate limited: {}", message)
                }
            },
            Self::Storage(msg) => write!(f, "ACME storage error: {}", msg),
            Self::Io(e) => write!(f, "ACME I/O error: {}", e),
            Self::DomainValidation(msg) => write!(f, "Domain validation error: {}", msg),
            Self::CertificateExpired { domain, expired_at } => {
                write!(f, "Certificate for {} expired at {}", domain, expired_at)
            },
            Self::RenewalFailed(msg) => write!(f, "Certificate renewal failed: {}", msg),
            Self::InvalidResponse(msg) => write!(f, "Invalid ACME response: {}", msg),
            Self::Timeout(msg) => write!(f, "ACME timeout: {}", msg),
            Self::Internal(msg) => write!(f, "ACME internal error: {}", msg),
        }
    }
}

impl std::error::Error for AcmeError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Io(e) => Some(e),
            _ => None,
        }
    }
}

impl From<io::Error> for AcmeError {
    fn from(err: io::Error) -> Self {
        Self::Io(err)
    }
}

impl From<serde_json::Error> for AcmeError {
    fn from(err: serde_json::Error) -> Self {
        Self::Json(err.to_string())
    }
}

/// Result type for ACME operations
pub type AcmeResult<T> = Result<T, AcmeError>;

impl AcmeError {
    /// Check if this error is retryable
    pub fn is_retryable(&self) -> bool {
        matches!(
            self,
            Self::Http(_) | Self::RateLimited { .. } | Self::Timeout(_) | Self::Io(_)
        )
    }

    /// Check if this is a rate limit error
    pub fn is_rate_limited(&self) -> bool {
        matches!(self, Self::RateLimited { .. })
    }

    /// Get retry-after seconds if rate limited
    pub fn retry_after(&self) -> Option<u64> {
        match self {
            Self::RateLimited { retry_after, .. } => *retry_after,
            _ => None,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_error_display() {
        let err = AcmeError::Config("invalid directory URL".to_string());
        assert!(err.to_string().contains("config error"));
        assert!(err.to_string().contains("invalid directory URL"));
    }

    #[test]
    fn test_challenge_error() {
        let err = AcmeError::Challenge {
            challenge_type: "http-01".to_string(),
            message: "connection refused".to_string(),
        };
        let msg = err.to_string();
        assert!(msg.contains("http-01"));
        assert!(msg.contains("connection refused"));
    }

    #[test]
    fn test_rate_limited_error() {
        let err = AcmeError::RateLimited {
            retry_after: Some(3600),
            message: "too many requests".to_string(),
        };
        assert!(err.is_rate_limited());
        assert!(err.is_retryable());
        assert_eq!(err.retry_after(), Some(3600));
    }

    #[test]
    fn test_io_error_conversion() {
        let io_err = io::Error::new(io::ErrorKind::NotFound, "file not found");
        let acme_err: AcmeError = io_err.into();
        assert!(matches!(acme_err, AcmeError::Io(_)));
        assert!(acme_err.is_retryable());
    }

    #[test]
    fn test_non_retryable_errors() {
        let err = AcmeError::Config("bad config".to_string());
        assert!(!err.is_retryable());

        let err = AcmeError::DomainValidation("invalid domain".to_string());
        assert!(!err.is_retryable());
    }
}
