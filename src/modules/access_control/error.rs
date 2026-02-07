//! Error types for access control.

use std::fmt;

/// Result type for access control operations.
pub type AccessControlResult<T> = Result<T, AccessControlError>;

/// Errors that can occur during access control.
#[derive(Debug)]
pub enum AccessControlError {
    /// Invalid configuration.
    InvalidConfig(String),

    /// IP address parsing error.
    InvalidIpAddress(String),

    /// CIDR parsing error.
    InvalidCidr(String),

    /// Authentication failed.
    AuthenticationFailed(String),

    /// Authorization denied.
    AuthorizationDenied(String),

    /// Policy evaluation error.
    PolicyError(String),

    /// Provider connection error.
    ProviderError(String),

    /// Token validation error.
    TokenError(String),

    /// Internal error.
    Internal(String),
}

impl fmt::Display for AccessControlError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidConfig(msg) => write!(f, "invalid configuration: {msg}"),
            Self::InvalidIpAddress(ip) => write!(f, "invalid IP address: {ip}"),
            Self::InvalidCidr(cidr) => write!(f, "invalid CIDR notation: {cidr}"),
            Self::AuthenticationFailed(msg) => write!(f, "authentication failed: {msg}"),
            Self::AuthorizationDenied(msg) => write!(f, "authorization denied: {msg}"),
            Self::PolicyError(msg) => write!(f, "policy error: {msg}"),
            Self::ProviderError(msg) => write!(f, "provider error: {msg}"),
            Self::TokenError(msg) => write!(f, "token error: {msg}"),
            Self::Internal(msg) => write!(f, "internal error: {msg}"),
        }
    }
}

impl std::error::Error for AccessControlError {}

impl AccessControlError {
    /// Check if the error is recoverable.
    #[must_use]
    pub fn is_recoverable(&self) -> bool {
        matches!(self, Self::ProviderError(_) | Self::Internal(_))
    }

    /// Check if this is an authentication error.
    #[must_use]
    pub fn is_auth_error(&self) -> bool {
        matches!(self, Self::AuthenticationFailed(_) | Self::TokenError(_))
    }

    /// Check if this is an authorization error.
    #[must_use]
    pub fn is_authz_error(&self) -> bool {
        matches!(self, Self::AuthorizationDenied(_))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_error_display() {
        let err = AccessControlError::InvalidConfig("bad value".to_string());
        assert_eq!(err.to_string(), "invalid configuration: bad value");

        let err = AccessControlError::AuthenticationFailed("invalid token".to_string());
        assert_eq!(err.to_string(), "authentication failed: invalid token");

        let err = AccessControlError::InvalidCidr("not/valid".to_string());
        assert_eq!(err.to_string(), "invalid CIDR notation: not/valid");
    }

    #[test]
    fn test_is_recoverable() {
        assert!(AccessControlError::ProviderError("test".to_string()).is_recoverable());
        assert!(AccessControlError::Internal("test".to_string()).is_recoverable());
        assert!(!AccessControlError::AuthenticationFailed("test".to_string()).is_recoverable());
    }

    #[test]
    fn test_is_auth_error() {
        assert!(AccessControlError::AuthenticationFailed("test".to_string()).is_auth_error());
        assert!(AccessControlError::TokenError("test".to_string()).is_auth_error());
        assert!(!AccessControlError::AuthorizationDenied("test".to_string()).is_auth_error());
    }

    #[test]
    fn test_is_authz_error() {
        assert!(AccessControlError::AuthorizationDenied("test".to_string()).is_authz_error());
        assert!(!AccessControlError::AuthenticationFailed("test".to_string()).is_authz_error());
    }
}
