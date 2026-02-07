//! WAF error types

use std::fmt;

/// WAF-specific errors
#[derive(Debug, Clone)]
pub enum WafError {
    /// Invalid configuration
    InvalidConfig(String),
    /// Invalid rule definition
    InvalidRule(String),
    /// Invalid regex pattern
    InvalidPattern(String),
    /// Rule compilation failed
    RuleCompilationFailed(String),
    /// Request blocked by WAF
    RequestBlocked {
        /// The ID of the rule that caused the block.
        rule_id: String,
        /// Description of why the request was blocked.
        message: String,
    },
    /// Detection error
    DetectionError(String),
    /// Logging error
    LoggingError(String),
    /// Internal error
    Internal(String),
}

impl fmt::Display for WafError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidConfig(msg) => write!(f, "Invalid WAF config: {}", msg),
            Self::InvalidRule(msg) => write!(f, "Invalid rule: {}", msg),
            Self::InvalidPattern(msg) => write!(f, "Invalid pattern: {}", msg),
            Self::RuleCompilationFailed(msg) => write!(f, "Rule compilation failed: {}", msg),
            Self::RequestBlocked { rule_id, message } => {
                write!(f, "Request blocked by rule {}: {}", rule_id, message)
            },
            Self::DetectionError(msg) => write!(f, "Detection error: {}", msg),
            Self::LoggingError(msg) => write!(f, "Logging error: {}", msg),
            Self::Internal(msg) => write!(f, "Internal WAF error: {}", msg),
        }
    }
}

impl std::error::Error for WafError {}

/// Result type for WAF operations
pub type WafResult<T> = Result<T, WafError>;

impl WafError {
    /// Check if the error should block the request
    pub fn should_block(&self) -> bool {
        matches!(self, Self::RequestBlocked { .. })
    }

    /// Check if the error is recoverable
    pub fn is_recoverable(&self) -> bool {
        matches!(
            self,
            Self::DetectionError(_) | Self::LoggingError(_) | Self::Internal(_)
        )
    }

    /// Get the rule ID if this is a blocked request
    pub fn rule_id(&self) -> Option<&str> {
        match self {
            Self::RequestBlocked { rule_id, .. } => Some(rule_id),
            _ => None,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_error_display() {
        let err = WafError::InvalidConfig("bad config".to_string());
        assert!(err.to_string().contains("bad config"));

        let err = WafError::RequestBlocked {
            rule_id: "SQL-001".to_string(),
            message: "SQL injection detected".to_string(),
        };
        assert!(err.to_string().contains("SQL-001"));
    }

    #[test]
    fn test_should_block() {
        let err = WafError::RequestBlocked {
            rule_id: "XSS-001".to_string(),
            message: "XSS detected".to_string(),
        };
        assert!(err.should_block());

        let err = WafError::DetectionError("error".to_string());
        assert!(!err.should_block());
    }

    #[test]
    fn test_is_recoverable() {
        assert!(WafError::DetectionError("err".to_string()).is_recoverable());
        assert!(WafError::LoggingError("err".to_string()).is_recoverable());
        assert!(!WafError::InvalidConfig("err".to_string()).is_recoverable());
    }

    #[test]
    fn test_rule_id() {
        let err = WafError::RequestBlocked {
            rule_id: "RULE-123".to_string(),
            message: "blocked".to_string(),
        };
        assert_eq!(err.rule_id(), Some("RULE-123"));

        let err = WafError::InvalidConfig("config".to_string());
        assert_eq!(err.rule_id(), None);
    }
}
