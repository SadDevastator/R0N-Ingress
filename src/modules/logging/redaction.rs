//! Sensitive data redaction

use super::config::RedactionConfig;
use super::error::LogResult;
use regex::Regex;
use std::collections::HashSet;
use std::sync::Arc;

/// Redactor for sensitive data
pub struct Redactor {
    /// Configuration
    config: RedactionConfig,

    /// Compiled field patterns (lowercased for matching)
    fields: HashSet<String>,

    /// Compiled regex patterns
    patterns: Vec<Regex>,
}

impl Redactor {
    /// Create a new redactor from configuration
    pub fn new(config: RedactionConfig) -> LogResult<Self> {
        let fields: HashSet<String> = if config.case_insensitive {
            config.fields.iter().map(|f| f.to_lowercase()).collect()
        } else {
            config.fields.iter().cloned().collect()
        };

        let patterns: Vec<Regex> = config
            .patterns
            .iter()
            .filter_map(|p| {
                if config.case_insensitive {
                    Regex::new(&format!("(?i){}", p)).ok()
                } else {
                    Regex::new(p).ok()
                }
            })
            .collect();

        Ok(Self {
            config,
            fields,
            patterns,
        })
    }

    /// Create a disabled redactor
    pub fn disabled() -> Self {
        Self {
            config: RedactionConfig::none(),
            fields: HashSet::new(),
            patterns: Vec::new(),
        }
    }

    /// Check if redaction is enabled
    pub fn is_enabled(&self) -> bool {
        self.config.enabled
    }

    /// Check if a field name should be redacted
    pub fn should_redact_field(&self, field: &str) -> bool {
        if !self.config.enabled {
            return false;
        }

        let check_field = if self.config.case_insensitive {
            field.to_lowercase()
        } else {
            field.to_string()
        };

        self.fields.contains(&check_field)
    }

    /// Redact a value if it matches sensitive patterns
    pub fn redact_value(&self, value: &str) -> String {
        if !self.config.enabled {
            return value.to_string();
        }

        let mut result = value.to_string();

        for pattern in &self.patterns {
            result = pattern
                .replace_all(&result, &self.config.replacement)
                .to_string();
        }

        result
    }

    /// Redact a key-value pair
    pub fn redact_pair(&self, key: &str, value: &str) -> String {
        if !self.config.enabled {
            return value.to_string();
        }

        // Check if field name is sensitive
        if self.should_redact_field(key) {
            return self.config.replacement.clone();
        }

        // Check value patterns
        self.redact_value(value)
    }

    /// Redact a JSON value recursively
    pub fn redact_json(&self, value: &mut serde_json::Value) {
        if !self.config.enabled {
            return;
        }

        match value {
            serde_json::Value::Object(map) => {
                for (key, val) in map.iter_mut() {
                    if self.should_redact_field(key) {
                        *val = serde_json::Value::String(self.config.replacement.clone());
                    } else {
                        self.redact_json(val);
                    }
                }
            },
            serde_json::Value::Array(arr) => {
                for item in arr.iter_mut() {
                    self.redact_json(item);
                }
            },
            serde_json::Value::String(s) => {
                *s = self.redact_value(s);
            },
            _ => {},
        }
    }

    /// Get the replacement string
    pub fn replacement(&self) -> &str {
        &self.config.replacement
    }
}

impl std::fmt::Debug for Redactor {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Redactor")
            .field("enabled", &self.config.enabled)
            .field("fields_count", &self.fields.len())
            .field("patterns_count", &self.patterns.len())
            .finish()
    }
}

/// Shared redactor for use across threads
pub type SharedRedactor = Arc<Redactor>;

/// Create a shared redactor
pub fn create_shared_redactor(config: RedactionConfig) -> LogResult<SharedRedactor> {
    Ok(Arc::new(Redactor::new(config)?))
}

/// Redaction helper for strings
pub trait RedactExt {
    /// Redact sensitive data using the given redactor
    fn redact(&self, redactor: &Redactor) -> String;
}

impl RedactExt for str {
    fn redact(&self, redactor: &Redactor) -> String {
        redactor.redact_value(self)
    }
}

impl RedactExt for String {
    fn redact(&self, redactor: &Redactor) -> String {
        redactor.redact_value(self)
    }
}

/// Mask a string value (show first/last n characters)
pub fn mask_value(value: &str, visible_start: usize, visible_end: usize) -> String {
    if value.len() <= visible_start + visible_end {
        return "*".repeat(value.len());
    }

    let start = &value[..visible_start];
    let end = &value[value.len() - visible_end..];
    let middle_len = value.len() - visible_start - visible_end;

    format!("{}{}{}", start, "*".repeat(middle_len), end)
}

/// Mask an email address
pub fn mask_email(email: &str) -> String {
    if let Some(at_pos) = email.find('@') {
        let local = &email[..at_pos];
        let domain = &email[at_pos..];

        if local.len() <= 2 {
            format!("{}***{}", &local[..1], domain)
        } else {
            format!("{}***{}", &local[..2], domain)
        }
    } else {
        mask_value(email, 2, 0)
    }
}

/// Mask a credit card number
pub fn mask_credit_card(card: &str) -> String {
    // Remove spaces and dashes
    let digits: String = card.chars().filter(|c| c.is_ascii_digit()).collect();

    if digits.len() < 12 {
        return "*".repeat(digits.len());
    }

    // Show last 4 digits
    let visible = &digits[digits.len() - 4..];
    format!("****-****-****-{}", visible)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn create_test_redactor() -> Redactor {
        Redactor::new(RedactionConfig::default()).unwrap()
    }

    #[test]
    fn test_redactor_creation() {
        let redactor = create_test_redactor();
        assert!(redactor.is_enabled());
    }

    #[test]
    fn test_disabled_redactor() {
        let redactor = Redactor::disabled();
        assert!(!redactor.is_enabled());
        assert!(!redactor.should_redact_field("password"));
    }

    #[test]
    fn test_field_redaction() {
        let redactor = create_test_redactor();

        assert!(redactor.should_redact_field("password"));
        assert!(redactor.should_redact_field("PASSWORD"));
        assert!(redactor.should_redact_field("api_key"));
        assert!(redactor.should_redact_field("token"));
        assert!(!redactor.should_redact_field("username"));
        assert!(!redactor.should_redact_field("email"));
    }

    #[test]
    fn test_value_redaction() {
        let redactor = create_test_redactor();

        // Credit card pattern
        let result = redactor.redact_value("Card: 1234-5678-9012-3456");
        assert!(result.contains("[REDACTED]"));
        assert!(!result.contains("1234"));

        // SSN pattern
        let result = redactor.redact_value("SSN: 123-45-6789");
        assert!(result.contains("[REDACTED]"));
    }

    #[test]
    fn test_bearer_token_redaction() {
        let redactor = create_test_redactor();

        let result = redactor.redact_value(
            "Authorization: Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.payload.signature",
        );
        assert!(result.contains("[REDACTED]"));
        assert!(!result.contains("eyJ"));
    }

    #[test]
    fn test_basic_auth_redaction() {
        let redactor = create_test_redactor();

        let result = redactor.redact_value("Authorization: Basic dXNlcjpwYXNz");
        assert!(result.contains("[REDACTED]"));
    }

    #[test]
    fn test_pair_redaction() {
        let redactor = create_test_redactor();

        // Sensitive field name
        let result = redactor.redact_pair("password", "secret123");
        assert_eq!(result, "[REDACTED]");

        // Non-sensitive field, sensitive value
        let result = redactor.redact_pair("data", "Card: 1234-5678-9012-3456");
        assert!(result.contains("[REDACTED]"));

        // Non-sensitive field and value
        let result = redactor.redact_pair("name", "John Doe");
        assert_eq!(result, "John Doe");
    }

    #[test]
    fn test_json_redaction() {
        let redactor = create_test_redactor();

        let mut json = serde_json::json!({
            "username": "john",
            "password": "secret123",
            "data": {
                "token": "abc123",
                "email": "john@example.com"
            }
        });

        redactor.redact_json(&mut json);

        assert_eq!(json["username"], "john");
        assert_eq!(json["password"], "[REDACTED]");
        assert_eq!(json["data"]["token"], "[REDACTED]");
        assert_eq!(json["data"]["email"], "john@example.com");
    }

    #[test]
    fn test_mask_value() {
        assert_eq!(mask_value("1234567890", 2, 2), "12******90");
        assert_eq!(mask_value("abc", 1, 1), "a*c");
        assert_eq!(mask_value("ab", 2, 2), "**");
    }

    #[test]
    fn test_mask_email() {
        assert_eq!(mask_email("john@example.com"), "jo***@example.com");
        assert_eq!(mask_email("a@example.com"), "a***@example.com");
    }

    #[test]
    fn test_mask_credit_card() {
        assert_eq!(
            mask_credit_card("1234-5678-9012-3456"),
            "****-****-****-3456"
        );
        assert_eq!(mask_credit_card("1234567890123456"), "****-****-****-3456");
    }

    #[test]
    fn test_redact_ext_trait() {
        let redactor = create_test_redactor();

        let value = "Bearer abc123";
        let redacted = value.redact(&redactor);
        assert!(redacted.contains("[REDACTED]"));
    }

    #[test]
    fn test_custom_replacement() {
        let config = RedactionConfig {
            replacement: "***HIDDEN***".to_string(),
            ..Default::default()
        };
        let redactor = Redactor::new(config).unwrap();

        let result = redactor.redact_pair("password", "secret");
        assert_eq!(result, "***HIDDEN***");
    }
}
