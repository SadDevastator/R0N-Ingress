//! Configuration validation system.

use super::types::GatewayConfig;

/// A single validation error.
#[derive(Debug, Clone)]
pub struct ValidationError {
    /// The field path that failed validation.
    pub field: String,
    /// Error message.
    pub message: String,
    /// Severity level.
    pub severity: ValidationSeverity,
}

impl ValidationError {
    /// Create a new error.
    pub fn error(field: impl Into<String>, message: impl Into<String>) -> Self {
        Self {
            field: field.into(),
            message: message.into(),
            severity: ValidationSeverity::Error,
        }
    }

    /// Create a new warning.
    pub fn warning(field: impl Into<String>, message: impl Into<String>) -> Self {
        Self {
            field: field.into(),
            message: message.into(),
            severity: ValidationSeverity::Warning,
        }
    }
}

/// Severity of validation issues.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ValidationSeverity {
    /// Error - configuration is invalid.
    Error,
    /// Warning - configuration may have issues.
    Warning,
}

/// Result of configuration validation.
#[derive(Debug, Default)]
pub struct ValidationResult {
    errors: Vec<ValidationError>,
}

impl ValidationResult {
    /// Create a new empty (valid) result.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Add an error to the result.
    pub fn add_error(&mut self, error: ValidationError) {
        self.errors.push(error);
    }

    /// Check if the validation passed (no errors).
    #[must_use]
    pub fn is_valid(&self) -> bool {
        !self
            .errors
            .iter()
            .any(|e| e.severity == ValidationSeverity::Error)
    }

    /// Get all validation errors.
    #[must_use]
    pub fn errors(&self) -> &[ValidationError] {
        &self.errors
    }

    /// Get only errors (not warnings).
    #[must_use]
    pub fn errors_only(&self) -> Vec<&ValidationError> {
        self.errors
            .iter()
            .filter(|e| e.severity == ValidationSeverity::Error)
            .collect()
    }

    /// Get only warnings.
    #[must_use]
    pub fn warnings(&self) -> Vec<&ValidationError> {
        self.errors
            .iter()
            .filter(|e| e.severity == ValidationSeverity::Warning)
            .collect()
    }

    /// Merge another validation result into this one.
    pub fn merge(&mut self, other: ValidationResult) {
        self.errors.extend(other.errors);
    }
}

/// Trait for configuration validators.
pub trait Validator: std::fmt::Debug + Send + Sync {
    /// Validate a configuration and return any errors.
    fn validate(&self, config: &GatewayConfig) -> ValidationResult;
}

/// Built-in validator for basic configuration checks.
#[derive(Debug, Default)]
pub struct BasicValidator;

impl BasicValidator {
    /// Create a new basic validator.
    #[must_use]
    pub fn new() -> Self {
        Self
    }
}

impl Validator for BasicValidator {
    fn validate(&self, config: &GatewayConfig) -> ValidationResult {
        let mut result = ValidationResult::new();

        // Validate gateway name
        if config.gateway.name.is_empty() {
            result.add_error(ValidationError::error(
                "gateway.name",
                "Gateway name cannot be empty",
            ));
        }

        // Validate control port
        if config.gateway.control_port == 0 {
            result.add_error(ValidationError::error(
                "gateway.control_port",
                "Control port cannot be 0",
            ));
        }

        // Validate logging file path when output is file
        if config.logging.output == super::types::LogOutput::File
            && config.logging.file_path.is_none()
        {
            result.add_error(ValidationError::error(
                "logging.file_path",
                "File path is required when output is 'file'",
            ));
        }

        // Check for duplicate module names
        let mut seen_names = std::collections::HashSet::new();
        for module in &config.modules {
            if !seen_names.insert(&module.name) {
                result.add_error(ValidationError::error(
                    format!("modules.{}", module.name),
                    format!("Duplicate module name: {}", module.name),
                ));
            }

            // Validate module name
            if module.name.is_empty() {
                result.add_error(ValidationError::error(
                    "modules[].name",
                    "Module name cannot be empty",
                ));
            }

            // Validate module type
            if module.module_type.is_empty() {
                result.add_error(ValidationError::error(
                    format!("modules.{}.type", module.name),
                    "Module type cannot be empty",
                ));
            }
        }

        result
    }
}

/// Validator that checks for port conflicts.
#[derive(Debug, Default)]
pub struct PortConflictValidator;

impl PortConflictValidator {
    /// Create a new port conflict validator.
    #[must_use]
    pub fn new() -> Self {
        Self
    }
}

impl Validator for PortConflictValidator {
    fn validate(&self, config: &GatewayConfig) -> ValidationResult {
        let mut result = ValidationResult::new();
        let mut used_ports: std::collections::HashMap<u16, String> =
            std::collections::HashMap::new();

        // Add control port
        used_ports.insert(
            config.gateway.control_port,
            "gateway.control_port".to_string(),
        );

        // Check module ports (if they have port configs)
        for module in &config.modules {
            // Check for common port field names
            for port_field in &["port", "listen_port", "bind_port"] {
                if let Some(port_value) = module.config.get(*port_field) {
                    if let Some(port) = port_value.as_integer() {
                        if let Ok(port_u16) = u16::try_from(port) {
                            if let Some(existing) = used_ports.get(&port_u16) {
                                result.add_error(ValidationError::error(
                                    format!("modules.{}.config.{}", module.name, port_field),
                                    format!("Port {} conflicts with {}", port_u16, existing),
                                ));
                            } else {
                                used_ports.insert(
                                    port_u16,
                                    format!("modules.{}.config.{}", module.name, port_field),
                                );
                            }
                        }
                    }
                }
            }
        }

        result
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::ModuleEntry;

    #[test]
    fn test_basic_validator_valid() {
        let config = GatewayConfig::default();
        let validator = BasicValidator::new();
        let result = validator.validate(&config);
        assert!(result.is_valid());
    }

    #[test]
    fn test_basic_validator_empty_name() {
        let mut config = GatewayConfig::default();
        config.gateway.name = String::new();

        let validator = BasicValidator::new();
        let result = validator.validate(&config);

        assert!(!result.is_valid());
        assert!(result.errors()[0].message.contains("name cannot be empty"));
    }

    #[test]
    fn test_basic_validator_duplicate_modules() {
        let mut config = GatewayConfig::default();
        config.modules.push(ModuleEntry::new("test", "tcp-router"));
        config.modules.push(ModuleEntry::new("test", "udp-router"));

        let validator = BasicValidator::new();
        let result = validator.validate(&config);

        assert!(!result.is_valid());
        assert!(result.errors()[0].message.contains("Duplicate"));
    }

    #[test]
    fn test_port_conflict_validator() {
        let mut config = GatewayConfig::default();
        config.gateway.control_port = 8080;
        config
            .modules
            .push(ModuleEntry::new("router", "tcp-router").with_config("port", 8080i64));

        let validator = PortConflictValidator::new();
        let result = validator.validate(&config);

        assert!(!result.is_valid());
        assert!(result.errors()[0].message.contains("conflicts"));
    }

    #[test]
    fn test_validation_result_merge() {
        let mut result1 = ValidationResult::new();
        result1.add_error(ValidationError::error("field1", "error1"));

        let mut result2 = ValidationResult::new();
        result2.add_error(ValidationError::warning("field2", "warning1"));

        result1.merge(result2);
        assert_eq!(result1.errors().len(), 2);
    }
}
