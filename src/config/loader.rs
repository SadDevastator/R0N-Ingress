//! Configuration file loader.

use super::error::{ConfigError, ConfigResult};
use super::types::GatewayConfig;
use super::validation::Validator;
use std::path::Path;

/// Configuration loader with validation support.
#[derive(Debug, Default)]
pub struct ConfigLoader {
    /// Validators to run on loaded configuration.
    validators: Vec<Box<dyn Validator>>,
}

impl ConfigLoader {
    /// Create a new configuration loader.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Add a validator to the loader.
    #[must_use]
    pub fn with_validator<V: Validator + 'static>(mut self, validator: V) -> Self {
        self.validators.push(Box::new(validator));
        self
    }

    /// Load configuration from a file path.
    ///
    /// # Errors
    ///
    /// Returns an error if:
    /// - The file does not exist
    /// - The file cannot be read
    /// - The TOML is malformed
    /// - Validation fails
    pub fn load<P: AsRef<Path>>(&self, path: P) -> ConfigResult<GatewayConfig> {
        let path = path.as_ref();

        if !path.exists() {
            return Err(ConfigError::NotFound(path.to_path_buf()));
        }

        let content = std::fs::read_to_string(path).map_err(|e| ConfigError::ReadError {
            path: path.to_path_buf(),
            source: e,
        })?;

        self.load_str(&content)
    }

    /// Load configuration from a TOML string.
    ///
    /// # Errors
    ///
    /// Returns an error if:
    /// - The TOML is malformed
    /// - Validation fails
    pub fn load_str(&self, content: &str) -> ConfigResult<GatewayConfig> {
        let config: GatewayConfig = toml::from_str(content)?;
        self.validate(&config)?;
        Ok(config)
    }

    /// Validate a configuration against all registered validators.
    fn validate(&self, config: &GatewayConfig) -> ConfigResult<()> {
        for validator in &self.validators {
            let result = validator.validate(config);
            if !result.is_valid() {
                let errors: Vec<String> =
                    result.errors().iter().map(|e| e.message.clone()).collect();
                return Err(ConfigError::ValidationError(errors.join("; ")));
            }
        }
        Ok(())
    }

    /// Load configuration or return default if file doesn't exist.
    ///
    /// # Errors
    ///
    /// Returns an error if the file exists but cannot be read or parsed.
    pub fn load_or_default<P: AsRef<Path>>(&self, path: P) -> ConfigResult<GatewayConfig> {
        let path = path.as_ref();
        if path.exists() {
            self.load(path)
        } else {
            Ok(GatewayConfig::default())
        }
    }

    /// Save configuration to a file.
    ///
    /// # Errors
    ///
    /// Returns an error if serialization or writing fails.
    pub fn save<P: AsRef<Path>>(&self, config: &GatewayConfig, path: P) -> ConfigResult<()> {
        let path = path.as_ref();
        let content = toml::to_string_pretty(config)?;
        std::fs::write(path, content).map_err(|e| ConfigError::ReadError {
            path: path.to_path_buf(),
            source: e,
        })?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::tempdir;

    #[test]
    fn test_load_from_string() {
        let loader = ConfigLoader::new();
        let config = loader
            .load_str(
                r#"
            [gateway]
            name = "test"
        "#,
            )
            .unwrap();
        assert_eq!(config.gateway.name, "test");
    }

    #[test]
    fn test_load_from_file() {
        let dir = tempdir().unwrap();
        let config_path = dir.path().join("config.toml");

        std::fs::write(
            &config_path,
            r#"
            [gateway]
            name = "file-test"
        "#,
        )
        .unwrap();

        let loader = ConfigLoader::new();
        let config = loader.load(&config_path).unwrap();
        assert_eq!(config.gateway.name, "file-test");
    }

    #[test]
    fn test_load_nonexistent_file() {
        let loader = ConfigLoader::new();
        let result = loader.load("/nonexistent/path/config.toml");
        assert!(matches!(result, Err(ConfigError::NotFound(_))));
    }

    #[test]
    fn test_load_or_default() {
        let loader = ConfigLoader::new();
        let config = loader.load_or_default("/nonexistent/path").unwrap();
        assert_eq!(config.gateway.name, "r0n-gateway");
    }

    #[test]
    fn test_save_and_load() {
        let dir = tempdir().unwrap();
        let config_path = dir.path().join("saved.toml");

        let mut config = GatewayConfig::default();
        config.gateway.name = "saved-gateway".to_string();

        let loader = ConfigLoader::new();
        loader.save(&config, &config_path).unwrap();

        let loaded = loader.load(&config_path).unwrap();
        assert_eq!(loaded.gateway.name, "saved-gateway");
    }
}
