//! Module configuration types.

use std::collections::HashMap;

/// Configuration for a module.
///
/// This is a flexible configuration structure that can hold
/// arbitrary key-value pairs from TOML configuration.
#[derive(Debug, Clone, Default)]
pub struct ModuleConfig {
    /// Raw configuration values.
    values: HashMap<String, ConfigValue>,

    /// Raw TOML string (if available).
    raw: Option<String>,
}

/// A configuration value that can be various types.
#[derive(Debug, Clone)]
#[allow(dead_code)] // Part of public API, will be used by TOML parser
pub enum ConfigValue {
    /// String value.
    String(String),

    /// Integer value.
    Integer(i64),

    /// Floating point value.
    Float(f64),

    /// Boolean value.
    Bool(bool),

    /// Array of values.
    Array(Vec<ConfigValue>),

    /// Nested table/map.
    Table(HashMap<String, ConfigValue>),
}

impl ModuleConfig {
    /// Creates a new empty configuration.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Sets a string value.
    pub fn set_string(&mut self, key: impl Into<String>, value: impl Into<String>) {
        self.values
            .insert(key.into(), ConfigValue::String(value.into()));
    }

    /// Sets an integer value.
    pub fn set_integer(&mut self, key: impl Into<String>, value: i64) {
        self.values.insert(key.into(), ConfigValue::Integer(value));
    }

    /// Sets a boolean value.
    pub fn set_bool(&mut self, key: impl Into<String>, value: bool) {
        self.values.insert(key.into(), ConfigValue::Bool(value));
    }

    /// Gets a string value.
    #[must_use]
    pub fn get_string(&self, key: &str) -> Option<&str> {
        match self.values.get(key) {
            Some(ConfigValue::String(s)) => Some(s.as_str()),
            _ => None,
        }
    }

    /// Gets an integer value.
    #[must_use]
    pub fn get_integer(&self, key: &str) -> Option<i64> {
        match self.values.get(key) {
            Some(ConfigValue::Integer(i)) => Some(*i),
            _ => None,
        }
    }

    /// Gets a boolean value.
    #[must_use]
    pub fn get_bool(&self, key: &str) -> Option<bool> {
        match self.values.get(key) {
            Some(ConfigValue::Bool(b)) => Some(*b),
            _ => None,
        }
    }

    /// Checks if a key exists.
    #[must_use]
    pub fn contains_key(&self, key: &str) -> bool {
        self.values.contains_key(key)
    }

    /// Returns the number of configuration entries.
    #[must_use]
    pub fn len(&self) -> usize {
        self.values.len()
    }

    /// Returns `true` if the configuration is empty.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.values.is_empty()
    }

    /// Creates a ModuleConfig from a raw TOML string.
    #[must_use]
    pub fn from_raw(raw: String) -> Self {
        Self {
            values: HashMap::new(),
            raw: Some(raw),
        }
    }

    /// Gets the raw configuration string.
    #[must_use]
    pub fn raw_config(&self) -> Option<&str> {
        self.raw.as_deref()
    }
}
