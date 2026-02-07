//! JSON Schema generation for configuration.
//!
//! Generates JSON Schema from Rust types for IDE autocompletion
//! and configuration validation.

use serde::{Deserialize, Serialize};
use std::collections::HashMap;

/// Schema type enumeration.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum SchemaType {
    /// String type.
    String,
    /// Integer type.
    Integer,
    /// Number (float) type.
    Number,
    /// Boolean type.
    Boolean,
    /// Array type.
    Array,
    /// Object type.
    Object,
    /// Null type.
    Null,
}

/// A field in a configuration schema.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SchemaField {
    /// Field name.
    pub name: String,
    /// Field type.
    #[serde(rename = "type")]
    pub field_type: SchemaType,
    /// Field description.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub description: Option<String>,
    /// Whether the field is required.
    #[serde(default)]
    pub required: bool,
    /// Default value (as JSON).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub default: Option<serde_json::Value>,
    /// Allowed values (enum).
    #[serde(skip_serializing_if = "Option::is_none", rename = "enum")]
    pub enum_values: Option<Vec<String>>,
    /// Minimum value (for numbers).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub minimum: Option<f64>,
    /// Maximum value (for numbers).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub maximum: Option<f64>,
    /// Nested fields (for objects).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub properties: Option<Vec<SchemaField>>,
    /// Array item type.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub items: Option<Box<SchemaField>>,
}

impl SchemaField {
    /// Create a new string field.
    #[must_use]
    pub fn string(name: &str) -> Self {
        Self {
            name: name.to_string(),
            field_type: SchemaType::String,
            description: None,
            required: false,
            default: None,
            enum_values: None,
            minimum: None,
            maximum: None,
            properties: None,
            items: None,
        }
    }

    /// Create a new integer field.
    #[must_use]
    pub fn integer(name: &str) -> Self {
        Self {
            name: name.to_string(),
            field_type: SchemaType::Integer,
            description: None,
            required: false,
            default: None,
            enum_values: None,
            minimum: None,
            maximum: None,
            properties: None,
            items: None,
        }
    }

    /// Create a new boolean field.
    #[must_use]
    pub fn boolean(name: &str) -> Self {
        Self {
            name: name.to_string(),
            field_type: SchemaType::Boolean,
            description: None,
            required: false,
            default: None,
            enum_values: None,
            minimum: None,
            maximum: None,
            properties: None,
            items: None,
        }
    }

    /// Create a new object field.
    #[must_use]
    pub fn object(name: &str) -> Self {
        Self {
            name: name.to_string(),
            field_type: SchemaType::Object,
            description: None,
            required: false,
            default: None,
            enum_values: None,
            minimum: None,
            maximum: None,
            properties: Some(Vec::new()),
            items: None,
        }
    }

    /// Create a new array field.
    #[must_use]
    pub fn array(name: &str, item_type: SchemaField) -> Self {
        Self {
            name: name.to_string(),
            field_type: SchemaType::Array,
            description: None,
            required: false,
            default: None,
            enum_values: None,
            minimum: None,
            maximum: None,
            properties: None,
            items: Some(Box::new(item_type)),
        }
    }

    /// Set the description.
    #[must_use]
    pub fn with_description(mut self, description: &str) -> Self {
        self.description = Some(description.to_string());
        self
    }

    /// Mark as required.
    #[must_use]
    pub fn required(mut self) -> Self {
        self.required = true;
        self
    }

    /// Set the default value.
    #[must_use]
    pub fn with_default(mut self, default: serde_json::Value) -> Self {
        self.default = Some(default);
        self
    }

    /// Set enum values.
    #[must_use]
    pub fn with_enum(mut self, values: Vec<&str>) -> Self {
        self.enum_values = Some(values.into_iter().map(String::from).collect());
        self
    }

    /// Set minimum value.
    #[must_use]
    pub fn with_minimum(mut self, min: f64) -> Self {
        self.minimum = Some(min);
        self
    }

    /// Set maximum value.
    #[must_use]
    pub fn with_maximum(mut self, max: f64) -> Self {
        self.maximum = Some(max);
        self
    }

    /// Add a nested property (for objects).
    #[must_use]
    pub fn with_property(mut self, field: SchemaField) -> Self {
        if let Some(ref mut props) = self.properties {
            props.push(field);
        }
        self
    }
}

/// Configuration schema for a module.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ConfigSchema {
    /// Schema title.
    pub title: String,
    /// Schema description.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub description: Option<String>,
    /// Schema version.
    pub version: String,
    /// Root fields.
    pub fields: Vec<SchemaField>,
}

impl ConfigSchema {
    /// Create a new schema.
    #[must_use]
    pub fn new(title: &str, version: &str) -> Self {
        Self {
            title: title.to_string(),
            description: None,
            version: version.to_string(),
            fields: Vec::new(),
        }
    }

    /// Set the description.
    #[must_use]
    pub fn with_description(mut self, description: &str) -> Self {
        self.description = Some(description.to_string());
        self
    }

    /// Add a field to the schema.
    #[must_use]
    pub fn with_field(mut self, field: SchemaField) -> Self {
        self.fields.push(field);
        self
    }

    /// Convert to JSON Schema format.
    #[must_use]
    pub fn to_json_schema(&self) -> serde_json::Value {
        let mut properties_map = serde_json::Map::new();
        let mut required_vec = Vec::new();

        for field in &self.fields {
            properties_map.insert(field.name.clone(), self.field_to_json_schema(field));
            if field.required {
                required_vec.push(serde_json::json!(field.name));
            }
        }

        let mut schema = serde_json::json!({
            "$schema": "http://json-schema.org/draft-07/schema#",
            "title": self.title,
            "type": "object",
            "properties": properties_map,
            "required": required_vec
        });

        if let Some(ref desc) = self.description {
            schema["description"] = serde_json::json!(desc);
        }

        schema
    }

    fn field_to_json_schema(&self, field: &SchemaField) -> serde_json::Value {
        let mut schema = serde_json::json!({
            "type": field.field_type
        });

        if let Some(ref desc) = field.description {
            schema["description"] = serde_json::json!(desc);
        }

        if let Some(ref default) = field.default {
            schema["default"] = default.clone();
        }

        if let Some(ref enum_values) = field.enum_values {
            schema["enum"] = serde_json::json!(enum_values);
        }

        if let Some(min) = field.minimum {
            schema["minimum"] = serde_json::json!(min);
        }

        if let Some(max) = field.maximum {
            schema["maximum"] = serde_json::json!(max);
        }

        if let Some(ref properties) = field.properties {
            let mut props_map = HashMap::new();
            let mut req_fields = Vec::new();
            for prop in properties {
                props_map.insert(prop.name.clone(), self.field_to_json_schema(prop));
                if prop.required {
                    req_fields.push(prop.name.clone());
                }
            }
            schema["properties"] = serde_json::json!(props_map);
            if !req_fields.is_empty() {
                schema["required"] = serde_json::json!(req_fields);
            }
        }

        if let Some(ref items) = field.items {
            schema["items"] = self.field_to_json_schema(items);
        }

        schema
    }

    /// Generate schema for the gateway configuration.
    #[must_use]
    pub fn gateway_schema() -> Self {
        Self::new("R0N Gateway Configuration", "1.0.0")
            .with_description("Configuration schema for R0N Gateway")
            .with_field(
                SchemaField::object("gateway")
                    .with_description("Gateway identity and binding configuration")
                    .required()
                    .with_property(
                        SchemaField::string("name")
                            .with_description("Gateway instance name")
                            .with_default(serde_json::json!("r0n-gateway")),
                    )
                    .with_property(
                        SchemaField::string("bind_address")
                            .with_description("Bind address for control socket")
                            .with_default(serde_json::json!("127.0.0.1")),
                    )
                    .with_property(
                        SchemaField::integer("control_port")
                            .with_description("Control port for metrics and health")
                            .with_default(serde_json::json!(9000))
                            .with_minimum(1.0)
                            .with_maximum(65535.0),
                    ),
            )
            .with_field(
                SchemaField::object("logging")
                    .with_description("Logging configuration")
                    .with_property(
                        SchemaField::string("level")
                            .with_description("Log level")
                            .with_enum(vec!["trace", "debug", "info", "warn", "error"])
                            .with_default(serde_json::json!("info")),
                    )
                    .with_property(
                        SchemaField::string("format")
                            .with_description("Log format")
                            .with_enum(vec!["json", "pretty", "compact"])
                            .with_default(serde_json::json!("pretty")),
                    ),
            )
            .with_field(
                SchemaField::object("metrics")
                    .with_description("Metrics configuration")
                    .with_property(
                        SchemaField::boolean("enabled")
                            .with_description("Enable Prometheus metrics endpoint")
                            .with_default(serde_json::json!(true)),
                    )
                    .with_property(
                        SchemaField::string("path")
                            .with_description("Metrics endpoint path")
                            .with_default(serde_json::json!("/metrics")),
                    ),
            )
            .with_field(
                SchemaField::array(
                    "modules",
                    SchemaField::object("module")
                        .with_property(SchemaField::string("name").required())
                        .with_property(SchemaField::string("type").required())
                        .with_property(
                            SchemaField::boolean("enabled").with_default(serde_json::json!(true)),
                        )
                        .with_property(SchemaField::object("config")),
                )
                .with_description("Module configurations"),
            )
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_schema_field_string() {
        let field = SchemaField::string("test")
            .with_description("A test field")
            .required();

        assert_eq!(field.name, "test");
        assert_eq!(field.field_type, SchemaType::String);
        assert!(field.required);
    }

    #[test]
    fn test_schema_field_integer_with_range() {
        let field = SchemaField::integer("port")
            .with_minimum(1.0)
            .with_maximum(65535.0);

        assert_eq!(field.minimum, Some(1.0));
        assert_eq!(field.maximum, Some(65535.0));
    }

    #[test]
    fn test_config_schema_to_json() {
        let schema = ConfigSchema::new("Test", "1.0.0")
            .with_field(SchemaField::string("name").required())
            .with_field(SchemaField::integer("port"));

        let json = schema.to_json_schema();
        assert_eq!(json["title"], "Test");
        assert!(json["properties"]["name"].is_object());
        assert_eq!(json["required"], serde_json::json!(["name"]));
    }

    #[test]
    fn test_gateway_schema_generation() {
        let schema = ConfigSchema::gateway_schema();
        let json = schema.to_json_schema();

        assert_eq!(json["title"], "R0N Gateway Configuration");
        assert!(json["properties"]["gateway"].is_object());
        assert!(json["properties"]["logging"].is_object());
        assert!(json["properties"]["modules"].is_object());
    }
}
