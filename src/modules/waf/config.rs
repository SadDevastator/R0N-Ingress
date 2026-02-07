//! WAF configuration types

use serde::{Deserialize, Serialize};
use std::collections::HashMap;

/// Main WAF configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WafConfig {
    /// Whether WAF is enabled
    #[serde(default = "default_enabled")]
    pub enabled: bool,

    /// Detection mode
    #[serde(default)]
    pub mode: DetectionMode,

    /// Rule configurations
    #[serde(default)]
    pub rules: Vec<WafRuleConfig>,

    /// Built-in detector settings
    #[serde(default)]
    pub detectors: DetectorConfig,

    /// Bypass rules
    #[serde(default)]
    pub bypass_rules: Vec<BypassRule>,

    /// Threat logging configuration
    #[serde(default)]
    pub logging: ThreatLogConfig,

    /// Per-route overrides
    #[serde(default)]
    pub route_overrides: HashMap<String, RouteWafConfig>,

    /// Maximum request body size to inspect (bytes)
    #[serde(default = "default_max_body_size")]
    pub max_body_size: usize,

    /// Request body inspection enabled
    #[serde(default = "default_true")]
    pub inspect_body: bool,

    /// Response body inspection enabled
    #[serde(default)]
    pub inspect_response: bool,
}

fn default_enabled() -> bool {
    true
}

fn default_true() -> bool {
    true
}

fn default_max_body_size() -> usize {
    1024 * 1024 // 1MB
}

impl Default for WafConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            mode: DetectionMode::default(),
            rules: Vec::new(),
            detectors: DetectorConfig::default(),
            bypass_rules: Vec::new(),
            logging: ThreatLogConfig::default(),
            route_overrides: HashMap::new(),
            max_body_size: default_max_body_size(),
            inspect_body: true,
            inspect_response: false,
        }
    }
}

/// Detection mode for the WAF
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum DetectionMode {
    /// Block malicious requests
    #[default]
    Block,
    /// Detect and log but don't block
    Detect,
    /// Log only, for debugging
    Log,
}

impl DetectionMode {
    /// Check if this mode should block requests
    pub fn should_block(&self) -> bool {
        matches!(self, Self::Block)
    }

    /// Check if this mode should log threats
    pub fn should_log(&self) -> bool {
        matches!(self, Self::Block | Self::Detect | Self::Log)
    }
}

/// Configuration for a WAF rule
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WafRuleConfig {
    /// Unique rule identifier
    pub id: String,

    /// Rule description
    #[serde(default)]
    pub description: String,

    /// Whether the rule is enabled
    #[serde(default = "default_true")]
    pub enabled: bool,

    /// Rule severity
    #[serde(default)]
    pub severity: RuleSeverity,

    /// Action to take when rule matches
    #[serde(default)]
    pub action: RuleAction,

    /// Pattern to match (regex)
    pub pattern: String,

    /// Targets to scan
    #[serde(default)]
    pub targets: Vec<String>,

    /// Transformations to apply before matching
    #[serde(default)]
    pub transforms: Vec<String>,

    /// Tags for categorization
    #[serde(default)]
    pub tags: Vec<String>,

    /// Score to add to anomaly counter (for scoring mode)
    #[serde(default)]
    pub score: u32,
}

/// Rule severity level
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum RuleSeverity {
    /// Low severity - informational
    Low,
    /// Medium severity - potential threat
    #[default]
    Medium,
    /// High severity - likely attack
    High,
    /// Critical severity - confirmed attack
    Critical,
}

impl RuleSeverity {
    /// Get numeric value for scoring
    pub fn score(&self) -> u32 {
        match self {
            Self::Low => 1,
            Self::Medium => 3,
            Self::High => 5,
            Self::Critical => 10,
        }
    }

    /// Get display name
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Low => "low",
            Self::Medium => "medium",
            Self::High => "high",
            Self::Critical => "critical",
        }
    }
}

/// Action to take when a rule matches
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum RuleAction {
    /// Block the request
    #[default]
    Block,
    /// Allow but log
    Log,
    /// Add to anomaly score
    Score,
    /// Pass without action
    Pass,
    /// Redirect to another URL
    Redirect,
    /// Drop connection immediately
    Drop,
}

impl RuleAction {
    /// Check if this action blocks the request
    pub fn is_blocking(&self) -> bool {
        matches!(self, Self::Block | Self::Drop)
    }
}

/// Built-in detector configuration
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct DetectorConfig {
    /// SQL injection detection
    #[serde(default)]
    pub sql_injection: SqlInjectionConfig,

    /// XSS detection
    #[serde(default)]
    pub xss: XssConfig,

    /// Path traversal detection
    #[serde(default)]
    pub path_traversal: PathTraversalConfig,

    /// Protocol attack detection
    #[serde(default)]
    pub protocol_attack: ProtocolAttackConfig,

    /// Request smuggling detection
    #[serde(default)]
    pub request_smuggling: RequestSmugglingConfig,
}

/// SQL injection detector configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SqlInjectionConfig {
    /// Whether enabled
    #[serde(default = "default_true")]
    pub enabled: bool,

    /// Sensitivity level (1-5)
    #[serde(default = "default_sensitivity")]
    pub sensitivity: u8,

    /// Scan query parameters
    #[serde(default = "default_true")]
    pub scan_query: bool,

    /// Scan request body
    #[serde(default = "default_true")]
    pub scan_body: bool,

    /// Scan cookies
    #[serde(default = "default_true")]
    pub scan_cookies: bool,

    /// Scan headers
    #[serde(default)]
    pub scan_headers: bool,
}

fn default_sensitivity() -> u8 {
    3
}

impl Default for SqlInjectionConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            sensitivity: 3,
            scan_query: true,
            scan_body: true,
            scan_cookies: true,
            scan_headers: false,
        }
    }
}

/// XSS detector configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct XssConfig {
    /// Whether enabled
    #[serde(default = "default_true")]
    pub enabled: bool,

    /// Sensitivity level (1-5)
    #[serde(default = "default_sensitivity")]
    pub sensitivity: u8,

    /// Scan query parameters
    #[serde(default = "default_true")]
    pub scan_query: bool,

    /// Scan request body
    #[serde(default = "default_true")]
    pub scan_body: bool,

    /// Scan cookies
    #[serde(default)]
    pub scan_cookies: bool,

    /// Block inline JavaScript
    #[serde(default = "default_true")]
    pub block_inline_js: bool,

    /// Block event handlers
    #[serde(default = "default_true")]
    pub block_event_handlers: bool,
}

impl Default for XssConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            sensitivity: 3,
            scan_query: true,
            scan_body: true,
            scan_cookies: false,
            block_inline_js: true,
            block_event_handlers: true,
        }
    }
}

/// Path traversal detector configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PathTraversalConfig {
    /// Whether enabled
    #[serde(default = "default_true")]
    pub enabled: bool,

    /// Block encoded traversal attempts
    #[serde(default = "default_true")]
    pub block_encoded: bool,

    /// Block null byte injections
    #[serde(default = "default_true")]
    pub block_null_bytes: bool,

    /// Allowed file extensions (empty = all blocked)
    #[serde(default)]
    pub allowed_extensions: Vec<String>,

    /// Maximum path depth
    #[serde(default = "default_max_path_depth")]
    pub max_path_depth: usize,
}

fn default_max_path_depth() -> usize {
    10
}

impl Default for PathTraversalConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            block_encoded: true,
            block_null_bytes: true,
            allowed_extensions: Vec::new(),
            max_path_depth: 10,
        }
    }
}

/// Protocol attack detector configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProtocolAttackConfig {
    /// Whether enabled
    #[serde(default = "default_true")]
    pub enabled: bool,

    /// Block HTTP response splitting
    #[serde(default = "default_true")]
    pub block_response_splitting: bool,

    /// Block header injection
    #[serde(default = "default_true")]
    pub block_header_injection: bool,
}

impl Default for ProtocolAttackConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            block_response_splitting: true,
            block_header_injection: true,
        }
    }
}

/// Request smuggling detector configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RequestSmugglingConfig {
    /// Whether enabled
    #[serde(default = "default_true")]
    pub enabled: bool,

    /// Strict Content-Length validation
    #[serde(default = "default_true")]
    pub strict_content_length: bool,

    /// Block ambiguous requests
    #[serde(default = "default_true")]
    pub block_ambiguous: bool,
}

impl Default for RequestSmugglingConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            strict_content_length: true,
            block_ambiguous: true,
        }
    }
}

/// Bypass rule configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BypassRule {
    /// Rule identifier
    pub id: String,

    /// Description
    #[serde(default)]
    pub description: String,

    /// Conditions that must match
    pub conditions: Vec<BypassCondition>,

    /// Rules to bypass (empty = all rules)
    #[serde(default)]
    pub bypass_rules: Vec<String>,

    /// Whether enabled
    #[serde(default = "default_true")]
    pub enabled: bool,
}

/// Condition for a bypass rule
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BypassCondition {
    /// Field to check
    pub field: BypassField,

    /// Operator
    pub operator: BypassOperator,

    /// Value to compare
    pub value: String,
}

/// Field for bypass condition
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum BypassField {
    /// Source IP address
    SourceIp,
    /// Request path
    Path,
    /// HTTP method
    Method,
    /// Request header
    Header,
    /// User agent
    UserAgent,
    /// Content type
    ContentType,
}

/// Operator for bypass condition
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum BypassOperator {
    /// Exact match
    Equals,
    /// Not equal
    NotEquals,
    /// Contains substring
    Contains,
    /// Does not contain
    NotContains,
    /// Regex match
    Matches,
    /// Starts with
    StartsWith,
    /// Ends with
    EndsWith,
    /// IP in CIDR range
    InCidr,
}

/// Threat logging configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ThreatLogConfig {
    /// Whether logging is enabled
    #[serde(default = "default_true")]
    pub enabled: bool,

    /// Log file path
    #[serde(default)]
    pub file_path: Option<String>,

    /// Log format
    #[serde(default)]
    pub format: LogFormat,

    /// Include request body in logs
    #[serde(default)]
    pub include_body: bool,

    /// Include response in logs
    #[serde(default)]
    pub include_response: bool,

    /// Maximum entries to keep in memory
    #[serde(default = "default_max_entries")]
    pub max_entries: usize,

    /// Alert on critical threats
    #[serde(default = "default_true")]
    pub alert_on_critical: bool,

    /// Alert webhook URL
    #[serde(default)]
    pub alert_webhook: Option<String>,
}

fn default_max_entries() -> usize {
    10000
}

impl Default for ThreatLogConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            file_path: None,
            format: LogFormat::default(),
            include_body: false,
            include_response: false,
            max_entries: 10000,
            alert_on_critical: true,
            alert_webhook: None,
        }
    }
}

/// Log format
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum LogFormat {
    /// JSON format
    #[default]
    Json,
    /// Common Log Format
    Clf,
    /// Extended Log Format
    Elf,
}

/// Per-route WAF configuration override
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct RouteWafConfig {
    /// Override enabled status
    #[serde(default)]
    pub enabled: Option<bool>,

    /// Override detection mode
    #[serde(default)]
    pub mode: Option<DetectionMode>,

    /// Additional rules for this route
    #[serde(default)]
    pub additional_rules: Vec<String>,

    /// Rules to disable for this route
    #[serde(default)]
    pub disabled_rules: Vec<String>,

    /// Override body inspection
    #[serde(default)]
    pub inspect_body: Option<bool>,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_default_config() {
        let config = WafConfig::default();
        assert!(config.enabled);
        assert_eq!(config.mode, DetectionMode::Block);
        assert!(config.inspect_body);
        assert!(!config.inspect_response);
        assert_eq!(config.max_body_size, 1024 * 1024);
    }

    #[test]
    fn test_detection_mode() {
        assert!(DetectionMode::Block.should_block());
        assert!(!DetectionMode::Detect.should_block());
        assert!(!DetectionMode::Log.should_block());

        assert!(DetectionMode::Block.should_log());
        assert!(DetectionMode::Detect.should_log());
        assert!(DetectionMode::Log.should_log());
    }

    #[test]
    fn test_rule_severity() {
        assert_eq!(RuleSeverity::Low.score(), 1);
        assert_eq!(RuleSeverity::Medium.score(), 3);
        assert_eq!(RuleSeverity::High.score(), 5);
        assert_eq!(RuleSeverity::Critical.score(), 10);

        assert!(RuleSeverity::Critical > RuleSeverity::High);
        assert!(RuleSeverity::High > RuleSeverity::Medium);
    }

    #[test]
    fn test_rule_action() {
        assert!(RuleAction::Block.is_blocking());
        assert!(RuleAction::Drop.is_blocking());
        assert!(!RuleAction::Log.is_blocking());
        assert!(!RuleAction::Score.is_blocking());
    }

    #[test]
    fn test_detector_config_defaults() {
        let config = DetectorConfig::default();
        assert!(config.sql_injection.enabled);
        assert!(config.xss.enabled);
        assert!(config.path_traversal.enabled);
        assert_eq!(config.sql_injection.sensitivity, 3);
    }

    #[test]
    fn test_bypass_rule() {
        let bypass = BypassRule {
            id: "bypass-1".to_string(),
            description: "Bypass for internal IPs".to_string(),
            conditions: vec![BypassCondition {
                field: BypassField::SourceIp,
                operator: BypassOperator::InCidr,
                value: "10.0.0.0/8".to_string(),
            }],
            bypass_rules: vec![],
            enabled: true,
        };

        assert!(bypass.enabled);
        assert_eq!(bypass.conditions.len(), 1);
    }

    #[test]
    fn test_threat_log_config() {
        let config = ThreatLogConfig::default();
        assert!(config.enabled);
        assert!(!config.include_body);
        assert!(config.alert_on_critical);
        assert_eq!(config.max_entries, 10000);
    }

    #[test]
    fn test_config_serialization() {
        let config = WafConfig::default();
        let json = serde_json::to_string(&config).unwrap();
        let parsed: WafConfig = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed.enabled, config.enabled);
        assert_eq!(parsed.mode, config.mode);
    }
}
