//! WAF rule engine for request scanning

use super::config::{
    BypassCondition, BypassField, BypassOperator, BypassRule, DetectionMode, DetectorConfig,
    RuleAction, WafConfig,
};
use super::detector::{
    DetectionResult, Detector, PathTraversalDetector, SqlInjectionDetector, XssDetector,
};
use super::error::WafResult;
use super::rules::{RuleCategory, RuleSet, RuleTarget};
use std::borrow::Cow;
use std::collections::{HashMap, HashSet};
use std::net::IpAddr;

/// Context for scanning a request
#[derive(Debug, Clone, Default)]
pub struct ScanContext {
    /// Source IP address
    pub source_ip: Option<IpAddr>,

    /// HTTP method
    pub method: String,

    /// Request URI/path
    pub uri: String,

    /// Query string (raw)
    pub query_string: Option<String>,

    /// Query parameters
    pub query_params: HashMap<String, String>,

    /// Request headers
    pub headers: HashMap<String, String>,

    /// Cookies
    pub cookies: HashMap<String, String>,

    /// Request body (if available)
    pub body: Option<String>,

    /// Content type
    pub content_type: Option<String>,

    /// Form fields (parsed from body)
    pub form_fields: HashMap<String, String>,

    /// Route/path being accessed
    pub route: Option<String>,
}

impl ScanContext {
    /// Create new scan context
    pub fn new() -> Self {
        Self::default()
    }

    /// Builder: set source IP
    pub fn with_source_ip(mut self, ip: IpAddr) -> Self {
        self.source_ip = Some(ip);
        self
    }

    /// Builder: set method
    pub fn with_method(mut self, method: impl Into<String>) -> Self {
        self.method = method.into();
        self
    }

    /// Builder: set URI
    pub fn with_uri(mut self, uri: impl Into<String>) -> Self {
        self.uri = uri.into();
        self
    }

    /// Builder: set query string
    pub fn with_query_string(mut self, qs: impl Into<String>) -> Self {
        self.query_string = Some(qs.into());
        self
    }

    /// Builder: add query parameter
    pub fn with_query_param(mut self, key: impl Into<String>, value: impl Into<String>) -> Self {
        self.query_params.insert(key.into(), value.into());
        self
    }

    /// Builder: add header
    pub fn with_header(mut self, key: impl Into<String>, value: impl Into<String>) -> Self {
        self.headers.insert(key.into().to_lowercase(), value.into());
        self
    }

    /// Builder: add cookie
    pub fn with_cookie(mut self, name: impl Into<String>, value: impl Into<String>) -> Self {
        self.cookies.insert(name.into(), value.into());
        self
    }

    /// Builder: set body
    pub fn with_body(mut self, body: impl Into<String>) -> Self {
        self.body = Some(body.into());
        self
    }

    /// Builder: set content type
    pub fn with_content_type(mut self, ct: impl Into<String>) -> Self {
        self.content_type = Some(ct.into());
        self
    }

    /// Builder: add form field
    pub fn with_form_field(mut self, name: impl Into<String>, value: impl Into<String>) -> Self {
        self.form_fields.insert(name.into(), value.into());
        self
    }

    /// Get value for a target (zero-copy where possible via `Cow`)
    pub fn get_target_value(&self, target: &RuleTarget) -> Option<Cow<'_, str>> {
        match target {
            RuleTarget::Uri => Some(Cow::Borrowed(&self.uri)),
            RuleTarget::QueryString => self.query_string.as_deref().map(Cow::Borrowed),
            RuleTarget::QueryParam(name) => self
                .query_params
                .get(name)
                .map(|v| Cow::Borrowed(v.as_str())),
            RuleTarget::QueryParams => {
                if self.query_params.is_empty() {
                    None
                } else {
                    Some(Cow::Owned(
                        self.query_params
                            .values()
                            .map(String::as_str)
                            .collect::<Vec<_>>()
                            .join(" "),
                    ))
                }
            },
            RuleTarget::Body => self.body.as_deref().map(Cow::Borrowed),
            RuleTarget::FormField(name) => self
                .form_fields
                .get(name)
                .map(|v| Cow::Borrowed(v.as_str())),
            RuleTarget::FormFields => {
                if self.form_fields.is_empty() {
                    None
                } else {
                    Some(Cow::Owned(
                        self.form_fields
                            .values()
                            .map(String::as_str)
                            .collect::<Vec<_>>()
                            .join(" "),
                    ))
                }
            },
            RuleTarget::JsonPath(_path) => {
                // JSON path evaluation would go here
                // For now, return the whole body
                self.body.as_deref().map(Cow::Borrowed)
            },
            RuleTarget::Header(name) => self
                .headers
                .get(&name.to_lowercase())
                .map(|v| Cow::Borrowed(v.as_str())),
            RuleTarget::Headers => {
                if self.headers.is_empty() {
                    None
                } else {
                    Some(Cow::Owned(
                        self.headers
                            .values()
                            .map(String::as_str)
                            .collect::<Vec<_>>()
                            .join(" "),
                    ))
                }
            },
            RuleTarget::Cookie(name) => self.cookies.get(name).map(|v| Cow::Borrowed(v.as_str())),
            RuleTarget::Cookies => {
                if self.cookies.is_empty() {
                    None
                } else {
                    Some(Cow::Owned(
                        self.cookies
                            .values()
                            .map(String::as_str)
                            .collect::<Vec<_>>()
                            .join(" "),
                    ))
                }
            },
            RuleTarget::Method => Some(Cow::Borrowed(&self.method)),
            RuleTarget::RequestLine => Some(Cow::Owned(format!("{} {}", self.method, self.uri))),
            RuleTarget::UserAgent => self
                .headers
                .get("user-agent")
                .map(|v| Cow::Borrowed(v.as_str())),
            RuleTarget::ContentType => self.content_type.as_deref().map(Cow::Borrowed),
            RuleTarget::Referer => self
                .headers
                .get("referer")
                .map(|v| Cow::Borrowed(v.as_str())),
        }
    }

    /// Iterate all scannable values without allocating.
    ///
    /// Calls `f(key, value)` for every field in the context.
    /// Returns early with `Err` if the callback returns `Err`.
    fn for_each_value<E>(&self, mut f: impl FnMut(&str, &str) -> Result<(), E>) -> Result<(), E> {
        f("uri", &self.uri)?;
        f("method", &self.method)?;

        if let Some(qs) = &self.query_string {
            f("query_string", qs)?;
        }

        for (k, v) in &self.query_params {
            f(k, v)?;
        }

        for (k, v) in &self.headers {
            f(k, v)?;
        }

        for (k, v) in &self.cookies {
            f(k, v)?;
        }

        if let Some(body) = &self.body {
            f("body", body)?;
        }

        for (k, v) in &self.form_fields {
            f(k, v)?;
        }

        Ok(())
    }
}

/// Match result from a rule
#[derive(Debug, Clone)]
pub struct RuleMatch {
    /// Rule ID
    pub rule_id: String,

    /// Rule description
    pub description: String,

    /// Category
    pub category: RuleCategory,

    /// Severity score
    pub score: u32,

    /// Action
    pub action: RuleAction,

    /// Matched target
    pub target: String,

    /// Matched value
    pub matched_value: String,
}

/// Result of scanning a request
#[derive(Debug, Clone)]
pub struct ScanResult {
    /// Whether to block the request
    pub blocked: bool,

    /// Detection mode used
    pub mode: DetectionMode,

    /// Matched rules
    pub matches: Vec<RuleMatch>,

    /// Built-in detector results
    pub detector_results: Vec<DetectionResult>,

    /// Total anomaly score
    pub anomaly_score: u32,

    /// Block reason (if blocked)
    pub block_reason: Option<String>,

    /// Scan duration in microseconds
    pub duration_us: u64,
}

impl ScanResult {
    /// Create an allowed result
    pub fn allowed() -> Self {
        Self {
            blocked: false,
            mode: DetectionMode::Block,
            matches: Vec::new(),
            detector_results: Vec::new(),
            anomaly_score: 0,
            block_reason: None,
            duration_us: 0,
        }
    }

    /// Create a blocked result
    pub fn blocked(reason: &str) -> Self {
        Self {
            blocked: true,
            mode: DetectionMode::Block,
            matches: Vec::new(),
            detector_results: Vec::new(),
            anomaly_score: 0,
            block_reason: Some(reason.to_string()),
            duration_us: 0,
        }
    }

    /// Check if any threats were detected
    pub fn has_threats(&self) -> bool {
        !self.matches.is_empty() || self.detector_results.iter().any(|r| r.detected)
    }

    /// Get highest severity match
    pub fn highest_severity(&self) -> Option<&RuleMatch> {
        self.matches.iter().max_by_key(|m| m.score)
    }
}

/// The main rule engine
pub struct RuleEngine {
    /// WAF configuration
    config: WafConfig,

    /// Compiled rule set
    rules: RuleSet,

    /// SQL injection detector
    sqli_detector: SqlInjectionDetector,

    /// XSS detector
    xss_detector: XssDetector,

    /// Path traversal detector
    path_traversal_detector: PathTraversalDetector,

    /// Bypass rules
    bypass_rules: Vec<BypassRule>,

    /// Pre-compiled bypass regexes (for BypassOperator::Matches)
    bypass_regexes: HashMap<String, regex::Regex>,

    /// Disabled rule IDs (per route) — HashSet for O(1) lookup
    disabled_rules: HashMap<String, HashSet<String>>,
}

impl RuleEngine {
    /// Create new rule engine with config
    pub fn new(config: WafConfig) -> Self {
        let detector_config = &config.detectors;

        // Pre-compile any bypass regexes at construction time
        let mut bypass_regexes = HashMap::new();
        for rule in &config.bypass_rules {
            for condition in &rule.conditions {
                if matches!(condition.operator, BypassOperator::Matches) {
                    if let Ok(re) = regex::Regex::new(&condition.value) {
                        bypass_regexes.insert(condition.value.clone(), re);
                    }
                }
            }
        }

        Self {
            sqli_detector: SqlInjectionDetector::new(detector_config.sql_injection.clone()),
            xss_detector: XssDetector::new(detector_config.xss.clone()),
            path_traversal_detector: PathTraversalDetector::new(
                detector_config.path_traversal.clone(),
            ),
            bypass_rules: config.bypass_rules.clone(),
            bypass_regexes,
            disabled_rules: HashMap::new(),
            rules: RuleSet::load_crs_rules(),
            config,
        }
    }

    /// Create with default config
    pub fn default_config() -> Self {
        Self::new(WafConfig::default())
    }

    /// Create with custom detector config
    pub fn with_detectors(detector_config: DetectorConfig) -> Self {
        let config = WafConfig {
            detectors: detector_config,
            ..Default::default()
        };
        Self::new(config)
    }

    /// Add custom rules
    pub fn add_rules(&mut self, rules: RuleSet) {
        for rule in rules.all_rules() {
            self.rules.add_rule(rule.clone());
        }
    }

    /// Disable a rule
    pub fn disable_rule(&mut self, rule_id: &str) {
        self.disabled_rules
            .entry("*".to_string())
            .or_default()
            .insert(rule_id.to_string());
    }

    /// Disable a rule for a specific route
    pub fn disable_rule_for_route(&mut self, route: &str, rule_id: &str) {
        self.disabled_rules
            .entry(route.to_string())
            .or_default()
            .insert(rule_id.to_string());
    }

    /// Check if a rule is disabled for a route (O(1) HashSet lookup)
    fn is_rule_disabled(&self, rule_id: &str, route: Option<&str>) -> bool {
        // Check global disables
        if let Some(disabled) = self.disabled_rules.get("*") {
            if disabled.contains(rule_id) {
                return true;
            }
        }

        // Check route-specific disables
        if let Some(route) = route {
            if let Some(disabled) = self.disabled_rules.get(route) {
                if disabled.contains(rule_id) {
                    return true;
                }
            }
        }

        false
    }

    /// Check if request should bypass WAF
    fn should_bypass(&self, context: &ScanContext) -> bool {
        for bypass in &self.bypass_rules {
            if !bypass.enabled {
                continue;
            }

            if bypass
                .conditions
                .iter()
                .all(|c| self.check_bypass_condition(c, context))
            {
                return true;
            }
        }
        false
    }

    fn check_bypass_condition(&self, condition: &BypassCondition, context: &ScanContext) -> bool {
        let field_value: Option<Cow<'_, str>> = match condition.field {
            BypassField::SourceIp => context.source_ip.map(|ip| Cow::Owned(ip.to_string())),
            BypassField::Path => Some(Cow::Borrowed(&context.uri)),
            BypassField::Method => Some(Cow::Borrowed(&context.method)),
            BypassField::Header => context
                .headers
                .values()
                .next()
                .map(|v| Cow::Borrowed(v.as_str())),
            BypassField::UserAgent => context
                .headers
                .get("user-agent")
                .map(|v| Cow::Borrowed(v.as_str())),
            BypassField::ContentType => context.content_type.as_deref().map(Cow::Borrowed),
        };

        let Some(value) = field_value else {
            return false;
        };

        match condition.operator {
            BypassOperator::Equals => *value == condition.value,
            BypassOperator::NotEquals => *value != condition.value,
            BypassOperator::Contains => value.contains(&*condition.value),
            BypassOperator::NotContains => !value.contains(&*condition.value),
            BypassOperator::StartsWith => value.starts_with(&*condition.value),
            BypassOperator::EndsWith => value.ends_with(&*condition.value),
            BypassOperator::Matches => self
                .bypass_regexes
                .get(&condition.value)
                .is_some_and(|re| re.is_match(&value)),
            BypassOperator::InCidr => {
                // Parse IP and check CIDR
                if let Some(ip) = context.source_ip {
                    self.ip_in_cidr(ip, &condition.value)
                } else {
                    false
                }
            },
        }
    }

    fn ip_in_cidr(&self, ip: IpAddr, cidr: &str) -> bool {
        let parts: Vec<&str> = cidr.split('/').collect();
        if parts.len() != 2 {
            return false;
        }

        let Ok(network) = parts[0].parse::<IpAddr>() else {
            return false;
        };

        let Ok(prefix_len) = parts[1].parse::<u8>() else {
            return false;
        };

        match (ip, network) {
            (IpAddr::V4(ip), IpAddr::V4(net)) => {
                let ip_bits = u32::from(ip);
                let net_bits = u32::from(net);
                let mask = if prefix_len >= 32 {
                    u32::MAX
                } else {
                    u32::MAX << (32 - prefix_len)
                };
                (ip_bits & mask) == (net_bits & mask)
            },
            (IpAddr::V6(ip), IpAddr::V6(net)) => {
                let ip_bits = u128::from(ip);
                let net_bits = u128::from(net);
                let mask = if prefix_len >= 128 {
                    u128::MAX
                } else {
                    u128::MAX << (128 - prefix_len)
                };
                (ip_bits & mask) == (net_bits & mask)
            },
            _ => false,
        }
    }

    /// Scan a request
    pub fn scan(&self, context: &ScanContext) -> WafResult<ScanResult> {
        let start = std::time::Instant::now();

        // Check bypass rules first
        if self.should_bypass(context) {
            return Ok(ScanResult::allowed());
        }

        let mut result = ScanResult {
            blocked: false,
            mode: self.config.mode,
            matches: Vec::new(),
            detector_results: Vec::new(),
            anomaly_score: 0,
            block_reason: None,
            duration_us: 0,
        };

        // Run built-in detectors
        self.run_detectors(context, &mut result)?;

        // Run custom rules
        self.run_rules(context, &mut result)?;

        // Calculate final score and blocking decision
        result.anomaly_score = result.matches.iter().map(|m| m.score).sum::<u32>()
            + result
                .detector_results
                .iter()
                .filter(|r| r.detected)
                .map(|r| (r.confidence * 10.0) as u32)
                .sum::<u32>();

        // Determine if we should block
        if self.config.mode.should_block() {
            // Block if any blocking action matched
            if result.matches.iter().any(|m| m.action.is_blocking()) {
                result.blocked = true;
                if let Some(m) = result.highest_severity() {
                    result.block_reason = Some(format!("Rule {}: {}", m.rule_id, m.description));
                }
            }

            // Block if detectors found something
            if result.detector_results.iter().any(|r| r.detected) {
                result.blocked = true;
                if result.block_reason.is_none() {
                    if let Some(r) = result.detector_results.iter().find(|r| r.detected) {
                        result.block_reason = Some(format!("{}: {}", r.attack_type, r.details));
                    }
                }
            }
        }

        result.duration_us = start.elapsed().as_micros() as u64;
        Ok(result)
    }

    fn run_detectors(&self, context: &ScanContext, result: &mut ScanResult) -> WafResult<()> {
        // SQL injection detection — iterate all values without allocating a Vec
        if self.sqli_detector.is_enabled() {
            context.for_each_value(|_key, value| {
                let detection = self.sqli_detector.detect(value)?;
                if detection.detected {
                    result.detector_results.push(detection);
                }
                Ok(())
            })?;
        }

        // XSS detection
        if self.xss_detector.is_enabled() {
            context.for_each_value(|_key, value| {
                let detection = self.xss_detector.detect(value)?;
                if detection.detected {
                    result.detector_results.push(detection);
                }
                Ok(())
            })?;
        }

        // Path traversal detection
        if self.path_traversal_detector.is_enabled() {
            // Focus on URI and file-related parameters
            let detection = self.path_traversal_detector.detect(&context.uri)?;
            if detection.detected {
                result.detector_results.push(detection);
            }

            context.for_each_value(|key, value| {
                if key.contains("file")
                    || key.contains("path")
                    || key.contains("url")
                    || key.contains("uri")
                {
                    let detection = self.path_traversal_detector.detect(value)?;
                    if detection.detected {
                        result.detector_results.push(detection);
                    }
                }
                Ok(())
            })?;
        }

        Ok(())
    }

    fn run_rules(&self, context: &ScanContext, result: &mut ScanResult) -> WafResult<()> {
        for rule in self.rules.enabled_rules() {
            // Check if rule is disabled (O(1) HashSet lookup)
            if self.is_rule_disabled(&rule.definition.id, context.route.as_deref()) {
                continue;
            }

            // Check each target — get_target_value returns Cow to avoid cloning
            for target in &rule.definition.targets {
                if let Some(value) = context.get_target_value(target) {
                    if rule.matches(&value) {
                        result.matches.push(RuleMatch {
                            rule_id: rule.definition.id.clone(),
                            description: rule.definition.description.clone(),
                            category: rule.definition.category,
                            score: rule.definition.score,
                            action: rule.definition.action,
                            target: format!("{:?}", target),
                            matched_value: truncate_value(&value, 100),
                        });

                        // If blocking action, no need to check more targets for this rule
                        if rule.definition.action.is_blocking() {
                            break;
                        }
                    }
                }
            }
        }

        Ok(())
    }

    /// Get the current configuration
    pub fn config(&self) -> &WafConfig {
        &self.config
    }

    /// Get rule count
    pub fn rule_count(&self) -> usize {
        self.rules.len()
    }
}

fn truncate_value(value: &str, max_len: usize) -> String {
    if value.len() <= max_len {
        value.to_string()
    } else {
        format!("{}...", &value[..max_len])
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_scan_context_builder() {
        let context = ScanContext::new()
            .with_method("POST")
            .with_uri("/api/users")
            .with_query_param("id", "1")
            .with_header("Content-Type", "application/json")
            .with_body(r#"{"name": "test"}"#);

        assert_eq!(context.method, "POST");
        assert_eq!(context.uri, "/api/users");
        assert_eq!(context.query_params.get("id"), Some(&"1".to_string()));
        assert!(context.body.is_some());
    }

    #[test]
    fn test_scan_context_get_target() {
        let context = ScanContext::new()
            .with_uri("/test")
            .with_query_param("name", "value")
            .with_header("X-Custom", "header-value");

        assert_eq!(
            context.get_target_value(&RuleTarget::Uri).as_deref(),
            Some("/test")
        );
        assert_eq!(
            context
                .get_target_value(&RuleTarget::QueryParam("name".to_string()))
                .as_deref(),
            Some("value")
        );
        assert_eq!(
            context
                .get_target_value(&RuleTarget::Header("x-custom".to_string()))
                .as_deref(),
            Some("header-value")
        );
    }

    #[test]
    fn test_engine_scan_clean_request() {
        let engine = RuleEngine::default_config();
        let context = ScanContext::new()
            .with_method("GET")
            .with_uri("/api/users")
            .with_query_param("page", "1");

        let result = engine.scan(&context).unwrap();
        assert!(!result.blocked);
        assert!(result.matches.is_empty());
    }

    #[test]
    fn test_engine_scan_sqli() {
        let engine = RuleEngine::default_config();
        let context = ScanContext::new()
            .with_method("GET")
            .with_uri("/api/users")
            .with_query_param("id", "1' OR '1'='1");

        let result = engine.scan(&context).unwrap();
        assert!(result.blocked);
        assert!(result.has_threats());
    }

    #[test]
    fn test_engine_scan_xss() {
        let engine = RuleEngine::default_config();
        let context = ScanContext::new()
            .with_method("POST")
            .with_uri("/api/comments")
            .with_body("<script>alert('xss')</script>");

        let result = engine.scan(&context).unwrap();
        assert!(result.blocked);
        assert!(result.has_threats());
    }

    #[test]
    fn test_engine_scan_path_traversal() {
        let engine = RuleEngine::default_config();
        let context = ScanContext::new()
            .with_method("GET")
            .with_uri("/files/../../../etc/passwd");

        let result = engine.scan(&context).unwrap();
        assert!(result.blocked);
        assert!(result.has_threats());
    }

    #[test]
    fn test_engine_detect_mode() {
        let config = WafConfig {
            mode: DetectionMode::Detect,
            ..WafConfig::default()
        };
        let engine = RuleEngine::new(config);

        let context = ScanContext::new()
            .with_method("GET")
            .with_query_param("id", "1' OR '1'='1");

        let result = engine.scan(&context).unwrap();
        assert!(!result.blocked); // Detect mode doesn't block
        assert!(result.has_threats()); // But still detects
    }

    #[test]
    fn test_engine_bypass_rule() {
        let mut config = WafConfig::default();
        config.bypass_rules.push(BypassRule {
            id: "bypass-1".to_string(),
            description: "Bypass for test path".to_string(),
            conditions: vec![BypassCondition {
                field: BypassField::Path,
                operator: BypassOperator::StartsWith,
                value: "/internal/".to_string(),
            }],
            bypass_rules: vec![],
            enabled: true,
        });

        let engine = RuleEngine::new(config);

        // This attack on internal path should be bypassed
        let context = ScanContext::new()
            .with_uri("/internal/test")
            .with_query_param("id", "1' OR '1'='1");

        let result = engine.scan(&context).unwrap();
        assert!(!result.blocked);

        // Same attack on public path should be blocked
        let context = ScanContext::new()
            .with_uri("/api/test")
            .with_query_param("id", "1' OR '1'='1");

        let result = engine.scan(&context).unwrap();
        assert!(result.blocked);
    }

    #[test]
    fn test_engine_disable_rule() {
        let mut engine = RuleEngine::default_config();
        engine.disable_rule("942100"); // Disable main SQLi rule

        // Note: Other SQLi rules might still trigger
        assert!(engine.is_rule_disabled("942100", None));
    }

    #[test]
    fn test_scan_result_methods() {
        let mut result = ScanResult::allowed();
        assert!(!result.blocked);
        assert!(!result.has_threats());

        result.matches.push(RuleMatch {
            rule_id: "test".to_string(),
            description: "Test rule".to_string(),
            category: RuleCategory::SqlInjection,
            score: 5,
            action: RuleAction::Block,
            target: "query".to_string(),
            matched_value: "test".to_string(),
        });

        assert!(result.has_threats());
        assert!(result.highest_severity().is_some());
    }

    #[test]
    fn test_ip_in_cidr() {
        let engine = RuleEngine::default_config();

        assert!(engine.ip_in_cidr("10.0.0.1".parse().unwrap(), "10.0.0.0/8"));
        assert!(engine.ip_in_cidr("192.168.1.1".parse().unwrap(), "192.168.0.0/16"));
        assert!(!engine.ip_in_cidr("192.168.1.1".parse().unwrap(), "10.0.0.0/8"));
    }
}
