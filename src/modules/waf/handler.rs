//! WAF handler implementing ModuleContract

use super::config::WafConfig;
use super::engine::{RuleEngine, ScanContext, ScanResult};
use super::error::WafResult;
use super::logging::{ThreatLog, ThreatLogger};
use crate::module::{
    Capability, MetricsPayload, ModuleConfig, ModuleContract, ModuleError, ModuleManifest,
    ModuleResult, ModuleStatus,
};
use std::collections::HashMap;
use std::net::IpAddr;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::Instant;
use tracing::{debug, info, warn};

/// Statistics for the WAF handler
#[derive(Debug, Default)]
pub struct WafStats {
    /// Total requests scanned
    pub requests_scanned: AtomicU64,
    /// Requests allowed
    pub requests_allowed: AtomicU64,
    /// Requests blocked
    pub requests_blocked: AtomicU64,
    /// SQL injection detections
    pub sqli_detections: AtomicU64,
    /// XSS detections
    pub xss_detections: AtomicU64,
    /// Path traversal detections
    pub path_traversal_detections: AtomicU64,
    /// Other detections
    pub other_detections: AtomicU64,
    /// Total scan time in microseconds
    pub total_scan_time_us: AtomicU64,
    /// Bypassed requests
    pub bypassed_requests: AtomicU64,
}

impl WafStats {
    /// Create new stats
    pub fn new() -> Self {
        Self::default()
    }

    /// Record a scan result
    pub fn record_scan(&self, result: &ScanResult) {
        self.requests_scanned.fetch_add(1, Ordering::Relaxed);
        self.total_scan_time_us
            .fetch_add(result.duration_us, Ordering::Relaxed);

        if result.blocked {
            self.requests_blocked.fetch_add(1, Ordering::Relaxed);
        } else {
            self.requests_allowed.fetch_add(1, Ordering::Relaxed);
        }

        // Count by detection type
        for detector_result in &result.detector_results {
            if detector_result.detected {
                match detector_result.attack_type.to_lowercase().as_str() {
                    s if s.contains("sql") => {
                        self.sqli_detections.fetch_add(1, Ordering::Relaxed);
                    },
                    s if s.contains("xss") || s.contains("cross-site") => {
                        self.xss_detections.fetch_add(1, Ordering::Relaxed);
                    },
                    s if s.contains("path") || s.contains("traversal") => {
                        self.path_traversal_detections
                            .fetch_add(1, Ordering::Relaxed);
                    },
                    _ => {
                        self.other_detections.fetch_add(1, Ordering::Relaxed);
                    },
                }
            }
        }
    }

    /// Record a bypassed request
    pub fn record_bypass(&self) {
        self.requests_scanned.fetch_add(1, Ordering::Relaxed);
        self.bypassed_requests.fetch_add(1, Ordering::Relaxed);
        self.requests_allowed.fetch_add(1, Ordering::Relaxed);
    }

    /// Get average scan time in microseconds
    pub fn avg_scan_time_us(&self) -> u64 {
        let scanned = self.requests_scanned.load(Ordering::Relaxed);
        if scanned == 0 {
            0
        } else {
            self.total_scan_time_us.load(Ordering::Relaxed) / scanned
        }
    }

    /// Get block rate as percentage
    pub fn block_rate(&self) -> f64 {
        let scanned = self.requests_scanned.load(Ordering::Relaxed);
        if scanned == 0 {
            0.0
        } else {
            (self.requests_blocked.load(Ordering::Relaxed) as f64 / scanned as f64) * 100.0
        }
    }
}

/// Threat information for a blocked request
#[derive(Debug, Clone)]
pub struct ThreatInfo {
    /// Whether the request was blocked
    pub blocked: bool,
    /// Reason for blocking
    pub block_reason: Option<String>,
    /// Attack types detected
    pub attack_types: Vec<String>,
    /// Matched rule IDs
    pub matched_rules: Vec<String>,
    /// Anomaly score
    pub anomaly_score: u32,
    /// Recommended HTTP status code
    pub status_code: u16,
}

impl ThreatInfo {
    /// Create info for an allowed request
    pub fn allowed() -> Self {
        Self {
            blocked: false,
            block_reason: None,
            attack_types: Vec::new(),
            matched_rules: Vec::new(),
            anomaly_score: 0,
            status_code: 200,
        }
    }

    /// Create info from scan result
    pub fn from_result(result: &ScanResult) -> Self {
        let attack_types: Vec<String> = result
            .detector_results
            .iter()
            .filter(|r| r.detected)
            .map(|r| r.attack_type.clone())
            .collect();

        let matched_rules: Vec<String> = result.matches.iter().map(|m| m.rule_id.clone()).collect();

        Self {
            blocked: result.blocked,
            block_reason: result.block_reason.clone(),
            attack_types,
            matched_rules,
            anomaly_score: result.anomaly_score,
            status_code: if result.blocked { 403 } else { 200 },
        }
    }
}

/// Request context for WAF scanning
#[derive(Debug, Clone, Default)]
pub struct WafRequest {
    /// Source IP address
    pub source_ip: Option<IpAddr>,
    /// HTTP method
    pub method: String,
    /// Request URI/path
    pub uri: String,
    /// Query string
    pub query_string: Option<String>,
    /// Query parameters
    pub query_params: HashMap<String, String>,
    /// Request headers
    pub headers: HashMap<String, String>,
    /// Cookies
    pub cookies: HashMap<String, String>,
    /// Request body
    pub body: Option<String>,
    /// Content type
    pub content_type: Option<String>,
    /// Form fields (parsed)
    pub form_fields: HashMap<String, String>,
}

impl WafRequest {
    /// Create new empty request
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

    /// Convert to scan context
    fn to_scan_context(&self) -> ScanContext {
        let mut ctx = ScanContext::new()
            .with_method(&self.method)
            .with_uri(&self.uri);

        if let Some(ip) = self.source_ip {
            ctx = ctx.with_source_ip(ip);
        }

        if let Some(qs) = &self.query_string {
            ctx = ctx.with_query_string(qs);
        }

        for (k, v) in &self.query_params {
            ctx = ctx.with_query_param(k, v);
        }

        for (k, v) in &self.headers {
            ctx = ctx.with_header(k, v);
        }

        for (k, v) in &self.cookies {
            ctx = ctx.with_cookie(k, v);
        }

        if let Some(body) = &self.body {
            ctx = ctx.with_body(body);
        }

        if let Some(ct) = &self.content_type {
            ctx = ctx.with_content_type(ct);
        }

        for (k, v) in &self.form_fields {
            ctx = ctx.with_form_field(k, v);
        }

        ctx
    }
}

/// WAF handler implementing ModuleContract
pub struct WafHandler {
    /// Configuration
    config: WafConfig,

    /// Rule engine
    engine: Option<RuleEngine>,

    /// Threat log
    threat_log: Option<ThreatLog>,

    /// Current status
    status: ModuleStatus,

    /// Statistics
    stats: Arc<WafStats>,

    /// Start time for uptime calculation
    started_at: Option<Instant>,
}

impl std::fmt::Debug for WafHandler {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("WafHandler")
            .field("config", &self.config)
            .field("engine", &self.engine.is_some())
            .field("status", &self.status)
            .field("stats", &self.stats)
            .finish()
    }
}

impl WafHandler {
    /// Create a new WAF handler
    pub fn new() -> Self {
        Self::with_config(WafConfig::default())
    }

    /// Create a WAF handler with custom configuration
    pub fn with_config(config: WafConfig) -> Self {
        Self {
            config,
            engine: None,
            threat_log: None,
            status: ModuleStatus::Stopped,
            stats: Arc::new(WafStats::new()),
            started_at: None,
        }
    }

    /// Check a request through the WAF
    pub fn check_request(&self, request: &WafRequest) -> WafResult<ThreatInfo> {
        if !self.config.enabled {
            return Ok(ThreatInfo::allowed());
        }

        let Some(engine) = &self.engine else {
            return Ok(ThreatInfo::allowed());
        };

        // Convert to scan context
        let context = request.to_scan_context();

        // Run the scan
        let result = engine.scan(&context)?;

        // Record stats
        self.stats.record_scan(&result);

        // Log threats if configured
        if result.has_threats() {
            if let Some(log) = &self.threat_log {
                let entry = log.create_entry(
                    &result,
                    &generate_request_id(),
                    request.source_ip,
                    &request.method,
                    &request.uri,
                    request.query_string.as_deref(),
                    request.headers.get("user-agent").map(|s| s.as_str()),
                    request.body.as_deref(),
                );

                if let Err(e) = log.log(entry.clone()) {
                    warn!("Failed to log threat: {}", e);
                }

                // Check for alerting
                if log.should_alert(&entry) {
                    debug!("Critical threat detected, alerting");
                    // Alert handling would happen here
                }
            }
        }

        Ok(ThreatInfo::from_result(&result))
    }

    /// Scan raw input values (for simpler use cases)
    pub fn scan_value(&self, value: &str) -> WafResult<ThreatInfo> {
        let request = WafRequest::new()
            .with_method("GET")
            .with_uri("/")
            .with_query_param("input", value);

        self.check_request(&request)
    }

    /// Get statistics
    pub fn stats(&self) -> &WafStats {
        &self.stats
    }

    /// Get threat log
    pub fn threat_log(&self) -> Option<&ThreatLog> {
        self.threat_log.as_ref()
    }

    /// Get rule count
    pub fn rule_count(&self) -> usize {
        self.engine.as_ref().map(|e| e.rule_count()).unwrap_or(0)
    }
}

impl Default for WafHandler {
    fn default() -> Self {
        Self::new()
    }
}

fn generate_request_id() -> String {
    use std::sync::atomic::{AtomicU64, Ordering};
    use std::time::{SystemTime, UNIX_EPOCH};

    static COUNTER: AtomicU64 = AtomicU64::new(0);

    let timestamp = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_nanos())
        .unwrap_or(0);
    let seq = COUNTER.fetch_add(1, Ordering::Relaxed);
    format!("req-{:x}-{:04x}", timestamp, seq)
}

impl ModuleContract for WafHandler {
    fn manifest(&self) -> ModuleManifest {
        ModuleManifest::builder("waf")
            .description(
                "Web Application Firewall with SQL injection, XSS, and path traversal detection",
            )
            .version(1, 0, 0)
            .capability(Capability::Custom("WebApplicationFirewall".to_string()))
            .capability(Capability::Custom("RequestInspection".to_string()))
            .capability(Capability::Custom("ThreatDetection".to_string()))
            .build()
    }

    fn init(&mut self, config: ModuleConfig) -> ModuleResult<()> {
        if self.status != ModuleStatus::Stopped {
            return Err(ModuleError::InvalidState {
                current: format!("{:?}", self.status),
                expected: "Stopped".to_string(),
            });
        }

        info!("Initializing WAF handler");

        // Parse configuration from raw TOML if available
        if let Some(raw_config) = config.raw_config() {
            if let Ok(waf_config) = toml::from_str::<WafConfig>(raw_config) {
                self.config = waf_config;
                debug!("Loaded WAF configuration from TOML");
            }
        }

        // Initialize the rule engine
        self.engine = Some(RuleEngine::new(self.config.clone()));
        debug!(
            "Initialized rule engine with {} rules",
            self.engine.as_ref().map(|e| e.rule_count()).unwrap_or(0)
        );

        // Initialize threat log
        self.threat_log = Some(ThreatLog::new(self.config.logging.clone()));
        debug!("Initialized threat logging");

        self.status = ModuleStatus::Initializing;
        info!("WAF handler initialized successfully");
        Ok(())
    }

    fn start(&mut self) -> ModuleResult<()> {
        if self.status != ModuleStatus::Initializing {
            return Err(ModuleError::InvalidState {
                current: format!("{:?}", self.status),
                expected: "Initializing".to_string(),
            });
        }

        self.started_at = Some(Instant::now());
        self.status = ModuleStatus::Running;

        info!(
            "WAF handler started in {:?} mode with {} rules",
            self.config.mode,
            self.rule_count()
        );

        Ok(())
    }

    fn stop(&mut self) -> ModuleResult<()> {
        if self.status != ModuleStatus::Running {
            return Err(ModuleError::InvalidState {
                current: format!("{:?}", self.status),
                expected: "Running".to_string(),
            });
        }

        self.status = ModuleStatus::Stopped;
        self.started_at = None;

        info!("WAF handler stopped");
        Ok(())
    }

    fn status(&self) -> ModuleStatus {
        self.status.clone()
    }

    fn metrics(&self) -> MetricsPayload {
        let mut payload = MetricsPayload::new();

        // Counter metrics
        payload.counter(
            "requests_scanned",
            self.stats.requests_scanned.load(Ordering::Relaxed),
        );
        payload.counter(
            "requests_allowed",
            self.stats.requests_allowed.load(Ordering::Relaxed),
        );
        payload.counter(
            "requests_blocked",
            self.stats.requests_blocked.load(Ordering::Relaxed),
        );
        payload.counter(
            "sqli_detections",
            self.stats.sqli_detections.load(Ordering::Relaxed),
        );
        payload.counter(
            "xss_detections",
            self.stats.xss_detections.load(Ordering::Relaxed),
        );
        payload.counter(
            "path_traversal_detections",
            self.stats.path_traversal_detections.load(Ordering::Relaxed),
        );

        // Gauge metrics
        payload.gauge("avg_scan_time_us", self.stats.avg_scan_time_us() as f64);
        payload.gauge("block_rate", self.stats.block_rate());
        payload.gauge("rule_count", self.rule_count() as f64);

        if let Some(started) = self.started_at {
            payload.gauge("uptime_secs", started.elapsed().as_secs() as f64);
        }

        if let Some(log) = &self.threat_log {
            payload.counter("threat_log_entries", log.count() as u64);
        }

        payload
    }

    fn heartbeat(&self) -> bool {
        self.status == ModuleStatus::Running && self.engine.is_some()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::module::ModuleConfig;

    fn create_test_handler() -> WafHandler {
        let mut handler = WafHandler::new();
        let config = ModuleConfig::new();
        handler.init(config).unwrap();
        handler.start().unwrap();
        handler
    }

    #[test]
    fn test_waf_handler_lifecycle() {
        let mut handler = WafHandler::new();
        assert_eq!(handler.status(), ModuleStatus::Stopped);

        let config = ModuleConfig::new();

        handler.init(config).unwrap();
        assert_eq!(handler.status(), ModuleStatus::Initializing);

        handler.start().unwrap();
        assert_eq!(handler.status(), ModuleStatus::Running);

        handler.stop().unwrap();
        assert_eq!(handler.status(), ModuleStatus::Stopped);
    }

    #[test]
    fn test_waf_handler_manifest() {
        let handler = WafHandler::new();
        let manifest = handler.manifest();
        assert_eq!(manifest.name, "waf");
        assert!(!manifest.capabilities.is_empty());
    }

    #[test]
    fn test_waf_handler_check_clean_request() {
        let handler = create_test_handler();

        let request = WafRequest::new()
            .with_method("GET")
            .with_uri("/api/users")
            .with_query_param("page", "1");

        let result = handler.check_request(&request).unwrap();
        assert!(!result.blocked);
        assert_eq!(result.status_code, 200);
    }

    #[test]
    fn test_waf_handler_block_sqli() {
        let handler = create_test_handler();

        let request = WafRequest::new()
            .with_method("GET")
            .with_uri("/api/users")
            .with_query_param("id", "1' OR '1'='1");

        let result = handler.check_request(&request).unwrap();
        assert!(result.blocked);
        assert_eq!(result.status_code, 403);
        assert!(!result.attack_types.is_empty());
    }

    #[test]
    fn test_waf_handler_block_xss() {
        let handler = create_test_handler();

        let request = WafRequest::new()
            .with_method("POST")
            .with_uri("/api/comments")
            .with_body("<script>alert('xss')</script>");

        let result = handler.check_request(&request).unwrap();
        assert!(result.blocked);
        assert!(result.attack_types.iter().any(|t| t.contains("XSS")));
    }

    #[test]
    fn test_waf_handler_block_path_traversal() {
        let handler = create_test_handler();

        let request = WafRequest::new()
            .with_method("GET")
            .with_uri("/files/../../../etc/passwd");

        let result = handler.check_request(&request).unwrap();
        assert!(result.blocked);
    }

    #[test]
    fn test_waf_handler_scan_value() {
        let handler = create_test_handler();

        // Clean value
        let result = handler.scan_value("hello world").unwrap();
        assert!(!result.blocked);

        // Malicious value
        let result = handler.scan_value("'; DROP TABLE users--").unwrap();
        assert!(result.blocked);
    }

    #[test]
    fn test_waf_handler_stats() {
        let handler = create_test_handler();

        // Make some requests
        let _ = handler.scan_value("clean");
        let _ = handler.scan_value("1' OR '1'='1");
        let _ = handler.scan_value("also clean");

        let stats = handler.stats();
        assert!(stats.requests_scanned.load(Ordering::Relaxed) >= 3);
        assert!(stats.requests_blocked.load(Ordering::Relaxed) >= 1);
    }

    #[test]
    fn test_waf_handler_metrics() {
        let handler = create_test_handler();

        let _ = handler.scan_value("test");

        let metrics = handler.metrics();
        assert!(metrics.counters.contains_key("requests_scanned"));
        assert!(metrics.gauges.contains_key("rule_count"));
    }

    #[test]
    fn test_waf_handler_heartbeat() {
        let handler = create_test_handler();
        assert!(handler.heartbeat());
    }

    #[test]
    fn test_waf_stats() {
        let stats = WafStats::new();

        // Create a mock result
        let result = ScanResult {
            blocked: true,
            mode: super::super::config::DetectionMode::Block,
            matches: Vec::new(),
            detector_results: vec![super::super::detector::DetectionResult::detected(
                "SQL Injection",
                0.95,
                "payload",
                "details",
            )],
            anomaly_score: 10,
            block_reason: Some("test".to_string()),
            duration_us: 100,
        };

        stats.record_scan(&result);

        assert_eq!(stats.requests_scanned.load(Ordering::Relaxed), 1);
        assert_eq!(stats.requests_blocked.load(Ordering::Relaxed), 1);
        assert_eq!(stats.sqli_detections.load(Ordering::Relaxed), 1);
    }

    #[test]
    fn test_waf_stats_avg_scan_time() {
        let stats = WafStats::new();
        assert_eq!(stats.avg_scan_time_us(), 0);

        stats.requests_scanned.store(2, Ordering::Relaxed);
        stats.total_scan_time_us.store(200, Ordering::Relaxed);

        assert_eq!(stats.avg_scan_time_us(), 100);
    }

    #[test]
    fn test_waf_stats_block_rate() {
        let stats = WafStats::new();
        assert_eq!(stats.block_rate(), 0.0);

        stats.requests_scanned.store(10, Ordering::Relaxed);
        stats.requests_blocked.store(3, Ordering::Relaxed);

        assert!((stats.block_rate() - 30.0).abs() < 0.01);
    }

    #[test]
    fn test_threat_info() {
        let info = ThreatInfo::allowed();
        assert!(!info.blocked);
        assert_eq!(info.status_code, 200);

        let result = ScanResult {
            blocked: true,
            mode: super::super::config::DetectionMode::Block,
            matches: Vec::new(),
            detector_results: Vec::new(),
            anomaly_score: 5,
            block_reason: Some("Test".to_string()),
            duration_us: 50,
        };

        let info = ThreatInfo::from_result(&result);
        assert!(info.blocked);
        assert_eq!(info.status_code, 403);
        assert_eq!(info.anomaly_score, 5);
    }

    #[test]
    fn test_waf_request_builder() {
        let request = WafRequest::new()
            .with_method("POST")
            .with_uri("/api/test")
            .with_source_ip("192.168.1.1".parse().unwrap())
            .with_header("Content-Type", "application/json")
            .with_body(r#"{"key": "value"}"#);

        assert_eq!(request.method, "POST");
        assert_eq!(request.uri, "/api/test");
        assert!(request.source_ip.is_some());
        assert!(request.body.is_some());
    }

    #[test]
    fn test_waf_disabled() {
        let config = WafConfig {
            enabled: false,
            ..WafConfig::default()
        };

        let mut handler = WafHandler::with_config(config);
        let module_config = ModuleConfig::new();

        handler.init(module_config).unwrap();
        handler.start().unwrap();

        // Should not block when disabled
        let result = handler.scan_value("'; DROP TABLE users--").unwrap();
        assert!(!result.blocked);
    }
}
