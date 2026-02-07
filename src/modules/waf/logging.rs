//! Threat logging and alerting

use super::config::{LogFormat, RuleSeverity, ThreatLogConfig};
use super::engine::{RuleMatch, ScanResult};
use super::error::{WafError, WafResult};
use serde::{Deserialize, Serialize};
use std::collections::VecDeque;
use std::net::IpAddr;
use std::sync::RwLock;
use std::time::{SystemTime, UNIX_EPOCH};

/// A single threat log entry
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ThreatLogEntry {
    /// Timestamp (Unix epoch millis)
    pub timestamp: u64,

    /// Unique request ID
    pub request_id: String,

    /// Source IP
    pub source_ip: Option<IpAddr>,

    /// HTTP method
    pub method: String,

    /// Request URI
    pub uri: String,

    /// Query string
    pub query_string: Option<String>,

    /// User agent
    pub user_agent: Option<String>,

    /// Whether request was blocked
    pub blocked: bool,

    /// Matched rules
    pub matched_rules: Vec<MatchedRuleInfo>,

    /// Detector findings
    pub detector_findings: Vec<DetectorFinding>,

    /// Total anomaly score
    pub anomaly_score: u32,

    /// Block reason
    pub block_reason: Option<String>,

    /// Scan duration in microseconds
    pub scan_duration_us: u64,

    /// Request body (if configured)
    pub request_body: Option<String>,

    /// Additional context
    pub context: std::collections::HashMap<String, String>,
}

/// Info about a matched rule
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MatchedRuleInfo {
    /// Rule ID
    pub rule_id: String,

    /// Description
    pub description: String,

    /// Category
    pub category: String,

    /// Severity
    pub severity: String,

    /// Score
    pub score: u32,

    /// Matched target
    pub target: String,

    /// Matched value (truncated)
    pub matched_value: String,
}

impl From<&RuleMatch> for MatchedRuleInfo {
    fn from(m: &RuleMatch) -> Self {
        Self {
            rule_id: m.rule_id.clone(),
            description: m.description.clone(),
            category: format!("{:?}", m.category),
            severity: severity_to_string(m.score),
            score: m.score,
            target: m.target.clone(),
            matched_value: m.matched_value.clone(),
        }
    }
}

fn severity_to_string(score: u32) -> String {
    match score {
        0..=2 => "low".to_string(),
        3..=5 => "medium".to_string(),
        6..=8 => "high".to_string(),
        _ => "critical".to_string(),
    }
}

/// Finding from a built-in detector
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DetectorFinding {
    /// Attack type
    pub attack_type: String,

    /// Confidence (0-100)
    pub confidence: u8,

    /// Details
    pub details: String,

    /// Matched payload (truncated)
    pub matched_payload: Option<String>,
}

/// Trait for threat loggers
pub trait ThreatLogger: Send + Sync {
    /// Log a threat entry
    fn log(&self, entry: ThreatLogEntry) -> WafResult<()>;

    /// Get recent entries
    fn recent_entries(&self, count: usize) -> Vec<ThreatLogEntry>;

    /// Get entries by severity
    fn entries_by_severity(&self, severity: RuleSeverity) -> Vec<ThreatLogEntry>;

    /// Get entries for IP
    fn entries_for_ip(&self, ip: IpAddr) -> Vec<ThreatLogEntry>;

    /// Clear all entries
    fn clear(&self);

    /// Entry count
    fn count(&self) -> usize;
}

/// In-memory threat log with optional file persistence
pub struct ThreatLog {
    config: ThreatLogConfig,
    entries: RwLock<VecDeque<ThreatLogEntry>>,
}

impl ThreatLog {
    /// Create new threat log with config
    pub fn new(config: ThreatLogConfig) -> Self {
        Self {
            config,
            entries: RwLock::new(VecDeque::new()),
        }
    }

    /// Create with default config
    pub fn default_config() -> Self {
        Self::new(ThreatLogConfig::default())
    }

    /// Create a log entry from scan result
    pub fn create_entry(
        &self,
        result: &ScanResult,
        request_id: &str,
        source_ip: Option<IpAddr>,
        method: &str,
        uri: &str,
        query_string: Option<&str>,
        user_agent: Option<&str>,
        body: Option<&str>,
    ) -> ThreatLogEntry {
        let timestamp = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_millis() as u64)
            .unwrap_or(0);

        let matched_rules: Vec<MatchedRuleInfo> =
            result.matches.iter().map(MatchedRuleInfo::from).collect();

        let detector_findings: Vec<DetectorFinding> = result
            .detector_results
            .iter()
            .filter(|r| r.detected)
            .map(|r| DetectorFinding {
                attack_type: r.attack_type.clone(),
                confidence: (r.confidence * 100.0) as u8,
                details: r.details.clone(),
                matched_payload: r.matched_payload.clone().map(|p| truncate(&p, 200)),
            })
            .collect();

        ThreatLogEntry {
            timestamp,
            request_id: request_id.to_string(),
            source_ip,
            method: method.to_string(),
            uri: uri.to_string(),
            query_string: query_string.map(|s| s.to_string()),
            user_agent: user_agent.map(|s| s.to_string()),
            blocked: result.blocked,
            matched_rules,
            detector_findings,
            anomaly_score: result.anomaly_score,
            block_reason: result.block_reason.clone(),
            scan_duration_us: result.duration_us,
            request_body: if self.config.include_body {
                body.map(|b| truncate(b, 1000))
            } else {
                None
            },
            context: std::collections::HashMap::new(),
        }
    }

    /// Format entry according to config
    pub fn format_entry(&self, entry: &ThreatLogEntry) -> String {
        match self.config.format {
            LogFormat::Json => serde_json::to_string(entry).unwrap_or_default(),
            LogFormat::Clf => self.format_clf(entry),
            LogFormat::Elf => self.format_elf(entry),
        }
    }

    fn format_clf(&self, entry: &ThreatLogEntry) -> String {
        // Common Log Format: host ident authuser date request status bytes
        let ip = entry
            .source_ip
            .map(|ip| ip.to_string())
            .unwrap_or_else(|| "-".to_string());
        let timestamp = format_timestamp(entry.timestamp);
        let status = if entry.blocked { 403 } else { 200 };

        format!(
            "{} - - [{}] \"{} {}\" {} - [WAF: {}]",
            ip,
            timestamp,
            entry.method,
            entry.uri,
            status,
            if entry.blocked { "BLOCKED" } else { "ALLOWED" }
        )
    }

    fn format_elf(&self, entry: &ThreatLogEntry) -> String {
        // Extended Log Format with more details
        let ip = entry
            .source_ip
            .map(|ip| ip.to_string())
            .unwrap_or_else(|| "-".to_string());
        let timestamp = format_timestamp(entry.timestamp);
        let status = if entry.blocked { 403 } else { 200 };
        let rules = entry
            .matched_rules
            .iter()
            .map(|r| r.rule_id.as_str())
            .collect::<Vec<_>>()
            .join(",");

        format!(
            "{} [{}] \"{} {}\" {} score={} rules=[{}] blocked={} duration={}us",
            ip,
            timestamp,
            entry.method,
            entry.uri,
            status,
            entry.anomaly_score,
            rules,
            entry.blocked,
            entry.scan_duration_us
        )
    }

    /// Check if alert should be sent
    pub fn should_alert(&self, entry: &ThreatLogEntry) -> bool {
        if !self.config.alert_on_critical {
            return false;
        }

        // Alert on critical severity (score >= 9) or blocked requests with high score
        entry.anomaly_score >= 9 || (entry.blocked && entry.anomaly_score >= 5)
    }

    /// Send alert (webhook)
    pub async fn send_alert(&self, entry: &ThreatLogEntry) -> WafResult<()> {
        let Some(webhook_url) = &self.config.alert_webhook else {
            return Ok(());
        };

        let payload = serde_json::json!({
            "alert_type": "waf_threat",
            "severity": if entry.anomaly_score >= 9 { "critical" } else { "high" },
            "timestamp": entry.timestamp,
            "source_ip": entry.source_ip.map(|ip| ip.to_string()),
            "uri": entry.uri,
            "blocked": entry.blocked,
            "anomaly_score": entry.anomaly_score,
            "matched_rules": entry.matched_rules.len(),
            "block_reason": entry.block_reason,
        });

        // In a real implementation, this would make an HTTP POST request
        // For now, we just log that we would send it
        let _ = (webhook_url, payload);

        Ok(())
    }
}

impl ThreatLogger for ThreatLog {
    fn log(&self, entry: ThreatLogEntry) -> WafResult<()> {
        if !self.config.enabled {
            return Ok(());
        }

        let mut entries = self
            .entries
            .write()
            .map_err(|e| WafError::LoggingError(e.to_string()))?;

        // Maintain max entries limit
        while entries.len() >= self.config.max_entries {
            entries.pop_front();
        }

        // Write to file if configured
        if let Some(file_path) = &self.config.file_path {
            if let Ok(mut file) = std::fs::OpenOptions::new()
                .create(true)
                .append(true)
                .open(file_path)
            {
                use std::io::Write;
                let formatted = self.format_entry(&entry);
                let _ = writeln!(file, "{}", formatted);
            }
        }

        entries.push_back(entry);
        Ok(())
    }

    fn recent_entries(&self, count: usize) -> Vec<ThreatLogEntry> {
        self.entries
            .read()
            .map(|entries| entries.iter().rev().take(count).cloned().collect())
            .unwrap_or_default()
    }

    fn entries_by_severity(&self, severity: RuleSeverity) -> Vec<ThreatLogEntry> {
        let min_score = severity.score();
        self.entries
            .read()
            .map(|entries| {
                entries
                    .iter()
                    .filter(|e| e.anomaly_score >= min_score)
                    .cloned()
                    .collect()
            })
            .unwrap_or_default()
    }

    fn entries_for_ip(&self, ip: IpAddr) -> Vec<ThreatLogEntry> {
        self.entries
            .read()
            .map(|entries| {
                entries
                    .iter()
                    .filter(|e| e.source_ip == Some(ip))
                    .cloned()
                    .collect()
            })
            .unwrap_or_default()
    }

    fn clear(&self) {
        if let Ok(mut entries) = self.entries.write() {
            entries.clear();
        }
    }

    fn count(&self) -> usize {
        self.entries.read().map(|e| e.len()).unwrap_or(0)
    }
}

fn truncate(s: &str, max_len: usize) -> String {
    if s.len() <= max_len {
        s.to_string()
    } else {
        format!("{}...", &s[..max_len])
    }
}

fn format_timestamp(millis: u64) -> String {
    // Simple timestamp format
    let secs = millis / 1000;
    let datetime = chrono::DateTime::from_timestamp(secs as i64, 0);
    datetime
        .map(|dt| dt.format("%d/%b/%Y:%H:%M:%S %z").to_string())
        .unwrap_or_else(|| format!("{}", millis))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::modules::waf::engine::ScanResult;
    use crate::modules::waf::rules::RuleCategory;

    fn create_test_result() -> ScanResult {
        let mut result = ScanResult::blocked("Test block");
        result.anomaly_score = 10;
        result.matches.push(RuleMatch {
            rule_id: "942100".to_string(),
            description: "SQL Injection".to_string(),
            category: RuleCategory::SqlInjection,
            score: 10,
            action: crate::modules::waf::config::RuleAction::Block,
            target: "query".to_string(),
            matched_value: "1' OR '1'='1".to_string(),
        });
        result
    }

    #[test]
    fn test_threat_log_create_entry() {
        let log = ThreatLog::default_config();
        let result = create_test_result();

        let entry = log.create_entry(
            &result,
            "req-123",
            Some("192.168.1.1".parse().unwrap()),
            "GET",
            "/api/users",
            Some("id=1"),
            Some("TestAgent/1.0"),
            None,
        );

        assert_eq!(entry.request_id, "req-123");
        assert_eq!(entry.method, "GET");
        assert!(entry.blocked);
        assert_eq!(entry.matched_rules.len(), 1);
        assert_eq!(entry.matched_rules[0].rule_id, "942100");
    }

    #[test]
    fn test_threat_log_logging() {
        let log = ThreatLog::default_config();
        let result = create_test_result();

        let entry = log.create_entry(
            &result,
            "req-1",
            Some("10.0.0.1".parse().unwrap()),
            "POST",
            "/api/login",
            None,
            None,
            None,
        );

        log.log(entry).unwrap();
        assert_eq!(log.count(), 1);

        let recent = log.recent_entries(10);
        assert_eq!(recent.len(), 1);
    }

    #[test]
    fn test_threat_log_max_entries() {
        let mut config = ThreatLogConfig::default();
        config.max_entries = 3;
        let log = ThreatLog::new(config);

        for i in 0..5 {
            let mut result = ScanResult::blocked("test");
            result.anomaly_score = i;

            let entry = log.create_entry(
                &result,
                &format!("req-{}", i),
                None,
                "GET",
                "/test",
                None,
                None,
                None,
            );
            log.log(entry).unwrap();
        }

        assert_eq!(log.count(), 3);
        let recent = log.recent_entries(10);
        // Should have the last 3 entries
        assert_eq!(recent[0].request_id, "req-4");
    }

    #[test]
    fn test_threat_log_by_severity() {
        let log = ThreatLog::default_config();

        for score in [1, 3, 5, 7, 10] {
            let mut result = ScanResult::blocked("test");
            result.anomaly_score = score;

            let entry = log.create_entry(&result, "req", None, "GET", "/", None, None, None);
            log.log(entry).unwrap();
        }

        let high_severity = log.entries_by_severity(RuleSeverity::High);
        assert_eq!(high_severity.len(), 3); // score >= 5 (5, 7, 10)
    }

    #[test]
    fn test_threat_log_by_ip() {
        let log = ThreatLog::default_config();
        let ip1: IpAddr = "192.168.1.1".parse().unwrap();
        let ip2: IpAddr = "10.0.0.1".parse().unwrap();

        for (i, ip) in [(0, ip1), (1, ip1), (2, ip2), (3, ip1)] {
            let result = ScanResult::blocked("test");
            let entry = log.create_entry(
                &result,
                &format!("req-{}", i),
                Some(ip),
                "GET",
                "/",
                None,
                None,
                None,
            );
            log.log(entry).unwrap();
        }

        let ip1_entries = log.entries_for_ip(ip1);
        assert_eq!(ip1_entries.len(), 3);

        let ip2_entries = log.entries_for_ip(ip2);
        assert_eq!(ip2_entries.len(), 1);
    }

    #[test]
    fn test_format_clf() {
        let log = ThreatLog::default_config();
        let result = create_test_result();

        let entry = log.create_entry(
            &result,
            "req-1",
            Some("192.168.1.1".parse().unwrap()),
            "GET",
            "/api/users",
            None,
            None,
            None,
        );

        let formatted = log.format_clf(&entry);
        assert!(formatted.contains("192.168.1.1"));
        assert!(formatted.contains("GET /api/users"));
        assert!(formatted.contains("403")); // Blocked
        assert!(formatted.contains("BLOCKED"));
    }

    #[test]
    fn test_format_elf() {
        let log = ThreatLog::default_config();
        let result = create_test_result();

        let entry = log.create_entry(
            &result,
            "req-1",
            Some("192.168.1.1".parse().unwrap()),
            "GET",
            "/api/users",
            None,
            None,
            None,
        );

        let formatted = log.format_elf(&entry);
        assert!(formatted.contains("192.168.1.1"));
        assert!(formatted.contains("score=10"));
        assert!(formatted.contains("942100")); // Rule ID
        assert!(formatted.contains("blocked=true"));
    }

    #[test]
    fn test_format_json() {
        let mut config = ThreatLogConfig::default();
        config.format = LogFormat::Json;
        let log = ThreatLog::new(config);

        let result = create_test_result();
        let entry = log.create_entry(&result, "req-1", None, "GET", "/", None, None, None);

        let formatted = log.format_entry(&entry);
        assert!(formatted.starts_with('{'));
        assert!(formatted.contains("\"blocked\":true"));
    }

    #[test]
    fn test_should_alert() {
        let log = ThreatLog::default_config();

        // Critical score
        let mut result = ScanResult::blocked("test");
        result.anomaly_score = 10;
        let entry = log.create_entry(&result, "req", None, "GET", "/", None, None, None);
        assert!(log.should_alert(&entry));

        // Low score, not blocked
        let mut result = ScanResult::allowed();
        result.anomaly_score = 2;
        let entry = log.create_entry(&result, "req", None, "GET", "/", None, None, None);
        assert!(!log.should_alert(&entry));
    }

    #[test]
    fn test_clear() {
        let log = ThreatLog::default_config();

        for _ in 0..5 {
            let result = ScanResult::blocked("test");
            let entry = log.create_entry(&result, "req", None, "GET", "/", None, None, None);
            log.log(entry).unwrap();
        }

        assert_eq!(log.count(), 5);
        log.clear();
        assert_eq!(log.count(), 0);
    }

    #[test]
    fn test_disabled_logging() {
        let mut config = ThreatLogConfig::default();
        config.enabled = false;
        let log = ThreatLog::new(config);

        let result = ScanResult::blocked("test");
        let entry = log.create_entry(&result, "req", None, "GET", "/", None, None, None);
        log.log(entry).unwrap();

        // Should not log when disabled
        assert_eq!(log.count(), 0);
    }
}
