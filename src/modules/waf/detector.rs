//! Attack detectors for specific vulnerability categories

#![allow(clippy::incompatible_msrv)]

use super::config::{PathTraversalConfig, SqlInjectionConfig, XssConfig};
use super::error::WafResult;
use regex::Regex;
use std::borrow::Cow;
use std::sync::LazyLock;

/// Result of a detection check
#[derive(Debug, Clone)]
pub struct DetectionResult {
    /// Whether an attack was detected
    pub detected: bool,

    /// Confidence level (0.0-1.0)
    pub confidence: f64,

    /// Attack type description
    pub attack_type: String,

    /// Matched pattern or payload
    pub matched_payload: Option<String>,

    /// Details about the detection
    pub details: String,
}

impl DetectionResult {
    /// Create a safe (no attack) result
    #[inline]
    pub fn safe() -> Self {
        Self {
            detected: false,
            confidence: 0.0,
            attack_type: String::new(),
            matched_payload: None,
            details: String::new(),
        }
    }

    /// Create a detected result (payload truncated to 256 bytes to reduce allocation)
    #[inline]
    pub fn detected(attack_type: &str, confidence: f64, payload: &str, details: &str) -> Self {
        const MAX_PAYLOAD: usize = 256;
        let truncated = if payload.len() <= MAX_PAYLOAD {
            payload.to_string()
        } else {
            // Find a valid UTF-8 boundary
            let end = payload
                .char_indices()
                .take_while(|(i, _)| *i <= MAX_PAYLOAD)
                .last()
                .map(|(i, c)| i + c.len_utf8())
                .unwrap_or(MAX_PAYLOAD);
            let mut s = payload[..end].to_string();
            s.push_str("...");
            s
        };

        Self {
            detected: true,
            confidence,
            attack_type: attack_type.to_string(),
            matched_payload: Some(truncated),
            details: details.to_string(),
        }
    }
}

/// Trait for attack detectors
pub trait Detector: Send + Sync {
    /// Detector name
    fn name(&self) -> &str;

    /// Detect attacks in input
    fn detect(&self, input: &str) -> WafResult<DetectionResult>;

    /// Check if detector is enabled
    fn is_enabled(&self) -> bool;
}

// SQL injection patterns
static SQLI_KEYWORDS: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"(?i)\b(select|insert|update|delete|drop|union|alter|create|truncate|exec|execute|xp_|sp_|declare|cast|convert)\b").unwrap()
});

static SQLI_OPERATORS: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r#"(?i)(\bor\b|\band\b)\s+[\d'"]+\s*[=<>]"#).unwrap());

static SQLI_COMMENTS: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"(--|#|/[*]|[*]/|;)").unwrap());

static SQLI_TAUTOLOGY: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r#"(?i)(\bor\b|\band\b)\s+['"]?\d+['"]?\s*=\s*['"]?\d+['"]?|\b1\s*=\s*1\b|\btrue\b"#)
        .unwrap()
});

static SQLI_QUOTES: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r#"['"]\s*(or|and|;|--|#)"#).unwrap());

static SQLI_UNION_SELECT: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"(?i)\bunion\b\s+(all\s+)?\bselect\b").unwrap());

/// SQL injection detector
pub struct SqlInjectionDetector {
    config: SqlInjectionConfig,
}

impl SqlInjectionDetector {
    /// Create new detector with config
    pub fn new(config: SqlInjectionConfig) -> Self {
        Self { config }
    }

    /// Create with default config
    pub fn default_config() -> Self {
        Self::new(SqlInjectionConfig::default())
    }

    fn decode_input(&self, input: &str) -> String {
        // URL decode
        let mut decoded = input.to_string();

        // Basic URL decoding
        let mut result = String::with_capacity(decoded.len());
        let mut chars = decoded.chars().peekable();

        while let Some(c) = chars.next() {
            if c == '%' {
                let hex: String = chars.by_ref().take(2).collect();
                if hex.len() == 2 {
                    if let Ok(byte) = u8::from_str_radix(&hex, 16) {
                        result.push(byte as char);
                        continue;
                    }
                }
                result.push('%');
                result.push_str(&hex);
            } else if c == '+' {
                result.push(' ');
            } else {
                result.push(c);
            }
        }

        decoded = result;

        // Remove comments for analysis
        decoded = decoded.replace("/**/", " ");

        decoded.to_lowercase()
    }

    fn calculate_score(&self, input: &str) -> (u32, Vec<&'static str>) {
        let decoded = self.decode_input(input);
        let mut score = 0u32;
        let mut indicators = Vec::new();

        // Check for UNION SELECT - high severity attack pattern
        if SQLI_UNION_SELECT.is_match(&decoded) {
            score += 6;
            indicators.push("UNION SELECT attack detected");
        }

        // Check for SQL keywords
        if SQLI_KEYWORDS.is_match(&decoded) {
            score += 3;
            indicators.push("SQL keywords detected");
        }

        // Check for boolean operators with values
        if SQLI_OPERATORS.is_match(&decoded) {
            score += 4;
            indicators.push("Boolean operator injection");
        }

        // Check for comment markers
        if SQLI_COMMENTS.is_match(&decoded) {
            score += 2;
            indicators.push("Comment markers detected");
        }

        // Check for tautologies
        if SQLI_TAUTOLOGY.is_match(&decoded) {
            score += 5;
            indicators.push("Tautology detected");
        }

        // Check for quote-based injection
        if SQLI_QUOTES.is_match(&decoded) {
            score += 4;
            indicators.push("Quote-based injection");
        }

        // Check for stacked queries
        if decoded.contains(';') && SQLI_KEYWORDS.is_match(&decoded) {
            score += 3;
            indicators.push("Stacked query attempt");
        }

        (score, indicators)
    }
}

impl Detector for SqlInjectionDetector {
    fn name(&self) -> &str {
        "SQL Injection Detector"
    }

    fn detect(&self, input: &str) -> WafResult<DetectionResult> {
        if !self.config.enabled || input.is_empty() {
            return Ok(DetectionResult::safe());
        }

        let (score, indicators) = self.calculate_score(input);

        // Threshold based on sensitivity
        let threshold = match self.config.sensitivity {
            1 => 10,
            2 => 7,
            3 => 5,
            4 => 3,
            5 => 2,
            _ => 5,
        };

        if score >= threshold {
            let confidence = (score as f64 / 15.0).min(1.0);
            Ok(DetectionResult::detected(
                "SQL Injection",
                confidence,
                input,
                &indicators.join(", "),
            ))
        } else {
            Ok(DetectionResult::safe())
        }
    }

    fn is_enabled(&self) -> bool {
        self.config.enabled
    }
}

// XSS patterns
static XSS_SCRIPT_TAG: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"(?i)<\s*script[^>]*>").unwrap());

static XSS_EVENT_HANDLER: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"(?i)\bon(abort|blur|change|click|dblclick|error|focus|keydown|keypress|keyup|load|mousedown|mousemove|mouseout|mouseover|mouseup|reset|resize|select|submit|unload|copy|cut|paste|drag|drop|scroll|wheel|contextmenu|input|invalid|search|toggle|pointerdown|pointerup|pointermove|pointerenter|pointerleave|pointercancel|gotpointercapture|lostpointercapture|touchstart|touchend|touchmove|touchcancel)\s*=").unwrap()
});

static XSS_JAVASCRIPT_PROTO: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"(?i)(javascript|vbscript|data)\s*:").unwrap());

static XSS_HTML_INJECTION: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"(?i)<\s*(img|iframe|object|embed|video|audio|source|svg|math|base|link|meta|style|form|input|button|textarea|select)[^>]*>").unwrap()
});

static XSS_EXPRESSION: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"(?i)(expression|behavior|binding|mozbinding|htc)\s*\(").unwrap());

static XSS_EVAL: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"(?i)(eval|settimeout|setinterval|function|new\s+function)\s*\(").unwrap()
});

/// XSS (Cross-Site Scripting) detector
pub struct XssDetector {
    config: XssConfig,
}

impl XssDetector {
    /// Create new detector with config
    pub fn new(config: XssConfig) -> Self {
        Self { config }
    }

    /// Create with default config
    pub fn default_config() -> Self {
        Self::new(XssConfig::default())
    }

    fn decode_input(&self, input: &str) -> String {
        let mut decoded = input.to_string();

        // URL decode
        let mut result = String::with_capacity(decoded.len());
        let mut chars = decoded.chars().peekable();

        while let Some(c) = chars.next() {
            if c == '%' {
                let hex: String = chars.by_ref().take(2).collect();
                if hex.len() == 2 {
                    if let Ok(byte) = u8::from_str_radix(&hex, 16) {
                        result.push(byte as char);
                        continue;
                    }
                }
                result.push('%');
                result.push_str(&hex);
            } else {
                result.push(c);
            }
        }
        decoded = result;

        // HTML entity decode
        let entities = [
            ("&lt;", "<"),
            ("&gt;", ">"),
            ("&amp;", "&"),
            ("&quot;", "\""),
            ("&apos;", "'"),
            ("&#x27;", "'"),
            ("&#39;", "'"),
            ("&#x3c;", "<"),
            ("&#x3e;", ">"),
            ("&#60;", "<"),
            ("&#62;", ">"),
        ];

        for (entity, replacement) in &entities {
            decoded = decoded.replace(entity, replacement);
        }

        decoded
    }

    fn calculate_score(&self, input: &str) -> (u32, Vec<&'static str>) {
        let decoded = self.decode_input(input);
        let mut score = 0u32;
        let mut indicators = Vec::new();

        // Script tag
        if XSS_SCRIPT_TAG.is_match(&decoded) {
            score += 10;
            indicators.push("Script tag detected");
        }

        // Event handlers
        if self.config.block_event_handlers && XSS_EVENT_HANDLER.is_match(&decoded) {
            score += 8;
            indicators.push("Event handler detected");
        }

        // JavaScript protocol
        if self.config.block_inline_js && XSS_JAVASCRIPT_PROTO.is_match(&decoded) {
            score += 8;
            indicators.push("JavaScript protocol detected");
        }

        // HTML injection
        if XSS_HTML_INJECTION.is_match(&decoded) {
            score += 4;
            indicators.push("HTML tag injection");
        }

        // Expression/behavior
        if XSS_EXPRESSION.is_match(&decoded) {
            score += 6;
            indicators.push("CSS expression detected");
        }

        // Eval and similar
        if XSS_EVAL.is_match(&decoded) {
            score += 5;
            indicators.push("Eval-like function detected");
        }

        // Basic angle brackets with potential payload
        if decoded.contains('<') && decoded.contains('>') {
            score += 2;
            indicators.push("HTML-like content");
        }

        (score, indicators)
    }
}

impl Detector for XssDetector {
    fn name(&self) -> &str {
        "XSS Detector"
    }

    fn detect(&self, input: &str) -> WafResult<DetectionResult> {
        if !self.config.enabled || input.is_empty() {
            return Ok(DetectionResult::safe());
        }

        let (score, indicators) = self.calculate_score(input);

        let threshold = match self.config.sensitivity {
            1 => 12,
            2 => 9,
            3 => 6,
            4 => 4,
            5 => 2,
            _ => 6,
        };

        if score >= threshold {
            let confidence = (score as f64 / 15.0).min(1.0);
            Ok(DetectionResult::detected(
                "Cross-Site Scripting (XSS)",
                confidence,
                input,
                &indicators.join(", "),
            ))
        } else {
            Ok(DetectionResult::safe())
        }
    }

    fn is_enabled(&self) -> bool {
        self.config.enabled
    }
}

// Path traversal patterns
static PATH_TRAVERSAL_BASIC: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"(\.\.[/\\]|[/\\]\.\.|\.\.;)").unwrap());

static PATH_TRAVERSAL_ENCODED: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"(?i)(%2e%2e[/\\]|[/\\]%2e%2e|%252e%252e|%c0%ae|%c1%9c)").unwrap()
});

static PATH_TRAVERSAL_NULL: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"(%00|\\x00|\\0)").unwrap());

static PATH_TRAVERSAL_SENSITIVE: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"(?i)(etc[/\\](passwd|shadow|group|hosts)|boot\.ini|win\.ini|system32|/proc/|/dev/|\.htaccess|\.htpasswd|web\.config|\.env|\.git)").unwrap()
});

/// Path traversal detector
pub struct PathTraversalDetector {
    config: PathTraversalConfig,
}

impl PathTraversalDetector {
    /// Create new detector with config
    pub fn new(config: PathTraversalConfig) -> Self {
        Self { config }
    }

    /// Create with default config
    pub fn default_config() -> Self {
        Self::new(PathTraversalConfig::default())
    }

    fn decode_input(&self, input: &str) -> String {
        let mut decoded = input.to_string();

        // Multiple rounds of URL decoding to catch double encoding
        for _ in 0..3 {
            let mut result = String::with_capacity(decoded.len());
            let mut chars = decoded.chars().peekable();
            let mut changed = false;

            while let Some(c) = chars.next() {
                if c == '%' {
                    let hex: String = chars.by_ref().take(2).collect();
                    if hex.len() == 2 {
                        if let Ok(byte) = u8::from_str_radix(&hex, 16) {
                            result.push(byte as char);
                            changed = true;
                            continue;
                        }
                    }
                    result.push('%');
                    result.push_str(&hex);
                } else {
                    result.push(c);
                }
            }

            if !changed {
                break;
            }
            decoded = result;
        }

        decoded
    }

    fn count_depth(&self, path: &str) -> usize {
        path.split(['/', '\\'])
            .filter(|s| !s.is_empty() && *s != "." && *s != "..")
            .count()
    }

    fn calculate_score(&self, input: &str) -> (u32, Vec<Cow<'static, str>>) {
        let decoded = self.decode_input(input);
        let mut score = 0u32;
        let mut indicators: Vec<Cow<'static, str>> = Vec::new();

        // Basic path traversal
        if PATH_TRAVERSAL_BASIC.is_match(&decoded) {
            score += 10;
            indicators.push(Cow::Borrowed("Path traversal sequence detected"));
        }

        // Encoded traversal
        if self.config.block_encoded && PATH_TRAVERSAL_ENCODED.is_match(input) {
            score += 8;
            indicators.push(Cow::Borrowed("Encoded path traversal"));
        }

        // Null byte injection
        if self.config.block_null_bytes && PATH_TRAVERSAL_NULL.is_match(input) {
            score += 10;
            indicators.push(Cow::Borrowed("Null byte injection"));
        }

        // Sensitive file access
        if PATH_TRAVERSAL_SENSITIVE.is_match(&decoded) {
            score += 8;
            indicators.push(Cow::Borrowed("Sensitive file access attempt"));
        }

        // Path depth check
        if self.count_depth(&decoded) > self.config.max_path_depth {
            score += 3;
            indicators.push(Cow::Borrowed("Excessive path depth"));
        }

        // Multiple .. sequences
        let traversal_count = decoded.matches("..").count();
        if traversal_count > 2 {
            score += traversal_count as u32;
            indicators.push(Cow::Owned(format!(
                "Multiple traversal sequences ({})",
                traversal_count
            )));
        }

        (score, indicators)
    }
}

impl Detector for PathTraversalDetector {
    fn name(&self) -> &str {
        "Path Traversal Detector"
    }

    fn detect(&self, input: &str) -> WafResult<DetectionResult> {
        if !self.config.enabled || input.is_empty() {
            return Ok(DetectionResult::safe());
        }

        let (score, indicators) = self.calculate_score(input);

        // Lower threshold for path traversal - it's usually pretty definitive
        let threshold = 5;

        if score >= threshold {
            let confidence = (score as f64 / 15.0).min(1.0);
            Ok(DetectionResult::detected(
                "Path Traversal",
                confidence,
                input,
                &indicators.join(", "),
            ))
        } else {
            Ok(DetectionResult::safe())
        }
    }

    fn is_enabled(&self) -> bool {
        self.config.enabled
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // SQL Injection tests
    #[test]
    fn test_sqli_detector_safe_input() {
        let detector = SqlInjectionDetector::default_config();
        let result = detector.detect("hello world").unwrap();
        assert!(!result.detected);
    }

    #[test]
    fn test_sqli_detector_basic_injection() {
        let detector = SqlInjectionDetector::default_config();

        let attacks = [
            "1' OR '1'='1",
            "'; DROP TABLE users--",
            "1 UNION SELECT * FROM users",
            "admin'--",
            "1; DELETE FROM users",
        ];

        for attack in &attacks {
            let result = detector.detect(attack).unwrap();
            assert!(result.detected, "Should detect: {}", attack);
        }
    }

    #[test]
    fn test_sqli_detector_encoded() {
        let detector = SqlInjectionDetector::default_config();
        let result = detector.detect("1%27%20OR%20%271%27%3D%271").unwrap();
        assert!(result.detected);
    }

    #[test]
    fn test_sqli_detector_tautology() {
        let detector = SqlInjectionDetector::default_config();
        let result = detector.detect("1 OR 1=1").unwrap();
        assert!(result.detected);
    }

    #[test]
    fn test_sqli_detector_disabled() {
        let config = SqlInjectionConfig {
            enabled: false,
            ..Default::default()
        };
        let detector = SqlInjectionDetector::new(config);
        let result = detector.detect("'; DROP TABLE users--").unwrap();
        assert!(!result.detected);
    }

    // XSS tests
    #[test]
    fn test_xss_detector_safe_input() {
        let detector = XssDetector::default_config();
        let result = detector.detect("Hello, World!").unwrap();
        assert!(!result.detected);
    }

    #[test]
    fn test_xss_detector_script_tag() {
        let detector = XssDetector::default_config();
        let result = detector.detect("<script>alert('xss')</script>").unwrap();
        assert!(result.detected);
        assert!(result.attack_type.contains("XSS"));
    }

    #[test]
    fn test_xss_detector_event_handler() {
        let detector = XssDetector::default_config();

        let attacks = [
            "<img onerror=alert(1)>",
            "<body onload=alert(1)>",
            "<div onclick=alert(1)>",
            "<input onfocus=alert(1)>",
        ];

        for attack in &attacks {
            let result = detector.detect(attack).unwrap();
            assert!(result.detected, "Should detect: {}", attack);
        }
    }

    #[test]
    fn test_xss_detector_javascript_protocol() {
        let detector = XssDetector::default_config();
        let result = detector.detect("javascript:alert(1)").unwrap();
        assert!(result.detected);
    }

    #[test]
    fn test_xss_detector_encoded() {
        let detector = XssDetector::default_config();
        let result = detector
            .detect("%3Cscript%3Ealert(1)%3C/script%3E")
            .unwrap();
        assert!(result.detected);
    }

    #[test]
    fn test_xss_detector_html_entities() {
        let detector = XssDetector::default_config();
        let result = detector
            .detect("&lt;script&gt;alert(1)&lt;/script&gt;")
            .unwrap();
        assert!(result.detected);
    }

    // Path traversal tests
    #[test]
    fn test_path_traversal_safe_input() {
        let detector = PathTraversalDetector::default_config();
        let result = detector.detect("/images/photo.jpg").unwrap();
        assert!(!result.detected);
    }

    #[test]
    fn test_path_traversal_basic() {
        let detector = PathTraversalDetector::default_config();

        let attacks = [
            "../../../etc/passwd",
            "..\\..\\windows\\system32",
            "/var/log/../../../etc/shadow",
            "....//....//etc/passwd",
        ];

        for attack in &attacks {
            let result = detector.detect(attack).unwrap();
            assert!(result.detected, "Should detect: {}", attack);
        }
    }

    #[test]
    fn test_path_traversal_encoded() {
        let detector = PathTraversalDetector::default_config();
        let result = detector.detect("%2e%2e%2f%2e%2e%2fetc/passwd").unwrap();
        assert!(result.detected);
    }

    #[test]
    fn test_path_traversal_null_byte() {
        let detector = PathTraversalDetector::default_config();
        let result = detector.detect("/etc/passwd%00.jpg").unwrap();
        assert!(result.detected);
    }

    #[test]
    fn test_path_traversal_sensitive_files() {
        let detector = PathTraversalDetector::default_config();

        let attacks = [
            "/etc/passwd",
            "/etc/shadow",
            "C:\\Windows\\System32\\config",
            ".htpasswd",
            ".git/config",
            ".env",
        ];

        for attack in &attacks {
            let result = detector.detect(attack).unwrap();
            assert!(result.detected, "Should detect: {}", attack);
        }
    }

    #[test]
    fn test_detection_result_methods() {
        let safe = DetectionResult::safe();
        assert!(!safe.detected);
        assert_eq!(safe.confidence, 0.0);

        let detected = DetectionResult::detected("SQLi", 0.95, "payload", "details");
        assert!(detected.detected);
        assert_eq!(detected.confidence, 0.95);
        assert_eq!(detected.attack_type, "SQLi");
    }
}
