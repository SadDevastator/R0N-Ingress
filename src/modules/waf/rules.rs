//! WAF rule definitions and compilation

use super::config::{RuleAction, RuleSeverity, WafRuleConfig};
use super::error::{WafError, WafResult};
use regex::Regex;
use serde::{Deserialize, Serialize};
use std::borrow::Cow;
use std::collections::HashMap;

/// Rule category for classification
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RuleCategory {
    /// SQL injection attacks
    SqlInjection,
    /// Cross-site scripting
    Xss,
    /// Path traversal
    PathTraversal,
    /// Local file inclusion
    Lfi,
    /// Remote file inclusion
    Rfi,
    /// Remote code execution
    Rce,
    /// Protocol attack
    ProtocolAttack,
    /// Session fixation
    SessionFixation,
    /// HTTP response splitting
    ResponseSplitting,
    /// Request smuggling
    RequestSmuggling,
    /// Scanner detection
    Scanner,
    /// Bot detection
    Bot,
    /// Custom rule
    Custom,
}

impl RuleCategory {
    /// Get OWASP CRS category prefix
    pub fn crs_prefix(&self) -> &'static str {
        match self {
            Self::SqlInjection => "942",
            Self::Xss => "941",
            Self::PathTraversal => "930",
            Self::Lfi => "930",
            Self::Rfi => "931",
            Self::Rce => "932",
            Self::ProtocolAttack => "921",
            Self::SessionFixation => "943",
            Self::ResponseSplitting => "921",
            Self::RequestSmuggling => "921",
            Self::Scanner => "913",
            Self::Bot => "913",
            Self::Custom => "900",
        }
    }
}

/// Target for rule scanning
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RuleTarget {
    /// Request URI
    Uri,
    /// Query string (raw)
    QueryString,
    /// Query parameter by name
    QueryParam(String),
    /// All query parameters
    QueryParams,
    /// Request body (raw)
    Body,
    /// Form field by name
    FormField(String),
    /// All form fields
    FormFields,
    /// JSON body path
    JsonPath(String),
    /// Request header by name
    Header(String),
    /// All headers
    Headers,
    /// Cookie by name
    Cookie(String),
    /// All cookies
    Cookies,
    /// HTTP method
    Method,
    /// Full request line
    RequestLine,
    /// User agent
    UserAgent,
    /// Content type
    ContentType,
    /// Referer header
    Referer,
}

impl RuleTarget {
    /// Parse target from string
    pub fn parse(s: &str) -> WafResult<Self> {
        let lower = s.to_lowercase();

        if let Some(name) = lower.strip_prefix("query:") {
            return Ok(Self::QueryParam(name.to_string()));
        }
        if let Some(name) = lower.strip_prefix("header:") {
            return Ok(Self::Header(name.to_string()));
        }
        if let Some(name) = lower.strip_prefix("cookie:") {
            return Ok(Self::Cookie(name.to_string()));
        }
        if let Some(name) = lower.strip_prefix("form:") {
            return Ok(Self::FormField(name.to_string()));
        }
        if let Some(path) = lower.strip_prefix("json:") {
            return Ok(Self::JsonPath(path.to_string()));
        }

        match lower.as_str() {
            "uri" | "url" | "path" => Ok(Self::Uri),
            "query_string" | "querystring" => Ok(Self::QueryString),
            "query_params" | "queryparams" => Ok(Self::QueryParams),
            "body" => Ok(Self::Body),
            "form_fields" | "formfields" => Ok(Self::FormFields),
            "headers" => Ok(Self::Headers),
            "cookies" => Ok(Self::Cookies),
            "method" => Ok(Self::Method),
            "request_line" | "requestline" => Ok(Self::RequestLine),
            "user_agent" | "useragent" => Ok(Self::UserAgent),
            "content_type" | "contenttype" => Ok(Self::ContentType),
            "referer" | "referrer" => Ok(Self::Referer),
            _ => Err(WafError::InvalidRule(format!("Unknown target: {}", s))),
        }
    }
}

/// Operator for rule matching
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Operator {
    /// Regex match
    #[default]
    Regex,
    /// Contains substring
    Contains,
    /// Equals exactly
    Equals,
    /// Starts with
    StartsWith,
    /// Ends with
    EndsWith,
    /// Greater than (numeric)
    GreaterThan,
    /// Less than (numeric)
    LessThan,
    /// IP in CIDR range
    IpMatch,
    /// String length exceeds
    LengthExceeds,
    /// Phrase match (multiple words)
    PhraseMatch,
    /// Detect SQLi
    DetectSqli,
    /// Detect XSS
    DetectXss,
}

/// Transformation to apply before matching
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Transform {
    /// Lowercase
    Lowercase,
    /// Uppercase
    Uppercase,
    /// URL decode
    UrlDecode,
    /// URL decode Unicode
    UrlDecodeUni,
    /// HTML entity decode
    HtmlEntityDecode,
    /// Remove whitespace
    RemoveWhitespace,
    /// Compress whitespace
    CompressWhitespace,
    /// Remove comments (SQL/HTML)
    RemoveComments,
    /// Remove null bytes
    RemoveNulls,
    /// Normalize path
    NormalizePath,
    /// Base64 decode
    Base64Decode,
    /// Hex decode
    HexDecode,
    /// UTF-8 to Unicode
    Utf8ToUnicode,
    /// None (no transformation)
    None,
}

impl Transform {
    /// Parse from string
    pub fn parse(s: &str) -> WafResult<Self> {
        match s.to_lowercase().as_str() {
            "lowercase" | "lower" => Ok(Self::Lowercase),
            "uppercase" | "upper" => Ok(Self::Uppercase),
            "urldecode" | "url_decode" => Ok(Self::UrlDecode),
            "urldecodeuni" | "url_decode_uni" => Ok(Self::UrlDecodeUni),
            "htmlentitydecode" | "html_entity_decode" => Ok(Self::HtmlEntityDecode),
            "removewhitespace" | "remove_whitespace" => Ok(Self::RemoveWhitespace),
            "compresswhitespace" | "compress_whitespace" => Ok(Self::CompressWhitespace),
            "removecomments" | "remove_comments" => Ok(Self::RemoveComments),
            "removenulls" | "remove_nulls" => Ok(Self::RemoveNulls),
            "normalizepath" | "normalize_path" => Ok(Self::NormalizePath),
            "base64decode" | "base64_decode" => Ok(Self::Base64Decode),
            "hexdecode" | "hex_decode" => Ok(Self::HexDecode),
            "utf8tounicode" | "utf8_to_unicode" => Ok(Self::Utf8ToUnicode),
            "none" => Ok(Self::None),
            _ => Err(WafError::InvalidRule(format!("Unknown transform: {}", s))),
        }
    }

    /// Apply transformation to input (zero-copy for no-op transforms)
    pub fn apply<'a>(&self, input: &'a str) -> Cow<'a, str> {
        match self {
            Self::None | Self::Utf8ToUnicode => Cow::Borrowed(input),
            Self::Lowercase => Cow::Owned(input.to_lowercase()),
            Self::Uppercase => Cow::Owned(input.to_uppercase()),
            Self::UrlDecode => Cow::Owned(Self::url_decode(input)),
            Self::UrlDecodeUni => Cow::Owned(Self::url_decode_uni(input)),
            Self::HtmlEntityDecode => Cow::Owned(Self::html_entity_decode(input)),
            Self::RemoveWhitespace => {
                Cow::Owned(input.chars().filter(|c| !c.is_whitespace()).collect())
            },
            Self::CompressWhitespace => Cow::Owned(Self::compress_whitespace(input)),
            Self::RemoveComments => Cow::Owned(Self::remove_comments(input)),
            Self::RemoveNulls => Cow::Owned(input.replace('\0', "")),
            Self::NormalizePath => Cow::Owned(Self::normalize_path(input)),
            Self::Base64Decode => Cow::Owned(Self::base64_decode(input)),
            Self::HexDecode => Cow::Owned(Self::hex_decode(input)),
        }
    }

    fn url_decode(input: &str) -> String {
        let mut result = String::with_capacity(input.len());
        let mut chars = input.chars().peekable();

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
        result
    }

    fn url_decode_uni(input: &str) -> String {
        let mut result = Self::url_decode(input);
        // Handle %uXXXX unicode encoding
        while let Some(pos) = result.find("%u") {
            if pos + 6 <= result.len() {
                let hex = &result[pos + 2..pos + 6];
                if let Ok(code) = u32::from_str_radix(hex, 16) {
                    if let Some(c) = char::from_u32(code) {
                        result = format!("{}{}{}", &result[..pos], c, &result[pos + 6..]);
                        continue;
                    }
                }
            }
            break;
        }
        result
    }

    fn html_entity_decode(input: &str) -> String {
        let mut result = input.to_string();
        let entities = [
            ("&lt;", "<"),
            ("&gt;", ">"),
            ("&amp;", "&"),
            ("&quot;", "\""),
            ("&apos;", "'"),
            ("&#x27;", "'"),
            ("&#39;", "'"),
            ("&#x22;", "\""),
            ("&#34;", "\""),
            ("&nbsp;", " "),
        ];

        for (entity, replacement) in &entities {
            result = result.replace(entity, replacement);
        }

        // Handle numeric entities &#NNN;
        while let Some(start) = result.find("&#") {
            if let Some(end) = result[start..].find(';') {
                let num_str = &result[start + 2..start + end];
                if let Ok(code) = if num_str.starts_with('x') || num_str.starts_with('X') {
                    u32::from_str_radix(&num_str[1..], 16)
                } else {
                    num_str.parse::<u32>()
                } {
                    if let Some(c) = char::from_u32(code) {
                        result = format!("{}{}{}", &result[..start], c, &result[start + end + 1..]);
                        continue;
                    }
                }
            }
            break;
        }
        result
    }

    fn compress_whitespace(input: &str) -> String {
        let mut result = String::with_capacity(input.len());
        let mut prev_ws = false;

        for c in input.chars() {
            if c.is_whitespace() {
                if !prev_ws {
                    result.push(' ');
                    prev_ws = true;
                }
            } else {
                result.push(c);
                prev_ws = false;
            }
        }
        result.trim().to_string()
    }

    fn remove_comments(input: &str) -> String {
        let mut result = input.to_string();

        // Remove SQL comments
        while let Some(start) = result.find("/*") {
            if let Some(end) = result[start..].find("*/") {
                result = format!("{}{}", &result[..start], &result[start + end + 2..]);
            } else {
                break;
            }
        }

        // Remove -- comments
        if let Some(pos) = result.find("--") {
            if let Some(nl) = result[pos..].find('\n') {
                result = format!("{}{}", &result[..pos], &result[pos + nl..]);
            } else {
                result = result[..pos].to_string();
            }
        }

        // Remove # comments
        if let Some(pos) = result.find('#') {
            if let Some(nl) = result[pos..].find('\n') {
                result = format!("{}{}", &result[..pos], &result[pos + nl..]);
            } else {
                result = result[..pos].to_string();
            }
        }

        result
    }

    fn normalize_path(input: &str) -> String {
        let mut parts: Vec<&str> = Vec::new();

        for part in input.split('/') {
            match part {
                "" | "." => {},
                ".." => {
                    parts.pop();
                },
                _ => parts.push(part),
            }
        }

        if input.starts_with('/') {
            format!("/{}", parts.join("/"))
        } else {
            parts.join("/")
        }
    }

    fn base64_decode(input: &str) -> String {
        use base64::Engine;
        base64::engine::general_purpose::STANDARD
            .decode(input)
            .ok()
            .and_then(|bytes| String::from_utf8(bytes).ok())
            .unwrap_or_else(|| input.to_string())
    }

    fn hex_decode(input: &str) -> String {
        let mut result = String::new();
        let chars: Vec<char> = input.chars().collect();
        let mut i = 0;

        while i < chars.len() {
            if i + 1 < chars.len() {
                let hex: String = chars[i..i + 2].iter().collect();
                if let Ok(byte) = u8::from_str_radix(&hex, 16) {
                    result.push(byte as char);
                    i += 2;
                    continue;
                }
            }
            result.push(chars[i]);
            i += 1;
        }
        result
    }
}

/// A rule definition (not yet compiled)
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RuleDefinition {
    /// Unique rule ID
    pub id: String,

    /// Description
    pub description: String,

    /// Category
    pub category: RuleCategory,

    /// Severity
    pub severity: RuleSeverity,

    /// Action
    pub action: RuleAction,

    /// Operator
    pub operator: Operator,

    /// Pattern (for regex/string matching)
    pub pattern: String,

    /// Targets to scan
    pub targets: Vec<RuleTarget>,

    /// Transformations
    pub transforms: Vec<Transform>,

    /// Tags
    pub tags: Vec<String>,

    /// Score for anomaly scoring
    pub score: u32,

    /// Whether rule is enabled
    pub enabled: bool,
}

impl RuleDefinition {
    /// Create from config
    pub fn from_config(config: &WafRuleConfig) -> WafResult<Self> {
        let targets = if config.targets.is_empty() {
            vec![RuleTarget::QueryParams, RuleTarget::Body]
        } else {
            config
                .targets
                .iter()
                .map(|t| RuleTarget::parse(t))
                .collect::<WafResult<Vec<_>>>()?
        };

        let transforms = if config.transforms.is_empty() {
            vec![Transform::Lowercase, Transform::UrlDecode]
        } else {
            config
                .transforms
                .iter()
                .map(|t| Transform::parse(t))
                .collect::<WafResult<Vec<_>>>()?
        };

        Ok(Self {
            id: config.id.clone(),
            description: config.description.clone(),
            category: RuleCategory::Custom,
            severity: config.severity,
            action: config.action,
            operator: Operator::Regex,
            pattern: config.pattern.clone(),
            targets,
            transforms,
            tags: config.tags.clone(),
            score: config.score,
            enabled: config.enabled,
        })
    }
}

/// A compiled rule ready for execution
#[derive(Debug, Clone)]
pub struct CompiledRule {
    /// Rule definition
    pub definition: RuleDefinition,

    /// Compiled regex (if applicable)
    pub regex: Option<Regex>,

    /// Phrase list (for phrase matching)
    pub phrases: Vec<String>,
}

impl CompiledRule {
    /// Compile a rule definition
    pub fn compile(definition: RuleDefinition) -> WafResult<Self> {
        let regex = match definition.operator {
            Operator::Regex | Operator::DetectSqli | Operator::DetectXss => {
                Some(Regex::new(&definition.pattern).map_err(|e| {
                    WafError::InvalidPattern(format!("Rule {}: {}", definition.id, e))
                })?)
            },
            _ => None,
        };

        let phrases = match definition.operator {
            Operator::PhraseMatch => definition
                .pattern
                .split('|')
                .map(|s| s.trim().to_lowercase())
                .collect(),
            _ => Vec::new(),
        };

        Ok(Self {
            definition,
            regex,
            phrases,
        })
    }

    /// Check if rule matches input
    pub fn matches(&self, input: &str) -> bool {
        // Apply transformations — zero-copy chain: only allocate if a transform modifies
        let mut owned: Option<String> = None;
        for transform in &self.definition.transforms {
            let current = owned.as_deref().unwrap_or(input);
            match transform.apply(current) {
                Cow::Borrowed(_) => {}, // no-op, keep current value
                Cow::Owned(new) => {
                    owned = Some(new);
                },
            }
        }
        let value = owned.as_deref().unwrap_or(input);

        match self.definition.operator {
            Operator::Regex | Operator::DetectSqli | Operator::DetectXss => {
                self.regex.as_ref().is_some_and(|re| re.is_match(value))
            },
            Operator::Contains => value.contains(&*self.definition.pattern),
            Operator::Equals => value == self.definition.pattern,
            Operator::StartsWith => value.starts_with(&*self.definition.pattern),
            Operator::EndsWith => value.ends_with(&*self.definition.pattern),
            Operator::PhraseMatch => {
                let lower = value.to_lowercase();
                self.phrases.iter().any(|p| lower.contains(p.as_str()))
            },
            Operator::LengthExceeds => self
                .definition
                .pattern
                .parse::<usize>()
                .is_ok_and(|max| value.len() > max),
            Operator::GreaterThan => {
                if let (Ok(input_val), Ok(pattern_val)) =
                    (value.parse::<f64>(), self.definition.pattern.parse::<f64>())
                {
                    input_val > pattern_val
                } else {
                    false
                }
            },
            Operator::LessThan => {
                if let (Ok(input_val), Ok(pattern_val)) =
                    (value.parse::<f64>(), self.definition.pattern.parse::<f64>())
                {
                    input_val < pattern_val
                } else {
                    false
                }
            },
            Operator::IpMatch => {
                // IP matching handled separately
                false
            },
        }
    }
}

/// A collection of rules
#[derive(Debug, Clone, Default)]
pub struct RuleSet {
    /// Rules by ID
    rules: HashMap<String, CompiledRule>,

    /// Rules by category
    by_category: HashMap<RuleCategory, Vec<String>>,

    /// Rules by tag
    by_tag: HashMap<String, Vec<String>>,
}

impl RuleSet {
    /// Create empty ruleset
    pub fn new() -> Self {
        Self::default()
    }

    /// Add a rule
    pub fn add_rule(&mut self, rule: CompiledRule) {
        let id = rule.definition.id.clone();
        let category = rule.definition.category;
        let tags = rule.definition.tags.clone();

        self.by_category
            .entry(category)
            .or_default()
            .push(id.clone());

        for tag in tags {
            self.by_tag.entry(tag).or_default().push(id.clone());
        }

        self.rules.insert(id, rule);
    }

    /// Get rule by ID
    pub fn get(&self, id: &str) -> Option<&CompiledRule> {
        self.rules.get(id)
    }

    /// Get all rules
    pub fn all_rules(&self) -> impl Iterator<Item = &CompiledRule> {
        self.rules.values()
    }

    /// Get rules by category
    pub fn by_category(&self, category: RuleCategory) -> Vec<&CompiledRule> {
        self.by_category
            .get(&category)
            .map(|ids| ids.iter().filter_map(|id| self.rules.get(id)).collect())
            .unwrap_or_default()
    }

    /// Get rules by tag
    pub fn by_tag(&self, tag: &str) -> Vec<&CompiledRule> {
        self.by_tag
            .get(tag)
            .map(|ids| ids.iter().filter_map(|id| self.rules.get(id)).collect())
            .unwrap_or_default()
    }

    /// Get enabled rules
    pub fn enabled_rules(&self) -> impl Iterator<Item = &CompiledRule> {
        self.rules.values().filter(|r| r.definition.enabled)
    }

    /// Rule count
    pub fn len(&self) -> usize {
        self.rules.len()
    }

    /// Check if empty
    pub fn is_empty(&self) -> bool {
        self.rules.is_empty()
    }

    /// Load OWASP CRS-style rules (simplified)
    pub fn load_crs_rules() -> Self {
        let mut set = Self::new();

        // Add common SQL injection rules
        let sqli_rules = Self::sqli_rules();
        for rule in sqli_rules {
            if let Ok(compiled) = CompiledRule::compile(rule) {
                set.add_rule(compiled);
            }
        }

        // Add XSS rules
        let xss_rules = Self::xss_rules();
        for rule in xss_rules {
            if let Ok(compiled) = CompiledRule::compile(rule) {
                set.add_rule(compiled);
            }
        }

        // Add path traversal rules
        let pt_rules = Self::path_traversal_rules();
        for rule in pt_rules {
            if let Ok(compiled) = CompiledRule::compile(rule) {
                set.add_rule(compiled);
            }
        }

        set
    }

    fn sqli_rules() -> Vec<RuleDefinition> {
        vec![
            RuleDefinition {
                id: "942100".to_string(),
                description: "SQL Injection Attack Detected via libinjection".to_string(),
                category: RuleCategory::SqlInjection,
                severity: RuleSeverity::Critical,
                action: RuleAction::Block,
                operator: Operator::DetectSqli,
                pattern: r"(?i)(\b(select|insert|update|delete|drop|union|alter|create|truncate)\b.*\b(from|into|set|table|database)\b)".to_string(),
                targets: vec![RuleTarget::QueryParams, RuleTarget::Body],
                transforms: vec![Transform::Lowercase, Transform::UrlDecode, Transform::RemoveComments],
                tags: vec!["sqli".to_string(), "owasp".to_string()],
                score: 10,
                enabled: true,
            },
            RuleDefinition {
                id: "942110".to_string(),
                description: "SQL Injection Attack: Common Injection Testing Detected".to_string(),
                category: RuleCategory::SqlInjection,
                severity: RuleSeverity::High,
                action: RuleAction::Block,
                operator: Operator::Regex,
                pattern: r#"(?i)('|"|;|--|#|/[*]|[*]/|@@|@|\bchar\s*\(|\bexec\s*\(|\bexecute\s*\(|\bsp_|\bxp_)"#.to_string(),
                targets: vec![RuleTarget::QueryParams, RuleTarget::Body],
                transforms: vec![Transform::UrlDecode],
                tags: vec!["sqli".to_string()],
                score: 5,
                enabled: true,
            },
            RuleDefinition {
                id: "942120".to_string(),
                description: "SQL Injection Attack: SQL Operator Detected".to_string(),
                category: RuleCategory::SqlInjection,
                severity: RuleSeverity::Medium,
                action: RuleAction::Block,
                operator: Operator::Regex,
                pattern: r#"(?i)\b(and|or)\b\s+\d+\s*[=<>]|\b(and|or)\b\s+['"]?\w+['"]?\s*[=<>]"#.to_string(),
                targets: vec![RuleTarget::QueryParams],
                transforms: vec![Transform::Lowercase, Transform::UrlDecode],
                tags: vec!["sqli".to_string()],
                score: 3,
                enabled: true,
            },
            RuleDefinition {
                id: "942130".to_string(),
                description: "SQL Injection: Tautology Detected".to_string(),
                category: RuleCategory::SqlInjection,
                severity: RuleSeverity::High,
                action: RuleAction::Block,
                operator: Operator::Regex,
                pattern: r#"(?i)\b(or|and)\s+['"]?\d+['"]?\s*=\s*['"]?\d+['"]?|\b1\s*=\s*1\b|\btrue\s*=\s*true\b"#.to_string(),
                targets: vec![RuleTarget::QueryParams, RuleTarget::Body],
                transforms: vec![Transform::Lowercase, Transform::UrlDecode],
                tags: vec!["sqli".to_string()],
                score: 5,
                enabled: true,
            },
        ]
    }

    fn xss_rules() -> Vec<RuleDefinition> {
        vec![
            RuleDefinition {
                id: "941100".to_string(),
                description: "XSS Attack Detected via libinjection".to_string(),
                category: RuleCategory::Xss,
                severity: RuleSeverity::Critical,
                action: RuleAction::Block,
                operator: Operator::DetectXss,
                pattern: r"(?i)(<script[^>]*>|</script>|javascript:|on\w+\s*=)".to_string(),
                targets: vec![RuleTarget::QueryParams, RuleTarget::Body],
                transforms: vec![Transform::HtmlEntityDecode, Transform::UrlDecode],
                tags: vec!["xss".to_string(), "owasp".to_string()],
                score: 10,
                enabled: true,
            },
            RuleDefinition {
                id: "941110".to_string(),
                description: "XSS Filter - Category 1: Script Tag Vector".to_string(),
                category: RuleCategory::Xss,
                severity: RuleSeverity::High,
                action: RuleAction::Block,
                operator: Operator::Regex,
                pattern: r"(?i)<script[^>]*>[\s\S]*?</script>".to_string(),
                targets: vec![RuleTarget::QueryParams, RuleTarget::Body],
                transforms: vec![Transform::HtmlEntityDecode],
                tags: vec!["xss".to_string()],
                score: 5,
                enabled: true,
            },
            RuleDefinition {
                id: "941120".to_string(),
                description: "XSS Filter - Category 2: Event Handler Vector".to_string(),
                category: RuleCategory::Xss,
                severity: RuleSeverity::High,
                action: RuleAction::Block,
                operator: Operator::Regex,
                pattern: r"(?i)\b(on(abort|blur|change|click|dblclick|error|focus|keydown|keypress|keyup|load|mousedown|mousemove|mouseout|mouseover|mouseup|reset|resize|select|submit|unload))\s*=".to_string(),
                targets: vec![RuleTarget::QueryParams, RuleTarget::Body],
                transforms: vec![Transform::HtmlEntityDecode, Transform::UrlDecode],
                tags: vec!["xss".to_string()],
                score: 5,
                enabled: true,
            },
            RuleDefinition {
                id: "941130".to_string(),
                description: "XSS Filter - Category 3: JavaScript Protocol".to_string(),
                category: RuleCategory::Xss,
                severity: RuleSeverity::High,
                action: RuleAction::Block,
                operator: Operator::Regex,
                pattern: r"(?i)(javascript|vbscript|data):\s*[^,]".to_string(),
                targets: vec![RuleTarget::QueryParams, RuleTarget::Body, RuleTarget::Headers],
                transforms: vec![Transform::HtmlEntityDecode, Transform::UrlDecode],
                tags: vec!["xss".to_string()],
                score: 5,
                enabled: true,
            },
            RuleDefinition {
                id: "941140".to_string(),
                description: "XSS Filter - Category 4: Img Tag Vector".to_string(),
                category: RuleCategory::Xss,
                severity: RuleSeverity::Medium,
                action: RuleAction::Block,
                operator: Operator::Regex,
                pattern: r"(?i)<img[^>]+\bonerror\s*=".to_string(),
                targets: vec![RuleTarget::QueryParams, RuleTarget::Body],
                transforms: vec![Transform::HtmlEntityDecode],
                tags: vec!["xss".to_string()],
                score: 3,
                enabled: true,
            },
        ]
    }

    fn path_traversal_rules() -> Vec<RuleDefinition> {
        vec![
            RuleDefinition {
                id: "930100".to_string(),
                description: "Path Traversal Attack (/../)".to_string(),
                category: RuleCategory::PathTraversal,
                severity: RuleSeverity::Critical,
                action: RuleAction::Block,
                operator: Operator::Regex,
                pattern: r"(\.\.[/\\]|[/\\]\.\.|\.\.([;,]|%[0-9a-fA-F]{2}))".to_string(),
                targets: vec![RuleTarget::Uri, RuleTarget::QueryParams],
                transforms: vec![Transform::UrlDecode, Transform::NormalizePath],
                tags: vec!["lfi".to_string(), "path-traversal".to_string()],
                score: 10,
                enabled: true,
            },
            RuleDefinition {
                id: "930110".to_string(),
                description: "Path Traversal Attack: Encoded Traversal".to_string(),
                category: RuleCategory::PathTraversal,
                severity: RuleSeverity::High,
                action: RuleAction::Block,
                operator: Operator::Regex,
                pattern: r"(?i)(%2e%2e[/\\]|[/\\]%2e%2e|%252e%252e|%c0%ae%c0%ae)".to_string(),
                targets: vec![RuleTarget::Uri, RuleTarget::QueryParams],
                transforms: vec![Transform::UrlDecodeUni],
                tags: vec!["lfi".to_string()],
                score: 5,
                enabled: true,
            },
            RuleDefinition {
                id: "930120".to_string(),
                description: "OS File Access Attempt".to_string(),
                category: RuleCategory::PathTraversal,
                severity: RuleSeverity::High,
                action: RuleAction::Block,
                operator: Operator::Regex,
                pattern: r"(?i)(etc/(passwd|shadow|group|hosts)|boot\.ini|win\.ini|system32|/proc/|/dev/)".to_string(),
                targets: vec![RuleTarget::Uri, RuleTarget::QueryParams, RuleTarget::Body],
                transforms: vec![Transform::Lowercase, Transform::UrlDecode, Transform::NormalizePath],
                tags: vec!["lfi".to_string()],
                score: 5,
                enabled: true,
            },
            RuleDefinition {
                id: "930130".to_string(),
                description: "Null Byte Injection".to_string(),
                category: RuleCategory::PathTraversal,
                severity: RuleSeverity::High,
                action: RuleAction::Block,
                operator: Operator::Regex,
                pattern: r"(%00|\\x00|\\0)".to_string(),
                targets: vec![RuleTarget::Uri, RuleTarget::QueryParams],
                transforms: vec![Transform::UrlDecode],
                tags: vec!["injection".to_string()],
                score: 5,
                enabled: true,
            },
        ]
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_rule_target_parse() {
        assert!(matches!(RuleTarget::parse("uri"), Ok(RuleTarget::Uri)));
        assert!(matches!(RuleTarget::parse("body"), Ok(RuleTarget::Body)));
        assert!(matches!(
            RuleTarget::parse("query:id"),
            Ok(RuleTarget::QueryParam(_))
        ));
        assert!(matches!(
            RuleTarget::parse("header:Authorization"),
            Ok(RuleTarget::Header(_))
        ));
    }

    #[test]
    fn test_transform_lowercase() {
        assert_eq!(Transform::Lowercase.apply("HELLO"), "hello");
        assert_eq!(Transform::Uppercase.apply("hello"), "HELLO");
    }

    #[test]
    fn test_transform_url_decode() {
        assert_eq!(Transform::UrlDecode.apply("%20"), " ");
        assert_eq!(Transform::UrlDecode.apply("hello%20world"), "hello world");
        assert_eq!(Transform::UrlDecode.apply("%3Cscript%3E"), "<script>");
    }

    #[test]
    fn test_transform_html_entity_decode() {
        assert_eq!(Transform::HtmlEntityDecode.apply("&lt;"), "<");
        assert_eq!(Transform::HtmlEntityDecode.apply("&gt;"), ">");
        assert_eq!(
            Transform::HtmlEntityDecode.apply("&lt;script&gt;"),
            "<script>"
        );
    }

    #[test]
    fn test_transform_remove_comments() {
        assert_eq!(
            Transform::RemoveComments.apply("SELECT /* comment */ *"),
            "SELECT  *"
        );
        assert_eq!(Transform::RemoveComments.apply("id=1--comment"), "id=1");
    }

    #[test]
    fn test_transform_normalize_path() {
        assert_eq!(Transform::NormalizePath.apply("/a/b/../c"), "/a/c");
        assert_eq!(Transform::NormalizePath.apply("/a/./b/./c"), "/a/b/c");
        assert_eq!(
            Transform::NormalizePath.apply("/../../../etc/passwd"),
            "/etc/passwd"
        );
    }

    #[test]
    fn test_compiled_rule_regex_match() {
        let definition = RuleDefinition {
            id: "test-1".to_string(),
            description: "Test rule".to_string(),
            category: RuleCategory::Custom,
            severity: RuleSeverity::Medium,
            action: RuleAction::Block,
            operator: Operator::Regex,
            pattern: r"<script>".to_string(),
            targets: vec![RuleTarget::Body],
            transforms: vec![Transform::Lowercase],
            tags: vec![],
            score: 5,
            enabled: true,
        };

        let rule = CompiledRule::compile(definition).unwrap();
        assert!(rule.matches("<SCRIPT>"));
        assert!(rule.matches("<script>"));
        assert!(!rule.matches("hello"));
    }

    #[test]
    fn test_compiled_rule_contains() {
        let definition = RuleDefinition {
            id: "test-2".to_string(),
            description: "Test contains".to_string(),
            category: RuleCategory::Custom,
            severity: RuleSeverity::Low,
            action: RuleAction::Log,
            operator: Operator::Contains,
            pattern: "admin".to_string(),
            targets: vec![RuleTarget::Uri],
            transforms: vec![Transform::Lowercase],
            tags: vec![],
            score: 1,
            enabled: true,
        };

        let rule = CompiledRule::compile(definition).unwrap();
        assert!(rule.matches("user=ADMIN"));
        assert!(rule.matches("/admin/panel"));
        assert!(!rule.matches("/user/panel"));
    }

    #[test]
    fn test_ruleset_operations() {
        let mut set = RuleSet::new();

        let rule1 = CompiledRule::compile(RuleDefinition {
            id: "rule-1".to_string(),
            description: "Rule 1".to_string(),
            category: RuleCategory::SqlInjection,
            severity: RuleSeverity::High,
            action: RuleAction::Block,
            operator: Operator::Contains,
            pattern: "test".to_string(),
            targets: vec![],
            transforms: vec![],
            tags: vec!["sqli".to_string()],
            score: 5,
            enabled: true,
        })
        .unwrap();

        set.add_rule(rule1);

        assert_eq!(set.len(), 1);
        assert!(set.get("rule-1").is_some());
        assert_eq!(set.by_category(RuleCategory::SqlInjection).len(), 1);
        assert_eq!(set.by_tag("sqli").len(), 1);
    }

    #[test]
    fn test_load_crs_rules() {
        let set = RuleSet::load_crs_rules();
        assert!(!set.is_empty());
        assert!(!set.by_category(RuleCategory::SqlInjection).is_empty());
        assert!(!set.by_category(RuleCategory::Xss).is_empty());
        assert!(!set.by_category(RuleCategory::PathTraversal).is_empty());
    }

    #[test]
    fn test_sqli_detection() {
        let set = RuleSet::load_crs_rules();
        let sqli_rules: Vec<_> = set.by_category(RuleCategory::SqlInjection);

        // Test common SQL injection patterns
        let attacks = [
            "1' OR '1'='1",
            "'; DROP TABLE users--",
            "1 UNION SELECT * FROM users",
            "admin'--",
        ];

        for attack in &attacks {
            let matched = sqli_rules.iter().any(|r| r.matches(attack));
            assert!(matched, "Should detect SQLi: {}", attack);
        }
    }

    #[test]
    fn test_xss_detection() {
        let set = RuleSet::load_crs_rules();
        let xss_rules: Vec<_> = set.by_category(RuleCategory::Xss);

        let attacks = [
            "<script>alert(1)</script>",
            "javascript:alert(1)",
            "<img onerror=alert(1)>",
            "<body onload=alert(1)>",
        ];

        for attack in &attacks {
            let matched = xss_rules.iter().any(|r| r.matches(attack));
            assert!(matched, "Should detect XSS: {}", attack);
        }
    }

    #[test]
    fn test_path_traversal_detection() {
        let set = RuleSet::load_crs_rules();
        let pt_rules: Vec<_> = set.by_category(RuleCategory::PathTraversal);

        let attacks = [
            "../../../etc/passwd",
            "..\\..\\windows\\system32",
            "%2e%2e%2fetc/passwd",
            "/etc/passwd%00.jpg",
        ];

        for attack in &attacks {
            let matched = pt_rules.iter().any(|r| r.matches(attack));
            assert!(matched, "Should detect path traversal: {}", attack);
        }
    }
}
