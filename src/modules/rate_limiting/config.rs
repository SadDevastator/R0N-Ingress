//! Configuration for rate limiting.

use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::time::Duration;

/// Main configuration for the rate limiting module.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RateLimitConfig {
    /// Whether rate limiting is enabled.
    #[serde(default = "default_enabled")]
    pub enabled: bool,

    /// Default rate limit applied to all requests.
    #[serde(default)]
    pub default_limit: Option<RateLimitRule>,

    /// Per-route rate limit rules.
    #[serde(default)]
    pub routes: HashMap<String, RateLimitRule>,

    /// Per-IP rate limiting configuration.
    #[serde(default)]
    pub per_ip: Option<PerIpConfig>,

    /// Distributed rate limiting configuration.
    #[serde(default)]
    pub distributed: Option<DistributedConfig>,

    /// How to extract client identity for rate limiting.
    #[serde(default)]
    pub identity_extraction: IdentityExtraction,

    /// Action to take when rate limited.
    #[serde(default)]
    pub exceeded_action: ExceededAction,

    /// Headers to add to responses.
    #[serde(default)]
    pub response_headers: ResponseHeadersConfig,
}

fn default_enabled() -> bool {
    true
}

impl Default for RateLimitConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            default_limit: Some(RateLimitRule::default()),
            routes: HashMap::new(),
            per_ip: Some(PerIpConfig::default()),
            distributed: None,
            identity_extraction: IdentityExtraction::default(),
            exceeded_action: ExceededAction::default(),
            response_headers: ResponseHeadersConfig::default(),
        }
    }
}

impl RateLimitConfig {
    /// Create a new rate limit config.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Set the default rate limit.
    #[must_use]
    pub fn with_default_limit(mut self, limit: RateLimitRule) -> Self {
        self.default_limit = Some(limit);
        self
    }

    /// Add a route-specific limit.
    #[must_use]
    pub fn with_route_limit(mut self, route: impl Into<String>, limit: RateLimitRule) -> Self {
        self.routes.insert(route.into(), limit);
        self
    }

    /// Enable per-IP limiting.
    #[must_use]
    pub fn with_per_ip(mut self, config: PerIpConfig) -> Self {
        self.per_ip = Some(config);
        self
    }

    /// Enable distributed rate limiting.
    #[must_use]
    pub fn with_distributed(mut self, config: DistributedConfig) -> Self {
        self.distributed = Some(config);
        self
    }

    /// Validate the configuration.
    pub fn validate(&self) -> Result<(), String> {
        if let Some(ref limit) = self.default_limit {
            limit.validate()?;
        }

        for (route, limit) in &self.routes {
            limit
                .validate()
                .map_err(|e| format!("route {route}: {e}"))?;
        }

        if let Some(ref per_ip) = self.per_ip {
            per_ip.validate()?;
        }

        if let Some(ref distributed) = self.distributed {
            distributed.validate()?;
        }

        Ok(())
    }
}

/// A single rate limit rule using token bucket.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RateLimitRule {
    /// Maximum tokens (burst capacity).
    #[serde(default = "default_max_tokens")]
    pub max_tokens: u64,

    /// Token refill rate (tokens per second).
    #[serde(default = "default_refill_rate")]
    pub refill_rate: f64,

    /// Tokens consumed per request.
    #[serde(default = "default_tokens_per_request")]
    pub tokens_per_request: u64,

    /// Scope of the limit.
    #[serde(default)]
    pub scope: LimitScope,

    /// Optional: Override action when this specific rule is exceeded.
    #[serde(default)]
    pub exceeded_action: Option<ExceededAction>,
}

fn default_max_tokens() -> u64 {
    100
}

fn default_refill_rate() -> f64 {
    10.0
}

fn default_tokens_per_request() -> u64 {
    1
}

impl Default for RateLimitRule {
    fn default() -> Self {
        Self {
            max_tokens: 100,
            refill_rate: 10.0,
            tokens_per_request: 1,
            scope: LimitScope::default(),
            exceeded_action: None,
        }
    }
}

impl RateLimitRule {
    /// Create a new rate limit rule.
    #[must_use]
    pub fn new(max_tokens: u64, refill_rate: f64) -> Self {
        Self {
            max_tokens,
            refill_rate,
            ..Default::default()
        }
    }

    /// Set tokens per request.
    #[must_use]
    pub fn with_tokens_per_request(mut self, tokens: u64) -> Self {
        self.tokens_per_request = tokens;
        self
    }

    /// Set the scope.
    #[must_use]
    pub fn with_scope(mut self, scope: LimitScope) -> Self {
        self.scope = scope;
        self
    }

    /// Validate the rule.
    pub fn validate(&self) -> Result<(), String> {
        if self.max_tokens == 0 {
            return Err("max_tokens must be greater than 0".to_string());
        }

        if self.refill_rate <= 0.0 {
            return Err("refill_rate must be greater than 0".to_string());
        }

        if self.tokens_per_request == 0 {
            return Err("tokens_per_request must be greater than 0".to_string());
        }

        if self.tokens_per_request > self.max_tokens {
            return Err("tokens_per_request cannot exceed max_tokens".to_string());
        }

        Ok(())
    }

    /// Calculate time until the bucket would have enough tokens.
    #[must_use]
    pub fn time_until_available(&self, current_tokens: f64, required: u64) -> Duration {
        if current_tokens >= required as f64 {
            return Duration::ZERO;
        }

        let needed = required as f64 - current_tokens;
        let seconds = needed / self.refill_rate;
        Duration::from_secs_f64(seconds)
    }
}

/// Scope of rate limiting.
#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq, Eq, Hash)]
pub enum LimitScope {
    /// Apply limit globally across all clients.
    #[default]
    Global,

    /// Apply limit per client IP.
    PerIp,

    /// Apply limit per authenticated user.
    PerUser,

    /// Apply limit per API key.
    PerApiKey,

    /// Apply limit per custom header value.
    PerHeader(String),

    /// Composite: apply multiple scopes.
    Composite(Vec<LimitScope>),
}

impl LimitScope {
    /// Extract the rate limit key from request context.
    #[must_use]
    pub fn extract_key(
        &self,
        ip: Option<&str>,
        user: Option<&str>,
        headers: &HashMap<String, String>,
    ) -> String {
        match self {
            Self::Global => "global".to_string(),
            Self::PerIp => ip.unwrap_or("unknown").to_string(),
            Self::PerUser => user.unwrap_or("anonymous").to_string(),
            Self::PerApiKey => headers
                .get("x-api-key")
                .or_else(|| headers.get("authorization"))
                .cloned()
                .unwrap_or_else(|| "no-key".to_string()),
            Self::PerHeader(header_name) => headers
                .get(header_name)
                .cloned()
                .unwrap_or_else(|| format!("no-{header_name}")),
            Self::Composite(scopes) => scopes
                .iter()
                .map(|s| s.extract_key(ip, user, headers))
                .collect::<Vec<_>>()
                .join(":"),
        }
    }
}

/// Configuration for per-IP rate limiting.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PerIpConfig {
    /// Whether per-IP limiting is enabled.
    #[serde(default = "default_enabled")]
    pub enabled: bool,

    /// Maximum requests per window.
    #[serde(default = "default_max_requests")]
    pub max_requests: u64,

    /// Refill rate (requests per second).
    #[serde(default = "default_refill_rate")]
    pub refill_rate: f64,

    /// IPs to whitelist from rate limiting.
    #[serde(default)]
    pub whitelist: Vec<String>,

    /// IPs to blacklist (always reject).
    #[serde(default)]
    pub blacklist: Vec<String>,

    /// Whether to trust X-Forwarded-For header.
    #[serde(default)]
    pub trust_forwarded_for: bool,
}

fn default_max_requests() -> u64 {
    1000
}

impl Default for PerIpConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            max_requests: 1000,
            refill_rate: 100.0,
            whitelist: Vec::new(),
            blacklist: Vec::new(),
            trust_forwarded_for: false,
        }
    }
}

impl PerIpConfig {
    /// Validate the configuration.
    pub fn validate(&self) -> Result<(), String> {
        if self.max_requests == 0 {
            return Err("per_ip.max_requests must be greater than 0".to_string());
        }

        if self.refill_rate <= 0.0 {
            return Err("per_ip.refill_rate must be greater than 0".to_string());
        }

        Ok(())
    }

    /// Check if an IP is whitelisted.
    #[must_use]
    pub fn is_whitelisted(&self, ip: &str) -> bool {
        self.whitelist.iter().any(|w| ip_matches(ip, w))
    }

    /// Check if an IP is blacklisted.
    #[must_use]
    pub fn is_blacklisted(&self, ip: &str) -> bool {
        self.blacklist.iter().any(|b| ip_matches(ip, b))
    }
}

/// Check if an IP matches a pattern (supports CIDR notation).
fn ip_matches(ip: &str, pattern: &str) -> bool {
    if pattern.contains('/') {
        // CIDR notation - simplified prefix check
        if let Some((network, bits_str)) = pattern.split_once('/') {
            // Parse network and IP as octets
            let network_octets: Vec<u8> =
                network.split('.').filter_map(|s| s.parse().ok()).collect();
            let ip_octets: Vec<u8> = ip.split('.').filter_map(|s| s.parse().ok()).collect();

            if network_octets.len() != 4 || ip_octets.len() != 4 {
                return false;
            }

            let bits: u32 = bits_str.parse().unwrap_or(32);
            let mask = if bits >= 32 {
                u32::MAX
            } else {
                !((1u32 << (32 - bits)) - 1)
            };

            let network_u32 = u32::from_be_bytes([
                network_octets[0],
                network_octets[1],
                network_octets[2],
                network_octets[3],
            ]);
            let ip_u32 =
                u32::from_be_bytes([ip_octets[0], ip_octets[1], ip_octets[2], ip_octets[3]]);

            (network_u32 & mask) == (ip_u32 & mask)
        } else {
            false
        }
    } else {
        ip == pattern
    }
}

/// Configuration for distributed rate limiting.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct DistributedConfig {
    /// Backend to use for distributed state.
    #[serde(default)]
    pub backend: DistributedBackend,

    /// Redis configuration (if using Redis backend).
    pub redis: Option<RedisConfig>,

    /// Sync interval for pushing local counts.
    #[serde(default = "default_sync_interval", with = "humantime_serde")]
    pub sync_interval: Duration,

    /// Key prefix for distributed keys.
    #[serde(default = "default_key_prefix")]
    pub key_prefix: String,

    /// TTL for distributed keys.
    #[serde(default = "default_key_ttl", with = "humantime_serde")]
    pub key_ttl: Duration,
}

fn default_sync_interval() -> Duration {
    Duration::from_secs(1)
}

fn default_key_prefix() -> String {
    "r0n:ratelimit".to_string()
}

fn default_key_ttl() -> Duration {
    Duration::from_secs(3600)
}

impl Default for DistributedConfig {
    fn default() -> Self {
        Self {
            backend: DistributedBackend::Local,
            redis: None,
            sync_interval: default_sync_interval(),
            key_prefix: default_key_prefix(),
            key_ttl: default_key_ttl(),
        }
    }
}

impl DistributedConfig {
    /// Validate the configuration.
    pub fn validate(&self) -> Result<(), String> {
        match self.backend {
            DistributedBackend::Redis => {
                if self.redis.is_none() {
                    return Err("redis configuration required when using Redis backend".to_string());
                }
                if let Some(ref redis) = self.redis {
                    redis.validate()?;
                }
            },
            DistributedBackend::Local => {},
        }

        Ok(())
    }
}

/// Backend type for distributed rate limiting.
#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub enum DistributedBackend {
    /// Local in-memory state (no distribution).
    #[default]
    Local,

    /// Redis-based distributed state.
    Redis,
}

/// Redis configuration for distributed rate limiting.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RedisConfig {
    /// Redis connection URL.
    pub url: String,

    /// Connection pool size.
    #[serde(default = "default_pool_size")]
    pub pool_size: usize,

    /// Connection timeout.
    #[serde(default = "default_connection_timeout", with = "humantime_serde")]
    pub connection_timeout: Duration,

    /// Read timeout.
    #[serde(default = "default_read_timeout", with = "humantime_serde")]
    pub read_timeout: Duration,
}

fn default_pool_size() -> usize {
    10
}

fn default_connection_timeout() -> Duration {
    Duration::from_secs(5)
}

fn default_read_timeout() -> Duration {
    Duration::from_millis(100)
}

impl Default for RedisConfig {
    fn default() -> Self {
        Self {
            url: "redis://localhost:6379".to_string(),
            pool_size: 10,
            connection_timeout: default_connection_timeout(),
            read_timeout: default_read_timeout(),
        }
    }
}

impl RedisConfig {
    /// Validate the configuration.
    pub fn validate(&self) -> Result<(), String> {
        if self.url.is_empty() {
            return Err("redis.url cannot be empty".to_string());
        }

        if !self.url.starts_with("redis://") && !self.url.starts_with("rediss://") {
            return Err("redis.url must start with redis:// or rediss://".to_string());
        }

        if self.pool_size == 0 {
            return Err("redis.pool_size must be greater than 0".to_string());
        }

        Ok(())
    }
}

/// How to extract client identity for rate limiting.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct IdentityExtraction {
    /// Headers to check for client IP (in priority order).
    #[serde(default = "default_ip_headers")]
    pub ip_headers: Vec<String>,

    /// Headers to check for user identity.
    #[serde(default = "default_user_headers")]
    pub user_headers: Vec<String>,

    /// Header for API key.
    #[serde(default = "default_api_key_header")]
    pub api_key_header: String,
}

fn default_ip_headers() -> Vec<String> {
    vec!["X-Real-IP".to_string(), "X-Forwarded-For".to_string()]
}

fn default_user_headers() -> Vec<String> {
    vec!["X-User-ID".to_string(), "X-Authenticated-User".to_string()]
}

fn default_api_key_header() -> String {
    "X-API-Key".to_string()
}

/// Action to take when rate limit is exceeded.
#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub enum ExceededAction {
    /// Reject the request with 429 Too Many Requests.
    #[default]
    Reject,

    /// Allow but log the request.
    Log,

    /// Queue the request for later processing.
    Queue,

    /// Apply a delay before processing.
    Delay,
}

/// Configuration for response headers.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ResponseHeadersConfig {
    /// Include rate limit headers in responses.
    #[serde(default = "default_enabled")]
    pub include_headers: bool,

    /// Header name for rate limit.
    #[serde(default = "default_limit_header")]
    pub limit_header: String,

    /// Header name for remaining tokens.
    #[serde(default = "default_remaining_header")]
    pub remaining_header: String,

    /// Header name for reset time.
    #[serde(default = "default_reset_header")]
    pub reset_header: String,

    /// Header name for retry-after.
    #[serde(default = "default_retry_after_header")]
    pub retry_after_header: String,
}

fn default_limit_header() -> String {
    "X-RateLimit-Limit".to_string()
}

fn default_remaining_header() -> String {
    "X-RateLimit-Remaining".to_string()
}

fn default_reset_header() -> String {
    "X-RateLimit-Reset".to_string()
}

fn default_retry_after_header() -> String {
    "Retry-After".to_string()
}

impl Default for ResponseHeadersConfig {
    fn default() -> Self {
        Self {
            include_headers: true,
            limit_header: default_limit_header(),
            remaining_header: default_remaining_header(),
            reset_header: default_reset_header(),
            retry_after_header: default_retry_after_header(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_default_config() {
        let config = RateLimitConfig::default();
        assert!(config.enabled);
        assert!(config.default_limit.is_some());
        assert!(config.per_ip.is_some());
        assert!(config.distributed.is_none());
    }

    #[test]
    fn test_rate_limit_rule_validation() {
        let rule = RateLimitRule::new(100, 10.0);
        assert!(rule.validate().is_ok());

        let bad_rule = RateLimitRule::new(0, 10.0);
        assert!(bad_rule.validate().is_err());

        let bad_rule = RateLimitRule::new(100, 0.0);
        assert!(bad_rule.validate().is_err());
    }

    #[test]
    fn test_limit_scope_extract_key() {
        let headers = HashMap::from([
            ("x-api-key".to_string(), "key123".to_string()),
            ("custom-header".to_string(), "custom-value".to_string()),
        ]);

        assert_eq!(
            LimitScope::Global.extract_key(Some("1.2.3.4"), None, &headers),
            "global"
        );

        assert_eq!(
            LimitScope::PerIp.extract_key(Some("1.2.3.4"), None, &headers),
            "1.2.3.4"
        );

        assert_eq!(
            LimitScope::PerUser.extract_key(None, Some("user123"), &headers),
            "user123"
        );

        assert_eq!(
            LimitScope::PerApiKey.extract_key(None, None, &headers),
            "key123"
        );

        assert_eq!(
            LimitScope::PerHeader("custom-header".to_string()).extract_key(None, None, &headers),
            "custom-value"
        );
    }

    #[test]
    fn test_per_ip_whitelist_blacklist() {
        let config = PerIpConfig {
            whitelist: vec!["127.0.0.1".to_string(), "10.0.0.0/8".to_string()],
            blacklist: vec!["192.168.1.100".to_string()],
            ..Default::default()
        };

        assert!(config.is_whitelisted("127.0.0.1"));
        assert!(!config.is_whitelisted("192.168.1.1"));
        assert!(config.is_blacklisted("192.168.1.100"));
        assert!(!config.is_blacklisted("192.168.1.1"));
    }

    #[test]
    fn test_time_until_available() {
        let rule = RateLimitRule::new(100, 10.0);

        // Have enough tokens
        assert_eq!(rule.time_until_available(50.0, 10), Duration::ZERO);

        // Need more tokens
        let wait = rule.time_until_available(5.0, 15);
        assert!(wait > Duration::ZERO);
        assert!(wait <= Duration::from_secs(1));
    }

    #[test]
    fn test_redis_config_validation() {
        let config = RedisConfig::default();
        assert!(config.validate().is_ok());

        let bad_config = RedisConfig {
            url: "".to_string(),
            ..Default::default()
        };
        assert!(bad_config.validate().is_err());

        let bad_config = RedisConfig {
            url: "http://localhost:6379".to_string(),
            ..Default::default()
        };
        assert!(bad_config.validate().is_err());
    }

    #[test]
    fn test_distributed_config_validation() {
        let config = DistributedConfig {
            backend: DistributedBackend::Local,
            ..Default::default()
        };
        assert!(config.validate().is_ok());

        let config = DistributedConfig {
            backend: DistributedBackend::Redis,
            redis: Some(RedisConfig::default()),
            ..Default::default()
        };
        assert!(config.validate().is_ok());

        let bad_config = DistributedConfig {
            backend: DistributedBackend::Redis,
            redis: None,
            ..Default::default()
        };
        assert!(bad_config.validate().is_err());
    }

    #[test]
    fn test_config_builder_pattern() {
        let config = RateLimitConfig::new()
            .with_default_limit(RateLimitRule::new(1000, 100.0))
            .with_route_limit("/api/expensive", RateLimitRule::new(10, 1.0))
            .with_per_ip(PerIpConfig::default());

        assert!(config.default_limit.is_some());
        assert!(config.routes.contains_key("/api/expensive"));
        assert!(config.per_ip.is_some());
    }
}
