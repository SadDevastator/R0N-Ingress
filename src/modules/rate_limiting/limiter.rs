//! Rate limiter with multi-level limits.

use super::bucket::TokenBucket;
use super::config::{LimitScope, PerIpConfig, RateLimitConfig, RateLimitRule};
use std::borrow::Cow;
use std::collections::HashMap;
use std::fmt::Write;
use std::sync::{Arc, RwLock};
use std::time::{Duration, Instant};

/// Decision from rate limit check.
#[derive(Debug, Clone)]
pub struct RateLimitDecision {
    /// Whether the request is allowed.
    pub allowed: bool,

    /// Current token count.
    pub tokens_remaining: u64,

    /// Maximum tokens (limit).
    pub tokens_limit: u64,

    /// Time until reset/refill.
    pub reset_after: Duration,

    /// Which limiter made the decision.
    pub limiter_key: Cow<'static, str>,

    /// The scope that was applied.
    pub scope: LimitScope,
}

impl RateLimitDecision {
    /// Create an "allowed" decision.
    #[inline]
    #[must_use]
    pub fn allowed(
        tokens_remaining: u64,
        tokens_limit: u64,
        limiter_key: impl Into<Cow<'static, str>>,
        scope: LimitScope,
    ) -> Self {
        Self {
            allowed: true,
            tokens_remaining,
            tokens_limit,
            reset_after: Duration::ZERO,
            limiter_key: limiter_key.into(),
            scope,
        }
    }

    /// Create a "denied" decision.
    #[inline]
    #[must_use]
    pub fn denied(
        tokens_remaining: u64,
        tokens_limit: u64,
        reset_after: Duration,
        limiter_key: impl Into<Cow<'static, str>>,
        scope: LimitScope,
    ) -> Self {
        Self {
            allowed: false,
            tokens_remaining,
            tokens_limit,
            reset_after,
            limiter_key: limiter_key.into(),
            scope,
        }
    }

    /// Get retry-after in seconds (for HTTP header).
    #[inline]
    #[must_use]
    pub fn retry_after_secs(&self) -> u64 {
        self.reset_after.as_secs().max(1)
    }
}

/// Context for a rate limit check.
#[derive(Debug, Clone, Default)]
pub struct RateLimitContext {
    /// Client IP address.
    pub client_ip: Option<String>,

    /// Authenticated user ID.
    pub user_id: Option<String>,

    /// Route/path being accessed.
    pub route: Option<String>,

    /// Request headers.
    pub headers: HashMap<String, String>,
}

impl RateLimitContext {
    /// Create a new context.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Set client IP.
    #[must_use]
    pub fn with_ip(mut self, ip: impl Into<String>) -> Self {
        self.client_ip = Some(ip.into());
        self
    }

    /// Set user ID.
    #[must_use]
    pub fn with_user(mut self, user: impl Into<String>) -> Self {
        self.user_id = Some(user.into());
        self
    }

    /// Set route.
    #[must_use]
    pub fn with_route(mut self, route: impl Into<String>) -> Self {
        self.route = Some(route.into());
        self
    }

    /// Add a header.
    #[must_use]
    pub fn with_header(mut self, key: impl Into<String>, value: impl Into<String>) -> Self {
        self.headers.insert(key.into(), value.into());
        self
    }
}

/// Entry in the bucket cache.
struct BucketEntry {
    bucket: Arc<TokenBucket>,
    last_used: Instant,
}

/// The main rate limiter combining all limiting strategies.
pub struct RateLimiter {
    /// Configuration.
    config: RateLimitConfig,

    /// Per-key token buckets.
    buckets: RwLock<HashMap<String, BucketEntry>>,

    /// Creation time for cleanup scheduling.
    created_at: Instant,

    /// Stats: total checks.
    total_checks: std::sync::atomic::AtomicU64,

    /// Stats: total allowed.
    total_allowed: std::sync::atomic::AtomicU64,

    /// Stats: total denied.
    total_denied: std::sync::atomic::AtomicU64,
}

impl std::fmt::Debug for RateLimiter {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("RateLimiter")
            .field("config", &self.config)
            .field("total_checks", &self.total_checks)
            .field("total_allowed", &self.total_allowed)
            .field("total_denied", &self.total_denied)
            .finish()
    }
}

impl RateLimiter {
    /// Create a new rate limiter with the given configuration.
    #[must_use]
    pub fn new(config: RateLimitConfig) -> Self {
        Self {
            config,
            buckets: RwLock::new(HashMap::new()),
            created_at: Instant::now(),
            total_checks: std::sync::atomic::AtomicU64::new(0),
            total_allowed: std::sync::atomic::AtomicU64::new(0),
            total_denied: std::sync::atomic::AtomicU64::new(0),
        }
    }

    /// Create a rate limiter with default configuration.
    #[must_use]
    pub fn with_defaults() -> Self {
        Self::new(RateLimitConfig::default())
    }

    /// Check if a request should be allowed.
    pub fn check(&self, ctx: &RateLimitContext) -> RateLimitDecision {
        use std::sync::atomic::Ordering;

        self.total_checks.fetch_add(1, Ordering::Relaxed);

        if !self.config.enabled {
            self.total_allowed.fetch_add(1, Ordering::Relaxed);
            return RateLimitDecision::allowed(u64::MAX, u64::MAX, "disabled", LimitScope::Global);
        }

        // Check per-IP limits first (if configured)
        if let Some(ref per_ip_config) = self.config.per_ip {
            if per_ip_config.enabled {
                if let Some(ref ip) = ctx.client_ip {
                    // Check whitelist
                    if per_ip_config.is_whitelisted(ip) {
                        self.total_allowed.fetch_add(1, Ordering::Relaxed);
                        let mut key = String::with_capacity(4 + ip.len() + 12);
                        let _ = write!(key, "ip:{ip}:whitelisted");
                        return RateLimitDecision::allowed(
                            u64::MAX,
                            u64::MAX,
                            key,
                            LimitScope::PerIp,
                        );
                    }

                    // Check blacklist
                    if per_ip_config.is_blacklisted(ip) {
                        self.total_denied.fetch_add(1, Ordering::Relaxed);
                        let mut key = String::with_capacity(4 + ip.len() + 12);
                        let _ = write!(key, "ip:{ip}:blacklisted");
                        return RateLimitDecision::denied(
                            0,
                            0,
                            Duration::from_secs(3600),
                            key,
                            LimitScope::PerIp,
                        );
                    }

                    // Apply per-IP rate limit
                    let decision = self.check_ip_limit(ip, per_ip_config);
                    if !decision.allowed {
                        self.total_denied.fetch_add(1, Ordering::Relaxed);
                        return decision;
                    }
                }
            }
        }

        // Check route-specific limits
        if let Some(ref route) = ctx.route {
            if let Some(rule) = self.config.routes.get(route) {
                let decision = self.check_rule(ctx, route, rule);
                if !decision.allowed {
                    self.total_denied.fetch_add(1, Ordering::Relaxed);
                    return decision;
                }
            }
        }

        // Check default limit
        if let Some(ref default_rule) = self.config.default_limit {
            let decision = self.check_rule(ctx, "default", default_rule);
            if !decision.allowed {
                self.total_denied.fetch_add(1, Ordering::Relaxed);
                return decision;
            }
            self.total_allowed.fetch_add(1, Ordering::Relaxed);
            return decision;
        }

        // No limits configured - allow
        self.total_allowed.fetch_add(1, Ordering::Relaxed);
        RateLimitDecision::allowed(u64::MAX, u64::MAX, "no-limit", LimitScope::Global)
    }

    /// Check a specific rate limit rule.
    fn check_rule(
        &self,
        ctx: &RateLimitContext,
        rule_name: &str,
        rule: &RateLimitRule,
    ) -> RateLimitDecision {
        let scope_key = rule.scope.extract_key(
            ctx.client_ip.as_deref(),
            ctx.user_id.as_deref(),
            &ctx.headers,
        );

        let scope_str = rule.scope_string();
        let mut bucket_key =
            String::with_capacity(rule_name.len() + scope_str.len() + scope_key.len() + 2);
        let _ = write!(bucket_key, "{}:{}:{}", rule_name, scope_str, scope_key);
        let bucket = self.get_or_create_bucket(&bucket_key, rule);

        if bucket.try_consume(rule.tokens_per_request) {
            let remaining = bucket.available_tokens() as u64;
            RateLimitDecision::allowed(remaining, rule.max_tokens, bucket_key, rule.scope.clone())
        } else {
            let reset_after = bucket.time_until_available(rule.tokens_per_request);
            RateLimitDecision::denied(
                0,
                rule.max_tokens,
                reset_after,
                bucket_key,
                rule.scope.clone(),
            )
        }
    }

    /// Check per-IP rate limit.
    fn check_ip_limit(&self, ip: &str, config: &PerIpConfig) -> RateLimitDecision {
        let mut bucket_key = String::with_capacity(7 + ip.len());
        let _ = write!(bucket_key, "per-ip:{ip}");

        let rule = RateLimitRule {
            max_tokens: config.max_requests,
            refill_rate: config.refill_rate,
            tokens_per_request: 1,
            scope: LimitScope::PerIp,
            exceeded_action: None,
        };

        let bucket = self.get_or_create_bucket(&bucket_key, &rule);

        if bucket.try_consume(1) {
            let remaining = bucket.available_tokens() as u64;
            RateLimitDecision::allowed(
                remaining,
                config.max_requests,
                bucket_key,
                LimitScope::PerIp,
            )
        } else {
            let reset_after = bucket.time_until_available(1);
            RateLimitDecision::denied(
                0,
                config.max_requests,
                reset_after,
                bucket_key,
                LimitScope::PerIp,
            )
        }
    }

    /// Get or create a bucket for the given key.
    fn get_or_create_bucket(&self, key: &str, rule: &RateLimitRule) -> Arc<TokenBucket> {
        // Try read lock first
        {
            let buckets = self.buckets.read().unwrap();
            if let Some(entry) = buckets.get(key) {
                return Arc::clone(&entry.bucket);
            }
        }

        // Need to create - get write lock
        let mut buckets = self.buckets.write().unwrap();

        // Double-check after acquiring write lock
        if let Some(entry) = buckets.get(key) {
            return Arc::clone(&entry.bucket);
        }

        // Create new bucket
        let bucket = Arc::new(TokenBucket::with_rate(rule.max_tokens, rule.refill_rate));
        buckets.insert(
            key.to_string(),
            BucketEntry {
                bucket: Arc::clone(&bucket),
                last_used: Instant::now(),
            },
        );

        bucket
    }

    /// Clean up expired buckets.
    pub fn cleanup(&self, max_idle: Duration) {
        let now = Instant::now();
        let mut buckets = self.buckets.write().unwrap();

        buckets.retain(|_, entry| now.duration_since(entry.last_used) < max_idle);
    }

    /// Get the number of active buckets.
    #[must_use]
    pub fn active_bucket_count(&self) -> usize {
        self.buckets.read().unwrap().len()
    }

    /// Get total checks.
    #[must_use]
    pub fn total_checks(&self) -> u64 {
        self.total_checks.load(std::sync::atomic::Ordering::Relaxed)
    }

    /// Get total allowed.
    #[must_use]
    pub fn total_allowed(&self) -> u64 {
        self.total_allowed
            .load(std::sync::atomic::Ordering::Relaxed)
    }

    /// Get total denied.
    #[must_use]
    pub fn total_denied(&self) -> u64 {
        self.total_denied.load(std::sync::atomic::Ordering::Relaxed)
    }

    /// Get the configuration.
    #[must_use]
    pub fn config(&self) -> &RateLimitConfig {
        &self.config
    }

    /// Get uptime.
    #[must_use]
    #[allow(dead_code)]
    pub fn uptime(&self) -> Duration {
        self.created_at.elapsed()
    }
}

// Helper trait to get scope as string
trait ScopeString {
    fn scope_string(&self) -> Cow<'static, str>;
}

impl ScopeString for RateLimitRule {
    #[inline]
    fn scope_string(&self) -> Cow<'static, str> {
        match &self.scope {
            LimitScope::Global => Cow::Borrowed("global"),
            LimitScope::PerIp => Cow::Borrowed("per-ip"),
            LimitScope::PerUser => Cow::Borrowed("per-user"),
            LimitScope::PerApiKey => Cow::Borrowed("per-api-key"),
            LimitScope::PerHeader(h) => Cow::Owned(format!("per-header:{h}")),
            LimitScope::Composite(scopes) => Cow::Owned(format!("composite:{}", scopes.len())),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_rate_limit_decision() {
        let allowed = RateLimitDecision::allowed(50, 100, "test".to_string(), LimitScope::Global);
        assert!(allowed.allowed);
        assert_eq!(allowed.tokens_remaining, 50);
        assert_eq!(allowed.tokens_limit, 100);

        let denied = RateLimitDecision::denied(
            0,
            100,
            Duration::from_secs(60),
            "test".to_string(),
            LimitScope::Global,
        );
        assert!(!denied.allowed);
        assert_eq!(denied.retry_after_secs(), 60);
    }

    #[test]
    fn test_rate_limit_context() {
        let ctx = RateLimitContext::new()
            .with_ip("1.2.3.4")
            .with_user("user123")
            .with_route("/api/test")
            .with_header("x-api-key", "key123");

        assert_eq!(ctx.client_ip, Some("1.2.3.4".to_string()));
        assert_eq!(ctx.user_id, Some("user123".to_string()));
        assert_eq!(ctx.route, Some("/api/test".to_string()));
        assert_eq!(ctx.headers.get("x-api-key"), Some(&"key123".to_string()));
    }

    #[test]
    fn test_rate_limiter_disabled() {
        let config = RateLimitConfig {
            enabled: false,
            ..Default::default()
        };
        let limiter = RateLimiter::new(config);

        let ctx = RateLimitContext::new().with_ip("1.2.3.4");
        let decision = limiter.check(&ctx);

        assert!(decision.allowed);
        assert_eq!(decision.limiter_key, "disabled");
    }

    #[test]
    fn test_rate_limiter_basic() {
        let config = RateLimitConfig {
            enabled: true,
            default_limit: Some(RateLimitRule::new(10, 0.001)), // Very slow refill
            per_ip: None,
            ..Default::default()
        };
        let limiter = RateLimiter::new(config);

        let ctx = RateLimitContext::new();

        // First 10 requests should be allowed
        for _ in 0..10 {
            let decision = limiter.check(&ctx);
            assert!(decision.allowed);
        }

        // 11th request should be denied
        let decision = limiter.check(&ctx);
        assert!(!decision.allowed);
    }

    #[test]
    fn test_rate_limiter_per_ip() {
        let config = RateLimitConfig {
            enabled: true,
            default_limit: None,
            per_ip: Some(PerIpConfig {
                enabled: true,
                max_requests: 5,
                refill_rate: 0.001, // Very slow refill
                ..Default::default()
            }),
            ..Default::default()
        };
        let limiter = RateLimiter::new(config);

        let ctx1 = RateLimitContext::new().with_ip("1.2.3.4");
        let ctx2 = RateLimitContext::new().with_ip("5.6.7.8");

        // Each IP gets 5 requests
        for _ in 0..5 {
            assert!(limiter.check(&ctx1).allowed);
            assert!(limiter.check(&ctx2).allowed);
        }

        // Both should be rate limited now
        assert!(!limiter.check(&ctx1).allowed);
        assert!(!limiter.check(&ctx2).allowed);
    }

    #[test]
    fn test_rate_limiter_whitelist() {
        let config = RateLimitConfig {
            enabled: true,
            per_ip: Some(PerIpConfig {
                enabled: true,
                max_requests: 1,
                refill_rate: 0.001,
                whitelist: vec!["127.0.0.1".to_string()],
                ..Default::default()
            }),
            ..Default::default()
        };
        let limiter = RateLimiter::new(config);

        let ctx = RateLimitContext::new().with_ip("127.0.0.1");

        // Whitelisted IP should always be allowed
        for _ in 0..100 {
            let decision = limiter.check(&ctx);
            assert!(decision.allowed);
            assert!(decision.limiter_key.contains("whitelisted"));
        }
    }

    #[test]
    fn test_rate_limiter_blacklist() {
        let config = RateLimitConfig {
            enabled: true,
            per_ip: Some(PerIpConfig {
                enabled: true,
                max_requests: 1000,
                refill_rate: 100.0,
                blacklist: vec!["10.0.0.1".to_string()],
                ..Default::default()
            }),
            ..Default::default()
        };
        let limiter = RateLimiter::new(config);

        let ctx = RateLimitContext::new().with_ip("10.0.0.1");

        // Blacklisted IP should always be denied
        let decision = limiter.check(&ctx);
        assert!(!decision.allowed);
        assert!(decision.limiter_key.contains("blacklisted"));
    }

    #[test]
    fn test_rate_limiter_route_specific() {
        let config = RateLimitConfig {
            enabled: true,
            default_limit: Some(RateLimitRule::new(100, 10.0)),
            routes: HashMap::from([("/api/expensive".to_string(), RateLimitRule::new(2, 0.1))]),
            per_ip: None,
            ..Default::default()
        };
        let limiter = RateLimiter::new(config);

        let ctx = RateLimitContext::new().with_route("/api/expensive");

        // Only 2 requests allowed for this route
        assert!(limiter.check(&ctx).allowed);
        assert!(limiter.check(&ctx).allowed);
        assert!(!limiter.check(&ctx).allowed);
    }

    #[test]
    fn test_rate_limiter_stats() {
        let config = RateLimitConfig {
            enabled: true,
            default_limit: Some(RateLimitRule::new(5, 0.001)), // Very slow refill
            per_ip: None,
            ..Default::default()
        };
        let limiter = RateLimiter::new(config);

        let ctx = RateLimitContext::new();

        for _ in 0..10 {
            limiter.check(&ctx);
        }

        assert_eq!(limiter.total_checks(), 10);
        assert_eq!(limiter.total_allowed(), 5);
        assert_eq!(limiter.total_denied(), 5);
    }

    #[test]
    fn test_rate_limiter_cleanup() {
        let config = RateLimitConfig {
            per_ip: None,
            ..Default::default()
        };
        let limiter = RateLimiter::new(config);

        // Create some buckets
        for i in 0..10 {
            let ctx = RateLimitContext::new().with_ip(format!("1.2.3.{i}"));
            limiter.check(&ctx);
        }

        assert!(limiter.active_bucket_count() > 0);

        // Cleanup with very short max idle should remove all
        limiter.cleanup(Duration::ZERO);
        assert_eq!(limiter.active_bucket_count(), 0);
    }

    #[test]
    fn test_rate_limiter_per_user_scope() {
        let config = RateLimitConfig {
            enabled: true,
            default_limit: Some(RateLimitRule::new(3, 0.001).with_scope(LimitScope::PerUser)), // Very slow refill
            per_ip: None,
            ..Default::default()
        };
        let limiter = RateLimiter::new(config);

        let user1 = RateLimitContext::new().with_user("alice");
        let user2 = RateLimitContext::new().with_user("bob");

        // Each user gets their own bucket
        for _ in 0..3 {
            assert!(limiter.check(&user1).allowed);
            assert!(limiter.check(&user2).allowed);
        }

        // Both should be limited now
        assert!(!limiter.check(&user1).allowed);
        assert!(!limiter.check(&user2).allowed);
    }
}
