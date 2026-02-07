//! Rate limiting handler implementing ModuleContract.

use super::config::RateLimitConfig;
use super::distributed::{create_backend, DistributedState, LocalState};
use super::limiter::{RateLimitContext, RateLimitDecision, RateLimiter};
use crate::module::{
    Capability, MetricsPayload, ModuleConfig, ModuleContract, ModuleError, ModuleManifest,
    ModuleResult, ModuleStatus,
};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};
use tracing::{debug, info};

/// Statistics for the rate limiting handler.
#[derive(Debug, Default)]
pub struct RateLimitStats {
    /// Total requests checked.
    pub requests_checked: AtomicU64,
    /// Requests allowed.
    pub requests_allowed: AtomicU64,
    /// Requests denied (rate limited).
    pub requests_denied: AtomicU64,
    /// Active buckets.
    pub active_buckets: AtomicU64,
    /// Cleanup cycles run.
    pub cleanup_cycles: AtomicU64,
}

impl RateLimitStats {
    /// Create new stats.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Record a check result.
    pub fn record_check(&self, allowed: bool) {
        self.requests_checked.fetch_add(1, Ordering::Relaxed);
        if allowed {
            self.requests_allowed.fetch_add(1, Ordering::Relaxed);
        } else {
            self.requests_denied.fetch_add(1, Ordering::Relaxed);
        }
    }

    /// Update active bucket count.
    pub fn update_bucket_count(&self, count: u64) {
        self.active_buckets.store(count, Ordering::Relaxed);
    }

    /// Record a cleanup cycle.
    pub fn record_cleanup(&self) {
        self.cleanup_cycles.fetch_add(1, Ordering::Relaxed);
    }
}

/// Rate limiting handler module.
pub struct RateLimitHandler {
    /// Configuration.
    config: RateLimitConfig,

    /// The rate limiter.
    limiter: Option<RateLimiter>,

    /// Distributed state backend.
    distributed_state: Option<Arc<dyn DistributedState>>,

    /// Current status.
    status: ModuleStatus,

    /// Statistics.
    stats: Arc<RateLimitStats>,

    /// Start time for uptime calculation.
    started_at: Option<Instant>,

    /// Cleanup interval.
    #[allow(dead_code)]
    cleanup_interval: Duration,

    /// Max idle time for bucket cleanup.
    max_bucket_idle: Duration,
}

impl std::fmt::Debug for RateLimitHandler {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("RateLimitHandler")
            .field("config", &self.config)
            .field("limiter", &self.limiter)
            .field("status", &self.status)
            .field("stats", &self.stats)
            .field("started_at", &self.started_at)
            .finish()
    }
}

impl RateLimitHandler {
    /// Create a new rate limit handler.
    #[must_use]
    pub fn new() -> Self {
        Self::with_config(RateLimitConfig::default())
    }

    /// Create a rate limit handler with custom configuration.
    #[must_use]
    pub fn with_config(config: RateLimitConfig) -> Self {
        Self {
            config,
            limiter: None,
            distributed_state: None,
            status: ModuleStatus::Stopped,
            stats: Arc::new(RateLimitStats::new()),
            started_at: None,
            cleanup_interval: Duration::from_secs(60),
            max_bucket_idle: Duration::from_secs(3600),
        }
    }

    /// Check if a request should be rate limited.
    ///
    /// Returns the rate limit decision with details about tokens remaining.
    pub fn check_rate_limit(&self, ctx: &RateLimitContext) -> RateLimitDecision {
        if let Some(ref limiter) = self.limiter {
            let decision = limiter.check(ctx);
            self.stats.record_check(decision.allowed);
            decision
        } else {
            // Not initialized - allow all
            RateLimitDecision::allowed(
                u64::MAX,
                u64::MAX,
                "not-initialized".to_string(),
                super::config::LimitScope::Global,
            )
        }
    }

    /// Convenience method to check rate limit by IP and route.
    pub fn check(&self, client_ip: Option<&str>, route: Option<&str>) -> bool {
        let mut ctx = RateLimitContext::new();
        if let Some(ip) = client_ip {
            ctx = ctx.with_ip(ip);
        }
        if let Some(r) = route {
            ctx = ctx.with_route(r);
        }
        self.check_rate_limit(&ctx).allowed
    }

    /// Get the rate limiter.
    #[must_use]
    pub fn limiter(&self) -> Option<&RateLimiter> {
        self.limiter.as_ref()
    }

    /// Get statistics.
    #[must_use]
    pub fn stats(&self) -> &Arc<RateLimitStats> {
        &self.stats
    }

    /// Get the configuration.
    #[must_use]
    pub fn config(&self) -> &RateLimitConfig {
        &self.config
    }

    /// Run cleanup of expired buckets.
    pub fn cleanup(&self) {
        if let Some(ref limiter) = self.limiter {
            limiter.cleanup(self.max_bucket_idle);
            self.stats
                .update_bucket_count(limiter.active_bucket_count() as u64);
            self.stats.record_cleanup();
        }
    }

    /// Get uptime.
    #[must_use]
    pub fn uptime(&self) -> Option<Duration> {
        self.started_at.map(|t| t.elapsed())
    }

    /// Check if distributed backend is healthy.
    #[must_use]
    pub fn is_distributed_healthy(&self) -> bool {
        self.distributed_state
            .as_ref()
            .map(|s| s.is_healthy())
            .unwrap_or(true)
    }
}

impl Default for RateLimitHandler {
    fn default() -> Self {
        Self::new()
    }
}

impl ModuleContract for RateLimitHandler {
    fn manifest(&self) -> ModuleManifest {
        ModuleManifest::builder("rate-limiter")
            .description("Rate limiting with token bucket algorithm")
            .version(1, 0, 0)
            .capability(Capability::RateLimiting)
            .build()
    }

    fn init(&mut self, config: ModuleConfig) -> ModuleResult<()> {
        if self.status != ModuleStatus::Stopped {
            return Err(ModuleError::InvalidState {
                current: self.status.to_string(),
                expected: "Stopped".to_string(),
            });
        }

        debug!("Initializing rate limiter");

        // Parse configuration
        let rate_config: RateLimitConfig = if let Some(raw) = config.raw_config() {
            toml::from_str(raw)
                .map_err(|e| ModuleError::ConfigError(format!("failed to parse config: {e}")))?
        } else {
            RateLimitConfig::default()
        };

        // Validate configuration
        rate_config.validate().map_err(ModuleError::ConfigError)?;

        // Create distributed state backend if configured
        if let Some(ref dist_config) = rate_config.distributed {
            self.distributed_state = Some(create_backend(dist_config));
            info!(
                "Distributed rate limiting enabled with {:?} backend",
                dist_config.backend
            );
        } else {
            // Use local state
            self.distributed_state = Some(Arc::new(LocalState::new()));
        }

        // Create the limiter
        self.limiter = Some(RateLimiter::new(rate_config.clone()));
        self.config = rate_config;
        self.status = ModuleStatus::Initializing;

        info!("Rate limiter initialized");
        Ok(())
    }

    fn start(&mut self) -> ModuleResult<()> {
        if self.status != ModuleStatus::Initializing {
            return Err(ModuleError::InvalidState {
                current: self.status.to_string(),
                expected: "Initializing".to_string(),
            });
        }

        debug!("Starting rate limiter");

        self.started_at = Some(Instant::now());
        self.status = ModuleStatus::Running;

        info!(
            "Rate limiter started (enabled: {}, default_limit: {:?})",
            self.config.enabled,
            self.config.default_limit.as_ref().map(|l| l.max_tokens)
        );

        Ok(())
    }

    fn stop(&mut self) -> ModuleResult<()> {
        debug!("Stopping rate limiter");

        // Log final stats
        if let Some(ref limiter) = self.limiter {
            info!(
                "Rate limiter stopping - total_checks: {}, allowed: {}, denied: {}",
                limiter.total_checks(),
                limiter.total_allowed(),
                limiter.total_denied()
            );
        }

        self.status = ModuleStatus::Stopped;
        self.started_at = None;

        info!("Rate limiter stopped");
        Ok(())
    }

    fn reload(&mut self, config: ModuleConfig) -> ModuleResult<()> {
        debug!("Reloading rate limiter configuration");

        // Parse new configuration
        let new_config: RateLimitConfig = if let Some(raw) = config.raw_config() {
            toml::from_str(raw)
                .map_err(|e| ModuleError::ConfigError(format!("failed to parse config: {e}")))?
        } else {
            return Err(ModuleError::ConfigError(
                "no configuration provided".to_string(),
            ));
        };

        // Validate
        new_config.validate().map_err(ModuleError::ConfigError)?;

        // Update distributed backend if changed
        if new_config.distributed != self.config.distributed {
            if let Some(ref dist_config) = new_config.distributed {
                self.distributed_state = Some(create_backend(dist_config));
                info!("Distributed backend updated to {:?}", dist_config.backend);
            }
        }

        // Create new limiter (preserving stats from old one if possible)
        self.limiter = Some(RateLimiter::new(new_config.clone()));
        self.config = new_config;

        info!("Rate limiter configuration reloaded");
        Ok(())
    }

    fn status(&self) -> ModuleStatus {
        self.status.clone()
    }

    fn metrics(&self) -> MetricsPayload {
        let mut metrics = MetricsPayload::new();

        // Core metrics
        metrics.counter(
            "requests_checked",
            self.stats.requests_checked.load(Ordering::Relaxed),
        );
        metrics.counter(
            "requests_allowed",
            self.stats.requests_allowed.load(Ordering::Relaxed),
        );
        metrics.counter(
            "requests_denied",
            self.stats.requests_denied.load(Ordering::Relaxed),
        );

        // Limiter metrics
        if let Some(ref limiter) = self.limiter {
            metrics.gauge("active_buckets", limiter.active_bucket_count() as f64);
            metrics.counter("limiter_total_checks", limiter.total_checks());
            metrics.counter("limiter_total_allowed", limiter.total_allowed());
            metrics.counter("limiter_total_denied", limiter.total_denied());
        }

        // Cleanup metrics
        metrics.counter(
            "cleanup_cycles",
            self.stats.cleanup_cycles.load(Ordering::Relaxed),
        );

        // Uptime
        if let Some(uptime) = self.uptime() {
            metrics.gauge("uptime_seconds", uptime.as_secs_f64());
        }

        // Distributed backend health
        metrics.gauge(
            "distributed_healthy",
            if self.is_distributed_healthy() {
                1.0
            } else {
                0.0
            },
        );

        metrics
    }

    fn heartbeat(&self) -> bool {
        if self.status != ModuleStatus::Running {
            return false;
        }

        // Check distributed backend health
        self.is_distributed_healthy()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::module::ModuleConfig;

    fn create_test_config() -> String {
        r#"
            enabled = true

            [default_limit]
            max_tokens = 100
            refill_rate = 10.0
            tokens_per_request = 1

            [per_ip]
            enabled = true
            max_requests = 50
            refill_rate = 5.0
        "#
        .to_string()
    }

    #[test]
    fn test_handler_creation() {
        let handler = RateLimitHandler::new();
        assert_eq!(handler.status(), ModuleStatus::Stopped);
        assert!(handler.limiter().is_none());
    }

    #[test]
    fn test_handler_manifest() {
        let handler = RateLimitHandler::new();
        let manifest = handler.manifest();
        assert_eq!(manifest.name, "rate-limiter");
        assert!(manifest.capabilities.contains(&Capability::RateLimiting));
    }

    #[test]
    fn test_handler_lifecycle() {
        let mut handler = RateLimitHandler::new();

        // Init
        let config = ModuleConfig::from_raw(create_test_config());
        assert!(handler.init(config).is_ok());
        assert_eq!(handler.status(), ModuleStatus::Initializing);
        assert!(handler.limiter().is_some());

        // Start
        assert!(handler.start().is_ok());
        assert_eq!(handler.status(), ModuleStatus::Running);
        assert!(handler.uptime().is_some());

        // Stop
        assert!(handler.stop().is_ok());
        assert_eq!(handler.status(), ModuleStatus::Stopped);
    }

    #[test]
    fn test_handler_check_rate_limit() {
        let mut handler = RateLimitHandler::new();

        let config = ModuleConfig::from_raw(
            r#"
            enabled = true
            [default_limit]
            max_tokens = 5
            refill_rate = 0.001
            "#
            .to_string(),
        );

        handler.init(config).unwrap();
        handler.start().unwrap();

        // First 5 should be allowed
        for _ in 0..5 {
            assert!(handler.check(None, None));
        }

        // 6th should be denied
        assert!(!handler.check(None, None));

        // Stats should reflect this
        assert_eq!(handler.stats.requests_checked.load(Ordering::Relaxed), 6);
        assert_eq!(handler.stats.requests_allowed.load(Ordering::Relaxed), 5);
        assert_eq!(handler.stats.requests_denied.load(Ordering::Relaxed), 1);
    }

    #[test]
    fn test_handler_disabled() {
        let mut handler = RateLimitHandler::new();

        let config = ModuleConfig::from_raw(
            r#"
            enabled = false
            "#
            .to_string(),
        );

        handler.init(config).unwrap();
        handler.start().unwrap();

        // All should be allowed when disabled
        for _ in 0..100 {
            assert!(handler.check(Some("1.2.3.4"), Some("/api/test")));
        }
    }

    #[test]
    fn test_handler_per_ip_limits() {
        let mut handler = RateLimitHandler::new();

        let config = ModuleConfig::from_raw(
            r#"
            enabled = true
            [per_ip]
            enabled = true
            max_requests = 3
            refill_rate = 0.001
            "#
            .to_string(),
        );

        handler.init(config).unwrap();
        handler.start().unwrap();

        // Each IP gets 3 requests
        assert!(handler.check(Some("1.1.1.1"), None));
        assert!(handler.check(Some("1.1.1.1"), None));
        assert!(handler.check(Some("1.1.1.1"), None));
        assert!(!handler.check(Some("1.1.1.1"), None));

        // Different IP should have its own limit
        assert!(handler.check(Some("2.2.2.2"), None));
        assert!(handler.check(Some("2.2.2.2"), None));
        assert!(handler.check(Some("2.2.2.2"), None));
        assert!(!handler.check(Some("2.2.2.2"), None));
    }

    #[test]
    fn test_handler_metrics() {
        let mut handler = RateLimitHandler::new();

        let config = ModuleConfig::from_raw(create_test_config());
        handler.init(config).unwrap();
        handler.start().unwrap();

        // Make some requests
        handler.check(None, None);
        handler.check(None, None);

        let metrics = handler.metrics();
        assert!(metrics.counters.contains_key("requests_checked"));
        assert!(metrics.gauges.contains_key("uptime_seconds"));
        assert!(metrics.gauges.contains_key("distributed_healthy"));
    }

    #[test]
    fn test_handler_cleanup() {
        let mut handler = RateLimitHandler::new();

        let config = ModuleConfig::from_raw(create_test_config());
        handler.init(config).unwrap();
        handler.start().unwrap();

        // Create some buckets
        for i in 0..10 {
            handler.check(Some(&format!("1.2.3.{i}")), None);
        }

        // Run cleanup
        handler.cleanup();

        assert!(handler.stats.cleanup_cycles.load(Ordering::Relaxed) > 0);
    }

    #[test]
    fn test_handler_reload() {
        let mut handler = RateLimitHandler::new();

        let config = ModuleConfig::from_raw(create_test_config());
        handler.init(config).unwrap();
        handler.start().unwrap();

        // Reload with new config
        let new_config = ModuleConfig::from_raw(
            r#"
            enabled = true
            [default_limit]
            max_tokens = 200
            refill_rate = 20.0
            "#
            .to_string(),
        );

        assert!(handler.reload(new_config).is_ok());
        assert_eq!(
            handler.config.default_limit.as_ref().unwrap().max_tokens,
            200
        );
    }

    #[test]
    fn test_handler_invalid_state_transitions() {
        let mut handler = RateLimitHandler::new();

        // Can't start before init
        assert!(handler.start().is_err());

        // Init
        let config = ModuleConfig::from_raw(create_test_config());
        handler.init(config).unwrap();

        // Can't init twice
        let config = ModuleConfig::from_raw(create_test_config());
        assert!(handler.init(config).is_err());
    }

    #[test]
    fn test_handler_heartbeat() {
        let mut handler = RateLimitHandler::new();

        // Not running - heartbeat should fail
        assert!(!handler.heartbeat());

        let config = ModuleConfig::from_raw(create_test_config());
        handler.init(config).unwrap();
        handler.start().unwrap();

        // Running - heartbeat should succeed
        assert!(handler.heartbeat());

        handler.stop().unwrap();

        // Stopped - heartbeat should fail
        assert!(!handler.heartbeat());
    }

    #[test]
    fn test_handler_distributed_health() {
        let handler = RateLimitHandler::new();
        // No distributed state - should be healthy
        assert!(handler.is_distributed_healthy());
    }

    #[test]
    fn test_rate_limit_decision_details() {
        let mut handler = RateLimitHandler::new();

        let config = ModuleConfig::from_raw(
            r#"
            enabled = true
            [default_limit]
            max_tokens = 5
            refill_rate = 0.001
            "#
            .to_string(),
        );

        handler.init(config).unwrap();
        handler.start().unwrap();

        let ctx = RateLimitContext::new();

        // First request
        let decision = handler.check_rate_limit(&ctx);
        assert!(decision.allowed);
        assert_eq!(decision.tokens_limit, 5);
        assert!(decision.tokens_remaining <= 5);

        // Consume all tokens
        for _ in 0..4 {
            handler.check_rate_limit(&ctx);
        }

        // Should be denied now
        let decision = handler.check_rate_limit(&ctx);
        assert!(!decision.allowed);
        assert!(decision.reset_after > Duration::ZERO);
    }
}
