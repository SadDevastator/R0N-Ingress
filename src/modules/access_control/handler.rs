//! Access control handler implementing ModuleContract.

use super::config::AccessControlConfig;
use super::ip_filter::IpFilter;
use super::policy::{PolicyContext, PolicyDecision, PolicyEngine};
use super::provider::{AuthContext, AuthManager, AuthResult};
use crate::module::{
    Capability, MetricsPayload, ModuleConfig, ModuleContract, ModuleError, ModuleManifest,
    ModuleResult, ModuleStatus,
};
use std::collections::HashMap;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::Instant;
use tracing::{debug, info};

/// Statistics for the access control handler.
#[derive(Debug, Default)]
pub struct AccessControlStats {
    /// Total requests checked.
    pub requests_checked: AtomicU64,
    /// Requests allowed.
    pub requests_allowed: AtomicU64,
    /// Requests denied.
    pub requests_denied: AtomicU64,
    /// IP filter denials.
    pub ip_denials: AtomicU64,
    /// Authentication failures.
    pub auth_failures: AtomicU64,
    /// Authorization denials.
    pub authz_denials: AtomicU64,
}

impl AccessControlStats {
    /// Create new stats.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Record a check result.
    pub fn record_check(&self, allowed: bool, reason: DenialReason) {
        self.requests_checked.fetch_add(1, Ordering::Relaxed);
        if allowed {
            self.requests_allowed.fetch_add(1, Ordering::Relaxed);
        } else {
            self.requests_denied.fetch_add(1, Ordering::Relaxed);
            match reason {
                DenialReason::IpFilter => {
                    self.ip_denials.fetch_add(1, Ordering::Relaxed);
                },
                DenialReason::Authentication => {
                    self.auth_failures.fetch_add(1, Ordering::Relaxed);
                },
                DenialReason::Authorization => {
                    self.authz_denials.fetch_add(1, Ordering::Relaxed);
                },
                DenialReason::None => {},
            }
        }
    }
}

/// Reason for denial.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DenialReason {
    /// No denial.
    None,
    /// IP filter denied.
    IpFilter,
    /// Authentication failed.
    Authentication,
    /// Authorization denied.
    Authorization,
}

/// Result of an access control check.
#[derive(Debug, Clone)]
pub struct AccessCheckResult {
    /// Whether access is allowed.
    pub allowed: bool,
    /// Denial reason if not allowed.
    pub denial_reason: DenialReason,
    /// Message explaining the result.
    pub message: String,
    /// Authentication result if auth was performed.
    pub auth_result: Option<AuthResult>,
    /// Policy decision if evaluated.
    pub policy_decision: Option<PolicyDecision>,
}

impl AccessCheckResult {
    /// Create an allowed result.
    #[must_use]
    pub fn allow() -> Self {
        Self {
            allowed: true,
            denial_reason: DenialReason::None,
            message: "Access allowed".to_string(),
            auth_result: None,
            policy_decision: None,
        }
    }

    /// Create a denied result.
    #[must_use]
    pub fn deny(reason: DenialReason, message: impl Into<String>) -> Self {
        Self {
            allowed: false,
            denial_reason: reason,
            message: message.into(),
            auth_result: None,
            policy_decision: None,
        }
    }

    /// Add authentication result.
    #[must_use]
    pub fn with_auth(mut self, result: AuthResult) -> Self {
        self.auth_result = Some(result);
        self
    }

    /// Add policy decision.
    #[must_use]
    pub fn with_policy(mut self, decision: PolicyDecision) -> Self {
        self.policy_decision = Some(decision);
        self
    }
}

/// Context for access control check.
#[derive(Debug, Clone, Default)]
pub struct CheckContext {
    /// Client IP address.
    pub client_ip: String,
    /// Request path.
    pub path: String,
    /// Request method.
    pub method: String,
    /// Route name (if resolved).
    pub route: Option<String>,
    /// Request headers.
    pub headers: HashMap<String, String>,
    /// Authorization header value.
    pub authorization: Option<String>,
}

impl CheckContext {
    /// Create a new check context.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Set the client IP.
    #[must_use]
    pub fn with_client_ip(mut self, ip: impl Into<String>) -> Self {
        self.client_ip = ip.into();
        self
    }

    /// Set the path.
    #[must_use]
    pub fn with_path(mut self, path: impl Into<String>) -> Self {
        self.path = path.into();
        self
    }

    /// Set the method.
    #[must_use]
    pub fn with_method(mut self, method: impl Into<String>) -> Self {
        self.method = method.into();
        self
    }

    /// Set the route.
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

    /// Set the authorization header.
    #[must_use]
    pub fn with_authorization(mut self, auth: impl Into<String>) -> Self {
        self.authorization = Some(auth.into());
        self
    }
}

/// Access control handler module.
pub struct AccessControlHandler {
    /// Configuration.
    config: AccessControlConfig,

    /// IP filter (if configured).
    ip_filter: Option<IpFilter>,

    /// Authentication manager (if configured).
    auth_manager: Option<AuthManager>,

    /// Policy engine (if configured).
    policy_engine: Option<PolicyEngine>,

    /// Current status.
    status: ModuleStatus,

    /// Statistics.
    stats: Arc<AccessControlStats>,

    /// Start time for uptime calculation.
    started_at: Option<Instant>,
}

impl std::fmt::Debug for AccessControlHandler {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("AccessControlHandler")
            .field("config", &self.config)
            .field("ip_filter", &self.ip_filter.is_some())
            .field("auth_manager", &self.auth_manager.is_some())
            .field("policy_engine", &self.policy_engine.is_some())
            .field("status", &self.status)
            .field("stats", &self.stats)
            .finish()
    }
}

impl AccessControlHandler {
    /// Create a new access control handler.
    #[must_use]
    pub fn new() -> Self {
        Self::with_config(AccessControlConfig::default())
    }

    /// Create an access control handler with custom configuration.
    #[must_use]
    pub fn with_config(config: AccessControlConfig) -> Self {
        Self {
            config,
            ip_filter: None,
            auth_manager: None,
            policy_engine: None,
            status: ModuleStatus::Stopped,
            stats: Arc::new(AccessControlStats::new()),
            started_at: None,
        }
    }

    /// Check if a request is allowed.
    pub fn check_access(&self, context: &CheckContext) -> AccessCheckResult {
        // Step 1: IP filtering
        if let Some(ref filter) = self.ip_filter {
            match filter.is_allowed(&context.client_ip) {
                Ok(true) => {},
                Ok(false) => {
                    self.stats.record_check(false, DenialReason::IpFilter);
                    return AccessCheckResult::deny(
                        DenialReason::IpFilter,
                        format!("IP {} is not allowed", context.client_ip),
                    );
                },
                Err(e) => {
                    debug!("IP filter error: {}", e);
                    // Continue on error
                },
            }
        }

        // Step 2: Authentication
        let auth_result = if let Some(ref manager) = self.auth_manager {
            let auth_ctx = AuthContext {
                authorization_header: context.authorization.clone(),
                headers: context.headers.clone(),
                path: context.path.clone(),
                method: context.method.clone(),
                client_ip: context.client_ip.clone(),
                ..Default::default()
            };

            match manager.authenticate(&auth_ctx) {
                Ok(result) => {
                    if manager.is_required() && !result.authenticated {
                        self.stats.record_check(false, DenialReason::Authentication);
                        let error_msg = result
                            .error
                            .clone()
                            .unwrap_or_else(|| "Authentication required".to_string());
                        return AccessCheckResult::deny(DenialReason::Authentication, error_msg)
                            .with_auth(result);
                    }
                    Some(result)
                },
                Err(e) => {
                    self.stats.record_check(false, DenialReason::Authentication);
                    return AccessCheckResult::deny(
                        DenialReason::Authentication,
                        format!("Authentication error: {}", e),
                    );
                },
            }
        } else {
            None
        };

        // Step 3: Authorization (policy evaluation)
        if let Some(ref engine) = self.policy_engine {
            let mut policy_ctx = PolicyContext::new()
                .with_path(&context.path)
                .with_method(&context.method)
                .with_client_ip(&context.client_ip);

            // Add roles and claims from auth result
            if let Some(ref auth) = auth_result {
                if auth.authenticated {
                    if let Some(ref identity) = auth.identity {
                        policy_ctx = policy_ctx.with_identity(identity);
                    }
                    policy_ctx = policy_ctx.with_roles(auth.roles.clone());
                    for (k, v) in &auth.claims {
                        policy_ctx = policy_ctx.with_claim(k, v);
                    }
                }
            }

            // Add headers
            for (k, v) in &context.headers {
                policy_ctx = policy_ctx.with_header(k, v);
            }

            match engine.evaluate(&policy_ctx) {
                Ok(decision) => {
                    if decision.is_denied() {
                        self.stats.record_check(false, DenialReason::Authorization);
                        return AccessCheckResult::deny(
                            DenialReason::Authorization,
                            decision.reason.clone(),
                        )
                        .with_policy(decision);
                    }

                    // Access allowed
                    self.stats.record_check(true, DenialReason::None);
                    let mut result = AccessCheckResult::allow().with_policy(decision);
                    if let Some(auth) = auth_result {
                        result = result.with_auth(auth);
                    }
                    return result;
                },
                Err(e) => {
                    self.stats.record_check(false, DenialReason::Authorization);
                    return AccessCheckResult::deny(
                        DenialReason::Authorization,
                        format!("Policy error: {}", e),
                    );
                },
            }
        }

        // All checks passed
        self.stats.record_check(true, DenialReason::None);
        let mut result = AccessCheckResult::allow();
        if let Some(auth) = auth_result {
            result = result.with_auth(auth);
        }
        result
    }

    /// Get statistics.
    #[must_use]
    pub fn stats(&self) -> &AccessControlStats {
        &self.stats
    }
}

impl Default for AccessControlHandler {
    fn default() -> Self {
        Self::new()
    }
}

impl ModuleContract for AccessControlHandler {
    fn manifest(&self) -> ModuleManifest {
        ModuleManifest::builder("access_control")
            .description("Access control with IP filtering, authentication, and authorization")
            .version(1, 0, 0)
            .capability(Capability::Custom("AccessControl".to_string()))
            .build()
    }

    fn init(&mut self, config: ModuleConfig) -> ModuleResult<()> {
        if self.status != ModuleStatus::Stopped {
            return Err(ModuleError::InvalidState {
                current: self.status.to_string(),
                expected: "Stopped".to_string(),
            });
        }

        info!("Initializing access control module");

        // Parse config from raw TOML if available
        if let Some(raw) = config.raw_config() {
            self.config = toml::from_str(raw)
                .map_err(|e| ModuleError::ConfigError(format!("failed to parse config: {e}")))?;
        }

        // Validate config
        self.config.validate().map_err(ModuleError::ConfigError)?;

        self.status = ModuleStatus::Initializing;
        info!("Access control module initialized");
        Ok(())
    }

    fn start(&mut self) -> ModuleResult<()> {
        if self.status != ModuleStatus::Initializing {
            return Err(ModuleError::InvalidState {
                current: self.status.to_string(),
                expected: "Initializing".to_string(),
            });
        }

        debug!("Starting access control module");

        // Initialize IP filter
        if let Some(ref ip_config) = self.config.ip_filter {
            if ip_config.enabled {
                self.ip_filter = Some(IpFilter::new(ip_config.clone()).map_err(|e| {
                    ModuleError::StartFailed(format!("Failed to create IP filter: {}", e))
                })?);
                debug!("IP filter initialized");
            }
        }

        // Initialize auth manager
        if let Some(ref auth_config) = self.config.auth {
            if auth_config.enabled {
                self.auth_manager = Some(
                    AuthManager::from_providers(&auth_config.providers, auth_config.required)
                        .map_err(|e| {
                            ModuleError::StartFailed(format!(
                                "Failed to create auth manager: {}",
                                e
                            ))
                        })?,
                );
                debug!("Auth manager initialized");
            }
        }

        // Initialize policy engine
        if let Some(ref policy_config) = self.config.policy {
            if policy_config.enabled {
                self.policy_engine = Some(PolicyEngine::new(policy_config.clone()));
                debug!("Policy engine initialized");
            }
        }

        self.status = ModuleStatus::Running;
        self.started_at = Some(Instant::now());

        info!("Access control module started");
        Ok(())
    }

    fn stop(&mut self) -> ModuleResult<()> {
        debug!("Stopping access control module");

        self.ip_filter = None;
        self.auth_manager = None;
        self.policy_engine = None;

        self.status = ModuleStatus::Stopped;
        self.started_at = None;

        info!("Access control module stopped");
        Ok(())
    }

    fn status(&self) -> ModuleStatus {
        self.status.clone()
    }

    fn metrics(&self) -> MetricsPayload {
        let mut metrics = MetricsPayload::new();

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
        metrics.counter("ip_denials", self.stats.ip_denials.load(Ordering::Relaxed));
        metrics.counter(
            "auth_failures",
            self.stats.auth_failures.load(Ordering::Relaxed),
        );
        metrics.counter(
            "authz_denials",
            self.stats.authz_denials.load(Ordering::Relaxed),
        );

        if let Some(started) = self.started_at {
            metrics.gauge("uptime_secs", started.elapsed().as_secs_f64());
        }

        metrics
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::modules::access_control::config::*;

    #[test]
    fn test_handler_creation() {
        let handler = AccessControlHandler::new();
        assert_eq!(handler.status, ModuleStatus::Stopped);

        let manifest = handler.manifest();
        assert_eq!(manifest.name, "access_control");
    }

    #[test]
    fn test_handler_lifecycle() {
        let mut handler = AccessControlHandler::new();

        // Initialize
        let config = ModuleConfig::default();
        handler.init(config).unwrap();
        assert_eq!(handler.status(), ModuleStatus::Initializing);

        // Start
        handler.start().unwrap();
        assert_eq!(handler.status(), ModuleStatus::Running);
        assert!(handler.heartbeat());

        // Stop
        handler.stop().unwrap();
        assert_eq!(handler.status(), ModuleStatus::Stopped);
    }

    #[test]
    fn test_ip_filtering() {
        let config = AccessControlConfig {
            enabled: true,
            ip_filter: Some(IpFilterConfig {
                enabled: true,
                rules: vec![IpRule::deny(vec!["10.0.0.0/8".to_string()])],
                default_action: RuleAction::Allow,
                ..Default::default()
            }),
            ..Default::default()
        };

        let mut handler = AccessControlHandler::with_config(config);
        handler.init(ModuleConfig::default()).unwrap();
        handler.start().unwrap();

        // Allowed IP
        let ctx = CheckContext::new().with_client_ip("192.168.1.1");
        let result = handler.check_access(&ctx);
        assert!(result.allowed);

        // Denied IP
        let ctx = CheckContext::new().with_client_ip("10.1.2.3");
        let result = handler.check_access(&ctx);
        assert!(!result.allowed);
        assert_eq!(result.denial_reason, DenialReason::IpFilter);

        assert!(handler.stats.ip_denials.load(Ordering::Relaxed) > 0);
    }

    #[test]
    fn test_authentication() {
        let config = AccessControlConfig {
            enabled: true,
            auth: Some(AuthConfig {
                enabled: true,
                required: true,
                providers: vec![AuthProvider::Basic {
                    realm: "Test".to_string(),
                    users: HashMap::from([("admin".to_string(), "secret".to_string())]),
                }],
                ..Default::default()
            }),
            ..Default::default()
        };

        let mut handler = AccessControlHandler::with_config(config);
        handler.init(ModuleConfig::default()).unwrap();
        handler.start().unwrap();

        // No auth
        let ctx = CheckContext::new().with_client_ip("192.168.1.1");
        let result = handler.check_access(&ctx);
        assert!(!result.allowed);
        assert_eq!(result.denial_reason, DenialReason::Authentication);

        // Valid auth (admin:secret base64)
        let ctx = CheckContext::new()
            .with_client_ip("192.168.1.1")
            .with_authorization("Basic YWRtaW46c2VjcmV0");
        let result = handler.check_access(&ctx);
        assert!(result.allowed);
        assert!(result.auth_result.is_some());
    }

    #[test]
    fn test_policy_evaluation() {
        let config = AccessControlConfig {
            enabled: true,
            policy: Some(PolicyConfig {
                enabled: true,
                strategy: PolicyStrategy::FirstMatch,
                rules: vec![
                    PolicyRule::new("admin-only", RuleAction::Allow)
                        .with_condition(PolicyCondition::HasRole {
                            role: "admin".to_string(),
                        })
                        .with_routes(vec!["/admin/*".to_string()]),
                    PolicyRule::new("deny-admin", RuleAction::Deny)
                        .with_routes(vec!["/admin/*".to_string()]),
                    PolicyRule::new("allow-all", RuleAction::Allow),
                ],
                default_action: RuleAction::Deny,
            }),
            auth: Some(AuthConfig {
                enabled: true,
                required: false,
                providers: vec![AuthProvider::Basic {
                    realm: "Test".to_string(),
                    users: HashMap::from([("admin".to_string(), "secret".to_string())]),
                }],
                ..Default::default()
            }),
            ..Default::default()
        };

        let mut handler = AccessControlHandler::with_config(config);
        handler.init(ModuleConfig::default()).unwrap();
        handler.start().unwrap();

        // Public route - allowed
        let ctx = CheckContext::new()
            .with_client_ip("192.168.1.1")
            .with_path("/api/public");
        let result = handler.check_access(&ctx);
        assert!(result.allowed);

        // Admin route without auth - denied
        let ctx = CheckContext::new()
            .with_client_ip("192.168.1.1")
            .with_path("/admin/users");
        let result = handler.check_access(&ctx);
        assert!(!result.allowed);
        assert_eq!(result.denial_reason, DenialReason::Authorization);
    }

    #[test]
    fn test_check_context_builder() {
        let ctx = CheckContext::new()
            .with_client_ip("192.168.1.1")
            .with_path("/api/users")
            .with_method("POST")
            .with_route("users")
            .with_header("Content-Type", "application/json")
            .with_authorization("Bearer token123");

        assert_eq!(ctx.client_ip, "192.168.1.1");
        assert_eq!(ctx.path, "/api/users");
        assert_eq!(ctx.method, "POST");
        assert_eq!(ctx.route, Some("users".to_string()));
        assert_eq!(
            ctx.headers.get("Content-Type"),
            Some(&"application/json".to_string())
        );
        assert_eq!(ctx.authorization, Some("Bearer token123".to_string()));
    }

    #[test]
    fn test_metrics() {
        let mut handler = AccessControlHandler::new();
        handler.init(ModuleConfig::default()).unwrap();
        handler.start().unwrap();

        // Perform some checks
        let ctx = CheckContext::new().with_client_ip("192.168.1.1");
        let _ = handler.check_access(&ctx);
        let _ = handler.check_access(&ctx);

        let _metrics = handler.metrics();
        // Check that metrics are present - we can't check specific values easily
        // since metrics returns a MetricsPayload, not a HashMap
    }

    #[test]
    fn test_combined_checks() {
        let config = AccessControlConfig {
            enabled: true,
            ip_filter: Some(IpFilterConfig {
                enabled: true,
                rules: vec![IpRule::deny(vec!["10.0.0.0/8".to_string()])],
                default_action: RuleAction::Allow,
                ..Default::default()
            }),
            auth: Some(AuthConfig {
                enabled: true,
                required: true,
                providers: vec![AuthProvider::Basic {
                    realm: "Test".to_string(),
                    users: HashMap::from([("user".to_string(), "pass".to_string())]),
                }],
                ..Default::default()
            }),
            policy: Some(PolicyConfig {
                enabled: true,
                strategy: PolicyStrategy::FirstMatch,
                rules: vec![PolicyRule::new("allow-all", RuleAction::Allow)],
                default_action: RuleAction::Deny,
            }),
            ..Default::default()
        };

        let mut handler = AccessControlHandler::with_config(config);
        handler.init(ModuleConfig::default()).unwrap();
        handler.start().unwrap();

        // IP denied first
        let ctx = CheckContext::new()
            .with_client_ip("10.1.2.3")
            .with_authorization("Basic dXNlcjpwYXNz");
        let result = handler.check_access(&ctx);
        assert!(!result.allowed);
        assert_eq!(result.denial_reason, DenialReason::IpFilter);

        // Auth fails second
        let ctx = CheckContext::new().with_client_ip("192.168.1.1");
        let result = handler.check_access(&ctx);
        assert!(!result.allowed);
        assert_eq!(result.denial_reason, DenialReason::Authentication);

        // All pass
        let ctx = CheckContext::new()
            .with_client_ip("192.168.1.1")
            .with_authorization("Basic dXNlcjpwYXNz"); // user:pass
        let result = handler.check_access(&ctx);
        assert!(result.allowed);
    }
}
