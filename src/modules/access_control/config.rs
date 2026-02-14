//! Configuration for access control.

use serde::{Deserialize, Serialize};
use std::collections::HashMap;

/// Main configuration for the access control module.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AccessControlConfig {
    /// Whether access control is enabled.
    #[serde(default = "default_enabled")]
    pub enabled: bool,

    /// Default action when no rules match.
    #[serde(default)]
    pub default_action: RuleAction,

    /// IP filtering configuration.
    #[serde(default)]
    pub ip_filter: Option<IpFilterConfig>,

    /// Authentication configuration.
    #[serde(default)]
    pub auth: Option<AuthConfig>,

    /// Authorization policy configuration.
    #[serde(default)]
    pub policy: Option<PolicyConfig>,

    /// Per-route access control overrides.
    #[serde(default)]
    pub routes: HashMap<String, RouteAccessConfig>,
}

fn default_enabled() -> bool {
    true
}

impl Default for AccessControlConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            default_action: RuleAction::Allow,
            ip_filter: None,
            auth: None,
            policy: None,
            routes: HashMap::new(),
        }
    }
}

impl AccessControlConfig {
    /// Create a new access control config.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Enable IP filtering.
    #[must_use]
    pub fn with_ip_filter(mut self, config: IpFilterConfig) -> Self {
        self.ip_filter = Some(config);
        self
    }

    /// Enable authentication.
    #[must_use]
    pub fn with_auth(mut self, config: AuthConfig) -> Self {
        self.auth = Some(config);
        self
    }

    /// Enable authorization policies.
    #[must_use]
    pub fn with_policy(mut self, config: PolicyConfig) -> Self {
        self.policy = Some(config);
        self
    }

    /// Add a route-specific configuration.
    #[must_use]
    pub fn with_route(mut self, route: impl Into<String>, config: RouteAccessConfig) -> Self {
        self.routes.insert(route.into(), config);
        self
    }

    /// Validate the configuration.
    pub fn validate(&self) -> Result<(), String> {
        if let Some(ref ip_filter) = self.ip_filter {
            ip_filter.validate()?;
        }

        if let Some(ref auth) = self.auth {
            auth.validate()?;
        }

        if let Some(ref policy) = self.policy {
            policy.validate()?;
        }

        Ok(())
    }
}

/// Action to take for an access control rule.
#[derive(Debug, Clone, Copy, Default, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub enum RuleAction {
    /// Allow the request.
    #[default]
    Allow,

    /// Deny the request.
    Deny,

    /// Challenge the request (require authentication).
    Challenge,

    /// Log but allow (audit mode).
    Log,
}

impl RuleAction {
    /// Check if this action allows the request.
    #[must_use]
    pub fn is_allow(&self) -> bool {
        matches!(self, Self::Allow | Self::Log)
    }

    /// Check if this action denies the request.
    #[must_use]
    pub fn is_deny(&self) -> bool {
        matches!(self, Self::Deny)
    }
}

/// IP filtering configuration.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IpFilterConfig {
    /// Whether IP filtering is enabled.
    #[serde(default = "default_enabled")]
    pub enabled: bool,

    /// IP rules to evaluate.
    #[serde(default)]
    pub rules: Vec<IpRule>,

    /// Default action if no rules match.
    #[serde(default)]
    pub default_action: RuleAction,

    /// Trust proxy headers (X-Forwarded-For, X-Real-IP).
    #[serde(default)]
    pub trust_proxy_headers: bool,

    /// Trusted proxy IPs (only trust headers from these).
    #[serde(default)]
    pub trusted_proxies: Vec<String>,
}

impl Default for IpFilterConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            rules: Vec::new(),
            default_action: RuleAction::Allow,
            trust_proxy_headers: false,
            trusted_proxies: Vec::new(),
        }
    }
}

impl IpFilterConfig {
    /// Validate the configuration.
    pub fn validate(&self) -> Result<(), String> {
        for (i, rule) in self.rules.iter().enumerate() {
            rule.validate()
                .map_err(|e| format!("ip_filter.rules[{i}]: {e}"))?;
        }
        Ok(())
    }
}

/// A single IP filter rule.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IpRule {
    /// Name/description of the rule.
    #[serde(default)]
    pub name: Option<String>,

    /// IP addresses or CIDR ranges to match.
    pub addresses: Vec<String>,

    /// Action to take when matched.
    pub action: RuleAction,

    /// Priority (higher = evaluated first).
    #[serde(default)]
    pub priority: i32,
}

impl IpRule {
    /// Create a new allow rule.
    #[must_use]
    pub fn allow(addresses: Vec<String>) -> Self {
        Self {
            name: None,
            addresses,
            action: RuleAction::Allow,
            priority: 0,
        }
    }

    /// Create a new deny rule.
    #[must_use]
    pub fn deny(addresses: Vec<String>) -> Self {
        Self {
            name: None,
            addresses,
            action: RuleAction::Deny,
            priority: 0,
        }
    }

    /// Set the rule name.
    #[must_use]
    pub fn with_name(mut self, name: impl Into<String>) -> Self {
        self.name = Some(name.into());
        self
    }

    /// Set the priority.
    #[must_use]
    pub fn with_priority(mut self, priority: i32) -> Self {
        self.priority = priority;
        self
    }

    /// Validate the rule.
    pub fn validate(&self) -> Result<(), String> {
        if self.addresses.is_empty() {
            return Err("addresses cannot be empty".to_string());
        }

        for addr in &self.addresses {
            // Basic validation - proper validation in ip_filter module
            if addr.is_empty() {
                return Err("empty address in list".to_string());
            }
        }

        Ok(())
    }
}

/// Authentication configuration.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuthConfig {
    /// Whether authentication is enabled.
    #[serde(default = "default_enabled")]
    pub enabled: bool,

    /// Required authentication for all requests.
    #[serde(default)]
    pub required: bool,

    /// Authentication providers.
    #[serde(default)]
    pub providers: Vec<AuthProvider>,

    /// Header to check for authentication token.
    #[serde(default = "default_auth_header")]
    pub header: String,

    /// Query parameter for token (alternative to header).
    #[serde(default)]
    pub query_param: Option<String>,

    /// Cookie name for session token.
    #[serde(default)]
    pub cookie: Option<String>,

    /// Anonymous access allowed for these routes.
    #[serde(default)]
    pub anonymous_routes: Vec<String>,
}

fn default_auth_header() -> String {
    "Authorization".to_string()
}

impl Default for AuthConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            required: false,
            providers: Vec::new(),
            header: default_auth_header(),
            query_param: None,
            cookie: None,
            anonymous_routes: Vec::new(),
        }
    }
}

impl AuthConfig {
    /// Validate the configuration.
    pub fn validate(&self) -> Result<(), String> {
        if self.required && self.providers.is_empty() {
            return Err("auth.required is true but no providers configured".to_string());
        }

        for (i, provider) in self.providers.iter().enumerate() {
            provider
                .validate()
                .map_err(|e| format!("auth.providers[{i}]: {e}"))?;
        }

        Ok(())
    }
}

/// Authentication provider configuration.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "lowercase")]
pub enum AuthProvider {
    /// Basic authentication.
    Basic {
        /// Realm for basic auth challenge.
        #[serde(default = "default_realm")]
        realm: String,
        /// Users (username -> password hash).
        users: HashMap<String, String>,
    },

    /// JWT/Bearer token authentication.
    Jwt {
        /// Secret key for HS256 (or path to public key for RS256).
        secret: String,
        /// Algorithm (HS256, RS256, etc.).
        #[serde(default = "default_jwt_algorithm")]
        algorithm: String,
        /// Issuer to validate.
        issuer: Option<String>,
        /// Audience to validate.
        audience: Option<String>,
        /// Claims to extract and add to context.
        #[serde(default)]
        extract_claims: Vec<String>,
    },

    /// API key authentication.
    ApiKey {
        /// Header name for API key.
        #[serde(default = "default_api_key_header")]
        header: String,
        /// Valid API keys.
        keys: HashMap<String, ApiKeyConfig>,
    },

    /// External authentication provider.
    External {
        /// URL to call for authentication.
        url: String,
        /// HTTP method to use.
        #[serde(default = "default_http_method")]
        method: String,
        /// Headers to forward to the auth endpoint.
        #[serde(default)]
        forward_headers: Vec<String>,
        /// Timeout for auth request.
        #[serde(default = "default_auth_timeout")]
        timeout_ms: u64,
    },
}

fn default_realm() -> String {
    "R0N Gateway".to_string()
}

fn default_jwt_algorithm() -> String {
    "HS256".to_string()
}

fn default_api_key_header() -> String {
    "X-API-Key".to_string()
}

fn default_http_method() -> String {
    "GET".to_string()
}

fn default_auth_timeout() -> u64 {
    5000
}

impl AuthProvider {
    /// Validate the provider configuration.
    pub fn validate(&self) -> Result<(), String> {
        match self {
            Self::Basic { users, .. } => {
                if users.is_empty() {
                    return Err("basic auth requires at least one user".to_string());
                }
            },
            Self::Jwt { secret, .. } => {
                if secret.is_empty() {
                    return Err("jwt requires a secret".to_string());
                }
            },
            Self::ApiKey { keys, .. } => {
                if keys.is_empty() {
                    return Err("api_key requires at least one key".to_string());
                }
            },
            Self::External { url, .. } => {
                if url.is_empty() {
                    return Err("external auth requires a url".to_string());
                }
            },
        }
        Ok(())
    }

    /// Get the provider type name.
    #[must_use]
    pub fn provider_type(&self) -> &'static str {
        match self {
            Self::Basic { .. } => "basic",
            Self::Jwt { .. } => "jwt",
            Self::ApiKey { .. } => "api_key",
            Self::External { .. } => "external",
        }
    }
}

/// API key configuration.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ApiKeyConfig {
    /// Description of the API key.
    #[serde(default)]
    pub description: Option<String>,

    /// Roles/permissions granted by this key.
    #[serde(default)]
    pub roles: Vec<String>,

    /// Rate limit override for this key.
    #[serde(default)]
    pub rate_limit: Option<u64>,

    /// Whether the key is active.
    #[serde(default = "default_enabled")]
    pub active: bool,
}

impl Default for ApiKeyConfig {
    fn default() -> Self {
        Self {
            description: None,
            roles: Vec::new(),
            rate_limit: None,
            active: true,
        }
    }
}

/// Authorization policy configuration.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PolicyConfig {
    /// Whether policy evaluation is enabled.
    #[serde(default = "default_enabled")]
    pub enabled: bool,

    /// Policy evaluation strategy.
    #[serde(default)]
    pub strategy: PolicyStrategy,

    /// Policy rules.
    #[serde(default)]
    pub rules: Vec<PolicyRule>,

    /// Default action when no rules match.
    #[serde(default)]
    pub default_action: RuleAction,
}

impl Default for PolicyConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            strategy: PolicyStrategy::default(),
            rules: Vec::new(),
            default_action: RuleAction::Allow,
        }
    }
}

impl PolicyConfig {
    /// Validate the configuration.
    pub fn validate(&self) -> Result<(), String> {
        for (i, rule) in self.rules.iter().enumerate() {
            rule.validate()
                .map_err(|e| format!("policy.rules[{i}]: {e}"))?;
        }
        Ok(())
    }
}

/// Policy evaluation strategy.
#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum PolicyStrategy {
    /// First matching rule wins.
    #[default]
    FirstMatch,

    /// All rules must allow (AND logic).
    AllMustAllow,

    /// Any rule allowing is sufficient (OR logic).
    AnyMustAllow,

    /// Priority-based evaluation.
    Priority,
}

/// A single policy rule.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PolicyRule {
    /// Name of the rule.
    pub name: String,

    /// Conditions that must be met.
    #[serde(default)]
    pub conditions: Vec<PolicyCondition>,

    /// Action to take when conditions are met.
    pub action: RuleAction,

    /// Priority (for priority-based strategy).
    #[serde(default)]
    pub priority: i32,

    /// Routes this rule applies to (empty = all).
    #[serde(default)]
    pub routes: Vec<String>,

    /// Methods this rule applies to (empty = all).
    #[serde(default)]
    pub methods: Vec<String>,
}

impl PolicyRule {
    /// Create a new policy rule.
    #[must_use]
    pub fn new(name: impl Into<String>, action: RuleAction) -> Self {
        Self {
            name: name.into(),
            conditions: Vec::new(),
            action,
            priority: 0,
            routes: Vec::new(),
            methods: Vec::new(),
        }
    }

    /// Add a condition.
    #[must_use]
    pub fn with_condition(mut self, condition: PolicyCondition) -> Self {
        self.conditions.push(condition);
        self
    }

    /// Set routes.
    #[must_use]
    pub fn with_routes(mut self, routes: Vec<String>) -> Self {
        self.routes = routes;
        self
    }

    /// Validate the rule.
    pub fn validate(&self) -> Result<(), String> {
        if self.name.is_empty() {
            return Err("rule name cannot be empty".to_string());
        }
        Ok(())
    }
}

/// A condition for a policy rule.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum PolicyCondition {
    /// Check if user has a role.
    HasRole {
        /// The role to check for.
        role: String,
    },

    /// Check if user has any of the roles.
    HasAnyRole {
        /// The roles to check for.
        roles: Vec<String>,
    },

    /// Check if user has all of the roles.
    HasAllRoles {
        /// The roles that must all be present.
        roles: Vec<String>,
    },

    /// Check if a claim has a specific value.
    ClaimEquals {
        /// The claim name.
        claim: String,
        /// The expected value.
        value: String,
    },

    /// Check if a claim contains a value.
    ClaimContains {
        /// The claim name.
        claim: String,
        /// The value to search for.
        value: String,
    },

    /// Check if a header has a specific value.
    HeaderEquals {
        /// The header name.
        header: String,
        /// The expected value.
        value: String,
    },

    /// Check if the request time is within a range.
    TimeRange {
        /// Start time (HH:MM format).
        start: String,
        /// End time (HH:MM format).
        end: String,
    },

    /// Check if the client IP is in a list.
    IpInList {
        /// IP addresses or CIDR ranges.
        addresses: Vec<String>,
    },

    /// Custom expression (for future extensibility).
    Expression {
        /// The expression to evaluate.
        expr: String,
    },
}

/// Per-route access control configuration.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct RouteAccessConfig {
    /// Override IP filter for this route.
    #[serde(default)]
    pub ip_filter: Option<IpFilterConfig>,

    /// Whether authentication is required.
    #[serde(default)]
    pub auth_required: Option<bool>,

    /// Required roles for this route.
    #[serde(default)]
    pub required_roles: Vec<String>,

    /// Override policy rules for this route.
    #[serde(default)]
    pub policy_rules: Vec<PolicyRule>,

    /// Override action for this route.
    #[serde(default)]
    pub action: Option<RuleAction>,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_default_config() {
        let config = AccessControlConfig::default();
        assert!(config.enabled);
        assert_eq!(config.default_action, RuleAction::Allow);
        assert!(config.ip_filter.is_none());
        assert!(config.auth.is_none());
    }

    #[test]
    fn test_rule_action() {
        assert!(RuleAction::Allow.is_allow());
        assert!(RuleAction::Log.is_allow());
        assert!(!RuleAction::Deny.is_allow());

        assert!(RuleAction::Deny.is_deny());
        assert!(!RuleAction::Allow.is_deny());
    }

    #[test]
    fn test_ip_rule_creation() {
        let rule = IpRule::deny(vec!["10.0.0.0/8".to_string()])
            .with_name("block-internal")
            .with_priority(10);

        assert_eq!(rule.action, RuleAction::Deny);
        assert_eq!(rule.name, Some("block-internal".to_string()));
        assert_eq!(rule.priority, 10);
    }

    #[test]
    fn test_auth_provider_validation() {
        let basic = AuthProvider::Basic {
            realm: "test".to_string(),
            users: HashMap::from([("user".to_string(), "hash".to_string())]),
        };
        assert!(basic.validate().is_ok());

        let empty_basic = AuthProvider::Basic {
            realm: "test".to_string(),
            users: HashMap::new(),
        };
        assert!(empty_basic.validate().is_err());

        let jwt = AuthProvider::Jwt {
            secret: "secret".to_string(),
            algorithm: "HS256".to_string(),
            issuer: None,
            audience: None,
            extract_claims: Vec::new(),
        };
        assert!(jwt.validate().is_ok());
    }

    #[test]
    fn test_policy_rule_creation() {
        let rule = PolicyRule::new("admin-only", RuleAction::Allow)
            .with_condition(PolicyCondition::HasRole {
                role: "admin".to_string(),
            })
            .with_routes(vec!["/admin/*".to_string()]);

        assert_eq!(rule.name, "admin-only");
        assert_eq!(rule.action, RuleAction::Allow);
        assert_eq!(rule.conditions.len(), 1);
        assert_eq!(rule.routes.len(), 1);
    }

    #[test]
    fn test_config_builder() {
        let config = AccessControlConfig::new()
            .with_ip_filter(IpFilterConfig::default())
            .with_auth(AuthConfig::default())
            .with_policy(PolicyConfig::default())
            .with_route("/api/*", RouteAccessConfig::default());

        assert!(config.ip_filter.is_some());
        assert!(config.auth.is_some());
        assert!(config.policy.is_some());
        assert!(config.routes.contains_key("/api/*"));
    }

    #[test]
    fn test_config_validation() {
        let config = AccessControlConfig::default();
        assert!(config.validate().is_ok());

        // Auth required but no providers
        let bad_config = AccessControlConfig {
            auth: Some(AuthConfig {
                required: true,
                providers: Vec::new(),
                ..Default::default()
            }),
            ..Default::default()
        };
        assert!(bad_config.validate().is_err());
    }
}
