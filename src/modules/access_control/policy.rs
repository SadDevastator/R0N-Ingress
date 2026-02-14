//! Authorization policy engine.

use std::collections::{HashMap, HashSet};

use super::config::{PolicyCondition, PolicyConfig, PolicyRule, PolicyStrategy, RuleAction};
use super::error::{AccessControlError, AccessControlResult};

/// Context for policy evaluation.
#[derive(Debug, Clone, Default)]
pub struct PolicyContext {
    /// User identity (if authenticated).
    pub identity: Option<String>,

    /// User roles.
    pub roles: HashSet<String>,

    /// User claims (from JWT, etc.).
    pub claims: HashMap<String, String>,

    /// Request path.
    pub path: String,

    /// Request method.
    pub method: String,

    /// Request headers.
    pub headers: HashMap<String, String>,

    /// Client IP address.
    pub client_ip: String,

    /// Additional context data.
    pub extra: HashMap<String, String>,
}

impl PolicyContext {
    /// Create a new policy context.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Set the identity.
    #[must_use]
    pub fn with_identity(mut self, identity: impl Into<String>) -> Self {
        self.identity = Some(identity.into());
        self
    }

    /// Add a role.
    #[must_use]
    pub fn with_role(mut self, role: impl Into<String>) -> Self {
        self.roles.insert(role.into());
        self
    }

    /// Add multiple roles.
    #[must_use]
    pub fn with_roles(mut self, roles: impl IntoIterator<Item = impl Into<String>>) -> Self {
        for role in roles {
            self.roles.insert(role.into());
        }
        self
    }

    /// Add a claim.
    #[must_use]
    pub fn with_claim(mut self, key: impl Into<String>, value: impl Into<String>) -> Self {
        self.claims.insert(key.into(), value.into());
        self
    }

    /// Set the request path.
    #[must_use]
    pub fn with_path(mut self, path: impl Into<String>) -> Self {
        self.path = path.into();
        self
    }

    /// Set the request method.
    #[must_use]
    pub fn with_method(mut self, method: impl Into<String>) -> Self {
        self.method = method.into();
        self
    }

    /// Set a header.
    #[must_use]
    pub fn with_header(mut self, key: impl Into<String>, value: impl Into<String>) -> Self {
        self.headers.insert(key.into(), value.into());
        self
    }

    /// Set the client IP.
    #[must_use]
    pub fn with_client_ip(mut self, ip: impl Into<String>) -> Self {
        self.client_ip = ip.into();
        self
    }

    /// Check if the user has a role.
    #[must_use]
    pub fn has_role(&self, role: &str) -> bool {
        self.roles.contains(role)
    }

    /// Check if the user has any of the roles.
    #[must_use]
    pub fn has_any_role(&self, roles: &[String]) -> bool {
        roles.iter().any(|r| self.roles.contains(r))
    }

    /// Check if the user has all of the roles.
    #[must_use]
    pub fn has_all_roles(&self, roles: &[String]) -> bool {
        roles.iter().all(|r| self.roles.contains(r))
    }

    /// Get a claim value.
    #[must_use]
    pub fn get_claim(&self, key: &str) -> Option<&str> {
        self.claims.get(key).map(String::as_str)
    }

    /// Get a header value.
    #[must_use]
    pub fn get_header(&self, key: &str) -> Option<&str> {
        self.headers.get(key).map(String::as_str)
    }
}

/// Result of a policy evaluation.
#[derive(Debug, Clone)]
pub struct PolicyDecision {
    /// The action to take.
    pub action: RuleAction,

    /// The rule that matched (if any).
    pub matched_rule: Option<String>,

    /// Reason for the decision.
    pub reason: String,

    /// Additional data.
    pub data: HashMap<String, String>,
}

impl PolicyDecision {
    /// Create an allow decision.
    #[must_use]
    pub fn allow(reason: impl Into<String>) -> Self {
        Self {
            action: RuleAction::Allow,
            matched_rule: None,
            reason: reason.into(),
            data: HashMap::new(),
        }
    }

    /// Create a deny decision.
    #[must_use]
    pub fn deny(reason: impl Into<String>) -> Self {
        Self {
            action: RuleAction::Deny,
            matched_rule: None,
            reason: reason.into(),
            data: HashMap::new(),
        }
    }

    /// Create a challenge decision.
    #[must_use]
    pub fn challenge(reason: impl Into<String>) -> Self {
        Self {
            action: RuleAction::Challenge,
            matched_rule: None,
            reason: reason.into(),
            data: HashMap::new(),
        }
    }

    /// Set the matched rule.
    #[must_use]
    pub fn with_rule(mut self, rule: impl Into<String>) -> Self {
        self.matched_rule = Some(rule.into());
        self
    }

    /// Check if the request is allowed.
    #[must_use]
    pub fn is_allowed(&self) -> bool {
        self.action.is_allow()
    }

    /// Check if the request is denied.
    #[must_use]
    pub fn is_denied(&self) -> bool {
        self.action.is_deny()
    }
}

/// Policy engine for authorization.
#[derive(Debug)]
pub struct PolicyEngine {
    /// Configuration.
    config: PolicyConfig,

    /// Rules sorted by priority (if using priority strategy).
    sorted_rules: Vec<PolicyRule>,
}

impl PolicyEngine {
    /// Create a new policy engine.
    #[must_use]
    pub fn new(config: PolicyConfig) -> Self {
        let mut sorted_rules = config.rules.clone();

        // Sort by priority for Priority strategy
        if config.strategy == PolicyStrategy::Priority {
            sorted_rules.sort_by(|a, b| b.priority.cmp(&a.priority));
        }

        Self {
            config,
            sorted_rules,
        }
    }

    /// Evaluate the policy for a given context.
    pub fn evaluate(&self, context: &PolicyContext) -> AccessControlResult<PolicyDecision> {
        match self.config.strategy {
            PolicyStrategy::FirstMatch => self.evaluate_first_match(context),
            PolicyStrategy::AllMustAllow => self.evaluate_all_must_allow(context),
            PolicyStrategy::AnyMustAllow => self.evaluate_any_must_allow(context),
            PolicyStrategy::Priority => self.evaluate_priority(context),
        }
    }

    /// First matching rule wins.
    fn evaluate_first_match(&self, context: &PolicyContext) -> AccessControlResult<PolicyDecision> {
        for rule in &self.config.rules {
            if self.rule_applies(rule, context)
                && self.evaluate_conditions(&rule.conditions, context)?
            {
                return Ok(PolicyDecision {
                    action: rule.action,
                    matched_rule: Some(rule.name.clone()),
                    reason: format!("Rule '{}' matched", rule.name),
                    data: HashMap::new(),
                });
            }
        }

        Ok(self.default_decision())
    }

    /// All matching rules must allow.
    fn evaluate_all_must_allow(
        &self,
        context: &PolicyContext,
    ) -> AccessControlResult<PolicyDecision> {
        let mut any_matched = false;

        for rule in &self.config.rules {
            if self.rule_applies(rule, context)
                && self.evaluate_conditions(&rule.conditions, context)?
            {
                any_matched = true;

                if !rule.action.is_allow() {
                    return Ok(PolicyDecision {
                        action: rule.action,
                        matched_rule: Some(rule.name.clone()),
                        reason: format!("Rule '{}' denied access", rule.name),
                        data: HashMap::new(),
                    });
                }
            }
        }

        if any_matched {
            Ok(PolicyDecision::allow("All rules allowed"))
        } else {
            Ok(self.default_decision())
        }
    }

    /// Any matching rule allowing is sufficient.
    fn evaluate_any_must_allow(
        &self,
        context: &PolicyContext,
    ) -> AccessControlResult<PolicyDecision> {
        let mut any_matched = false;
        let mut last_deny: Option<PolicyDecision> = None;

        for rule in &self.config.rules {
            if self.rule_applies(rule, context)
                && self.evaluate_conditions(&rule.conditions, context)?
            {
                any_matched = true;

                if rule.action.is_allow() {
                    return Ok(PolicyDecision {
                        action: rule.action,
                        matched_rule: Some(rule.name.clone()),
                        reason: format!("Rule '{}' allowed access", rule.name),
                        data: HashMap::new(),
                    });
                }
                last_deny = Some(PolicyDecision {
                    action: rule.action,
                    matched_rule: Some(rule.name.clone()),
                    reason: format!("Rule '{}' denied access", rule.name),
                    data: HashMap::new(),
                });
            }
        }

        if any_matched {
            // No allow found, return last deny or default
            Ok(last_deny.unwrap_or_else(|| self.default_decision()))
        } else {
            Ok(self.default_decision())
        }
    }

    /// Priority-based evaluation (highest priority first).
    fn evaluate_priority(&self, context: &PolicyContext) -> AccessControlResult<PolicyDecision> {
        for rule in &self.sorted_rules {
            if self.rule_applies(rule, context)
                && self.evaluate_conditions(&rule.conditions, context)?
            {
                return Ok(PolicyDecision {
                    action: rule.action,
                    matched_rule: Some(rule.name.clone()),
                    reason: format!("Rule '{}' matched (priority {})", rule.name, rule.priority),
                    data: HashMap::new(),
                });
            }
        }

        Ok(self.default_decision())
    }

    /// Check if a rule applies to the current context (route/method).
    fn rule_applies(&self, rule: &PolicyRule, context: &PolicyContext) -> bool {
        // Check route
        if !rule.routes.is_empty() {
            let matches_route = rule
                .routes
                .iter()
                .any(|pattern| self.path_matches(pattern, &context.path));

            if !matches_route {
                return false;
            }
        }

        // Check method
        if !rule.methods.is_empty() {
            let matches_method = rule
                .methods
                .iter()
                .any(|m| m.eq_ignore_ascii_case(&context.method));

            if !matches_method {
                return false;
            }
        }

        true
    }

    /// Check if a path matches a pattern.
    fn path_matches(&self, pattern: &str, path: &str) -> bool {
        if let Some(prefix) = pattern.strip_suffix("/*") {
            // "/admin/*" matches "/admin/foo", "/admin/foo/bar"
            path.starts_with(prefix) && path.len() > prefix.len()
        } else if let Some(prefix) = pattern.strip_suffix('*') {
            // "/admin*" matches "/admin", "/adminfoo"
            path.starts_with(prefix)
        } else {
            pattern == path
        }
    }

    /// Evaluate all conditions for a rule.
    fn evaluate_conditions(
        &self,
        conditions: &[PolicyCondition],
        context: &PolicyContext,
    ) -> AccessControlResult<bool> {
        // Empty conditions = always match
        if conditions.is_empty() {
            return Ok(true);
        }

        // All conditions must be true (AND logic)
        for condition in conditions {
            if !self.evaluate_condition(condition, context)? {
                return Ok(false);
            }
        }

        Ok(true)
    }

    /// Evaluate a single condition.
    fn evaluate_condition(
        &self,
        condition: &PolicyCondition,
        context: &PolicyContext,
    ) -> AccessControlResult<bool> {
        match condition {
            PolicyCondition::HasRole { role } => Ok(context.has_role(role)),

            PolicyCondition::HasAnyRole { roles } => Ok(context.has_any_role(roles)),

            PolicyCondition::HasAllRoles { roles } => Ok(context.has_all_roles(roles)),

            PolicyCondition::ClaimEquals { claim, value } => {
                Ok(context.get_claim(claim) == Some(value.as_str()))
            },

            PolicyCondition::ClaimContains { claim, value } => Ok(context
                .get_claim(claim)
                .map(|v| v.contains(value.as_str()))
                .unwrap_or(false)),

            PolicyCondition::HeaderEquals { header, value } => {
                Ok(context.get_header(header) == Some(value.as_str()))
            },

            PolicyCondition::TimeRange { start, end } => {
                // Placeholder - would need actual time checking
                let _ = (start, end);
                Ok(true)
            },

            PolicyCondition::IpInList { addresses } => {
                // Parse and check CIDR
                for addr in addresses {
                    if self.ip_matches(addr, &context.client_ip) {
                        return Ok(true);
                    }
                }
                Ok(false)
            },

            PolicyCondition::Expression { expr } => {
                // Placeholder for future expression evaluation
                let _ = expr;
                Err(AccessControlError::PolicyError(
                    "Expression evaluation not implemented".to_string(),
                ))
            },
        }
    }

    /// Check if an IP matches a CIDR pattern.
    fn ip_matches(&self, pattern: &str, ip: &str) -> bool {
        // Parse IP
        let ip_u32 = match Self::parse_ip(ip) {
            Ok(v) => v,
            Err(_) => return false,
        };

        // Parse CIDR
        let (net_str, prefix) = if let Some((n, p)) = pattern.split_once('/') {
            let prefix: u8 = p.parse().unwrap_or(32);
            (n, prefix)
        } else {
            (pattern, 32)
        };

        let network = match Self::parse_ip(net_str) {
            Ok(v) => v,
            Err(_) => return false,
        };

        let mask = if prefix == 0 {
            0
        } else {
            !0u32 << (32 - prefix)
        };
        (ip_u32 & mask) == (network & mask)
    }

    /// Parse an IP to u32.
    fn parse_ip(ip: &str) -> AccessControlResult<u32> {
        let parts: Vec<&str> = ip.split('.').collect();
        if parts.len() != 4 {
            return Err(AccessControlError::InvalidIpAddress(ip.to_string()));
        }

        let mut result = 0u32;
        for (i, part) in parts.iter().enumerate() {
            let octet: u8 = part
                .parse()
                .map_err(|_| AccessControlError::InvalidIpAddress(ip.to_string()))?;
            result |= (octet as u32) << (24 - i * 8);
        }

        Ok(result)
    }

    /// Get the default decision.
    fn default_decision(&self) -> PolicyDecision {
        PolicyDecision {
            action: self.config.default_action,
            matched_rule: None,
            reason: "No rules matched, using default action".to_string(),
            data: HashMap::new(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_policy_context_builder() {
        let ctx = PolicyContext::new()
            .with_identity("user@example.com")
            .with_role("admin")
            .with_roles(["user", "editor"])
            .with_claim("org", "acme")
            .with_path("/api/users")
            .with_method("GET")
            .with_client_ip("192.168.1.1");

        assert_eq!(ctx.identity, Some("user@example.com".to_string()));
        assert!(ctx.has_role("admin"));
        assert!(ctx.has_role("user"));
        assert!(ctx.has_role("editor"));
        assert!(ctx.has_all_roles(&["admin".to_string(), "user".to_string()]));
        assert!(ctx.has_any_role(&["admin".to_string(), "guest".to_string()]));
        assert_eq!(ctx.get_claim("org"), Some("acme"));
        assert_eq!(ctx.path, "/api/users");
        assert_eq!(ctx.method, "GET");
    }

    #[test]
    fn test_first_match_strategy() {
        let config = PolicyConfig {
            enabled: true,
            strategy: PolicyStrategy::FirstMatch,
            rules: vec![
                PolicyRule::new("deny-delete", RuleAction::Deny).with_condition(
                    PolicyCondition::HeaderEquals {
                        header: "X-Method".to_string(),
                        value: "DELETE".to_string(),
                    },
                ),
                PolicyRule::new("allow-all", RuleAction::Allow),
            ],
            default_action: RuleAction::Deny,
        };

        let engine = PolicyEngine::new(config);

        // First rule matches
        let ctx = PolicyContext::new().with_header("X-Method", "DELETE");
        let decision = engine.evaluate(&ctx).unwrap();
        assert!(decision.is_denied());
        assert_eq!(decision.matched_rule, Some("deny-delete".to_string()));

        // Second rule matches
        let ctx = PolicyContext::new();
        let decision = engine.evaluate(&ctx).unwrap();
        assert!(decision.is_allowed());
        assert_eq!(decision.matched_rule, Some("allow-all".to_string()));
    }

    #[test]
    fn test_role_based_policy() {
        let config = PolicyConfig {
            enabled: true,
            strategy: PolicyStrategy::FirstMatch,
            rules: vec![
                PolicyRule::new("admin-only", RuleAction::Allow)
                    .with_condition(PolicyCondition::HasRole {
                        role: "admin".to_string(),
                    })
                    .with_routes(vec!["/admin/*".to_string()]),
                PolicyRule::new("deny-admin-routes", RuleAction::Deny)
                    .with_routes(vec!["/admin/*".to_string()]),
                PolicyRule::new("allow-public", RuleAction::Allow),
            ],
            default_action: RuleAction::Deny,
        };

        let engine = PolicyEngine::new(config);

        // Admin can access /admin
        let ctx = PolicyContext::new()
            .with_role("admin")
            .with_path("/admin/users");
        let decision = engine.evaluate(&ctx).unwrap();
        assert!(decision.is_allowed());

        // Non-admin denied /admin
        let ctx = PolicyContext::new()
            .with_role("user")
            .with_path("/admin/users");
        let decision = engine.evaluate(&ctx).unwrap();
        assert!(decision.is_denied());

        // Non-admin can access public
        let ctx = PolicyContext::new()
            .with_role("user")
            .with_path("/api/users");
        let decision = engine.evaluate(&ctx).unwrap();
        assert!(decision.is_allowed());
    }

    #[test]
    fn test_all_must_allow_strategy() {
        // AllMustAllow means: all rules that match must have Allow action
        // If any matching rule has Deny action, the result is Deny
        let config = PolicyConfig {
            enabled: true,
            strategy: PolicyStrategy::AllMustAllow,
            rules: vec![
                PolicyRule::new("check-auth", RuleAction::Allow).with_condition(
                    PolicyCondition::HasRole {
                        role: "authenticated".to_string(),
                    },
                ),
                PolicyRule::new("deny-unverified", RuleAction::Deny).with_condition(
                    PolicyCondition::ClaimEquals {
                        claim: "verified".to_string(),
                        value: "false".to_string(),
                    },
                ),
            ],
            default_action: RuleAction::Deny,
        };

        let engine = PolicyEngine::new(config);

        // Authenticated and not unverified - only first rule matches, allows
        let ctx = PolicyContext::new()
            .with_role("authenticated")
            .with_claim("verified", "true");
        let decision = engine.evaluate(&ctx).unwrap();
        assert!(decision.is_allowed());

        // Authenticated but marked as unverified - both rules match, second denies
        let ctx = PolicyContext::new()
            .with_role("authenticated")
            .with_claim("verified", "false");
        let decision = engine.evaluate(&ctx).unwrap();
        assert!(decision.is_denied());
    }

    #[test]
    fn test_any_must_allow_strategy() {
        let config = PolicyConfig {
            enabled: true,
            strategy: PolicyStrategy::AnyMustAllow,
            rules: vec![
                PolicyRule::new("admin-access", RuleAction::Allow).with_condition(
                    PolicyCondition::HasRole {
                        role: "admin".to_string(),
                    },
                ),
                PolicyRule::new("vip-access", RuleAction::Allow).with_condition(
                    PolicyCondition::ClaimEquals {
                        claim: "tier".to_string(),
                        value: "vip".to_string(),
                    },
                ),
            ],
            default_action: RuleAction::Deny,
        };

        let engine = PolicyEngine::new(config);

        // First condition met
        let ctx = PolicyContext::new().with_role("admin");
        let decision = engine.evaluate(&ctx).unwrap();
        assert!(decision.is_allowed());

        // Second condition met
        let ctx = PolicyContext::new().with_claim("tier", "vip");
        let decision = engine.evaluate(&ctx).unwrap();
        assert!(decision.is_allowed());

        // Neither condition met
        let ctx = PolicyContext::new().with_role("user");
        let decision = engine.evaluate(&ctx).unwrap();
        assert!(decision.is_denied());
    }

    #[test]
    fn test_priority_strategy() {
        let config = PolicyConfig {
            enabled: true,
            strategy: PolicyStrategy::Priority,
            rules: vec![
                PolicyRule {
                    name: "low-priority-allow".to_string(),
                    conditions: vec![],
                    action: RuleAction::Allow,
                    priority: 1,
                    routes: vec![],
                    methods: vec![],
                },
                PolicyRule {
                    name: "high-priority-deny".to_string(),
                    conditions: vec![PolicyCondition::HasRole {
                        role: "blocked".to_string(),
                    }],
                    action: RuleAction::Deny,
                    priority: 10,
                    routes: vec![],
                    methods: vec![],
                },
            ],
            default_action: RuleAction::Deny,
        };

        let engine = PolicyEngine::new(config);

        // High priority deny wins
        let ctx = PolicyContext::new().with_role("blocked");
        let decision = engine.evaluate(&ctx).unwrap();
        assert!(decision.is_denied());
        assert!(decision.reason.contains("priority 10"));

        // Without blocked role, allow wins
        let ctx = PolicyContext::new();
        let decision = engine.evaluate(&ctx).unwrap();
        assert!(decision.is_allowed());
    }

    #[test]
    fn test_method_filtering() {
        let config = PolicyConfig {
            enabled: true,
            strategy: PolicyStrategy::FirstMatch,
            rules: vec![PolicyRule::new("readonly", RuleAction::Deny)
                .with_routes(vec!["/api/*".to_string()])
                .with_condition(PolicyCondition::HasRole {
                    role: "readonly".to_string(),
                })],
            default_action: RuleAction::Allow,
        };

        let mut rule = config.rules[0].clone();
        rule.methods = vec!["POST".to_string(), "PUT".to_string(), "DELETE".to_string()];

        let config = PolicyConfig {
            rules: vec![rule],
            ..config
        };

        let engine = PolicyEngine::new(config);

        // GET is allowed
        let ctx = PolicyContext::new()
            .with_role("readonly")
            .with_path("/api/users")
            .with_method("GET");
        let decision = engine.evaluate(&ctx).unwrap();
        assert!(decision.is_allowed());

        // POST is denied
        let ctx = PolicyContext::new()
            .with_role("readonly")
            .with_path("/api/users")
            .with_method("POST");
        let decision = engine.evaluate(&ctx).unwrap();
        assert!(decision.is_denied());
    }

    #[test]
    fn test_ip_in_list_condition() {
        let config = PolicyConfig {
            enabled: true,
            strategy: PolicyStrategy::FirstMatch,
            rules: vec![
                PolicyRule::new("internal-only", RuleAction::Allow).with_condition(
                    PolicyCondition::IpInList {
                        addresses: vec!["10.0.0.0/8".to_string(), "192.168.0.0/16".to_string()],
                    },
                ),
            ],
            default_action: RuleAction::Deny,
        };

        let engine = PolicyEngine::new(config);

        // Internal IP allowed
        let ctx = PolicyContext::new().with_client_ip("10.1.2.3");
        let decision = engine.evaluate(&ctx).unwrap();
        assert!(decision.is_allowed());

        // External IP denied
        let ctx = PolicyContext::new().with_client_ip("8.8.8.8");
        let decision = engine.evaluate(&ctx).unwrap();
        assert!(decision.is_denied());
    }

    #[test]
    fn test_default_action() {
        let config = PolicyConfig {
            enabled: true,
            strategy: PolicyStrategy::FirstMatch,
            rules: vec![],
            default_action: RuleAction::Deny,
        };

        let engine = PolicyEngine::new(config);
        let ctx = PolicyContext::new();
        let decision = engine.evaluate(&ctx).unwrap();

        assert!(decision.is_denied());
        assert!(decision.matched_rule.is_none());
        assert!(decision.reason.contains("default"));
    }
}
