//! ACME order management

use super::challenge::{Challenge, ChallengeType};
use super::error::{AcmeError, AcmeResult};
use serde::{Deserialize, Serialize};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

/// ACME order status
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum OrderStatus {
    /// Order is pending authorization
    Pending,
    /// Order is ready for finalization
    Ready,
    /// Order is being processed
    Processing,
    /// Order is complete
    Valid,
    /// Order failed
    Invalid,
}

/// Authorization status
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum AuthorizationStatus {
    /// Authorization is pending
    Pending,
    /// Authorization is valid
    Valid,
    /// Authorization is invalid
    Invalid,
    /// Authorization was deactivated
    Deactivated,
    /// Authorization expired
    Expired,
    /// Authorization was revoked
    Revoked,
}

/// ACME order
#[derive(Debug, Clone)]
pub struct Order {
    /// Order URL
    pub url: String,

    /// Order status
    pub status: OrderStatus,

    /// Ordered identifiers (domains)
    pub identifiers: Vec<Identifier>,

    /// Authorization URLs
    pub authorizations: Vec<String>,

    /// Finalize URL
    pub finalize: String,

    /// Certificate URL (when valid)
    pub certificate: Option<String>,

    /// Order expiry
    pub expires: Option<u64>,

    /// When the order was created
    pub created_at: u64,

    /// Error details if invalid
    pub error: Option<OrderError>,
}

impl Order {
    /// Create a new order
    pub fn new(
        url: String,
        identifiers: Vec<Identifier>,
        authorizations: Vec<String>,
        finalize: String,
    ) -> Self {
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();

        Self {
            url,
            status: OrderStatus::Pending,
            identifiers,
            authorizations,
            finalize,
            certificate: None,
            expires: None,
            created_at: now,
            error: None,
        }
    }

    /// Check if order is pending
    pub fn is_pending(&self) -> bool {
        matches!(self.status, OrderStatus::Pending)
    }

    /// Check if order is ready for finalization
    pub fn is_ready(&self) -> bool {
        matches!(self.status, OrderStatus::Ready)
    }

    /// Check if order is complete
    pub fn is_valid(&self) -> bool {
        matches!(self.status, OrderStatus::Valid)
    }

    /// Check if order failed
    pub fn is_invalid(&self) -> bool {
        matches!(self.status, OrderStatus::Invalid)
    }

    /// Check if order is expired
    pub fn is_expired(&self) -> bool {
        if let Some(expires) = self.expires {
            let now = SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap_or_default()
                .as_secs();
            now >= expires
        } else {
            false
        }
    }

    /// Get domains from identifiers
    pub fn domains(&self) -> Vec<&str> {
        self.identifiers
            .iter()
            .filter_map(|id| {
                if id.id_type == IdentifierType::Dns {
                    Some(id.value.as_str())
                } else {
                    None
                }
            })
            .collect()
    }

    /// Get time until expiry
    pub fn time_until_expiry(&self) -> Option<Duration> {
        self.expires.and_then(|expires| {
            let now = SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap_or_default()
                .as_secs();
            if expires > now {
                Some(Duration::from_secs(expires - now))
            } else {
                None
            }
        })
    }
}

/// ACME identifier
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Identifier {
    /// Identifier type
    #[serde(rename = "type")]
    pub id_type: IdentifierType,

    /// Identifier value (domain name)
    pub value: String,
}

impl Identifier {
    /// Create a DNS identifier
    pub fn dns(domain: impl Into<String>) -> Self {
        Self {
            id_type: IdentifierType::Dns,
            value: domain.into(),
        }
    }
}

/// Identifier type
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum IdentifierType {
    /// DNS domain name
    Dns,
    /// IP address
    Ip,
}

/// Order error details
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OrderError {
    /// Error type
    #[serde(rename = "type")]
    pub error_type: String,

    /// Error detail
    pub detail: String,

    /// Error status code
    pub status: Option<u16>,

    /// Sub-problems
    #[serde(default)]
    pub subproblems: Vec<SubProblem>,
}

/// Sub-problem in order error
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SubProblem {
    /// Error type
    #[serde(rename = "type")]
    pub error_type: String,

    /// Error detail
    pub detail: String,

    /// Related identifier
    pub identifier: Option<Identifier>,
}

/// ACME authorization
#[derive(Debug, Clone)]
pub struct Authorization {
    /// Authorization URL
    pub url: String,

    /// Authorization status
    pub status: AuthorizationStatus,

    /// Identifier being authorized
    pub identifier: Identifier,

    /// Available challenges
    pub challenges: Vec<Challenge>,

    /// Expiry timestamp
    pub expires: Option<u64>,

    /// Wildcard authorization
    pub wildcard: bool,
}

impl Authorization {
    /// Create a new authorization
    pub fn new(url: String, identifier: Identifier, challenges: Vec<Challenge>) -> Self {
        Self {
            url,
            status: AuthorizationStatus::Pending,
            identifier,
            challenges,
            expires: None,
            wildcard: false,
        }
    }

    /// Check if authorization is pending
    pub fn is_pending(&self) -> bool {
        matches!(self.status, AuthorizationStatus::Pending)
    }

    /// Check if authorization is valid
    pub fn is_valid(&self) -> bool {
        matches!(self.status, AuthorizationStatus::Valid)
    }

    /// Get the domain being authorized
    pub fn domain(&self) -> &str {
        &self.identifier.value
    }

    /// Get a challenge by type
    pub fn get_challenge(&self, challenge_type: ChallengeType) -> Option<&Challenge> {
        self.challenges
            .iter()
            .find(|c| c.challenge_type == challenge_type)
    }

    /// Get HTTP-01 challenge if available
    pub fn http01_challenge(&self) -> Option<&Challenge> {
        self.get_challenge(ChallengeType::Http01)
    }

    /// Get DNS-01 challenge if available
    pub fn dns01_challenge(&self) -> Option<&Challenge> {
        self.get_challenge(ChallengeType::Dns01)
    }

    /// Get available challenge types
    pub fn available_challenge_types(&self) -> Vec<ChallengeType> {
        self.challenges.iter().map(|c| c.challenge_type).collect()
    }
}

/// Order builder for creating new orders
#[allow(dead_code)]
#[derive(Debug, Default)]
pub struct OrderBuilder {
    domains: Vec<String>,
    not_before: Option<u64>,
    not_after: Option<u64>,
}

#[allow(dead_code)]
impl OrderBuilder {
    /// Create a new order builder
    pub fn new() -> Self {
        Self::default()
    }

    /// Add a domain to the order
    pub fn domain(mut self, domain: impl Into<String>) -> Self {
        self.domains.push(domain.into());
        self
    }

    /// Add multiple domains
    pub fn domains(mut self, domains: impl IntoIterator<Item = impl Into<String>>) -> Self {
        for domain in domains {
            self.domains.push(domain.into());
        }
        self
    }

    /// Set not before time
    pub fn not_before(mut self, timestamp: u64) -> Self {
        self.not_before = Some(timestamp);
        self
    }

    /// Set not after time
    pub fn not_after(mut self, timestamp: u64) -> Self {
        self.not_after = Some(timestamp);
        self
    }

    /// Validate the order request
    pub fn validate(&self) -> AcmeResult<()> {
        if self.domains.is_empty() {
            return Err(AcmeError::Order("No domains specified".to_string()));
        }

        for domain in &self.domains {
            Self::validate_domain(domain)?;
        }

        Ok(())
    }

    /// Validate a domain name
    fn validate_domain(domain: &str) -> AcmeResult<()> {
        if domain.is_empty() {
            return Err(AcmeError::DomainValidation("Empty domain".to_string()));
        }

        if domain.len() > 253 {
            return Err(AcmeError::DomainValidation("Domain too long".to_string()));
        }

        // Check for valid characters
        for c in domain.chars() {
            if !c.is_ascii_alphanumeric() && c != '.' && c != '-' && c != '*' {
                return Err(AcmeError::DomainValidation(format!(
                    "Invalid character '{}' in domain",
                    c
                )));
            }
        }

        // Check wildcard format
        if domain.contains('*') {
            if !domain.starts_with("*.") {
                return Err(AcmeError::DomainValidation(
                    "Wildcard must be at start of domain".to_string(),
                ));
            }
            if domain.matches('*').count() > 1 {
                return Err(AcmeError::DomainValidation(
                    "Only one wildcard allowed".to_string(),
                ));
            }
        }

        Ok(())
    }

    /// Build identifiers for the order
    pub fn build_identifiers(&self) -> Vec<Identifier> {
        self.domains
            .iter()
            .map(|d| Identifier::dns(d.clone()))
            .collect()
    }

    /// Get the domains
    pub fn get_domains(&self) -> &[String] {
        &self.domains
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_order_creation() {
        let order = Order::new(
            "https://acme.example.com/order/123".to_string(),
            vec![Identifier::dns("example.com")],
            vec!["https://acme.example.com/authz/456".to_string()],
            "https://acme.example.com/finalize/123".to_string(),
        );

        assert!(order.is_pending());
        assert!(!order.is_ready());
        assert!(!order.is_valid());
        assert_eq!(order.domains(), vec!["example.com"]);
    }

    #[test]
    fn test_order_status() {
        let mut order = Order::new(
            "url".to_string(),
            vec![Identifier::dns("test.com")],
            vec![],
            "finalize".to_string(),
        );

        assert!(order.is_pending());

        order.status = OrderStatus::Ready;
        assert!(order.is_ready());

        order.status = OrderStatus::Valid;
        assert!(order.is_valid());

        order.status = OrderStatus::Invalid;
        assert!(order.is_invalid());
    }

    #[test]
    fn test_order_expiry() {
        let mut order = Order::new("url".to_string(), vec![], vec![], "finalize".to_string());

        assert!(!order.is_expired());

        // Set expiry in the past
        order.expires = Some(1);
        assert!(order.is_expired());

        // Set expiry in the future
        let future = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs()
            + 3600;
        order.expires = Some(future);
        assert!(!order.is_expired());
        assert!(order.time_until_expiry().is_some());
    }

    #[test]
    fn test_identifier() {
        let id = Identifier::dns("example.com");
        assert_eq!(id.id_type, IdentifierType::Dns);
        assert_eq!(id.value, "example.com");
    }

    #[test]
    fn test_authorization() {
        let challenge = Challenge::new(
            ChallengeType::Http01,
            "url".to_string(),
            "token".to_string(),
            "example.com".to_string(),
        );

        let auth = Authorization::new(
            "https://acme.example.com/authz/123".to_string(),
            Identifier::dns("example.com"),
            vec![challenge],
        );

        assert!(auth.is_pending());
        assert_eq!(auth.domain(), "example.com");
        assert!(auth.http01_challenge().is_some());
        assert!(auth.dns01_challenge().is_none());
        assert_eq!(
            auth.available_challenge_types(),
            vec![ChallengeType::Http01]
        );
    }

    #[test]
    fn test_order_builder() {
        let builder = OrderBuilder::new()
            .domain("example.com")
            .domain("www.example.com");

        assert!(builder.validate().is_ok());
        assert_eq!(builder.get_domains().len(), 2);

        let identifiers = builder.build_identifiers();
        assert_eq!(identifiers.len(), 2);
    }

    #[test]
    fn test_order_builder_empty() {
        let builder = OrderBuilder::new();
        assert!(builder.validate().is_err());
    }

    #[test]
    fn test_order_builder_invalid_domain() {
        let builder = OrderBuilder::new().domain("invalid domain");
        assert!(builder.validate().is_err());
    }

    #[test]
    fn test_order_builder_wildcard() {
        let builder = OrderBuilder::new().domain("*.example.com");
        assert!(builder.validate().is_ok());

        let builder = OrderBuilder::new().domain("example.*.com");
        assert!(builder.validate().is_err());

        let builder = OrderBuilder::new().domain("*.*.example.com");
        assert!(builder.validate().is_err());
    }

    #[test]
    fn test_order_builder_multiple_domains() {
        let builder =
            OrderBuilder::new().domains(vec!["example.com", "example.org", "example.net"]);

        assert_eq!(builder.get_domains().len(), 3);
        assert!(builder.validate().is_ok());
    }
}
