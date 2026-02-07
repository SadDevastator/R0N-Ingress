//! ACME challenge handling

use super::error::{AcmeError, AcmeResult};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::sync::{Arc, RwLock};

/// ACME challenge types
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum ChallengeType {
    /// HTTP-01 challenge
    Http01,
    /// DNS-01 challenge
    Dns01,
    /// TLS-ALPN-01 challenge
    TlsAlpn01,
}

impl ChallengeType {
    /// Get the ACME identifier for this challenge type
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Http01 => "http-01",
            Self::Dns01 => "dns-01",
            Self::TlsAlpn01 => "tls-alpn-01",
        }
    }

    /// Parse from ACME identifier string
    pub fn parse(s: &str) -> Option<Self> {
        match s {
            "http-01" => Some(Self::Http01),
            "dns-01" => Some(Self::Dns01),
            "tls-alpn-01" => Some(Self::TlsAlpn01),
            _ => None,
        }
    }
}

/// Challenge status
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum ChallengeStatus {
    /// Challenge is pending
    Pending,
    /// Challenge is being processed
    Processing,
    /// Challenge completed successfully
    Valid,
    /// Challenge failed
    Invalid,
}

/// Generic challenge
#[derive(Debug, Clone)]
pub struct Challenge {
    /// Challenge type
    pub challenge_type: ChallengeType,

    /// Challenge URL
    pub url: String,

    /// Token from ACME server
    pub token: String,

    /// Current status
    pub status: ChallengeStatus,

    /// Domain this challenge is for
    pub domain: String,

    /// Error details if invalid
    pub error: Option<String>,
}

impl Challenge {
    /// Create a new challenge
    pub fn new(challenge_type: ChallengeType, url: String, token: String, domain: String) -> Self {
        Self {
            challenge_type,
            url,
            token,
            status: ChallengeStatus::Pending,
            domain,
            error: None,
        }
    }

    /// Check if challenge is complete (valid or invalid)
    pub fn is_complete(&self) -> bool {
        matches!(
            self.status,
            ChallengeStatus::Valid | ChallengeStatus::Invalid
        )
    }

    /// Check if challenge succeeded
    pub fn is_valid(&self) -> bool {
        matches!(self.status, ChallengeStatus::Valid)
    }

    /// Check if challenge failed
    pub fn is_invalid(&self) -> bool {
        matches!(self.status, ChallengeStatus::Invalid)
    }
}

/// Challenge token for validation
#[derive(Debug, Clone)]
pub struct ChallengeToken {
    /// The token value
    pub token: String,

    /// Key authorization
    pub key_authorization: String,

    /// Challenge type
    pub challenge_type: ChallengeType,

    /// Domain
    pub domain: String,
}

impl ChallengeToken {
    /// Create a new challenge token
    pub fn new(
        token: String,
        key_thumbprint: &str,
        challenge_type: ChallengeType,
        domain: String,
    ) -> Self {
        let key_authorization = format!("{}.{}", token, key_thumbprint);

        Self {
            token,
            key_authorization,
            challenge_type,
            domain,
        }
    }

    /// Get HTTP-01 response content
    pub fn http01_content(&self) -> &str {
        &self.key_authorization
    }

    /// Get DNS-01 TXT record value (base64url encoded SHA-256 of key authorization)
    pub fn dns01_txt_value(&self) -> String {
        // SHA-256 hash of key authorization, then base64url encode
        let hash = simple_sha256(self.key_authorization.as_bytes());
        base64_url_encode(&hash)
    }

    /// Get the HTTP-01 challenge path
    pub fn http01_path(&self) -> String {
        format!("/.well-known/acme-challenge/{}", self.token)
    }

    /// Get the DNS-01 TXT record name
    pub fn dns01_record_name(&self) -> String {
        format!("_acme-challenge.{}", self.domain)
    }
}

/// HTTP-01 challenge details
#[derive(Debug, Clone)]
pub struct Http01Challenge {
    /// Base challenge
    pub challenge: Challenge,

    /// Challenge token
    pub token: ChallengeToken,
}

impl Http01Challenge {
    /// Create from challenge and key thumbprint
    pub fn new(challenge: Challenge, key_thumbprint: &str) -> Self {
        let token = ChallengeToken::new(
            challenge.token.clone(),
            key_thumbprint,
            ChallengeType::Http01,
            challenge.domain.clone(),
        );

        Self { challenge, token }
    }

    /// Get the path for HTTP response
    pub fn path(&self) -> String {
        self.token.http01_path()
    }

    /// Get the response content
    pub fn response(&self) -> &str {
        self.token.http01_content()
    }
}

/// DNS-01 challenge details
#[derive(Debug, Clone)]
pub struct Dns01Challenge {
    /// Base challenge
    pub challenge: Challenge,

    /// Challenge token
    pub token: ChallengeToken,
}

impl Dns01Challenge {
    /// Create from challenge and key thumbprint
    pub fn new(challenge: Challenge, key_thumbprint: &str) -> Self {
        let token = ChallengeToken::new(
            challenge.token.clone(),
            key_thumbprint,
            ChallengeType::Dns01,
            challenge.domain.clone(),
        );

        Self { challenge, token }
    }

    /// Get the TXT record name
    pub fn record_name(&self) -> String {
        self.token.dns01_record_name()
    }

    /// Get the TXT record value
    pub fn txt_value(&self) -> String {
        self.token.dns01_txt_value()
    }
}

/// HTTP-01 challenge responder
#[derive(Debug, Clone, Default)]
pub struct Http01Responder {
    /// Pending challenges: token -> key_authorization
    challenges: Arc<RwLock<HashMap<String, String>>>,
}

impl Http01Responder {
    /// Create a new responder
    pub fn new() -> Self {
        Self {
            challenges: Arc::new(RwLock::new(HashMap::new())),
        }
    }

    /// Add a challenge to respond to
    pub fn add_challenge(&self, token: &str, key_authorization: &str) -> AcmeResult<()> {
        self.challenges
            .write()
            .map_err(|_| AcmeError::Internal("Lock poisoned".to_string()))?
            .insert(token.to_string(), key_authorization.to_string());
        Ok(())
    }

    /// Remove a challenge
    pub fn remove_challenge(&self, token: &str) -> AcmeResult<()> {
        self.challenges
            .write()
            .map_err(|_| AcmeError::Internal("Lock poisoned".to_string()))?
            .remove(token);
        Ok(())
    }

    /// Get response for a token
    pub fn get_response(&self, token: &str) -> Option<String> {
        self.challenges.read().ok()?.get(token).cloned()
    }

    /// Check if a token is pending
    pub fn has_challenge(&self, token: &str) -> bool {
        self.challenges
            .read()
            .map(|c| c.contains_key(token))
            .unwrap_or(false)
    }

    /// Handle an HTTP request for a challenge
    pub fn handle_request(&self, path: &str) -> Option<String> {
        // Path should be /.well-known/acme-challenge/{token}
        let token = path.strip_prefix("/.well-known/acme-challenge/")?;
        self.get_response(token)
    }

    /// Get count of pending challenges
    pub fn pending_count(&self) -> usize {
        self.challenges.read().map(|c| c.len()).unwrap_or(0)
    }

    /// Clear all challenges
    pub fn clear(&self) -> AcmeResult<()> {
        self.challenges
            .write()
            .map_err(|_| AcmeError::Internal("Lock poisoned".to_string()))?
            .clear();
        Ok(())
    }
}

/// Simple SHA-256 implementation (placeholder)
fn simple_sha256(data: &[u8]) -> [u8; 32] {
    // This is a simplified placeholder
    // In production, use ring or sha2 crate
    use std::collections::hash_map::DefaultHasher;
    use std::hash::{Hash, Hasher};

    let mut result = [0u8; 32];

    for chunk in data.chunks(8) {
        let mut hasher = DefaultHasher::new();
        chunk.hash(&mut hasher);
        let hash = hasher.finish();

        for (i, byte) in hash.to_be_bytes().iter().enumerate() {
            result[i % 32] ^= byte;
        }
    }

    // Additional mixing
    for (i, val) in result.iter_mut().enumerate() {
        let mut hasher = DefaultHasher::new();
        (i, data.len()).hash(&mut hasher);
        *val ^= hasher.finish() as u8;
    }

    result
}

/// Base64 URL-safe encoding without padding
fn base64_url_encode(data: &[u8]) -> String {
    const ALPHABET: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";

    let mut result = String::new();
    let mut bits = 0u32;
    let mut bit_count = 0;

    for &byte in data {
        bits = (bits << 8) | u32::from(byte);
        bit_count += 8;

        while bit_count >= 6 {
            bit_count -= 6;
            let index = ((bits >> bit_count) & 0x3F) as usize;
            result.push(ALPHABET[index] as char);
        }
    }

    if bit_count > 0 {
        let index = ((bits << (6 - bit_count)) & 0x3F) as usize;
        result.push(ALPHABET[index] as char);
    }

    result
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_challenge_type_str() {
        assert_eq!(ChallengeType::Http01.as_str(), "http-01");
        assert_eq!(ChallengeType::Dns01.as_str(), "dns-01");
        assert_eq!(ChallengeType::TlsAlpn01.as_str(), "tls-alpn-01");
    }

    #[test]
    fn test_challenge_type_parse() {
        assert_eq!(ChallengeType::parse("http-01"), Some(ChallengeType::Http01));
        assert_eq!(ChallengeType::parse("dns-01"), Some(ChallengeType::Dns01));
        assert_eq!(ChallengeType::parse("unknown"), None);
    }

    #[test]
    fn test_challenge_creation() {
        let challenge = Challenge::new(
            ChallengeType::Http01,
            "https://acme.example.com/challenge/123".to_string(),
            "abc123".to_string(),
            "example.com".to_string(),
        );

        assert_eq!(challenge.challenge_type, ChallengeType::Http01);
        assert_eq!(challenge.token, "abc123");
        assert!(!challenge.is_complete());
        assert!(!challenge.is_valid());
    }

    #[test]
    fn test_challenge_status() {
        let mut challenge = Challenge::new(
            ChallengeType::Http01,
            "url".to_string(),
            "token".to_string(),
            "domain".to_string(),
        );

        assert!(!challenge.is_complete());

        challenge.status = ChallengeStatus::Valid;
        assert!(challenge.is_complete());
        assert!(challenge.is_valid());

        challenge.status = ChallengeStatus::Invalid;
        assert!(challenge.is_complete());
        assert!(challenge.is_invalid());
    }

    #[test]
    fn test_challenge_token() {
        let token = ChallengeToken::new(
            "abc123".to_string(),
            "thumbprint",
            ChallengeType::Http01,
            "example.com".to_string(),
        );

        assert_eq!(token.key_authorization, "abc123.thumbprint");
        assert_eq!(token.http01_path(), "/.well-known/acme-challenge/abc123");
        assert_eq!(token.dns01_record_name(), "_acme-challenge.example.com");
    }

    #[test]
    fn test_http01_challenge() {
        let challenge = Challenge::new(
            ChallengeType::Http01,
            "url".to_string(),
            "token123".to_string(),
            "example.com".to_string(),
        );

        let http01 = Http01Challenge::new(challenge, "thumbprint");

        assert_eq!(http01.path(), "/.well-known/acme-challenge/token123");
        assert_eq!(http01.response(), "token123.thumbprint");
    }

    #[test]
    fn test_dns01_challenge() {
        let challenge = Challenge::new(
            ChallengeType::Dns01,
            "url".to_string(),
            "token456".to_string(),
            "example.com".to_string(),
        );

        let dns01 = Dns01Challenge::new(challenge, "thumbprint");

        assert_eq!(dns01.record_name(), "_acme-challenge.example.com");
        assert!(!dns01.txt_value().is_empty());
    }

    #[test]
    fn test_http01_responder() {
        let responder = Http01Responder::new();

        responder.add_challenge("token1", "auth1").unwrap();
        responder.add_challenge("token2", "auth2").unwrap();

        assert_eq!(responder.pending_count(), 2);
        assert!(responder.has_challenge("token1"));
        assert!(!responder.has_challenge("token3"));

        assert_eq!(responder.get_response("token1"), Some("auth1".to_string()));
        assert_eq!(responder.get_response("missing"), None);

        responder.remove_challenge("token1").unwrap();
        assert_eq!(responder.pending_count(), 1);
    }

    #[test]
    fn test_responder_handle_request() {
        let responder = Http01Responder::new();
        responder.add_challenge("mytoken", "myauth").unwrap();

        let response = responder.handle_request("/.well-known/acme-challenge/mytoken");
        assert_eq!(response, Some("myauth".to_string()));

        let response = responder.handle_request("/other/path");
        assert_eq!(response, None);
    }

    #[test]
    fn test_responder_clear() {
        let responder = Http01Responder::new();
        responder.add_challenge("t1", "a1").unwrap();
        responder.add_challenge("t2", "a2").unwrap();

        responder.clear().unwrap();
        assert_eq!(responder.pending_count(), 0);
    }

    #[test]
    fn test_base64_url_encode() {
        let data = b"test data";
        let encoded = base64_url_encode(data);
        assert!(!encoded.contains('+'));
        assert!(!encoded.contains('/'));
        assert!(!encoded.contains('='));
    }

    #[test]
    fn test_sha256_produces_output() {
        let data = b"test input";
        let hash = simple_sha256(data);
        assert_eq!(hash.len(), 32);

        // Different inputs should produce different outputs
        let hash2 = simple_sha256(b"different input");
        assert_ne!(hash, hash2);
    }
}
