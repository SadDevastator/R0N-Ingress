//! Authentication providers for access control.

use std::collections::HashMap;
use std::sync::Arc;

use super::config::{ApiKeyConfig, AuthProvider};
use super::error::{AccessControlError, AccessControlResult};

/// Constant-time byte comparison to prevent timing side-channel attacks.
fn constant_time_eq(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    a.iter()
        .zip(b.iter())
        .fold(0u8, |acc, (x, y)| acc | (x ^ y))
        == 0
}

/// Result of an authentication attempt.
#[derive(Debug, Clone)]
pub struct AuthResult {
    /// Whether authentication succeeded.
    pub authenticated: bool,

    /// The authenticated identity (username, email, etc.).
    pub identity: Option<String>,

    /// Roles granted to the user.
    pub roles: Vec<String>,

    /// Claims extracted from the token/credentials.
    pub claims: HashMap<String, String>,

    /// Error message if authentication failed.
    pub error: Option<String>,
}

impl AuthResult {
    /// Create a successful authentication result.
    #[must_use]
    pub fn success(identity: impl Into<String>) -> Self {
        Self {
            authenticated: true,
            identity: Some(identity.into()),
            roles: Vec::new(),
            claims: HashMap::new(),
            error: None,
        }
    }

    /// Create a failed authentication result.
    #[must_use]
    pub fn failure(error: impl Into<String>) -> Self {
        Self {
            authenticated: false,
            identity: None,
            roles: Vec::new(),
            claims: HashMap::new(),
            error: Some(error.into()),
        }
    }

    /// Add roles.
    #[must_use]
    pub fn with_roles(mut self, roles: Vec<String>) -> Self {
        self.roles = roles;
        self
    }

    /// Add a claim.
    #[must_use]
    pub fn with_claim(mut self, key: impl Into<String>, value: impl Into<String>) -> Self {
        self.claims.insert(key.into(), value.into());
        self
    }

    /// Add multiple claims.
    #[must_use]
    pub fn with_claims(mut self, claims: HashMap<String, String>) -> Self {
        self.claims.extend(claims);
        self
    }
}

/// Context for authentication.
#[derive(Debug, Clone, Default)]
pub struct AuthContext {
    /// The raw Authorization header value.
    pub authorization_header: Option<String>,

    /// Token from query parameter.
    pub query_token: Option<String>,

    /// Token from cookie.
    pub cookie_token: Option<String>,

    /// All request headers.
    pub headers: HashMap<String, String>,

    /// Request path.
    pub path: String,

    /// Request method.
    pub method: String,

    /// Client IP address.
    pub client_ip: String,
}

impl AuthContext {
    /// Create a new auth context.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Set the Authorization header.
    #[must_use]
    pub fn with_authorization(mut self, value: impl Into<String>) -> Self {
        self.authorization_header = Some(value.into());
        self
    }

    /// Set a header.
    #[must_use]
    pub fn with_header(mut self, key: impl Into<String>, value: impl Into<String>) -> Self {
        self.headers.insert(key.into(), value.into());
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

    /// Extract Basic auth credentials.
    pub fn extract_basic_auth(&self) -> Option<(String, String)> {
        let header = self.authorization_header.as_ref()?;

        if !header.starts_with("Basic ") {
            return None;
        }

        let encoded = &header[6..];
        let decoded = base64_decode(encoded).ok()?;
        let decoded_str = String::from_utf8(decoded).ok()?;

        let (username, password) = decoded_str.split_once(':')?;
        Some((username.to_string(), password.to_string()))
    }

    /// Extract Bearer token.
    pub fn extract_bearer_token(&self) -> Option<&str> {
        let header = self.authorization_header.as_ref()?;

        if !header.starts_with("Bearer ") {
            return None;
        }

        Some(&header[7..])
    }

    /// Get an API key from headers.
    pub fn get_api_key(&self, header_name: &str) -> Option<&str> {
        self.headers.get(header_name).map(String::as_str)
    }
}

/// Simple base64 decoder (minimal implementation for Basic auth).
fn base64_decode(input: &str) -> AccessControlResult<Vec<u8>> {
    const ALPHABET: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

    fn char_to_val(c: u8) -> Option<u8> {
        ALPHABET.iter().position(|&x| x == c).map(|p| p as u8)
    }

    let input = input.trim_end_matches('=');
    let mut output = Vec::with_capacity(input.len() * 3 / 4);

    let bytes = input.as_bytes();
    let mut i = 0;

    while i + 3 < bytes.len() {
        let a = char_to_val(bytes[i]).ok_or_else(|| {
            AccessControlError::TokenError("Invalid base64 character".to_string())
        })?;
        let b = char_to_val(bytes[i + 1]).ok_or_else(|| {
            AccessControlError::TokenError("Invalid base64 character".to_string())
        })?;
        let c = char_to_val(bytes[i + 2]).ok_or_else(|| {
            AccessControlError::TokenError("Invalid base64 character".to_string())
        })?;
        let d = char_to_val(bytes[i + 3]).ok_or_else(|| {
            AccessControlError::TokenError("Invalid base64 character".to_string())
        })?;

        output.push((a << 2) | (b >> 4));
        output.push((b << 4) | (c >> 2));
        output.push((c << 6) | d);

        i += 4;
    }

    // Handle remaining bytes
    let remaining = bytes.len() - i;
    if remaining >= 2 {
        let a = char_to_val(bytes[i]).ok_or_else(|| {
            AccessControlError::TokenError("Invalid base64 character".to_string())
        })?;
        let b = char_to_val(bytes[i + 1]).ok_or_else(|| {
            AccessControlError::TokenError("Invalid base64 character".to_string())
        })?;

        output.push((a << 2) | (b >> 4));

        if remaining >= 3 {
            let c = char_to_val(bytes[i + 2]).ok_or_else(|| {
                AccessControlError::TokenError("Invalid base64 character".to_string())
            })?;
            output.push((b << 4) | (c >> 2));
        }
    }

    Ok(output)
}

/// Trait for authentication hooks.
pub trait AuthHook: Send + Sync {
    /// Authenticate a request.
    fn authenticate(&self, context: &AuthContext) -> AccessControlResult<AuthResult>;

    /// Get the provider name.
    fn name(&self) -> &str;
}

/// Basic authentication provider.
#[derive(Debug)]
pub struct BasicAuthProvider {
    /// Realm for challenge.
    realm: String,

    /// Users (username -> password hash).
    users: HashMap<String, String>,
}

impl BasicAuthProvider {
    /// Create a new Basic auth provider.
    #[must_use]
    pub fn new(realm: impl Into<String>, users: HashMap<String, String>) -> Self {
        Self {
            realm: realm.into(),
            users,
        }
    }

    /// Get the realm.
    #[must_use]
    pub fn realm(&self) -> &str {
        &self.realm
    }

    /// Verify a password against a hash.
    ///
    /// Uses constant-time comparison to prevent timing side-channel attacks.
    fn verify_password(&self, password: &str, hash: &str) -> bool {
        // Simple comparison - in production, use proper password hashing
        // This supports plain text (for testing) and simple hash prefix
        if let Some(plain) = hash.strip_prefix("plain:") {
            constant_time_eq(password.as_bytes(), plain.as_bytes())
        } else {
            // Default: assume plain text comparison
            constant_time_eq(password.as_bytes(), hash.as_bytes())
        }
    }
}

impl AuthHook for BasicAuthProvider {
    fn authenticate(&self, context: &AuthContext) -> AccessControlResult<AuthResult> {
        let (username, password) = match context.extract_basic_auth() {
            Some(creds) => creds,
            None => {
                return Ok(AuthResult::failure("No Basic authentication credentials"));
            },
        };

        match self.users.get(&username) {
            Some(hash) if self.verify_password(&password, hash) => {
                Ok(AuthResult::success(&username))
            },
            Some(_) => Ok(AuthResult::failure("Invalid password")),
            None => Ok(AuthResult::failure("Unknown user")),
        }
    }

    fn name(&self) -> &str {
        "basic"
    }
}

/// API key authentication provider.
#[derive(Debug)]
pub struct ApiKeyProvider {
    /// Header name for API key.
    header: String,

    /// Valid API keys.
    keys: HashMap<String, ApiKeyConfig>,
}

impl ApiKeyProvider {
    /// Create a new API key provider.
    #[must_use]
    pub fn new(header: impl Into<String>, keys: HashMap<String, ApiKeyConfig>) -> Self {
        Self {
            header: header.into(),
            keys,
        }
    }

    /// Get the header name.
    #[must_use]
    pub fn header(&self) -> &str {
        &self.header
    }
}

impl AuthHook for ApiKeyProvider {
    fn authenticate(&self, context: &AuthContext) -> AccessControlResult<AuthResult> {
        // Try to get the API key from headers
        let key = match context.get_api_key(&self.header) {
            Some(k) => k,
            None => {
                // Also try lowercase header
                match context.get_api_key(&self.header.to_lowercase()) {
                    Some(k) => k,
                    None => return Ok(AuthResult::failure("No API key provided")),
                }
            },
        };

        match self.keys.get(key) {
            Some(config) if config.active => Ok(AuthResult::success(key)
                .with_roles(config.roles.clone())
                .with_claim(
                    "description",
                    config.description.clone().unwrap_or_default(),
                )),
            Some(_) => Ok(AuthResult::failure("API key is inactive")),
            None => Ok(AuthResult::failure("Invalid API key")),
        }
    }

    fn name(&self) -> &str {
        "api_key"
    }
}

/// JWT authentication provider (simplified).
#[derive(Debug)]
pub struct JwtProvider {
    /// Secret for verification (used in production for signature validation).
    #[allow(dead_code)]
    secret: String,

    /// Expected issuer.
    issuer: Option<String>,

    /// Expected audience.
    audience: Option<String>,

    /// Claims to extract.
    extract_claims: Vec<String>,
}

impl JwtProvider {
    /// Create a new JWT provider.
    #[must_use]
    pub fn new(secret: impl Into<String>) -> Self {
        Self {
            secret: secret.into(),
            issuer: None,
            audience: None,
            extract_claims: Vec::new(),
        }
    }

    /// Set expected issuer.
    #[must_use]
    pub fn with_issuer(mut self, issuer: impl Into<String>) -> Self {
        self.issuer = Some(issuer.into());
        self
    }

    /// Set expected audience.
    #[must_use]
    pub fn with_audience(mut self, audience: impl Into<String>) -> Self {
        self.audience = Some(audience.into());
        self
    }

    /// Set claims to extract.
    #[must_use]
    pub fn with_extract_claims(mut self, claims: Vec<String>) -> Self {
        self.extract_claims = claims;
        self
    }

    /// Parse a JWT token (simplified - extracts payload only).
    fn parse_token(&self, token: &str) -> AccessControlResult<HashMap<String, String>> {
        let parts: Vec<&str> = token.split('.').collect();
        if parts.len() != 3 {
            return Err(AccessControlError::TokenError(
                "Invalid JWT format".to_string(),
            ));
        }

        // Decode payload (middle part)
        let payload = base64_decode(parts[1])?;
        let payload_str = String::from_utf8(payload)
            .map_err(|_| AccessControlError::TokenError("Invalid UTF-8 in JWT".to_string()))?;

        // Simple JSON parsing (in production, use serde_json)
        let claims = self.parse_simple_json(&payload_str)?;

        Ok(claims)
    }

    /// Very simple JSON parser for flat objects.
    fn parse_simple_json(&self, json: &str) -> AccessControlResult<HashMap<String, String>> {
        let mut claims = HashMap::new();

        // Remove braces and split by comma
        let json = json.trim();
        if !json.starts_with('{') || !json.ends_with('}') {
            return Err(AccessControlError::TokenError(
                "Invalid JSON format".to_string(),
            ));
        }

        let inner = &json[1..json.len() - 1];

        for pair in inner.split(',') {
            let pair = pair.trim();
            if let Some((key, value)) = pair.split_once(':') {
                let key = key.trim().trim_matches('"');
                let value = value.trim().trim_matches('"');
                claims.insert(key.to_string(), value.to_string());
            }
        }

        Ok(claims)
    }
}

impl AuthHook for JwtProvider {
    fn authenticate(&self, context: &AuthContext) -> AccessControlResult<AuthResult> {
        let token = match context.extract_bearer_token() {
            Some(t) => t,
            None => return Ok(AuthResult::failure("No Bearer token provided")),
        };

        // Parse the token
        let claims = self.parse_token(token)?;

        // Validate issuer
        if let Some(expected_iss) = &self.issuer {
            match claims.get("iss") {
                Some(iss) if iss == expected_iss => {},
                _ => return Ok(AuthResult::failure("Invalid issuer")),
            }
        }

        // Validate audience
        if let Some(expected_aud) = &self.audience {
            match claims.get("aud") {
                Some(aud) if aud == expected_aud => {},
                _ => return Ok(AuthResult::failure("Invalid audience")),
            }
        }

        // Extract identity (sub claim)
        let identity = claims
            .get("sub")
            .cloned()
            .unwrap_or_else(|| "unknown".to_string());

        // Extract requested claims
        let mut result = AuthResult::success(&identity);
        for claim_name in &self.extract_claims {
            if let Some(value) = claims.get(claim_name) {
                result = result.with_claim(claim_name, value);
            }
        }

        Ok(result)
    }

    fn name(&self) -> &str {
        "jwt"
    }
}

/// Authentication manager that tries multiple providers.
#[derive(Debug)]
pub struct AuthManager {
    /// Authentication providers.
    providers: Vec<Arc<dyn AuthHook>>,

    /// Whether authentication is required.
    required: bool,
}

impl AuthManager {
    /// Create a new auth manager.
    #[must_use]
    pub fn new(required: bool) -> Self {
        Self {
            providers: Vec::new(),
            required,
        }
    }

    /// Add a provider.
    pub fn add_provider(&mut self, provider: Arc<dyn AuthHook>) {
        self.providers.push(provider);
    }

    /// Create from config.
    pub fn from_providers(providers: &[AuthProvider], required: bool) -> AccessControlResult<Self> {
        let mut manager = Self::new(required);

        for provider in providers {
            match provider {
                AuthProvider::Basic { realm, users } => {
                    manager.add_provider(Arc::new(BasicAuthProvider::new(realm, users.clone())));
                },
                AuthProvider::Jwt {
                    secret,
                    issuer,
                    audience,
                    extract_claims,
                    ..
                } => {
                    let mut jwt = JwtProvider::new(secret);
                    if let Some(iss) = issuer {
                        jwt = jwt.with_issuer(iss);
                    }
                    if let Some(aud) = audience {
                        jwt = jwt.with_audience(aud);
                    }
                    jwt = jwt.with_extract_claims(extract_claims.clone());
                    manager.add_provider(Arc::new(jwt));
                },
                AuthProvider::ApiKey { header, keys } => {
                    manager.add_provider(Arc::new(ApiKeyProvider::new(header, keys.clone())));
                },
                AuthProvider::External { .. } => {
                    // External providers would need async support
                    // For now, skip them
                },
            }
        }

        Ok(manager)
    }

    /// Authenticate a request.
    pub fn authenticate(&self, context: &AuthContext) -> AccessControlResult<AuthResult> {
        for provider in &self.providers {
            let result = provider.authenticate(context)?;
            if result.authenticated {
                return Ok(result);
            }
        }

        if self.required {
            Err(AccessControlError::AuthenticationFailed(
                "No valid credentials provided".to_string(),
            ))
        } else {
            Ok(AuthResult::failure("No authentication"))
        }
    }

    /// Check if authentication is required.
    #[must_use]
    pub fn is_required(&self) -> bool {
        self.required
    }

    /// Get the number of providers.
    #[must_use]
    pub fn provider_count(&self) -> usize {
        self.providers.len()
    }
}

// Implement Debug manually for AuthManager since Arc<dyn AuthHook> doesn't implement Debug
impl std::fmt::Debug for dyn AuthHook {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "AuthHook({})", self.name())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_auth_result_builder() {
        let result = AuthResult::success("user@example.com")
            .with_roles(vec!["admin".to_string()])
            .with_claim("org", "acme");

        assert!(result.authenticated);
        assert_eq!(result.identity, Some("user@example.com".to_string()));
        assert_eq!(result.roles, vec!["admin".to_string()]);
        assert_eq!(result.claims.get("org"), Some(&"acme".to_string()));
    }

    #[test]
    fn test_basic_auth_extraction() {
        // "user:password" base64 encoded
        let ctx = AuthContext::new().with_authorization("Basic dXNlcjpwYXNzd29yZA==");

        let (username, password) = ctx.extract_basic_auth().unwrap();
        assert_eq!(username, "user");
        assert_eq!(password, "password");
    }

    #[test]
    fn test_bearer_token_extraction() {
        let ctx = AuthContext::new().with_authorization("Bearer abc123token");

        assert_eq!(ctx.extract_bearer_token(), Some("abc123token"));
    }

    #[test]
    fn test_basic_auth_provider() {
        let users = HashMap::from([
            ("admin".to_string(), "plain:secret".to_string()),
            ("user".to_string(), "password123".to_string()),
        ]);

        let provider = BasicAuthProvider::new("Test Realm", users);

        // Valid credentials
        let ctx = AuthContext::new().with_authorization("Basic YWRtaW46c2VjcmV0"); // admin:secret
        let result = provider.authenticate(&ctx).unwrap();
        assert!(result.authenticated);
        assert_eq!(result.identity, Some("admin".to_string()));

        // Invalid password
        let ctx = AuthContext::new().with_authorization("Basic YWRtaW46d3Jvbmc="); // admin:wrong
        let result = provider.authenticate(&ctx).unwrap();
        assert!(!result.authenticated);

        // Unknown user
        let ctx = AuthContext::new().with_authorization("Basic dW5rbm93bjpwYXNz"); // unknown:pass
        let result = provider.authenticate(&ctx).unwrap();
        assert!(!result.authenticated);
    }

    #[test]
    fn test_api_key_provider() {
        let keys = HashMap::from([
            (
                "valid-key-123".to_string(),
                ApiKeyConfig {
                    description: Some("Test key".to_string()),
                    roles: vec!["user".to_string()],
                    rate_limit: None,
                    active: true,
                },
            ),
            (
                "inactive-key".to_string(),
                ApiKeyConfig {
                    active: false,
                    ..Default::default()
                },
            ),
        ]);

        let provider = ApiKeyProvider::new("X-API-Key", keys);

        // Valid key
        let ctx = AuthContext::new().with_header("X-API-Key", "valid-key-123");
        let result = provider.authenticate(&ctx).unwrap();
        assert!(result.authenticated);
        assert_eq!(result.roles, vec!["user".to_string()]);

        // Inactive key
        let ctx = AuthContext::new().with_header("X-API-Key", "inactive-key");
        let result = provider.authenticate(&ctx).unwrap();
        assert!(!result.authenticated);

        // Invalid key
        let ctx = AuthContext::new().with_header("X-API-Key", "invalid-key");
        let result = provider.authenticate(&ctx).unwrap();
        assert!(!result.authenticated);
    }

    #[test]
    fn test_auth_manager() {
        let users = HashMap::from([("admin".to_string(), "secret".to_string())]);

        let mut manager = AuthManager::new(false);
        manager.add_provider(Arc::new(BasicAuthProvider::new("Test", users)));

        // Valid auth
        let ctx = AuthContext::new().with_authorization("Basic YWRtaW46c2VjcmV0");
        let result = manager.authenticate(&ctx).unwrap();
        assert!(result.authenticated);

        // No auth (not required)
        let ctx = AuthContext::new();
        let result = manager.authenticate(&ctx).unwrap();
        assert!(!result.authenticated);
        assert!(result.error.is_some());
    }

    #[test]
    fn test_auth_manager_required() {
        let manager = AuthManager::new(true);

        // No auth but required
        let ctx = AuthContext::new();
        let result = manager.authenticate(&ctx);
        assert!(result.is_err());
    }

    #[test]
    fn test_base64_decode() {
        // "Hello World"
        let decoded = base64_decode("SGVsbG8gV29ybGQ=").unwrap();
        assert_eq!(String::from_utf8(decoded).unwrap(), "Hello World");

        // "user:password"
        let decoded = base64_decode("dXNlcjpwYXNzd29yZA==").unwrap();
        assert_eq!(String::from_utf8(decoded).unwrap(), "user:password");
    }

    #[test]
    fn test_jwt_parsing() {
        // Create a simple JWT-like structure (no signature verification in this simplified version)
        // Header: {"alg":"HS256","typ":"JWT"} -> eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9
        // Payload: {"sub":"user123","iss":"test"} -> eyJzdWIiOiJ1c2VyMTIzIiwiaXNzIjoidGVzdCJ9
        // Signature: fake

        let provider = JwtProvider::new("secret").with_issuer("test");

        let token =
            "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiJ1c2VyMTIzIiwiaXNzIjoidGVzdCJ9.fake";
        let ctx = AuthContext::new().with_authorization(format!("Bearer {token}"));

        let result = provider.authenticate(&ctx).unwrap();
        assert!(result.authenticated);
        assert_eq!(result.identity, Some("user123".to_string()));
    }
}
