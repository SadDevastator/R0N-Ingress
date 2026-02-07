//! ACME account management

use super::error::{AcmeError, AcmeResult};
use serde::{Deserialize, Serialize};
use std::path::Path;

/// ACME account
#[derive(Debug, Clone)]
pub struct Account {
    /// Account ID (URL from ACME server)
    pub id: String,

    /// Account status
    pub status: AccountStatus,

    /// Contact information
    pub contacts: Vec<String>,

    /// Account credentials
    pub credentials: AccountCredentials,

    /// Whether terms of service were accepted
    pub tos_agreed: bool,

    /// Account URL
    pub url: String,
}

impl Account {
    /// Create a new account
    pub fn new(id: String, url: String, credentials: AccountCredentials) -> Self {
        Self {
            id,
            status: AccountStatus::Valid,
            contacts: Vec::new(),
            credentials,
            tos_agreed: false,
            url,
        }
    }

    /// Check if account is valid
    pub fn is_valid(&self) -> bool {
        matches!(self.status, AccountStatus::Valid)
    }

    /// Get the account key thumbprint
    pub fn key_thumbprint(&self) -> &str {
        &self.credentials.key_thumbprint
    }

    /// Save account to file
    pub fn save<P: AsRef<Path>>(&self, path: P) -> AcmeResult<()> {
        let data = AccountData {
            id: self.id.clone(),
            status: self.status.clone(),
            contacts: self.contacts.clone(),
            tos_agreed: self.tos_agreed,
            url: self.url.clone(),
            private_key_pem: self.credentials.private_key_pem.clone(),
            key_thumbprint: self.credentials.key_thumbprint.clone(),
        };

        let json = serde_json::to_string_pretty(&data)?;
        std::fs::write(path, json)?;
        Ok(())
    }

    /// Load account from file
    pub fn load<P: AsRef<Path>>(path: P) -> AcmeResult<Self> {
        let json = std::fs::read_to_string(path)?;
        let data: AccountData = serde_json::from_str(&json)?;

        Ok(Self {
            id: data.id,
            status: data.status,
            contacts: data.contacts,
            credentials: AccountCredentials {
                private_key_pem: data.private_key_pem,
                key_thumbprint: data.key_thumbprint,
            },
            tos_agreed: data.tos_agreed,
            url: data.url,
        })
    }
}

/// Account data for serialization
#[derive(Debug, Serialize, Deserialize)]
struct AccountData {
    id: String,
    status: AccountStatus,
    contacts: Vec<String>,
    tos_agreed: bool,
    url: String,
    private_key_pem: String,
    key_thumbprint: String,
}

/// Account status
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum AccountStatus {
    /// Account is valid
    Valid,
    /// Account is deactivated
    Deactivated,
    /// Account is revoked
    Revoked,
}

/// Account credentials (key pair)
#[derive(Debug, Clone)]
pub struct AccountCredentials {
    /// Private key in PEM format
    pub private_key_pem: String,

    /// JWK thumbprint of the public key
    pub key_thumbprint: String,
}

impl AccountCredentials {
    /// Create new account credentials with a new key pair
    pub fn generate() -> AcmeResult<Self> {
        // Generate an ECDSA P-256 key pair
        let private_key = Self::generate_ec_key()?;
        let thumbprint = Self::compute_thumbprint(&private_key)?;

        Ok(Self {
            private_key_pem: private_key,
            key_thumbprint: thumbprint,
        })
    }

    /// Generate an EC private key (P-256)
    fn generate_ec_key() -> AcmeResult<String> {
        // In production, use ring or openssl crate
        // This is a placeholder that returns a mock key format
        // The actual implementation would use cryptographic libraries

        // Generate a random 32-byte key material (for demonstration)
        let mut key_bytes = [0u8; 32];
        getrandom(&mut key_bytes).map_err(|e| AcmeError::Crypto(e.to_string()))?;

        // Format as PEM (simplified, not actual EC key format)
        let base64_key = base64_url_encode(&key_bytes);

        Ok(format!(
            "-----BEGIN EC PRIVATE KEY-----\n{}\n-----END EC PRIVATE KEY-----",
            base64_key
        ))
    }

    /// Compute JWK thumbprint
    fn compute_thumbprint(private_key_pem: &str) -> AcmeResult<String> {
        // In production, extract public key and compute SHA-256 of canonical JWK
        // This is simplified for demonstration
        use std::collections::hash_map::DefaultHasher;
        use std::hash::{Hash, Hasher};

        let mut hasher = DefaultHasher::new();
        private_key_pem.hash(&mut hasher);
        let hash = hasher.finish();

        Ok(base64_url_encode(&hash.to_be_bytes()))
    }

    /// Create from existing PEM
    pub fn from_pem(pem: String) -> AcmeResult<Self> {
        let thumbprint = Self::compute_thumbprint(&pem)?;
        Ok(Self {
            private_key_pem: pem,
            key_thumbprint: thumbprint,
        })
    }

    /// Sign data with the private key (JWS)
    pub fn sign(&self, data: &[u8]) -> AcmeResult<Vec<u8>> {
        // In production, use proper ECDSA signing
        // This is a placeholder
        use std::collections::hash_map::DefaultHasher;
        use std::hash::{Hash, Hasher};

        let mut hasher = DefaultHasher::new();
        data.hash(&mut hasher);
        self.private_key_pem.hash(&mut hasher);

        Ok(hasher.finish().to_be_bytes().to_vec())
    }

    /// Get public key in JWK format
    pub fn public_key_jwk(&self) -> AcmeResult<serde_json::Value> {
        // In production, extract actual public key components
        // This is simplified
        Ok(serde_json::json!({
            "kty": "EC",
            "crv": "P-256",
            "x": base64_url_encode(b"placeholder_x_coordinate"),
            "y": base64_url_encode(b"placeholder_y_coordinate"),
        }))
    }
}

/// Get random bytes (using getrandom crate pattern)
fn getrandom(dest: &mut [u8]) -> Result<(), std::io::Error> {
    use std::time::{SystemTime, UNIX_EPOCH};

    // Simple fallback using time-based pseudo-randomness
    // In production, use the getrandom crate
    let seed = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_nanos();

    for (i, byte) in dest.iter_mut().enumerate() {
        *byte = ((seed >> (i % 16)) ^ (seed >> ((i + 7) % 16))) as u8;
    }

    Ok(())
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

/// Base64 URL-safe decoding
#[allow(dead_code)]
fn base64_url_decode(data: &str) -> AcmeResult<Vec<u8>> {
    let mut result = Vec::new();
    let mut bits = 0u32;
    let mut bit_count = 0;

    for c in data.chars() {
        let value = match c {
            'A'..='Z' => c as u32 - 'A' as u32,
            'a'..='z' => c as u32 - 'a' as u32 + 26,
            '0'..='9' => c as u32 - '0' as u32 + 52,
            '-' => 62,
            '_' => 63,
            _ => continue,
        };

        bits = (bits << 6) | value;
        bit_count += 6;

        if bit_count >= 8 {
            bit_count -= 8;
            result.push((bits >> bit_count) as u8);
        }
    }

    Ok(result)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_account_creation() {
        let creds = AccountCredentials {
            private_key_pem: "test-key".to_string(),
            key_thumbprint: "test-thumb".to_string(),
        };

        let account = Account::new(
            "account-id".to_string(),
            "https://acme.example.com/acct/123".to_string(),
            creds,
        );

        assert_eq!(account.id, "account-id");
        assert!(account.is_valid());
        assert_eq!(account.key_thumbprint(), "test-thumb");
    }

    #[test]
    fn test_account_status() {
        let creds = AccountCredentials {
            private_key_pem: "test".to_string(),
            key_thumbprint: "thumb".to_string(),
        };

        let mut account = Account::new("id".to_string(), "url".to_string(), creds);
        assert!(account.is_valid());

        account.status = AccountStatus::Deactivated;
        assert!(!account.is_valid());
    }

    #[test]
    fn test_credentials_generation() {
        let creds = AccountCredentials::generate().unwrap();
        assert!(!creds.private_key_pem.is_empty());
        assert!(!creds.key_thumbprint.is_empty());
        assert!(creds.private_key_pem.contains("BEGIN EC PRIVATE KEY"));
    }

    #[test]
    fn test_credentials_from_pem() {
        let pem = "-----BEGIN EC PRIVATE KEY-----\ntest\n-----END EC PRIVATE KEY-----";
        let creds = AccountCredentials::from_pem(pem.to_string()).unwrap();
        assert_eq!(creds.private_key_pem, pem);
        assert!(!creds.key_thumbprint.is_empty());
    }

    #[test]
    fn test_signing() {
        let creds = AccountCredentials::generate().unwrap();
        let signature = creds.sign(b"test data").unwrap();
        assert!(!signature.is_empty());
    }

    #[test]
    fn test_public_key_jwk() {
        let creds = AccountCredentials::generate().unwrap();
        let jwk = creds.public_key_jwk().unwrap();
        assert_eq!(jwk["kty"], "EC");
        assert_eq!(jwk["crv"], "P-256");
    }

    #[test]
    fn test_base64_url_encode() {
        assert_eq!(base64_url_encode(b""), "");
        assert_eq!(base64_url_encode(b"f"), "Zg");
        assert_eq!(base64_url_encode(b"fo"), "Zm8");
        assert_eq!(base64_url_encode(b"foo"), "Zm9v");
    }

    #[test]
    fn test_base64_url_decode() {
        assert_eq!(base64_url_decode("Zm9v").unwrap(), b"foo");
        assert_eq!(base64_url_decode("Zm8").unwrap(), b"fo");
    }

    #[test]
    fn test_base64_roundtrip() {
        let original = b"Hello, ACME World!";
        let encoded = base64_url_encode(original);
        let decoded = base64_url_decode(&encoded).unwrap();
        assert_eq!(decoded, original);
    }
}
