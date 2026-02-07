//! Kubernetes Secrets and ConfigMaps management.
//!
//! Provides integration with Kubernetes Secrets and ConfigMaps for
//! TLS certificates, configuration data, and sensitive credentials.

use std::collections::HashMap;
use std::time::{Duration, Instant};

use super::discovery::WatchEvent;
use super::error::{K8sError, K8sResult};

/// Secret manager for Kubernetes Secrets and ConfigMaps.
#[derive(Debug)]
pub struct SecretManager {
    /// Cached secrets by namespace/name.
    secrets: HashMap<SecretKey, Secret>,
    /// Cached config maps by namespace/name.
    config_maps: HashMap<SecretKey, ConfigMap>,
    /// Namespace filter.
    namespace_filter: Option<String>,
    /// Secret type filter.
    type_filter: Option<SecretType>,
    /// Last sync time.
    last_sync: Option<Instant>,
    /// Cache TTL for refreshing.
    cache_ttl: Duration,
}

impl Default for SecretManager {
    fn default() -> Self {
        Self::new()
    }
}

impl SecretManager {
    /// Create a new secret manager.
    pub fn new() -> Self {
        Self {
            secrets: HashMap::new(),
            config_maps: HashMap::new(),
            namespace_filter: None,
            type_filter: None,
            last_sync: None,
            cache_ttl: Duration::from_secs(300), // 5 minutes
        }
    }

    /// Create a secret manager for a specific namespace.
    pub fn for_namespace(namespace: impl Into<String>) -> Self {
        Self {
            namespace_filter: Some(namespace.into()),
            ..Self::new()
        }
    }

    /// Set a type filter for secrets.
    pub fn with_type_filter(mut self, secret_type: SecretType) -> Self {
        self.type_filter = Some(secret_type);
        self
    }

    /// Set the cache TTL.
    pub fn with_cache_ttl(mut self, ttl: Duration) -> Self {
        self.cache_ttl = ttl;
        self
    }

    /// Get a secret by namespace and name.
    pub fn get_secret(&self, namespace: &str, name: &str) -> Option<&Secret> {
        let key = SecretKey::new(namespace, name);
        self.secrets.get(&key)
    }

    /// Get a config map by namespace and name.
    pub fn get_config_map(&self, namespace: &str, name: &str) -> Option<&ConfigMap> {
        let key = SecretKey::new(namespace, name);
        self.config_maps.get(&key)
    }

    /// Get a secret value by key.
    pub fn get_secret_value(&self, namespace: &str, name: &str, key: &str) -> Option<Vec<u8>> {
        self.get_secret(namespace, name)
            .and_then(|s| s.data.get(key).cloned())
    }

    /// Get a secret value as string.
    pub fn get_secret_string(&self, namespace: &str, name: &str, key: &str) -> Option<String> {
        self.get_secret_value(namespace, name, key)
            .and_then(|v| String::from_utf8(v).ok())
    }

    /// Get a config map value.
    pub fn get_config_value(&self, namespace: &str, name: &str, key: &str) -> Option<&str> {
        self.get_config_map(namespace, name)
            .and_then(|cm| cm.data.get(key).map(|s| s.as_str()))
    }

    /// Get TLS certificate and key from a secret.
    pub fn get_tls_certificate(&self, namespace: &str, name: &str) -> K8sResult<TlsCertificate> {
        let secret = self
            .get_secret(namespace, name)
            .ok_or_else(|| K8sError::NotFound {
                kind: "Secret".to_string(),
                name: name.to_string(),
                namespace: Some(namespace.to_string()),
            })?;

        if secret.secret_type != SecretType::Tls {
            return Err(K8sError::SecretDecodeError(format!(
                "Secret {} is not a TLS secret (type: {:?})",
                name, secret.secret_type
            )));
        }

        let cert = secret
            .data
            .get("tls.crt")
            .ok_or_else(|| K8sError::SecretDecodeError("Missing tls.crt".to_string()))?
            .clone();

        let key = secret
            .data
            .get("tls.key")
            .ok_or_else(|| K8sError::SecretDecodeError("Missing tls.key".to_string()))?
            .clone();

        let ca = secret.data.get("ca.crt").cloned();

        Ok(TlsCertificate { cert, key, ca })
    }

    /// Get Docker registry credentials from a secret.
    pub fn get_docker_credentials(&self, namespace: &str, name: &str) -> K8sResult<DockerConfig> {
        let secret = self
            .get_secret(namespace, name)
            .ok_or_else(|| K8sError::NotFound {
                kind: "Secret".to_string(),
                name: name.to_string(),
                namespace: Some(namespace.to_string()),
            })?;

        let config_key = match secret.secret_type {
            SecretType::DockerConfigJson => ".dockerconfigjson",
            SecretType::DockerConfig => ".dockercfg",
            _ => {
                return Err(K8sError::SecretDecodeError(
                    "Secret is not a docker config type".to_string(),
                ))
            },
        };

        let data = secret
            .data
            .get(config_key)
            .ok_or_else(|| K8sError::SecretDecodeError(format!("Missing {}", config_key)))?;

        // Parse docker config JSON
        let config_str = String::from_utf8(data.clone())
            .map_err(|e| K8sError::SecretDecodeError(format!("Invalid UTF-8: {}", e)))?;

        // Simple parsing - in production use serde_json
        Ok(DockerConfig {
            raw: config_str,
            auths: HashMap::new(), // Would be parsed from JSON
        })
    }

    /// Get basic auth credentials from a secret.
    pub fn get_basic_auth(&self, namespace: &str, name: &str) -> K8sResult<BasicAuth> {
        let secret = self
            .get_secret(namespace, name)
            .ok_or_else(|| K8sError::NotFound {
                kind: "Secret".to_string(),
                name: name.to_string(),
                namespace: Some(namespace.to_string()),
            })?;

        let username = secret
            .data
            .get("username")
            .and_then(|v| String::from_utf8(v.clone()).ok())
            .unwrap_or_default();

        let password = secret
            .data
            .get("password")
            .and_then(|v| String::from_utf8(v.clone()).ok())
            .unwrap_or_default();

        Ok(BasicAuth { username, password })
    }

    /// List all secrets.
    pub fn list_secrets(&self) -> impl Iterator<Item = &Secret> {
        self.secrets.values()
    }

    /// List all config maps.
    pub fn list_config_maps(&self) -> impl Iterator<Item = &ConfigMap> {
        self.config_maps.values()
    }

    /// Get the number of cached secrets.
    pub fn secret_count(&self) -> usize {
        self.secrets.len()
    }

    /// Get the number of cached config maps.
    pub fn config_map_count(&self) -> usize {
        self.config_maps.len()
    }

    /// Check if cache needs refresh.
    pub fn needs_refresh(&self) -> bool {
        match self.last_sync {
            Some(last) => last.elapsed() > self.cache_ttl,
            None => true,
        }
    }

    /// Handle a secret watch event.
    pub fn handle_secret_event(&mut self, event: WatchEvent<Secret>) -> K8sResult<()> {
        match event {
            WatchEvent::Added(secret) | WatchEvent::Modified(secret) => {
                // Check type filter
                if let Some(ref filter) = self.type_filter {
                    if &secret.secret_type != filter {
                        return Ok(());
                    }
                }

                // Check namespace filter
                if let Some(ref ns) = self.namespace_filter {
                    if &secret.namespace != ns {
                        return Ok(());
                    }
                }

                let key = SecretKey::new(&secret.namespace, &secret.name);
                self.secrets.insert(key, secret);
            },
            WatchEvent::Deleted(secret) => {
                let key = SecretKey::new(&secret.namespace, &secret.name);
                self.secrets.remove(&key);
            },
            WatchEvent::Bookmark {
                resource_version: _,
            } => {},
            WatchEvent::Error(err) => {
                return Err(K8sError::WatchError(err));
            },
        }
        self.last_sync = Some(Instant::now());
        Ok(())
    }

    /// Handle a config map watch event.
    pub fn handle_config_map_event(&mut self, event: WatchEvent<ConfigMap>) -> K8sResult<()> {
        match event {
            WatchEvent::Added(cm) | WatchEvent::Modified(cm) => {
                // Check namespace filter
                if let Some(ref ns) = self.namespace_filter {
                    if &cm.namespace != ns {
                        return Ok(());
                    }
                }

                let key = SecretKey::new(&cm.namespace, &cm.name);
                self.config_maps.insert(key, cm);
            },
            WatchEvent::Deleted(cm) => {
                let key = SecretKey::new(&cm.namespace, &cm.name);
                self.config_maps.remove(&key);
            },
            WatchEvent::Bookmark {
                resource_version: _,
            } => {},
            WatchEvent::Error(err) => {
                return Err(K8sError::WatchError(err));
            },
        }
        self.last_sync = Some(Instant::now());
        Ok(())
    }

    /// Resolve a secret reference.
    pub fn resolve_ref(&self, secret_ref: &SecretRef) -> K8sResult<Vec<u8>> {
        self.get_secret_value(&secret_ref.namespace, &secret_ref.name, &secret_ref.key)
            .ok_or_else(|| K8sError::NotFound {
                kind: "Secret".to_string(),
                name: format!("{}/{}", secret_ref.name, secret_ref.key),
                namespace: Some(secret_ref.namespace.clone()),
            })
    }
}

/// Key for secret/config map lookup.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct SecretKey {
    /// Namespace.
    pub namespace: String,
    /// Resource name.
    pub name: String,
}

impl SecretKey {
    /// Create a new secret key.
    pub fn new(namespace: impl Into<String>, name: impl Into<String>) -> Self {
        Self {
            namespace: namespace.into(),
            name: name.into(),
        }
    }
}

/// Reference to a secret key.
#[derive(Debug, Clone)]
pub struct SecretRef {
    /// Secret name.
    pub name: String,
    /// Namespace.
    pub namespace: String,
    /// Key within the secret.
    pub key: String,
}

impl SecretRef {
    /// Create a new secret reference.
    pub fn new(
        namespace: impl Into<String>,
        name: impl Into<String>,
        key: impl Into<String>,
    ) -> Self {
        Self {
            namespace: namespace.into(),
            name: name.into(),
            key: key.into(),
        }
    }
}

/// Kubernetes Secret representation.
#[derive(Debug, Clone)]
pub struct Secret {
    /// Secret name.
    pub name: String,
    /// Namespace.
    pub namespace: String,
    /// Resource UID.
    pub uid: String,
    /// Resource version.
    pub resource_version: String,
    /// Labels.
    pub labels: HashMap<String, String>,
    /// Annotations.
    pub annotations: HashMap<String, String>,
    /// Secret type.
    pub secret_type: SecretType,
    /// Secret data (base64 decoded).
    pub data: HashMap<String, Vec<u8>>,
    /// String data (not base64 encoded).
    pub string_data: HashMap<String, String>,
    /// Immutable flag.
    pub immutable: bool,
}

impl Secret {
    /// Create a new secret.
    pub fn new(name: impl Into<String>, namespace: impl Into<String>) -> Self {
        Self {
            name: name.into(),
            namespace: namespace.into(),
            uid: String::new(),
            resource_version: String::new(),
            labels: HashMap::new(),
            annotations: HashMap::new(),
            secret_type: SecretType::Opaque,
            data: HashMap::new(),
            string_data: HashMap::new(),
            immutable: false,
        }
    }

    /// Set the secret type.
    pub fn with_type(mut self, secret_type: SecretType) -> Self {
        self.secret_type = secret_type;
        self
    }

    /// Add data entry.
    pub fn with_data(mut self, key: impl Into<String>, value: Vec<u8>) -> Self {
        self.data.insert(key.into(), value);
        self
    }

    /// Add string data entry.
    pub fn with_string_data(mut self, key: impl Into<String>, value: impl Into<String>) -> Self {
        self.string_data.insert(key.into(), value.into());
        self
    }

    /// Mark as immutable.
    pub fn immutable(mut self) -> Self {
        self.immutable = true;
        self
    }

    /// Check if this is a TLS secret.
    pub fn is_tls(&self) -> bool {
        self.secret_type == SecretType::Tls
    }

    /// Get all keys.
    pub fn keys(&self) -> impl Iterator<Item = &String> {
        self.data.keys().chain(self.string_data.keys())
    }
}

/// Secret type.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub enum SecretType {
    /// Opaque (arbitrary data).
    #[default]
    Opaque,
    /// Service account token.
    ServiceAccountToken,
    /// Docker config.
    DockerConfig,
    /// Docker config JSON.
    DockerConfigJson,
    /// Basic auth.
    BasicAuth,
    /// SSH auth.
    SshAuth,
    /// TLS.
    Tls,
    /// Bootstrap token.
    BootstrapToken,
    /// Custom type.
    Custom(String),
}

impl SecretType {
    /// Parse from Kubernetes type string.
    pub fn from_k8s_type(s: &str) -> Self {
        match s {
            "Opaque" => Self::Opaque,
            "kubernetes.io/service-account-token" => Self::ServiceAccountToken,
            "kubernetes.io/dockercfg" => Self::DockerConfig,
            "kubernetes.io/dockerconfigjson" => Self::DockerConfigJson,
            "kubernetes.io/basic-auth" => Self::BasicAuth,
            "kubernetes.io/ssh-auth" => Self::SshAuth,
            "kubernetes.io/tls" => Self::Tls,
            "bootstrap.kubernetes.io/token" => Self::BootstrapToken,
            other => Self::Custom(other.to_string()),
        }
    }

    /// Convert to Kubernetes type string.
    pub fn to_k8s_type(&self) -> &str {
        match self {
            Self::Opaque => "Opaque",
            Self::ServiceAccountToken => "kubernetes.io/service-account-token",
            Self::DockerConfig => "kubernetes.io/dockercfg",
            Self::DockerConfigJson => "kubernetes.io/dockerconfigjson",
            Self::BasicAuth => "kubernetes.io/basic-auth",
            Self::SshAuth => "kubernetes.io/ssh-auth",
            Self::Tls => "kubernetes.io/tls",
            Self::BootstrapToken => "bootstrap.kubernetes.io/token",
            Self::Custom(s) => s,
        }
    }
}

/// Kubernetes ConfigMap representation.
#[derive(Debug, Clone)]
pub struct ConfigMap {
    /// ConfigMap name.
    pub name: String,
    /// Namespace.
    pub namespace: String,
    /// Resource UID.
    pub uid: String,
    /// Resource version.
    pub resource_version: String,
    /// Labels.
    pub labels: HashMap<String, String>,
    /// Annotations.
    pub annotations: HashMap<String, String>,
    /// String data.
    pub data: HashMap<String, String>,
    /// Binary data.
    pub binary_data: HashMap<String, Vec<u8>>,
    /// Immutable flag.
    pub immutable: bool,
}

impl ConfigMap {
    /// Create a new config map.
    pub fn new(name: impl Into<String>, namespace: impl Into<String>) -> Self {
        Self {
            name: name.into(),
            namespace: namespace.into(),
            uid: String::new(),
            resource_version: String::new(),
            labels: HashMap::new(),
            annotations: HashMap::new(),
            data: HashMap::new(),
            binary_data: HashMap::new(),
            immutable: false,
        }
    }

    /// Add a data entry.
    pub fn with_data(mut self, key: impl Into<String>, value: impl Into<String>) -> Self {
        self.data.insert(key.into(), value.into());
        self
    }

    /// Add a binary data entry.
    pub fn with_binary_data(mut self, key: impl Into<String>, value: Vec<u8>) -> Self {
        self.binary_data.insert(key.into(), value);
        self
    }

    /// Mark as immutable.
    pub fn immutable(mut self) -> Self {
        self.immutable = true;
        self
    }

    /// Get a value.
    pub fn get(&self, key: &str) -> Option<&str> {
        self.data.get(key).map(|s| s.as_str())
    }

    /// Get all keys.
    pub fn keys(&self) -> impl Iterator<Item = &String> {
        self.data.keys().chain(self.binary_data.keys())
    }
}

/// TLS certificate data.
#[derive(Debug, Clone)]
pub struct TlsCertificate {
    /// Certificate PEM data.
    pub cert: Vec<u8>,
    /// Private key PEM data.
    pub key: Vec<u8>,
    /// CA certificate PEM data (optional).
    pub ca: Option<Vec<u8>>,
}

impl TlsCertificate {
    /// Get certificate as string.
    pub fn cert_pem(&self) -> Option<String> {
        String::from_utf8(self.cert.clone()).ok()
    }

    /// Get key as string.
    pub fn key_pem(&self) -> Option<String> {
        String::from_utf8(self.key.clone()).ok()
    }

    /// Get CA as string.
    pub fn ca_pem(&self) -> Option<String> {
        self.ca
            .as_ref()
            .and_then(|ca| String::from_utf8(ca.clone()).ok())
    }
}

/// Docker registry configuration.
#[derive(Debug, Clone)]
pub struct DockerConfig {
    /// Raw JSON configuration.
    pub raw: String,
    /// Parsed auth entries by registry.
    pub auths: HashMap<String, DockerAuth>,
}

/// Docker registry authentication.
#[derive(Debug, Clone)]
pub struct DockerAuth {
    /// Username.
    pub username: String,
    /// Password.
    pub password: String,
    /// Email.
    pub email: Option<String>,
    /// Auth token (base64 encoded username:password).
    pub auth: Option<String>,
}

/// Basic authentication credentials.
#[derive(Debug, Clone)]
pub struct BasicAuth {
    /// Username.
    pub username: String,
    /// Password.
    pub password: String,
}

impl BasicAuth {
    /// Encode as base64 for Authorization header.
    pub fn encode(&self) -> String {
        use std::io::Write;
        let mut buf = Vec::new();
        write!(&mut buf, "{}:{}", self.username, self.password).unwrap();
        base64_encode(&buf)
    }
}

/// Simple base64 encoding (for testing).
fn base64_encode(data: &[u8]) -> String {
    const ALPHABET: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

    let mut result = String::new();
    let mut i = 0;

    while i < data.len() {
        let b0 = data[i] as usize;
        let b1 = if i + 1 < data.len() {
            data[i + 1] as usize
        } else {
            0
        };
        let b2 = if i + 2 < data.len() {
            data[i + 2] as usize
        } else {
            0
        };

        result.push(ALPHABET[b0 >> 2] as char);
        result.push(ALPHABET[((b0 & 0x03) << 4) | (b1 >> 4)] as char);

        if i + 1 < data.len() {
            result.push(ALPHABET[((b1 & 0x0f) << 2) | (b2 >> 6)] as char);
        } else {
            result.push('=');
        }

        if i + 2 < data.len() {
            result.push(ALPHABET[b2 & 0x3f] as char);
        } else {
            result.push('=');
        }

        i += 3;
    }

    result
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_secret_manager_new() {
        let manager = SecretManager::new();
        assert_eq!(manager.secret_count(), 0);
        assert_eq!(manager.config_map_count(), 0);
    }

    #[test]
    fn test_secret_creation() {
        let secret = Secret::new("my-secret", "default")
            .with_type(SecretType::Tls)
            .with_data("tls.crt", b"cert-data".to_vec())
            .with_data("tls.key", b"key-data".to_vec())
            .immutable();

        assert_eq!(secret.name, "my-secret");
        assert!(secret.is_tls());
        assert!(secret.immutable);
        assert!(secret.data.contains_key("tls.crt"));
    }

    #[test]
    fn test_config_map_creation() {
        let cm = ConfigMap::new("my-config", "default")
            .with_data("config.yaml", "key: value")
            .with_binary_data("binary.dat", vec![0, 1, 2, 3]);

        assert_eq!(cm.name, "my-config");
        assert_eq!(cm.get("config.yaml"), Some("key: value"));
        assert!(cm.binary_data.contains_key("binary.dat"));
    }

    #[test]
    fn test_secret_event_handling() {
        let mut manager = SecretManager::new();

        let secret = Secret::new("test-secret", "default").with_data("key", b"value".to_vec());

        manager
            .handle_secret_event(WatchEvent::Added(secret.clone()))
            .unwrap();
        assert_eq!(manager.secret_count(), 1);

        let value = manager.get_secret_value("default", "test-secret", "key");
        assert_eq!(value, Some(b"value".to_vec()));

        manager
            .handle_secret_event(WatchEvent::Deleted(secret))
            .unwrap();
        assert_eq!(manager.secret_count(), 0);
    }

    #[test]
    fn test_config_map_event_handling() {
        let mut manager = SecretManager::new();

        let cm = ConfigMap::new("app-config", "default").with_data("setting", "enabled");

        manager
            .handle_config_map_event(WatchEvent::Added(cm.clone()))
            .unwrap();
        assert_eq!(manager.config_map_count(), 1);

        let value = manager.get_config_value("default", "app-config", "setting");
        assert_eq!(value, Some("enabled"));

        manager
            .handle_config_map_event(WatchEvent::Deleted(cm))
            .unwrap();
        assert_eq!(manager.config_map_count(), 0);
    }

    #[test]
    fn test_tls_certificate_extraction() {
        let mut manager = SecretManager::new();

        let secret = Secret::new("tls-secret", "default")
            .with_type(SecretType::Tls)
            .with_data("tls.crt", b"-----BEGIN CERTIFICATE-----\nMIIC...".to_vec())
            .with_data("tls.key", b"-----BEGIN PRIVATE KEY-----\nMIIE...".to_vec())
            .with_data("ca.crt", b"-----BEGIN CERTIFICATE-----\nMIID...".to_vec());

        manager
            .handle_secret_event(WatchEvent::Added(secret))
            .unwrap();

        let cert = manager
            .get_tls_certificate("default", "tls-secret")
            .unwrap();
        assert!(!cert.cert.is_empty());
        assert!(!cert.key.is_empty());
        assert!(cert.ca.is_some());
    }

    #[test]
    fn test_tls_certificate_not_found() {
        let manager = SecretManager::new();
        let result = manager.get_tls_certificate("default", "nonexistent");
        assert!(result.is_err());
    }

    #[test]
    fn test_tls_certificate_wrong_type() {
        let mut manager = SecretManager::new();

        let secret = Secret::new("opaque-secret", "default")
            .with_type(SecretType::Opaque)
            .with_data("data", b"some data".to_vec());

        manager
            .handle_secret_event(WatchEvent::Added(secret))
            .unwrap();

        let result = manager.get_tls_certificate("default", "opaque-secret");
        assert!(result.is_err());
    }

    #[test]
    fn test_basic_auth() {
        let mut manager = SecretManager::new();

        let secret = Secret::new("basic-auth", "default")
            .with_type(SecretType::BasicAuth)
            .with_data("username", b"admin".to_vec())
            .with_data("password", b"secret123".to_vec());

        manager
            .handle_secret_event(WatchEvent::Added(secret))
            .unwrap();

        let auth = manager.get_basic_auth("default", "basic-auth").unwrap();
        assert_eq!(auth.username, "admin");
        assert_eq!(auth.password, "secret123");
    }

    #[test]
    fn test_basic_auth_encode() {
        let auth = BasicAuth {
            username: "user".to_string(),
            password: "pass".to_string(),
        };

        let encoded = auth.encode();
        assert_eq!(encoded, "dXNlcjpwYXNz");
    }

    #[test]
    fn test_secret_type_parsing() {
        assert_eq!(SecretType::from_k8s_type("Opaque"), SecretType::Opaque);
        assert_eq!(
            SecretType::from_k8s_type("kubernetes.io/tls"),
            SecretType::Tls
        );
        assert_eq!(
            SecretType::from_k8s_type("custom/type"),
            SecretType::Custom("custom/type".to_string())
        );
    }

    #[test]
    fn test_secret_ref() {
        let mut manager = SecretManager::new();

        let secret =
            Secret::new("my-secret", "prod").with_data("api-key", b"secret-key-123".to_vec());

        manager
            .handle_secret_event(WatchEvent::Added(secret))
            .unwrap();

        let secret_ref = SecretRef::new("prod", "my-secret", "api-key");
        let value = manager.resolve_ref(&secret_ref).unwrap();
        assert_eq!(value, b"secret-key-123");
    }

    #[test]
    fn test_namespace_filter() {
        let mut manager = SecretManager::for_namespace("production");

        let prod_secret = Secret::new("secret", "production");
        let dev_secret = Secret::new("secret", "development");

        manager
            .handle_secret_event(WatchEvent::Added(prod_secret))
            .unwrap();
        manager
            .handle_secret_event(WatchEvent::Added(dev_secret))
            .unwrap();

        assert_eq!(manager.secret_count(), 1);
        assert!(manager.get_secret("production", "secret").is_some());
        assert!(manager.get_secret("development", "secret").is_none());
    }

    #[test]
    fn test_type_filter() {
        let mut manager = SecretManager::new().with_type_filter(SecretType::Tls);

        let tls_secret = Secret::new("tls", "default").with_type(SecretType::Tls);
        let opaque_secret = Secret::new("opaque", "default").with_type(SecretType::Opaque);

        manager
            .handle_secret_event(WatchEvent::Added(tls_secret))
            .unwrap();
        manager
            .handle_secret_event(WatchEvent::Added(opaque_secret))
            .unwrap();

        assert_eq!(manager.secret_count(), 1);
        assert!(manager.get_secret("default", "tls").is_some());
    }

    #[test]
    fn test_cache_refresh() {
        let manager = SecretManager::new();
        assert!(manager.needs_refresh());
    }

    #[test]
    fn test_secret_string() {
        let mut manager = SecretManager::new();

        let secret = Secret::new("config", "default")
            .with_data("endpoint", b"https://api.example.com".to_vec());

        manager
            .handle_secret_event(WatchEvent::Added(secret))
            .unwrap();

        let value = manager.get_secret_string("default", "config", "endpoint");
        assert_eq!(value, Some("https://api.example.com".to_string()));
    }
}
