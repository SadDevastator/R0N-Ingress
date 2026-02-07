//! TLS Terminator configuration types.

use serde::{Deserialize, Serialize};
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::path::PathBuf;

/// Configuration for the TLS terminator module.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(default)]
pub struct TlsTerminatorConfig {
    /// TLS listeners to bind.
    pub listeners: Vec<ListenerConfig>,

    /// Certificate configurations.
    pub certificates: Vec<CertificateConfig>,

    /// Default certificate name (used when SNI doesn't match).
    pub default_certificate: Option<String>,

    /// Enable TLS passthrough mode.
    pub passthrough: PassthroughConfig,

    /// mTLS configuration.
    pub mtls: MtlsConfig,

    /// Connection settings.
    pub connection: ConnectionSettings,
}

/// Configuration for a TLS listener.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ListenerConfig {
    /// Bind address.
    #[serde(default = "default_bind_address")]
    pub address: IpAddr,

    /// Listen port.
    pub port: u16,

    /// Optional name for identification.
    #[serde(default)]
    pub name: Option<String>,

    /// Backend to forward decrypted traffic to.
    pub backend: Option<BackendConfig>,
}

fn default_bind_address() -> IpAddr {
    IpAddr::V4(Ipv4Addr::new(0, 0, 0, 0))
}

impl ListenerConfig {
    /// Create a new listener config.
    #[must_use]
    pub fn new(port: u16) -> Self {
        Self {
            address: default_bind_address(),
            port,
            name: None,
            backend: None,
        }
    }

    /// Set the bind address.
    #[must_use]
    pub fn with_address(mut self, address: IpAddr) -> Self {
        self.address = address;
        self
    }

    /// Set the listener name.
    #[must_use]
    pub fn with_name(mut self, name: &str) -> Self {
        self.name = Some(name.to_string());
        self
    }

    /// Set the backend.
    #[must_use]
    pub fn with_backend(mut self, backend: BackendConfig) -> Self {
        self.backend = Some(backend);
        self
    }

    /// Get the socket address.
    #[must_use]
    pub fn socket_addr(&self) -> SocketAddr {
        SocketAddr::new(self.address, self.port)
    }
}

/// Backend server configuration.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BackendConfig {
    /// Backend address.
    pub address: IpAddr,

    /// Backend port.
    pub port: u16,
}

impl BackendConfig {
    /// Create a new backend config.
    #[must_use]
    pub fn new(address: IpAddr, port: u16) -> Self {
        Self { address, port }
    }

    /// Get the socket address.
    #[must_use]
    pub fn socket_addr(&self) -> SocketAddr {
        SocketAddr::new(self.address, self.port)
    }
}

/// Certificate configuration.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CertificateConfig {
    /// Certificate name for identification.
    pub name: String,

    /// Path to the certificate file (PEM or DER).
    pub cert_path: PathBuf,

    /// Path to the private key file (PEM or DER).
    pub key_path: PathBuf,

    /// Optional path to CA certificate chain.
    #[serde(default)]
    pub chain_path: Option<PathBuf>,

    /// SNI names this certificate should match.
    #[serde(default)]
    pub sni_names: Vec<String>,

    /// Enable hot-reload for this certificate.
    #[serde(default)]
    pub hot_reload: bool,
}

impl CertificateConfig {
    /// Create a new certificate config.
    #[must_use]
    pub fn new(name: &str, cert_path: PathBuf, key_path: PathBuf) -> Self {
        Self {
            name: name.to_string(),
            cert_path,
            key_path,
            chain_path: None,
            sni_names: Vec::new(),
            hot_reload: false,
        }
    }

    /// Add an SNI name.
    #[must_use]
    pub fn with_sni(mut self, sni: &str) -> Self {
        self.sni_names.push(sni.to_string());
        self
    }

    /// Enable hot-reload.
    #[must_use]
    pub fn with_hot_reload(mut self) -> Self {
        self.hot_reload = true;
        self
    }
}

/// TLS passthrough configuration.
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
#[serde(default)]
pub struct PassthroughConfig {
    /// Enable TLS passthrough (no termination).
    pub enabled: bool,

    /// Routes for passthrough mode.
    pub routes: Vec<PassthroughRoute>,
}

/// A passthrough route.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PassthroughRoute {
    /// SNI pattern to match.
    pub sni_pattern: String,

    /// Backend to forward encrypted traffic to.
    pub backend: BackendConfig,
}

impl PassthroughRoute {
    /// Create a new passthrough route.
    #[must_use]
    pub fn new(sni_pattern: &str, backend: BackendConfig) -> Self {
        Self {
            sni_pattern: sni_pattern.to_string(),
            backend,
        }
    }
}

/// mTLS (Mutual TLS) configuration.
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
#[serde(default)]
pub struct MtlsConfig {
    /// Enable mTLS (require client certificates).
    pub enabled: bool,

    /// Path to CA certificates for client validation.
    pub client_ca_path: Option<PathBuf>,

    /// Allow self-signed client certificates.
    pub allow_self_signed: bool,

    /// Verify client certificate hostname.
    pub verify_hostname: bool,
}

impl MtlsConfig {
    /// Create a new mTLS config with client CA.
    #[must_use]
    pub fn new(client_ca_path: PathBuf) -> Self {
        Self {
            enabled: true,
            client_ca_path: Some(client_ca_path),
            allow_self_signed: false,
            verify_hostname: true,
        }
    }
}

/// Connection settings.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct ConnectionSettings {
    /// Read timeout in seconds.
    pub read_timeout_secs: u64,

    /// Write timeout in seconds.
    pub write_timeout_secs: u64,

    /// Handshake timeout in seconds.
    pub handshake_timeout_secs: u64,

    /// Maximum concurrent connections.
    pub max_connections: usize,

    /// TLS session cache size.
    pub session_cache_size: usize,
}

impl Default for ConnectionSettings {
    fn default() -> Self {
        Self {
            read_timeout_secs: 30,
            write_timeout_secs: 30,
            handshake_timeout_secs: 10,
            max_connections: 10000,
            session_cache_size: 1024,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::Ipv4Addr;

    #[test]
    fn test_default_config() {
        let config = TlsTerminatorConfig::default();
        assert!(config.listeners.is_empty());
        assert!(config.certificates.is_empty());
        assert!(!config.passthrough.enabled);
        assert!(!config.mtls.enabled);
    }

    #[test]
    fn test_listener_config() {
        let listener = ListenerConfig::new(443)
            .with_address(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)))
            .with_name("https");

        assert_eq!(listener.port, 443);
        assert_eq!(listener.name, Some("https".to_string()));
        assert_eq!(listener.socket_addr().port(), 443);
    }

    #[test]
    fn test_certificate_config() {
        let cert = CertificateConfig::new(
            "example",
            PathBuf::from("/etc/certs/example.pem"),
            PathBuf::from("/etc/certs/example.key"),
        )
        .with_sni("example.com")
        .with_sni("*.example.com")
        .with_hot_reload();

        assert_eq!(cert.name, "example");
        assert_eq!(cert.sni_names.len(), 2);
        assert!(cert.hot_reload);
    }

    #[test]
    fn test_deserialize_config() {
        let config_str = r#"
            [[listeners]]
            port = 443
            name = "https"

            [[certificates]]
            name = "default"
            cert_path = "/etc/certs/server.pem"
            key_path = "/etc/certs/server.key"
            sni_names = ["example.com"]

            [mtls]
            enabled = true
            client_ca_path = "/etc/certs/client-ca.pem"
        "#;

        let config: TlsTerminatorConfig = toml::from_str(config_str).unwrap();
        assert_eq!(config.listeners.len(), 1);
        assert_eq!(config.certificates.len(), 1);
        assert!(config.mtls.enabled);
    }

    #[test]
    fn test_passthrough_route() {
        let backend = BackendConfig::new(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)), 8443);
        let route = PassthroughRoute::new("*.internal.example.com", backend);

        assert_eq!(route.sni_pattern, "*.internal.example.com");
        assert_eq!(route.backend.port, 8443);
    }
}
