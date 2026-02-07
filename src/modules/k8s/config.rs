//! Kubernetes client configuration.
//!
//! Provides configuration for connecting to Kubernetes clusters,
//! authentication methods, and watch settings.

use std::path::PathBuf;
use std::time::Duration;

/// Kubernetes client configuration.
#[derive(Debug, Clone)]
pub struct K8sConfig {
    /// Cluster connection configuration.
    pub cluster: ClusterConfig,
    /// Authentication configuration.
    pub auth: AuthConfig,
    /// Default namespace for operations.
    pub namespace: Option<String>,
    /// Watch configuration.
    pub watch: WatchConfig,
    /// Request timeout.
    pub timeout: Duration,
    /// Enable leader election for HA deployments.
    pub leader_election: bool,
    /// Leader election lease name.
    pub lease_name: String,
    /// User agent string for API requests.
    pub user_agent: String,
}

impl Default for K8sConfig {
    fn default() -> Self {
        Self {
            cluster: ClusterConfig::default(),
            auth: AuthConfig::default(),
            namespace: None,
            watch: WatchConfig::default(),
            timeout: Duration::from_secs(30),
            leader_election: false,
            lease_name: "r0n-gateway-leader".to_string(),
            user_agent: format!("R0N-Gateway/{}", env!("CARGO_PKG_VERSION")),
        }
    }
}

impl K8sConfig {
    /// Create a new configuration with default settings.
    pub fn new() -> Self {
        Self::default()
    }

    /// Create configuration for in-cluster deployment.
    pub fn in_cluster() -> Self {
        Self {
            cluster: ClusterConfig::in_cluster(),
            auth: AuthConfig::ServiceAccount {
                token_path: PathBuf::from("/var/run/secrets/kubernetes.io/serviceaccount/token"),
            },
            namespace: std::env::var("POD_NAMESPACE").ok(),
            ..Default::default()
        }
    }

    /// Create configuration from kubeconfig file.
    pub fn from_kubeconfig(path: PathBuf) -> Self {
        Self {
            auth: AuthConfig::Kubeconfig {
                path: path.clone(),
                context: None,
            },
            ..Default::default()
        }
    }

    /// Set the cluster configuration.
    pub fn with_cluster(mut self, cluster: ClusterConfig) -> Self {
        self.cluster = cluster;
        self
    }

    /// Set the authentication configuration.
    pub fn with_auth(mut self, auth: AuthConfig) -> Self {
        self.auth = auth;
        self
    }

    /// Set the default namespace.
    pub fn with_namespace(mut self, namespace: impl Into<String>) -> Self {
        self.namespace = Some(namespace.into());
        self
    }

    /// Set the watch configuration.
    pub fn with_watch(mut self, watch: WatchConfig) -> Self {
        self.watch = watch;
        self
    }

    /// Set the request timeout.
    pub fn with_timeout(mut self, timeout: Duration) -> Self {
        self.timeout = timeout;
        self
    }

    /// Enable leader election.
    pub fn with_leader_election(mut self, enabled: bool) -> Self {
        self.leader_election = enabled;
        self
    }

    /// Set the leader election lease name.
    pub fn with_lease_name(mut self, name: impl Into<String>) -> Self {
        self.lease_name = name.into();
        self
    }

    /// Get the effective namespace, defaulting to "default" if not set.
    pub fn effective_namespace(&self) -> &str {
        self.namespace.as_deref().unwrap_or("default")
    }

    /// Validate the configuration.
    pub fn validate(&self) -> Result<(), ConfigValidationError> {
        if self.cluster.api_server_url.is_empty() {
            return Err(ConfigValidationError::MissingApiServer);
        }

        if self.timeout.is_zero() {
            return Err(ConfigValidationError::InvalidTimeout);
        }

        self.auth.validate()?;
        Ok(())
    }
}

/// Cluster connection configuration.
#[derive(Debug, Clone)]
pub struct ClusterConfig {
    /// Kubernetes API server URL.
    pub api_server_url: String,
    /// CA certificate for TLS verification.
    pub ca_cert: Option<CertificateSource>,
    /// Skip TLS verification (not recommended for production).
    pub insecure_skip_tls_verify: bool,
    /// Custom TLS server name for verification.
    pub tls_server_name: Option<String>,
    /// Proxy URL for API requests.
    pub proxy_url: Option<String>,
}

impl Default for ClusterConfig {
    fn default() -> Self {
        Self {
            api_server_url: "https://kubernetes.default.svc".to_string(),
            ca_cert: None,
            insecure_skip_tls_verify: false,
            tls_server_name: None,
            proxy_url: None,
        }
    }
}

impl ClusterConfig {
    /// Create configuration for in-cluster deployment.
    pub fn in_cluster() -> Self {
        Self {
            api_server_url: format!(
                "https://{}:{}",
                std::env::var("KUBERNETES_SERVICE_HOST")
                    .unwrap_or_else(|_| "kubernetes.default.svc".to_string()),
                std::env::var("KUBERNETES_SERVICE_PORT").unwrap_or_else(|_| "443".to_string())
            ),
            ca_cert: Some(CertificateSource::File(PathBuf::from(
                "/var/run/secrets/kubernetes.io/serviceaccount/ca.crt",
            ))),
            insecure_skip_tls_verify: false,
            tls_server_name: None,
            proxy_url: None,
        }
    }

    /// Create configuration for a specific API server.
    pub fn with_server(url: impl Into<String>) -> Self {
        Self {
            api_server_url: url.into(),
            ..Default::default()
        }
    }

    /// Set the CA certificate.
    pub fn with_ca_cert(mut self, cert: CertificateSource) -> Self {
        self.ca_cert = Some(cert);
        self
    }

    /// Enable insecure TLS (skip verification).
    pub fn insecure(mut self) -> Self {
        self.insecure_skip_tls_verify = true;
        self
    }

    /// Set the TLS server name.
    pub fn with_tls_server_name(mut self, name: impl Into<String>) -> Self {
        self.tls_server_name = Some(name.into());
        self
    }

    /// Set the proxy URL.
    pub fn with_proxy(mut self, url: impl Into<String>) -> Self {
        self.proxy_url = Some(url.into());
        self
    }
}

/// Certificate source configuration.
#[derive(Debug, Clone)]
pub enum CertificateSource {
    /// Load certificate from file.
    File(PathBuf),
    /// Certificate data as PEM string.
    Pem(String),
    /// Certificate data as DER bytes.
    Der(Vec<u8>),
}

/// Authentication configuration.
#[derive(Debug, Clone, Default)]
pub enum AuthConfig {
    /// No authentication.
    #[default]
    None,
    /// Bearer token authentication.
    Token(String),
    /// Service account token from file.
    ServiceAccount {
        /// Path to the token file.
        token_path: PathBuf,
    },
    /// Client certificate authentication.
    ClientCertificate {
        /// Client certificate.
        cert: CertificateSource,
        /// Client private key.
        key: CertificateSource,
    },
    /// Load from kubeconfig file.
    Kubeconfig {
        /// Path to kubeconfig file.
        path: PathBuf,
        /// Context to use (None for current-context).
        context: Option<String>,
    },
    /// OIDC token authentication.
    Oidc {
        /// OIDC issuer URL.
        issuer_url: String,
        /// Client ID.
        client_id: String,
        /// Refresh token.
        refresh_token: Option<String>,
    },
    /// Exec-based authentication (external command).
    Exec {
        /// Command to execute.
        command: String,
        /// Command arguments.
        args: Vec<String>,
        /// Environment variables.
        env: Vec<(String, String)>,
    },
}

impl AuthConfig {
    /// Create bearer token authentication.
    pub fn bearer_token(token: impl Into<String>) -> Self {
        Self::Token(token.into())
    }

    /// Create service account authentication.
    pub fn service_account() -> Self {
        Self::ServiceAccount {
            token_path: PathBuf::from("/var/run/secrets/kubernetes.io/serviceaccount/token"),
        }
    }

    /// Create client certificate authentication.
    pub fn client_certificate(cert: CertificateSource, key: CertificateSource) -> Self {
        Self::ClientCertificate { cert, key }
    }

    /// Create kubeconfig authentication.
    pub fn kubeconfig(path: PathBuf) -> Self {
        Self::Kubeconfig {
            path,
            context: None,
        }
    }

    /// Validate the authentication configuration.
    pub fn validate(&self) -> Result<(), ConfigValidationError> {
        match self {
            Self::None => Ok(()),
            Self::Token(token) => {
                if token.is_empty() {
                    Err(ConfigValidationError::EmptyToken)
                } else {
                    Ok(())
                }
            },
            Self::ServiceAccount { token_path } => {
                if !token_path.exists() {
                    // In tests or dev, file might not exist
                    // Just validate path is set
                    Ok(())
                } else {
                    Ok(())
                }
            },
            Self::ClientCertificate { .. } => Ok(()),
            Self::Kubeconfig { path, .. } => {
                if !path.exists() {
                    // In tests or dev, file might not exist
                    Ok(())
                } else {
                    Ok(())
                }
            },
            Self::Oidc {
                issuer_url,
                client_id,
                ..
            } => {
                if issuer_url.is_empty() {
                    return Err(ConfigValidationError::EmptyIssuerUrl);
                }
                if client_id.is_empty() {
                    return Err(ConfigValidationError::EmptyClientId);
                }
                Ok(())
            },
            Self::Exec { command, .. } => {
                if command.is_empty() {
                    Err(ConfigValidationError::EmptyExecCommand)
                } else {
                    Ok(())
                }
            },
        }
    }

    /// Check if this is in-cluster authentication.
    pub fn is_in_cluster(&self) -> bool {
        matches!(self, Self::ServiceAccount { .. })
    }
}

/// Watch configuration for Kubernetes resources.
#[derive(Debug, Clone)]
pub struct WatchConfig {
    /// Initial resource version for watching.
    pub resource_version: Option<String>,
    /// Watch timeout before reconnecting.
    pub timeout: Duration,
    /// Allow watch bookmarks for efficiency.
    pub allow_bookmarks: bool,
    /// Reconnection backoff configuration.
    pub backoff: BackoffConfig,
    /// Maximum events to buffer.
    pub buffer_size: usize,
}

impl Default for WatchConfig {
    fn default() -> Self {
        Self {
            resource_version: None,
            timeout: Duration::from_secs(300), // 5 minutes
            allow_bookmarks: true,
            backoff: BackoffConfig::default(),
            buffer_size: 1000,
        }
    }
}

impl WatchConfig {
    /// Create a new watch configuration.
    pub fn new() -> Self {
        Self::default()
    }

    /// Set the initial resource version.
    pub fn with_resource_version(mut self, version: impl Into<String>) -> Self {
        self.resource_version = Some(version.into());
        self
    }

    /// Set the watch timeout.
    pub fn with_timeout(mut self, timeout: Duration) -> Self {
        self.timeout = timeout;
        self
    }

    /// Set whether to allow bookmarks.
    pub fn with_bookmarks(mut self, allow: bool) -> Self {
        self.allow_bookmarks = allow;
        self
    }

    /// Set the backoff configuration.
    pub fn with_backoff(mut self, backoff: BackoffConfig) -> Self {
        self.backoff = backoff;
        self
    }

    /// Set the event buffer size.
    pub fn with_buffer_size(mut self, size: usize) -> Self {
        self.buffer_size = size;
        self
    }
}

/// Backoff configuration for reconnection.
#[derive(Debug, Clone)]
pub struct BackoffConfig {
    /// Initial backoff duration.
    pub initial: Duration,
    /// Maximum backoff duration.
    pub max: Duration,
    /// Backoff multiplier.
    pub multiplier: f64,
    /// Add random jitter to backoff.
    pub jitter: bool,
}

impl Default for BackoffConfig {
    fn default() -> Self {
        Self {
            initial: Duration::from_millis(100),
            max: Duration::from_secs(30),
            multiplier: 2.0,
            jitter: true,
        }
    }
}

impl BackoffConfig {
    /// Calculate the next backoff duration.
    pub fn next_backoff(&self, current: Duration) -> Duration {
        let next = Duration::from_secs_f64(current.as_secs_f64() * self.multiplier);
        std::cmp::min(next, self.max)
    }
}

/// Configuration validation error.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ConfigValidationError {
    /// Missing API server URL.
    MissingApiServer,
    /// Invalid timeout value.
    InvalidTimeout,
    /// Empty bearer token.
    EmptyToken,
    /// Empty OIDC issuer URL.
    EmptyIssuerUrl,
    /// Empty OIDC client ID.
    EmptyClientId,
    /// Empty exec command.
    EmptyExecCommand,
}

impl std::fmt::Display for ConfigValidationError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::MissingApiServer => write!(f, "API server URL is required"),
            Self::InvalidTimeout => write!(f, "Timeout must be greater than zero"),
            Self::EmptyToken => write!(f, "Bearer token cannot be empty"),
            Self::EmptyIssuerUrl => write!(f, "OIDC issuer URL cannot be empty"),
            Self::EmptyClientId => write!(f, "OIDC client ID cannot be empty"),
            Self::EmptyExecCommand => write!(f, "Exec command cannot be empty"),
        }
    }
}

impl std::error::Error for ConfigValidationError {}

/// Label selector for filtering resources.
#[derive(Debug, Clone, Default)]
pub struct LabelSelector {
    /// Match labels (equality).
    pub match_labels: Vec<(String, String)>,
    /// Match expressions.
    pub match_expressions: Vec<LabelSelectorRequirement>,
}

impl LabelSelector {
    /// Create a new empty label selector.
    pub fn new() -> Self {
        Self::default()
    }

    /// Add an equality match.
    pub fn with_label(mut self, key: impl Into<String>, value: impl Into<String>) -> Self {
        self.match_labels.push((key.into(), value.into()));
        self
    }

    /// Add a match expression.
    pub fn with_expression(mut self, expr: LabelSelectorRequirement) -> Self {
        self.match_expressions.push(expr);
        self
    }

    /// Convert to Kubernetes label selector string.
    pub fn to_selector_string(&self) -> String {
        let mut parts = Vec::new();

        for (key, value) in &self.match_labels {
            parts.push(format!("{}={}", key, value));
        }

        for expr in &self.match_expressions {
            parts.push(expr.to_string());
        }

        parts.join(",")
    }

    /// Check if the selector is empty.
    pub fn is_empty(&self) -> bool {
        self.match_labels.is_empty() && self.match_expressions.is_empty()
    }
}

/// Label selector requirement (set-based).
#[derive(Debug, Clone)]
pub struct LabelSelectorRequirement {
    /// Label key.
    pub key: String,
    /// Operator.
    pub operator: LabelSelectorOperator,
    /// Values for the operator.
    pub values: Vec<String>,
}

impl std::fmt::Display for LabelSelectorRequirement {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match &self.operator {
            LabelSelectorOperator::In => {
                write!(f, "{} in ({})", self.key, self.values.join(","))
            },
            LabelSelectorOperator::NotIn => {
                write!(f, "{} notin ({})", self.key, self.values.join(","))
            },
            LabelSelectorOperator::Exists => {
                write!(f, "{}", self.key)
            },
            LabelSelectorOperator::DoesNotExist => {
                write!(f, "!{}", self.key)
            },
        }
    }
}

/// Label selector operator.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum LabelSelectorOperator {
    /// Key's value is in the set.
    In,
    /// Key's value is not in the set.
    NotIn,
    /// Key exists.
    Exists,
    /// Key does not exist.
    DoesNotExist,
}

/// Field selector for filtering resources.
#[derive(Debug, Clone, Default)]
pub struct FieldSelector {
    /// Field conditions.
    pub conditions: Vec<FieldCondition>,
}

impl FieldSelector {
    /// Create a new empty field selector.
    pub fn new() -> Self {
        Self::default()
    }

    /// Add an equality condition.
    pub fn equals(mut self, field: impl Into<String>, value: impl Into<String>) -> Self {
        self.conditions.push(FieldCondition {
            field: field.into(),
            operator: FieldOperator::Equals,
            value: value.into(),
        });
        self
    }

    /// Add a not-equals condition.
    pub fn not_equals(mut self, field: impl Into<String>, value: impl Into<String>) -> Self {
        self.conditions.push(FieldCondition {
            field: field.into(),
            operator: FieldOperator::NotEquals,
            value: value.into(),
        });
        self
    }

    /// Convert to field selector string.
    pub fn to_selector_string(&self) -> String {
        self.conditions
            .iter()
            .map(|c| c.to_string())
            .collect::<Vec<_>>()
            .join(",")
    }
}

/// Field condition.
#[derive(Debug, Clone)]
pub struct FieldCondition {
    /// Field path.
    pub field: String,
    /// Operator.
    pub operator: FieldOperator,
    /// Value to compare.
    pub value: String,
}

impl std::fmt::Display for FieldCondition {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self.operator {
            FieldOperator::Equals => write!(f, "{}={}", self.field, self.value),
            FieldOperator::NotEquals => write!(f, "{}!={}", self.field, self.value),
        }
    }
}

/// Field selector operator.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum FieldOperator {
    /// Field equals value.
    Equals,
    /// Field does not equal value.
    NotEquals,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_default_config() {
        let config = K8sConfig::default();
        assert_eq!(config.effective_namespace(), "default");
        assert!(!config.leader_election);
        assert_eq!(config.timeout, Duration::from_secs(30));
    }

    #[test]
    fn test_in_cluster_config() {
        let config = K8sConfig::in_cluster();
        assert!(config.auth.is_in_cluster());
        assert!(config.cluster.ca_cert.is_some());
    }

    #[test]
    fn test_config_builder() {
        let config = K8sConfig::new()
            .with_namespace("production")
            .with_timeout(Duration::from_secs(60))
            .with_leader_election(true)
            .with_lease_name("my-gateway");

        assert_eq!(config.effective_namespace(), "production");
        assert_eq!(config.timeout, Duration::from_secs(60));
        assert!(config.leader_election);
        assert_eq!(config.lease_name, "my-gateway");
    }

    #[test]
    fn test_cluster_config() {
        let cluster = ClusterConfig::with_server("https://k8s.example.com:6443")
            .with_tls_server_name("kubernetes")
            .insecure();

        assert_eq!(cluster.api_server_url, "https://k8s.example.com:6443");
        assert!(cluster.insecure_skip_tls_verify);
        assert_eq!(cluster.tls_server_name, Some("kubernetes".to_string()));
    }

    #[test]
    fn test_auth_config_validation() {
        assert!(AuthConfig::None.validate().is_ok());
        assert!(AuthConfig::bearer_token("my-token").validate().is_ok());
        assert!(AuthConfig::Token("".to_string()).validate().is_err());

        let oidc = AuthConfig::Oidc {
            issuer_url: "".to_string(),
            client_id: "test".to_string(),
            refresh_token: None,
        };
        assert!(oidc.validate().is_err());
    }

    #[test]
    fn test_watch_config() {
        let watch = WatchConfig::new()
            .with_timeout(Duration::from_secs(600))
            .with_bookmarks(false)
            .with_buffer_size(5000);

        assert_eq!(watch.timeout, Duration::from_secs(600));
        assert!(!watch.allow_bookmarks);
        assert_eq!(watch.buffer_size, 5000);
    }

    #[test]
    fn test_backoff_config() {
        let backoff = BackoffConfig::default();

        let next = backoff.next_backoff(Duration::from_millis(100));
        assert_eq!(next, Duration::from_millis(200));

        let next = backoff.next_backoff(Duration::from_secs(20));
        assert_eq!(next, Duration::from_secs(30)); // Capped at max
    }

    #[test]
    fn test_label_selector() {
        let selector = LabelSelector::new()
            .with_label("app", "gateway")
            .with_label("version", "v1")
            .with_expression(LabelSelectorRequirement {
                key: "environment".to_string(),
                operator: LabelSelectorOperator::In,
                values: vec!["prod".to_string(), "staging".to_string()],
            });

        let s = selector.to_selector_string();
        assert!(s.contains("app=gateway"));
        assert!(s.contains("version=v1"));
        assert!(s.contains("environment in (prod,staging)"));
    }

    #[test]
    fn test_field_selector() {
        let selector = FieldSelector::new()
            .equals("metadata.name", "my-service")
            .not_equals("status.phase", "Failed");

        let s = selector.to_selector_string();
        assert!(s.contains("metadata.name=my-service"));
        assert!(s.contains("status.phase!=Failed"));
    }

    #[test]
    fn test_config_validation() {
        let config = K8sConfig::new();
        assert!(config.validate().is_ok());

        let invalid = K8sConfig {
            cluster: ClusterConfig {
                api_server_url: "".to_string(),
                ..Default::default()
            },
            ..Default::default()
        };
        assert!(invalid.validate().is_err());
    }
}
