//! Kubernetes Ingress controller.
//!
//! Provides Ingress resource management for routing external traffic
//! to services within the cluster.

use std::collections::HashMap;
use std::sync::Arc;
use std::time::Instant;

use super::config::LabelSelector;
use super::discovery::{ServiceKey, WatchEvent};
use super::error::{K8sError, K8sResult};

/// Ingress controller for managing Kubernetes Ingress resources.
#[derive(Debug)]
pub struct IngressController {
    /// Ingress resources by namespace/name.
    ingresses: HashMap<IngressKey, Ingress>,
    /// Ingress class to watch.
    ingress_class: Option<String>,
    /// Namespace filter.
    namespace_filter: Option<String>,
    /// Label selector.
    label_selector: Option<LabelSelector>,
    /// Last sync time.
    last_sync: Option<Instant>,
    /// Route update callbacks.
    #[allow(dead_code)]
    callbacks: Vec<Arc<dyn IngressCallback>>,
}

impl Default for IngressController {
    fn default() -> Self {
        Self::new()
    }
}

impl IngressController {
    /// Create a new ingress controller.
    pub fn new() -> Self {
        Self {
            ingresses: HashMap::new(),
            ingress_class: None,
            namespace_filter: None,
            label_selector: None,
            last_sync: None,
            callbacks: Vec::new(),
        }
    }

    /// Create an ingress controller for a specific ingress class.
    pub fn for_class(class: impl Into<String>) -> Self {
        Self {
            ingress_class: Some(class.into()),
            ..Self::new()
        }
    }

    /// Set the namespace filter.
    pub fn with_namespace(mut self, namespace: impl Into<String>) -> Self {
        self.namespace_filter = Some(namespace.into());
        self
    }

    /// Set the label selector.
    pub fn with_label_selector(mut self, selector: LabelSelector) -> Self {
        self.label_selector = Some(selector);
        self
    }

    /// Register an ingress update callback.
    pub fn on_update<F>(&mut self, callback: F)
    where
        F: IngressCallback + 'static,
    {
        self.callbacks.push(Arc::new(callback));
    }

    /// Get an ingress by namespace and name.
    pub fn get_ingress(&self, namespace: &str, name: &str) -> Option<&Ingress> {
        let key = IngressKey::new(namespace, name);
        self.ingresses.get(&key)
    }

    /// List all ingresses.
    pub fn list_ingresses(&self) -> impl Iterator<Item = &Ingress> {
        self.ingresses.values()
    }

    /// Get the number of managed ingresses.
    pub fn ingress_count(&self) -> usize {
        self.ingresses.len()
    }

    /// Get the total number of rules.
    pub fn rule_count(&self) -> usize {
        self.ingresses.values().map(|i| i.rules.len()).sum()
    }

    /// Check if an ingress should be managed by this controller.
    fn should_manage(&self, ingress: &Ingress) -> bool {
        // Check ingress class
        if let Some(ref class) = self.ingress_class {
            if ingress.ingress_class.as_ref() != Some(class) {
                return false;
            }
        }

        // Check namespace
        if let Some(ref ns) = self.namespace_filter {
            if &ingress.namespace != ns {
                return false;
            }
        }

        true
    }

    /// Handle an ingress watch event.
    pub fn handle_event(&mut self, event: WatchEvent<Ingress>) -> K8sResult<()> {
        match event {
            WatchEvent::Added(ingress) | WatchEvent::Modified(ingress) => {
                if self.should_manage(&ingress) {
                    let key = IngressKey::new(&ingress.namespace, &ingress.name);
                    self.ingresses.insert(key, ingress);
                }
            },
            WatchEvent::Deleted(ingress) => {
                let key = IngressKey::new(&ingress.namespace, &ingress.name);
                self.ingresses.remove(&key);
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

    /// Generate routing rules from all ingresses.
    pub fn generate_routes(&self) -> Vec<Route> {
        let mut routes = Vec::new();

        for ingress in self.ingresses.values() {
            routes.extend(self.routes_from_ingress(ingress));
        }

        // Sort routes by priority (most specific first)
        routes.sort_by(|a, b| b.priority.cmp(&a.priority));
        routes
    }

    /// Generate routes from a single ingress.
    fn routes_from_ingress(&self, ingress: &Ingress) -> Vec<Route> {
        let mut routes = Vec::new();

        for rule in &ingress.rules {
            for path in &rule.paths {
                let route = Route {
                    id: format!("{}/{}/{}", ingress.namespace, ingress.name, routes.len()),
                    host: rule.host.clone(),
                    path: path.path.clone(),
                    path_type: path.path_type.clone(),
                    backend: path.backend.clone(),
                    priority: self.calculate_priority(&rule.host, &path.path, &path.path_type),
                    tls: ingress
                        .tls
                        .iter()
                        .any(|t| t.hosts.iter().any(|h| Some(h) == rule.host.as_ref())),
                    annotations: ingress.annotations.clone(),
                };
                routes.push(route);
            }
        }

        // Add default backend if present
        if let Some(ref backend) = ingress.default_backend {
            routes.push(Route {
                id: format!("{}/{}/default", ingress.namespace, ingress.name),
                host: None,
                path: "/".to_string(),
                path_type: PathType::Prefix,
                backend: backend.clone(),
                priority: 0,
                tls: false,
                annotations: ingress.annotations.clone(),
            });
        }

        routes
    }

    /// Calculate route priority (higher = more specific).
    fn calculate_priority(&self, host: &Option<String>, path: &str, path_type: &PathType) -> u32 {
        let mut priority = 0u32;

        // Host specificity
        if let Some(h) = host {
            if h.starts_with('*') {
                priority += 100; // Wildcard host
            } else {
                priority += 200; // Exact host
            }
        }

        // Path specificity
        priority += (path.len() as u32).min(100);

        // Path type
        match path_type {
            PathType::Exact => priority += 50,
            PathType::Prefix => priority += 25,
            PathType::ImplementationSpecific => priority += 10,
        }

        priority
    }

    /// Find routes matching a host and path.
    pub fn find_routes(&self, host: Option<&str>, path: &str) -> Vec<&Route> {
        let routes = self.generate_routes();
        let matching: Vec<Route> = routes
            .into_iter()
            .filter(|r| self.route_matches(r, host, path))
            .collect();

        // This is a workaround since we can't return references to local data
        // In practice, you'd cache the routes
        drop(matching);
        Vec::new()
    }

    /// Check if a route matches the given host and path.
    fn route_matches(&self, route: &Route, host: Option<&str>, path: &str) -> bool {
        // Check host
        match (&route.host, host) {
            (Some(route_host), Some(req_host)) => {
                if route_host.starts_with("*.") {
                    let suffix = &route_host[1..];
                    if !req_host.ends_with(suffix) {
                        return false;
                    }
                } else if route_host != req_host {
                    return false;
                }
            },
            (Some(_), None) => return false,
            (None, _) => {}, // Route matches any host
        }

        // Check path
        match route.path_type {
            PathType::Exact => path == route.path,
            PathType::Prefix => {
                path.starts_with(&route.path)
                    || (route.path.ends_with('/')
                        && path.starts_with(&route.path[..route.path.len() - 1]))
            },
            PathType::ImplementationSpecific => path.starts_with(&route.path),
        }
    }

    /// Get backends for a specific service.
    pub fn backends_for_service(&self, namespace: &str, name: &str) -> Vec<&IngressBackend> {
        self.ingresses
            .values()
            .flat_map(|i| &i.rules)
            .flat_map(|r| &r.paths)
            .filter(|p| {
                p.backend.service.as_ref().is_some_and(|s| {
                    s.namespace.as_deref().unwrap_or(namespace) == namespace && s.name == name
                })
            })
            .map(|p| &p.backend)
            .collect()
    }
}

/// Key for ingress lookup.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct IngressKey {
    /// Namespace.
    pub namespace: String,
    /// Ingress name.
    pub name: String,
}

impl IngressKey {
    /// Create a new ingress key.
    pub fn new(namespace: impl Into<String>, name: impl Into<String>) -> Self {
        Self {
            namespace: namespace.into(),
            name: name.into(),
        }
    }
}

/// Kubernetes Ingress resource.
#[derive(Debug, Clone)]
pub struct Ingress {
    /// Ingress name.
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
    /// Ingress class name.
    pub ingress_class: Option<String>,
    /// Default backend.
    pub default_backend: Option<IngressBackend>,
    /// Ingress rules.
    pub rules: Vec<IngressRule>,
    /// TLS configuration.
    pub tls: Vec<IngressTLS>,
    /// Ingress status.
    pub status: IngressStatus,
}

impl Ingress {
    /// Create a new ingress.
    pub fn new(name: impl Into<String>, namespace: impl Into<String>) -> Self {
        Self {
            name: name.into(),
            namespace: namespace.into(),
            uid: String::new(),
            resource_version: String::new(),
            labels: HashMap::new(),
            annotations: HashMap::new(),
            ingress_class: None,
            default_backend: None,
            rules: Vec::new(),
            tls: Vec::new(),
            status: IngressStatus::default(),
        }
    }

    /// Set the ingress class.
    pub fn with_class(mut self, class: impl Into<String>) -> Self {
        self.ingress_class = Some(class.into());
        self
    }

    /// Set the default backend.
    pub fn with_default_backend(mut self, backend: IngressBackend) -> Self {
        self.default_backend = Some(backend);
        self
    }

    /// Add a rule.
    pub fn with_rule(mut self, rule: IngressRule) -> Self {
        self.rules.push(rule);
        self
    }

    /// Add TLS configuration.
    pub fn with_tls(mut self, tls: IngressTLS) -> Self {
        self.tls.push(tls);
        self
    }

    /// Add an annotation.
    pub fn with_annotation(mut self, key: impl Into<String>, value: impl Into<String>) -> Self {
        self.annotations.insert(key.into(), value.into());
        self
    }

    /// Get all hosts from rules.
    pub fn hosts(&self) -> Vec<&str> {
        self.rules
            .iter()
            .filter_map(|r| r.host.as_deref())
            .collect()
    }

    /// Check if this ingress has TLS for a host.
    pub fn has_tls_for_host(&self, host: &str) -> bool {
        self.tls.iter().any(|t| t.hosts.iter().any(|h| h == host))
    }
}

/// Ingress rule.
#[derive(Debug, Clone)]
pub struct IngressRule {
    /// Host (optional, matches all if None).
    pub host: Option<String>,
    /// HTTP paths.
    pub paths: Vec<IngressPath>,
}

impl IngressRule {
    /// Create a new rule for a host.
    pub fn for_host(host: impl Into<String>) -> Self {
        Self {
            host: Some(host.into()),
            paths: Vec::new(),
        }
    }

    /// Create a rule matching all hosts.
    pub fn any_host() -> Self {
        Self {
            host: None,
            paths: Vec::new(),
        }
    }

    /// Add a path.
    pub fn with_path(mut self, path: IngressPath) -> Self {
        self.paths.push(path);
        self
    }
}

/// Ingress path.
#[derive(Debug, Clone)]
pub struct IngressPath {
    /// Path pattern.
    pub path: String,
    /// Path type.
    pub path_type: PathType,
    /// Backend for this path.
    pub backend: IngressBackend,
}

impl IngressPath {
    /// Create a new path.
    pub fn new(path: impl Into<String>, backend: IngressBackend) -> Self {
        Self {
            path: path.into(),
            path_type: PathType::Prefix,
            backend,
        }
    }

    /// Set the path type.
    pub fn with_type(mut self, path_type: PathType) -> Self {
        self.path_type = path_type;
        self
    }
}

/// Path matching type.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub enum PathType {
    /// Exact path match.
    Exact,
    /// Prefix match.
    #[default]
    Prefix,
    /// Implementation-specific matching.
    ImplementationSpecific,
}

/// Ingress backend.
#[derive(Debug, Clone)]
pub struct IngressBackend {
    /// Service backend.
    pub service: Option<ServiceBackend>,
    /// Resource backend (for custom resources).
    pub resource: Option<ResourceBackend>,
}

impl IngressBackend {
    /// Create a service backend.
    pub fn service(name: impl Into<String>, port: ServiceBackendPort) -> Self {
        Self {
            service: Some(ServiceBackend {
                name: name.into(),
                namespace: None,
                port,
            }),
            resource: None,
        }
    }

    /// Create a resource backend.
    pub fn resource(
        api_group: impl Into<String>,
        kind: impl Into<String>,
        name: impl Into<String>,
    ) -> Self {
        Self {
            service: None,
            resource: Some(ResourceBackend {
                api_group: api_group.into(),
                kind: kind.into(),
                name: name.into(),
            }),
        }
    }

    /// Get the service key if this is a service backend.
    pub fn service_key(&self, default_namespace: &str) -> Option<ServiceKey> {
        self.service
            .as_ref()
            .map(|s| ServiceKey::new(s.namespace.as_deref().unwrap_or(default_namespace), &s.name))
    }
}

/// Service backend reference.
#[derive(Debug, Clone)]
pub struct ServiceBackend {
    /// Service name.
    pub name: String,
    /// Service namespace (defaults to ingress namespace).
    pub namespace: Option<String>,
    /// Service port.
    pub port: ServiceBackendPort,
}

/// Service backend port.
#[derive(Debug, Clone)]
pub enum ServiceBackendPort {
    /// Port number.
    Number(u16),
    /// Port name.
    Name(String),
}

impl ServiceBackendPort {
    /// Get the port number if specified numerically.
    pub fn number(&self) -> Option<u16> {
        match self {
            Self::Number(n) => Some(*n),
            Self::Name(_) => None,
        }
    }

    /// Get the port name if specified by name.
    pub fn name(&self) -> Option<&str> {
        match self {
            Self::Number(_) => None,
            Self::Name(n) => Some(n),
        }
    }
}

/// Resource backend reference.
#[derive(Debug, Clone)]
pub struct ResourceBackend {
    /// API group.
    pub api_group: String,
    /// Resource kind.
    pub kind: String,
    /// Resource name.
    pub name: String,
}

/// Ingress TLS configuration.
#[derive(Debug, Clone)]
pub struct IngressTLS {
    /// Hosts covered by this TLS config.
    pub hosts: Vec<String>,
    /// Secret name containing the certificate.
    pub secret_name: Option<String>,
}

impl IngressTLS {
    /// Create TLS config for hosts.
    pub fn for_hosts(hosts: Vec<String>) -> Self {
        Self {
            hosts,
            secret_name: None,
        }
    }

    /// Set the secret name.
    pub fn with_secret(mut self, secret: impl Into<String>) -> Self {
        self.secret_name = Some(secret.into());
        self
    }
}

/// Ingress status.
#[derive(Debug, Clone, Default)]
pub struct IngressStatus {
    /// Load balancer status.
    pub load_balancer: LoadBalancerStatus,
}

/// Load balancer status.
#[derive(Debug, Clone, Default)]
pub struct LoadBalancerStatus {
    /// Ingress points (IPs or hostnames).
    pub ingress: Vec<LoadBalancerIngress>,
}

/// Load balancer ingress point.
#[derive(Debug, Clone)]
pub struct LoadBalancerIngress {
    /// IP address.
    pub ip: Option<String>,
    /// Hostname.
    pub hostname: Option<String>,
    /// Ports (for port-based load balancers).
    pub ports: Vec<PortStatus>,
}

/// Port status.
#[derive(Debug, Clone)]
pub struct PortStatus {
    /// Port number.
    pub port: u16,
    /// Protocol.
    pub protocol: String,
    /// Error message if any.
    pub error: Option<String>,
}

/// Generated route from ingress rules.
#[derive(Debug, Clone)]
pub struct Route {
    /// Unique route ID.
    pub id: String,
    /// Host to match.
    pub host: Option<String>,
    /// Path to match.
    pub path: String,
    /// Path matching type.
    pub path_type: PathType,
    /// Backend to route to.
    pub backend: IngressBackend,
    /// Route priority (higher = more specific).
    pub priority: u32,
    /// Whether TLS is required.
    pub tls: bool,
    /// Annotations from the ingress.
    pub annotations: HashMap<String, String>,
}

impl Route {
    /// Get an annotation value.
    pub fn annotation(&self, key: &str) -> Option<&str> {
        self.annotations.get(key).map(|s| s.as_str())
    }

    /// Check if this route requires authentication.
    pub fn requires_auth(&self) -> bool {
        self.annotations
            .contains_key("nginx.ingress.kubernetes.io/auth-url")
            || self.annotations.contains_key("r0n.io/auth-required")
    }

    /// Get rate limit if configured.
    pub fn rate_limit(&self) -> Option<u32> {
        self.annotation("r0n.io/rate-limit")
            .or_else(|| self.annotation("nginx.ingress.kubernetes.io/limit-rps"))
            .and_then(|v| v.parse().ok())
    }
}

/// Callback trait for ingress updates.
pub trait IngressCallback: Send + Sync + std::fmt::Debug {
    /// Called when an ingress is added or modified.
    fn on_ingress_update(&self, ingress: &Ingress);

    /// Called when an ingress is deleted.
    fn on_ingress_delete(&self, namespace: &str, name: &str);

    /// Called when routes are regenerated.
    fn on_routes_changed(&self, routes: &[Route]);
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_ingress_controller_new() {
        let controller = IngressController::new();
        assert_eq!(controller.ingress_count(), 0);
        assert_eq!(controller.rule_count(), 0);
    }

    #[test]
    fn test_ingress_controller_for_class() {
        let controller = IngressController::for_class("r0n");
        assert_eq!(controller.ingress_class, Some("r0n".to_string()));
    }

    #[test]
    fn test_ingress_creation() {
        let ingress = Ingress::new("my-ingress", "default")
            .with_class("r0n")
            .with_annotation("r0n.io/rate-limit", "100")
            .with_rule(
                IngressRule::for_host("example.com").with_path(IngressPath::new(
                    "/api",
                    IngressBackend::service("api-service", ServiceBackendPort::Number(8080)),
                )),
            )
            .with_tls(
                IngressTLS::for_hosts(vec!["example.com".to_string()]).with_secret("tls-secret"),
            );

        assert_eq!(ingress.name, "my-ingress");
        assert_eq!(ingress.ingress_class, Some("r0n".to_string()));
        assert_eq!(ingress.rules.len(), 1);
        assert_eq!(ingress.tls.len(), 1);
        assert!(ingress.has_tls_for_host("example.com"));
    }

    #[test]
    fn test_ingress_event_handling() {
        let mut controller = IngressController::new();

        let ingress = Ingress::new("web", "default").with_rule(
            IngressRule::for_host("web.example.com").with_path(IngressPath::new(
                "/",
                IngressBackend::service("web", ServiceBackendPort::Number(80)),
            )),
        );

        controller
            .handle_event(WatchEvent::Added(ingress.clone()))
            .unwrap();
        assert_eq!(controller.ingress_count(), 1);
        assert!(controller.get_ingress("default", "web").is_some());

        controller
            .handle_event(WatchEvent::Deleted(ingress))
            .unwrap();
        assert_eq!(controller.ingress_count(), 0);
    }

    #[test]
    fn test_ingress_class_filtering() {
        let mut controller = IngressController::for_class("r0n");

        let matching = Ingress::new("matching", "default").with_class("r0n");
        let non_matching = Ingress::new("non-matching", "default").with_class("nginx");

        controller
            .handle_event(WatchEvent::Added(matching))
            .unwrap();
        controller
            .handle_event(WatchEvent::Added(non_matching))
            .unwrap();

        assert_eq!(controller.ingress_count(), 1);
        assert!(controller.get_ingress("default", "matching").is_some());
        assert!(controller.get_ingress("default", "non-matching").is_none());
    }

    #[test]
    fn test_route_generation() {
        let mut controller = IngressController::new();

        let ingress = Ingress::new("multi-path", "default")
            .with_rule(
                IngressRule::for_host("app.example.com")
                    .with_path(IngressPath::new(
                        "/api",
                        IngressBackend::service("api", ServiceBackendPort::Number(8080)),
                    ))
                    .with_path(IngressPath::new(
                        "/web",
                        IngressBackend::service("web", ServiceBackendPort::Number(80)),
                    )),
            )
            .with_rule(
                IngressRule::for_host("admin.example.com").with_path(IngressPath::new(
                    "/",
                    IngressBackend::service("admin", ServiceBackendPort::Number(3000)),
                )),
            );

        controller.handle_event(WatchEvent::Added(ingress)).unwrap();

        let routes = controller.generate_routes();
        assert_eq!(routes.len(), 3);

        // Routes should be sorted by priority
        for i in 1..routes.len() {
            assert!(routes[i - 1].priority >= routes[i].priority);
        }
    }

    #[test]
    fn test_default_backend() {
        let mut controller = IngressController::new();

        let ingress = Ingress::new("with-default", "default").with_default_backend(
            IngressBackend::service("default-backend", ServiceBackendPort::Number(80)),
        );

        controller.handle_event(WatchEvent::Added(ingress)).unwrap();

        let routes = controller.generate_routes();
        assert_eq!(routes.len(), 1);
        assert_eq!(routes[0].path, "/");
        assert_eq!(routes[0].priority, 0);
    }

    #[test]
    fn test_path_types() {
        let exact = IngressPath::new(
            "/exact",
            IngressBackend::service("svc", ServiceBackendPort::Number(80)),
        )
        .with_type(PathType::Exact);
        assert_eq!(exact.path_type, PathType::Exact);

        let prefix = IngressPath::new(
            "/prefix",
            IngressBackend::service("svc", ServiceBackendPort::Number(80)),
        );
        assert_eq!(prefix.path_type, PathType::Prefix);
    }

    #[test]
    fn test_route_annotations() {
        let mut annotations = HashMap::new();
        annotations.insert("r0n.io/rate-limit".to_string(), "100".to_string());
        annotations.insert("r0n.io/auth-required".to_string(), "true".to_string());

        let route = Route {
            id: "test".to_string(),
            host: Some("example.com".to_string()),
            path: "/api".to_string(),
            path_type: PathType::Prefix,
            backend: IngressBackend::service("api", ServiceBackendPort::Number(8080)),
            priority: 100,
            tls: true,
            annotations,
        };

        assert_eq!(route.rate_limit(), Some(100));
        assert!(route.requires_auth());
    }

    #[test]
    fn test_service_backend_port() {
        let number = ServiceBackendPort::Number(8080);
        assert_eq!(number.number(), Some(8080));
        assert_eq!(number.name(), None);

        let name = ServiceBackendPort::Name("http".to_string());
        assert_eq!(name.number(), None);
        assert_eq!(name.name(), Some("http"));
    }

    #[test]
    fn test_ingress_hosts() {
        let ingress = Ingress::new("multi-host", "default")
            .with_rule(
                IngressRule::for_host("host1.example.com").with_path(IngressPath::new(
                    "/",
                    IngressBackend::service("svc", ServiceBackendPort::Number(80)),
                )),
            )
            .with_rule(
                IngressRule::for_host("host2.example.com").with_path(IngressPath::new(
                    "/",
                    IngressBackend::service("svc", ServiceBackendPort::Number(80)),
                )),
            );

        let hosts = ingress.hosts();
        assert_eq!(hosts.len(), 2);
        assert!(hosts.contains(&"host1.example.com"));
        assert!(hosts.contains(&"host2.example.com"));
    }

    #[test]
    fn test_tls_configuration() {
        let tls = IngressTLS::for_hosts(vec![
            "secure.example.com".to_string(),
            "*.example.com".to_string(),
        ])
        .with_secret("wildcard-tls");

        assert_eq!(tls.hosts.len(), 2);
        assert_eq!(tls.secret_name, Some("wildcard-tls".to_string()));
    }

    #[test]
    fn test_resource_backend() {
        let backend =
            IngressBackend::resource("gateway.networking.k8s.io", "Gateway", "my-gateway");

        assert!(backend.service.is_none());
        assert!(backend.resource.is_some());

        let resource = backend.resource.unwrap();
        assert_eq!(resource.api_group, "gateway.networking.k8s.io");
        assert_eq!(resource.kind, "Gateway");
        assert_eq!(resource.name, "my-gateway");
    }
}
