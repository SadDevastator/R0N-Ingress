//! Kubernetes service discovery.
//!
//! Provides service discovery by watching Kubernetes Services and Endpoints,
//! enabling dynamic backend resolution for routing.

use std::collections::HashMap;
use std::net::{IpAddr, SocketAddr};
use std::sync::Arc;
use std::time::{Duration, Instant};

use super::config::{LabelSelector, WatchConfig};
use super::error::{K8sError, K8sResult};

/// Service discovery for Kubernetes workloads.
#[derive(Debug)]
pub struct ServiceDiscovery {
    /// Discovered services by namespace/name.
    services: HashMap<ServiceKey, Service>,
    /// Discovered endpoints by namespace/name.
    endpoints: HashMap<ServiceKey, Vec<Endpoint>>,
    /// Watch configuration.
    #[allow(dead_code)]
    watch_config: WatchConfig,
    /// Label selector for filtering services.
    #[allow(dead_code)]
    label_selector: Option<LabelSelector>,
    /// Namespace filter (None = all namespaces).
    #[allow(dead_code)]
    namespace_filter: Option<String>,
    /// Last sync time.
    last_sync: Option<Instant>,
    /// Service update callbacks.
    #[allow(dead_code)]
    callbacks: Vec<Arc<dyn ServiceCallback>>,
}

impl Default for ServiceDiscovery {
    fn default() -> Self {
        Self::new()
    }
}

impl ServiceDiscovery {
    /// Create a new service discovery instance.
    pub fn new() -> Self {
        Self {
            services: HashMap::new(),
            endpoints: HashMap::new(),
            watch_config: WatchConfig::default(),
            label_selector: None,
            namespace_filter: None,
            last_sync: None,
            callbacks: Vec::new(),
        }
    }

    /// Create service discovery for a specific namespace.
    pub fn for_namespace(namespace: impl Into<String>) -> Self {
        Self {
            namespace_filter: Some(namespace.into()),
            ..Self::new()
        }
    }

    /// Set the watch configuration.
    pub fn with_watch_config(mut self, config: WatchConfig) -> Self {
        self.watch_config = config;
        self
    }

    /// Set the label selector.
    pub fn with_label_selector(mut self, selector: LabelSelector) -> Self {
        self.label_selector = Some(selector);
        self
    }

    /// Register a service update callback.
    pub fn on_update<F>(&mut self, callback: F)
    where
        F: ServiceCallback + 'static,
    {
        self.callbacks.push(Arc::new(callback));
    }

    /// Get a service by namespace and name.
    pub fn get_service(&self, namespace: &str, name: &str) -> Option<&Service> {
        let key = ServiceKey::new(namespace, name);
        self.services.get(&key)
    }

    /// Get endpoints for a service.
    pub fn get_endpoints(&self, namespace: &str, name: &str) -> Option<&[Endpoint]> {
        let key = ServiceKey::new(namespace, name);
        self.endpoints.get(&key).map(|v| v.as_slice())
    }

    /// Get ready endpoints for a service.
    pub fn get_ready_endpoints(&self, namespace: &str, name: &str) -> Vec<&Endpoint> {
        self.get_endpoints(namespace, name)
            .map(|eps| eps.iter().filter(|e| e.ready).collect())
            .unwrap_or_default()
    }

    /// Get all services.
    pub fn list_services(&self) -> impl Iterator<Item = &Service> {
        self.services.values()
    }

    /// Get services by label.
    pub fn find_services_by_label(&self, key: &str, value: &str) -> Vec<&Service> {
        self.services
            .values()
            .filter(|s| s.labels.get(key).map(|v| v == value).unwrap_or(false))
            .collect()
    }

    /// Get the total number of discovered services.
    pub fn service_count(&self) -> usize {
        self.services.len()
    }

    /// Get the total number of endpoints.
    pub fn endpoint_count(&self) -> usize {
        self.endpoints.values().map(|v| v.len()).sum()
    }

    /// Get the total number of ready endpoints.
    pub fn ready_endpoint_count(&self) -> usize {
        self.endpoints
            .values()
            .flat_map(|v| v.iter())
            .filter(|e| e.ready)
            .count()
    }

    /// Check if a service exists.
    pub fn has_service(&self, namespace: &str, name: &str) -> bool {
        let key = ServiceKey::new(namespace, name);
        self.services.contains_key(&key)
    }

    /// Get the last sync time.
    pub fn last_sync(&self) -> Option<Instant> {
        self.last_sync
    }

    /// Process a service update event.
    pub fn handle_service_event(&mut self, event: WatchEvent<Service>) -> K8sResult<()> {
        match event {
            WatchEvent::Added(service) | WatchEvent::Modified(service) => {
                let key = ServiceKey::new(&service.namespace, &service.name);
                self.services.insert(key, service);
            },
            WatchEvent::Deleted(service) => {
                let key = ServiceKey::new(&service.namespace, &service.name);
                self.services.remove(&key);
                self.endpoints.remove(&key);
            },
            WatchEvent::Bookmark {
                resource_version: _,
            } => {
                // Bookmark received, update sync time
            },
            WatchEvent::Error(err) => {
                return Err(K8sError::WatchError(err));
            },
        }
        self.last_sync = Some(Instant::now());
        Ok(())
    }

    /// Process an endpoints update event.
    pub fn handle_endpoints_event(&mut self, event: WatchEvent<EndpointSlice>) -> K8sResult<()> {
        match event {
            WatchEvent::Added(slice) | WatchEvent::Modified(slice) => {
                let key = ServiceKey::new(&slice.namespace, &slice.service_name);
                let default_port = slice.ports.first().map(|p| p.port).unwrap_or(80);
                let endpoints: Vec<Endpoint> = slice
                    .endpoints
                    .into_iter()
                    .flat_map(|ep| {
                        let ready = ep.ready;
                        let serving = ep.serving;
                        let terminating = ep.terminating;
                        let node_name = ep.node_name.clone();
                        let zone = ep.zone.clone();
                        let hints = ep.hints.clone();
                        ep.addresses.into_iter().map(move |addr| Endpoint {
                            address: addr,
                            port: default_port,
                            ready,
                            serving,
                            terminating,
                            node_name: node_name.clone(),
                            zone: zone.clone(),
                            hints: hints.clone(),
                        })
                    })
                    .collect();
                self.endpoints.insert(key, endpoints);
            },
            WatchEvent::Deleted(slice) => {
                let key = ServiceKey::new(&slice.namespace, &slice.service_name);
                self.endpoints.remove(&key);
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

    /// Resolve a service to backend addresses.
    pub fn resolve(&self, namespace: &str, name: &str, port: Option<u16>) -> Vec<SocketAddr> {
        let service = match self.get_service(namespace, name) {
            Some(s) => s,
            None => return Vec::new(),
        };

        // Determine port to use
        let target_port = port.or_else(|| {
            service
                .ports
                .first()
                .map(|p| p.target_port.unwrap_or(p.port))
        });

        let target_port = match target_port {
            Some(p) => p,
            None => return Vec::new(),
        };

        // Get ready endpoints
        self.get_ready_endpoints(namespace, name)
            .into_iter()
            .map(|ep| SocketAddr::new(ep.address, target_port))
            .collect()
    }

    /// Get service cluster IP.
    pub fn get_cluster_ip(&self, namespace: &str, name: &str) -> Option<IpAddr> {
        self.get_service(namespace, name).and_then(|s| s.cluster_ip)
    }
}

/// Key for service/endpoint lookup.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct ServiceKey {
    /// Namespace.
    pub namespace: String,
    /// Service name.
    pub name: String,
}

impl ServiceKey {
    /// Create a new service key.
    pub fn new(namespace: impl Into<String>, name: impl Into<String>) -> Self {
        Self {
            namespace: namespace.into(),
            name: name.into(),
        }
    }
}

/// Kubernetes Service representation.
#[derive(Debug, Clone)]
pub struct Service {
    /// Service name.
    pub name: String,
    /// Namespace.
    pub namespace: String,
    /// Service UID.
    pub uid: String,
    /// Resource version.
    pub resource_version: String,
    /// Labels.
    pub labels: HashMap<String, String>,
    /// Annotations.
    pub annotations: HashMap<String, String>,
    /// Service type.
    pub service_type: ServiceType,
    /// Cluster IP.
    pub cluster_ip: Option<IpAddr>,
    /// External IPs.
    pub external_ips: Vec<IpAddr>,
    /// Load balancer IP.
    pub load_balancer_ip: Option<IpAddr>,
    /// Service ports.
    pub ports: Vec<ServicePort>,
    /// Selector labels.
    pub selector: HashMap<String, String>,
    /// External name (for ExternalName type).
    pub external_name: Option<String>,
    /// Session affinity.
    pub session_affinity: SessionAffinity,
    /// Creation timestamp.
    pub created_at: Option<Duration>,
}

impl Service {
    /// Create a new service.
    pub fn new(name: impl Into<String>, namespace: impl Into<String>) -> Self {
        Self {
            name: name.into(),
            namespace: namespace.into(),
            uid: String::new(),
            resource_version: String::new(),
            labels: HashMap::new(),
            annotations: HashMap::new(),
            service_type: ServiceType::ClusterIP,
            cluster_ip: None,
            external_ips: Vec::new(),
            load_balancer_ip: None,
            ports: Vec::new(),
            selector: HashMap::new(),
            external_name: None,
            session_affinity: SessionAffinity::None,
            created_at: None,
        }
    }

    /// Add a port to the service.
    pub fn with_port(mut self, port: ServicePort) -> Self {
        self.ports.push(port);
        self
    }

    /// Set the cluster IP.
    pub fn with_cluster_ip(mut self, ip: IpAddr) -> Self {
        self.cluster_ip = Some(ip);
        self
    }

    /// Add a label.
    pub fn with_label(mut self, key: impl Into<String>, value: impl Into<String>) -> Self {
        self.labels.insert(key.into(), value.into());
        self
    }

    /// Check if this is a headless service.
    pub fn is_headless(&self) -> bool {
        self.cluster_ip.is_none() && self.service_type == ServiceType::ClusterIP
    }

    /// Get the primary port.
    pub fn primary_port(&self) -> Option<&ServicePort> {
        self.ports.first()
    }
}

/// Service type.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub enum ServiceType {
    /// ClusterIP (default).
    #[default]
    ClusterIP,
    /// NodePort.
    NodePort,
    /// LoadBalancer.
    LoadBalancer,
    /// ExternalName.
    ExternalName,
}

/// Service port configuration.
#[derive(Debug, Clone)]
pub struct ServicePort {
    /// Port name.
    pub name: Option<String>,
    /// Protocol.
    pub protocol: Protocol,
    /// Service port.
    pub port: u16,
    /// Target port on pods.
    pub target_port: Option<u16>,
    /// Node port (for NodePort/LoadBalancer).
    pub node_port: Option<u16>,
}

impl ServicePort {
    /// Create a new service port.
    pub fn new(port: u16) -> Self {
        Self {
            name: None,
            protocol: Protocol::Tcp,
            port,
            target_port: None,
            node_port: None,
        }
    }

    /// Set the port name.
    pub fn with_name(mut self, name: impl Into<String>) -> Self {
        self.name = Some(name.into());
        self
    }

    /// Set the protocol.
    pub fn with_protocol(mut self, protocol: Protocol) -> Self {
        self.protocol = protocol;
        self
    }

    /// Set the target port.
    pub fn with_target_port(mut self, port: u16) -> Self {
        self.target_port = Some(port);
        self
    }
}

/// Network protocol.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub enum Protocol {
    /// TCP.
    #[default]
    Tcp,
    /// UDP.
    Udp,
    /// SCTP.
    Sctp,
}

/// Session affinity configuration.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub enum SessionAffinity {
    /// No session affinity.
    #[default]
    None,
    /// Client IP based affinity.
    ClientIP {
        /// Timeout in seconds.
        timeout_seconds: u32,
    },
}

/// Kubernetes Endpoint representation.
#[derive(Debug, Clone)]
pub struct Endpoint {
    /// Endpoint IP address.
    pub address: IpAddr,
    /// Endpoint port.
    pub port: u16,
    /// Whether the endpoint is ready.
    pub ready: bool,
    /// Whether the endpoint is serving.
    pub serving: bool,
    /// Whether the endpoint is terminating.
    pub terminating: bool,
    /// Node name hosting the endpoint.
    pub node_name: Option<String>,
    /// Zone of the endpoint.
    pub zone: Option<String>,
    /// Topology hints.
    pub hints: Option<EndpointHints>,
}

impl Endpoint {
    /// Create a new endpoint.
    pub fn new(address: IpAddr, port: u16) -> Self {
        Self {
            address,
            port,
            ready: true,
            serving: true,
            terminating: false,
            node_name: None,
            zone: None,
            hints: None,
        }
    }

    /// Set the ready state.
    pub fn with_ready(mut self, ready: bool) -> Self {
        self.ready = ready;
        self
    }

    /// Set the node name.
    pub fn with_node(mut self, node: impl Into<String>) -> Self {
        self.node_name = Some(node.into());
        self
    }

    /// Set the zone.
    pub fn with_zone(mut self, zone: impl Into<String>) -> Self {
        self.zone = Some(zone.into());
        self
    }

    /// Get the socket address.
    pub fn socket_addr(&self) -> SocketAddr {
        SocketAddr::new(self.address, self.port)
    }

    /// Check if this endpoint is usable.
    pub fn is_usable(&self) -> bool {
        self.ready && self.serving && !self.terminating
    }
}

/// Endpoint hints for topology-aware routing.
#[derive(Debug, Clone)]
pub struct EndpointHints {
    /// Zones this endpoint should be consumed from.
    pub for_zones: Vec<String>,
}

/// EndpointSlice for efficient endpoint updates.
#[derive(Debug, Clone)]
pub struct EndpointSlice {
    /// Slice name.
    pub name: String,
    /// Namespace.
    pub namespace: String,
    /// Service name this slice belongs to.
    pub service_name: String,
    /// Address type.
    pub address_type: AddressType,
    /// Endpoints in this slice.
    pub endpoints: Vec<EndpointSliceEndpoint>,
    /// Ports in this slice.
    pub ports: Vec<EndpointSlicePort>,
}

/// Endpoint within an EndpointSlice.
#[derive(Debug, Clone)]
pub struct EndpointSliceEndpoint {
    /// Addresses.
    pub addresses: Vec<IpAddr>,
    /// Ready condition.
    pub ready: bool,
    /// Serving condition.
    pub serving: bool,
    /// Terminating condition.
    pub terminating: bool,
    /// Node name.
    pub node_name: Option<String>,
    /// Zone.
    pub zone: Option<String>,
    /// Hints.
    pub hints: Option<EndpointHints>,
}

/// Port within an EndpointSlice.
#[derive(Debug, Clone)]
pub struct EndpointSlicePort {
    /// Port name.
    pub name: Option<String>,
    /// Protocol.
    pub protocol: Protocol,
    /// Port number.
    pub port: u16,
}

/// Address type.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AddressType {
    /// IPv4 addresses.
    IPv4,
    /// IPv6 addresses.
    IPv6,
    /// FQDN addresses.
    FQDN,
}

/// Watch event for Kubernetes resources.
#[derive(Debug, Clone)]
pub enum WatchEvent<T> {
    /// Resource added.
    Added(T),
    /// Resource modified.
    Modified(T),
    /// Resource deleted.
    Deleted(T),
    /// Bookmark (sync point).
    Bookmark {
        /// Resource version at bookmark.
        resource_version: String,
    },
    /// Watch error.
    Error(String),
}

impl<T> WatchEvent<T> {
    /// Check if this is an error event.
    pub fn is_error(&self) -> bool {
        matches!(self, Self::Error(_))
    }

    /// Check if this is a bookmark.
    pub fn is_bookmark(&self) -> bool {
        matches!(self, Self::Bookmark { .. })
    }

    /// Map the inner value.
    pub fn map<U, F: FnOnce(T) -> U>(self, f: F) -> WatchEvent<U> {
        match self {
            WatchEvent::Added(t) => WatchEvent::Added(f(t)),
            WatchEvent::Modified(t) => WatchEvent::Modified(f(t)),
            WatchEvent::Deleted(t) => WatchEvent::Deleted(f(t)),
            WatchEvent::Bookmark { resource_version } => WatchEvent::Bookmark { resource_version },
            WatchEvent::Error(e) => WatchEvent::Error(e),
        }
    }
}

/// Callback trait for service updates.
pub trait ServiceCallback: Send + Sync + std::fmt::Debug {
    /// Called when a service is added or modified.
    fn on_service_update(&self, service: &Service);

    /// Called when a service is deleted.
    fn on_service_delete(&self, namespace: &str, name: &str);

    /// Called when endpoints are updated.
    fn on_endpoints_update(&self, namespace: &str, name: &str, endpoints: &[Endpoint]);
}

/// Simple callback implementation using closures.
#[derive(Debug)]
pub struct FnCallback<F1, F2, F3>
where
    F1: Fn(&Service) + Send + Sync,
    F2: Fn(&str, &str) + Send + Sync,
    F3: Fn(&str, &str, &[Endpoint]) + Send + Sync,
{
    on_update: F1,
    on_delete: F2,
    on_endpoints: F3,
}

impl<F1, F2, F3> ServiceCallback for FnCallback<F1, F2, F3>
where
    F1: Fn(&Service) + Send + Sync + std::fmt::Debug,
    F2: Fn(&str, &str) + Send + Sync + std::fmt::Debug,
    F3: Fn(&str, &str, &[Endpoint]) + Send + Sync + std::fmt::Debug,
{
    fn on_service_update(&self, service: &Service) {
        (self.on_update)(service);
    }

    fn on_service_delete(&self, namespace: &str, name: &str) {
        (self.on_delete)(namespace, name);
    }

    fn on_endpoints_update(&self, namespace: &str, name: &str, endpoints: &[Endpoint]) {
        (self.on_endpoints)(namespace, name, endpoints);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::Ipv4Addr;

    #[test]
    fn test_service_discovery_new() {
        let discovery = ServiceDiscovery::new();
        assert_eq!(discovery.service_count(), 0);
        assert_eq!(discovery.endpoint_count(), 0);
    }

    #[test]
    fn test_service_discovery_for_namespace() {
        let discovery = ServiceDiscovery::for_namespace("production");
        assert_eq!(discovery.namespace_filter, Some("production".to_string()));
    }

    #[test]
    fn test_service_creation() {
        let service = Service::new("my-service", "default")
            .with_cluster_ip(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)))
            .with_port(ServicePort::new(80).with_target_port(8080))
            .with_label("app", "web");

        assert_eq!(service.name, "my-service");
        assert_eq!(service.namespace, "default");
        assert!(service.cluster_ip.is_some());
        assert_eq!(service.ports.len(), 1);
        assert_eq!(service.labels.get("app"), Some(&"web".to_string()));
    }

    #[test]
    fn test_headless_service() {
        let service = Service::new("headless", "default");
        assert!(service.is_headless());

        let service_with_ip = Service::new("with-ip", "default")
            .with_cluster_ip(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)));
        assert!(!service_with_ip.is_headless());
    }

    #[test]
    fn test_endpoint_creation() {
        let endpoint = Endpoint::new(IpAddr::V4(Ipv4Addr::new(10, 0, 1, 1)), 8080)
            .with_ready(true)
            .with_node("node-1")
            .with_zone("us-east-1a");

        assert!(endpoint.ready);
        assert_eq!(endpoint.node_name, Some("node-1".to_string()));
        assert_eq!(endpoint.zone, Some("us-east-1a".to_string()));
        assert!(endpoint.is_usable());
    }

    #[test]
    fn test_endpoint_usability() {
        let ready = Endpoint::new(IpAddr::V4(Ipv4Addr::new(10, 0, 1, 1)), 80);
        assert!(ready.is_usable());

        let not_ready = Endpoint::new(IpAddr::V4(Ipv4Addr::new(10, 0, 1, 2)), 80).with_ready(false);
        assert!(!not_ready.is_usable());
    }

    #[test]
    fn test_service_event_handling() {
        let mut discovery = ServiceDiscovery::new();

        let service =
            Service::new("web", "default").with_cluster_ip(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)));

        // Add service
        discovery
            .handle_service_event(WatchEvent::Added(service.clone()))
            .unwrap();
        assert!(discovery.has_service("default", "web"));
        assert_eq!(discovery.service_count(), 1);

        // Modify service
        let modified =
            Service::new("web", "default").with_cluster_ip(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2)));
        discovery
            .handle_service_event(WatchEvent::Modified(modified))
            .unwrap();
        assert_eq!(
            discovery.get_cluster_ip("default", "web"),
            Some(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2)))
        );

        // Delete service
        discovery
            .handle_service_event(WatchEvent::Deleted(service))
            .unwrap();
        assert!(!discovery.has_service("default", "web"));
    }

    #[test]
    fn test_service_resolution() {
        let mut discovery = ServiceDiscovery::new();

        let service =
            Service::new("web", "default").with_port(ServicePort::new(80).with_target_port(8080));
        discovery
            .handle_service_event(WatchEvent::Added(service))
            .unwrap();

        let slice = EndpointSlice {
            name: "web-abc".to_string(),
            namespace: "default".to_string(),
            service_name: "web".to_string(),
            address_type: AddressType::IPv4,
            endpoints: vec![
                EndpointSliceEndpoint {
                    addresses: vec![IpAddr::V4(Ipv4Addr::new(10, 0, 1, 1))],
                    ready: true,
                    serving: true,
                    terminating: false,
                    node_name: None,
                    zone: None,
                    hints: None,
                },
                EndpointSliceEndpoint {
                    addresses: vec![IpAddr::V4(Ipv4Addr::new(10, 0, 1, 2))],
                    ready: true,
                    serving: true,
                    terminating: false,
                    node_name: None,
                    zone: None,
                    hints: None,
                },
            ],
            ports: vec![EndpointSlicePort {
                name: None,
                protocol: Protocol::Tcp,
                port: 8080,
            }],
        };
        discovery
            .handle_endpoints_event(WatchEvent::Added(slice))
            .unwrap();

        let addrs = discovery.resolve("default", "web", None);
        assert_eq!(addrs.len(), 2);
    }

    #[test]
    fn test_find_services_by_label() {
        let mut discovery = ServiceDiscovery::new();

        let svc1 = Service::new("web1", "default").with_label("app", "web");
        let svc2 = Service::new("web2", "default").with_label("app", "web");
        let svc3 = Service::new("api", "default").with_label("app", "api");

        discovery
            .handle_service_event(WatchEvent::Added(svc1))
            .unwrap();
        discovery
            .handle_service_event(WatchEvent::Added(svc2))
            .unwrap();
        discovery
            .handle_service_event(WatchEvent::Added(svc3))
            .unwrap();

        let web_services = discovery.find_services_by_label("app", "web");
        assert_eq!(web_services.len(), 2);
    }

    #[test]
    fn test_watch_event_map() {
        let event: WatchEvent<i32> = WatchEvent::Added(42);
        let mapped = event.map(|x| x.to_string());

        if let WatchEvent::Added(s) = mapped {
            assert_eq!(s, "42");
        } else {
            panic!("Expected Added variant");
        }
    }

    #[test]
    fn test_service_port() {
        let port = ServicePort::new(443)
            .with_name("https")
            .with_protocol(Protocol::Tcp)
            .with_target_port(8443);

        assert_eq!(port.name, Some("https".to_string()));
        assert_eq!(port.port, 443);
        assert_eq!(port.target_port, Some(8443));
        assert_eq!(port.protocol, Protocol::Tcp);
    }

    #[test]
    fn test_endpoint_socket_addr() {
        let endpoint = Endpoint::new(IpAddr::V4(Ipv4Addr::new(192, 168, 1, 100)), 8080);

        let addr = endpoint.socket_addr();
        assert_eq!(addr.ip(), IpAddr::V4(Ipv4Addr::new(192, 168, 1, 100)));
        assert_eq!(addr.port(), 8080);
    }
}
