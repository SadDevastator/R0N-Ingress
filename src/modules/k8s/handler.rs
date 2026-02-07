//! Kubernetes integration handler.
//!
//! Provides a ModuleContract implementation for Kubernetes integration,
//! coordinating service discovery, ingress control, and secret management.

use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::time::Instant;

use crate::module::{
    Capability, Dependency, MetricsPayload, ModuleConfig, ModuleContract, ModuleError,
    ModuleManifest, ModuleResult, ModuleStatus,
};

use super::config::K8sConfig;
use super::discovery::ServiceDiscovery;
use super::ingress::IngressController;
use super::secrets::SecretManager;

/// Kubernetes integration handler.
///
/// Provides service discovery, ingress controller, and secret management
/// functionality for Kubernetes-native deployments.
#[derive(Debug)]
pub struct K8sHandler {
    /// Handler configuration.
    config: K8sConfig,
    /// Service discovery instance.
    service_discovery: ServiceDiscovery,
    /// Ingress controller instance.
    ingress_controller: IngressController,
    /// Secret manager instance.
    secret_manager: SecretManager,
    /// Whether the handler is initialized.
    initialized: bool,
    /// Whether the handler is running.
    running: AtomicBool,
    /// Start time for uptime tracking.
    start_time: Option<Instant>,
    /// Metrics
    metrics: K8sMetrics,
}

/// Metrics for Kubernetes operations.
#[derive(Debug, Default)]
pub struct K8sMetrics {
    /// Number of services discovered.
    services_discovered: AtomicU64,
    /// Number of endpoints discovered.
    endpoints_discovered: AtomicU64,
    /// Number of ingresses managed.
    ingresses_managed: AtomicU64,
    /// Number of routes generated.
    routes_generated: AtomicU64,
    /// Number of secrets cached.
    secrets_cached: AtomicU64,
    /// Number of config maps cached.
    config_maps_cached: AtomicU64,
    /// Number of watch events processed.
    watch_events: AtomicU64,
    /// Number of watch errors.
    watch_errors: AtomicU64,
    /// Number of API requests made.
    api_requests: AtomicU64,
    /// Number of API errors.
    api_errors: AtomicU64,
    /// Last sync duration in milliseconds.
    sync_duration_ms: AtomicU64,
    /// Leader election state (1 = leader, 0 = follower).
    is_leader: AtomicU64,
}

impl Default for K8sHandler {
    fn default() -> Self {
        Self::new()
    }
}

impl K8sHandler {
    /// Create a new Kubernetes handler.
    pub fn new() -> Self {
        Self {
            config: K8sConfig::default(),
            service_discovery: ServiceDiscovery::new(),
            ingress_controller: IngressController::new(),
            secret_manager: SecretManager::new(),
            initialized: false,
            running: AtomicBool::new(false),
            start_time: None,
            metrics: K8sMetrics::default(),
        }
    }

    /// Create a handler with configuration.
    pub fn with_config(config: K8sConfig) -> Self {
        let namespace = config.namespace.clone();

        let service_discovery = match &namespace {
            Some(ns) => ServiceDiscovery::for_namespace(ns.clone()),
            None => ServiceDiscovery::new(),
        };

        let ingress_controller = match &namespace {
            Some(ns) => IngressController::new().with_namespace(ns.clone()),
            None => IngressController::new(),
        };

        let secret_manager = match &namespace {
            Some(ns) => SecretManager::for_namespace(ns.clone()),
            None => SecretManager::new(),
        };

        Self {
            config,
            service_discovery,
            ingress_controller,
            secret_manager,
            initialized: false,
            running: AtomicBool::new(false),
            start_time: None,
            metrics: K8sMetrics::default(),
        }
    }

    /// Create a handler for in-cluster deployment.
    pub fn in_cluster() -> Self {
        Self::with_config(K8sConfig::in_cluster())
    }

    /// Check if the handler is running.
    pub fn is_running(&self) -> bool {
        self.running.load(Ordering::SeqCst)
    }

    /// Get the service discovery instance.
    pub fn service_discovery(&self) -> &ServiceDiscovery {
        &self.service_discovery
    }

    /// Get mutable service discovery instance.
    pub fn service_discovery_mut(&mut self) -> &mut ServiceDiscovery {
        &mut self.service_discovery
    }

    /// Get the ingress controller instance.
    pub fn ingress_controller(&self) -> &IngressController {
        &self.ingress_controller
    }

    /// Get mutable ingress controller instance.
    pub fn ingress_controller_mut(&mut self) -> &mut IngressController {
        &mut self.ingress_controller
    }

    /// Get the secret manager instance.
    pub fn secret_manager(&self) -> &SecretManager {
        &self.secret_manager
    }

    /// Get mutable secret manager instance.
    pub fn secret_manager_mut(&mut self) -> &mut SecretManager {
        &mut self.secret_manager
    }

    /// Get the configuration.
    pub fn config(&self) -> &K8sConfig {
        &self.config
    }

    /// Get uptime in seconds.
    pub fn uptime_secs(&self) -> u64 {
        self.start_time.map(|t| t.elapsed().as_secs()).unwrap_or(0)
    }

    /// Update metrics from current state.
    fn update_metrics(&self) {
        self.metrics.services_discovered.store(
            self.service_discovery.service_count() as u64,
            Ordering::SeqCst,
        );
        self.metrics.endpoints_discovered.store(
            self.service_discovery.endpoint_count() as u64,
            Ordering::SeqCst,
        );
        self.metrics.ingresses_managed.store(
            self.ingress_controller.ingress_count() as u64,
            Ordering::SeqCst,
        );
        self.metrics.routes_generated.store(
            self.ingress_controller.rule_count() as u64,
            Ordering::SeqCst,
        );
        self.metrics
            .secrets_cached
            .store(self.secret_manager.secret_count() as u64, Ordering::SeqCst);
        self.metrics.config_maps_cached.store(
            self.secret_manager.config_map_count() as u64,
            Ordering::SeqCst,
        );
    }

    /// Record a watch event.
    pub fn on_watch_event(&self) {
        self.metrics.watch_events.fetch_add(1, Ordering::SeqCst);
    }

    /// Record a watch error.
    pub fn on_watch_error(&self) {
        self.metrics.watch_errors.fetch_add(1, Ordering::SeqCst);
    }

    /// Record an API request.
    pub fn on_api_request(&self) {
        self.metrics.api_requests.fetch_add(1, Ordering::SeqCst);
    }

    /// Record an API error.
    pub fn on_api_error(&self) {
        self.metrics.api_errors.fetch_add(1, Ordering::SeqCst);
    }

    /// Set leader status.
    pub fn set_leader(&self, is_leader: bool) {
        self.metrics
            .is_leader
            .store(if is_leader { 1 } else { 0 }, Ordering::SeqCst);
    }

    /// Record sync duration.
    pub fn record_sync_duration(&self, duration_ms: u64) {
        self.metrics
            .sync_duration_ms
            .store(duration_ms, Ordering::SeqCst);
    }
}

impl ModuleContract for K8sHandler {
    fn manifest(&self) -> ModuleManifest {
        ModuleManifest::builder("kubernetes")
            .description("Kubernetes integration for ingress, service discovery, and secrets")
            .version(1, 0, 0)
            .capability(Capability::Custom("ServiceDiscovery".to_string()))
            .capability(Capability::Custom("IngressController".to_string()))
            .capability(Capability::Custom("SecretManagement".to_string()))
            .capability(Capability::Custom("ConfigMapIntegration".to_string()))
            .dependency(Dependency::optional("tls-terminator"))
            .dependency(Dependency::optional("load_balancer"))
            .build()
    }

    fn init(&mut self, config: ModuleConfig) -> ModuleResult<()> {
        // Parse configuration
        if let Some(ns) = config.get_string("namespace") {
            self.config = self.config.clone().with_namespace(ns);
            self.service_discovery = ServiceDiscovery::for_namespace(ns);
            self.ingress_controller = IngressController::new().with_namespace(ns);
            self.secret_manager = SecretManager::for_namespace(ns);
        }

        if let Some(enabled) = config.get_bool("leader_election") {
            self.config = self.config.clone().with_leader_election(enabled);
        }

        if let Some(class) = config.get_string("ingress_class") {
            self.ingress_controller = IngressController::for_class(class);
        }

        // Validate configuration
        self.config.validate().map_err(|e| {
            ModuleError::ConfigError(format!("Invalid Kubernetes configuration: {}", e))
        })?;

        self.initialized = true;
        Ok(())
    }

    fn start(&mut self) -> ModuleResult<()> {
        if !self.initialized {
            return Err(ModuleError::InvalidState {
                current: "uninitialized".to_string(),
                expected: "initialized".to_string(),
            });
        }

        self.running.store(true, Ordering::SeqCst);
        self.start_time = Some(Instant::now());

        // If leader election is enabled and we're not the leader,
        // start in standby mode
        if self.config.leader_election {
            self.set_leader(false);
        } else {
            self.set_leader(true);
        }

        Ok(())
    }

    fn stop(&mut self) -> ModuleResult<()> {
        self.running.store(false, Ordering::SeqCst);
        self.set_leader(false);
        Ok(())
    }

    fn status(&self) -> ModuleStatus {
        if !self.initialized {
            ModuleStatus::Stopped
        } else if self.is_running() {
            ModuleStatus::Running
        } else {
            ModuleStatus::Stopped
        }
    }

    fn metrics(&self) -> MetricsPayload {
        // Update metrics from current state
        self.update_metrics();

        let mut payload = MetricsPayload::new();

        // Service discovery metrics
        payload.gauge(
            "k8s_services_discovered",
            self.metrics.services_discovered.load(Ordering::SeqCst) as f64,
        );
        payload.gauge(
            "k8s_endpoints_discovered",
            self.metrics.endpoints_discovered.load(Ordering::SeqCst) as f64,
        );
        payload.gauge(
            "k8s_ready_endpoints",
            self.service_discovery.ready_endpoint_count() as f64,
        );

        // Ingress metrics
        payload.gauge(
            "k8s_ingresses_managed",
            self.metrics.ingresses_managed.load(Ordering::SeqCst) as f64,
        );
        payload.gauge(
            "k8s_routes_generated",
            self.metrics.routes_generated.load(Ordering::SeqCst) as f64,
        );

        // Secret metrics
        payload.gauge(
            "k8s_secrets_cached",
            self.metrics.secrets_cached.load(Ordering::SeqCst) as f64,
        );
        payload.gauge(
            "k8s_config_maps_cached",
            self.metrics.config_maps_cached.load(Ordering::SeqCst) as f64,
        );

        // Watch metrics
        payload.counter(
            "k8s_watch_events_total",
            self.metrics.watch_events.load(Ordering::SeqCst),
        );
        payload.counter(
            "k8s_watch_errors_total",
            self.metrics.watch_errors.load(Ordering::SeqCst),
        );

        // API metrics
        payload.counter(
            "k8s_api_requests_total",
            self.metrics.api_requests.load(Ordering::SeqCst),
        );
        payload.counter(
            "k8s_api_errors_total",
            self.metrics.api_errors.load(Ordering::SeqCst),
        );

        // Sync metrics
        payload.gauge(
            "k8s_sync_duration_ms",
            self.metrics.sync_duration_ms.load(Ordering::SeqCst) as f64,
        );

        // Leader election
        payload.gauge(
            "k8s_is_leader",
            self.metrics.is_leader.load(Ordering::SeqCst) as f64,
        );

        // Uptime
        payload.gauge("k8s_uptime_seconds", self.uptime_secs() as f64);

        payload
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_handler_new() {
        let handler = K8sHandler::new();
        assert!(!handler.initialized);
        assert!(!handler.is_running());
    }

    #[test]
    fn test_handler_with_config() {
        let config = K8sConfig::new()
            .with_namespace("production")
            .with_leader_election(true);

        let handler = K8sHandler::with_config(config);
        assert_eq!(handler.config().effective_namespace(), "production");
        assert!(handler.config().leader_election);
    }

    #[test]
    fn test_handler_in_cluster() {
        let handler = K8sHandler::in_cluster();
        assert!(handler.config().auth.is_in_cluster());
    }

    #[test]
    fn test_handler_manifest() {
        let handler = K8sHandler::new();
        let manifest = handler.manifest();

        assert_eq!(manifest.name, "kubernetes");
        assert!(!manifest.capabilities.is_empty());
    }

    #[test]
    fn test_handler_lifecycle() {
        let mut handler = K8sHandler::new();

        // Should fail to start before init
        assert!(handler.start().is_err());

        // Initialize
        let config = ModuleConfig::new();
        assert!(handler.init(config).is_ok());
        assert!(handler.initialized);
        assert_eq!(handler.status(), ModuleStatus::Stopped);

        // Start
        assert!(handler.start().is_ok());
        assert!(handler.is_running());
        assert_eq!(handler.status(), ModuleStatus::Running);

        // Stop
        assert!(handler.stop().is_ok());
        assert!(!handler.is_running());
        assert_eq!(handler.status(), ModuleStatus::Stopped);
    }

    #[test]
    fn test_handler_init_with_namespace() {
        let mut handler = K8sHandler::new();

        let mut config = ModuleConfig::new();
        config.set_string("namespace", "kube-system");

        assert!(handler.init(config).is_ok());
        assert_eq!(handler.config().effective_namespace(), "kube-system");
    }

    #[test]
    fn test_handler_init_with_ingress_class() {
        let mut handler = K8sHandler::new();

        let mut config = ModuleConfig::new();
        config.set_string("ingress_class", "r0n");

        assert!(handler.init(config).is_ok());
    }

    #[test]
    fn test_handler_metrics() {
        let handler = K8sHandler::new();

        // Record some events
        handler.on_watch_event();
        handler.on_watch_event();
        handler.on_api_request();
        handler.on_api_error();
        handler.set_leader(true);
        handler.record_sync_duration(150);

        let metrics = handler.metrics();

        // Should have metrics
        assert!(!metrics.counters.is_empty() || !metrics.gauges.is_empty());
    }

    #[test]
    fn test_handler_accessors() {
        let mut handler = K8sHandler::new();

        // Test immutable accessors
        let _sd = handler.service_discovery();
        let _ic = handler.ingress_controller();
        let _sm = handler.secret_manager();
        let _cfg = handler.config();

        // Test mutable accessors
        let _sd_mut = handler.service_discovery_mut();
        let _ic_mut = handler.ingress_controller_mut();
        let _sm_mut = handler.secret_manager_mut();
    }

    #[test]
    fn test_handler_uptime() {
        let mut handler = K8sHandler::new();

        assert_eq!(handler.uptime_secs(), 0);

        handler.init(ModuleConfig::new()).unwrap();
        handler.start().unwrap();

        // Should have some uptime now (might be 0 if very fast)
        let uptime = handler.uptime_secs();
        assert!(uptime <= 1);
    }

    #[test]
    fn test_handler_leader_election() {
        let config = K8sConfig::new().with_leader_election(true);
        let mut handler = K8sHandler::with_config(config);

        handler.init(ModuleConfig::new()).unwrap();
        handler.start().unwrap();

        // Should start as non-leader when leader election is enabled
        assert_eq!(handler.metrics.is_leader.load(Ordering::SeqCst), 0);

        // Promote to leader
        handler.set_leader(true);
        assert_eq!(handler.metrics.is_leader.load(Ordering::SeqCst), 1);

        // Demote
        handler.set_leader(false);
        assert_eq!(handler.metrics.is_leader.load(Ordering::SeqCst), 0);
    }

    #[test]
    fn test_handler_default() {
        let handler = K8sHandler::default();
        assert!(!handler.initialized);
    }
}
