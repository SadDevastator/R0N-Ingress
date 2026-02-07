//! Load balancer module implementing `ModuleContract`.

use super::backend::{Backend, BackendPool};
use super::config::{LoadBalancerConfig, PoolConfig, StrategyType};
use super::error::{LoadBalancerError, LoadBalancerResult};
use super::health::HealthCheck;
use super::strategy::{
    HashStrategy, LeastConnectionsStrategy, RandomStrategy, RoundRobinStrategy, Strategy,
    WeightedRoundRobinStrategy,
};
use crate::module::{
    Capability, MetricsPayload, ModuleConfig, ModuleContract, ModuleError, ModuleManifest,
    ModuleResult, ModuleStatus,
};
use std::collections::HashMap;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use tracing::{debug, info, warn};

/// Load balancer statistics.
#[derive(Debug, Default)]
pub struct LoadBalancerStats {
    /// Total selections made.
    pub total_selections: AtomicU64,
    /// Successful selections.
    pub successful_selections: AtomicU64,
    /// Failed selections (no healthy backend).
    pub failed_selections: AtomicU64,
    /// Total connections made.
    pub total_connections: AtomicU64,
}

impl LoadBalancerStats {
    /// Record a successful selection.
    pub fn record_selection(&self, success: bool) {
        self.total_selections.fetch_add(1, Ordering::Relaxed);
        if success {
            self.successful_selections.fetch_add(1, Ordering::Relaxed);
        } else {
            self.failed_selections.fetch_add(1, Ordering::Relaxed);
        }
    }

    /// Record a connection.
    pub fn record_connection(&self) {
        self.total_connections.fetch_add(1, Ordering::Relaxed);
    }
}

/// Strategy container for different load balancing algorithms.
pub enum StrategyContainer {
    /// Round-robin distribution.
    RoundRobin(RoundRobinStrategy),
    /// Weighted round-robin.
    WeightedRoundRobin(WeightedRoundRobinStrategy),
    /// Least connections.
    LeastConnections(LeastConnectionsStrategy),
    /// IP/Header hash for sticky sessions.
    Hash(HashStrategy),
    /// Random selection.
    Random(RandomStrategy),
}

impl StrategyContainer {
    /// Get the strategy as a trait object.
    pub fn as_strategy(&self) -> &dyn Strategy {
        match self {
            Self::RoundRobin(s) => s,
            Self::WeightedRoundRobin(s) => s,
            Self::LeastConnections(s) => s,
            Self::Hash(s) => s,
            Self::Random(s) => s,
        }
    }

    /// Get strategy name.
    pub fn name(&self) -> &'static str {
        self.as_strategy().name()
    }
}

/// Load balancer module.
pub struct LoadBalancer {
    /// Module configuration.
    config: LoadBalancerConfig,
    /// Backend pools.
    pools: HashMap<String, Arc<BackendPool>>,
    /// Strategies per pool.
    strategies: HashMap<String, StrategyContainer>,
    /// Statistics.
    stats: Arc<LoadBalancerStats>,
    /// Current status.
    status: ModuleStatus,
    /// Health checkers per pool.
    #[allow(dead_code)]
    health_checkers: HashMap<String, HealthCheck>,
}

impl std::fmt::Debug for LoadBalancer {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("LoadBalancer")
            .field("stats", &self.stats)
            .field("status", &self.status)
            .field("pools", &self.pools.keys().collect::<Vec<_>>())
            .finish()
    }
}

impl LoadBalancer {
    /// Create a new load balancer.
    #[must_use]
    pub fn new() -> Self {
        Self {
            config: LoadBalancerConfig::default(),
            pools: HashMap::new(),
            strategies: HashMap::new(),
            stats: Arc::new(LoadBalancerStats::default()),
            status: ModuleStatus::Stopped,
            health_checkers: HashMap::new(),
        }
    }

    /// Create a new load balancer with configuration.
    #[must_use]
    pub fn with_config(config: LoadBalancerConfig) -> Self {
        Self {
            config,
            pools: HashMap::new(),
            strategies: HashMap::new(),
            stats: Arc::new(LoadBalancerStats::default()),
            status: ModuleStatus::Stopped,
            health_checkers: HashMap::new(),
        }
    }

    /// Get load balancer statistics.
    #[must_use]
    pub fn stats(&self) -> &Arc<LoadBalancerStats> {
        &self.stats
    }

    /// Create a pool from configuration.
    fn create_pool(&self, pool_config: &PoolConfig) -> LoadBalancerResult<Arc<BackendPool>> {
        let pool = BackendPool::new(&pool_config.name);

        for backend_config in &pool_config.backends {
            let backend = Backend::new(backend_config);
            pool.add_backend(backend);
        }

        Ok(Arc::new(pool))
    }

    /// Create a strategy for a pool.
    fn create_strategy(strategy_type: StrategyType, pool_config: &PoolConfig) -> StrategyContainer {
        let sticky_ttl = pool_config
            .sticky
            .as_ref()
            .map(|s| s.ttl.as_secs())
            .unwrap_or(3600);

        match strategy_type {
            StrategyType::RoundRobin => StrategyContainer::RoundRobin(RoundRobinStrategy::new()),
            StrategyType::WeightedRoundRobin => {
                StrategyContainer::WeightedRoundRobin(WeightedRoundRobinStrategy::new())
            },
            StrategyType::LeastConnections => {
                StrategyContainer::LeastConnections(LeastConnectionsStrategy::new())
            },
            StrategyType::IpHash | StrategyType::HeaderHash => {
                StrategyContainer::Hash(HashStrategy::ip_hash(sticky_ttl))
            },
            StrategyType::Random => StrategyContainer::Random(RandomStrategy::new()),
        }
    }

    /// Get a pool by name.
    #[must_use]
    pub fn get_pool(&self, name: &str) -> Option<&Arc<BackendPool>> {
        self.pools.get(name)
    }

    /// Select a backend from a pool asynchronously.
    pub async fn select_backend(
        &self,
        pool_name: &str,
        context: &super::strategy::SelectionContext,
    ) -> LoadBalancerResult<Arc<Backend>> {
        let pool = self
            .pools
            .get(pool_name)
            .ok_or_else(|| LoadBalancerError::PoolNotFound(pool_name.to_string()))?;

        let strategy = self
            .strategies
            .get(pool_name)
            .ok_or_else(|| LoadBalancerError::PoolNotFound(pool_name.to_string()))?;

        let backends = pool.healthy_backends();

        if backends.is_empty() {
            self.stats.record_selection(false);
            return Err(LoadBalancerError::NoHealthyBackends(pool_name.to_string()));
        }

        match strategy.as_strategy().select(&backends, context).await {
            Ok(backend) => {
                self.stats.record_selection(true);
                Ok(Arc::clone(backend))
            },
            Err(e) => {
                self.stats.record_selection(false);
                Err(e)
            },
        }
    }

    /// Add a new pool.
    pub fn add_pool(&mut self, pool_config: PoolConfig) -> LoadBalancerResult<()> {
        if self.pools.contains_key(&pool_config.name) {
            return Err(LoadBalancerError::PoolAlreadyExists(
                pool_config.name.clone(),
            ));
        }

        let strategy_type = pool_config.strategy.unwrap_or(self.config.default_strategy);
        let pool = self.create_pool(&pool_config)?;
        let strategy = Self::create_strategy(strategy_type, &pool_config);

        self.pools.insert(pool_config.name.clone(), pool);
        self.strategies.insert(pool_config.name, strategy);

        Ok(())
    }

    /// Remove a pool.
    pub fn remove_pool(&mut self, name: &str) -> LoadBalancerResult<()> {
        if self.pools.remove(name).is_none() {
            return Err(LoadBalancerError::PoolNotFound(name.to_string()));
        }

        self.strategies.remove(name);
        self.health_checkers.remove(name);
        Ok(())
    }

    /// List all pool names.
    #[must_use]
    pub fn list_pools(&self) -> Vec<&String> {
        self.pools.keys().collect()
    }
}

impl Default for LoadBalancer {
    fn default() -> Self {
        Self::new()
    }
}

impl ModuleContract for LoadBalancer {
    fn manifest(&self) -> ModuleManifest {
        ModuleManifest::builder("load_balancer")
            .description("Load balancer with multiple strategies and health checks")
            .version(1, 0, 0)
            .author("R0N Team")
            .capability(Capability::LoadBalancing)
            .capability(Capability::Custom("health-checks".to_string()))
            .capability(Capability::Custom("sticky-sessions".to_string()))
            .build()
    }

    fn init(&mut self, config: ModuleConfig) -> ModuleResult<()> {
        info!("Initializing load balancer module");
        self.status = ModuleStatus::Initializing;

        // Parse configuration
        let lb_config: LoadBalancerConfig = if let Some(raw) = config.get_string("config") {
            toml::from_str(raw)
                .map_err(|e| ModuleError::ConfigError(format!("failed to parse config: {e}")))?
        } else {
            LoadBalancerConfig::default()
        };

        // Validate configuration
        if lb_config.pools.is_empty() {
            warn!("No pools configured");
        }

        // Create pools
        for pool_config in &lb_config.pools {
            if pool_config.backends.is_empty() {
                return Err(ModuleError::ConfigError(format!(
                    "pool '{}' has no backends",
                    pool_config.name
                )));
            }

            let strategy_type = pool_config.strategy.unwrap_or(lb_config.default_strategy);
            let pool = self
                .create_pool(pool_config)
                .map_err(|e| ModuleError::ConfigError(e.to_string()))?;
            let strategy = Self::create_strategy(strategy_type, pool_config);

            debug!(
                pool = %pool_config.name,
                backends = pool_config.backends.len(),
                strategy = ?strategy_type,
                "Created pool"
            );

            self.pools.insert(pool_config.name.clone(), pool);
            self.strategies.insert(pool_config.name.clone(), strategy);

            // Create health checker for this pool
            let health_config = pool_config
                .health_check
                .clone()
                .unwrap_or_else(|| lb_config.health_check.clone());
            self.health_checkers
                .insert(pool_config.name.clone(), HealthCheck::new(health_config));
        }

        self.config = lb_config;

        info!("Load balancer initialized");
        Ok(())
    }

    fn start(&mut self) -> ModuleResult<()> {
        if self.status == ModuleStatus::Running {
            return Err(ModuleError::InvalidState {
                current: "running".to_string(),
                expected: "stopped or initializing".to_string(),
            });
        }

        info!("Starting load balancer");

        // In a real implementation, we would spawn health check tasks here
        // For now, we just transition to running state

        self.status = ModuleStatus::Running;

        info!("Load balancer started");
        Ok(())
    }

    fn stop(&mut self) -> ModuleResult<()> {
        if self.status != ModuleStatus::Running {
            return Err(ModuleError::InvalidState {
                current: format!("{:?}", self.status),
                expected: "running".to_string(),
            });
        }

        info!("Stopping load balancer");

        // In a real implementation, we would stop health check tasks here

        self.status = ModuleStatus::Stopped;

        info!("Load balancer stopped");
        Ok(())
    }

    fn reload(&mut self, config: ModuleConfig) -> ModuleResult<()> {
        info!("Reloading load balancer configuration");

        // Clear existing pools
        self.pools.clear();
        self.strategies.clear();
        self.health_checkers.clear();

        // Re-init with new config
        self.init(config)?;

        // If was running, stay running
        if self.status == ModuleStatus::Stopped {
            self.status = ModuleStatus::Running;
        }

        info!("Load balancer reloaded");
        Ok(())
    }

    fn status(&self) -> ModuleStatus {
        self.status.clone()
    }

    fn metrics(&self) -> MetricsPayload {
        let mut metrics = MetricsPayload::new();

        metrics.counter(
            "total_selections",
            self.stats.total_selections.load(Ordering::Relaxed),
        );
        metrics.counter(
            "successful_selections",
            self.stats.successful_selections.load(Ordering::Relaxed),
        );
        metrics.counter(
            "failed_selections",
            self.stats.failed_selections.load(Ordering::Relaxed),
        );
        metrics.counter(
            "total_connections",
            self.stats.total_connections.load(Ordering::Relaxed),
        );
        metrics.gauge("pool_count", self.pools.len() as f64);

        metrics
    }

    fn heartbeat(&self) -> bool {
        self.status == ModuleStatus::Running || self.status == ModuleStatus::Initializing
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::modules::load_balancer::config::BackendConfig;
    use std::net::{IpAddr, Ipv4Addr};

    fn test_pool_config() -> PoolConfig {
        PoolConfig {
            name: "test".to_string(),
            backends: vec![
                BackendConfig {
                    address: IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)),
                    port: 8080,
                    weight: 1,
                    max_connections: None,
                    enabled: true,
                },
                BackendConfig {
                    address: IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2)),
                    port: 8080,
                    weight: 1,
                    max_connections: None,
                    enabled: true,
                },
            ],
            strategy: Some(StrategyType::RoundRobin),
            health_check: None,
            sticky: None,
        }
    }

    #[test]
    fn test_balancer_creation() {
        let lb = LoadBalancer::new();
        assert_eq!(lb.stats.total_selections.load(Ordering::Relaxed), 0);
        assert_eq!(lb.status, ModuleStatus::Stopped);
    }

    #[test]
    fn test_stats_recording() {
        let stats = LoadBalancerStats::default();

        stats.record_selection(true);
        assert_eq!(stats.total_selections.load(Ordering::Relaxed), 1);
        assert_eq!(stats.successful_selections.load(Ordering::Relaxed), 1);
        assert_eq!(stats.failed_selections.load(Ordering::Relaxed), 0);

        stats.record_selection(false);
        assert_eq!(stats.total_selections.load(Ordering::Relaxed), 2);
        assert_eq!(stats.failed_selections.load(Ordering::Relaxed), 1);
    }

    #[test]
    fn test_balancer_manifest() {
        let lb = LoadBalancer::new();
        let manifest = lb.manifest();

        assert_eq!(manifest.name, "load_balancer");
        assert!(manifest.has_capability(&Capability::LoadBalancing));
    }

    #[tokio::test]
    async fn test_balancer_add_pool() {
        let mut lb = LoadBalancer::new();
        let pool_config = test_pool_config();

        lb.add_pool(pool_config.clone()).unwrap();

        let pool = lb.get_pool("test");
        assert!(pool.is_some());
        assert_eq!(pool.unwrap().backend_count(), 2);

        // Adding same pool again should fail
        let result = lb.add_pool(pool_config);
        assert!(matches!(
            result,
            Err(LoadBalancerError::PoolAlreadyExists(_))
        ));
    }

    #[tokio::test]
    async fn test_balancer_remove_pool() {
        let mut lb = LoadBalancer::new();
        lb.add_pool(test_pool_config()).unwrap();

        lb.remove_pool("test").unwrap();
        assert!(lb.get_pool("test").is_none());

        // Removing non-existent pool should fail
        let result = lb.remove_pool("test");
        assert!(matches!(result, Err(LoadBalancerError::PoolNotFound(_))));
    }

    #[tokio::test]
    async fn test_balancer_select_backend() {
        let mut lb = LoadBalancer::new();
        lb.add_pool(test_pool_config()).unwrap();

        let ctx = super::super::strategy::SelectionContext::new();
        let backend = lb.select_backend("test", &ctx).await.unwrap();

        assert_eq!(backend.address().port(), 8080);
    }

    #[test]
    fn test_balancer_heartbeat() {
        let mut lb = LoadBalancer::new();
        assert!(!lb.heartbeat()); // Stopped

        lb.status = ModuleStatus::Running;
        assert!(lb.heartbeat());
    }

    #[tokio::test]
    async fn test_balancer_metrics() {
        let mut lb = LoadBalancer::new();
        lb.add_pool(test_pool_config()).unwrap();

        lb.stats.record_selection(true);
        lb.stats.record_connection();

        let metrics = lb.metrics();
        assert!(metrics.counters.get("total_selections").is_some());
        assert!(metrics.counters.get("total_connections").is_some());
    }

    #[test]
    fn test_balancer_init_no_pools() {
        let mut lb = LoadBalancer::new();
        let config = ModuleConfig::default();

        // Should succeed with warning (no pools)
        let result = lb.init(config);
        assert!(result.is_ok());
    }

    #[test]
    fn test_balancer_start_stop() {
        let mut lb = LoadBalancer::new();
        lb.status = ModuleStatus::Initializing;

        lb.start().unwrap();
        assert_eq!(lb.status(), ModuleStatus::Running);

        lb.stop().unwrap();
        assert_eq!(lb.status(), ModuleStatus::Stopped);
    }

    #[test]
    fn test_balancer_stop_not_running() {
        let mut lb = LoadBalancer::new();

        let result = lb.stop();
        assert!(result.is_err());
    }

    #[test]
    fn test_strategy_container() {
        let strategy = StrategyContainer::RoundRobin(RoundRobinStrategy::new());
        assert_eq!(strategy.name(), "round-robin");

        let strategy = StrategyContainer::LeastConnections(LeastConnectionsStrategy::new());
        assert_eq!(strategy.name(), "least-connections");
    }
}
