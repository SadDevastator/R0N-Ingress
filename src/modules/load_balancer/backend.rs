//! Backend pool management.

use super::config::BackendConfig;
use super::error::{LoadBalancerError, LoadBalancerResult};
use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::atomic::{AtomicU32, AtomicU64, Ordering};
use std::sync::{Arc, RwLock};
use std::time::Instant;

/// State of a backend server.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BackendState {
    /// Backend is healthy and accepting connections.
    Healthy,
    /// Backend is unhealthy and should not receive traffic.
    Unhealthy,
    /// Backend is in drain mode (no new connections).
    Draining,
    /// Backend is disabled by configuration.
    Disabled,
}

impl BackendState {
    /// Check if this backend can accept new connections.
    #[must_use]
    pub fn can_accept_connections(&self) -> bool {
        matches!(self, Self::Healthy)
    }
}

/// Statistics for a single backend.
#[derive(Debug, Default)]
pub struct BackendStats {
    /// Total connections made to this backend.
    pub total_connections: AtomicU64,
    /// Currently active connections.
    pub active_connections: AtomicU32,
    /// Successful requests/connections.
    pub successes: AtomicU64,
    /// Failed requests/connections.
    pub failures: AtomicU64,
    /// Bytes sent to this backend.
    pub bytes_sent: AtomicU64,
    /// Bytes received from this backend.
    pub bytes_received: AtomicU64,
}

impl BackendStats {
    /// Create new stats.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Record a new connection.
    pub fn record_connection(&self) {
        self.total_connections.fetch_add(1, Ordering::Relaxed);
        self.active_connections.fetch_add(1, Ordering::Relaxed);
    }

    /// Record connection close.
    pub fn record_connection_close(&self) {
        self.active_connections.fetch_sub(1, Ordering::Relaxed);
    }

    /// Record success.
    pub fn record_success(&self) {
        self.successes.fetch_add(1, Ordering::Relaxed);
    }

    /// Record failure.
    pub fn record_failure(&self) {
        self.failures.fetch_add(1, Ordering::Relaxed);
    }

    /// Record bytes transferred.
    pub fn record_bytes(&self, sent: u64, received: u64) {
        self.bytes_sent.fetch_add(sent, Ordering::Relaxed);
        self.bytes_received.fetch_add(received, Ordering::Relaxed);
    }

    /// Get current active connection count.
    #[must_use]
    pub fn active_connection_count(&self) -> u32 {
        self.active_connections.load(Ordering::Relaxed)
    }

    /// Get total connection count.
    #[must_use]
    pub fn total_connection_count(&self) -> u64 {
        self.total_connections.load(Ordering::Relaxed)
    }
}

/// A single backend server.
#[derive(Debug)]
pub struct Backend {
    /// Backend address.
    address: SocketAddr,
    /// Backend weight (for weighted strategies).
    weight: u32,
    /// Maximum connections allowed.
    max_connections: Option<u32>,
    /// Current state.
    state: RwLock<BackendState>,
    /// Statistics.
    stats: BackendStats,
    /// Last health check time.
    last_health_check: RwLock<Option<Instant>>,
    /// Consecutive health check failures.
    consecutive_failures: AtomicU32,
    /// Consecutive health check successes.
    consecutive_successes: AtomicU32,
}

impl Backend {
    /// Create a new backend from configuration.
    #[must_use]
    pub fn new(config: &BackendConfig) -> Self {
        let state = if config.enabled {
            BackendState::Healthy
        } else {
            BackendState::Disabled
        };

        Self {
            address: config.socket_addr(),
            weight: config.weight,
            max_connections: config.max_connections,
            state: RwLock::new(state),
            stats: BackendStats::new(),
            last_health_check: RwLock::new(None),
            consecutive_failures: AtomicU32::new(0),
            consecutive_successes: AtomicU32::new(0),
        }
    }

    /// Get the backend address.
    #[must_use]
    pub fn address(&self) -> SocketAddr {
        self.address
    }

    /// Get the backend weight.
    #[must_use]
    pub fn weight(&self) -> u32 {
        self.weight
    }

    /// Get the maximum connections.
    #[must_use]
    pub fn max_connections(&self) -> Option<u32> {
        self.max_connections
    }

    /// Get the current state.
    #[must_use]
    pub fn state(&self) -> BackendState {
        *self.state.read().expect("state lock poisoned")
    }

    /// Set the backend state.
    pub fn set_state(&self, state: BackendState) {
        *self.state.write().expect("state lock poisoned") = state;
    }

    /// Check if backend can accept a new connection.
    #[must_use]
    pub fn can_accept(&self) -> bool {
        let state = self.state();
        if !state.can_accept_connections() {
            return false;
        }

        // Check max connections limit
        if let Some(max) = self.max_connections {
            if self.stats.active_connection_count() >= max {
                return false;
            }
        }

        true
    }

    /// Get backend statistics.
    #[must_use]
    pub fn stats(&self) -> &BackendStats {
        &self.stats
    }

    /// Record a health check result.
    pub fn record_health_check(
        &self,
        success: bool,
        unhealthy_threshold: u32,
        healthy_threshold: u32,
    ) {
        *self
            .last_health_check
            .write()
            .expect("health check lock poisoned") = Some(Instant::now());

        if success {
            self.consecutive_failures.store(0, Ordering::Relaxed);
            let successes = self.consecutive_successes.fetch_add(1, Ordering::Relaxed) + 1;

            if successes >= healthy_threshold {
                let current_state = self.state();
                if current_state == BackendState::Unhealthy {
                    self.set_state(BackendState::Healthy);
                }
            }
        } else {
            self.consecutive_successes.store(0, Ordering::Relaxed);
            let failures = self.consecutive_failures.fetch_add(1, Ordering::Relaxed) + 1;

            if failures >= unhealthy_threshold {
                let current_state = self.state();
                if current_state == BackendState::Healthy {
                    self.set_state(BackendState::Unhealthy);
                }
            }
        }
    }

    /// Get consecutive failure count.
    #[must_use]
    pub fn consecutive_failure_count(&self) -> u32 {
        self.consecutive_failures.load(Ordering::Relaxed)
    }

    /// Get consecutive success count.
    #[must_use]
    pub fn consecutive_success_count(&self) -> u32 {
        self.consecutive_successes.load(Ordering::Relaxed)
    }
}

/// A pool of backend servers.
#[derive(Debug)]
pub struct BackendPool {
    /// Pool name.
    name: String,
    /// Backends in this pool.
    backends: RwLock<Vec<Arc<Backend>>>,
    /// Address to backend index mapping.
    address_map: RwLock<HashMap<SocketAddr, usize>>,
}

impl BackendPool {
    /// Create a new empty pool.
    #[must_use]
    pub fn new(name: impl Into<String>) -> Self {
        Self {
            name: name.into(),
            backends: RwLock::new(Vec::new()),
            address_map: RwLock::new(HashMap::new()),
        }
    }

    /// Get the pool name.
    #[must_use]
    pub fn name(&self) -> &str {
        &self.name
    }

    /// Add a backend to the pool.
    pub fn add_backend(&self, backend: Backend) {
        let mut backends = self.backends.write().expect("backends lock poisoned");
        let mut address_map = self.address_map.write().expect("address_map lock poisoned");

        let index = backends.len();
        let addr = backend.address();
        backends.push(Arc::new(backend));
        address_map.insert(addr, index);
    }

    /// Remove a backend from the pool.
    pub fn remove_backend(&self, address: SocketAddr) -> LoadBalancerResult<()> {
        let mut backends = self.backends.write().expect("backends lock poisoned");
        let mut address_map = self.address_map.write().expect("address_map lock poisoned");

        if let Some(&index) = address_map.get(&address) {
            backends.remove(index);
            address_map.remove(&address);

            // Rebuild index map
            address_map.clear();
            for (i, backend) in backends.iter().enumerate() {
                address_map.insert(backend.address(), i);
            }

            Ok(())
        } else {
            Err(LoadBalancerError::BackendNotFound(
                address,
                self.name.clone(),
            ))
        }
    }

    /// Get a backend by address.
    #[must_use]
    pub fn get_backend(&self, address: SocketAddr) -> Option<Arc<Backend>> {
        let backends = self.backends.read().expect("backends lock poisoned");
        let address_map = self.address_map.read().expect("address_map lock poisoned");

        address_map
            .get(&address)
            .and_then(|&i| backends.get(i).cloned())
    }

    /// Get all backends.
    #[must_use]
    pub fn all_backends(&self) -> Vec<Arc<Backend>> {
        self.backends
            .read()
            .expect("backends lock poisoned")
            .clone()
    }

    /// Get all healthy backends.
    #[must_use]
    pub fn healthy_backends(&self) -> Vec<Arc<Backend>> {
        let backends = self.backends.read().expect("backends lock poisoned");
        let mut healthy = Vec::new();

        for backend in backends.iter() {
            if backend.can_accept() {
                healthy.push(Arc::clone(backend));
            }
        }

        healthy
    }

    /// Get backend count.
    #[must_use]
    pub fn backend_count(&self) -> usize {
        self.backends.read().expect("backends lock poisoned").len()
    }

    /// Get healthy backend count.
    #[must_use]
    pub fn healthy_backend_count(&self) -> usize {
        self.healthy_backends().len()
    }

    /// Check if pool is empty.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.backends
            .read()
            .expect("backends lock poisoned")
            .is_empty()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::{IpAddr, Ipv4Addr};

    fn test_backend_config(port: u16) -> BackendConfig {
        BackendConfig {
            address: IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)),
            port,
            weight: 1,
            max_connections: None,
            enabled: true,
        }
    }

    #[test]
    fn test_backend_state_can_accept() {
        assert!(BackendState::Healthy.can_accept_connections());
        assert!(!BackendState::Unhealthy.can_accept_connections());
        assert!(!BackendState::Draining.can_accept_connections());
        assert!(!BackendState::Disabled.can_accept_connections());
    }

    #[test]
    fn test_backend_stats() {
        let stats = BackendStats::new();
        assert_eq!(stats.active_connection_count(), 0);

        stats.record_connection();
        assert_eq!(stats.active_connection_count(), 1);
        assert_eq!(stats.total_connection_count(), 1);

        stats.record_connection();
        assert_eq!(stats.active_connection_count(), 2);

        stats.record_connection_close();
        assert_eq!(stats.active_connection_count(), 1);
    }

    #[test]
    fn test_backend_creation() {
        let config = test_backend_config(8080);
        let backend = Backend::new(&config);

        assert_eq!(backend.address(), "10.0.0.1:8080".parse().unwrap());
        assert_eq!(backend.weight(), 1);
        assert_eq!(backend.state(), BackendState::Healthy);
    }

    #[test]
    fn test_backend_disabled() {
        let config = BackendConfig {
            address: IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)),
            port: 8080,
            weight: 1,
            max_connections: None,
            enabled: false,
        };
        let backend = Backend::new(&config);
        assert_eq!(backend.state(), BackendState::Disabled);
        assert!(!backend.can_accept());
    }

    #[test]
    fn test_backend_max_connections() {
        let config = BackendConfig {
            address: IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)),
            port: 8080,
            weight: 1,
            max_connections: Some(2),
            enabled: true,
        };
        let backend = Backend::new(&config);

        assert!(backend.can_accept());

        backend.stats().record_connection();
        assert!(backend.can_accept());

        backend.stats().record_connection();
        assert!(!backend.can_accept()); // At max

        backend.stats().record_connection_close();
        assert!(backend.can_accept());
    }

    #[test]
    fn test_backend_health_check_transitions() {
        let config = test_backend_config(8080);
        let backend = Backend::new(&config);

        // Mark as unhealthy after 3 failures
        for _ in 0..3 {
            backend.record_health_check(false, 3, 2);
        }
        assert_eq!(backend.state(), BackendState::Unhealthy);

        // Mark as healthy after 2 successes
        for _ in 0..2 {
            backend.record_health_check(true, 3, 2);
        }
        assert_eq!(backend.state(), BackendState::Healthy);
    }

    #[test]
    fn test_pool_operations() {
        let pool = BackendPool::new("test");
        assert!(pool.is_empty());

        pool.add_backend(Backend::new(&test_backend_config(8080)));
        pool.add_backend(Backend::new(&test_backend_config(8081)));

        assert_eq!(pool.backend_count(), 2);
        assert!(!pool.is_empty());

        let backend = pool.get_backend("10.0.0.1:8080".parse().unwrap());
        assert!(backend.is_some());

        pool.remove_backend("10.0.0.1:8080".parse().unwrap())
            .unwrap();
        assert_eq!(pool.backend_count(), 1);
    }

    #[test]
    fn test_pool_healthy_backends() {
        let pool = BackendPool::new("test");

        let config1 = test_backend_config(8080);
        let config2 = BackendConfig {
            enabled: false,
            ..test_backend_config(8081)
        };

        pool.add_backend(Backend::new(&config1));
        pool.add_backend(Backend::new(&config2));

        assert_eq!(pool.backend_count(), 2);
        assert_eq!(pool.healthy_backend_count(), 1);
    }
}
