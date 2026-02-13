//! Load balancing strategies.

use super::backend::Backend;
use super::config::StickyHashKey;
use super::error::{LoadBalancerError, LoadBalancerResult};
use std::collections::HashMap;
use std::hash::{DefaultHasher, Hash, Hasher};
use std::net::SocketAddr;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;
use std::time::Instant;
use tokio::sync::RwLock;

/// Context for making load balancing decisions.
#[derive(Debug, Clone, Default)]
pub struct SelectionContext {
    /// Client IP address.
    pub client_ip: Option<SocketAddr>,
    /// Request headers (for header-based sticky).
    pub headers: HashMap<String, String>,
    /// Cookie values (for cookie-based sticky).
    pub cookies: HashMap<String, String>,
}

impl SelectionContext {
    /// Create a new selection context.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Set client IP.
    #[must_use]
    pub fn with_client_ip(mut self, ip: SocketAddr) -> Self {
        self.client_ip = Some(ip);
        self
    }

    /// Add a header.
    #[must_use]
    pub fn with_header(mut self, name: impl Into<String>, value: impl Into<String>) -> Self {
        self.headers.insert(name.into(), value.into());
        self
    }
}

/// Trait for load balancing strategies.
pub trait Strategy: Send + Sync {
    /// Select a backend from the available backends.
    fn select<'a>(
        &'a self,
        backends: &'a [Arc<Backend>],
        context: &'a SelectionContext,
    ) -> std::pin::Pin<
        Box<dyn std::future::Future<Output = LoadBalancerResult<&'a Arc<Backend>>> + Send + 'a>,
    >;

    /// Get the strategy name.
    fn name(&self) -> &'static str;
}

/// Round-robin load balancing strategy.
#[derive(Debug)]
pub struct RoundRobinStrategy {
    /// Current index.
    current: AtomicUsize,
}

impl RoundRobinStrategy {
    /// Create a new round-robin strategy.
    #[must_use]
    pub fn new() -> Self {
        Self {
            current: AtomicUsize::new(0),
        }
    }
}

impl Default for RoundRobinStrategy {
    fn default() -> Self {
        Self::new()
    }
}

impl Strategy for RoundRobinStrategy {
    fn select<'a>(
        &'a self,
        backends: &'a [Arc<Backend>],
        _context: &'a SelectionContext,
    ) -> std::pin::Pin<
        Box<dyn std::future::Future<Output = LoadBalancerResult<&'a Arc<Backend>>> + Send + 'a>,
    > {
        Box::pin(async move {
            if backends.is_empty() {
                return Err(LoadBalancerError::NoBackendsAvailable("pool".to_string()));
            }

            // Find healthy backends
            let mut healthy_indices = Vec::new();
            for (i, backend) in backends.iter().enumerate() {
                if backend.can_accept() {
                    healthy_indices.push(i);
                }
            }

            if healthy_indices.is_empty() {
                return Err(LoadBalancerError::NoHealthyBackends("pool".to_string()));
            }

            // Get next index within healthy backends
            let attempts = healthy_indices.len();
            for _ in 0..attempts {
                let idx = self.current.fetch_add(1, Ordering::Relaxed) % healthy_indices.len();
                let backend_idx = healthy_indices[idx];
                let backend = &backends[backend_idx];

                if backend.can_accept() {
                    return Ok(backend);
                }
            }

            Err(LoadBalancerError::NoHealthyBackends("pool".to_string()))
        })
    }

    fn name(&self) -> &'static str {
        "round-robin"
    }
}

/// Weighted round-robin load balancing strategy.
#[derive(Debug)]
pub struct WeightedRoundRobinStrategy {
    /// Current weight counter.
    current_weight: AtomicUsize,
}

impl WeightedRoundRobinStrategy {
    /// Create a new weighted round-robin strategy.
    #[must_use]
    pub fn new() -> Self {
        Self {
            current_weight: AtomicUsize::new(0),
        }
    }
}

impl Default for WeightedRoundRobinStrategy {
    fn default() -> Self {
        Self::new()
    }
}

impl Strategy for WeightedRoundRobinStrategy {
    fn select<'a>(
        &'a self,
        backends: &'a [Arc<Backend>],
        _context: &'a SelectionContext,
    ) -> std::pin::Pin<
        Box<dyn std::future::Future<Output = LoadBalancerResult<&'a Arc<Backend>>> + Send + 'a>,
    > {
        Box::pin(async move {
            if backends.is_empty() {
                return Err(LoadBalancerError::NoBackendsAvailable("pool".to_string()));
            }

            // Build weighted list
            let mut weighted: Vec<(usize, u32)> = Vec::new();
            let mut total_weight = 0u32;

            for (i, backend) in backends.iter().enumerate() {
                if backend.can_accept() {
                    weighted.push((i, backend.weight()));
                    total_weight += backend.weight();
                }
            }

            if weighted.is_empty() {
                return Err(LoadBalancerError::NoHealthyBackends("pool".to_string()));
            }

            // Select based on weight
            let counter = self.current_weight.fetch_add(1, Ordering::Relaxed) as u32 % total_weight;
            let mut accumulated = 0u32;

            for &(idx, weight) in &weighted {
                accumulated += weight;
                if counter < accumulated {
                    return Ok(&backends[idx]);
                }
            }

            // Fallback to first healthy
            Ok(&backends[weighted[0].0])
        })
    }

    fn name(&self) -> &'static str {
        "weighted-round-robin"
    }
}

/// Least connections load balancing strategy.
#[derive(Debug, Default)]
pub struct LeastConnectionsStrategy;

impl LeastConnectionsStrategy {
    /// Create a new least connections strategy.
    #[must_use]
    pub fn new() -> Self {
        Self
    }
}

impl Strategy for LeastConnectionsStrategy {
    fn select<'a>(
        &'a self,
        backends: &'a [Arc<Backend>],
        _context: &'a SelectionContext,
    ) -> std::pin::Pin<
        Box<dyn std::future::Future<Output = LoadBalancerResult<&'a Arc<Backend>>> + Send + 'a>,
    > {
        Box::pin(async move {
            if backends.is_empty() {
                return Err(LoadBalancerError::NoBackendsAvailable("pool".to_string()));
            }

            let mut best: Option<&Arc<Backend>> = None;
            let mut min_connections = u32::MAX;

            for backend in backends {
                if backend.can_accept() {
                    let connections = backend.stats().active_connection_count();

                    // Weighted: divide connections by weight for fair comparison
                    let weighted_connections = if backend.weight() > 0 {
                        connections / backend.weight()
                    } else {
                        connections
                    };

                    if weighted_connections < min_connections {
                        min_connections = weighted_connections;
                        best = Some(backend);
                    }
                }
            }

            best.ok_or_else(|| LoadBalancerError::NoHealthyBackends("pool".to_string()))
        })
    }

    fn name(&self) -> &'static str {
        "least-connections"
    }
}

/// Hash-based (sticky) load balancing strategy.
#[derive(Debug)]
pub struct HashStrategy {
    /// Hash key configuration.
    hash_key: StickyHashKey,
    /// Sticky session cache.
    sticky_cache: RwLock<HashMap<u64, (SocketAddr, Instant)>>,
    /// Cache TTL in seconds.
    ttl_secs: u64,
}

impl HashStrategy {
    /// Create a new hash strategy.
    #[must_use]
    pub fn new(hash_key: StickyHashKey, ttl_secs: u64) -> Self {
        Self {
            hash_key,
            sticky_cache: RwLock::new(HashMap::new()),
            ttl_secs,
        }
    }

    /// Create an IP hash strategy.
    #[must_use]
    pub fn ip_hash(ttl_secs: u64) -> Self {
        Self::new(StickyHashKey::ClientIp, ttl_secs)
    }

    /// Create a header hash strategy.
    #[must_use]
    pub fn header_hash(header_name: impl Into<String>, ttl_secs: u64) -> Self {
        Self::new(StickyHashKey::Header(header_name.into()), ttl_secs)
    }

    /// Compute hash from context.
    fn compute_hash(&self, context: &SelectionContext) -> Option<u64> {
        let mut hasher = DefaultHasher::new();

        match &self.hash_key {
            StickyHashKey::ClientIp => {
                if let Some(ip) = &context.client_ip {
                    ip.ip().hash(&mut hasher);
                    return Some(hasher.finish());
                }
            },
            StickyHashKey::Header(name) => {
                if let Some(value) = context.headers.get(name) {
                    value.hash(&mut hasher);
                    return Some(hasher.finish());
                }
            },
            StickyHashKey::Cookie(name) => {
                if let Some(value) = context.cookies.get(name) {
                    value.hash(&mut hasher);
                    return Some(hasher.finish());
                }
            },
        }

        None
    }

    /// Clean expired entries from cache.
    async fn clean_expired(&self) {
        let mut cache = self.sticky_cache.write().await;
        let now = Instant::now();

        cache.retain(|_, (_, created)| now.duration_since(*created).as_secs() < self.ttl_secs);
    }
}

impl Strategy for HashStrategy {
    fn select<'a>(
        &'a self,
        backends: &'a [Arc<Backend>],
        context: &'a SelectionContext,
    ) -> std::pin::Pin<
        Box<dyn std::future::Future<Output = LoadBalancerResult<&'a Arc<Backend>>> + Send + 'a>,
    > {
        Box::pin(async move {
            if backends.is_empty() {
                return Err(LoadBalancerError::NoBackendsAvailable("pool".to_string()));
            }

            // Clean expired entries periodically
            self.clean_expired().await;

            // Check if we have a cached sticky session
            if let Some(hash) = self.compute_hash(context) {
                let cache = self.sticky_cache.read().await;

                if let Some((addr, created)) = cache.get(&hash) {
                    // Check if still valid
                    if Instant::now().duration_since(*created).as_secs() < self.ttl_secs {
                        // Find the cached backend
                        for backend in backends {
                            if backend.address() == *addr && backend.can_accept() {
                                return Ok(backend);
                            }
                        }
                    }
                }
                drop(cache);

                // Select based on consistent hashing - collect healthy backends
                let mut healthy: Vec<&Arc<Backend>> = Vec::new();
                for backend in backends {
                    if backend.can_accept() {
                        healthy.push(backend);
                    }
                }

                if healthy.is_empty() {
                    return Err(LoadBalancerError::NoHealthyBackends("pool".to_string()));
                }

                let idx = (hash as usize) % healthy.len();
                let selected = healthy[idx];

                // Cache the selection
                let mut cache = self.sticky_cache.write().await;
                cache.insert(hash, (selected.address(), Instant::now()));

                return Ok(selected);
            }

            // No hash key available, fall back to first healthy
            for backend in backends {
                if backend.can_accept() {
                    return Ok(backend);
                }
            }

            Err(LoadBalancerError::NoHealthyBackends("pool".to_string()))
        })
    }

    fn name(&self) -> &'static str {
        "hash"
    }
}

/// Random load balancing strategy.
#[derive(Debug, Default)]
pub struct RandomStrategy;

impl RandomStrategy {
    /// Create a new random strategy.
    #[must_use]
    pub fn new() -> Self {
        Self
    }
}

impl Strategy for RandomStrategy {
    fn select<'a>(
        &'a self,
        backends: &'a [Arc<Backend>],
        _context: &'a SelectionContext,
    ) -> std::pin::Pin<
        Box<dyn std::future::Future<Output = LoadBalancerResult<&'a Arc<Backend>>> + Send + 'a>,
    > {
        Box::pin(async move {
            if backends.is_empty() {
                return Err(LoadBalancerError::NoBackendsAvailable("pool".to_string()));
            }

            // Collect healthy backends
            let mut healthy: Vec<&Arc<Backend>> = Vec::new();
            for backend in backends {
                if backend.can_accept() {
                    healthy.push(backend);
                }
            }

            if healthy.is_empty() {
                return Err(LoadBalancerError::NoHealthyBackends("pool".to_string()));
            }

            let idx = rand::RngExt::random_range(&mut rand::rng(), 0..healthy.len());
            Ok(healthy[idx])
        })
    }

    fn name(&self) -> &'static str {
        "random"
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::modules::load_balancer::config::BackendConfig;
    use std::net::{IpAddr, Ipv4Addr};

    fn make_backends(count: usize) -> Vec<Arc<Backend>> {
        (0..count)
            .map(|i| {
                Arc::new(Backend::new(&BackendConfig {
                    address: IpAddr::V4(Ipv4Addr::new(10, 0, 0, (i + 1) as u8)),
                    port: 8080,
                    weight: 1,
                    max_connections: None,
                    enabled: true,
                }))
            })
            .collect()
    }

    fn make_weighted_backends() -> Vec<Arc<Backend>> {
        vec![
            Arc::new(Backend::new(&BackendConfig {
                address: IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)),
                port: 8080,
                weight: 3,
                max_connections: None,
                enabled: true,
            })),
            Arc::new(Backend::new(&BackendConfig {
                address: IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2)),
                port: 8080,
                weight: 1,
                max_connections: None,
                enabled: true,
            })),
        ]
    }

    #[tokio::test]
    async fn test_round_robin_distributes() {
        let strategy = RoundRobinStrategy::new();
        let backends = make_backends(3);
        let ctx = SelectionContext::new();

        let mut counts = [0u32; 3];
        for _ in 0..30 {
            let backend = strategy.select(&backends, &ctx).await.unwrap();
            let ip = backend.address().ip();
            if let IpAddr::V4(v4) = ip {
                let idx = (v4.octets()[3] - 1) as usize;
                counts[idx] += 1;
            }
        }

        // Should be roughly even distribution
        for count in &counts {
            assert!(*count >= 8 && *count <= 12, "counts: {:?}", counts);
        }
    }

    #[tokio::test]
    async fn test_round_robin_no_backends() {
        let strategy = RoundRobinStrategy::new();
        let backends: Vec<Arc<Backend>> = vec![];
        let ctx = SelectionContext::new();

        let result = strategy.select(&backends, &ctx).await;
        assert!(matches!(
            result,
            Err(LoadBalancerError::NoBackendsAvailable(_))
        ));
    }

    #[tokio::test]
    async fn test_least_connections() {
        let strategy = LeastConnectionsStrategy::new();
        let backends = make_backends(3);
        let ctx = SelectionContext::new();

        // Record some connections
        backends[0].stats().record_connection();
        backends[0].stats().record_connection();
        backends[1].stats().record_connection();

        // Should select backend 2 (0 connections)
        let selected = strategy.select(&backends, &ctx).await.unwrap();
        assert_eq!(selected.address(), backends[2].address());
    }

    #[tokio::test]
    async fn test_weighted_round_robin() {
        let strategy = WeightedRoundRobinStrategy::new();
        let backends = make_weighted_backends();
        let ctx = SelectionContext::new();

        let mut counts = [0u32; 2];
        for _ in 0..40 {
            let backend = strategy.select(&backends, &ctx).await.unwrap();
            let ip = backend.address().ip();
            if let IpAddr::V4(v4) = ip {
                let idx = (v4.octets()[3] - 1) as usize;
                counts[idx] += 1;
            }
        }

        // Backend 1 has weight 3, backend 2 has weight 1
        // So backend 1 should get ~3x the traffic
        assert!(counts[0] > counts[1] * 2, "counts: {:?}", counts);
    }

    #[tokio::test]
    async fn test_hash_sticky_session() {
        let strategy = HashStrategy::ip_hash(3600);
        let backends = make_backends(3);

        let ctx = SelectionContext::new().with_client_ip("192.168.1.100:12345".parse().unwrap());

        // Multiple selections should return the same backend
        let first = strategy.select(&backends, &ctx).await.unwrap();
        let second = strategy.select(&backends, &ctx).await.unwrap();
        let third = strategy.select(&backends, &ctx).await.unwrap();

        assert_eq!(first.address(), second.address());
        assert_eq!(second.address(), third.address());
    }

    #[tokio::test]
    async fn test_random_selects() {
        let strategy = RandomStrategy::new();
        let backends = make_backends(3);
        let ctx = SelectionContext::new();

        // Just verify it can select without error
        for _ in 0..10 {
            let result = strategy.select(&backends, &ctx).await;
            assert!(result.is_ok());
        }
    }

    #[tokio::test]
    async fn test_strategy_names() {
        assert_eq!(RoundRobinStrategy::new().name(), "round-robin");
        assert_eq!(LeastConnectionsStrategy::new().name(), "least-connections");
        assert_eq!(
            WeightedRoundRobinStrategy::new().name(),
            "weighted-round-robin"
        );
        assert_eq!(HashStrategy::ip_hash(3600).name(), "hash");
        assert_eq!(RandomStrategy::new().name(), "random");
    }
}
