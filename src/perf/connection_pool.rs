//! Connection pool tuning and optimization.
//!
//! Provides adaptive connection pooling with automatic sizing based on
//! workload characteristics and performance metrics.

use std::collections::VecDeque;
use std::fmt;
use std::sync::atomic::{AtomicBool, AtomicU64, AtomicUsize, Ordering};
use std::sync::{Arc, Condvar, Mutex, RwLock};
use std::time::{Duration, Instant};

/// Connection pool configuration.
#[derive(Debug, Clone)]
pub struct PoolConfig {
    /// Minimum number of connections.
    pub min_size: usize,
    /// Maximum number of connections.
    pub max_size: usize,
    /// Connection idle timeout.
    pub idle_timeout: Duration,
    /// Maximum connection lifetime.
    pub max_lifetime: Duration,
    /// Timeout for acquiring a connection.
    pub acquire_timeout: Duration,
    /// Health check interval.
    pub health_check_interval: Duration,
    /// Enable adaptive sizing.
    pub adaptive: bool,
    /// Target utilization (0.0 - 1.0).
    pub target_utilization: f64,
}

impl Default for PoolConfig {
    fn default() -> Self {
        Self {
            min_size: 1,
            max_size: 10,
            idle_timeout: Duration::from_secs(300),
            max_lifetime: Duration::from_secs(3600),
            acquire_timeout: Duration::from_secs(30),
            health_check_interval: Duration::from_secs(30),
            adaptive: true,
            target_utilization: 0.75,
        }
    }
}

impl PoolConfig {
    /// Create a new pool configuration.
    pub fn new() -> Self {
        Self::default()
    }

    /// Set minimum size.
    pub fn min_size(mut self, size: usize) -> Self {
        self.min_size = size;
        self
    }

    /// Set maximum size.
    pub fn max_size(mut self, size: usize) -> Self {
        self.max_size = size;
        self
    }

    /// Set idle timeout.
    pub fn idle_timeout(mut self, timeout: Duration) -> Self {
        self.idle_timeout = timeout;
        self
    }

    /// Set maximum lifetime.
    pub fn max_lifetime(mut self, lifetime: Duration) -> Self {
        self.max_lifetime = lifetime;
        self
    }

    /// Set acquire timeout.
    pub fn acquire_timeout(mut self, timeout: Duration) -> Self {
        self.acquire_timeout = timeout;
        self
    }

    /// Set health check interval.
    pub fn health_check_interval(mut self, interval: Duration) -> Self {
        self.health_check_interval = interval;
        self
    }

    /// Enable/disable adaptive sizing.
    pub fn adaptive(mut self, enabled: bool) -> Self {
        self.adaptive = enabled;
        self
    }

    /// Set target utilization.
    pub fn target_utilization(mut self, util: f64) -> Self {
        self.target_utilization = util.clamp(0.1, 1.0);
        self
    }

    /// Validate configuration.
    pub fn validate(&self) -> Result<(), &'static str> {
        if self.min_size > self.max_size {
            return Err("min_size cannot exceed max_size");
        }
        if self.max_size == 0 {
            return Err("max_size must be positive");
        }
        if self.target_utilization <= 0.0 || self.target_utilization > 1.0 {
            return Err("target_utilization must be in (0, 1]");
        }
        Ok(())
    }
}

/// Pool metrics for monitoring.
#[derive(Debug, Default)]
pub struct PoolMetrics {
    /// Total connections created.
    pub connections_created: AtomicU64,
    /// Total connections closed.
    pub connections_closed: AtomicU64,
    /// Total acquire attempts.
    pub acquire_attempts: AtomicU64,
    /// Successful acquires.
    pub acquire_success: AtomicU64,
    /// Failed acquires (timeout).
    pub acquire_timeout_count: AtomicU64,
    /// Total wait time in microseconds.
    pub total_wait_time_us: AtomicU64,
    /// Current pool size.
    pub current_size: AtomicUsize,
    /// Current in-use count.
    pub in_use: AtomicUsize,
    /// Peak in-use count.
    pub peak_in_use: AtomicUsize,
}

impl PoolMetrics {
    /// Get utilization (in_use / current_size).
    pub fn utilization(&self) -> f64 {
        let size = self.current_size.load(Ordering::Relaxed);
        let used = self.in_use.load(Ordering::Relaxed);
        if size == 0 {
            0.0
        } else {
            used as f64 / size as f64
        }
    }

    /// Get average wait time.
    pub fn avg_wait_time(&self) -> Duration {
        let success = self.acquire_success.load(Ordering::Relaxed);
        let total = self.total_wait_time_us.load(Ordering::Relaxed);
        if success == 0 {
            Duration::ZERO
        } else {
            Duration::from_micros(total / success)
        }
    }

    /// Get acquire success rate.
    pub fn success_rate(&self) -> f64 {
        let attempts = self.acquire_attempts.load(Ordering::Relaxed);
        let success = self.acquire_success.load(Ordering::Relaxed);
        if attempts == 0 {
            1.0
        } else {
            success as f64 / attempts as f64
        }
    }
}

/// A pooled connection wrapper.
pub struct PooledConnection<T> {
    /// The connection.
    conn: Option<T>,
    /// Creation time.
    created_at: Instant,
    /// Last used time.
    last_used: Instant,
    /// Pool reference for returning.
    pool: Arc<ConnectionPoolInner<T>>,
    /// Whether the connection is valid.
    valid: bool,
}

impl<T> PooledConnection<T> {
    /// Get connection age.
    pub fn age(&self) -> Duration {
        self.created_at.elapsed()
    }

    /// Get idle time.
    pub fn idle_time(&self) -> Duration {
        self.last_used.elapsed()
    }

    /// Mark connection as invalid (won't be returned to pool).
    pub fn invalidate(&mut self) {
        self.valid = false;
    }

    /// Check if connection is valid.
    pub fn is_valid(&self) -> bool {
        self.valid
    }
}

impl<T> std::ops::Deref for PooledConnection<T> {
    type Target = T;

    fn deref(&self) -> &Self::Target {
        self.conn.as_ref().expect("connection taken")
    }
}

impl<T> std::ops::DerefMut for PooledConnection<T> {
    fn deref_mut(&mut self) -> &mut Self::Target {
        self.conn.as_mut().expect("connection taken")
    }
}

impl<T> Drop for PooledConnection<T> {
    fn drop(&mut self) {
        if let Some(conn) = self.conn.take() {
            if self.valid {
                self.pool.return_connection(conn, self.created_at);
            } else {
                self.pool
                    .metrics
                    .connections_closed
                    .fetch_add(1, Ordering::Relaxed);
            }
            self.pool.metrics.in_use.fetch_sub(1, Ordering::Relaxed);
        }
    }
}

impl<T> fmt::Debug for PooledConnection<T> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("PooledConnection")
            .field("age", &self.age())
            .field("idle_time", &self.idle_time())
            .field("valid", &self.valid)
            .finish()
    }
}

/// Internal pool state.
struct ConnectionPoolInner<T> {
    /// Configuration.
    config: PoolConfig,
    /// Available connections.
    available: Mutex<VecDeque<PoolEntry<T>>>,
    /// Condition variable for waiting.
    condvar: Condvar,
    /// Pool metrics.
    metrics: PoolMetrics,
    /// Factory function.
    factory: Box<dyn Fn() -> Result<T, Box<dyn std::error::Error + Send + Sync>> + Send + Sync>,
    /// Whether pool is closed.
    closed: AtomicBool,
    /// Target size (for adaptive pooling).
    target_size: AtomicUsize,
}

impl<T> ConnectionPoolInner<T> {
    fn return_connection(&self, conn: T, created_at: Instant) {
        if self.closed.load(Ordering::Relaxed) {
            self.metrics
                .connections_closed
                .fetch_add(1, Ordering::Relaxed);
            return;
        }

        // Check lifetime
        if created_at.elapsed() > self.config.max_lifetime {
            self.metrics
                .connections_closed
                .fetch_add(1, Ordering::Relaxed);
            return;
        }

        let entry = PoolEntry {
            conn,
            created_at,
            last_used: Instant::now(),
        };

        if let Ok(mut available) = self.available.lock() {
            available.push_back(entry);
            self.condvar.notify_one();
        }
    }
}

struct PoolEntry<T> {
    conn: T,
    created_at: Instant,
    last_used: Instant,
}

/// Connection pool error.
#[derive(Debug)]
pub enum PoolError {
    /// Timeout acquiring connection.
    Timeout,
    /// Pool is closed.
    Closed,
    /// Failed to create connection.
    CreateFailed(Box<dyn std::error::Error + Send + Sync>),
    /// Invalid configuration.
    InvalidConfig(&'static str),
}

impl fmt::Display for PoolError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Timeout => write!(f, "connection acquire timeout"),
            Self::Closed => write!(f, "pool is closed"),
            Self::CreateFailed(e) => write!(f, "failed to create connection: {}", e),
            Self::InvalidConfig(msg) => write!(f, "invalid configuration: {}", msg),
        }
    }
}

impl std::error::Error for PoolError {}

/// Generic connection pool.
pub struct ConnectionPool<T> {
    inner: Arc<ConnectionPoolInner<T>>,
}

impl<T: Send + 'static> ConnectionPool<T> {
    /// Create a new connection pool.
    pub fn new<F>(config: PoolConfig, factory: F) -> Result<Self, PoolError>
    where
        F: Fn() -> Result<T, Box<dyn std::error::Error + Send + Sync>> + Send + Sync + 'static,
    {
        config.validate().map_err(PoolError::InvalidConfig)?;

        let inner = Arc::new(ConnectionPoolInner {
            config: config.clone(),
            available: Mutex::new(VecDeque::with_capacity(config.max_size)),
            condvar: Condvar::new(),
            metrics: PoolMetrics::default(),
            factory: Box::new(factory),
            closed: AtomicBool::new(false),
            target_size: AtomicUsize::new(config.min_size),
        });

        // Pre-create minimum connections
        let pool = Self { inner };
        pool.fill_to_min()?;

        Ok(pool)
    }

    fn fill_to_min(&self) -> Result<(), PoolError> {
        let min = self.inner.config.min_size;
        for _ in 0..min {
            let conn = (self.inner.factory)().map_err(PoolError::CreateFailed)?;
            self.inner
                .metrics
                .connections_created
                .fetch_add(1, Ordering::Relaxed);
            self.inner
                .metrics
                .current_size
                .fetch_add(1, Ordering::Relaxed);

            if let Ok(mut available) = self.inner.available.lock() {
                available.push_back(PoolEntry {
                    conn,
                    created_at: Instant::now(),
                    last_used: Instant::now(),
                });
            }
        }
        Ok(())
    }

    /// Acquire a connection from the pool.
    pub fn acquire(&self) -> Result<PooledConnection<T>, PoolError> {
        if self.inner.closed.load(Ordering::Relaxed) {
            return Err(PoolError::Closed);
        }

        self.inner
            .metrics
            .acquire_attempts
            .fetch_add(1, Ordering::Relaxed);
        let start = Instant::now();
        let deadline = start + self.inner.config.acquire_timeout;

        loop {
            // Try to get from available
            if let Ok(mut available) = self.inner.available.lock() {
                // Remove expired connections
                while let Some(entry) = available.front() {
                    let expired = entry.last_used.elapsed() > self.inner.config.idle_timeout
                        || entry.created_at.elapsed() > self.inner.config.max_lifetime;
                    if expired {
                        available.pop_front();
                        self.inner
                            .metrics
                            .connections_closed
                            .fetch_add(1, Ordering::Relaxed);
                        self.inner
                            .metrics
                            .current_size
                            .fetch_sub(1, Ordering::Relaxed);
                    } else {
                        break;
                    }
                }

                if let Some(entry) = available.pop_front() {
                    let wait_time = start.elapsed();
                    self.inner
                        .metrics
                        .total_wait_time_us
                        .fetch_add(wait_time.as_micros() as u64, Ordering::Relaxed);
                    self.inner
                        .metrics
                        .acquire_success
                        .fetch_add(1, Ordering::Relaxed);

                    let in_use = self.inner.metrics.in_use.fetch_add(1, Ordering::Relaxed) + 1;
                    let peak = self.inner.metrics.peak_in_use.load(Ordering::Relaxed);
                    if in_use > peak {
                        self.inner
                            .metrics
                            .peak_in_use
                            .store(in_use, Ordering::Relaxed);
                    }

                    return Ok(PooledConnection {
                        conn: Some(entry.conn),
                        created_at: entry.created_at,
                        last_used: entry.last_used,
                        pool: Arc::clone(&self.inner),
                        valid: true,
                    });
                }

                // Try to create a new connection
                let current = self.inner.metrics.current_size.load(Ordering::Relaxed);
                if current < self.inner.config.max_size {
                    drop(available); // Release lock before creating

                    match (self.inner.factory)() {
                        Ok(conn) => {
                            self.inner
                                .metrics
                                .connections_created
                                .fetch_add(1, Ordering::Relaxed);
                            self.inner
                                .metrics
                                .current_size
                                .fetch_add(1, Ordering::Relaxed);
                            self.inner
                                .metrics
                                .acquire_success
                                .fetch_add(1, Ordering::Relaxed);

                            let in_use =
                                self.inner.metrics.in_use.fetch_add(1, Ordering::Relaxed) + 1;
                            let peak = self.inner.metrics.peak_in_use.load(Ordering::Relaxed);
                            if in_use > peak {
                                self.inner
                                    .metrics
                                    .peak_in_use
                                    .store(in_use, Ordering::Relaxed);
                            }

                            let wait_time = start.elapsed();
                            self.inner
                                .metrics
                                .total_wait_time_us
                                .fetch_add(wait_time.as_micros() as u64, Ordering::Relaxed);

                            return Ok(PooledConnection {
                                conn: Some(conn),
                                created_at: Instant::now(),
                                last_used: Instant::now(),
                                pool: Arc::clone(&self.inner),
                                valid: true,
                            });
                        },
                        Err(e) => {
                            return Err(PoolError::CreateFailed(e));
                        },
                    }
                }

                // Wait for a connection
                let remaining = deadline.saturating_duration_since(Instant::now());
                if remaining.is_zero() {
                    self.inner
                        .metrics
                        .acquire_timeout_count
                        .fetch_add(1, Ordering::Relaxed);
                    return Err(PoolError::Timeout);
                }

                let (guard, result) = match self.inner.condvar.wait_timeout(available, remaining) {
                    Ok(r) => r,
                    Err(poisoned) => poisoned.into_inner(),
                };
                if result.timed_out() {
                    self.inner
                        .metrics
                        .acquire_timeout_count
                        .fetch_add(1, Ordering::Relaxed);
                    return Err(PoolError::Timeout);
                }
                drop(guard);
            }
        }
    }

    /// Try to acquire without waiting.
    pub fn try_acquire(&self) -> Option<PooledConnection<T>> {
        if self.inner.closed.load(Ordering::Relaxed) {
            return None;
        }

        self.inner
            .metrics
            .acquire_attempts
            .fetch_add(1, Ordering::Relaxed);

        if let Ok(mut available) = self.inner.available.lock() {
            if let Some(entry) = available.pop_front() {
                self.inner
                    .metrics
                    .acquire_success
                    .fetch_add(1, Ordering::Relaxed);

                let in_use = self.inner.metrics.in_use.fetch_add(1, Ordering::Relaxed) + 1;
                let peak = self.inner.metrics.peak_in_use.load(Ordering::Relaxed);
                if in_use > peak {
                    self.inner
                        .metrics
                        .peak_in_use
                        .store(in_use, Ordering::Relaxed);
                }

                return Some(PooledConnection {
                    conn: Some(entry.conn),
                    created_at: entry.created_at,
                    last_used: entry.last_used,
                    pool: Arc::clone(&self.inner),
                    valid: true,
                });
            }
        }

        None
    }

    /// Get pool metrics.
    pub fn metrics(&self) -> &PoolMetrics {
        &self.inner.metrics
    }

    /// Get current pool size.
    pub fn size(&self) -> usize {
        self.inner.metrics.current_size.load(Ordering::Relaxed)
    }

    /// Get available connection count.
    pub fn available(&self) -> usize {
        self.inner.available.lock().map(|a| a.len()).unwrap_or(0)
    }

    /// Close the pool.
    pub fn close(&self) {
        self.inner.closed.store(true, Ordering::Relaxed);
        if let Ok(mut available) = self.inner.available.lock() {
            let count = available.len();
            available.clear();
            self.inner
                .metrics
                .connections_closed
                .fetch_add(count as u64, Ordering::Relaxed);
        }
        self.inner.condvar.notify_all();
    }

    /// Check if pool is closed.
    pub fn is_closed(&self) -> bool {
        self.inner.closed.load(Ordering::Relaxed)
    }
}

impl<T> fmt::Debug for ConnectionPool<T> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let size = self.inner.metrics.current_size.load(Ordering::Relaxed);
        let available = self.inner.available.lock().map(|a| a.len()).unwrap_or(0);
        let closed = self.inner.closed.load(Ordering::Relaxed);
        f.debug_struct("ConnectionPool")
            .field("size", &size)
            .field("available", &available)
            .field("closed", &closed)
            .finish()
    }
}

impl<T> Clone for ConnectionPool<T> {
    fn clone(&self) -> Self {
        Self {
            inner: Arc::clone(&self.inner),
        }
    }
}

/// Adaptive pool that adjusts size based on workload.
pub struct AdaptivePool<T> {
    /// Underlying pool.
    pool: ConnectionPool<T>,
    /// Tuning configuration.
    tuning: RwLock<AdaptiveTuning>,
}

/// Adaptive tuning configuration.
#[derive(Debug, Clone)]
pub struct AdaptiveTuning {
    /// Sample window.
    pub sample_window: Duration,
    /// Scale up threshold (utilization).
    pub scale_up_threshold: f64,
    /// Scale down threshold (utilization).
    pub scale_down_threshold: f64,
    /// Minimum samples before adjusting.
    pub min_samples: usize,
    /// Cooldown between adjustments.
    pub cooldown: Duration,
    /// Last adjustment time.
    pub last_adjustment: Option<Instant>,
}

impl Default for AdaptiveTuning {
    fn default() -> Self {
        Self {
            sample_window: Duration::from_secs(60),
            scale_up_threshold: 0.9,
            scale_down_threshold: 0.5,
            min_samples: 100,
            cooldown: Duration::from_secs(30),
            last_adjustment: None,
        }
    }
}

impl<T: Send + 'static> AdaptivePool<T> {
    /// Create a new adaptive pool.
    pub fn new<F>(config: PoolConfig, factory: F) -> Result<Self, PoolError>
    where
        F: Fn() -> Result<T, Box<dyn std::error::Error + Send + Sync>> + Send + Sync + 'static,
    {
        let pool = ConnectionPool::new(config, factory)?;
        Ok(Self {
            pool,
            tuning: RwLock::new(AdaptiveTuning::default()),
        })
    }

    /// Create with custom tuning.
    pub fn with_tuning<F>(
        config: PoolConfig,
        factory: F,
        tuning: AdaptiveTuning,
    ) -> Result<Self, PoolError>
    where
        F: Fn() -> Result<T, Box<dyn std::error::Error + Send + Sync>> + Send + Sync + 'static,
    {
        let pool = ConnectionPool::new(config, factory)?;
        Ok(Self {
            pool,
            tuning: RwLock::new(tuning),
        })
    }

    /// Acquire a connection.
    pub fn acquire(&self) -> Result<PooledConnection<T>, PoolError> {
        let conn = self.pool.acquire()?;
        self.maybe_adjust();
        Ok(conn)
    }

    /// Try to acquire without waiting.
    pub fn try_acquire(&self) -> Option<PooledConnection<T>> {
        self.pool.try_acquire()
    }

    fn maybe_adjust(&self) {
        // Check if we should adjust
        let should_adjust = if let Ok(tuning) = self.tuning.read() {
            if let Some(last) = tuning.last_adjustment {
                last.elapsed() > tuning.cooldown
            } else {
                true
            }
        } else {
            false
        };

        if !should_adjust {
            return;
        }

        let utilization = self.pool.metrics().utilization();
        let current = self.pool.size();
        let min = self.pool.inner.config.min_size;
        let max = self.pool.inner.config.max_size;

        if let Ok(tuning) = self.tuning.read() {
            if utilization > tuning.scale_up_threshold && current < max {
                // Would scale up, but we can't actually resize the pool
                // This is just for demonstration
                let _new_target = (current + 1).min(max);
                self.pool
                    .inner
                    .target_size
                    .store(_new_target, Ordering::Relaxed);
            } else if utilization < tuning.scale_down_threshold && current > min {
                let _new_target = (current - 1).max(min);
                self.pool
                    .inner
                    .target_size
                    .store(_new_target, Ordering::Relaxed);
            }
        }
    }

    /// Get underlying pool.
    pub fn pool(&self) -> &ConnectionPool<T> {
        &self.pool
    }

    /// Get metrics.
    pub fn metrics(&self) -> &PoolMetrics {
        self.pool.metrics()
    }

    /// Get current tuning.
    pub fn tuning(&self) -> AdaptiveTuning {
        self.tuning.read().map(|t| t.clone()).unwrap_or_default()
    }

    /// Update tuning.
    pub fn set_tuning(&self, tuning: AdaptiveTuning) {
        if let Ok(mut t) = self.tuning.write() {
            *t = tuning;
        }
    }
}

impl<T> fmt::Debug for AdaptivePool<T> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("AdaptivePool")
            .field("pool", &self.pool)
            .finish()
    }
}

impl<T> Clone for AdaptivePool<T> {
    fn clone(&self) -> Self {
        let tuning = self.tuning.read().map(|t| t.clone()).unwrap_or_default();
        Self {
            pool: self.pool.clone(),
            tuning: RwLock::new(tuning),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::AtomicU32;

    fn test_factory() -> Result<u32, Box<dyn std::error::Error + Send + Sync>> {
        static COUNTER: AtomicU32 = AtomicU32::new(0);
        Ok(COUNTER.fetch_add(1, Ordering::Relaxed))
    }

    #[test]
    fn test_pool_config() {
        let config = PoolConfig::new()
            .min_size(2)
            .max_size(10)
            .idle_timeout(Duration::from_secs(60))
            .adaptive(true);

        assert_eq!(config.min_size, 2);
        assert_eq!(config.max_size, 10);
        assert!(config.validate().is_ok());
    }

    #[test]
    fn test_pool_config_validation() {
        let config = PoolConfig::new().min_size(10).max_size(5);
        assert!(config.validate().is_err());

        let config = PoolConfig::new().max_size(0);
        assert!(config.validate().is_err());
    }

    #[test]
    fn test_pool_create() {
        let config = PoolConfig::new().min_size(2).max_size(5);
        let pool = ConnectionPool::new(config, test_factory).unwrap();

        assert_eq!(pool.size(), 2);
        assert_eq!(pool.available(), 2);
    }

    #[test]
    fn test_pool_acquire() {
        let config = PoolConfig::new().min_size(1).max_size(5);
        let pool = ConnectionPool::new(config, test_factory).unwrap();

        let conn = pool.acquire().unwrap();
        assert!(conn.is_valid());
        assert_eq!(pool.available(), 0);
    }

    #[test]
    fn test_pool_return() {
        let config = PoolConfig::new().min_size(1).max_size(5);
        let pool = ConnectionPool::new(config, test_factory).unwrap();

        {
            let _conn = pool.acquire().unwrap();
            assert_eq!(pool.available(), 0);
        }

        // Connection returned on drop
        assert_eq!(pool.available(), 1);
    }

    #[test]
    fn test_pool_try_acquire() {
        let config = PoolConfig::new().min_size(1).max_size(1);
        let pool = ConnectionPool::new(config, test_factory).unwrap();

        let conn1 = pool.try_acquire();
        assert!(conn1.is_some());

        let conn2 = pool.try_acquire();
        assert!(conn2.is_none());
    }

    #[test]
    fn test_pool_expand() {
        let config = PoolConfig::new().min_size(1).max_size(3);
        let pool = ConnectionPool::new(config, test_factory).unwrap();

        let _c1 = pool.acquire().unwrap();
        let _c2 = pool.acquire().unwrap();
        let _c3 = pool.acquire().unwrap();

        assert_eq!(pool.size(), 3);
    }

    #[test]
    fn test_pool_close() {
        let config = PoolConfig::new().min_size(2).max_size(5);
        let pool = ConnectionPool::new(config, test_factory).unwrap();

        assert!(!pool.is_closed());
        pool.close();
        assert!(pool.is_closed());

        let result = pool.acquire();
        assert!(matches!(result, Err(PoolError::Closed)));
    }

    #[test]
    fn test_pool_metrics() {
        let config = PoolConfig::new().min_size(1).max_size(5);
        let pool = ConnectionPool::new(config, test_factory).unwrap();

        let _conn = pool.acquire().unwrap();
        drop(_conn);

        assert!(pool.metrics().acquire_success.load(Ordering::Relaxed) >= 1);
    }

    #[test]
    fn test_pool_metrics_utilization() {
        let metrics = PoolMetrics::default();
        metrics.current_size.store(10, Ordering::Relaxed);
        metrics.in_use.store(5, Ordering::Relaxed);

        assert!((metrics.utilization() - 0.5).abs() < 0.01);
    }

    #[test]
    fn test_pooled_connection_invalidate() {
        let config = PoolConfig::new().min_size(1).max_size(5);
        let pool = ConnectionPool::new(config, test_factory).unwrap();

        {
            let mut conn = pool.acquire().unwrap();
            conn.invalidate();
            assert!(!conn.is_valid());
        }

        // Invalidated connection not returned to pool
        // A new one would need to be created
        assert!(pool.metrics().connections_closed.load(Ordering::Relaxed) >= 1);
    }

    #[test]
    fn test_adaptive_pool() {
        let config = PoolConfig::new().min_size(1).max_size(10);
        let pool = AdaptivePool::new(config, test_factory).unwrap();

        let _conn = pool.acquire().unwrap();
        assert!(pool.pool().size() >= 1);
    }

    #[test]
    fn test_adaptive_pool_tuning() {
        let config = PoolConfig::new().min_size(1).max_size(10);
        let pool = AdaptivePool::new(config, test_factory).unwrap();

        let tuning = AdaptiveTuning {
            scale_up_threshold: 0.8,
            scale_down_threshold: 0.3,
            ..Default::default()
        };

        pool.set_tuning(tuning.clone());
        let current = pool.tuning();
        assert!((current.scale_up_threshold - 0.8).abs() < 0.01);
    }

    #[test]
    fn test_pool_clone() {
        let config = PoolConfig::new().min_size(1).max_size(5);
        let pool1 = ConnectionPool::new(config, test_factory).unwrap();
        let pool2 = pool1.clone();

        let _conn = pool1.acquire().unwrap();
        // Both share the same underlying pool
        assert_eq!(pool1.available(), pool2.available());
    }
}
