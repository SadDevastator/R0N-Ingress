//! Distributed rate limiting backends.

use super::config::{DistributedBackend, DistributedConfig, RedisConfig};
use super::error::RateLimitResult;
use std::collections::HashMap;
use std::sync::{Arc, RwLock};
use std::time::{Duration, Instant};

/// Trait for distributed state backends.
pub trait DistributedState: Send + Sync {
    /// Get the current token count for a key.
    fn get_tokens(&self, key: &str) -> RateLimitResult<Option<f64>>;

    /// Set the token count for a key with TTL.
    fn set_tokens(&self, key: &str, tokens: f64, ttl: Duration) -> RateLimitResult<()>;

    /// Atomically consume tokens if available.
    /// Returns the new token count if successful, None if not enough tokens.
    fn consume_tokens(
        &self,
        key: &str,
        tokens: u64,
        max_tokens: u64,
        refill_rate: f64,
        ttl: Duration,
    ) -> RateLimitResult<Option<f64>>;

    /// Increment a counter.
    fn increment(&self, key: &str, ttl: Duration) -> RateLimitResult<u64>;

    /// Get a counter value.
    fn get_count(&self, key: &str) -> RateLimitResult<u64>;

    /// Delete a key.
    fn delete(&self, key: &str) -> RateLimitResult<()>;

    /// Check if the backend is healthy.
    fn is_healthy(&self) -> bool;
}

/// Local in-memory state (for single-instance deployments).
#[derive(Debug)]
pub struct LocalState {
    /// Token counts.
    tokens: RwLock<HashMap<String, TokenEntry>>,

    /// Counters.
    counters: RwLock<HashMap<String, CounterEntry>>,
}

#[derive(Debug, Clone)]
struct TokenEntry {
    tokens: f64,
    last_update: Instant,
    refill_rate: f64,
    max_tokens: u64,
    expires_at: Instant,
}

#[derive(Debug, Clone)]
struct CounterEntry {
    count: u64,
    expires_at: Instant,
}

impl LocalState {
    /// Create a new local state store.
    #[must_use]
    pub fn new() -> Self {
        Self {
            tokens: RwLock::new(HashMap::new()),
            counters: RwLock::new(HashMap::new()),
        }
    }

    /// Clean up expired entries.
    pub fn cleanup_expired(&self) {
        let now = Instant::now();

        {
            let mut tokens = self.tokens.write().unwrap();
            tokens.retain(|_, entry| entry.expires_at > now);
        }

        {
            let mut counters = self.counters.write().unwrap();
            counters.retain(|_, entry| entry.expires_at > now);
        }
    }

    /// Get the number of entries.
    #[must_use]
    pub fn entry_count(&self) -> usize {
        self.tokens.read().unwrap().len() + self.counters.read().unwrap().len()
    }
}

impl Default for LocalState {
    fn default() -> Self {
        Self::new()
    }
}

impl DistributedState for LocalState {
    fn get_tokens(&self, key: &str) -> RateLimitResult<Option<f64>> {
        let tokens = self.tokens.read().unwrap();

        if let Some(entry) = tokens.get(key) {
            if entry.expires_at > Instant::now() {
                // Calculate current tokens with refill
                let elapsed = entry.last_update.elapsed().as_secs_f64();
                let refilled = entry.tokens + (elapsed * entry.refill_rate);
                let current = refilled.min(entry.max_tokens as f64);
                return Ok(Some(current));
            }
        }

        Ok(None)
    }

    fn set_tokens(&self, key: &str, tokens: f64, ttl: Duration) -> RateLimitResult<()> {
        let mut store = self.tokens.write().unwrap();

        let entry = store.entry(key.to_string()).or_insert(TokenEntry {
            tokens,
            last_update: Instant::now(),
            refill_rate: 1.0,
            max_tokens: 100,
            expires_at: Instant::now() + ttl,
        });

        entry.tokens = tokens;
        entry.last_update = Instant::now();
        entry.expires_at = Instant::now() + ttl;

        Ok(())
    }

    fn consume_tokens(
        &self,
        key: &str,
        tokens: u64,
        max_tokens: u64,
        refill_rate: f64,
        ttl: Duration,
    ) -> RateLimitResult<Option<f64>> {
        let mut store = self.tokens.write().unwrap();
        let now = Instant::now();

        let entry = store.entry(key.to_string()).or_insert(TokenEntry {
            tokens: max_tokens as f64,
            last_update: now,
            refill_rate,
            max_tokens,
            expires_at: now + ttl,
        });

        // Check if expired and reset
        if entry.expires_at <= now {
            entry.tokens = max_tokens as f64;
            entry.last_update = now;
            entry.expires_at = now + ttl;
        }

        // Calculate current tokens with refill
        let elapsed = entry.last_update.elapsed().as_secs_f64();
        let refilled = entry.tokens + (elapsed * refill_rate);
        let current = refilled.min(max_tokens as f64);

        if current >= tokens as f64 {
            entry.tokens = current - tokens as f64;
            entry.last_update = now;
            entry.expires_at = now + ttl;
            Ok(Some(entry.tokens))
        } else {
            // Update with refilled tokens even on failure
            entry.tokens = current;
            entry.last_update = now;
            Ok(None)
        }
    }

    fn increment(&self, key: &str, ttl: Duration) -> RateLimitResult<u64> {
        let mut counters = self.counters.write().unwrap();
        let now = Instant::now();

        let entry = counters.entry(key.to_string()).or_insert(CounterEntry {
            count: 0,
            expires_at: now + ttl,
        });

        // Reset if expired
        if entry.expires_at <= now {
            entry.count = 0;
            entry.expires_at = now + ttl;
        }

        entry.count += 1;
        Ok(entry.count)
    }

    fn get_count(&self, key: &str) -> RateLimitResult<u64> {
        let counters = self.counters.read().unwrap();

        if let Some(entry) = counters.get(key) {
            if entry.expires_at > Instant::now() {
                return Ok(entry.count);
            }
        }

        Ok(0)
    }

    fn delete(&self, key: &str) -> RateLimitResult<()> {
        self.tokens.write().unwrap().remove(key);
        self.counters.write().unwrap().remove(key);
        Ok(())
    }

    fn is_healthy(&self) -> bool {
        true
    }
}

/// Redis-based distributed state.
///
/// Note: This is a placeholder implementation. In production, you would
/// use a Redis client like `redis-rs` or `deadpool-redis`.
#[derive(Debug)]
pub struct RedisState {
    /// Redis configuration.
    #[allow(dead_code)]
    config: RedisConfig,

    /// Key prefix.
    key_prefix: String,

    /// Whether connected.
    connected: RwLock<bool>,

    /// Fallback local state.
    fallback: LocalState,
}

impl RedisState {
    /// Create a new Redis state backend.
    #[must_use]
    pub fn new(config: RedisConfig, key_prefix: String) -> Self {
        Self {
            config,
            key_prefix,
            connected: RwLock::new(false),
            fallback: LocalState::new(),
        }
    }

    /// Connect to Redis.
    pub fn connect(&self) -> RateLimitResult<()> {
        // In a real implementation, this would establish a Redis connection
        // For now, we just mark as connected
        *self.connected.write().unwrap() = true;
        Ok(())
    }

    /// Disconnect from Redis.
    pub fn disconnect(&self) {
        *self.connected.write().unwrap() = false;
    }

    /// Get the full key with prefix.
    fn full_key(&self, key: &str) -> String {
        format!("{}:{}", self.key_prefix, key)
    }

    /// Check if connected to Redis.
    fn is_connected(&self) -> bool {
        *self.connected.read().unwrap()
    }
}

impl DistributedState for RedisState {
    fn get_tokens(&self, key: &str) -> RateLimitResult<Option<f64>> {
        if !self.is_connected() {
            return self.fallback.get_tokens(key);
        }

        // In a real implementation, this would:
        // GET {prefix}:{key}
        // Parse as float

        // For now, use fallback
        self.fallback.get_tokens(&self.full_key(key))
    }

    fn set_tokens(&self, key: &str, tokens: f64, ttl: Duration) -> RateLimitResult<()> {
        if !self.is_connected() {
            return self.fallback.set_tokens(key, tokens, ttl);
        }

        // In a real implementation, this would:
        // SET {prefix}:{key} {tokens} EX {ttl_secs}

        self.fallback.set_tokens(&self.full_key(key), tokens, ttl)
    }

    fn consume_tokens(
        &self,
        key: &str,
        tokens: u64,
        max_tokens: u64,
        refill_rate: f64,
        ttl: Duration,
    ) -> RateLimitResult<Option<f64>> {
        if !self.is_connected() {
            return self
                .fallback
                .consume_tokens(key, tokens, max_tokens, refill_rate, ttl);
        }

        // In a real implementation, this would use a Lua script for atomicity:
        // ```lua
        // local key = KEYS[1]
        // local tokens_to_consume = tonumber(ARGV[1])
        // local max_tokens = tonumber(ARGV[2])
        // local refill_rate = tonumber(ARGV[3])
        // local now = tonumber(ARGV[4])
        // local ttl = tonumber(ARGV[5])
        //
        // local data = redis.call('HMGET', key, 'tokens', 'last_update')
        // local tokens = tonumber(data[1]) or max_tokens
        // local last_update = tonumber(data[2]) or now
        //
        // local elapsed = now - last_update
        // tokens = math.min(tokens + elapsed * refill_rate, max_tokens)
        //
        // if tokens >= tokens_to_consume then
        //     tokens = tokens - tokens_to_consume
        //     redis.call('HMSET', key, 'tokens', tokens, 'last_update', now)
        //     redis.call('EXPIRE', key, ttl)
        //     return tokens
        // else
        //     redis.call('HMSET', key, 'tokens', tokens, 'last_update', now)
        //     redis.call('EXPIRE', key, ttl)
        //     return nil
        // end
        // ```

        self.fallback
            .consume_tokens(&self.full_key(key), tokens, max_tokens, refill_rate, ttl)
    }

    fn increment(&self, key: &str, ttl: Duration) -> RateLimitResult<u64> {
        if !self.is_connected() {
            return self.fallback.increment(key, ttl);
        }

        // In a real implementation:
        // INCR {prefix}:{key}
        // EXPIRE {prefix}:{key} {ttl_secs}

        self.fallback.increment(&self.full_key(key), ttl)
    }

    fn get_count(&self, key: &str) -> RateLimitResult<u64> {
        if !self.is_connected() {
            return self.fallback.get_count(key);
        }

        // GET {prefix}:{key}
        self.fallback.get_count(&self.full_key(key))
    }

    fn delete(&self, key: &str) -> RateLimitResult<()> {
        if !self.is_connected() {
            return self.fallback.delete(key);
        }

        // DEL {prefix}:{key}
        self.fallback.delete(&self.full_key(key))
    }

    fn is_healthy(&self) -> bool {
        self.is_connected()
    }
}

/// Create a distributed state backend from configuration.
#[must_use]
pub fn create_backend(config: &DistributedConfig) -> Arc<dyn DistributedState> {
    match config.backend {
        DistributedBackend::Local => Arc::new(LocalState::new()),
        DistributedBackend::Redis => {
            let redis_config = config.redis.clone().unwrap_or_default();
            let state = RedisState::new(redis_config, config.key_prefix.clone());
            // Attempt connection (non-blocking in real impl)
            let _ = state.connect();
            Arc::new(state)
        },
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_local_state_tokens() {
        let state = LocalState::new();

        // Initially no tokens
        assert!(state.get_tokens("test").unwrap().is_none());

        // Set tokens
        state
            .set_tokens("test", 100.0, Duration::from_secs(60))
            .unwrap();

        // Get tokens
        let tokens = state.get_tokens("test").unwrap();
        assert!(tokens.is_some());
        assert!((tokens.unwrap() - 100.0).abs() < 1.0);
    }

    #[test]
    fn test_local_state_consume() {
        let state = LocalState::new();

        // Consume from non-existent key creates it
        let result = state
            .consume_tokens("test", 10, 100, 1.0, Duration::from_secs(60))
            .unwrap();
        assert!(result.is_some());
        assert!((result.unwrap() - 90.0).abs() < 0.1);

        // Consume more
        let result = state
            .consume_tokens("test", 50, 100, 1.0, Duration::from_secs(60))
            .unwrap();
        assert!(result.is_some());
        assert!((result.unwrap() - 40.0).abs() < 0.5);

        // Try to consume more than available
        let result = state
            .consume_tokens("test", 100, 100, 1.0, Duration::from_secs(60))
            .unwrap();
        assert!(result.is_none());
    }

    #[test]
    fn test_local_state_counter() {
        let state = LocalState::new();

        // Initial count is 0
        assert_eq!(state.get_count("counter").unwrap(), 0);

        // Increment
        assert_eq!(
            state.increment("counter", Duration::from_secs(60)).unwrap(),
            1
        );
        assert_eq!(
            state.increment("counter", Duration::from_secs(60)).unwrap(),
            2
        );
        assert_eq!(
            state.increment("counter", Duration::from_secs(60)).unwrap(),
            3
        );

        // Get count
        assert_eq!(state.get_count("counter").unwrap(), 3);
    }

    #[test]
    fn test_local_state_delete() {
        let state = LocalState::new();

        state
            .set_tokens("test", 100.0, Duration::from_secs(60))
            .unwrap();
        state.increment("counter", Duration::from_secs(60)).unwrap();

        assert!(state.get_tokens("test").unwrap().is_some());
        assert_eq!(state.get_count("counter").unwrap(), 1);

        state.delete("test").unwrap();
        state.delete("counter").unwrap();

        assert!(state.get_tokens("test").unwrap().is_none());
        assert_eq!(state.get_count("counter").unwrap(), 0);
    }

    #[test]
    fn test_local_state_cleanup() {
        let state = LocalState::new();

        // Add entries with very short TTL
        state
            .set_tokens("test", 100.0, Duration::from_millis(1))
            .unwrap();

        assert_eq!(state.entry_count(), 1);

        // Wait for expiry
        std::thread::sleep(Duration::from_millis(5));

        // Cleanup
        state.cleanup_expired();

        assert_eq!(state.entry_count(), 0);
    }

    #[test]
    fn test_redis_state_fallback() {
        let state = RedisState::new(RedisConfig::default(), "test".to_string());

        // Not connected, should use fallback
        assert!(!state.is_connected());

        // Operations should work via fallback
        state
            .set_tokens("key", 100.0, Duration::from_secs(60))
            .unwrap();
        let result = state
            .consume_tokens("key", 10, 100, 1.0, Duration::from_secs(60))
            .unwrap();
        assert!(result.is_some());
    }

    #[test]
    fn test_create_backend_local() {
        let config = DistributedConfig {
            backend: DistributedBackend::Local,
            ..Default::default()
        };

        let backend = create_backend(&config);
        assert!(backend.is_healthy());
    }

    #[test]
    fn test_local_state_is_healthy() {
        let state = LocalState::new();
        assert!(state.is_healthy());
    }
}
