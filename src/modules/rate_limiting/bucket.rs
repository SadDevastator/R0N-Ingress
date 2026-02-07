//! Token bucket implementation for rate limiting.

use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{Duration, Instant};

/// Configuration for a token bucket.
#[derive(Debug, Clone)]
pub struct TokenBucketConfig {
    /// Maximum tokens (burst capacity).
    pub max_tokens: u64,

    /// Token refill rate (tokens per second).
    pub refill_rate: f64,
}

impl Default for TokenBucketConfig {
    fn default() -> Self {
        Self {
            max_tokens: 100,
            refill_rate: 10.0,
        }
    }
}

impl TokenBucketConfig {
    /// Create a new token bucket configuration.
    #[must_use]
    pub fn new(max_tokens: u64, refill_rate: f64) -> Self {
        Self {
            max_tokens,
            refill_rate,
        }
    }
}

/// A thread-safe token bucket for rate limiting.
///
/// The token bucket algorithm allows bursts up to `max_tokens` while
/// limiting the long-term rate to `refill_rate` tokens per second.
#[derive(Debug)]
pub struct TokenBucket {
    /// Configuration.
    config: TokenBucketConfig,

    /// Current tokens (stored as fixed-point: actual * 1000).
    /// Using fixed-point for atomic operations on fractional values.
    tokens_millis: AtomicU64,

    /// Last refill timestamp (nanoseconds since creation).
    last_refill_nanos: AtomicU64,

    /// Creation instant for time calculations.
    created_at: Instant,
}

impl TokenBucket {
    /// Create a new token bucket.
    #[must_use]
    pub fn new(config: TokenBucketConfig) -> Self {
        let initial_tokens_millis = config.max_tokens * 1000;
        Self {
            config,
            tokens_millis: AtomicU64::new(initial_tokens_millis),
            last_refill_nanos: AtomicU64::new(0),
            created_at: Instant::now(),
        }
    }

    /// Create a token bucket with default configuration.
    #[must_use]
    pub fn with_defaults() -> Self {
        Self::new(TokenBucketConfig::default())
    }

    /// Create a token bucket with specific rate and burst.
    #[must_use]
    pub fn with_rate(max_tokens: u64, refill_rate: f64) -> Self {
        Self::new(TokenBucketConfig::new(max_tokens, refill_rate))
    }

    /// Try to consume tokens from the bucket.
    ///
    /// Returns `true` if tokens were consumed, `false` if not enough tokens.
    pub fn try_consume(&self, tokens: u64) -> bool {
        self.refill();

        let tokens_millis_needed = tokens * 1000;

        loop {
            let current = self.tokens_millis.load(Ordering::Acquire);

            if current < tokens_millis_needed {
                return false;
            }

            let new_value = current - tokens_millis_needed;

            match self.tokens_millis.compare_exchange_weak(
                current,
                new_value,
                Ordering::AcqRel,
                Ordering::Acquire,
            ) {
                Ok(_) => return true,
                Err(_) => continue, // Retry on contention
            }
        }
    }

    /// Consume tokens, blocking until available.
    ///
    /// Returns the time spent waiting.
    pub fn consume_blocking(&self, tokens: u64) -> Duration {
        let start = Instant::now();

        while !self.try_consume(tokens) {
            // Calculate wait time
            let wait_time = self.time_until_available(tokens);
            if wait_time > Duration::ZERO {
                std::thread::sleep(wait_time.min(Duration::from_millis(10)));
            }
        }

        start.elapsed()
    }

    /// Get current token count.
    #[must_use]
    pub fn available_tokens(&self) -> f64 {
        self.refill();
        self.tokens_millis.load(Ordering::Acquire) as f64 / 1000.0
    }

    /// Get the maximum tokens (burst capacity).
    #[must_use]
    pub fn max_tokens(&self) -> u64 {
        self.config.max_tokens
    }

    /// Get the refill rate (tokens per second).
    #[must_use]
    pub fn refill_rate(&self) -> f64 {
        self.config.refill_rate
    }

    /// Calculate time until the specified number of tokens is available.
    #[must_use]
    pub fn time_until_available(&self, tokens: u64) -> Duration {
        self.refill();

        let current_millis = self.tokens_millis.load(Ordering::Acquire);
        let current = current_millis as f64 / 1000.0;
        let needed = tokens as f64;

        if current >= needed {
            return Duration::ZERO;
        }

        let deficit = needed - current;
        let seconds = deficit / self.config.refill_rate;
        Duration::from_secs_f64(seconds)
    }

    /// Get the fill ratio (0.0 to 1.0).
    #[must_use]
    pub fn fill_ratio(&self) -> f64 {
        self.available_tokens() / self.config.max_tokens as f64
    }

    /// Reset the bucket to full capacity.
    pub fn reset(&self) {
        self.tokens_millis
            .store(self.config.max_tokens * 1000, Ordering::Release);
        self.last_refill_nanos.store(
            self.created_at.elapsed().as_nanos() as u64,
            Ordering::Release,
        );
    }

    /// Refill tokens based on elapsed time.
    fn refill(&self) {
        let now_nanos = self.created_at.elapsed().as_nanos() as u64;
        let last_nanos = self.last_refill_nanos.load(Ordering::Acquire);

        if now_nanos <= last_nanos {
            return;
        }

        // Calculate tokens to add
        let elapsed_secs = (now_nanos - last_nanos) as f64 / 1_000_000_000.0;
        let tokens_to_add = (elapsed_secs * self.config.refill_rate * 1000.0) as u64;

        if tokens_to_add == 0 {
            return;
        }

        // Try to update last refill time
        if self
            .last_refill_nanos
            .compare_exchange(last_nanos, now_nanos, Ordering::AcqRel, Ordering::Acquire)
            .is_err()
        {
            return; // Another thread is handling refill
        }

        // Add tokens up to max
        let max_millis = self.config.max_tokens * 1000;
        loop {
            let current = self.tokens_millis.load(Ordering::Acquire);
            let new_value = (current + tokens_to_add).min(max_millis);

            if current == new_value {
                break;
            }

            match self.tokens_millis.compare_exchange_weak(
                current,
                new_value,
                Ordering::AcqRel,
                Ordering::Acquire,
            ) {
                Ok(_) => break,
                Err(_) => continue,
            }
        }
    }
}

impl Clone for TokenBucket {
    fn clone(&self) -> Self {
        Self {
            config: self.config.clone(),
            tokens_millis: AtomicU64::new(self.tokens_millis.load(Ordering::Acquire)),
            last_refill_nanos: AtomicU64::new(self.last_refill_nanos.load(Ordering::Acquire)),
            created_at: self.created_at,
        }
    }
}

/// A sliding window counter for rate limiting.
///
/// Provides smoother rate limiting than fixed windows by tracking
/// requests across overlapping time windows.
#[derive(Debug)]
#[allow(dead_code)]
pub struct SlidingWindowCounter {
    /// Window size.
    window_size: Duration,

    /// Maximum requests per window.
    max_requests: u64,

    /// Current window count.
    current_count: AtomicU64,

    /// Previous window count.
    previous_count: AtomicU64,

    /// Current window start (nanoseconds since creation).
    window_start_nanos: AtomicU64,

    /// Creation instant.
    created_at: Instant,
}

#[allow(dead_code)]
impl SlidingWindowCounter {
    /// Create a new sliding window counter.
    #[must_use]
    pub fn new(window_size: Duration, max_requests: u64) -> Self {
        Self {
            window_size,
            max_requests,
            current_count: AtomicU64::new(0),
            previous_count: AtomicU64::new(0),
            window_start_nanos: AtomicU64::new(0),
            created_at: Instant::now(),
        }
    }

    /// Try to record a request.
    ///
    /// Returns `true` if allowed, `false` if rate limited.
    pub fn try_record(&self) -> bool {
        self.maybe_rotate_window();

        let weighted_count = self.weighted_count();

        if weighted_count >= self.max_requests as f64 {
            return false;
        }

        self.current_count.fetch_add(1, Ordering::Relaxed);
        true
    }

    /// Get the current weighted count.
    #[must_use]
    pub fn weighted_count(&self) -> f64 {
        self.maybe_rotate_window();

        let now_nanos = self.created_at.elapsed().as_nanos() as u64;
        let window_start = self.window_start_nanos.load(Ordering::Acquire);
        let window_size_nanos = self.window_size.as_nanos() as u64;

        let elapsed_in_window = now_nanos.saturating_sub(window_start);
        let window_progress = elapsed_in_window as f64 / window_size_nanos as f64;

        let current = self.current_count.load(Ordering::Acquire) as f64;
        let previous = self.previous_count.load(Ordering::Acquire) as f64;

        // Weight previous window by how much of current window has elapsed
        current + previous * (1.0 - window_progress)
    }

    /// Get remaining requests in current window.
    #[must_use]
    pub fn remaining(&self) -> u64 {
        let weighted = self.weighted_count();
        if weighted >= self.max_requests as f64 {
            0
        } else {
            (self.max_requests as f64 - weighted) as u64
        }
    }

    /// Get time until window resets.
    #[must_use]
    pub fn time_until_reset(&self) -> Duration {
        let now_nanos = self.created_at.elapsed().as_nanos() as u64;
        let window_start = self.window_start_nanos.load(Ordering::Acquire);
        let window_size_nanos = self.window_size.as_nanos() as u64;

        let elapsed_in_window = now_nanos.saturating_sub(window_start);
        let remaining_nanos = window_size_nanos.saturating_sub(elapsed_in_window);

        Duration::from_nanos(remaining_nanos)
    }

    /// Rotate window if needed.
    fn maybe_rotate_window(&self) {
        let now_nanos = self.created_at.elapsed().as_nanos() as u64;
        let window_start = self.window_start_nanos.load(Ordering::Acquire);
        let window_size_nanos = self.window_size.as_nanos() as u64;

        if now_nanos >= window_start + window_size_nanos {
            // Move to new window
            let new_window_start = (now_nanos / window_size_nanos) * window_size_nanos;

            if self
                .window_start_nanos
                .compare_exchange(
                    window_start,
                    new_window_start,
                    Ordering::AcqRel,
                    Ordering::Acquire,
                )
                .is_ok()
            {
                // Rotate counts
                let current = self.current_count.swap(0, Ordering::AcqRel);
                self.previous_count.store(current, Ordering::Release);
            }
        }
    }
}

impl Clone for SlidingWindowCounter {
    fn clone(&self) -> Self {
        Self {
            window_size: self.window_size,
            max_requests: self.max_requests,
            current_count: AtomicU64::new(self.current_count.load(Ordering::Acquire)),
            previous_count: AtomicU64::new(self.previous_count.load(Ordering::Acquire)),
            window_start_nanos: AtomicU64::new(self.window_start_nanos.load(Ordering::Acquire)),
            created_at: self.created_at,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::thread;

    #[test]
    fn test_token_bucket_creation() {
        let bucket = TokenBucket::with_rate(100, 10.0);
        assert_eq!(bucket.max_tokens(), 100);
        assert_eq!(bucket.refill_rate(), 10.0);
        assert!((bucket.available_tokens() - 100.0).abs() < 0.1);
    }

    #[test]
    fn test_token_bucket_consume() {
        let bucket = TokenBucket::with_rate(10, 1.0);

        // Should be able to consume up to max
        for _ in 0..10 {
            assert!(bucket.try_consume(1));
        }

        // Should be exhausted
        assert!(!bucket.try_consume(1));
    }

    #[test]
    fn test_token_bucket_refill() {
        let bucket = TokenBucket::with_rate(10, 100.0); // 100 tokens/sec

        // Consume all tokens
        assert!(bucket.try_consume(10));
        assert!(!bucket.try_consume(1));

        // Wait for refill
        thread::sleep(Duration::from_millis(50));

        // Should have some tokens now
        assert!(bucket.available_tokens() > 0.0);
    }

    #[test]
    fn test_token_bucket_burst() {
        let bucket = TokenBucket::with_rate(100, 10.0);

        // Burst of 50 should work
        assert!(bucket.try_consume(50));

        // Another burst of 50 should work
        assert!(bucket.try_consume(50));

        // No more tokens
        assert!(!bucket.try_consume(1));
    }

    #[test]
    fn test_token_bucket_reset() {
        let bucket = TokenBucket::with_rate(100, 10.0);

        // Consume all
        bucket.try_consume(100);
        assert!(!bucket.try_consume(1));

        // Reset
        bucket.reset();
        assert!(bucket.try_consume(100));
    }

    #[test]
    fn test_token_bucket_time_until_available() {
        let bucket = TokenBucket::with_rate(10, 10.0); // 10 tokens/sec

        // Consume all
        bucket.try_consume(10);

        // Should need ~1 second for 10 tokens
        let wait = bucket.time_until_available(10);
        assert!(wait >= Duration::from_millis(900));
        assert!(wait <= Duration::from_millis(1100));
    }

    #[test]
    fn test_token_bucket_fill_ratio() {
        let bucket = TokenBucket::with_rate(100, 10.0);

        assert!((bucket.fill_ratio() - 1.0).abs() < 0.01);

        bucket.try_consume(50);
        assert!((bucket.fill_ratio() - 0.5).abs() < 0.01);

        bucket.try_consume(50);
        assert!(bucket.fill_ratio() < 0.01);
    }

    #[test]
    fn test_sliding_window_counter() {
        let counter = SlidingWindowCounter::new(Duration::from_secs(1), 10);

        // Should allow up to max
        for _ in 0..10 {
            assert!(counter.try_record());
        }

        // Should be rate limited
        assert!(!counter.try_record());
    }

    #[test]
    fn test_sliding_window_remaining() {
        let counter = SlidingWindowCounter::new(Duration::from_secs(1), 10);

        assert_eq!(counter.remaining(), 10);

        for _ in 0..5 {
            counter.try_record();
        }

        assert_eq!(counter.remaining(), 5);
    }

    #[test]
    fn test_token_bucket_concurrent() {
        use std::sync::Arc;

        let bucket = Arc::new(TokenBucket::with_rate(100, 1000.0));
        let mut handles = vec![];

        for _ in 0..10 {
            let bucket = Arc::clone(&bucket);
            handles.push(thread::spawn(move || {
                let mut consumed = 0;
                for _ in 0..20 {
                    if bucket.try_consume(1) {
                        consumed += 1;
                    }
                }
                consumed
            }));
        }

        let total: u64 = handles.into_iter().map(|h| h.join().unwrap()).sum();

        // Should have consumed approximately 100 tokens initially
        // plus some refilled during the test
        assert!(total >= 100);
    }
}
