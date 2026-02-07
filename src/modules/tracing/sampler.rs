//! Trace sampling strategies

use super::context::SpanContext;
use super::span::TraceId;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{Duration, Instant};

/// Sampling decision
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SamplingDecision {
    /// Do not sample
    Drop,

    /// Record but do not export
    RecordOnly,

    /// Record and export
    RecordAndSample,
}

impl SamplingDecision {
    /// Check if this decision means we should record
    pub fn is_recording(&self) -> bool {
        matches!(self, Self::RecordOnly | Self::RecordAndSample)
    }

    /// Check if this decision means we should sample/export
    pub fn is_sampled(&self) -> bool {
        matches!(self, Self::RecordAndSample)
    }
}

/// Sampling result with decision and attributes
#[derive(Debug, Clone)]
pub struct SamplingResult {
    /// The sampling decision
    pub decision: SamplingDecision,

    /// Additional attributes to add to the span
    pub attributes: Vec<(String, String)>,
}

impl SamplingResult {
    /// Create a drop result
    pub fn drop() -> Self {
        Self {
            decision: SamplingDecision::Drop,
            attributes: Vec::new(),
        }
    }

    /// Create a record-only result
    pub fn record_only() -> Self {
        Self {
            decision: SamplingDecision::RecordOnly,
            attributes: Vec::new(),
        }
    }

    /// Create a record-and-sample result
    pub fn record_and_sample() -> Self {
        Self {
            decision: SamplingDecision::RecordAndSample,
            attributes: Vec::new(),
        }
    }

    /// Add an attribute
    pub fn with_attribute(mut self, key: impl Into<String>, value: impl Into<String>) -> Self {
        self.attributes.push((key.into(), value.into()));
        self
    }
}

/// Sampling parameters for making sampling decisions
#[derive(Debug, Clone)]
pub struct SamplingParameters<'a> {
    /// Parent context (if any)
    pub parent_context: Option<&'a SpanContext>,

    /// Trace ID
    pub trace_id: TraceId,

    /// Span name
    pub name: &'a str,

    /// Span kind
    pub kind: &'a str,

    /// Initial attributes
    pub attributes: &'a [(String, String)],
}

/// Trait for samplers
pub trait Sampler: Send + Sync {
    /// Make a sampling decision
    fn should_sample(&self, params: &SamplingParameters) -> SamplingResult;

    /// Get a description of this sampler
    fn description(&self) -> &str;
}

/// Always-on sampler (sample everything)
#[derive(Debug, Default)]
pub struct AlwaysOnSampler;

impl AlwaysOnSampler {
    /// Create a new always-on sampler
    pub fn new() -> Self {
        Self
    }
}

impl Sampler for AlwaysOnSampler {
    fn should_sample(&self, _params: &SamplingParameters) -> SamplingResult {
        SamplingResult::record_and_sample()
    }

    fn description(&self) -> &str {
        "AlwaysOnSampler"
    }
}

/// Always-off sampler (sample nothing)
#[derive(Debug, Default)]
pub struct AlwaysOffSampler;

impl AlwaysOffSampler {
    /// Create a new always-off sampler
    pub fn new() -> Self {
        Self
    }
}

impl Sampler for AlwaysOffSampler {
    fn should_sample(&self, _params: &SamplingParameters) -> SamplingResult {
        SamplingResult::drop()
    }

    fn description(&self) -> &str {
        "AlwaysOffSampler"
    }
}

/// Ratio-based sampler (probability sampling)
#[derive(Debug)]
pub struct TraceIdRatioSampler {
    /// Sampling ratio (0.0 to 1.0)
    ratio: f64,

    /// Upper bound for trace ID (ratio * u64::MAX)
    upper_bound: u64,

    /// Description string
    description: String,
}

impl TraceIdRatioSampler {
    /// Create a new ratio sampler
    pub fn new(ratio: f64) -> Self {
        let ratio = ratio.clamp(0.0, 1.0);
        let upper_bound = (ratio * u64::MAX as f64) as u64;

        Self {
            ratio,
            upper_bound,
            description: format!("TraceIdRatioSampler{{ratio={}}}", ratio),
        }
    }

    /// Get the ratio
    pub fn ratio(&self) -> f64 {
        self.ratio
    }
}

impl Sampler for TraceIdRatioSampler {
    fn should_sample(&self, params: &SamplingParameters) -> SamplingResult {
        // Use the low bits of the trace ID for deterministic sampling
        if params.trace_id.low() <= self.upper_bound {
            SamplingResult::record_and_sample()
        } else {
            SamplingResult::drop()
        }
    }

    fn description(&self) -> &str {
        &self.description
    }
}

/// Parent-based sampler (follow parent's decision)
pub struct ParentBasedSampler {
    /// Root sampler (used when there's no parent)
    root: Box<dyn Sampler>,

    /// Sampler for remote parent sampled
    remote_parent_sampled: Box<dyn Sampler>,

    /// Sampler for remote parent not sampled
    remote_parent_not_sampled: Box<dyn Sampler>,

    /// Sampler for local parent sampled
    local_parent_sampled: Box<dyn Sampler>,

    /// Sampler for local parent not sampled
    local_parent_not_sampled: Box<dyn Sampler>,
}

impl ParentBasedSampler {
    /// Create a new parent-based sampler with default behavior
    pub fn new(root: Box<dyn Sampler>) -> Self {
        Self {
            root,
            remote_parent_sampled: Box::new(AlwaysOnSampler::new()),
            remote_parent_not_sampled: Box::new(AlwaysOffSampler::new()),
            local_parent_sampled: Box::new(AlwaysOnSampler::new()),
            local_parent_not_sampled: Box::new(AlwaysOffSampler::new()),
        }
    }

    /// Set the sampler for remote parent sampled case
    pub fn with_remote_parent_sampled(mut self, sampler: Box<dyn Sampler>) -> Self {
        self.remote_parent_sampled = sampler;
        self
    }

    /// Set the sampler for remote parent not sampled case
    pub fn with_remote_parent_not_sampled(mut self, sampler: Box<dyn Sampler>) -> Self {
        self.remote_parent_not_sampled = sampler;
        self
    }
}

impl Sampler for ParentBasedSampler {
    fn should_sample(&self, params: &SamplingParameters) -> SamplingResult {
        match params.parent_context {
            None => self.root.should_sample(params),
            Some(parent) => {
                if parent.is_remote {
                    if parent.is_sampled() {
                        self.remote_parent_sampled.should_sample(params)
                    } else {
                        self.remote_parent_not_sampled.should_sample(params)
                    }
                } else if parent.is_sampled() {
                    self.local_parent_sampled.should_sample(params)
                } else {
                    self.local_parent_not_sampled.should_sample(params)
                }
            },
        }
    }

    fn description(&self) -> &str {
        "ParentBasedSampler"
    }
}

impl std::fmt::Debug for ParentBasedSampler {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ParentBasedSampler")
            .field("root", &self.root.description())
            .finish()
    }
}

/// Rate-limiting sampler
pub struct RateLimitingSampler {
    /// Maximum samples per second
    max_per_second: u32,

    /// Tokens available
    tokens: AtomicU64,

    /// Last refill time
    last_refill: std::sync::RwLock<Instant>,

    /// Description
    description: String,
}

impl RateLimitingSampler {
    /// Create a new rate-limiting sampler
    pub fn new(max_per_second: u32) -> Self {
        Self {
            max_per_second,
            tokens: AtomicU64::new(max_per_second as u64),
            last_refill: std::sync::RwLock::new(Instant::now()),
            description: format!("RateLimitingSampler{{rate={}/s}}", max_per_second),
        }
    }

    /// Refill tokens based on elapsed time
    fn refill(&self) {
        let mut last = self.last_refill.write().unwrap();
        let elapsed = last.elapsed();

        if elapsed >= Duration::from_secs(1) {
            // Refill tokens
            let new_tokens =
                (elapsed.as_secs() as u32 * self.max_per_second).min(self.max_per_second);
            self.tokens.store(new_tokens as u64, Ordering::Relaxed);
            *last = Instant::now();
        }
    }
}

impl Sampler for RateLimitingSampler {
    fn should_sample(&self, _params: &SamplingParameters) -> SamplingResult {
        self.refill();

        // Try to consume a token
        loop {
            let current = self.tokens.load(Ordering::Relaxed);
            if current == 0 {
                return SamplingResult::drop();
            }

            if self
                .tokens
                .compare_exchange_weak(current, current - 1, Ordering::Relaxed, Ordering::Relaxed)
                .is_ok()
            {
                return SamplingResult::record_and_sample();
            }
        }
    }

    fn description(&self) -> &str {
        &self.description
    }
}

impl std::fmt::Debug for RateLimitingSampler {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("RateLimitingSampler")
            .field("max_per_second", &self.max_per_second)
            .finish()
    }
}

/// Create a sampler from configuration
pub fn create_sampler(
    strategy: super::config::SamplingStrategy,
    ratio: f64,
    rate_limit: Option<u32>,
) -> Box<dyn Sampler> {
    use super::config::SamplingStrategy;

    match strategy {
        SamplingStrategy::AlwaysOn => Box::new(AlwaysOnSampler::new()),
        SamplingStrategy::AlwaysOff => Box::new(AlwaysOffSampler::new()),
        SamplingStrategy::Ratio => Box::new(TraceIdRatioSampler::new(ratio)),
        SamplingStrategy::ParentBased => Box::new(ParentBasedSampler::new(Box::new(
            TraceIdRatioSampler::new(ratio),
        ))),
        SamplingStrategy::RateLimited => {
            Box::new(RateLimitingSampler::new(rate_limit.unwrap_or(100)))
        },
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_sampling_decision() {
        assert!(!SamplingDecision::Drop.is_recording());
        assert!(!SamplingDecision::Drop.is_sampled());

        assert!(SamplingDecision::RecordOnly.is_recording());
        assert!(!SamplingDecision::RecordOnly.is_sampled());

        assert!(SamplingDecision::RecordAndSample.is_recording());
        assert!(SamplingDecision::RecordAndSample.is_sampled());
    }

    #[test]
    fn test_always_on_sampler() {
        let sampler = AlwaysOnSampler::new();
        let params = SamplingParameters {
            parent_context: None,
            trace_id: TraceId::generate(),
            name: "test",
            kind: "internal",
            attributes: &[],
        };

        let result = sampler.should_sample(&params);
        assert!(result.decision.is_sampled());
    }

    #[test]
    fn test_always_off_sampler() {
        let sampler = AlwaysOffSampler::new();
        let params = SamplingParameters {
            parent_context: None,
            trace_id: TraceId::generate(),
            name: "test",
            kind: "internal",
            attributes: &[],
        };

        let result = sampler.should_sample(&params);
        assert!(!result.decision.is_sampled());
    }

    #[test]
    fn test_ratio_sampler() {
        let sampler = TraceIdRatioSampler::new(0.5);
        assert_eq!(sampler.ratio(), 0.5);

        // With 50% sampling, some should be sampled, some not
        let mut sampled = 0;
        let mut dropped = 0;

        for _ in 0..1000 {
            let params = SamplingParameters {
                parent_context: None,
                trace_id: TraceId::generate(),
                name: "test",
                kind: "internal",
                attributes: &[],
            };

            let result = sampler.should_sample(&params);
            if result.decision.is_sampled() {
                sampled += 1;
            } else {
                dropped += 1;
            }
        }

        // With 1000 samples at 50%, we should have a reasonable distribution
        // Allow 30-70% range to account for randomness
        assert!(sampled > 300, "expected >300 sampled, got {}", sampled);
        assert!(dropped > 300, "expected >300 dropped, got {}", dropped);
    }

    #[test]
    fn test_ratio_sampler_deterministic() {
        let sampler = TraceIdRatioSampler::new(0.5);
        let trace_id = TraceId::generate();

        // Same trace ID should always get the same result
        let params = SamplingParameters {
            parent_context: None,
            trace_id,
            name: "test",
            kind: "internal",
            attributes: &[],
        };

        let result1 = sampler.should_sample(&params);
        let result2 = sampler.should_sample(&params);
        assert_eq!(result1.decision, result2.decision);
    }

    #[test]
    fn test_parent_based_sampler() {
        let sampler = ParentBasedSampler::new(Box::new(AlwaysOnSampler::new()));

        // No parent - use root sampler
        let params = SamplingParameters {
            parent_context: None,
            trace_id: TraceId::generate(),
            name: "test",
            kind: "internal",
            attributes: &[],
        };
        let result = sampler.should_sample(&params);
        assert!(result.decision.is_sampled());

        // Parent sampled - should sample
        let parent = SpanContext::new(TraceId::generate(), super::super::span::SpanId::generate())
            .with_sampled(true)
            .with_remote(true);

        let params = SamplingParameters {
            parent_context: Some(&parent),
            trace_id: TraceId::generate(),
            name: "test",
            kind: "internal",
            attributes: &[],
        };
        let result = sampler.should_sample(&params);
        assert!(result.decision.is_sampled());

        // Parent not sampled - should not sample
        let parent = SpanContext::new(TraceId::generate(), super::super::span::SpanId::generate())
            .with_sampled(false)
            .with_remote(true);

        let params = SamplingParameters {
            parent_context: Some(&parent),
            trace_id: TraceId::generate(),
            name: "test",
            kind: "internal",
            attributes: &[],
        };
        let result = sampler.should_sample(&params);
        assert!(!result.decision.is_sampled());
    }

    #[test]
    fn test_rate_limiting_sampler() {
        let sampler = RateLimitingSampler::new(10);

        // First 10 should be sampled
        let mut sampled = 0;
        for _ in 0..15 {
            let params = SamplingParameters {
                parent_context: None,
                trace_id: TraceId::generate(),
                name: "test",
                kind: "internal",
                attributes: &[],
            };

            if sampler.should_sample(&params).decision.is_sampled() {
                sampled += 1;
            }
        }

        assert_eq!(sampled, 10);
    }

    #[test]
    fn test_create_sampler() {
        use super::super::config::SamplingStrategy;

        let sampler = create_sampler(SamplingStrategy::AlwaysOn, 1.0, None);
        assert_eq!(sampler.description(), "AlwaysOnSampler");

        let sampler = create_sampler(SamplingStrategy::Ratio, 0.5, None);
        assert!(sampler.description().contains("0.5"));

        let sampler = create_sampler(SamplingStrategy::RateLimited, 1.0, Some(100));
        assert!(sampler.description().contains("100"));
    }

    #[test]
    fn test_sampling_result_attributes() {
        let result = SamplingResult::record_and_sample()
            .with_attribute("sampler", "test")
            .with_attribute("reason", "always");

        assert_eq!(result.attributes.len(), 2);
    }
}
