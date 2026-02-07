//! HTTP/3 handler

use super::frame::Settings;
use crate::module::{
    Capability, Dependency, MetricsPayload, ModuleConfig, ModuleContract, ModuleManifest,
    ModuleResult, ModuleStatus,
};
use serde::{Deserialize, Serialize};
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::time::Duration;

/// HTTP/3 configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Http3Config {
    /// Enable HTTP/3
    #[serde(default = "default_enabled")]
    pub enabled: bool,

    /// Maximum header list size
    #[serde(default = "default_max_field_section_size")]
    pub max_field_section_size: u64,

    /// QPACK max table capacity
    #[serde(default = "default_qpack_max_table_capacity")]
    pub qpack_max_table_capacity: u64,

    /// QPACK blocked streams
    #[serde(default = "default_qpack_blocked_streams")]
    pub qpack_blocked_streams: u64,

    /// Enable CONNECT protocol (RFC 9220)
    #[serde(default)]
    pub enable_connect_protocol: bool,

    /// Enable WebTransport
    #[serde(default)]
    pub enable_webtransport: bool,

    /// Enable server push
    #[serde(default)]
    pub enable_push: bool,

    /// Maximum push ID
    #[serde(default = "default_max_push_id")]
    pub max_push_id: u64,

    /// Request timeout
    #[serde(default = "default_request_timeout", with = "humantime_serde")]
    pub request_timeout: Duration,

    /// Enable 0-RTT early data
    #[serde(default = "default_enable_0rtt")]
    pub enable_0rtt: bool,
}

fn default_enabled() -> bool {
    true
}

fn default_max_field_section_size() -> u64 {
    16 * 1024 // 16 KB
}

fn default_qpack_max_table_capacity() -> u64 {
    4096
}

fn default_qpack_blocked_streams() -> u64 {
    100
}

fn default_max_push_id() -> u64 {
    0
}

fn default_request_timeout() -> Duration {
    Duration::from_secs(30)
}

fn default_enable_0rtt() -> bool {
    true
}

impl Default for Http3Config {
    fn default() -> Self {
        Self {
            enabled: default_enabled(),
            max_field_section_size: default_max_field_section_size(),
            qpack_max_table_capacity: default_qpack_max_table_capacity(),
            qpack_blocked_streams: default_qpack_blocked_streams(),
            enable_connect_protocol: false,
            enable_webtransport: false,
            enable_push: false,
            max_push_id: default_max_push_id(),
            request_timeout: default_request_timeout(),
            enable_0rtt: default_enable_0rtt(),
        }
    }
}

impl Http3Config {
    /// Create settings from config
    pub fn to_settings(&self) -> Settings {
        Settings::new()
            .with_max_field_section_size(self.max_field_section_size)
            .with_qpack_max_table_capacity(self.qpack_max_table_capacity)
            .with_qpack_blocked_streams(self.qpack_blocked_streams)
            .with_connect_protocol(self.enable_connect_protocol)
            .with_webtransport(self.enable_webtransport)
    }
}

/// HTTP/3 connection state
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ConnectionState {
    /// Initial state
    Initial,

    /// Settings exchanged
    SettingsReceived,

    /// Ready for requests
    Ready,

    /// Closing (GOAWAY sent/received)
    Closing,

    /// Closed
    Closed,
}

impl ConnectionState {
    /// Check if can send requests
    pub fn can_request(&self) -> bool {
        matches!(self, Self::Ready)
    }

    /// Check if closed
    pub fn is_closed(&self) -> bool {
        matches!(self, Self::Closed)
    }
}

impl std::fmt::Display for ConnectionState {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Initial => write!(f, "initial"),
            Self::SettingsReceived => write!(f, "settings_received"),
            Self::Ready => write!(f, "ready"),
            Self::Closing => write!(f, "closing"),
            Self::Closed => write!(f, "closed"),
        }
    }
}

/// HTTP/3 handler implementing ModuleContract
pub struct Http3Handler {
    /// Configuration
    config: Http3Config,

    /// Initialized flag
    initialized: bool,

    /// Running flag
    running: AtomicBool,

    /// Total requests received
    requests_received: AtomicU64,

    /// Total responses sent
    responses_sent: AtomicU64,

    /// Total bytes received (HTTP/3 payload)
    bytes_received: AtomicU64,

    /// Total bytes sent (HTTP/3 payload)
    bytes_sent: AtomicU64,

    /// Total streams opened
    streams_opened: AtomicU64,

    /// Total streams closed
    streams_closed: AtomicU64,

    /// Push promises sent
    push_promises_sent: AtomicU64,

    /// GOAWAY frames sent
    goaway_sent: AtomicU64,

    /// Header compression ratio (x1000 for precision)
    header_compression_ratio: AtomicU64,

    /// Active connections
    active_connections: AtomicU64,

    /// Request errors
    request_errors: AtomicU64,

    /// 0-RTT requests
    zero_rtt_requests: AtomicU64,
}

impl Http3Handler {
    /// Create new handler
    pub fn new() -> Self {
        Self {
            config: Http3Config::default(),
            initialized: false,
            running: AtomicBool::new(false),
            requests_received: AtomicU64::new(0),
            responses_sent: AtomicU64::new(0),
            bytes_received: AtomicU64::new(0),
            bytes_sent: AtomicU64::new(0),
            streams_opened: AtomicU64::new(0),
            streams_closed: AtomicU64::new(0),
            push_promises_sent: AtomicU64::new(0),
            goaway_sent: AtomicU64::new(0),
            header_compression_ratio: AtomicU64::new(1000), // 1.0 = no compression
            active_connections: AtomicU64::new(0),
            request_errors: AtomicU64::new(0),
            zero_rtt_requests: AtomicU64::new(0),
        }
    }

    /// Get configuration
    pub fn config(&self) -> &Http3Config {
        &self.config
    }

    /// Get local settings
    pub fn local_settings(&self) -> Settings {
        self.config.to_settings()
    }

    /// Check if running
    pub fn is_running(&self) -> bool {
        self.running.load(Ordering::SeqCst)
    }

    /// Record request received
    pub fn on_request(&self) {
        self.requests_received.fetch_add(1, Ordering::SeqCst);
    }

    /// Record response sent
    pub fn on_response(&self) {
        self.responses_sent.fetch_add(1, Ordering::SeqCst);
    }

    /// Record bytes
    pub fn record_bytes(&self, received: u64, sent: u64) {
        self.bytes_received.fetch_add(received, Ordering::SeqCst);
        self.bytes_sent.fetch_add(sent, Ordering::SeqCst);
    }

    /// Record stream opened
    pub fn on_stream_opened(&self) {
        self.streams_opened.fetch_add(1, Ordering::SeqCst);
    }

    /// Record stream closed
    pub fn on_stream_closed(&self) {
        self.streams_closed.fetch_add(1, Ordering::SeqCst);
    }

    /// Record connection opened
    pub fn on_connection_opened(&self) {
        self.active_connections.fetch_add(1, Ordering::SeqCst);
    }

    /// Record connection closed
    pub fn on_connection_closed(&self) {
        self.active_connections.fetch_sub(1, Ordering::SeqCst);
    }

    /// Record request error
    pub fn on_request_error(&self) {
        self.request_errors.fetch_add(1, Ordering::SeqCst);
    }

    /// Record 0-RTT request
    pub fn on_zero_rtt_request(&self) {
        self.zero_rtt_requests.fetch_add(1, Ordering::SeqCst);
    }

    /// Record push promise
    pub fn on_push_promise(&self) {
        self.push_promises_sent.fetch_add(1, Ordering::SeqCst);
    }

    /// Record GOAWAY
    pub fn on_goaway(&self) {
        self.goaway_sent.fetch_add(1, Ordering::SeqCst);
    }

    /// Update header compression ratio
    pub fn update_compression_ratio(&self, original_size: u64, compressed_size: u64) {
        if original_size > 0 {
            let ratio = (compressed_size * 1000) / original_size;
            self.header_compression_ratio.store(ratio, Ordering::SeqCst);
        }
    }
}

impl Default for Http3Handler {
    fn default() -> Self {
        Self::new()
    }
}

impl ModuleContract for Http3Handler {
    fn manifest(&self) -> ModuleManifest {
        ModuleManifest::builder("http3")
            .description("HTTP/3 protocol handler (RFC 9114)")
            .version(1, 0, 0)
            .capability(Capability::HttpProtocol)
            .capability(Capability::Custom("Http3".to_string()))
            .capability(Capability::Custom("Qpack".to_string()))
            .dependency(Dependency::required("quic"))
            .build()
    }

    fn init(&mut self, _config: ModuleConfig) -> ModuleResult<()> {
        // Use defaults for now
        self.config = Http3Config::default();
        self.initialized = true;
        Ok(())
    }

    fn start(&mut self) -> ModuleResult<()> {
        if !self.initialized {
            return Err(crate::module::ModuleError::InvalidState {
                current: "uninitialized".to_string(),
                expected: "initialized".to_string(),
            });
        }

        self.running.store(true, Ordering::SeqCst);
        Ok(())
    }

    fn stop(&mut self) -> ModuleResult<()> {
        self.running.store(false, Ordering::SeqCst);
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
        let mut payload = MetricsPayload::new();

        payload.counter(
            "requests_received",
            self.requests_received.load(Ordering::SeqCst),
        );
        payload.counter("responses_sent", self.responses_sent.load(Ordering::SeqCst));
        payload.counter("bytes_received", self.bytes_received.load(Ordering::SeqCst));
        payload.counter("bytes_sent", self.bytes_sent.load(Ordering::SeqCst));
        payload.counter("streams_opened", self.streams_opened.load(Ordering::SeqCst));
        payload.counter("streams_closed", self.streams_closed.load(Ordering::SeqCst));
        payload.counter(
            "push_promises_sent",
            self.push_promises_sent.load(Ordering::SeqCst),
        );
        payload.counter("goaway_sent", self.goaway_sent.load(Ordering::SeqCst));
        payload.counter("request_errors", self.request_errors.load(Ordering::SeqCst));
        payload.counter(
            "zero_rtt_requests",
            self.zero_rtt_requests.load(Ordering::SeqCst),
        );

        payload.gauge(
            "active_connections",
            self.active_connections.load(Ordering::SeqCst) as f64,
        );
        payload.gauge(
            "header_compression_ratio",
            self.header_compression_ratio.load(Ordering::SeqCst) as f64 / 1000.0,
        );

        payload
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_config_default() {
        let config = Http3Config::default();
        assert!(config.enabled);
        assert_eq!(config.max_field_section_size, 16 * 1024);
        assert!(!config.enable_connect_protocol);
    }

    #[test]
    fn test_config_to_settings() {
        let config = Http3Config {
            max_field_section_size: 8192,
            enable_connect_protocol: true,
            ..Default::default()
        };

        let settings = config.to_settings();
        assert_eq!(settings.max_field_section_size, Some(8192));
        assert_eq!(settings.enable_connect_protocol, Some(true));
    }

    #[test]
    fn test_connection_state() {
        assert!(!ConnectionState::Initial.can_request());
        assert!(ConnectionState::Ready.can_request());
        assert!(ConnectionState::Closed.is_closed());
    }

    #[test]
    fn test_handler_manifest() {
        let handler = Http3Handler::new();
        let manifest = handler.manifest();
        assert_eq!(manifest.name, "http3");
        assert!(!manifest.dependencies.is_empty());
    }

    #[test]
    fn test_handler_init() {
        let mut handler = Http3Handler::new();
        let config = ModuleConfig::new();

        handler.init(config).unwrap();
        assert!(handler.initialized);
    }

    #[test]
    fn test_handler_lifecycle() {
        let mut handler = Http3Handler::new();
        handler.init(ModuleConfig::new()).unwrap();

        let status = handler.status();
        assert_eq!(status, ModuleStatus::Stopped);

        handler.start().unwrap();
        let status = handler.status();
        assert_eq!(status, ModuleStatus::Running);

        handler.stop().unwrap();
        let status = handler.status();
        assert_eq!(status, ModuleStatus::Stopped);
    }

    #[test]
    fn test_handler_metrics() {
        let handler = Http3Handler::new();

        handler.on_request();
        handler.on_request();
        handler.on_response();
        handler.record_bytes(1000, 500);
        handler.on_stream_opened();
        handler.on_connection_opened();

        let metrics = handler.metrics();
        assert_eq!(metrics.counters.get("requests_received"), Some(&2));
        assert_eq!(metrics.counters.get("responses_sent"), Some(&1));
    }

    #[test]
    fn test_compression_ratio() {
        let handler = Http3Handler::new();

        // 500 bytes compressed to 250 = 50% = ratio of 500
        handler.update_compression_ratio(500, 250);
        assert_eq!(handler.header_compression_ratio.load(Ordering::SeqCst), 500);
    }

    #[test]
    fn test_local_settings() {
        let mut handler = Http3Handler::new();
        handler.config.max_field_section_size = 4096;
        handler.config.enable_connect_protocol = true;

        let settings = handler.local_settings();
        assert_eq!(settings.max_field_section_size, Some(4096));
        assert_eq!(settings.enable_connect_protocol, Some(true));
    }
}
