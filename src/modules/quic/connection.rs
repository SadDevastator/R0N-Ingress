//! QUIC connection management

use super::config::{QuicConfig, QuicVersion, TransportParameters};
use super::error::{QuicError, QuicResult, TransportErrorCode};
use super::stream::{Stream, StreamId, StreamType};
use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};

/// Connection ID (variable length, up to 20 bytes)
#[derive(Clone, PartialEq, Eq, Hash)]
pub struct ConnectionId(Vec<u8>);

impl ConnectionId {
    /// Maximum connection ID length
    pub const MAX_LENGTH: usize = 20;

    /// Create empty connection ID
    pub fn empty() -> Self {
        Self(Vec::new())
    }

    /// Create from bytes
    pub fn from_bytes(bytes: &[u8]) -> QuicResult<Self> {
        if bytes.len() > Self::MAX_LENGTH {
            return Err(QuicError::Protocol(format!(
                "connection ID too long: {} > {}",
                bytes.len(),
                Self::MAX_LENGTH
            )));
        }
        Ok(Self(bytes.to_vec()))
    }

    /// Generate random connection ID
    pub fn generate(length: usize) -> QuicResult<Self> {
        if length > Self::MAX_LENGTH {
            return Err(QuicError::Protocol(format!(
                "connection ID length too long: {} > {}",
                length,
                Self::MAX_LENGTH
            )));
        }

        use std::collections::hash_map::DefaultHasher;
        use std::hash::{Hash, Hasher};

        let mut bytes = vec![0u8; length];
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default();

        for (i, byte) in bytes.iter_mut().enumerate() {
            let mut hasher = DefaultHasher::new();
            now.as_nanos().hash(&mut hasher);
            i.hash(&mut hasher);
            std::thread::current().id().hash(&mut hasher);
            *byte = (hasher.finish() >> (i % 8 * 8)) as u8;
        }

        Ok(Self(bytes))
    }

    /// Get bytes
    pub fn as_bytes(&self) -> &[u8] {
        &self.0
    }

    /// Get length
    pub fn len(&self) -> usize {
        self.0.len()
    }

    /// Check if empty
    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }
}

impl std::fmt::Debug for ConnectionId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "ConnectionId(")?;
        for byte in &self.0 {
            write!(f, "{:02x}", byte)?;
        }
        write!(f, ")")
    }
}

impl std::fmt::Display for ConnectionId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        for byte in &self.0 {
            write!(f, "{:02x}", byte)?;
        }
        Ok(())
    }
}

/// Connection state
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ConnectionState {
    /// Initial state, preparing handshake
    Initial,

    /// Handshake in progress
    Handshaking,

    /// Connection established
    Connected,

    /// Connection is closing
    Closing,

    /// Connection is draining (waiting for packets)
    Draining,

    /// Connection is closed
    Closed,
}

impl ConnectionState {
    /// Check if connected
    pub fn is_connected(&self) -> bool {
        matches!(self, Self::Connected)
    }

    /// Check if closed
    pub fn is_closed(&self) -> bool {
        matches!(self, Self::Closed)
    }

    /// Check if can send data
    pub fn can_send(&self) -> bool {
        matches!(self, Self::Connected)
    }

    /// Check if can receive data
    pub fn can_receive(&self) -> bool {
        matches!(self, Self::Handshaking | Self::Connected)
    }
}

impl std::fmt::Display for ConnectionState {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Initial => write!(f, "initial"),
            Self::Handshaking => write!(f, "handshaking"),
            Self::Connected => write!(f, "connected"),
            Self::Closing => write!(f, "closing"),
            Self::Draining => write!(f, "draining"),
            Self::Closed => write!(f, "closed"),
        }
    }
}

/// Close reason
#[derive(Debug, Clone)]
pub struct CloseReason {
    /// Error code
    pub error_code: TransportErrorCode,

    /// Frame type that caused the error (if any)
    pub frame_type: Option<u64>,

    /// Human-readable reason
    pub reason: String,
}

impl CloseReason {
    /// No error
    pub fn no_error() -> Self {
        Self {
            error_code: TransportErrorCode::NoError,
            frame_type: None,
            reason: String::new(),
        }
    }

    /// Application error
    pub fn application(_code: u64, reason: impl Into<String>) -> Self {
        Self {
            error_code: TransportErrorCode::NoError,
            frame_type: None,
            reason: reason.into(),
        }
    }

    /// Transport error
    pub fn transport(error_code: TransportErrorCode, reason: impl Into<String>) -> Self {
        Self {
            error_code,
            frame_type: None,
            reason: reason.into(),
        }
    }
}

/// Connection statistics
#[derive(Debug, Clone, Default)]
pub struct ConnectionStats {
    /// Total bytes sent
    pub bytes_sent: u64,

    /// Total bytes received
    pub bytes_received: u64,

    /// Total packets sent
    pub packets_sent: u64,

    /// Total packets received
    pub packets_received: u64,

    /// Packets lost
    pub packets_lost: u64,

    /// Packets retransmitted
    pub packets_retransmitted: u64,

    /// Smoothed RTT (in microseconds)
    pub smoothed_rtt: u64,

    /// RTT variance (in microseconds)
    pub rtt_variance: u64,

    /// Minimum RTT observed
    pub min_rtt: u64,

    /// Congestion window
    pub congestion_window: u64,

    /// Bytes in flight
    pub bytes_in_flight: u64,

    /// Connection established time
    pub established_at: Option<Instant>,

    /// Number of streams opened
    pub streams_opened: u64,

    /// Number of streams closed
    pub streams_closed: u64,

    /// 0-RTT packets sent
    pub zero_rtt_sent: u64,

    /// 0-RTT packets accepted
    pub zero_rtt_accepted: u64,
}

impl ConnectionStats {
    /// Get connection uptime
    pub fn uptime(&self) -> Option<Duration> {
        self.established_at.map(|t| t.elapsed())
    }

    /// Get packet loss rate
    pub fn loss_rate(&self) -> f64 {
        if self.packets_sent == 0 {
            0.0
        } else {
            self.packets_lost as f64 / self.packets_sent as f64
        }
    }
}

/// Flow control state
#[derive(Debug, Clone)]
pub struct FlowControl {
    /// Maximum data we can receive
    pub max_data: u64,

    /// Data consumed
    pub data_consumed: u64,

    /// Maximum data peer can receive
    pub peer_max_data: u64,

    /// Data sent to peer
    pub data_sent: u64,
}

impl FlowControl {
    /// Create with initial values
    pub fn new(max_data: u64, peer_max_data: u64) -> Self {
        Self {
            max_data,
            data_consumed: 0,
            peer_max_data,
            data_sent: 0,
        }
    }

    /// Available receive window
    pub fn receive_window(&self) -> u64 {
        self.max_data.saturating_sub(self.data_consumed)
    }

    /// Available send window
    pub fn send_window(&self) -> u64 {
        self.peer_max_data.saturating_sub(self.data_sent)
    }

    /// Check if blocked on receive
    pub fn receive_blocked(&self) -> bool {
        self.data_consumed >= self.max_data
    }

    /// Check if blocked on send
    pub fn send_blocked(&self) -> bool {
        self.data_sent >= self.peer_max_data
    }

    /// Record data consumed
    pub fn consume(&mut self, amount: u64) -> QuicResult<()> {
        let new_consumed = self.data_consumed.saturating_add(amount);
        if new_consumed > self.max_data {
            return Err(QuicError::FlowControl(format!(
                "flow control limit exceeded: {} > {}",
                new_consumed, self.max_data
            )));
        }
        self.data_consumed = new_consumed;
        Ok(())
    }

    /// Record data sent
    pub fn send(&mut self, amount: u64) -> QuicResult<()> {
        let new_sent = self.data_sent.saturating_add(amount);
        if new_sent > self.peer_max_data {
            return Err(QuicError::FlowControl(format!(
                "peer flow control limit exceeded: {} > {}",
                new_sent, self.peer_max_data
            )));
        }
        self.data_sent = new_sent;
        Ok(())
    }

    /// Update max data (from MAX_DATA frame)
    pub fn update_max_data(&mut self, max_data: u64) {
        if max_data > self.max_data {
            self.max_data = max_data;
        }
    }

    /// Update peer max data
    pub fn update_peer_max_data(&mut self, max_data: u64) {
        if max_data > self.peer_max_data {
            self.peer_max_data = max_data;
        }
    }
}

/// Stream limits
#[derive(Debug, Clone)]
pub struct StreamLimits {
    /// Max bidirectional streams we can initiate
    pub max_bidi_local: u64,

    /// Max unidirectional streams we can initiate
    pub max_uni_local: u64,

    /// Current bidirectional streams initiated
    pub bidi_initiated: u64,

    /// Current unidirectional streams initiated
    pub uni_initiated: u64,

    /// Max bidirectional streams peer can initiate
    pub max_bidi_remote: u64,

    /// Max unidirectional streams peer can initiate
    pub max_uni_remote: u64,
}

impl StreamLimits {
    /// Create with initial values
    pub fn new(max_bidi: u64, max_uni: u64) -> Self {
        Self {
            max_bidi_local: max_bidi,
            max_uni_local: max_uni,
            bidi_initiated: 0,
            uni_initiated: 0,
            max_bidi_remote: max_bidi,
            max_uni_remote: max_uni,
        }
    }

    /// Check if can open bidirectional stream
    pub fn can_open_bidi(&self) -> bool {
        self.bidi_initiated < self.max_bidi_local
    }

    /// Check if can open unidirectional stream
    pub fn can_open_uni(&self) -> bool {
        self.uni_initiated < self.max_uni_local
    }
}

/// QUIC Connection
pub struct Connection {
    /// Source connection ID
    pub source_cid: ConnectionId,

    /// Destination connection ID
    pub destination_cid: ConnectionId,

    /// Remote address
    pub remote_addr: SocketAddr,

    /// Local address
    pub local_addr: SocketAddr,

    /// Connection state
    state: ConnectionState,

    /// QUIC version
    version: QuicVersion,

    /// Is server side
    is_server: bool,

    /// Transport parameters (ours)
    local_params: TransportParameters,

    /// Transport parameters (peer)
    peer_params: Option<TransportParameters>,

    /// Active streams
    streams: HashMap<StreamId, Stream>,

    /// Connection-level flow control
    flow_control: FlowControl,

    /// Stream limits
    stream_limits: StreamLimits,

    /// Statistics
    stats: ConnectionStats,

    /// Close reason (if closing/closed)
    close_reason: Option<CloseReason>,

    /// Created timestamp
    created_at: Instant,

    /// Last activity timestamp
    last_activity: Instant,

    /// Idle timeout
    idle_timeout: Duration,

    /// Next stream ID for client-initiated bidirectional
    next_bidi_stream_id: AtomicU64,

    /// Next stream ID for client-initiated unidirectional
    next_uni_stream_id: AtomicU64,
}

impl Connection {
    /// Create new connection
    pub fn new(
        source_cid: ConnectionId,
        destination_cid: ConnectionId,
        remote_addr: SocketAddr,
        local_addr: SocketAddr,
        is_server: bool,
        config: &QuicConfig,
    ) -> Self {
        let local_params = TransportParameters::from_config(config);
        let flow_control = FlowControl::new(config.max_data, config.max_data);
        let stream_limits = StreamLimits::new(
            config.max_bidirectional_streams,
            config.max_unidirectional_streams,
        );
        let now = Instant::now();

        // Stream IDs: client initiates even (0, 4, 8...), server initiates odd (1, 5, 9...)
        let (bidi_base, uni_base) = if is_server { (1, 3) } else { (0, 2) };

        Self {
            source_cid,
            destination_cid,
            remote_addr,
            local_addr,
            state: ConnectionState::Initial,
            version: QuicVersion::V1,
            is_server,
            local_params,
            peer_params: None,
            streams: HashMap::new(),
            flow_control,
            stream_limits,
            stats: ConnectionStats::default(),
            close_reason: None,
            created_at: now,
            last_activity: now,
            idle_timeout: config.idle_timeout,
            next_bidi_stream_id: AtomicU64::new(bidi_base),
            next_uni_stream_id: AtomicU64::new(uni_base),
        }
    }

    /// Get connection state
    pub fn state(&self) -> ConnectionState {
        self.state
    }

    /// Set connection state
    pub fn set_state(&mut self, state: ConnectionState) {
        self.state = state;
        if state == ConnectionState::Connected && self.stats.established_at.is_none() {
            self.stats.established_at = Some(Instant::now());
        }
    }

    /// Get QUIC version
    pub fn version(&self) -> QuicVersion {
        self.version
    }

    /// Check if server side
    pub fn is_server(&self) -> bool {
        self.is_server
    }

    /// Get local transport parameters
    pub fn local_params(&self) -> &TransportParameters {
        &self.local_params
    }

    /// Get peer transport parameters
    pub fn peer_params(&self) -> Option<&TransportParameters> {
        self.peer_params.as_ref()
    }

    /// Set peer transport parameters
    pub fn set_peer_params(&mut self, params: TransportParameters) {
        self.peer_params = Some(params);
    }

    /// Get connection statistics
    pub fn stats(&self) -> &ConnectionStats {
        &self.stats
    }

    /// Get mutable statistics
    pub fn stats_mut(&mut self) -> &mut ConnectionStats {
        &mut self.stats
    }

    /// Get flow control
    pub fn flow_control(&self) -> &FlowControl {
        &self.flow_control
    }

    /// Get mutable flow control
    pub fn flow_control_mut(&mut self) -> &mut FlowControl {
        &mut self.flow_control
    }

    /// Get stream limits
    pub fn stream_limits(&self) -> &StreamLimits {
        &self.stream_limits
    }

    /// Update last activity timestamp
    pub fn touch(&mut self) {
        self.last_activity = Instant::now();
    }

    /// Check if connection has timed out
    pub fn is_timed_out(&self) -> bool {
        self.last_activity.elapsed() > self.idle_timeout
    }

    /// Get close reason
    pub fn close_reason(&self) -> Option<&CloseReason> {
        self.close_reason.as_ref()
    }

    /// Open a new bidirectional stream
    pub fn open_bidirectional_stream(&mut self) -> QuicResult<StreamId> {
        if !self.state.can_send() {
            return Err(QuicError::ConnectionClosed(
                "connection not ready".to_string(),
            ));
        }

        if !self.stream_limits.can_open_bidi() {
            return Err(QuicError::Stream(format!(
                "max bidirectional streams reached: {}",
                self.stream_limits.max_bidi_local
            )));
        }

        let id_val = self.next_bidi_stream_id.fetch_add(4, Ordering::SeqCst);
        let stream_id = StreamId::new(id_val);
        let stream = Stream::new(stream_id, StreamType::Bidirectional);

        self.streams.insert(stream_id, stream);
        self.stream_limits.bidi_initiated += 1;
        self.stats.streams_opened += 1;

        Ok(stream_id)
    }

    /// Open a new unidirectional stream
    pub fn open_unidirectional_stream(&mut self) -> QuicResult<StreamId> {
        if !self.state.can_send() {
            return Err(QuicError::ConnectionClosed(
                "connection not ready".to_string(),
            ));
        }

        if !self.stream_limits.can_open_uni() {
            return Err(QuicError::Stream(format!(
                "max unidirectional streams reached: {}",
                self.stream_limits.max_uni_local
            )));
        }

        let id_val = self.next_uni_stream_id.fetch_add(4, Ordering::SeqCst);
        let stream_id = StreamId::new(id_val);
        let stream = Stream::new(stream_id, StreamType::Unidirectional);

        self.streams.insert(stream_id, stream);
        self.stream_limits.uni_initiated += 1;
        self.stats.streams_opened += 1;

        Ok(stream_id)
    }

    /// Get a stream
    pub fn stream(&self, id: StreamId) -> Option<&Stream> {
        self.streams.get(&id)
    }

    /// Get a mutable stream
    pub fn stream_mut(&mut self, id: StreamId) -> Option<&mut Stream> {
        self.streams.get_mut(&id)
    }

    /// Get all streams
    pub fn streams(&self) -> impl Iterator<Item = (&StreamId, &Stream)> {
        self.streams.iter()
    }

    /// Get number of active streams
    pub fn stream_count(&self) -> usize {
        self.streams.len()
    }

    /// Accept a new stream from peer
    pub fn accept_stream(
        &mut self,
        stream_id: StreamId,
        stream_type: StreamType,
    ) -> QuicResult<()> {
        if self.streams.contains_key(&stream_id) {
            return Err(QuicError::Stream(format!(
                "stream {} already exists",
                stream_id
            )));
        }

        let stream = Stream::new(stream_id, stream_type);
        self.streams.insert(stream_id, stream);
        self.stats.streams_opened += 1;

        Ok(())
    }

    /// Close a stream
    pub fn close_stream(&mut self, stream_id: StreamId) -> QuicResult<()> {
        if let Some(_stream) = self.streams.remove(&stream_id) {
            self.stats.streams_closed += 1;
            Ok(())
        } else {
            Err(QuicError::InvalidStreamId(stream_id.id()))
        }
    }

    /// Initiate connection close
    pub fn close(&mut self, reason: CloseReason) {
        match self.state {
            ConnectionState::Closed | ConnectionState::Draining => {},
            _ => {
                self.state = ConnectionState::Closing;
                self.close_reason = Some(reason);
            },
        }
    }

    /// Transition to draining state
    pub fn drain(&mut self) {
        if self.state == ConnectionState::Closing {
            self.state = ConnectionState::Draining;
        }
    }

    /// Transition to closed state
    pub fn set_closed(&mut self) {
        self.state = ConnectionState::Closed;
    }

    /// Get connection age
    pub fn age(&self) -> Duration {
        self.created_at.elapsed()
    }
}

impl std::fmt::Debug for Connection {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Connection")
            .field("source_cid", &self.source_cid)
            .field("destination_cid", &self.destination_cid)
            .field("remote_addr", &self.remote_addr)
            .field("state", &self.state)
            .field("version", &self.version)
            .field("is_server", &self.is_server)
            .field("stream_count", &self.streams.len())
            .finish()
    }
}

/// Connection handle for sharing across threads
pub type ConnectionHandle = Arc<tokio::sync::RwLock<Connection>>;

#[cfg(test)]
mod tests {
    use super::*;

    fn test_config() -> QuicConfig {
        QuicConfig::default()
    }

    #[test]
    fn test_connection_id_generate() {
        let cid = ConnectionId::generate(16).unwrap();
        assert_eq!(cid.len(), 16);
        assert!(!cid.is_empty());
    }

    #[test]
    fn test_connection_id_from_bytes() {
        let bytes = vec![1, 2, 3, 4];
        let cid = ConnectionId::from_bytes(&bytes).unwrap();
        assert_eq!(cid.as_bytes(), &bytes);
    }

    #[test]
    fn test_connection_id_too_long() {
        let bytes = vec![0u8; 21];
        assert!(ConnectionId::from_bytes(&bytes).is_err());
    }

    #[test]
    fn test_connection_state() {
        assert!(!ConnectionState::Initial.is_connected());
        assert!(ConnectionState::Connected.is_connected());
        assert!(ConnectionState::Connected.can_send());
        assert!(ConnectionState::Closed.is_closed());
    }

    #[test]
    fn test_flow_control() {
        let mut fc = FlowControl::new(1000, 1000);
        assert_eq!(fc.receive_window(), 1000);
        assert_eq!(fc.send_window(), 1000);

        fc.consume(500).unwrap();
        assert_eq!(fc.receive_window(), 500);

        fc.send(300).unwrap();
        assert_eq!(fc.send_window(), 700);
    }

    #[test]
    fn test_flow_control_blocked() {
        let mut fc = FlowControl::new(100, 100);
        fc.consume(100).unwrap();
        assert!(fc.receive_blocked());
        assert!(fc.consume(1).is_err());
    }

    #[test]
    fn test_connection_new() {
        let config = test_config();
        let source = ConnectionId::generate(8).unwrap();
        let dest = ConnectionId::generate(8).unwrap();
        let remote: SocketAddr = "127.0.0.1:443".parse().unwrap();
        let local: SocketAddr = "127.0.0.1:12345".parse().unwrap();

        let conn = Connection::new(source.clone(), dest.clone(), remote, local, false, &config);

        assert_eq!(conn.state(), ConnectionState::Initial);
        assert!(!conn.is_server());
        assert_eq!(conn.remote_addr, remote);
    }

    #[test]
    fn test_connection_open_streams() {
        let config = test_config();
        let source = ConnectionId::generate(8).unwrap();
        let dest = ConnectionId::generate(8).unwrap();
        let remote: SocketAddr = "127.0.0.1:443".parse().unwrap();
        let local: SocketAddr = "127.0.0.1:12345".parse().unwrap();

        let mut conn = Connection::new(source, dest, remote, local, false, &config);
        conn.set_state(ConnectionState::Connected);

        let stream1 = conn.open_bidirectional_stream().unwrap();
        let stream2 = conn.open_bidirectional_stream().unwrap();

        assert_ne!(stream1, stream2);
        assert_eq!(conn.stream_count(), 2);
    }

    #[test]
    fn test_connection_close() {
        let config = test_config();
        let source = ConnectionId::generate(8).unwrap();
        let dest = ConnectionId::generate(8).unwrap();
        let remote: SocketAddr = "127.0.0.1:443".parse().unwrap();
        let local: SocketAddr = "127.0.0.1:12345".parse().unwrap();

        let mut conn = Connection::new(source, dest, remote, local, false, &config);
        conn.set_state(ConnectionState::Connected);

        conn.close(CloseReason::no_error());

        assert_eq!(conn.state(), ConnectionState::Closing);
        assert!(conn.close_reason().is_some());
    }

    #[test]
    fn test_connection_stats() {
        let stats = ConnectionStats {
            packets_sent: 100,
            packets_lost: 5,
            ..ConnectionStats::default()
        };

        assert!((stats.loss_rate() - 0.05).abs() < 0.001);
    }
}
