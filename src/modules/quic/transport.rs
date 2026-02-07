//! QUIC transport layer

use super::config::QuicConfig;
use super::connection::{Connection, ConnectionHandle, ConnectionId};
use super::error::QuicResult;
use crate::module::{
    Capability, MetricsPayload, ModuleConfig, ModuleContract, ModuleError, ModuleManifest,
    ModuleResult, ModuleStatus,
};
use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::Arc;
use tokio::sync::RwLock;

/// QUIC transport
pub struct QuicTransport {
    /// Configuration
    config: QuicConfig,

    /// Active connections by source connection ID
    connections: Arc<RwLock<HashMap<ConnectionId, ConnectionHandle>>>,

    /// Connection ID to address mapping
    addr_to_cid: Arc<RwLock<HashMap<SocketAddr, ConnectionId>>>,

    /// Running state
    running: AtomicBool,

    /// Connection counter
    #[allow(dead_code)]
    connection_counter: AtomicU64,

    /// Total bytes sent
    bytes_sent: AtomicU64,

    /// Total bytes received
    bytes_received: AtomicU64,

    /// Total connections accepted
    connections_accepted: AtomicU64,

    /// Total connections established
    connections_established: AtomicU64,

    /// Total connections closed
    connections_closed: AtomicU64,

    /// Handshake failures
    handshake_failures: AtomicU64,

    /// 0-RTT connections
    zero_rtt_connections: AtomicU64,
}

impl QuicTransport {
    /// Create new transport
    pub fn new(config: QuicConfig) -> Self {
        Self {
            config,
            connections: Arc::new(RwLock::new(HashMap::new())),
            addr_to_cid: Arc::new(RwLock::new(HashMap::new())),
            running: AtomicBool::new(false),
            connection_counter: AtomicU64::new(0),
            bytes_sent: AtomicU64::new(0),
            bytes_received: AtomicU64::new(0),
            connections_accepted: AtomicU64::new(0),
            connections_established: AtomicU64::new(0),
            connections_closed: AtomicU64::new(0),
            handshake_failures: AtomicU64::new(0),
            zero_rtt_connections: AtomicU64::new(0),
        }
    }

    /// Get configuration
    pub fn config(&self) -> &QuicConfig {
        &self.config
    }

    /// Check if running
    pub fn is_running(&self) -> bool {
        self.running.load(Ordering::SeqCst)
    }

    /// Get connection by ID
    pub async fn get_connection(&self, cid: &ConnectionId) -> Option<ConnectionHandle> {
        let conns = self.connections.read().await;
        conns.get(cid).cloned()
    }

    /// Get connection by address
    pub async fn get_connection_by_addr(&self, addr: &SocketAddr) -> Option<ConnectionHandle> {
        let addr_map = self.addr_to_cid.read().await;
        if let Some(cid) = addr_map.get(addr) {
            self.get_connection(cid).await
        } else {
            None
        }
    }

    /// Get connection count
    pub async fn connection_count(&self) -> usize {
        self.connections.read().await.len()
    }

    /// Accept new connection
    pub async fn accept_connection(
        &self,
        source_cid: ConnectionId,
        destination_cid: ConnectionId,
        remote_addr: SocketAddr,
        local_addr: SocketAddr,
    ) -> QuicResult<ConnectionHandle> {
        let connection = Connection::new(
            source_cid.clone(),
            destination_cid,
            remote_addr,
            local_addr,
            true, // is_server
            &self.config,
        );

        let handle = Arc::new(RwLock::new(connection));

        {
            let mut conns = self.connections.write().await;
            conns.insert(source_cid.clone(), handle.clone());
        }

        {
            let mut addr_map = self.addr_to_cid.write().await;
            addr_map.insert(remote_addr, source_cid);
        }

        self.connections_accepted.fetch_add(1, Ordering::SeqCst);

        Ok(handle)
    }

    /// Create outbound connection
    pub async fn connect(
        &self,
        remote_addr: SocketAddr,
        local_addr: SocketAddr,
    ) -> QuicResult<ConnectionHandle> {
        let source_cid = ConnectionId::generate(8)?;
        let destination_cid = ConnectionId::generate(8)?;

        let connection = Connection::new(
            source_cid.clone(),
            destination_cid,
            remote_addr,
            local_addr,
            false, // is_client
            &self.config,
        );

        let handle = Arc::new(RwLock::new(connection));

        {
            let mut conns = self.connections.write().await;
            conns.insert(source_cid.clone(), handle.clone());
        }

        {
            let mut addr_map = self.addr_to_cid.write().await;
            addr_map.insert(remote_addr, source_cid);
        }

        Ok(handle)
    }

    /// Remove connection
    pub async fn remove_connection(&self, cid: &ConnectionId) -> Option<ConnectionHandle> {
        let handle = {
            let mut conns = self.connections.write().await;
            conns.remove(cid)
        };

        if let Some(ref h) = handle {
            let conn = h.read().await;
            let mut addr_map = self.addr_to_cid.write().await;
            addr_map.remove(&conn.remote_addr);
            self.connections_closed.fetch_add(1, Ordering::SeqCst);
        }

        handle
    }

    /// Mark connection as established
    pub fn on_connection_established(&self) {
        self.connections_established.fetch_add(1, Ordering::SeqCst);
    }

    /// Record handshake failure
    pub fn on_handshake_failure(&self) {
        self.handshake_failures.fetch_add(1, Ordering::SeqCst);
    }

    /// Record 0-RTT connection
    pub fn on_zero_rtt_connection(&self) {
        self.zero_rtt_connections.fetch_add(1, Ordering::SeqCst);
    }

    /// Record bytes sent
    pub fn record_bytes_sent(&self, bytes: u64) {
        self.bytes_sent.fetch_add(bytes, Ordering::SeqCst);
    }

    /// Record bytes received
    pub fn record_bytes_received(&self, bytes: u64) {
        self.bytes_received.fetch_add(bytes, Ordering::SeqCst);
    }

    /// Cleanup timed-out connections
    pub async fn cleanup_idle_connections(&self) -> usize {
        let mut to_remove = Vec::new();

        {
            let conns = self.connections.read().await;
            for (cid, handle) in conns.iter() {
                let conn = handle.read().await;
                if conn.is_timed_out() || conn.state().is_closed() {
                    to_remove.push(cid.clone());
                }
            }
        }

        let count = to_remove.len();
        for cid in to_remove {
            self.remove_connection(&cid).await;
        }

        count
    }

    /// Get all connection IDs
    pub async fn connection_ids(&self) -> Vec<ConnectionId> {
        self.connections.read().await.keys().cloned().collect()
    }

    /// Iterate over connections
    pub async fn for_each_connection<F>(&self, mut f: F)
    where
        F: FnMut(&ConnectionId, &ConnectionHandle),
    {
        let conns = self.connections.read().await;
        for (cid, handle) in conns.iter() {
            f(cid, handle);
        }
    }
}

impl std::fmt::Debug for QuicTransport {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("QuicTransport")
            .field("running", &self.is_running())
            .field("bytes_sent", &self.bytes_sent.load(Ordering::SeqCst))
            .field(
                "bytes_received",
                &self.bytes_received.load(Ordering::SeqCst),
            )
            .finish()
    }
}

/// QUIC handler implementing ModuleContract
pub struct QuicHandler {
    /// Transport
    transport: Option<QuicTransport>,

    /// Initialized flag
    initialized: bool,
}

impl QuicHandler {
    /// Create new handler
    pub fn new() -> Self {
        Self {
            transport: None,
            initialized: false,
        }
    }

    /// Get transport
    pub fn transport(&self) -> Option<&QuicTransport> {
        self.transport.as_ref()
    }
}

impl Default for QuicHandler {
    fn default() -> Self {
        Self::new()
    }
}

impl ModuleContract for QuicHandler {
    fn manifest(&self) -> ModuleManifest {
        ModuleManifest::builder("quic")
            .description("QUIC transport layer (RFC 9000)")
            .version(1, 0, 0)
            .capability(Capability::Custom("QuicTransport".to_string()))
            .capability(Capability::Custom("ZeroRtt".to_string()))
            .capability(Capability::Custom("ConnectionMigration".to_string()))
            .build()
    }

    fn init(&mut self, _config: ModuleConfig) -> ModuleResult<()> {
        // Config parsing would need raw string access or get methods
        // For now, use defaults
        self.transport = Some(QuicTransport::new(QuicConfig::default()));
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

        if let Some(ref transport) = self.transport {
            transport.running.store(true, Ordering::SeqCst);
        }

        Ok(())
    }

    fn stop(&mut self) -> ModuleResult<()> {
        if let Some(ref transport) = self.transport {
            transport.running.store(false, Ordering::SeqCst);
        }

        Ok(())
    }

    fn status(&self) -> ModuleStatus {
        if !self.initialized {
            ModuleStatus::Stopped
        } else if let Some(ref t) = self.transport {
            if t.is_running() {
                ModuleStatus::Running
            } else {
                ModuleStatus::Stopped
            }
        } else {
            ModuleStatus::Stopped
        }
    }

    fn metrics(&self) -> MetricsPayload {
        let mut payload = MetricsPayload::new();

        if let Some(ref transport) = self.transport {
            payload.counter("bytes_sent", transport.bytes_sent.load(Ordering::SeqCst));
            payload.counter(
                "bytes_received",
                transport.bytes_received.load(Ordering::SeqCst),
            );
            payload.counter(
                "connections_accepted",
                transport.connections_accepted.load(Ordering::SeqCst),
            );
            payload.counter(
                "connections_established",
                transport.connections_established.load(Ordering::SeqCst),
            );
            payload.counter(
                "connections_closed",
                transport.connections_closed.load(Ordering::SeqCst),
            );
            payload.counter(
                "handshake_failures",
                transport.handshake_failures.load(Ordering::SeqCst),
            );
            payload.counter(
                "zero_rtt_connections",
                transport.zero_rtt_connections.load(Ordering::SeqCst),
            );
        }

        payload
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::modules::quic::connection::ConnectionState;

    #[tokio::test]
    async fn test_transport_new() {
        let config = QuicConfig::default();
        let transport = QuicTransport::new(config);
        assert!(!transport.is_running());
        assert_eq!(transport.connection_count().await, 0);
    }

    #[tokio::test]
    async fn test_transport_accept_connection() {
        let config = QuicConfig::default();
        let transport = QuicTransport::new(config);

        let source_cid = ConnectionId::generate(8).unwrap();
        let dest_cid = ConnectionId::generate(8).unwrap();
        let remote: SocketAddr = "127.0.0.1:443".parse().unwrap();
        let local: SocketAddr = "127.0.0.1:12345".parse().unwrap();

        let handle = transport
            .accept_connection(source_cid.clone(), dest_cid, remote, local)
            .await
            .unwrap();

        assert_eq!(transport.connection_count().await, 1);

        let conn = handle.read().await;
        assert!(conn.is_server());
        assert_eq!(conn.state(), ConnectionState::Initial);
    }

    #[tokio::test]
    async fn test_transport_connect() {
        let config = QuicConfig::default();
        let transport = QuicTransport::new(config);

        let remote: SocketAddr = "127.0.0.1:443".parse().unwrap();
        let local: SocketAddr = "127.0.0.1:12345".parse().unwrap();

        let handle = transport.connect(remote, local).await.unwrap();

        let conn = handle.read().await;
        assert!(!conn.is_server());
    }

    #[tokio::test]
    async fn test_transport_get_connection_by_addr() {
        let config = QuicConfig::default();
        let transport = QuicTransport::new(config);

        let source_cid = ConnectionId::generate(8).unwrap();
        let dest_cid = ConnectionId::generate(8).unwrap();
        let remote: SocketAddr = "127.0.0.1:443".parse().unwrap();
        let local: SocketAddr = "127.0.0.1:12345".parse().unwrap();

        transport
            .accept_connection(source_cid.clone(), dest_cid, remote, local)
            .await
            .unwrap();

        let found = transport.get_connection_by_addr(&remote).await;
        assert!(found.is_some());
    }

    #[tokio::test]
    async fn test_transport_remove_connection() {
        let config = QuicConfig::default();
        let transport = QuicTransport::new(config);

        let source_cid = ConnectionId::generate(8).unwrap();
        let dest_cid = ConnectionId::generate(8).unwrap();
        let remote: SocketAddr = "127.0.0.1:443".parse().unwrap();
        let local: SocketAddr = "127.0.0.1:12345".parse().unwrap();

        transport
            .accept_connection(source_cid.clone(), dest_cid, remote, local)
            .await
            .unwrap();

        let removed = transport.remove_connection(&source_cid).await;
        assert!(removed.is_some());
        assert_eq!(transport.connection_count().await, 0);
    }

    #[tokio::test]
    async fn test_transport_metrics() {
        let config = QuicConfig::default();
        let transport = QuicTransport::new(config);

        transport.record_bytes_sent(1000);
        transport.record_bytes_received(2000);
        transport.on_connection_established();

        assert_eq!(transport.bytes_sent.load(Ordering::SeqCst), 1000);
        assert_eq!(transport.bytes_received.load(Ordering::SeqCst), 2000);
        assert_eq!(transport.connections_established.load(Ordering::SeqCst), 1);
    }

    #[test]
    fn test_handler_manifest() {
        let handler = QuicHandler::new();
        let manifest = handler.manifest();
        assert_eq!(manifest.name, "quic");
    }

    #[test]
    fn test_handler_init() {
        let mut handler = QuicHandler::new();
        let config = ModuleConfig::new();

        handler.init(config).unwrap();
        assert!(handler.initialized);
        assert!(handler.transport.is_some());
    }

    #[test]
    fn test_handler_lifecycle() {
        let mut handler = QuicHandler::new();
        let config = ModuleConfig::new();

        handler.init(config).unwrap();

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
        let mut handler = QuicHandler::new();
        handler.init(ModuleConfig::new()).unwrap();

        if let Some(ref transport) = handler.transport {
            transport.record_bytes_sent(500);
        }

        let metrics = handler.metrics();
        assert!(metrics.counters.contains_key("bytes_sent"));
    }
}
