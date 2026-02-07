//! TLS connection handling.

use std::net::SocketAddr;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::Instant;

use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio_rustls::server::TlsStream;
use tracing::{debug, trace};

use super::error::{TlsError, TlsResult};

/// Counter for generating connection IDs.
static NEXT_CONNECTION_ID: AtomicU64 = AtomicU64::new(1);

/// A TLS connection after handshake.
#[allow(dead_code)]
pub struct TlsConnection {
    /// The TLS stream.
    stream: TlsStream<TcpStream>,

    /// Peer address.
    peer_addr: SocketAddr,

    /// Local address.
    local_addr: SocketAddr,

    /// Connection ID.
    id: u64,

    /// Connection creation time.
    created_at: Instant,

    /// SNI name from handshake.
    sni_name: Option<String>,
}

impl TlsConnection {
    /// Create a new TLS connection.
    pub fn new(
        stream: TlsStream<TcpStream>,
        peer_addr: SocketAddr,
        local_addr: SocketAddr,
        sni_name: Option<String>,
    ) -> Self {
        Self {
            stream,
            peer_addr,
            local_addr,
            id: NEXT_CONNECTION_ID.fetch_add(1, Ordering::Relaxed),
            created_at: Instant::now(),
            sni_name,
        }
    }

    /// Get the connection ID.
    #[must_use]
    pub fn id(&self) -> u64 {
        self.id
    }

    /// Get the peer address.
    #[must_use]
    #[allow(dead_code)]
    pub fn peer_addr(&self) -> SocketAddr {
        self.peer_addr
    }

    /// Get the local address.
    #[must_use]
    #[allow(dead_code)]
    pub fn local_addr(&self) -> SocketAddr {
        self.local_addr
    }

    /// Get the SNI name.
    #[must_use]
    #[allow(dead_code)]
    pub fn sni_name(&self) -> Option<&str> {
        self.sni_name.as_deref()
    }

    /// Get the connection age.
    #[must_use]
    #[allow(dead_code)]
    pub fn age(&self) -> std::time::Duration {
        self.created_at.elapsed()
    }

    /// Get a reference to the underlying stream.
    #[must_use]
    pub fn stream(&mut self) -> &mut TlsStream<TcpStream> {
        &mut self.stream
    }

    /// Consume the connection and return the stream.
    #[must_use]
    #[allow(dead_code)]
    pub fn into_stream(self) -> TlsStream<TcpStream> {
        self.stream
    }
}

impl std::fmt::Debug for TlsConnection {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("TlsConnection")
            .field("id", &self.id)
            .field("peer", &self.peer_addr)
            .field("local", &self.local_addr)
            .field("sni", &self.sni_name)
            .finish()
    }
}

/// Connection statistics.
#[derive(Debug, Clone, Default)]
pub struct ConnectionStats {
    /// Total connections accepted.
    pub total_connections: u64,

    /// Active connections.
    pub active_connections: u64,

    /// Successful handshakes.
    pub successful_handshakes: u64,

    /// Failed handshakes.
    pub failed_handshakes: u64,

    /// Bytes read.
    pub bytes_read: u64,

    /// Bytes written.
    pub bytes_written: u64,
}

/// Atomic connection statistics.
#[derive(Debug, Default)]
pub struct AtomicConnectionStats {
    total_connections: AtomicU64,
    active_connections: AtomicU64,
    successful_handshakes: AtomicU64,
    failed_handshakes: AtomicU64,
    bytes_read: AtomicU64,
    bytes_written: AtomicU64,
}

impl AtomicConnectionStats {
    /// Create new atomic stats.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Record a new connection.
    pub fn record_connection(&self) {
        self.total_connections.fetch_add(1, Ordering::Relaxed);
        self.active_connections.fetch_add(1, Ordering::Relaxed);
    }

    /// Record connection closed.
    pub fn record_connection_closed(&self) {
        self.active_connections.fetch_sub(1, Ordering::Relaxed);
    }

    /// Record successful handshake.
    pub fn record_handshake_success(&self) {
        self.successful_handshakes.fetch_add(1, Ordering::Relaxed);
    }

    /// Record failed handshake.
    pub fn record_handshake_failure(&self) {
        self.failed_handshakes.fetch_add(1, Ordering::Relaxed);
    }

    /// Record bytes read.
    pub fn record_bytes_read(&self, bytes: u64) {
        self.bytes_read.fetch_add(bytes, Ordering::Relaxed);
    }

    /// Record bytes written.
    pub fn record_bytes_written(&self, bytes: u64) {
        self.bytes_written.fetch_add(bytes, Ordering::Relaxed);
    }

    /// Get current statistics.
    #[must_use]
    pub fn snapshot(&self) -> ConnectionStats {
        ConnectionStats {
            total_connections: self.total_connections.load(Ordering::Relaxed),
            active_connections: self.active_connections.load(Ordering::Relaxed),
            successful_handshakes: self.successful_handshakes.load(Ordering::Relaxed),
            failed_handshakes: self.failed_handshakes.load(Ordering::Relaxed),
            bytes_read: self.bytes_read.load(Ordering::Relaxed),
            bytes_written: self.bytes_written.load(Ordering::Relaxed),
        }
    }
}

/// Proxy data between a TLS connection and a backend.
///
/// # Errors
///
/// Returns an error if the proxy operation fails.
pub async fn proxy_to_backend(
    mut tls_conn: TlsConnection,
    backend_addr: SocketAddr,
    stats: &Arc<AtomicConnectionStats>,
) -> TlsResult<(u64, u64)> {
    debug!(
        conn_id = tls_conn.id(),
        backend = %backend_addr,
        "Proxying to backend"
    );

    let mut backend = TcpStream::connect(backend_addr)
        .await
        .map_err(TlsError::IoError)?;

    let tls_stream = tls_conn.stream();
    let (mut tls_read, mut tls_write) = tokio::io::split(tls_stream);
    let (mut backend_read, mut backend_write) = backend.split();

    let stats_clone = Arc::clone(stats);
    let client_to_backend = async {
        let mut buf = [0u8; 8192];
        let mut total = 0u64;
        loop {
            let n = tls_read.read(&mut buf).await?;
            if n == 0 {
                break;
            }
            backend_write.write_all(&buf[..n]).await?;
            total += n as u64;
            stats_clone.record_bytes_read(n as u64);
        }
        Ok::<_, std::io::Error>(total)
    };

    let stats_clone = Arc::clone(stats);
    let backend_to_client = async {
        let mut buf = [0u8; 8192];
        let mut total = 0u64;
        loop {
            let n = backend_read.read(&mut buf).await?;
            if n == 0 {
                break;
            }
            tls_write.write_all(&buf[..n]).await?;
            total += n as u64;
            stats_clone.record_bytes_written(n as u64);
        }
        Ok::<_, std::io::Error>(total)
    };

    let (result_a, result_b) = tokio::join!(client_to_backend, backend_to_client);

    let bytes_in = result_a.unwrap_or(0);
    let bytes_out = result_b.unwrap_or(0);

    debug!(
        conn_id = tls_conn.id(),
        bytes_in, bytes_out, "Proxy completed"
    );

    Ok((bytes_in, bytes_out))
}

/// Passthrough encrypted traffic without termination.
///
/// # Errors
///
/// Returns an error if the passthrough operation fails.
pub async fn passthrough_connection(
    mut client: TcpStream,
    backend_addr: SocketAddr,
    initial_data: &[u8],
    stats: &Arc<AtomicConnectionStats>,
) -> TlsResult<(u64, u64)> {
    debug!(
        backend = %backend_addr,
        initial_bytes = initial_data.len(),
        "TLS passthrough to backend"
    );

    let mut backend = TcpStream::connect(backend_addr)
        .await
        .map_err(TlsError::IoError)?;

    // Send initial data (Client Hello) to backend
    backend
        .write_all(initial_data)
        .await
        .map_err(TlsError::IoError)?;

    let (mut client_read, mut client_write) = client.split();
    let (mut backend_read, mut backend_write) = backend.split();

    let stats_clone = Arc::clone(stats);
    let client_to_backend = async {
        let mut buf = [0u8; 8192];
        let mut total = initial_data.len() as u64;
        loop {
            let n = client_read.read(&mut buf).await?;
            if n == 0 {
                break;
            }
            backend_write.write_all(&buf[..n]).await?;
            total += n as u64;
            stats_clone.record_bytes_read(n as u64);
        }
        Ok::<_, std::io::Error>(total)
    };

    let stats_clone = Arc::clone(stats);
    let backend_to_client = async {
        let mut buf = [0u8; 8192];
        let mut total = 0u64;
        loop {
            let n = backend_read.read(&mut buf).await?;
            if n == 0 {
                break;
            }
            client_write.write_all(&buf[..n]).await?;
            total += n as u64;
            stats_clone.record_bytes_written(n as u64);
        }
        Ok::<_, std::io::Error>(total)
    };

    let (result_a, result_b) = tokio::join!(client_to_backend, backend_to_client);

    let bytes_in = result_a.unwrap_or(0);
    let bytes_out = result_b.unwrap_or(0);

    trace!(bytes_in, bytes_out, "Passthrough completed");

    Ok((bytes_in, bytes_out))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_atomic_stats() {
        let stats = AtomicConnectionStats::new();

        stats.record_connection();
        stats.record_handshake_success();
        stats.record_bytes_read(100);
        stats.record_bytes_written(200);

        let snapshot = stats.snapshot();
        assert_eq!(snapshot.total_connections, 1);
        assert_eq!(snapshot.active_connections, 1);
        assert_eq!(snapshot.successful_handshakes, 1);
        assert_eq!(snapshot.bytes_read, 100);
        assert_eq!(snapshot.bytes_written, 200);

        stats.record_connection_closed();
        let snapshot = stats.snapshot();
        assert_eq!(snapshot.active_connections, 0);
    }

    #[test]
    fn test_connection_stats_default() {
        let stats = ConnectionStats::default();
        assert_eq!(stats.total_connections, 0);
        assert_eq!(stats.active_connections, 0);
    }
}
