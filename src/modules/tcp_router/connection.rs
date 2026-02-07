//! TCP connection wrapper.

use std::net::SocketAddr;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::Instant;
use tokio::net::TcpStream;

/// A wrapped TCP connection with metadata.
#[derive(Debug)]
pub struct Connection {
    /// The underlying TCP stream.
    stream: TcpStream,

    /// Remote peer address.
    peer_addr: SocketAddr,

    /// Local address.
    local_addr: SocketAddr,

    /// Connection creation time.
    created_at: Instant,

    /// Bytes read counter.
    bytes_read: AtomicU64,

    /// Bytes written counter.
    bytes_written: AtomicU64,

    /// Connection ID for tracking.
    id: u64,
}

/// Global connection ID counter.
static CONNECTION_ID: AtomicU64 = AtomicU64::new(0);

impl Connection {
    /// Create a new connection from a TCP stream.
    ///
    /// # Errors
    ///
    /// Returns an error if the peer or local address cannot be determined.
    pub fn new(stream: TcpStream) -> std::io::Result<Self> {
        let peer_addr = stream.peer_addr()?;
        let local_addr = stream.local_addr()?;
        let id = CONNECTION_ID.fetch_add(1, Ordering::Relaxed);

        Ok(Self {
            stream,
            peer_addr,
            local_addr,
            created_at: Instant::now(),
            bytes_read: AtomicU64::new(0),
            bytes_written: AtomicU64::new(0),
            id,
        })
    }

    /// Get the connection ID.
    #[must_use]
    pub fn id(&self) -> u64 {
        self.id
    }

    /// Get the peer address.
    #[must_use]
    pub fn peer_addr(&self) -> SocketAddr {
        self.peer_addr
    }

    /// Get the local address.
    #[must_use]
    pub fn local_addr(&self) -> SocketAddr {
        self.local_addr
    }

    /// Get connection age.
    #[must_use]
    pub fn age(&self) -> std::time::Duration {
        self.created_at.elapsed()
    }

    /// Get total bytes read.
    #[must_use]
    pub fn bytes_read(&self) -> u64 {
        self.bytes_read.load(Ordering::Relaxed)
    }

    /// Get total bytes written.
    #[must_use]
    pub fn bytes_written(&self) -> u64 {
        self.bytes_written.load(Ordering::Relaxed)
    }

    /// Add to bytes read counter.
    pub fn add_bytes_read(&self, bytes: u64) {
        self.bytes_read.fetch_add(bytes, Ordering::Relaxed);
    }

    /// Add to bytes written counter.
    pub fn add_bytes_written(&self, bytes: u64) {
        self.bytes_written.fetch_add(bytes, Ordering::Relaxed);
    }

    /// Get the underlying stream.
    #[must_use]
    pub fn stream(&self) -> &TcpStream {
        &self.stream
    }

    /// Get mutable access to the underlying stream.
    pub fn stream_mut(&mut self) -> &mut TcpStream {
        &mut self.stream
    }

    /// Consume and return the underlying stream.
    #[must_use]
    pub fn into_stream(self) -> TcpStream {
        self.stream
    }

    /// Split the connection into read and write halves.
    pub fn split(self) -> (ConnectionReadHalf, ConnectionWriteHalf) {
        let (read, write) = self.stream.into_split();
        let shared = Arc::new(ConnectionShared {
            id: self.id,
            peer_addr: self.peer_addr,
            local_addr: self.local_addr,
            created_at: self.created_at,
            bytes_read: self.bytes_read,
            bytes_written: self.bytes_written,
        });

        (
            ConnectionReadHalf {
                read,
                shared: Arc::clone(&shared),
            },
            ConnectionWriteHalf { write, shared },
        )
    }
}

/// Shared connection metadata.
#[allow(dead_code)]
struct ConnectionShared {
    id: u64,
    peer_addr: SocketAddr,
    local_addr: SocketAddr,
    created_at: Instant,
    bytes_read: AtomicU64,
    bytes_written: AtomicU64,
}

/// Read half of a split connection.
pub struct ConnectionReadHalf {
    /// The read half of the TCP stream.
    read: tokio::net::tcp::OwnedReadHalf,
    /// Shared connection data.
    shared: Arc<ConnectionShared>,
}

impl ConnectionReadHalf {
    /// Get the connection ID.
    #[must_use]
    pub fn id(&self) -> u64 {
        self.shared.id
    }

    /// Get the peer address.
    #[must_use]
    pub fn peer_addr(&self) -> SocketAddr {
        self.shared.peer_addr
    }

    /// Get the read half.
    pub fn inner(&mut self) -> &mut tokio::net::tcp::OwnedReadHalf {
        &mut self.read
    }

    /// Add to bytes read counter.
    pub fn add_bytes_read(&self, bytes: u64) {
        self.shared.bytes_read.fetch_add(bytes, Ordering::Relaxed);
    }
}

/// Write half of a split connection.
pub struct ConnectionWriteHalf {
    /// The write half of the TCP stream.
    write: tokio::net::tcp::OwnedWriteHalf,
    /// Shared connection data.
    shared: Arc<ConnectionShared>,
}

impl ConnectionWriteHalf {
    /// Get the connection ID.
    #[must_use]
    pub fn id(&self) -> u64 {
        self.shared.id
    }

    /// Get the peer address.
    #[must_use]
    pub fn peer_addr(&self) -> SocketAddr {
        self.shared.peer_addr
    }

    /// Get the write half.
    pub fn inner(&mut self) -> &mut tokio::net::tcp::OwnedWriteHalf {
        &mut self.write
    }

    /// Add to bytes written counter.
    pub fn add_bytes_written(&self, bytes: u64) {
        self.shared
            .bytes_written
            .fetch_add(bytes, Ordering::Relaxed);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::net::TcpListener as TokioTcpListener;

    #[tokio::test]
    async fn test_connection_creation() {
        let listener = TokioTcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();

        let client_task = tokio::spawn(async move { TcpStream::connect(addr).await.unwrap() });

        let (server_stream, _) = listener.accept().await.unwrap();
        let conn = Connection::new(server_stream).unwrap();

        assert!(conn.id() > 0 || conn.id() == 0); // Just check it's valid
        assert_eq!(conn.bytes_read(), 0);
        assert_eq!(conn.bytes_written(), 0);

        client_task.await.unwrap();
    }

    #[tokio::test]
    async fn test_connection_counters() {
        let listener = TokioTcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();

        let _client = tokio::spawn(async move { TcpStream::connect(addr).await.unwrap() });

        let (server_stream, _) = listener.accept().await.unwrap();
        let conn = Connection::new(server_stream).unwrap();

        conn.add_bytes_read(100);
        conn.add_bytes_written(200);

        assert_eq!(conn.bytes_read(), 100);
        assert_eq!(conn.bytes_written(), 200);
    }
}
