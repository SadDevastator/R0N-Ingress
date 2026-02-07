//! UDP socket wrapper with statistics.

use std::net::SocketAddr;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::Instant;

use tokio::net::UdpSocket;
use tracing::{debug, info};

use super::config::ListenerConfig;
use super::error::{UdpRouterError, UdpRouterResult};

/// Statistics for a bound socket.
#[derive(Debug, Clone, Default)]
pub struct SocketStats {
    /// Total datagrams received.
    pub datagrams_received: u64,

    /// Total datagrams sent.
    pub datagrams_sent: u64,

    /// Total bytes received.
    pub bytes_received: u64,

    /// Total bytes sent.
    pub bytes_sent: u64,

    /// Receive errors.
    pub recv_errors: u64,

    /// Send errors.
    pub send_errors: u64,

    /// Uptime in seconds.
    pub uptime_seconds: u64,
}

/// Inner statistics (atomic counters).
#[allow(dead_code)]
struct SocketStatsInner {
    datagrams_received: AtomicU64,
    datagrams_sent: AtomicU64,
    bytes_received: AtomicU64,
    bytes_sent: AtomicU64,
    recv_errors: AtomicU64,
    send_errors: AtomicU64,
}

impl Default for SocketStatsInner {
    fn default() -> Self {
        Self {
            datagrams_received: AtomicU64::new(0),
            datagrams_sent: AtomicU64::new(0),
            bytes_received: AtomicU64::new(0),
            bytes_sent: AtomicU64::new(0),
            recv_errors: AtomicU64::new(0),
            send_errors: AtomicU64::new(0),
        }
    }
}

/// A bound UDP socket with metadata and statistics.
pub struct BoundSocket {
    /// The underlying UDP socket.
    socket: Arc<UdpSocket>,

    /// The bound address.
    bound_addr: SocketAddr,

    /// Socket name.
    name: Option<String>,

    /// Creation time.
    created_at: Instant,

    /// Statistics.
    stats: Arc<SocketStatsInner>,
}

impl BoundSocket {
    /// Bind a new UDP socket.
    ///
    /// # Errors
    ///
    /// Returns an error if binding fails.
    pub async fn bind(config: ListenerConfig) -> UdpRouterResult<Self> {
        let addr = config.socket_addr();

        let socket = UdpSocket::bind(addr)
            .await
            .map_err(|e| UdpRouterError::BindError {
                address: addr,
                source: e,
            })?;

        let bound_addr = socket.local_addr().map_err(|e| UdpRouterError::BindError {
            address: addr,
            source: e,
        })?;

        info!(
            name = config.name.as_deref().unwrap_or("unnamed"),
            address = %bound_addr,
            "UDP socket bound"
        );

        Ok(Self {
            socket: Arc::new(socket),
            bound_addr,
            name: config.name,
            created_at: Instant::now(),
            stats: Arc::new(SocketStatsInner::default()),
        })
    }

    /// Get the bound address.
    #[must_use]
    pub fn bound_addr(&self) -> SocketAddr {
        self.bound_addr
    }

    /// Get the local address (alias for bound_addr).
    #[must_use]
    pub fn local_addr(&self) -> SocketAddr {
        self.bound_addr
    }

    /// Get the socket name.
    #[must_use]
    pub fn name(&self) -> Option<&str> {
        self.name.as_deref()
    }

    /// Get a clone of the underlying socket (for sharing across tasks).
    #[must_use]
    pub fn socket(&self) -> Arc<UdpSocket> {
        Arc::clone(&self.socket)
    }

    /// Receive a datagram.
    ///
    /// Returns the number of bytes received and the source address.
    ///
    /// # Errors
    ///
    /// Returns an error if the receive operation fails.
    pub async fn recv_from(&self, buf: &mut [u8]) -> UdpRouterResult<(usize, SocketAddr)> {
        match self.socket.recv_from(buf).await {
            Ok((len, addr)) => {
                self.stats
                    .datagrams_received
                    .fetch_add(1, Ordering::Relaxed);
                self.stats
                    .bytes_received
                    .fetch_add(len as u64, Ordering::Relaxed);
                debug!(len, peer = %addr, "Received datagram");
                Ok((len, addr))
            },
            Err(e) => {
                self.stats.recv_errors.fetch_add(1, Ordering::Relaxed);
                Err(UdpRouterError::RecvError(e))
            },
        }
    }

    /// Send a datagram to a specific address.
    ///
    /// # Errors
    ///
    /// Returns an error if the send operation fails.
    pub async fn send_to(&self, buf: &[u8], target: SocketAddr) -> UdpRouterResult<usize> {
        match self.socket.send_to(buf, target).await {
            Ok(len) => {
                self.stats.datagrams_sent.fetch_add(1, Ordering::Relaxed);
                self.stats
                    .bytes_sent
                    .fetch_add(len as u64, Ordering::Relaxed);
                debug!(len, target = %target, "Sent datagram");
                Ok(len)
            },
            Err(e) => {
                self.stats.send_errors.fetch_add(1, Ordering::Relaxed);
                Err(UdpRouterError::SendError {
                    address: target,
                    source: e,
                })
            },
        }
    }

    /// Get socket statistics.
    #[must_use]
    pub fn stats(&self) -> SocketStats {
        SocketStats {
            datagrams_received: self.stats.datagrams_received.load(Ordering::Relaxed),
            datagrams_sent: self.stats.datagrams_sent.load(Ordering::Relaxed),
            bytes_received: self.stats.bytes_received.load(Ordering::Relaxed),
            bytes_sent: self.stats.bytes_sent.load(Ordering::Relaxed),
            recv_errors: self.stats.recv_errors.load(Ordering::Relaxed),
            send_errors: self.stats.send_errors.load(Ordering::Relaxed),
            uptime_seconds: self.created_at.elapsed().as_secs(),
        }
    }

    /// Get a reference to stats for sharing.
    #[allow(dead_code)]
    fn stats_inner(&self) -> std::sync::Arc<SocketStatsInner> {
        Arc::clone(&self.stats)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_socket_bind() {
        let config = ListenerConfig::new(0); // Port 0 = random available port
        let socket = BoundSocket::bind(config).await.unwrap();

        assert_ne!(socket.bound_addr().port(), 0);
    }

    #[tokio::test]
    async fn test_socket_send_recv() {
        use std::net::{IpAddr, Ipv4Addr};

        // Create two sockets bound to loopback
        let config1 = ListenerConfig::new(0).with_address(IpAddr::V4(Ipv4Addr::LOCALHOST));
        let socket1 = BoundSocket::bind(config1).await.unwrap();

        let config2 = ListenerConfig::new(0).with_address(IpAddr::V4(Ipv4Addr::LOCALHOST));
        let socket2 = BoundSocket::bind(config2).await.unwrap();

        // Send from socket1 to socket2
        let data = b"Hello, UDP!";
        socket1.send_to(data, socket2.bound_addr()).await.unwrap();

        // Receive on socket2
        let mut buf = [0u8; 1024];
        let (len, from) = socket2.recv_from(&mut buf).await.unwrap();

        assert_eq!(&buf[..len], data);
        assert_eq!(from, socket1.bound_addr());

        // Check stats
        let stats1 = socket1.stats();
        assert_eq!(stats1.datagrams_sent, 1);
        assert_eq!(stats1.bytes_sent, data.len() as u64);

        let stats2 = socket2.stats();
        assert_eq!(stats2.datagrams_received, 1);
        assert_eq!(stats2.bytes_received, data.len() as u64);
    }

    #[tokio::test]
    async fn test_socket_stats_initial() {
        let config = ListenerConfig::new(0);
        let socket = BoundSocket::bind(config).await.unwrap();

        let stats = socket.stats();
        assert_eq!(stats.datagrams_received, 0);
        assert_eq!(stats.datagrams_sent, 0);
        assert_eq!(stats.bytes_received, 0);
        assert_eq!(stats.bytes_sent, 0);
    }
}
