//! Heartbeat mechanism for module liveness detection.

use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::sync::mpsc;
use tokio::time::interval;
use tracing::{debug, warn};

use super::client::{IpcClient, IpcClientError};
use super::message::ResponseStatus;

/// Configuration for heartbeat monitoring.
#[derive(Debug, Clone)]
pub struct HeartbeatConfig {
    /// Interval between heartbeat checks.
    pub interval: Duration,

    /// Timeout for individual heartbeat requests.
    pub timeout: Duration,

    /// Number of consecutive failures before marking unhealthy.
    pub failure_threshold: u32,
}

impl Default for HeartbeatConfig {
    fn default() -> Self {
        Self {
            interval: Duration::from_secs(5),
            timeout: Duration::from_secs(2),
            failure_threshold: 3,
        }
    }
}

/// Heartbeat monitor for a single module.
pub struct HeartbeatMonitor {
    /// The IPC client to use for heartbeat checks.
    client: IpcClient,

    /// Configuration.
    config: HeartbeatConfig,

    /// Whether the module is currently healthy.
    is_healthy: Arc<AtomicBool>,

    /// Consecutive failure count.
    failure_count: Arc<AtomicU64>,

    /// Last successful heartbeat time (Unix millis).
    last_success: Arc<AtomicU64>,

    /// Shutdown signal sender.
    shutdown_tx: Option<mpsc::Sender<()>>,
}

impl HeartbeatMonitor {
    /// Creates a new heartbeat monitor.
    #[must_use]
    pub fn new(client: IpcClient, config: HeartbeatConfig) -> Self {
        Self {
            client,
            config,
            is_healthy: Arc::new(AtomicBool::new(false)),
            failure_count: Arc::new(AtomicU64::new(0)),
            last_success: Arc::new(AtomicU64::new(0)),
            shutdown_tx: None,
        }
    }

    /// Returns whether the module is currently healthy.
    #[must_use]
    pub fn is_healthy(&self) -> bool {
        self.is_healthy.load(Ordering::SeqCst)
    }

    /// Returns the current consecutive failure count.
    #[must_use]
    pub fn failure_count(&self) -> u64 {
        self.failure_count.load(Ordering::SeqCst)
    }

    /// Returns the last successful heartbeat time as Unix milliseconds.
    #[must_use]
    pub fn last_success_time(&self) -> u64 {
        self.last_success.load(Ordering::SeqCst)
    }

    /// Performs a single heartbeat check.
    ///
    /// # Errors
    ///
    /// Returns an error if the heartbeat fails.
    pub async fn check(&self) -> Result<Duration, HeartbeatError> {
        let start = Instant::now();

        match self.client.heartbeat().await {
            Ok(response) if response.status.is_success() => {
                let elapsed = start.elapsed();
                self.record_success();
                Ok(elapsed)
            },
            Ok(response) => {
                self.record_failure();
                Err(HeartbeatError::UnhealthyResponse(response.status))
            },
            Err(e) => {
                self.record_failure();
                Err(HeartbeatError::ClientError(e))
            },
        }
    }

    /// Records a successful heartbeat.
    fn record_success(&self) {
        use std::time::{SystemTime, UNIX_EPOCH};

        self.failure_count.store(0, Ordering::SeqCst);
        self.is_healthy.store(true, Ordering::SeqCst);

        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_millis() as u64)
            .unwrap_or(0);
        self.last_success.store(now, Ordering::SeqCst);
    }

    /// Records a failed heartbeat.
    fn record_failure(&self) {
        let failures = self.failure_count.fetch_add(1, Ordering::SeqCst) + 1;

        if failures >= u64::from(self.config.failure_threshold) {
            self.is_healthy.store(false, Ordering::SeqCst);
        }
    }

    /// Starts the heartbeat monitoring loop.
    ///
    /// This runs until `stop()` is called.
    pub async fn start(&mut self) {
        let (shutdown_tx, mut shutdown_rx) = mpsc::channel::<()>(1);
        self.shutdown_tx = Some(shutdown_tx);

        let mut ticker = interval(self.config.interval);

        loop {
            tokio::select! {
                _ = ticker.tick() => {
                    match self.check().await {
                        Ok(latency) => {
                            debug!("Heartbeat OK, latency: {:?}", latency);
                        }
                        Err(e) => {
                            let failures = self.failure_count();
                            warn!(
                                "Heartbeat failed ({}/{} failures): {}",
                                failures, self.config.failure_threshold, e
                            );
                        }
                    }
                }
                _ = shutdown_rx.recv() => {
                    debug!("Heartbeat monitor shutting down");
                    break;
                }
            }
        }
    }

    /// Stops the heartbeat monitoring loop.
    pub async fn stop(&self) {
        if let Some(tx) = &self.shutdown_tx {
            let _ = tx.send(()).await;
        }
    }
}

/// Errors that can occur during heartbeat checks.
#[derive(Debug, thiserror::Error)]
pub enum HeartbeatError {
    /// The heartbeat response indicated an unhealthy status.
    #[error("unhealthy response: {0:?}")]
    UnhealthyResponse(ResponseStatus),

    /// IPC client error.
    #[error("client error: {0}")]
    ClientError(#[from] IpcClientError),
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::tempdir;

    #[test]
    fn test_heartbeat_config_default() {
        let config = HeartbeatConfig::default();
        assert_eq!(config.interval, Duration::from_secs(5));
        assert_eq!(config.timeout, Duration::from_secs(2));
        assert_eq!(config.failure_threshold, 3);
    }

    #[test]
    fn test_heartbeat_monitor_initial_state() {
        let dir = tempdir().unwrap();
        let socket_path = dir.path().join("test.sock");
        let client = IpcClient::new(&socket_path);
        let monitor = HeartbeatMonitor::new(client, HeartbeatConfig::default());

        assert!(!monitor.is_healthy());
        assert_eq!(monitor.failure_count(), 0);
        assert_eq!(monitor.last_success_time(), 0);
    }
}
