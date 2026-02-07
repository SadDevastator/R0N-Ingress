//! Health check system for backend servers.

use super::backend::Backend;
use super::config::{HealthCheckConfig, HealthCheckType};
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
use tokio::net::TcpStream;
use tokio::sync::mpsc;
use tokio::time::timeout;
use tracing::{debug, warn};

/// Health status of a backend.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HealthStatus {
    /// Backend is healthy.
    Healthy,
    /// Backend is unhealthy.
    Unhealthy,
    /// Health status is unknown.
    Unknown,
}

/// Result of a health check.
#[derive(Debug)]
pub struct HealthCheckResult {
    /// Backend address.
    pub address: SocketAddr,
    /// Health status.
    pub status: HealthStatus,
    /// Response time.
    pub response_time: Duration,
    /// Error message if unhealthy.
    pub error: Option<String>,
}

/// Health check executor.
#[derive(Debug)]
pub struct HealthCheck {
    /// Health check configuration.
    config: HealthCheckConfig,
}

impl HealthCheck {
    /// Create a new health checker.
    #[must_use]
    pub fn new(config: HealthCheckConfig) -> Self {
        Self { config }
    }

    /// Check if health checks are enabled.
    #[must_use]
    pub fn is_enabled(&self) -> bool {
        self.config.enabled
    }

    /// Get the check interval.
    #[must_use]
    pub fn interval(&self) -> Duration {
        self.config.interval
    }

    /// Get the check timeout.
    #[must_use]
    pub fn check_timeout(&self) -> Duration {
        self.config.timeout
    }

    /// Get unhealthy threshold.
    #[must_use]
    pub fn unhealthy_threshold(&self) -> u32 {
        self.config.unhealthy_threshold
    }

    /// Get healthy threshold.
    #[must_use]
    pub fn healthy_threshold(&self) -> u32 {
        self.config.healthy_threshold
    }

    /// Perform a health check on a backend.
    pub async fn check(&self, backend: &Backend) -> HealthCheckResult {
        let address = backend.address();
        let start = Instant::now();

        let result = match &self.config.check_type {
            HealthCheckType::Tcp => self.check_tcp(address).await,
            HealthCheckType::Http {
                path,
                expected_status,
            } => self.check_http(address, path, expected_status).await,
            HealthCheckType::Command { command } => self.check_command(command).await,
        };

        let response_time = start.elapsed();

        match result {
            Ok(()) => {
                debug!(
                    backend = %address,
                    response_time_ms = response_time.as_millis(),
                    "Health check passed"
                );
                HealthCheckResult {
                    address,
                    status: HealthStatus::Healthy,
                    response_time,
                    error: None,
                }
            },
            Err(e) => {
                warn!(
                    backend = %address,
                    error = %e,
                    "Health check failed"
                );
                HealthCheckResult {
                    address,
                    status: HealthStatus::Unhealthy,
                    response_time,
                    error: Some(e),
                }
            },
        }
    }

    /// TCP connection health check.
    async fn check_tcp(&self, address: SocketAddr) -> Result<(), String> {
        match timeout(self.config.timeout, TcpStream::connect(address)).await {
            Ok(Ok(_)) => Ok(()),
            Ok(Err(e)) => Err(format!("connection failed: {e}")),
            Err(_) => Err("connection timeout".to_string()),
        }
    }

    /// HTTP health check.
    async fn check_http(
        &self,
        address: SocketAddr,
        path: &str,
        expected_status: &[u16],
    ) -> Result<(), String> {
        let connect_result = timeout(self.config.timeout, TcpStream::connect(address)).await;

        let mut stream = match connect_result {
            Ok(Ok(s)) => s,
            Ok(Err(e)) => return Err(format!("connection failed: {e}")),
            Err(_) => return Err("connection timeout".to_string()),
        };

        // Send HTTP request
        let request = format!(
            "GET {} HTTP/1.1\r\nHost: {}\r\nConnection: close\r\n\r\n",
            path,
            address.ip()
        );

        if let Err(e) = stream.write_all(request.as_bytes()).await {
            return Err(format!("failed to send request: {e}"));
        }

        // Read response
        let mut reader = BufReader::new(stream);
        let mut status_line = String::new();

        match timeout(self.config.timeout, reader.read_line(&mut status_line)).await {
            Ok(Ok(_)) => {},
            Ok(Err(e)) => return Err(format!("failed to read response: {e}")),
            Err(_) => return Err("read timeout".to_string()),
        }

        // Parse status code
        let parts: Vec<&str> = status_line.split_whitespace().collect();
        if parts.len() < 2 {
            return Err(format!("invalid HTTP response: {status_line}"));
        }

        let status_code: u16 = parts[1]
            .parse()
            .map_err(|_| format!("invalid status code: {}", parts[1]))?;

        if expected_status.is_empty() || expected_status.contains(&status_code) {
            Ok(())
        } else {
            Err(format!(
                "unexpected status code: {}, expected one of {:?}",
                status_code, expected_status
            ))
        }
    }

    /// Command-based health check.
    async fn check_command(&self, command: &str) -> Result<(), String> {
        let parts: Vec<&str> = command.split_whitespace().collect();
        if parts.is_empty() {
            return Err("empty command".to_string());
        }

        let output = match timeout(
            self.config.timeout,
            tokio::process::Command::new(parts[0])
                .args(&parts[1..])
                .output(),
        )
        .await
        {
            Ok(Ok(output)) => output,
            Ok(Err(e)) => return Err(format!("command execution failed: {e}")),
            Err(_) => return Err("command timeout".to_string()),
        };

        if output.status.success() {
            Ok(())
        } else {
            Err(format!("command exited with status: {}", output.status))
        }
    }

    /// Run health checks on multiple backends.
    pub async fn check_all(&self, backends: &[Arc<Backend>]) -> Vec<HealthCheckResult> {
        let mut results = Vec::with_capacity(backends.len());

        for backend in backends {
            let result = self.check(backend).await;
            backend.record_health_check(
                result.status == HealthStatus::Healthy,
                self.config.unhealthy_threshold,
                self.config.healthy_threshold,
            );
            results.push(result);
        }

        results
    }
}

/// Health check task that runs periodically.
#[derive(Debug)]
pub struct HealthCheckTask {
    /// Health checker.
    health_check: Arc<HealthCheck>,
    /// Backends to check.
    backends: Arc<tokio::sync::RwLock<Vec<Arc<Backend>>>>,
    /// Shutdown signal.
    shutdown: mpsc::Receiver<()>,
}

impl HealthCheckTask {
    /// Create a new health check task.
    #[must_use]
    pub fn new(
        health_check: HealthCheck,
        backends: Arc<tokio::sync::RwLock<Vec<Arc<Backend>>>>,
        shutdown: mpsc::Receiver<()>,
    ) -> Self {
        Self {
            health_check: Arc::new(health_check),
            backends,
            shutdown,
        }
    }

    /// Run the health check task.
    pub async fn run(mut self) {
        if !self.health_check.is_enabled() {
            debug!("Health checks disabled");
            return;
        }

        let interval = self.health_check.interval();
        debug!(
            interval_secs = interval.as_secs(),
            "Starting health check task"
        );

        loop {
            tokio::select! {
                _ = self.shutdown.recv() => {
                    debug!("Health check task shutting down");
                    break;
                }
                _ = tokio::time::sleep(interval) => {
                    let backends = self.backends.read().await;
                    let results = self.health_check.check_all(&backends).await;

                    let healthy = results.iter().filter(|r| r.status == HealthStatus::Healthy).count();
                    let total = results.len();

                    debug!(
                        healthy,
                        total,
                        "Health check cycle complete"
                    );
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::modules::load_balancer::config::BackendConfig;
    use std::net::{IpAddr, Ipv4Addr};

    fn test_config() -> HealthCheckConfig {
        HealthCheckConfig {
            enabled: true,
            interval: Duration::from_secs(10),
            timeout: Duration::from_secs(2),
            unhealthy_threshold: 3,
            healthy_threshold: 2,
            check_type: HealthCheckType::Tcp,
        }
    }

    #[test]
    fn test_health_check_creation() {
        let config = test_config();
        let check = HealthCheck::new(config);

        assert!(check.is_enabled());
        assert_eq!(check.interval(), Duration::from_secs(10));
        assert_eq!(check.check_timeout(), Duration::from_secs(2));
    }

    #[test]
    fn test_health_status_eq() {
        assert_eq!(HealthStatus::Healthy, HealthStatus::Healthy);
        assert_ne!(HealthStatus::Healthy, HealthStatus::Unhealthy);
    }

    #[tokio::test]
    async fn test_tcp_check_unreachable() {
        let config = HealthCheckConfig {
            timeout: Duration::from_millis(100),
            ..test_config()
        };
        let check = HealthCheck::new(config);

        // Check against a non-existent address
        let backend = Backend::new(&BackendConfig {
            address: IpAddr::V4(Ipv4Addr::new(192, 0, 2, 1)), // TEST-NET, not routable
            port: 65535,
            weight: 1,
            max_connections: None,
            enabled: true,
        });

        let result = check.check(&backend).await;
        assert_eq!(result.status, HealthStatus::Unhealthy);
        assert!(result.error.is_some());
    }

    #[tokio::test]
    async fn test_health_check_disabled() {
        let config = HealthCheckConfig {
            enabled: false,
            ..test_config()
        };
        let check = HealthCheck::new(config);
        assert!(!check.is_enabled());
    }

    #[test]
    fn test_health_check_result() {
        let result = HealthCheckResult {
            address: "10.0.0.1:8080".parse().unwrap(),
            status: HealthStatus::Healthy,
            response_time: Duration::from_millis(50),
            error: None,
        };

        assert_eq!(result.status, HealthStatus::Healthy);
        assert!(result.error.is_none());
    }
}
