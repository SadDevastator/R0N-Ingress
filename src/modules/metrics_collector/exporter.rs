//! Prometheus HTTP exporter.

use super::config::ExporterConfig;
use super::error::{MetricsError, MetricsResult};
use super::registry::MetricsRegistry;
use bytes::Bytes;
use http_body_util::Full;
use hyper::body::Incoming;
use hyper::server::conn::http1;
use hyper::service::service_fn;
use hyper::{Request, Response, StatusCode};
use hyper_util::rt::TokioIo;
use std::convert::Infallible;
use std::net::SocketAddr;
use std::sync::Arc;
use tokio::net::TcpListener;
use tokio::sync::mpsc;
use tracing::{debug, error, info};

/// Constant-time byte comparison to prevent timing side-channel attacks.
fn constant_time_eq(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    a.iter()
        .zip(b.iter())
        .fold(0u8, |acc, (x, y)| acc | (x ^ y))
        == 0
}

/// Prometheus HTTP exporter server.
#[derive(Debug)]
pub struct PrometheusExporter {
    /// Configuration.
    config: ExporterConfig,
    /// Metrics registry.
    registry: Arc<MetricsRegistry>,
    /// Shutdown sender.
    shutdown_tx: Option<mpsc::Sender<()>>,
}

impl PrometheusExporter {
    /// Create a new exporter.
    #[must_use]
    pub fn new(config: ExporterConfig, registry: Arc<MetricsRegistry>) -> Self {
        Self {
            config,
            registry,
            shutdown_tx: None,
        }
    }

    /// Start the HTTP server.
    pub async fn start(&mut self) -> MetricsResult<()> {
        if self.shutdown_tx.is_some() {
            return Err(MetricsError::AlreadyRunning);
        }

        if !self.config.enabled {
            info!("Prometheus exporter is disabled");
            return Ok(());
        }

        let addr = self.config.socket_addr();
        let listener = TcpListener::bind(addr)
            .await
            .map_err(|e| MetricsError::BindError(format!("{addr}: {e}")))?;

        info!(%addr, "Prometheus exporter listening");

        let (shutdown_tx, mut shutdown_rx) = mpsc::channel::<()>(1);
        self.shutdown_tx = Some(shutdown_tx);

        let registry = Arc::clone(&self.registry);
        let metrics_path = self.config.path.clone();
        let auth = self.config.auth.clone();

        tokio::spawn(async move {
            loop {
                tokio::select! {
                    accept_result = listener.accept() => {
                        match accept_result {
                            Ok((stream, remote_addr)) => {
                                debug!(%remote_addr, "New metrics connection");

                                let registry = Arc::clone(&registry);
                                let metrics_path = metrics_path.clone();
                                let auth = auth.clone();

                                tokio::spawn(async move {
                                    let io = TokioIo::new(stream);

                                    let service = service_fn(move |req| {
                                        let registry = Arc::clone(&registry);
                                        let metrics_path = metrics_path.clone();
                                        let auth = auth.clone();

                                        async move {
                                            handle_request(req, &registry, &metrics_path, auth.as_ref()).await
                                        }
                                    });

                                    if let Err(e) = http1::Builder::new()
                                        .serve_connection(io, service)
                                        .await
                                    {
                                        debug!("Connection error: {e}");
                                    }
                                });
                            }
                            Err(e) => {
                                error!("Accept error: {e}");
                            }
                        }
                    }
                    _ = shutdown_rx.recv() => {
                        info!("Prometheus exporter shutting down");
                        break;
                    }
                }
            }
        });

        Ok(())
    }

    /// Stop the HTTP server.
    pub async fn stop(&mut self) -> MetricsResult<()> {
        if let Some(tx) = self.shutdown_tx.take() {
            let _ = tx.send(()).await;
            Ok(())
        } else {
            Err(MetricsError::NotRunning)
        }
    }

    /// Check if the server is running.
    #[must_use]
    pub fn is_running(&self) -> bool {
        self.shutdown_tx.is_some()
    }

    /// Get the bind address.
    #[must_use]
    pub fn bind_addr(&self) -> SocketAddr {
        self.config.socket_addr()
    }
}

/// Handle an HTTP request.
async fn handle_request(
    req: Request<Incoming>,
    registry: &MetricsRegistry,
    metrics_path: &str,
    auth: Option<&super::config::AuthConfig>,
) -> Result<Response<Full<Bytes>>, Infallible> {
    // Check authentication if configured
    if let Some(auth_config) = auth {
        if !check_auth(&req, auth_config) {
            return Ok(Response::builder()
                .status(StatusCode::UNAUTHORIZED)
                .header("WWW-Authenticate", "Basic realm=\"metrics\"")
                .body(Full::new(Bytes::from("Unauthorized")))
                .expect("response build failed"));
        }
    }

    // Route based on path
    let path = req.uri().path();

    if path == metrics_path {
        let metrics = registry.encode_prometheus();
        Ok(Response::builder()
            .status(StatusCode::OK)
            .header("Content-Type", "text/plain; version=0.0.4; charset=utf-8")
            .body(Full::new(Bytes::from(metrics)))
            .expect("response build failed"))
    } else if path == "/health" || path == "/healthz" {
        Ok(Response::builder()
            .status(StatusCode::OK)
            .body(Full::new(Bytes::from("OK")))
            .expect("response build failed"))
    } else if path == "/" {
        let body = format!(
            "<html><body><h1>R0N Gateway Metrics</h1><p><a href=\"{}\">Metrics</a></p></body></html>",
            metrics_path
        );
        Ok(Response::builder()
            .status(StatusCode::OK)
            .header("Content-Type", "text/html")
            .body(Full::new(Bytes::from(body)))
            .expect("response build failed"))
    } else {
        Ok(Response::builder()
            .status(StatusCode::NOT_FOUND)
            .body(Full::new(Bytes::from("Not Found")))
            .expect("response build failed"))
    }
}

/// Check basic authentication.
fn check_auth(req: &Request<Incoming>, auth: &super::config::AuthConfig) -> bool {
    let auth_header = match req.headers().get("Authorization") {
        Some(h) => h,
        None => return false,
    };

    let auth_str = match auth_header.to_str() {
        Ok(s) => s,
        Err(_) => return false,
    };

    if !auth_str.starts_with("Basic ") {
        return false;
    }

    let encoded = &auth_str[6..];
    let decoded = match base64_decode(encoded) {
        Some(d) => d,
        None => return false,
    };

    let expected = format!("{}:{}", auth.username, auth.password);
    constant_time_eq(decoded.as_bytes(), expected.as_bytes())
}

/// Simple base64 decode for basic auth.
fn base64_decode(input: &str) -> Option<String> {
    // Simple base64 decoder for ASCII credentials
    const ALPHABET: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

    let input = input.as_bytes();
    let mut output = Vec::new();
    let mut buffer = 0u32;
    let mut bits = 0;

    for &byte in input {
        if byte == b'=' {
            break;
        }

        let value = match ALPHABET.iter().position(|&c| c == byte) {
            Some(pos) => pos as u32,
            None => return None,
        };

        buffer = (buffer << 6) | value;
        bits += 6;

        if bits >= 8 {
            bits -= 8;
            output.push((buffer >> bits) as u8);
            buffer &= (1 << bits) - 1;
        }
    }

    String::from_utf8(output).ok()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_base64_decode() {
        // "admin:secret" in base64
        let encoded = "YWRtaW46c2VjcmV0";
        let decoded = base64_decode(encoded).unwrap();
        assert_eq!(decoded, "admin:secret");
    }

    #[test]
    fn test_exporter_creation() {
        let config = ExporterConfig::default();
        let registry = Arc::new(MetricsRegistry::new("test"));
        let exporter = PrometheusExporter::new(config, registry);

        assert!(!exporter.is_running());
        assert_eq!(exporter.bind_addr().port(), 9090);
    }

    #[tokio::test]
    async fn test_exporter_start_stop() {
        let mut config = ExporterConfig::default();
        config.port = 19090; // Use a different port for tests
        config.enabled = true;

        let registry = Arc::new(MetricsRegistry::new("test"));
        let mut exporter = PrometheusExporter::new(config, registry);

        exporter.start().await.unwrap();
        assert!(exporter.is_running());

        // Starting again should fail
        assert!(exporter.start().await.is_err());

        exporter.stop().await.unwrap();

        // Give the server time to shutdown
        tokio::time::sleep(tokio::time::Duration::from_millis(50)).await;

        // Stopping again should fail
        assert!(exporter.stop().await.is_err());
    }

    #[tokio::test]
    async fn test_exporter_disabled() {
        let mut config = ExporterConfig::default();
        config.enabled = false;

        let registry = Arc::new(MetricsRegistry::new("test"));
        let mut exporter = PrometheusExporter::new(config, registry);

        // Should succeed but not actually start
        exporter.start().await.unwrap();
        assert!(!exporter.is_running());
    }
}
