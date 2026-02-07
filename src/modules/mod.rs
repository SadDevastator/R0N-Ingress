//! # Gateway Modules
//!
//! This module contains all the built-in modules for R0N Gateway.
//! Each module implements the [`ModuleContract`] trait for uniform
//! lifecycle management and IPC communication.
//!
//! ## Available Modules
//!
//! - [`tcp_router`] - TCP routing and load balancing
//! - [`udp_router`] - UDP routing and load balancing
//! - [`tls_terminator`] - TLS termination with SNI routing
//! - [`load_balancer`] - Load balancing with multiple strategies
//! - [`metrics_collector`] - Prometheus-compatible metrics collection
//! - [`http_handler`] - HTTP/1.1 and HTTP/2 protocol handling
//! - [`mqtt_handler`] - MQTT 3.1.1 and MQTT 5.0 protocol handling
//! - [`websocket_handler`] - WebSocket protocol handling with upgrade support
//! - [`l4_passthrough`] - Generic Layer 4 TCP/UDP passthrough
//! - [`rate_limiting`] - Rate limiting with token bucket algorithm
//! - [`access_control`] - Access control with IP filtering, authentication, and authorization
//! - [`waf`] - Web Application Firewall with SQL injection, XSS, and path traversal detection
//! - [`acme`] - ACME integration for automatic TLS certificate management with Let's Encrypt
//! - [`logging`] - Structured logging with JSON output, rotation, and sensitive data redaction
//! - [`tracing`] - Distributed tracing with OpenTelemetry-compatible context propagation
//! - [`quic`] - QUIC transport layer (RFC 9000)
//! - [`http3`] - HTTP/3 protocol handler (RFC 9114)
//! - [`k8s`] - Kubernetes integration for ingress, service discovery, and secrets
//! - [`plugin`] - WASM plugin system for extending gateway functionality

pub mod access_control;
pub mod acme;
pub mod http3;
pub mod http_handler;
pub mod k8s;
pub mod l4_passthrough;
pub mod load_balancer;
pub mod logging;
pub mod metrics_collector;
pub mod mqtt_handler;
pub mod plugin;
pub mod quic;
pub mod rate_limiting;
pub mod tcp_router;
pub mod tls_terminator;
pub mod tracing;
pub mod udp_router;
pub mod waf;
pub mod websocket_handler;
