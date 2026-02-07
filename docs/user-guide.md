# R0N Ingress — User Guide

## Introduction

R0N Ingress is a modular, high-performance network gateway designed for modern cloud-native environments. It provides TCP/UDP routing, TLS termination, load balancing, rate limiting, security features, and more—all through a unified modular architecture.

---

## Installation

### From Source

```bash
# Clone the repository
git clone https://github.com/r0n/r0n-ingress.git
cd r0n-ingress

# Build release binary
cargo build --release

# Install to system path
sudo cp target/release/r0n-ingress /usr/local/bin/
```

### Prerequisites

- Rust 1.75 or later
- OpenSSL development libraries (for TLS support)

**Ubuntu/Debian:**

```bash
sudo apt-get install build-essential pkg-config libssl-dev
```

**macOS:**

```bash
brew install openssl
```

**Fedora/RHEL:**

```bash
sudo dnf install gcc openssl-devel
```

### Docker

```bash
docker pull ghcr.io/r0n/r0n-ingress:latest
docker run -p 8080:8080 -v /path/to/config:/etc/r0n ghcr.io/r0n/r0n-ingress
```

---

## Quick Start

### 1. Create Configuration

Create a configuration file at `/etc/r0n/config.toml`:

```toml
# Basic HTTP reverse proxy configuration

[http_handler]
enabled = true

[[http_handler.listeners]]
address = "0.0.0.0:8080"

[load_balancer]
strategy = "round_robin"

[[load_balancer.backends]]
address = "backend1:8080"

[[load_balancer.backends]]
address = "backend2:8080"

[metrics]
bind_address = "0.0.0.0:9090"
```

### 2. Start the Gateway

```bash
r0n-ingress --config /etc/r0n/config.toml
```

### 3. Verify Operation

```bash
# Check health endpoint
curl http://localhost:8080/health

# View metrics
curl http://localhost:9090/metrics
```

---

## Configuration

### Configuration File Structure

R0N Ingress uses TOML for configuration. Each module has its own section:

```toml
# Global settings
[global]
log_level = "info"
worker_threads = 4

# Module configurations
[tcp_router]
# ...

[load_balancer]
# ...

[tls_terminator]
# ...
```

### Environment Variables

Any configuration value can be overridden via environment variables:

```bash
# Pattern: R0N_<SECTION>_<KEY>
export R0N_GLOBAL_LOG_LEVEL=debug
export R0N_LOAD_BALANCER_STRATEGY=least_connections
```

### Configuration Validation

Validate configuration before starting:

```bash
r0n-ingress --config /etc/r0n/config.toml --validate
```

---

## Core Features

### TCP Routing

Route TCP connections based on port and destination:

```toml
[tcp_router]
connection_timeout = "30s"
buffer_size = 8192

[[tcp_router.listeners]]
address = "0.0.0.0:3306"
name = "mysql"

[[tcp_router.routes]]
listener = "mysql"
backend = "mysql-primary:3306"
```

### UDP Routing

Handle UDP datagrams with session tracking:

```toml
[udp_router]
session_timeout = "60s"
max_sessions = 10000

[[udp_router.listeners]]
address = "0.0.0.0:53"
name = "dns"

[[udp_router.routes]]
listener = "dns"
backends = ["dns1:53", "dns2:53"]
strategy = "round_robin"
```

### TLS Termination

Terminate TLS connections with SNI-based routing:

```toml
[tls_terminator]
min_version = "1.2"
alpn_protocols = ["h2", "http/1.1"]

[[tls_terminator.certificates]]
cert_path = "/etc/r0n/certs/example.com.pem"
key_path = "/etc/r0n/certs/example.com.key"
domains = ["example.com", "*.example.com"]

[[tls_terminator.listeners]]
address = "0.0.0.0:443"
```

**TLS Passthrough:**

For end-to-end encryption without termination:

```toml
[[tls_terminator.passthrough]]
sni_pattern = "*.internal.example.com"
backend = "internal-lb:443"
```

### Load Balancing

Distribute traffic across multiple backends:

```toml
[load_balancer]
strategy = "least_connections"  # or: round_robin, random, weighted_round_robin, ip_hash

[[load_balancer.backends]]
address = "backend1:8080"
weight = 2
max_connections = 100

[[load_balancer.backends]]
address = "backend2:8080"
weight = 1

[load_balancer.health_check]
enabled = true
interval = "10s"
timeout = "5s"
path = "/health"  # For HTTP health checks
healthy_threshold = 2
unhealthy_threshold = 3
```

### HTTP/HTTPS Handling

Process HTTP requests with middleware pipeline:

```toml
[http_handler]
http2_enabled = true
max_header_size = 8192
request_timeout = "30s"

[[http_handler.listeners]]
address = "0.0.0.0:8080"

[[http_handler.routes]]
path = "/api/*"
backend = "api-service:8080"
strip_prefix = "/api"

[[http_handler.routes]]
path = "/"
backend = "web-service:8080"

[http_handler.cors]
allowed_origins = ["https://example.com"]
allowed_methods = ["GET", "POST", "PUT", "DELETE"]
allowed_headers = ["Authorization", "Content-Type"]
max_age = 3600
```

### WebSocket Support

Handle WebSocket connections:

```toml
[websocket_handler]
ping_interval = "30s"
max_message_size = 65536

[[websocket_handler.routes]]
path = "/ws"
backend = "ws-service:8080"
subprotocols = ["graphql-ws"]

[websocket_handler.security]
allowed_origins = ["https://example.com"]
require_origin = true
```

### MQTT Handling

MQTT broker functionality with topic routing:

```toml
[mqtt_handler]
protocol_version = "5.0"  # or "3.1.1"
max_packet_size = 262144

[[mqtt_handler.listeners]]
address = "0.0.0.0:1883"

[mqtt_handler.session]
expiry_interval = "1h"
max_inflight = 100
```

---

## Security Features

### Rate Limiting

Protect against abuse with configurable rate limits:

```toml
[rate_limiting]
enabled = true

[rate_limiting.default]
requests = 100
window = "1m"

[rate_limiting.per_ip]
enabled = true
requests = 1000
window = "1h"

[[rate_limiting.rules]]
path = "/api/expensive"
requests = 10
window = "1m"

[rate_limiting.whitelist]
ips = ["10.0.0.0/8"]

[rate_limiting.blacklist]
ips = ["192.168.1.100"]
```

### Access Control

IP-based and authentication-based access control:

```toml
[access_control]
default_action = "deny"

[access_control.ip_filter]
allow = ["192.168.0.0/16", "10.0.0.0/8"]
deny = ["192.168.1.100"]

[[access_control.auth_providers]]
type = "jwt"
secret = "${JWT_SECRET}"
issuer = "https://auth.example.com"

[[access_control.auth_providers]]
type = "api_key"
header = "X-API-Key"
keys = ["key1", "key2"]

[[access_control.policies]]
path = "/admin/*"
require_auth = true
roles = ["admin"]
```

### Web Application Firewall (WAF)

Protect against common web attacks:

```toml
[waf]
enabled = true
mode = "block"  # or "detect" for logging only

[waf.detectors]
sqli = true
xss = true
path_traversal = true

[[waf.bypass_rules]]
path = "/api/webhook"
source_ip = "10.0.0.0/8"

[waf.logging]
enabled = true
format = "json"
path = "/var/log/r0n/threats.log"
```

### Automatic TLS Certificates (ACME)

Automatically obtain and renew TLS certificates:

```toml
[acme]
enabled = true
email = "admin@example.com"
directory = "https://acme-v02.api.letsencrypt.org/directory"
# Use staging for testing:
# directory = "https://acme-staging-v02.api.letsencrypt.org/directory"

domains = ["example.com", "www.example.com"]
challenge_type = "http-01"  # or "dns-01"

[acme.storage]
type = "file"
path = "/etc/r0n/acme"

[acme.renewal]
days_before_expiry = 30
check_interval = "12h"
```

---

## Observability

### Logging

Structured logging with multiple outputs:

```toml
[logging]
level = "info"  # trace, debug, info, warn, error
format = "json"  # or "text", "compact", "logfmt"

[[logging.outputs]]
type = "stdout"

[[logging.outputs]]
type = "file"
path = "/var/log/r0n/gateway.log"

[logging.outputs.rotation]
type = "daily"
keep = 7

[logging.redaction]
fields = ["password", "token", "secret", "authorization"]
patterns = ["Bearer [A-Za-z0-9-_]+"]
```

### Metrics

Prometheus-compatible metrics endpoint:

```toml
[metrics]
enabled = true
bind_address = "0.0.0.0:9090"
path = "/metrics"

# Optional authentication
[metrics.auth]
type = "basic"
username = "prometheus"
password = "${METRICS_PASSWORD}"
```

**Available Metrics:**

| Metric | Type | Description |
| ------ | ---- | ----------- |
| `r0n_requests_total` | Counter | Total requests processed |
| `r0n_request_duration_seconds` | Histogram | Request latency |
| `r0n_active_connections` | Gauge | Current active connections |
| `r0n_backend_health` | Gauge | Backend health status (0/1) |
| `r0n_rate_limit_exceeded_total` | Counter | Rate limit violations |
| `r0n_waf_blocked_total` | Counter | WAF blocked requests |

### Distributed Tracing

OpenTelemetry-compatible distributed tracing:

```toml
[tracing]
enabled = true
service_name = "r0n-ingress"

[tracing.exporter]
type = "otlp"  # or "jaeger", "zipkin"
endpoint = "http://otel-collector:4317"

[tracing.sampling]
strategy = "ratio"
ratio = 0.1  # Sample 10% of requests

[tracing.propagation]
formats = ["w3c", "b3"]  # Trace context formats
```

---

## Advanced Features

### HTTP/3 and QUIC

Enable HTTP/3 with QUIC transport:

```toml
[quic]
enabled = true
bind_address = "0.0.0.0:443"
zero_rtt = true

[quic.migration]
enabled = true

[http3]
enabled = true
max_header_list_size = 16384
```

### Kubernetes Integration

Run as a Kubernetes Ingress Controller:

```toml
[kubernetes]
enabled = true
ingress_class = "r0n"

[kubernetes.config]
type = "in_cluster"  # or "kubeconfig"
# kubeconfig_path = "~/.kube/config"

[kubernetes.watch]
namespaces = ["default", "production"]
label_selector = "app.kubernetes.io/managed-by=r0n"

[kubernetes.leader_election]
enabled = true
lease_name = "r0n-ingress-leader"
lease_namespace = "r0n-system"
```

### Plugin System

Extend functionality with WebAssembly plugins:

```toml
[plugins]
enabled = true
plugin_dir = "/etc/r0n/plugins"

[[plugins.load]]
name = "custom-auth"
path = "custom-auth.wasm"

[plugins.sandbox]
memory_limit = "64MB"
fuel_limit = 1000000
capabilities = ["network", "file_read"]
```

---

## Operational Commands

### Health Check

```bash
# Check gateway health
r0n-ingress health

# Check specific module
r0n-ingress health --module load_balancer
```

### Configuration Reload

```bash
# Reload configuration without restart
r0n-ingress reload

# Or send SIGHUP
kill -HUP $(pidof r0n-ingress)
```

### Status and Metrics

```bash
# View current status
r0n-ingress status

# Export metrics snapshot
r0n-ingress metrics --format prometheus
```

---

## Troubleshooting

### Common Issues

**Connection Refused:**

- Check if the listener is bound to the correct address
- Verify firewall rules allow traffic
- Ensure backend services are running

**TLS Handshake Failures:**

- Verify certificate paths are correct
- Check certificate expiration dates
- Ensure certificate covers the requested domain

**High Latency:**

- Check backend health status
- Review load balancing strategy
- Monitor connection pool utilization

**Rate Limiting:**

- Check current rate limit configuration
- Verify client IP detection (X-Forwarded-For)
- Review whitelist configuration

### Debug Logging

Enable debug logging for troubleshooting:

```bash
R0N_GLOBAL_LOG_LEVEL=debug r0n-ingress --config /etc/r0n/config.toml
```

### Performance Profiling

```bash
# Enable CPU profiling
r0n-ingress --config /etc/r0n/config.toml --profile cpu

# Enable memory profiling
r0n-ingress --config /etc/r0n/config.toml --profile memory
```

---

## See Also

- [API Documentation](api.md) — Detailed API reference
- [Deployment Guide](deployment.md) — Production deployment
- [Module Development Guide](module-development.md) — Creating custom modules
