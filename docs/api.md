# R0N Ingress — API Documentation

## Overview

R0N Ingress is a modular, high-performance network gateway written in Rust. All modules implement the `ModuleContract` trait, providing a consistent interface for lifecycle management, configuration, and metrics.

---

## Core Traits

### ModuleContract

The fundamental trait that all modules must implement:

```rust
pub trait ModuleContract: Send + Sync {
    /// Returns the module manifest with metadata
    fn manifest(&self) -> ModuleManifest;
    
    /// Initialize the module with configuration
    fn init(&mut self, config: Option<serde_json::Value>) -> Result<(), Box<dyn std::error::Error>>;
    
    /// Start the module
    fn start(&mut self) -> Result<(), Box<dyn std::error::Error>>;
    
    /// Stop the module
    fn stop(&mut self) -> Result<(), Box<dyn std::error::Error>>;
    
    /// Perform a health check
    fn heartbeat(&self) -> HeartbeatResponse;
    
    /// Get current metrics
    fn metrics(&self) -> HashMap<String, f64>;
}
```

### ModuleManifest

Describes a module's capabilities and requirements:

```rust
pub struct ModuleManifest {
    pub name: String,
    pub version: String,
    pub description: String,
    pub capabilities: Vec<String>,
    pub dependencies: Vec<String>,
    pub config_schema: Option<serde_json::Value>,
}
```

### HeartbeatResponse

Health status returned by modules:

```rust
pub struct HeartbeatResponse {
    pub healthy: bool,
    pub message: Option<String>,
    pub timestamp: u64,
    pub details: HashMap<String, serde_json::Value>,
}
```

---

## IPC Communication

### Message Protocol

All IPC messages use MessagePack serialization:

```rust
pub struct Message {
    pub id: u64,
    pub message_type: MessageType,
    pub payload: Vec<u8>,
}

pub enum MessageType {
    Request,
    Response,
    Event,
    Error,
}
```

### Frame Encoding

Messages are framed with a 4-byte length prefix:

```text
+--------+------------------+
| Length |     Payload      |
| 4 bytes| Variable length  |
+--------+------------------+
```

---

## Module APIs

### TCP Router

```rust
use r0n_ingress::modules::tcp_router::{TcpRouter, TcpRouterConfig};

let config = TcpRouterConfig::default();
let mut router = TcpRouter::new();
router.init(Some(serde_json::to_value(&config)?))?;
router.start()?;
```

**Configuration:**

| Field | Type | Default | Description |
| ----- | ---- | ------- | ----------- |
| `listeners` | `Vec<ListenerConfig>` | `[]` | TCP listeners |
| `routes` | `Vec<RouteConfig>` | `[]` | Routing rules |
| `connection_timeout` | `Duration` | `30s` | Connection timeout |
| `buffer_size` | `usize` | `8192` | Buffer size in bytes |

### UDP Router

```rust
use r0n_ingress::modules::udp_router::{UdpRouter, UdpRouterConfig};

let config = UdpRouterConfig::default();
let mut router = UdpRouter::new();
router.init(Some(serde_json::to_value(&config)?))?;
router.start()?;
```

**Configuration:**

| Field | Type | Default | Description |
| ----- | ---- | ------- | ----------- |
| `listeners` | `Vec<ListenerConfig>` | `[]` | UDP listeners |
| `routes` | `Vec<RouteConfig>` | `[]` | Routing rules |
| `session_timeout` | `Duration` | `60s` | Session timeout |
| `max_sessions` | `usize` | `10000` | Maximum concurrent sessions |

### TLS Terminator

```rust
use r0n_ingress::modules::tls_terminator::{TlsTerminator, TlsConfig};

let config = TlsConfig {
    certificates: vec![CertificateConfig {
        cert_path: "/path/to/cert.pem".into(),
        key_path: "/path/to/key.pem".into(),
        domains: vec!["example.com".into()],
    }],
    ..Default::default()
};
let mut terminator = TlsTerminator::new();
terminator.init(Some(serde_json::to_value(&config)?))?;
```

**Configuration:**

| Field | Type | Default | Description |
| ----- | ---- | ------- | ----------- |
| `certificates` | `Vec<CertificateConfig>` | `[]` | TLS certificates |
| `min_version` | `TlsVersion` | `TLS 1.2` | Minimum TLS version |
| `alpn_protocols` | `Vec<String>` | `["h2", "http/1.1"]` | ALPN protocols |
| `mtls_enabled` | `bool` | `false` | Require client certificates |

### Load Balancer

```rust
use r0n_ingress::modules::load_balancer::{LoadBalancer, LoadBalancerConfig, Strategy};

let config = LoadBalancerConfig {
    strategy: Strategy::LeastConnections,
    backends: vec![
        BackendConfig { address: "10.0.0.1:8080".into(), weight: 1 },
        BackendConfig { address: "10.0.0.2:8080".into(), weight: 2 },
    ],
    health_check: Some(HealthCheckConfig::default()),
    ..Default::default()
};
```

**Strategies:**

| Strategy | Description |
| -------- | ----------- |
| `RoundRobin` | Cycle through backends sequentially |
| `LeastConnections` | Route to backend with fewest connections |
| `Random` | Random backend selection |
| `WeightedRoundRobin` | Round-robin with weights |
| `IpHash` | Consistent hashing based on client IP |

### HTTP Handler

```rust
use r0n_ingress::modules::http_handler::{HttpHandler, HttpConfig};

let config = HttpConfig {
    listeners: vec![ListenerConfig {
        address: "0.0.0.0:8080".into(),
        ..Default::default()
    }],
    http2_enabled: true,
    ..Default::default()
};
```

**Middleware Pipeline:**

```rust
let handler = HttpHandler::new()
    .with_middleware(RequestIdMiddleware::new())
    .with_middleware(CorsMiddleware::new(cors_config))
    .with_middleware(HeadersMiddleware::new(headers));
```

### WebSocket Handler

```rust
use r0n_ingress::modules::websocket_handler::{WebSocketHandler, WebSocketConfig};

let config = WebSocketConfig {
    listeners: vec![ListenerConfig {
        address: "0.0.0.0:8080".into(),
        path: "/ws".into(),
    }],
    subprotocols: vec!["graphql-ws".into()],
    ..Default::default()
};
```

### MQTT Handler

```rust
use r0n_ingress::modules::mqtt_handler::{MqttHandler, MqttConfig, ProtocolVersion};

let config = MqttConfig {
    listeners: vec![ListenerConfig {
        address: "0.0.0.0:1883".into(),
    }],
    protocol_version: ProtocolVersion::V5,
    max_packet_size: 256 * 1024,
    ..Default::default()
};
```

### Rate Limiter

```rust
use r0n_ingress::modules::rate_limiting::{RateLimiter, RateLimitConfig, RateLimitRule};

let config = RateLimitConfig {
    default_limit: RateLimitRule {
        requests: 100,
        window: Duration::from_secs(60),
        ..Default::default()
    },
    per_ip_limits: true,
    whitelist: vec!["10.0.0.0/8".parse()?],
    ..Default::default()
};
```

### Access Control

```rust
use r0n_ingress::modules::access_control::{AccessControl, AccessControlConfig};

let config = AccessControlConfig {
    ip_filter: IpFilterConfig {
        allow_list: vec!["192.168.0.0/16".into()],
        deny_list: vec!["192.168.1.100".into()],
    },
    auth_providers: vec![
        AuthProviderConfig::Jwt { secret: "...".into() },
        AuthProviderConfig::ApiKey { header: "X-API-Key".into() },
    ],
    ..Default::default()
};
```

### WAF (Web Application Firewall)

```rust
use r0n_ingress::modules::waf::{WafHandler, WafConfig, DetectionMode};

let config = WafConfig {
    enabled: true,
    mode: DetectionMode::Block,
    detectors: DetectorConfig {
        sqli: true,
        xss: true,
        path_traversal: true,
    },
    ..Default::default()
};
```

### ACME (Automatic Certificate Management)

```rust
use r0n_ingress::modules::acme::{AcmeHandler, AcmeConfig};

let config = AcmeConfig::letsencrypt_staging()
    .with_domains(vec!["example.com".into()])
    .with_email("admin@example.com")
    .with_http01_challenge();
```

### Metrics Collector

```rust
use r0n_ingress::modules::metrics_collector::{MetricsCollector, MetricsConfig};

let config = MetricsConfig {
    bind_address: "0.0.0.0:9090".into(),
    path: "/metrics".into(),
    ..Default::default()
};
```

**Metric Types:**

| Type | Description | Example |
| ---- | ----------- | ------- |
| Counter | Monotonically increasing | `requests_total` |
| Gauge | Current value | `active_connections` |
| Histogram | Distribution of values | `request_duration_seconds` |

### Logging

```rust
use r0n_ingress::modules::logging::{LoggingHandler, LogConfig, LogLevel, LogFormat};

let config = LogConfig {
    level: LogLevel::Info,
    format: LogFormat::Json,
    outputs: vec![
        OutputConfig::Stdout,
        OutputConfig::File { 
            path: "/var/log/r0n.log".into(),
            rotation: Some(RotationConfig::Daily { keep: 7 }),
        },
    ],
    redaction: RedactionConfig {
        fields: vec!["password", "token", "secret"],
        ..Default::default()
    },
};
```

### Distributed Tracing

```rust
use r0n_ingress::modules::tracing::{TracingHandler, TracingConfig, ExporterType};

let config = TracingConfig {
    enabled: true,
    service_name: "r0n-ingress".into(),
    exporter: ExporterType::Otlp {
        endpoint: "http://otel-collector:4317".into(),
    },
    sampling: SamplingConfig::Ratio(0.1),
    propagation: vec![PropagationType::W3C, PropagationType::B3],
};
```

### QUIC Transport

```rust
use r0n_ingress::modules::quic::{QuicHandler, QuicConfig};

let config = QuicConfig {
    bind_address: "0.0.0.0:443".into(),
    certificates: vec![...],
    zero_rtt: true,
    migration: MigrationConfig::Enabled,
    ..Default::default()
};
```

### HTTP/3 Handler

```rust
use r0n_ingress::modules::http3::{Http3Handler, Http3Config};

let config = Http3Config {
    max_header_list_size: 16384,
    qpack_max_table_capacity: 4096,
    ..Default::default()
};
```

### Kubernetes Integration

```rust
use r0n_ingress::modules::k8s::{K8sHandler, K8sConfig};

let config = K8sConfig::in_cluster()
    .with_namespace("default")
    .with_ingress_class("r0n");
```

### Plugin System

```rust
use r0n_ingress::modules::plugin::{PluginHandler, PluginConfig};

let config = PluginConfig {
    plugin_dir: "/etc/r0n/plugins".into(),
    sandbox: SandboxConfig {
        memory_limit: 64 * 1024 * 1024,
        fuel_limit: Some(1_000_000),
        capabilities: vec![Capability::Network, Capability::FileRead],
    },
};

// Load and invoke a plugin
handler.load_plugin("my-plugin.wasm")?;
handler.start_plugin("my-plugin")?;
let result = handler.invoke("my-plugin", "handle_request", args)?;
```

---

## Performance Utilities

### Memory Pools

```rust
use r0n_ingress::perf::{MemoryPool, BufferPool, Arena};

// Object pool for reusable allocations
let pool: MemoryPool<Connection> = MemoryPool::new(|| Connection::new());
let conn = pool.acquire();
// conn is automatically returned when dropped

// Buffer pool for network I/O
let buffer_pool = BufferPool::new();
let buf = buffer_pool.acquire(8192);

// Arena allocator for batch allocations
let arena = Arena::new(1024 * 1024); // 1MB arena
let data: &mut [u8] = arena.alloc_slice(1024);
```

### Connection Pools

```rust
use r0n_ingress::perf::{ConnectionPool, AdaptivePool, PoolConfig};

let config = PoolConfig {
    min_size: 10,
    max_size: 100,
    acquire_timeout: Duration::from_secs(5),
};

let pool: ConnectionPool<TcpStream> = ConnectionPool::new(config, || async {
    TcpStream::connect("backend:8080").await
});

let conn = pool.acquire().await?;
// Use connection...
// Automatically returned when PooledConnection is dropped
```

### Zero-Copy Buffers

```rust
use r0n_ingress::perf::{SharedBuffer, BufferChain, ByteCursor};

// Shared buffer with reference counting
let buf = SharedBuffer::from(vec![1, 2, 3, 4]);
let slice = buf.slice(1..3); // Zero-copy slice

// Buffer chain for scatter-gather I/O
let mut chain = BufferChain::new();
chain.append(buf1);
chain.append(buf2);
let total = chain.total_len();

// Cursor for parsing
let mut cursor = ByteCursor::new(&data);
let value = cursor.read_u32_be()?;
let line = cursor.read_until(b'\n')?;
```

### Benchmarking

```rust
use r0n_ingress::perf::{Benchmark, BenchmarkConfig, BenchmarkRunner};

let config = BenchmarkConfig::default()
    .with_warmup(Duration::from_secs(5))
    .with_duration(Duration::from_secs(30))
    .with_concurrency(100);

let benchmark = Benchmark::new("http_requests", config, || async {
    // Benchmark operation
    client.get("http://localhost:8080/").await
});

let runner = BenchmarkRunner::new();
let results = runner.run(benchmark).await;

println!("Throughput: {} req/s", results.throughput.ops_per_second());
println!("P99 latency: {:?}", results.latency.percentile(99.0));
```

---

## Error Handling

All modules use domain-specific error types that implement `std::error::Error`:

```rust
pub enum TcpRouterError {
    Io(std::io::Error),
    Config(String),
    Connection(String),
    // ...
}

// Errors can be converted and propagated
fn handle_connection() -> Result<(), Box<dyn std::error::Error>> {
    router.accept()?; // Returns TcpRouterError
    Ok(())
}
```

---

## Thread Safety

All modules are `Send + Sync` and can be safely shared across threads:

```rust
let router = Arc::new(TcpRouter::new());

// Clone Arc for each worker thread
for _ in 0..num_cpus::get() {
    let router = Arc::clone(&router);
    std::thread::spawn(move || {
        // Use router...
    });
}
```

---

## Configuration Files

### TOML Format

```toml
[tcp_router]
connection_timeout = "30s"
buffer_size = 8192

[[tcp_router.listeners]]
address = "0.0.0.0:8080"

[[tcp_router.routes]]
match = { prefix = "/" }
backend = "upstream:8080"

[load_balancer]
strategy = "least_connections"

[[load_balancer.backends]]
address = "10.0.0.1:8080"
weight = 1

[[load_balancer.backends]]
address = "10.0.0.2:8080"
weight = 2

[metrics]
bind_address = "0.0.0.0:9090"
path = "/metrics"
```

### Environment Variables

Configuration can be overridden via environment variables:

```bash
R0N_TCP_ROUTER_BUFFER_SIZE=16384
R0N_LOAD_BALANCER_STRATEGY=round_robin
R0N_METRICS_BIND_ADDRESS=0.0.0.0:9091
```

---

## See Also

- [User Guide](user-guide.md) — Installation and usage
- [Deployment Guide](deployment.md) — Production deployment
- [Module Development Guide](module-development.md) — Creating custom modules
