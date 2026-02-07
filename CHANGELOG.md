# Changelog

All notable changes to R0N Ingress will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [0.1.0-beta.1] - 2026-02-03

### Added

#### Core Infrastructure

- Module Control Contract (`ModuleContract` trait) with lifecycle management
- IPC communication layer using Unix sockets with MessagePack serialization
- TOML configuration system with validation and hot-reload support
- Heartbeat/liveness mechanism for module health monitoring

#### Networking Modules

- **TCP Router**: Connection pooling, route matching, backend forwarding
- **UDP Router**: Datagram handling, session/flow tracking, route matching
- **TLS Terminator**: SNI routing, mTLS, certificate hot-reload, passthrough mode
- **Load Balancer**: Round-robin, least-connections, hash-based, weighted strategies

#### Protocol Handlers

- **HTTP/HTTPS**: HTTP/1.1 and HTTP/2 support, header manipulation, middleware pipeline
- **MQTT**: MQTT 3.1.1 and 5.0 support, topic-based routing, QoS handling
- **WebSocket**: Upgrade handling, subprotocol negotiation, origin validation
- **Generic L4**: Raw TCP/UDP forwarding with connection tracking

#### Security Features

- **Rate Limiting**: Token bucket and sliding window algorithms, per-IP/route limits
- **Access Control**: IP allow/deny lists, JWT/API key authentication, policy engine
- **Web Application Firewall**: SQL injection, XSS, path traversal detection, OWASP CRS
- **ACME Integration**: Let's Encrypt support, HTTP-01/DNS-01 challenges, auto-renewal

#### Observability

- **Metrics**: Prometheus-compatible exporter, per-module aggregation
- **Logging**: Structured JSON, log rotation, sensitive data redaction
- **Distributed Tracing**: OpenTelemetry-compatible, W3C/B3/Jaeger propagation

#### Advanced Features

- **QUIC/HTTP-3**: RFC 9000/9114 compliant, 0-RTT, connection migration
- **Kubernetes Integration**: Ingress controller, service discovery, ConfigMap/Secret sync
- **Plugin System**: WebAssembly runtime with sandboxing and capability-based security

#### Performance

- Memory pools with arena and slab allocators
- Adaptive connection pooling with metrics
- Zero-copy buffer utilities

#### Module Contract Enhancements

- `pause()` and `resume()` lifecycle methods for graceful traffic draining
- `ContractVersion` for module compatibility checking (v1.1.0)
- `Paused` status in `ModuleStatus` enum
- `Pause`, `Resume`, `Version` IPC control commands

### Changed

- Project renamed from R0N-Gateway to R0N-Ingress
- License changed to Apache-2.0 only

### Security

- All modules implement sandboxed execution
- Capability-based access control for plugins
- Sensitive data redaction in logs

---

## Version History

| Version | Date | Description |
| ------- | ---- | ----------- |
| 0.1.0-beta.1 | 2026-02-03 | Initial beta release |

[Unreleased]: https://github.com/R0N/R0N-Ingress/compare/v0.1.0-beta.1...HEAD
[0.1.0-beta.1]: https://github.com/R0N/R0N-Ingress/releases/tag/v0.1.0-beta.1
