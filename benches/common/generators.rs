//! Test data generators for benchmarks.
//!
//! Provides realistic test data for HTTP requests, IP addresses, WAF payloads,
//! TLS certificates, configuration files, and other module inputs.

use bytes::Bytes;
use rand::RngExt;
use std::collections::HashMap;
use std::net::SocketAddr;

// ---------------------------------------------------------------------------
// HTTP data generators
// ---------------------------------------------------------------------------

/// Generate a minimal valid HTTP/1.1 GET request as raw bytes.
pub fn http_get_request(path: &str, host: &str) -> Vec<u8> {
    format!(
        "GET {} HTTP/1.1\r\nHost: {}\r\nConnection: keep-alive\r\nAccept: */*\r\n\r\n",
        path, host
    )
    .into_bytes()
}

/// Generate an HTTP POST request with a JSON body.
pub fn http_post_request(path: &str, host: &str, body: &str) -> Vec<u8> {
    format!(
        "POST {} HTTP/1.1\r\nHost: {}\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: keep-alive\r\n\r\n{}",
        path, host, body.len(), body
    )
    .into_bytes()
}

/// Generate a batch of HTTP requests with varying paths for router benchmarks.
pub fn http_request_batch(count: usize) -> Vec<Vec<u8>> {
    let paths = [
        "/",
        "/api/v1/users",
        "/api/v1/users/123",
        "/api/v2/products",
        "/api/v2/products/456/reviews",
        "/health",
        "/metrics",
        "/static/js/app.js",
        "/static/css/style.css",
        "/admin/dashboard",
        "/api/v1/orders",
        "/api/v1/orders/789/items",
        "/ws/chat",
        "/ws/notifications",
        "/graphql",
    ];
    let hosts = ["example.com", "api.example.com", "admin.example.com"];
    let mut rng = rand::rng();
    (0..count)
        .map(|_| {
            let path = paths[rng.random_range(0..paths.len())];
            let host = hosts[rng.random_range(0..hosts.len())];
            http_get_request(path, host)
        })
        .collect()
}

/// Generate a valid HTTP/1.1 response as raw bytes.
pub fn http_response(status: u16, body: &str) -> Vec<u8> {
    let reason = match status {
        200 => "OK",
        404 => "Not Found",
        500 => "Internal Server Error",
        503 => "Service Unavailable",
        _ => "Unknown",
    };
    format!(
        "HTTP/1.1 {} {}\r\nContent-Type: text/plain\r\nContent-Length: {}\r\n\r\n{}",
        status,
        reason,
        body.len(),
        body
    )
    .into_bytes()
}

// ---------------------------------------------------------------------------
// IP address generators
// ---------------------------------------------------------------------------

/// Generate random IPv4 addresses as strings.
pub fn random_ipv4_addresses(count: usize) -> Vec<String> {
    let mut rng = rand::rng();
    (0..count)
        .map(|_| {
            format!(
                "{}.{}.{}.{}",
                rng.random_range(1u8..=254),
                rng.random_range(0u8..=255),
                rng.random_range(0u8..=255),
                rng.random_range(1u8..=254),
            )
        })
        .collect()
}

/// Generate random socket addresses for backend targets.
pub fn random_socket_addrs(count: usize) -> Vec<SocketAddr> {
    let mut rng = rand::rng();
    (0..count)
        .map(|_| {
            let ip: [u8; 4] = [
                rng.random_range(10u8..=10),
                rng.random_range(0u8..=255),
                rng.random_range(0u8..=255),
                rng.random_range(1u8..=254),
            ];
            let port = rng.random_range(8000u16..=9000);
            SocketAddr::from((ip, port))
        })
        .collect()
}

/// Generate CIDR ranges for IP filter benchmarks.
pub fn cidr_ranges(count: usize) -> Vec<String> {
    let mut rng = rand::rng();
    (0..count)
        .map(|_| {
            let prefix_len = rng.random_range(8u8..=30);
            format!(
                "{}.{}.{}.0/{}",
                rng.random_range(1u8..=223),
                rng.random_range(0u8..=255),
                rng.random_range(0u8..=255),
                prefix_len,
            )
        })
        .collect()
}

// ---------------------------------------------------------------------------
// WAF payload generators
// ---------------------------------------------------------------------------

/// Known SQL injection test payloads.
pub fn sqli_payloads() -> Vec<String> {
    vec![
        "' OR '1'='1".into(),
        "1; DROP TABLE users--".into(),
        "' UNION SELECT * FROM passwords--".into(),
        "admin'--".into(),
        "1' OR '1'='1' /*".into(),
        "'; EXEC xp_cmdshell('dir');--".into(),
        "1 AND 1=1 UNION ALL SELECT 1,NULL,'<script>alert(1)</script>',table_name FROM information_schema.tables WHERE 2>1--".into(),
        "' OR ''='".into(),
        "1' AND SLEEP(5)--".into(),
        "' UNION SELECT username,password FROM users--".into(),
    ]
}

/// Known XSS test payloads.
pub fn xss_payloads() -> Vec<String> {
    vec![
        "<script>alert('xss')</script>".into(),
        "<img src=x onerror=alert(1)>".into(),
        "<svg onload=alert(1)>".into(),
        "javascript:alert(document.cookie)".into(),
        "<body onload=alert('xss')>".into(),
        "<iframe src=\"javascript:alert('xss')\">".into(),
        "\"><script>alert(String.fromCharCode(88,83,83))</script>".into(),
        "<img src=\"javascript:alert('xss');\">".into(),
        "';!--\"<XSS>=&{()}".into(),
        "<INPUT TYPE=\"IMAGE\" SRC=\"javascript:alert('XSS');\">".into(),
    ]
}

/// Known path traversal payloads.
pub fn path_traversal_payloads() -> Vec<String> {
    vec![
        "../../../etc/passwd".into(),
        "..\\..\\..\\windows\\system32\\config\\sam".into(),
        "....//....//....//etc/passwd".into(),
        "%2e%2e%2f%2e%2e%2f%2e%2e%2fetc%2fpasswd".into(),
        "..%252f..%252f..%252fetc%252fpasswd".into(),
        "/var/www/../../etc/shadow".into(),
        "..%c0%af..%c0%af..%c0%afetc/passwd".into(),
        "%252e%252e%252f%252e%252e%252fetc%252fpasswd".into(),
    ]
}

/// Benign (non-malicious) payloads for WAF false-positive testing.
pub fn benign_payloads() -> Vec<String> {
    vec![
        "Hello, world!".into(),
        "The quick brown fox jumps over the lazy dog".into(),
        "{\"name\": \"John\", \"age\": 30}".into(),
        "SELECT your favorite color from the dropdown".into(),
        "O'Brien's restaurant serves great food".into(),
        "/api/v1/users/123/profile".into(),
        "path/to/my/file.txt".into(),
        "https://example.com/page?query=search+term".into(),
        "This is a <b>bold</b> statement in regular HTML".into(),
        "user@example.com".into(),
    ]
}

// ---------------------------------------------------------------------------
// Configuration generators
// ---------------------------------------------------------------------------

/// Generate a minimal valid gateway TOML configuration.
pub fn minimal_gateway_config() -> String {
    r#"
[gateway]
name = "bench-gateway"
bind_address = "0.0.0.0"
control_port = 9100

[logging]
level = "warn"
format = "json"

[metrics]
enabled = true
path = "/metrics"

[[modules]]
name = "test-module"
type = "http_handler"
enabled = true
"#
    .to_string()
}

/// Generate a complex gateway configuration with many modules.
pub fn complex_gateway_config(module_count: usize) -> String {
    let mut config = r#"
[gateway]
name = "bench-gateway-complex"
bind_address = "0.0.0.0"
control_port = 9100

[logging]
level = "info"
format = "json"

[metrics]
enabled = true
path = "/metrics"
include_runtime = true
"#
    .to_string();

    let module_types = [
        "http_handler",
        "tcp_router",
        "load_balancer",
        "rate_limiting",
        "tls_terminator",
    ];

    for i in 0..module_count {
        let mod_type = module_types[i % module_types.len()];
        config.push_str(&format!(
            r#"
[[modules]]
name = "module-{i}"
type = "{mod_type}"
enabled = true
"#
        ));
    }
    config
}

// ---------------------------------------------------------------------------
// IPC message generators
// ---------------------------------------------------------------------------

/// Generate a batch of ControlCommands for IPC benchmarks.
pub fn ipc_commands() -> Vec<&'static str> {
    vec![
        "Start",
        "Stop",
        "Status",
        "Metrics",
        "Heartbeat",
        "Version",
        "Pause",
        "Resume",
    ]
}

// ---------------------------------------------------------------------------
// Load balancer data generators
// ---------------------------------------------------------------------------

/// Generate backend configurations as (address, port, weight) tuples.
pub fn backend_configs(count: usize) -> Vec<(String, u16, u32)> {
    let mut rng = rand::rng();
    (0..count)
        .map(|i| {
            let addr = format!("10.0.{}.{}", i / 256, (i % 254) + 1);
            let port = rng.random_range(8000u16..=9000);
            let weight = rng.random_range(1u32..=10);
            (addr, port, weight)
        })
        .collect()
}

/// Generate random header maps for selection context.
pub fn random_headers(count: usize) -> Vec<HashMap<String, String>> {
    let header_names = [
        "X-Forwarded-For",
        "X-Real-IP",
        "X-Request-ID",
        "User-Agent",
        "Accept-Language",
    ];
    let mut rng = rand::rng();
    (0..count)
        .map(|_| {
            let mut headers = HashMap::new();
            for name in &header_names {
                if rng.random_bool(0.5) {
                    headers.insert(
                        name.to_string(),
                        format!("value-{}", rng.random_range(0u32..1000)),
                    );
                }
            }
            headers
        })
        .collect()
}

// ---------------------------------------------------------------------------
// Buffer / data generators
// ---------------------------------------------------------------------------

/// Generate random byte buffers of a given size.
pub fn random_bytes(size: usize) -> Vec<u8> {
    let mut rng = rand::rng();
    (0..size).map(|_| rng.random::<u8>()).collect()
}

/// Generate random byte buffers as `Bytes`.
pub fn random_bytes_buf(size: usize) -> Bytes {
    Bytes::from(random_bytes(size))
}

/// Generate a set of buffers with varying sizes for memory pool benchmarks.
pub fn varied_buffers(count: usize) -> Vec<Vec<u8>> {
    let sizes = [64, 256, 1024, 4096, 16384, 65536];
    let mut rng = rand::rng();
    (0..count)
        .map(|_| {
            let size = sizes[rng.random_range(0..sizes.len())];
            random_bytes(size)
        })
        .collect()
}
