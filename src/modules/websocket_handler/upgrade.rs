//! WebSocket HTTP upgrade handling.
//!
//! Implements the WebSocket handshake per RFC 6455.

use crate::modules::websocket_handler::error::{WebSocketError, WebSocketResult};
use base64::Engine;
use sha1::{Digest, Sha1};
use std::collections::HashMap;

/// WebSocket magic GUID for Sec-WebSocket-Accept calculation.
const WS_GUID: &str = "258EAFA5-E914-47DA-95CA-C5AB0DC85B11";

/// Parsed WebSocket upgrade request.
#[derive(Debug, Clone)]
pub struct UpgradeRequest {
    /// Request path.
    pub path: String,

    /// Host header.
    #[allow(dead_code)]
    pub host: Option<String>,

    /// Origin header.
    pub origin: Option<String>,

    /// Sec-WebSocket-Key header.
    pub key: String,

    /// Sec-WebSocket-Version header.
    #[allow(dead_code)]
    pub version: u8,

    /// Sec-WebSocket-Protocol header (subprotocols).
    pub protocols: Vec<String>,

    /// Sec-WebSocket-Extensions header.
    #[allow(dead_code)]
    pub extensions: Vec<String>,

    /// All headers.
    #[allow(dead_code)]
    pub headers: HashMap<String, String>,
}

impl UpgradeRequest {
    /// Parse an HTTP upgrade request.
    pub fn parse(request: &[u8]) -> WebSocketResult<Self> {
        let request_str = std::str::from_utf8(request)
            .map_err(|_| WebSocketError::InvalidUpgrade("Invalid UTF-8".to_string()))?;

        let mut lines = request_str.lines();

        // Parse request line
        let request_line = lines
            .next()
            .ok_or_else(|| WebSocketError::InvalidUpgrade("Empty request".to_string()))?;

        let parts: Vec<&str> = request_line.split_whitespace().collect();
        if parts.len() < 3 {
            return Err(WebSocketError::InvalidUpgrade(
                "Invalid request line".to_string(),
            ));
        }

        let method = parts[0];
        let path = parts[1].to_string();

        if method != "GET" {
            return Err(WebSocketError::InvalidUpgrade(format!(
                "Expected GET, got {method}"
            )));
        }

        // Parse headers
        let mut headers = HashMap::new();
        for line in lines {
            if line.is_empty() {
                break;
            }
            if let Some((name, value)) = line.split_once(':') {
                headers.insert(name.trim().to_lowercase(), value.trim().to_string());
            }
        }

        // Validate required headers
        let connection = headers.get("connection").map(|s| s.to_lowercase());
        if !connection.as_ref().is_some_and(|c| c.contains("upgrade")) {
            return Err(WebSocketError::InvalidUpgrade(
                "Missing or invalid Connection header".to_string(),
            ));
        }

        let upgrade = headers.get("upgrade").map(|s| s.to_lowercase());
        if upgrade.as_deref() != Some("websocket") {
            return Err(WebSocketError::InvalidUpgrade(
                "Missing or invalid Upgrade header".to_string(),
            ));
        }

        let key = headers
            .get("sec-websocket-key")
            .ok_or(WebSocketError::InvalidKey)?
            .clone();

        let version = headers
            .get("sec-websocket-version")
            .and_then(|v| v.parse().ok())
            .unwrap_or(13);

        let protocols = headers
            .get("sec-websocket-protocol")
            .map(|p| p.split(',').map(|s| s.trim().to_string()).collect())
            .unwrap_or_default();

        let extensions = headers
            .get("sec-websocket-extensions")
            .map(|e| e.split(',').map(|s| s.trim().to_string()).collect())
            .unwrap_or_default();

        let host = headers.get("host").cloned();
        let origin = headers.get("origin").cloned();

        Ok(Self {
            path,
            host,
            origin,
            key,
            version,
            protocols,
            extensions,
            headers,
        })
    }

    /// Validate the WebSocket key format.
    pub fn validate_key(&self) -> bool {
        // Key should be 16 bytes base64 encoded (24 chars with padding)
        if let Ok(decoded) = base64::engine::general_purpose::STANDARD.decode(&self.key) {
            decoded.len() == 16
        } else {
            false
        }
    }
}

/// WebSocket upgrade response builder.
#[derive(Debug)]
pub struct UpgradeResponse {
    /// Selected subprotocol.
    pub protocol: Option<String>,

    /// Accepted extensions.
    #[allow(dead_code)]
    pub extensions: Vec<String>,

    /// Additional headers.
    #[allow(dead_code)]
    pub headers: HashMap<String, String>,
}

impl Default for UpgradeResponse {
    fn default() -> Self {
        Self::new()
    }
}

impl UpgradeResponse {
    /// Create a new response builder.
    pub fn new() -> Self {
        Self {
            protocol: None,
            extensions: Vec::new(),
            headers: HashMap::new(),
        }
    }

    /// Set the selected subprotocol.
    pub fn protocol(mut self, protocol: impl Into<String>) -> Self {
        self.protocol = Some(protocol.into());
        self
    }

    /// Add an accepted extension.
    #[allow(dead_code)]
    pub fn extension(mut self, extension: impl Into<String>) -> Self {
        self.extensions.push(extension.into());
        self
    }

    /// Add a custom header.
    #[allow(dead_code)]
    pub fn header(mut self, name: impl Into<String>, value: impl Into<String>) -> Self {
        self.headers.insert(name.into(), value.into());
        self
    }

    /// Build the HTTP response bytes.
    pub fn build(&self, key: &str) -> Vec<u8> {
        let accept = compute_accept_key(key);

        let mut response = format!(
            "HTTP/1.1 101 Switching Protocols\r\n\
             Upgrade: websocket\r\n\
             Connection: Upgrade\r\n\
             Sec-WebSocket-Accept: {accept}\r\n"
        );

        if let Some(ref protocol) = self.protocol {
            response.push_str(&format!("Sec-WebSocket-Protocol: {protocol}\r\n"));
        }

        if !self.extensions.is_empty() {
            response.push_str(&format!(
                "Sec-WebSocket-Extensions: {}\r\n",
                self.extensions.join(", ")
            ));
        }

        for (name, value) in &self.headers {
            response.push_str(&format!("{name}: {value}\r\n"));
        }

        response.push_str("\r\n");
        response.into_bytes()
    }
}

/// Compute Sec-WebSocket-Accept value from client key.
pub fn compute_accept_key(key: &str) -> String {
    let mut hasher = Sha1::new();
    hasher.update(key.as_bytes());
    hasher.update(WS_GUID.as_bytes());
    let hash = hasher.finalize();
    base64::engine::general_purpose::STANDARD.encode(hash)
}

/// Build an error response for failed upgrades.
pub fn error_response(status: u16, reason: &str) -> Vec<u8> {
    let status_text = match status {
        400 => "Bad Request",
        401 => "Unauthorized",
        403 => "Forbidden",
        404 => "Not Found",
        426 => "Upgrade Required",
        500 => "Internal Server Error",
        503 => "Service Unavailable",
        _ => "Error",
    };

    format!(
        "HTTP/1.1 {status} {status_text}\r\n\
         Content-Type: text/plain\r\n\
         Content-Length: {}\r\n\
         Connection: close\r\n\
         \r\n\
         {reason}",
        reason.len()
    )
    .into_bytes()
}

/// Negotiate subprotocol from client request and server supported list.
pub fn negotiate_protocol(requested: &[String], supported: &[String]) -> Option<String> {
    for req in requested {
        if supported.iter().any(|s| s.eq_ignore_ascii_case(req)) {
            return Some(req.clone());
        }
    }
    None
}

/// Check if origin is allowed.
pub fn check_origin(origin: Option<&str>, allowed: &[String]) -> bool {
    // If no allowed origins specified, all are allowed
    if allowed.is_empty() {
        return true;
    }

    match origin {
        Some(origin) => allowed.iter().any(|a| {
            if a == "*" {
                true
            } else if a.starts_with("*.") {
                // Wildcard subdomain match
                let suffix = &a[1..]; // ".example.com"
                origin.ends_with(suffix) || origin == &a[2..]
            } else {
                a == origin
            }
        }),
        None => false,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_upgrade_request() {
        let request = b"GET /ws HTTP/1.1\r\n\
                        Host: example.com\r\n\
                        Upgrade: websocket\r\n\
                        Connection: Upgrade\r\n\
                        Sec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\n\
                        Sec-WebSocket-Version: 13\r\n\
                        \r\n";

        let req = UpgradeRequest::parse(request).unwrap();
        assert_eq!(req.path, "/ws");
        assert_eq!(req.host, Some("example.com".to_string()));
        assert_eq!(req.key, "dGhlIHNhbXBsZSBub25jZQ==");
        assert_eq!(req.version, 13);
    }

    #[test]
    fn test_parse_with_protocols() {
        let request = b"GET /ws HTTP/1.1\r\n\
                        Host: example.com\r\n\
                        Upgrade: websocket\r\n\
                        Connection: Upgrade\r\n\
                        Sec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\n\
                        Sec-WebSocket-Version: 13\r\n\
                        Sec-WebSocket-Protocol: graphql-ws, json\r\n\
                        \r\n";

        let req = UpgradeRequest::parse(request).unwrap();
        assert_eq!(req.protocols, vec!["graphql-ws", "json"]);
    }

    #[test]
    fn test_parse_missing_upgrade() {
        let request = b"GET /ws HTTP/1.1\r\n\
                        Host: example.com\r\n\
                        Connection: keep-alive\r\n\
                        \r\n";

        let result = UpgradeRequest::parse(request);
        assert!(result.is_err());
    }

    #[test]
    fn test_validate_key() {
        let request = b"GET /ws HTTP/1.1\r\n\
                        Host: example.com\r\n\
                        Upgrade: websocket\r\n\
                        Connection: Upgrade\r\n\
                        Sec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\n\
                        Sec-WebSocket-Version: 13\r\n\
                        \r\n";

        let req = UpgradeRequest::parse(request).unwrap();
        assert!(req.validate_key());
    }

    #[test]
    fn test_compute_accept_key() {
        // Test vector from RFC 6455
        let key = "dGhlIHNhbXBsZSBub25jZQ==";
        let accept = compute_accept_key(key);
        assert_eq!(accept, "s3pPLMBiTxaQ9kYGzzhZRbK+xOo=");
    }

    #[test]
    fn test_upgrade_response_build() {
        let response = UpgradeResponse::new()
            .protocol("graphql-ws")
            .header("X-Custom", "value")
            .build("dGhlIHNhbXBsZSBub25jZQ==");

        let response_str = String::from_utf8(response).unwrap();
        assert!(response_str.contains("101 Switching Protocols"));
        assert!(response_str.contains("Upgrade: websocket"));
        assert!(response_str.contains("Sec-WebSocket-Accept: s3pPLMBiTxaQ9kYGzzhZRbK+xOo="));
        assert!(response_str.contains("Sec-WebSocket-Protocol: graphql-ws"));
        assert!(response_str.contains("X-Custom: value"));
    }

    #[test]
    fn test_error_response() {
        let response = error_response(400, "Invalid request");
        let response_str = String::from_utf8(response).unwrap();
        assert!(response_str.contains("400 Bad Request"));
        assert!(response_str.contains("Invalid request"));
    }

    #[test]
    fn test_negotiate_protocol() {
        let requested = vec!["graphql-ws".to_string(), "json".to_string()];
        let supported = vec!["json".to_string(), "xml".to_string()];

        let result = negotiate_protocol(&requested, &supported);
        // Returns first matching from requested list
        assert_eq!(result, Some("json".to_string()));
    }

    #[test]
    fn test_negotiate_protocol_no_match() {
        let requested = vec!["graphql-ws".to_string()];
        let supported = vec!["json".to_string()];

        let result = negotiate_protocol(&requested, &supported);
        assert_eq!(result, None);
    }

    #[test]
    fn test_check_origin_empty_allowed() {
        // Empty allowed list means all origins allowed
        assert!(check_origin(Some("https://example.com"), &[]));
        assert!(check_origin(None, &[]));
    }

    #[test]
    fn test_check_origin_exact_match() {
        let allowed = vec!["https://example.com".to_string()];
        assert!(check_origin(Some("https://example.com"), &allowed));
        assert!(!check_origin(Some("https://other.com"), &allowed));
    }

    #[test]
    fn test_check_origin_wildcard() {
        let allowed = vec!["*".to_string()];
        assert!(check_origin(Some("https://example.com"), &allowed));
        assert!(check_origin(Some("https://any.com"), &allowed));
    }

    #[test]
    fn test_check_origin_wildcard_subdomain() {
        let allowed = vec!["*.example.com".to_string()];
        assert!(check_origin(Some("https://sub.example.com"), &allowed));
        assert!(check_origin(Some("https://deep.sub.example.com"), &allowed));
        assert!(check_origin(Some("example.com"), &allowed));
        assert!(!check_origin(Some("https://other.com"), &allowed));
    }

    #[test]
    fn test_check_origin_none() {
        let allowed = vec!["https://example.com".to_string()];
        assert!(!check_origin(None, &allowed));
    }
}
