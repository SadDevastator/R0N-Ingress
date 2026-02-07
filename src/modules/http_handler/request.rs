//! HTTP request parsing and handling.

use super::error::{HttpError, HttpResult};
use bytes::{Bytes, BytesMut};
use http::{Method, Uri, Version};
use std::collections::HashMap;
use std::str::FromStr;

/// Maximum number of headers to parse.
const MAX_HEADERS: usize = 100;

/// Parsed HTTP request.
#[derive(Debug, Clone)]
pub struct Request {
    /// HTTP method.
    method: Method,
    /// Request URI.
    uri: Uri,
    /// HTTP version.
    version: Version,
    /// Request headers.
    headers: HashMap<String, String>,
    /// Request body.
    body: Bytes,
    /// Remote address (if known).
    remote_addr: Option<String>,
    /// Request ID (for tracing).
    request_id: Option<String>,
}

impl Request {
    /// Create a new request builder.
    #[must_use]
    pub fn builder() -> RequestBuilder {
        RequestBuilder::new()
    }

    /// Get the HTTP method.
    #[must_use]
    pub fn method(&self) -> &Method {
        &self.method
    }

    /// Get the request URI.
    #[must_use]
    pub fn uri(&self) -> &Uri {
        &self.uri
    }

    /// Get the request path.
    #[must_use]
    pub fn path(&self) -> &str {
        self.uri.path()
    }

    /// Get the query string.
    #[must_use]
    pub fn query(&self) -> Option<&str> {
        self.uri.query()
    }

    /// Get the HTTP version.
    #[must_use]
    pub fn version(&self) -> Version {
        self.version
    }

    /// Get a header value.
    #[must_use]
    pub fn header(&self, name: &str) -> Option<&str> {
        self.headers.get(&name.to_lowercase()).map(|s| s.as_str())
    }

    /// Get all headers.
    #[must_use]
    pub fn headers(&self) -> &HashMap<String, String> {
        &self.headers
    }

    /// Get the Host header.
    #[must_use]
    pub fn host(&self) -> Option<&str> {
        self.header("host")
    }

    /// Get the Content-Type header.
    #[must_use]
    pub fn content_type(&self) -> Option<&str> {
        self.header("content-type")
    }

    /// Get the Content-Length header as usize.
    #[must_use]
    pub fn content_length(&self) -> Option<usize> {
        self.header("content-length").and_then(|s| s.parse().ok())
    }

    /// Get the request body.
    #[must_use]
    pub fn body(&self) -> &Bytes {
        &self.body
    }

    /// Take the request body.
    pub fn into_body(self) -> Bytes {
        self.body
    }

    /// Get the remote address.
    #[must_use]
    pub fn remote_addr(&self) -> Option<&str> {
        self.remote_addr.as_deref()
    }

    /// Get the request ID.
    #[must_use]
    pub fn request_id(&self) -> Option<&str> {
        self.request_id.as_deref()
    }

    /// Set a header value.
    pub fn set_header(&mut self, name: impl Into<String>, value: impl Into<String>) {
        self.headers
            .insert(name.into().to_lowercase(), value.into());
    }

    /// Remove a header.
    pub fn remove_header(&mut self, name: &str) -> Option<String> {
        self.headers.remove(&name.to_lowercase())
    }

    /// Check if connection should be kept alive.
    #[must_use]
    pub fn is_keep_alive(&self) -> bool {
        match self.version {
            Version::HTTP_11 | Version::HTTP_2 => {
                // Default to keep-alive unless Connection: close
                self.header("connection")
                    .map(|v| !v.eq_ignore_ascii_case("close"))
                    .unwrap_or(true)
            },
            Version::HTTP_10 => {
                // Default to close unless Connection: keep-alive
                self.header("connection")
                    .map(|v| v.eq_ignore_ascii_case("keep-alive"))
                    .unwrap_or(false)
            },
            _ => false,
        }
    }

    /// Parse a request from bytes.
    pub fn parse(data: &[u8]) -> HttpResult<(Self, usize)> {
        let mut headers = [httparse::EMPTY_HEADER; MAX_HEADERS];
        let mut req = httparse::Request::new(&mut headers);

        match req.parse(data)? {
            httparse::Status::Complete(body_offset) => {
                let method = Method::from_str(req.method.unwrap_or("GET"))
                    .map_err(|e| HttpError::InvalidMethod(e.to_string()))?;

                let uri = Uri::from_str(req.path.unwrap_or("/"))
                    .map_err(|e| HttpError::InvalidUri(e.to_string()))?;

                let version = match req.version {
                    Some(0) => Version::HTTP_10,
                    Some(1) => Version::HTTP_11,
                    _ => Version::HTTP_11,
                };

                let mut headers_map = HashMap::new();
                for header in req.headers.iter() {
                    let name = header.name.to_lowercase();
                    let value = String::from_utf8_lossy(header.value).to_string();
                    headers_map.insert(name, value);
                }

                let request = Request {
                    method,
                    uri,
                    version,
                    headers: headers_map,
                    body: Bytes::new(),
                    remote_addr: None,
                    request_id: None,
                };

                Ok((request, body_offset))
            },
            httparse::Status::Partial => Err(HttpError::Parse("Incomplete request".to_string())),
        }
    }

    /// Serialize the request to bytes.
    pub fn serialize(&self) -> BytesMut {
        let mut buf = BytesMut::new();

        // Request line
        let version_str = match self.version {
            Version::HTTP_10 => "HTTP/1.0",
            Version::HTTP_11 => "HTTP/1.1",
            Version::HTTP_2 => "HTTP/2.0",
            _ => "HTTP/1.1",
        };
        buf.extend_from_slice(
            format!("{} {} {}\r\n", self.method, self.uri, version_str).as_bytes(),
        );

        // Headers
        for (name, value) in &self.headers {
            buf.extend_from_slice(format!("{}: {}\r\n", name, value).as_bytes());
        }

        // End of headers
        buf.extend_from_slice(b"\r\n");

        // Body
        if !self.body.is_empty() {
            buf.extend_from_slice(&self.body);
        }

        buf
    }
}

/// Builder for HTTP requests.
#[derive(Debug, Default)]
pub struct RequestBuilder {
    method: Option<Method>,
    uri: Option<Uri>,
    version: Version,
    headers: HashMap<String, String>,
    body: Bytes,
    remote_addr: Option<String>,
    request_id: Option<String>,
}

impl RequestBuilder {
    /// Create a new request builder.
    #[must_use]
    pub fn new() -> Self {
        Self {
            version: Version::HTTP_11,
            ..Default::default()
        }
    }

    /// Set the HTTP method.
    pub fn method(mut self, method: Method) -> Self {
        self.method = Some(method);
        self
    }

    /// Set the request URI.
    pub fn uri(mut self, uri: impl Into<String>) -> HttpResult<Self> {
        self.uri = Some(Uri::from_str(&uri.into())?);
        Ok(self)
    }

    /// Set the HTTP version.
    pub fn version(mut self, version: Version) -> Self {
        self.version = version;
        self
    }

    /// Add a header.
    pub fn header(mut self, name: impl Into<String>, value: impl Into<String>) -> Self {
        self.headers
            .insert(name.into().to_lowercase(), value.into());
        self
    }

    /// Set the request body.
    pub fn body(mut self, body: impl Into<Bytes>) -> Self {
        self.body = body.into();
        self
    }

    /// Set the remote address.
    pub fn remote_addr(mut self, addr: impl Into<String>) -> Self {
        self.remote_addr = Some(addr.into());
        self
    }

    /// Set the request ID.
    pub fn request_id(mut self, id: impl Into<String>) -> Self {
        self.request_id = Some(id.into());
        self
    }

    /// Build the request.
    pub fn build(self) -> HttpResult<Request> {
        Ok(Request {
            method: self.method.unwrap_or(Method::GET),
            uri: self.uri.unwrap_or_else(|| Uri::from_static("/")),
            version: self.version,
            headers: self.headers,
            body: self.body,
            remote_addr: self.remote_addr,
            request_id: self.request_id,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_simple_request() {
        let data = b"GET /index.html HTTP/1.1\r\nHost: example.com\r\n\r\n";
        let (req, offset) = Request::parse(data).unwrap();

        assert_eq!(req.method(), Method::GET);
        assert_eq!(req.path(), "/index.html");
        assert_eq!(req.version(), Version::HTTP_11);
        assert_eq!(req.host(), Some("example.com"));
        assert_eq!(offset, data.len());
    }

    #[test]
    fn test_parse_post_request() {
        let data = b"POST /api/users HTTP/1.1\r\nHost: api.example.com\r\nContent-Type: application/json\r\nContent-Length: 13\r\n\r\n";
        let (req, _) = Request::parse(data).unwrap();

        assert_eq!(req.method(), Method::POST);
        assert_eq!(req.path(), "/api/users");
        assert_eq!(req.content_type(), Some("application/json"));
        assert_eq!(req.content_length(), Some(13));
    }

    #[test]
    fn test_request_builder() {
        let req = Request::builder()
            .method(Method::POST)
            .uri("/api/test")
            .unwrap()
            .header("Content-Type", "application/json")
            .body(Bytes::from(r#"{"key": "value"}"#))
            .build()
            .unwrap();

        assert_eq!(req.method(), Method::POST);
        assert_eq!(req.path(), "/api/test");
        assert_eq!(req.content_type(), Some("application/json"));
    }

    #[test]
    fn test_keep_alive_http11() {
        let data = b"GET / HTTP/1.1\r\nHost: example.com\r\n\r\n";
        let (req, _) = Request::parse(data).unwrap();
        assert!(req.is_keep_alive());
    }

    #[test]
    fn test_keep_alive_close() {
        let data = b"GET / HTTP/1.1\r\nHost: example.com\r\nConnection: close\r\n\r\n";
        let (req, _) = Request::parse(data).unwrap();
        assert!(!req.is_keep_alive());
    }

    #[test]
    fn test_request_serialize() {
        let req = Request::builder()
            .method(Method::GET)
            .uri("/test")
            .unwrap()
            .header("Host", "example.com")
            .build()
            .unwrap();

        let serialized = req.serialize();
        let s = String::from_utf8_lossy(&serialized);
        assert!(s.contains("GET /test HTTP/1.1"));
        assert!(s.contains("host: example.com"));
    }

    #[test]
    fn test_header_manipulation() {
        let mut req = Request::builder()
            .method(Method::GET)
            .uri("/")
            .unwrap()
            .header("X-Custom", "value")
            .build()
            .unwrap();

        assert_eq!(req.header("x-custom"), Some("value"));

        req.set_header("X-Another", "another");
        assert_eq!(req.header("x-another"), Some("another"));

        req.remove_header("x-custom");
        assert!(req.header("x-custom").is_none());
    }
}
