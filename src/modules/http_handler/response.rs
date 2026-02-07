//! HTTP response building and serialization.

use super::error::HttpResult;
use bytes::{Bytes, BytesMut};
use http::{StatusCode, Version};
use std::collections::HashMap;

/// HTTP response.
#[derive(Debug, Clone)]
pub struct Response {
    /// HTTP status code.
    status: StatusCode,
    /// HTTP version.
    version: Version,
    /// Response headers.
    headers: HashMap<String, String>,
    /// Response body.
    body: Bytes,
}

impl Response {
    /// Create a new response builder.
    #[must_use]
    pub fn builder() -> ResponseBuilder {
        ResponseBuilder::new()
    }

    /// Create an OK (200) response.
    #[must_use]
    pub fn ok() -> ResponseBuilder {
        ResponseBuilder::new().status(StatusCode::OK)
    }

    /// Create a Not Found (404) response.
    #[must_use]
    pub fn not_found() -> ResponseBuilder {
        ResponseBuilder::new().status(StatusCode::NOT_FOUND)
    }

    /// Create a Bad Request (400) response.
    #[must_use]
    pub fn bad_request() -> ResponseBuilder {
        ResponseBuilder::new().status(StatusCode::BAD_REQUEST)
    }

    /// Create an Internal Server Error (500) response.
    #[must_use]
    pub fn internal_error() -> ResponseBuilder {
        ResponseBuilder::new().status(StatusCode::INTERNAL_SERVER_ERROR)
    }

    /// Create a Service Unavailable (503) response.
    #[must_use]
    pub fn service_unavailable() -> ResponseBuilder {
        ResponseBuilder::new().status(StatusCode::SERVICE_UNAVAILABLE)
    }

    /// Get the status code.
    #[must_use]
    pub fn status(&self) -> StatusCode {
        self.status
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

    /// Get the Content-Type header.
    #[must_use]
    pub fn content_type(&self) -> Option<&str> {
        self.header("content-type")
    }

    /// Get the Content-Length.
    #[must_use]
    pub fn content_length(&self) -> Option<usize> {
        self.header("content-length").and_then(|s| s.parse().ok())
    }

    /// Get the response body.
    #[must_use]
    pub fn body(&self) -> &Bytes {
        &self.body
    }

    /// Take the response body.
    pub fn into_body(self) -> Bytes {
        self.body
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

    /// Serialize the response to bytes.
    #[must_use]
    pub fn serialize(&self) -> BytesMut {
        let mut buf = BytesMut::new();

        // Status line
        let version_str = match self.version {
            Version::HTTP_10 => "HTTP/1.0",
            Version::HTTP_11 => "HTTP/1.1",
            Version::HTTP_2 => "HTTP/2.0",
            _ => "HTTP/1.1",
        };
        buf.extend_from_slice(
            format!(
                "{} {} {}\r\n",
                version_str,
                self.status.as_u16(),
                self.status.canonical_reason().unwrap_or("")
            )
            .as_bytes(),
        );

        // Headers
        for (name, value) in &self.headers {
            buf.extend_from_slice(format!("{}: {}\r\n", name, value).as_bytes());
        }

        // Content-Length if not set and we have a body
        if !self.body.is_empty() && !self.headers.contains_key("content-length") {
            buf.extend_from_slice(format!("Content-Length: {}\r\n", self.body.len()).as_bytes());
        }

        // End of headers
        buf.extend_from_slice(b"\r\n");

        // Body
        if !self.body.is_empty() {
            buf.extend_from_slice(&self.body);
        }

        buf
    }

    /// Parse a response from bytes.
    pub fn parse(data: &[u8]) -> HttpResult<(Self, usize)> {
        let mut headers = [httparse::EMPTY_HEADER; 100];
        let mut resp = httparse::Response::new(&mut headers);

        match resp.parse(data)? {
            httparse::Status::Complete(body_offset) => {
                let status =
                    StatusCode::from_u16(resp.code.unwrap_or(200)).unwrap_or(StatusCode::OK);

                let version = match resp.version {
                    Some(0) => Version::HTTP_10,
                    Some(1) => Version::HTTP_11,
                    _ => Version::HTTP_11,
                };

                let mut headers_map = HashMap::new();
                for header in resp.headers.iter() {
                    let name = header.name.to_lowercase();
                    let value = String::from_utf8_lossy(header.value).to_string();
                    headers_map.insert(name, value);
                }

                let response = Response {
                    status,
                    version,
                    headers: headers_map,
                    body: Bytes::new(),
                };

                Ok((response, body_offset))
            },
            httparse::Status::Partial => Err(super::error::HttpError::Parse(
                "Incomplete response".to_string(),
            )),
        }
    }
}

impl Default for Response {
    fn default() -> Self {
        Self {
            status: StatusCode::OK,
            version: Version::HTTP_11,
            headers: HashMap::new(),
            body: Bytes::new(),
        }
    }
}

/// Builder for HTTP responses.
#[derive(Debug)]
pub struct ResponseBuilder {
    status: StatusCode,
    version: Version,
    headers: HashMap<String, String>,
    body: Bytes,
}

impl ResponseBuilder {
    /// Create a new response builder.
    #[must_use]
    pub fn new() -> Self {
        Self {
            status: StatusCode::OK,
            version: Version::HTTP_11,
            headers: HashMap::new(),
            body: Bytes::new(),
        }
    }

    /// Set the status code.
    pub fn status(mut self, status: StatusCode) -> Self {
        self.status = status;
        self
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

    /// Set the Content-Type header.
    pub fn content_type(self, content_type: impl Into<String>) -> Self {
        self.header("content-type", content_type)
    }

    /// Set the response body.
    pub fn body(mut self, body: impl Into<Bytes>) -> Self {
        self.body = body.into();
        self
    }

    /// Set a text body with Content-Type: text/plain.
    pub fn text(self, text: impl Into<String>) -> Self {
        let text = text.into();
        self.content_type("text/plain; charset=utf-8")
            .body(Bytes::from(text))
    }

    /// Set a JSON body with Content-Type: application/json.
    pub fn json(self, json: impl Into<String>) -> Self {
        let json = json.into();
        self.content_type("application/json")
            .body(Bytes::from(json))
    }

    /// Set an HTML body with Content-Type: text/html.
    pub fn html(self, html: impl Into<String>) -> Self {
        let html = html.into();
        self.content_type("text/html; charset=utf-8")
            .body(Bytes::from(html))
    }

    /// Build the response.
    #[must_use]
    pub fn build(self) -> Response {
        Response {
            status: self.status,
            version: self.version,
            headers: self.headers,
            body: self.body,
        }
    }
}

impl Default for ResponseBuilder {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_response_builder() {
        let resp = Response::builder()
            .status(StatusCode::OK)
            .header("Content-Type", "application/json")
            .body(Bytes::from(r#"{"status":"ok"}"#))
            .build();

        assert_eq!(resp.status(), StatusCode::OK);
        assert_eq!(resp.content_type(), Some("application/json"));
    }

    #[test]
    fn test_response_shortcuts() {
        let resp = Response::not_found().text("Page not found").build();
        assert_eq!(resp.status(), StatusCode::NOT_FOUND);
        assert_eq!(resp.content_type(), Some("text/plain; charset=utf-8"));
    }

    #[test]
    fn test_response_serialize() {
        let resp = Response::ok().json(r#"{"key":"value"}"#).build();

        let serialized = resp.serialize();
        let s = String::from_utf8_lossy(&serialized);
        assert!(s.contains("HTTP/1.1 200 OK"));
        assert!(s.contains("content-type: application/json"));
    }

    #[test]
    fn test_response_parse() {
        let data = b"HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\nContent-Length: 5\r\n\r\nhello";
        let (resp, offset) = Response::parse(data).unwrap();

        assert_eq!(resp.status(), StatusCode::OK);
        assert_eq!(resp.content_type(), Some("text/plain"));
        assert_eq!(resp.content_length(), Some(5));
        assert_eq!(offset, data.len() - 5); // Body starts after headers
    }

    #[test]
    fn test_header_manipulation() {
        let mut resp = Response::ok().build();
        resp.set_header("X-Custom", "value");
        assert_eq!(resp.header("x-custom"), Some("value"));

        resp.remove_header("x-custom");
        assert!(resp.header("x-custom").is_none());
    }

    #[test]
    fn test_internal_error() {
        let resp = Response::internal_error()
            .text("Something went wrong")
            .build();
        assert_eq!(resp.status(), StatusCode::INTERNAL_SERVER_ERROR);
    }
}
