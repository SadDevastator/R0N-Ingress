//! HTTP middleware pipeline.

use super::error::HttpResult;
use super::request::Request;
use super::response::Response;
use std::collections::HashMap;
use std::future::Future;
use std::pin::Pin;
use std::sync::Arc;
use std::time::Instant;
use tracing::{debug, info};

/// Type alias for async middleware result.
pub type MiddlewareFuture<'a> =
    Pin<Box<dyn Future<Output = HttpResult<MiddlewareAction>> + Send + 'a>>;

/// Action to take after middleware processing.
#[derive(Debug)]
pub enum MiddlewareAction {
    /// Continue to next middleware/handler.
    Continue(Request),
    /// Short-circuit with a response.
    Respond(Response),
}

/// Trait for HTTP middleware.
pub trait Middleware: Send + Sync {
    /// Middleware name.
    fn name(&self) -> &str;

    /// Process request before handler.
    fn before(&self, request: Request) -> HttpResult<MiddlewareAction> {
        Ok(MiddlewareAction::Continue(request))
    }

    /// Process response after handler.
    fn after(&self, _request: &Request, response: Response) -> HttpResult<Response> {
        Ok(response)
    }

    /// Priority (higher = runs first in before, last in after).
    fn priority(&self) -> i32 {
        0
    }
}

/// A chain of middleware.
pub struct MiddlewareChain {
    /// Middleware instances.
    middleware: Vec<Arc<dyn Middleware>>,
}

impl std::fmt::Debug for MiddlewareChain {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("MiddlewareChain")
            .field("middleware_count", &self.middleware.len())
            .finish()
    }
}

impl MiddlewareChain {
    /// Create a new empty middleware chain.
    #[must_use]
    pub fn new() -> Self {
        Self {
            middleware: Vec::new(),
        }
    }

    /// Add middleware to the chain.
    pub fn add(&mut self, middleware: Arc<dyn Middleware>) {
        self.middleware.push(middleware);
        // Sort by priority (descending for before, ascending for after)
        self.middleware
            .sort_by_key(|m| std::cmp::Reverse(m.priority()));
    }

    /// Process request through the middleware chain.
    pub fn process_request(&self, mut request: Request) -> HttpResult<MiddlewareAction> {
        for mw in &self.middleware {
            match mw.before(request)? {
                MiddlewareAction::Continue(req) => request = req,
                action @ MiddlewareAction::Respond(_) => return Ok(action),
            }
        }
        Ok(MiddlewareAction::Continue(request))
    }

    /// Process response through the middleware chain (reverse order).
    pub fn process_response(
        &self,
        request: &Request,
        mut response: Response,
    ) -> HttpResult<Response> {
        for mw in self.middleware.iter().rev() {
            response = mw.after(request, response)?;
        }
        Ok(response)
    }

    /// Get the number of middleware in the chain.
    #[must_use]
    pub fn len(&self) -> usize {
        self.middleware.len()
    }

    /// Check if the chain is empty.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.middleware.is_empty()
    }
}

impl Default for MiddlewareChain {
    fn default() -> Self {
        Self::new()
    }
}

// ============================================================================
// Built-in Middleware Implementations
// ============================================================================

/// Request ID middleware - adds X-Request-ID header.
#[derive(Debug)]
pub struct RequestIdMiddleware {
    /// Header name to use.
    header_name: String,
}

impl RequestIdMiddleware {
    /// Create a new request ID middleware.
    #[must_use]
    pub fn new() -> Self {
        Self {
            header_name: "x-request-id".to_string(),
        }
    }

    /// Create with a custom header name.
    #[must_use]
    pub fn with_header_name(name: impl Into<String>) -> Self {
        Self {
            header_name: name.into(),
        }
    }

    /// Generate a unique request ID.
    fn generate_id() -> String {
        use std::time::{SystemTime, UNIX_EPOCH};
        let timestamp = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_nanos();
        let random: u32 = rand::random();
        format!("{:x}-{:08x}", timestamp, random)
    }
}

impl Default for RequestIdMiddleware {
    fn default() -> Self {
        Self::new()
    }
}

impl Middleware for RequestIdMiddleware {
    fn name(&self) -> &str {
        "request-id"
    }

    fn before(&self, mut request: Request) -> HttpResult<MiddlewareAction> {
        // Only add if not already present
        if request.header(&self.header_name).is_none() {
            let id = Self::generate_id();
            request.set_header(&self.header_name, &id);
        }
        Ok(MiddlewareAction::Continue(request))
    }

    fn after(&self, request: &Request, mut response: Response) -> HttpResult<Response> {
        // Echo request ID in response
        if let Some(id) = request.header(&self.header_name) {
            response.set_header(&self.header_name, id);
        }
        Ok(response)
    }

    fn priority(&self) -> i32 {
        100 // Run early
    }
}

/// Timing middleware - adds X-Response-Time header.
#[derive(Debug)]
pub struct TimingMiddleware {
    /// Start times keyed by request ID.
    #[allow(dead_code)]
    start_times: std::sync::RwLock<HashMap<String, Instant>>,
}

impl TimingMiddleware {
    /// Create a new timing middleware.
    #[must_use]
    pub fn new() -> Self {
        Self {
            start_times: std::sync::RwLock::new(HashMap::new()),
        }
    }
}

impl Default for TimingMiddleware {
    fn default() -> Self {
        Self::new()
    }
}

impl Middleware for TimingMiddleware {
    fn name(&self) -> &str {
        "timing"
    }

    fn before(&self, mut request: Request) -> HttpResult<MiddlewareAction> {
        // Store start time in a custom header (internal use)
        let start = Instant::now();
        request.set_header(
            "x-internal-start-time",
            format!("{:?}", start.elapsed().as_nanos()),
        );
        Ok(MiddlewareAction::Continue(request))
    }

    fn after(&self, _request: &Request, mut response: Response) -> HttpResult<Response> {
        // Note: In a real implementation, we'd track the actual start time
        // For now, just add a placeholder
        response.set_header("x-response-time", "0ms");
        Ok(response)
    }

    fn priority(&self) -> i32 {
        99 // Run right after request-id
    }
}

/// Logger middleware - logs requests and responses.
#[derive(Debug)]
pub struct LoggerMiddleware {
    /// Log level.
    level: LogLevel,
}

/// Log level for the logger middleware.
#[derive(Debug, Clone, Copy)]
pub enum LogLevel {
    /// Debug level - verbose logging.
    Debug,
    /// Info level - standard logging.
    Info,
}

impl LoggerMiddleware {
    /// Create a new logger middleware.
    #[must_use]
    pub fn new() -> Self {
        Self {
            level: LogLevel::Info,
        }
    }

    /// Create with debug level.
    #[must_use]
    pub fn debug() -> Self {
        Self {
            level: LogLevel::Debug,
        }
    }
}

impl Default for LoggerMiddleware {
    fn default() -> Self {
        Self::new()
    }
}

impl Middleware for LoggerMiddleware {
    fn name(&self) -> &str {
        "logger"
    }

    fn before(&self, request: Request) -> HttpResult<MiddlewareAction> {
        match self.level {
            LogLevel::Debug => debug!(
                method = %request.method(),
                path = %request.path(),
                host = ?request.host(),
                "Incoming request"
            ),
            LogLevel::Info => info!(
                method = %request.method(),
                path = %request.path(),
                "Request"
            ),
        }
        Ok(MiddlewareAction::Continue(request))
    }

    fn after(&self, request: &Request, response: Response) -> HttpResult<Response> {
        match self.level {
            LogLevel::Debug => debug!(
                method = %request.method(),
                path = %request.path(),
                status = %response.status().as_u16(),
                "Response sent"
            ),
            LogLevel::Info => info!(
                method = %request.method(),
                path = %request.path(),
                status = %response.status().as_u16(),
                "Response"
            ),
        }
        Ok(response)
    }

    fn priority(&self) -> i32 {
        98 // Run after timing
    }
}

/// Header manipulation middleware.
#[derive(Debug)]
pub struct HeadersMiddleware {
    /// Headers to add to requests.
    request_add: HashMap<String, String>,
    /// Headers to remove from requests.
    request_remove: Vec<String>,
    /// Headers to add to responses.
    response_add: HashMap<String, String>,
    /// Headers to remove from responses.
    response_remove: Vec<String>,
}

impl HeadersMiddleware {
    /// Create a new headers middleware.
    #[must_use]
    pub fn new() -> Self {
        Self {
            request_add: HashMap::new(),
            request_remove: Vec::new(),
            response_add: HashMap::new(),
            response_remove: Vec::new(),
        }
    }

    /// Add a request header.
    pub fn add_request_header(mut self, name: impl Into<String>, value: impl Into<String>) -> Self {
        self.request_add.insert(name.into(), value.into());
        self
    }

    /// Remove a request header.
    pub fn remove_request_header(mut self, name: impl Into<String>) -> Self {
        self.request_remove.push(name.into());
        self
    }

    /// Add a response header.
    pub fn add_response_header(
        mut self,
        name: impl Into<String>,
        value: impl Into<String>,
    ) -> Self {
        self.response_add.insert(name.into(), value.into());
        self
    }

    /// Remove a response header.
    pub fn remove_response_header(mut self, name: impl Into<String>) -> Self {
        self.response_remove.push(name.into());
        self
    }
}

impl Default for HeadersMiddleware {
    fn default() -> Self {
        Self::new()
    }
}

impl Middleware for HeadersMiddleware {
    fn name(&self) -> &str {
        "headers"
    }

    fn before(&self, mut request: Request) -> HttpResult<MiddlewareAction> {
        for name in &self.request_remove {
            request.remove_header(name);
        }
        for (name, value) in &self.request_add {
            request.set_header(name, value);
        }
        Ok(MiddlewareAction::Continue(request))
    }

    fn after(&self, _request: &Request, mut response: Response) -> HttpResult<Response> {
        for name in &self.response_remove {
            response.remove_header(name);
        }
        for (name, value) in &self.response_add {
            response.set_header(name, value);
        }
        Ok(response)
    }

    fn priority(&self) -> i32 {
        50
    }
}

/// CORS middleware.
#[derive(Debug)]
pub struct CorsMiddleware {
    /// Allowed origins.
    allowed_origins: Vec<String>,
    /// Allowed methods.
    allowed_methods: Vec<String>,
    /// Allowed headers.
    allowed_headers: Vec<String>,
    /// Max age for preflight cache.
    max_age: u32,
    /// Allow credentials.
    allow_credentials: bool,
}

impl CorsMiddleware {
    /// Create a new CORS middleware with permissive defaults.
    #[must_use]
    pub fn new() -> Self {
        Self {
            allowed_origins: vec!["*".to_string()],
            allowed_methods: vec![
                "GET".to_string(),
                "POST".to_string(),
                "PUT".to_string(),
                "DELETE".to_string(),
                "OPTIONS".to_string(),
            ],
            allowed_headers: vec!["*".to_string()],
            max_age: 86400,
            allow_credentials: false,
        }
    }

    /// Set allowed origins.
    pub fn origins(mut self, origins: Vec<String>) -> Self {
        self.allowed_origins = origins;
        self
    }

    /// Set allowed methods.
    pub fn methods(mut self, methods: Vec<String>) -> Self {
        self.allowed_methods = methods;
        self
    }

    /// Allow credentials.
    pub fn credentials(mut self, allow: bool) -> Self {
        self.allow_credentials = allow;
        self
    }
}

impl Default for CorsMiddleware {
    fn default() -> Self {
        Self::new()
    }
}

impl Middleware for CorsMiddleware {
    fn name(&self) -> &str {
        "cors"
    }

    fn before(&self, request: Request) -> HttpResult<MiddlewareAction> {
        // Handle preflight OPTIONS request
        if request.method() == http::Method::OPTIONS {
            let response = Response::ok()
                .header(
                    "Access-Control-Allow-Origin",
                    self.allowed_origins.join(", "),
                )
                .header(
                    "Access-Control-Allow-Methods",
                    self.allowed_methods.join(", "),
                )
                .header(
                    "Access-Control-Allow-Headers",
                    self.allowed_headers.join(", "),
                )
                .header("Access-Control-Max-Age", self.max_age.to_string())
                .build();
            return Ok(MiddlewareAction::Respond(response));
        }
        Ok(MiddlewareAction::Continue(request))
    }

    fn after(&self, _request: &Request, mut response: Response) -> HttpResult<Response> {
        response.set_header(
            "Access-Control-Allow-Origin",
            self.allowed_origins.join(", "),
        );
        if self.allow_credentials {
            response.set_header("Access-Control-Allow-Credentials", "true");
        }
        Ok(response)
    }

    fn priority(&self) -> i32 {
        90 // Run early to handle preflight
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_request(method: &str, path: &str) -> Request {
        let data = format!("{method} {path} HTTP/1.1\r\nHost: example.com\r\n\r\n");
        let (req, _) = Request::parse(data.as_bytes()).unwrap();
        req
    }

    #[test]
    fn test_middleware_chain() {
        let mut chain = MiddlewareChain::new();
        chain.add(Arc::new(RequestIdMiddleware::new()));
        chain.add(Arc::new(LoggerMiddleware::new()));

        assert_eq!(chain.len(), 2);

        let request = make_request("GET", "/test");
        let action = chain.process_request(request).unwrap();

        match action {
            MiddlewareAction::Continue(req) => {
                assert!(req.header("x-request-id").is_some());
            },
            _ => panic!("Expected Continue"),
        }
    }

    #[test]
    fn test_request_id_middleware() {
        let mw = RequestIdMiddleware::new();
        let request = make_request("GET", "/test");

        match mw.before(request).unwrap() {
            MiddlewareAction::Continue(req) => {
                assert!(req.header("x-request-id").is_some());
            },
            _ => panic!("Expected Continue"),
        }
    }

    #[test]
    fn test_headers_middleware() {
        let mw = HeadersMiddleware::new()
            .add_request_header("X-Custom", "value")
            .add_response_header("X-Server", "R0N Gateway");

        let request = make_request("GET", "/test");

        match mw.before(request).unwrap() {
            MiddlewareAction::Continue(req) => {
                assert_eq!(req.header("x-custom"), Some("value"));
            },
            _ => panic!("Expected Continue"),
        }
    }

    #[test]
    fn test_cors_preflight() {
        let mw = CorsMiddleware::new();

        let data =
            b"OPTIONS /api HTTP/1.1\r\nHost: example.com\r\nOrigin: http://localhost\r\n\r\n";
        let (request, _) = Request::parse(data).unwrap();

        match mw.before(request).unwrap() {
            MiddlewareAction::Respond(resp) => {
                assert!(resp.header("access-control-allow-origin").is_some());
            },
            _ => panic!("Expected Respond for OPTIONS"),
        }
    }

    #[test]
    fn test_middleware_priority() {
        let mut chain = MiddlewareChain::new();

        let low = Arc::new(LoggerMiddleware::new()); // priority 98
        let high = Arc::new(RequestIdMiddleware::new()); // priority 100

        chain.add(low);
        chain.add(high);

        // High priority should be first
        assert_eq!(chain.middleware[0].priority(), 100);
        assert_eq!(chain.middleware[1].priority(), 98);
    }
}
