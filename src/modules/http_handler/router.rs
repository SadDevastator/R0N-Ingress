//! HTTP request routing.

use super::config::{BackendConfig, RouteConfig};
use super::error::{HttpError, HttpResult};
use super::request::Request;
use http::Method;
use std::collections::HashMap;
use std::sync::Arc;
use tracing::debug;

/// A compiled route for matching requests.
#[derive(Debug, Clone)]
pub struct Route {
    /// Route name.
    name: String,
    /// Path pattern (compiled).
    path_pattern: PathPattern,
    /// Methods to match (empty = all).
    methods: Vec<Method>,
    /// Host pattern.
    host_pattern: Option<String>,
    /// Required headers.
    required_headers: HashMap<String, String>,
    /// Backend configuration.
    backend: BackendConfig,
    /// Priority (higher = first).
    priority: i32,
    /// Strip prefix from path.
    strip_prefix: bool,
    /// Path rewrite pattern.
    rewrite: Option<String>,
    /// Route-specific middleware names.
    middleware: Vec<String>,
}

impl Route {
    /// Create a route from configuration.
    pub fn from_config(config: RouteConfig) -> HttpResult<Self> {
        let methods = config
            .methods
            .iter()
            .map(|m| m.parse::<Method>())
            .collect::<Result<Vec<_>, _>>()
            .map_err(|e| HttpError::Config(format!("Invalid method: {e}")))?;

        let path_pattern = PathPattern::compile(&config.path)?;

        Ok(Self {
            name: config.name,
            path_pattern,
            methods,
            host_pattern: config.host,
            required_headers: config.headers,
            backend: config.backend,
            priority: config.priority,
            strip_prefix: config.strip_prefix,
            rewrite: config.rewrite,
            middleware: config.middleware,
        })
    }

    /// Get the route name.
    #[must_use]
    pub fn name(&self) -> &str {
        &self.name
    }

    /// Get the backend configuration.
    #[must_use]
    pub fn backend(&self) -> &BackendConfig {
        &self.backend
    }

    /// Get the priority.
    #[must_use]
    pub fn priority(&self) -> i32 {
        self.priority
    }

    /// Check if this route should strip the matched prefix.
    #[must_use]
    pub fn strip_prefix(&self) -> bool {
        self.strip_prefix
    }

    /// Get the rewrite pattern.
    #[must_use]
    pub fn rewrite(&self) -> Option<&str> {
        self.rewrite.as_deref()
    }

    /// Get the middleware names for this route.
    #[must_use]
    pub fn middleware(&self) -> &[String] {
        &self.middleware
    }

    /// Check if this route matches a request.
    #[must_use]
    pub fn matches(&self, request: &Request) -> bool {
        // Check method
        if !self.methods.is_empty() && !self.methods.contains(request.method()) {
            return false;
        }

        // Check path
        if !self.path_pattern.matches(request.path()) {
            return false;
        }

        // Check host
        if let Some(ref host_pattern) = self.host_pattern {
            let host = request.host().unwrap_or("");
            if !pattern_matches(host_pattern, host) {
                return false;
            }
        }

        // Check required headers
        for (name, value) in &self.required_headers {
            match request.header(name) {
                Some(v) if pattern_matches(value, v) => {},
                _ => return false,
            }
        }

        true
    }

    /// Apply path transformation based on route configuration.
    #[must_use]
    pub fn transform_path(&self, path: &str) -> String {
        let mut result = path.to_string();

        // Apply rewrite if specified
        if let Some(ref rewrite) = self.rewrite {
            result = self.path_pattern.rewrite(path, rewrite);
        } else if self.strip_prefix {
            // Strip the matched prefix
            result = self.path_pattern.strip_prefix(path);
        }

        // Ensure path starts with /
        if !result.starts_with('/') {
            result = format!("/{result}");
        }

        result
    }
}

/// Compiled path pattern for efficient matching.
#[derive(Debug, Clone)]
pub struct PathPattern {
    /// Original pattern string.
    #[allow(dead_code)]
    pattern: String,
    /// Pattern segments.
    segments: Vec<PathSegment>,
    /// Whether pattern ends with wildcard.
    has_trailing_wildcard: bool,
}

/// A segment of a path pattern.
#[derive(Debug, Clone)]
enum PathSegment {
    /// Literal segment (exact match).
    Literal(String),
    /// Single segment wildcard (*).
    Wildcard,
    /// Named parameter (:name).
    #[allow(dead_code)]
    Param(String),
    /// Multi-segment wildcard (**).
    GlobStar,
}

impl PathPattern {
    /// Compile a path pattern.
    pub fn compile(pattern: &str) -> HttpResult<Self> {
        let pattern = if pattern.is_empty() { "/" } else { pattern };
        let mut segments = Vec::new();
        let mut has_trailing_wildcard = false;

        for part in pattern.split('/').filter(|s| !s.is_empty()) {
            let segment = match part {
                "*" => PathSegment::Wildcard,
                "**" => {
                    has_trailing_wildcard = true;
                    PathSegment::GlobStar
                },
                s if s.starts_with(':') => PathSegment::Param(s[1..].to_string()),
                s => PathSegment::Literal(s.to_string()),
            };
            segments.push(segment);
        }

        Ok(Self {
            pattern: pattern.to_string(),
            segments,
            has_trailing_wildcard,
        })
    }

    /// Check if the pattern matches a path.
    #[must_use]
    pub fn matches(&self, path: &str) -> bool {
        let path_parts: Vec<&str> = path.split('/').filter(|s| !s.is_empty()).collect();
        let mut path_idx = 0;

        for (seg_idx, segment) in self.segments.iter().enumerate() {
            match segment {
                PathSegment::Literal(lit) => {
                    if path_idx >= path_parts.len() || path_parts[path_idx] != lit {
                        return false;
                    }
                    path_idx += 1;
                },
                PathSegment::Wildcard | PathSegment::Param(_) => {
                    if path_idx >= path_parts.len() {
                        return false;
                    }
                    path_idx += 1;
                },
                PathSegment::GlobStar => {
                    // If this is the last segment, match everything remaining
                    if seg_idx == self.segments.len() - 1 {
                        return true;
                    }
                    // Otherwise, we'd need more complex matching
                    return true;
                },
            }
        }

        // All segments matched - check if path is fully consumed
        // or we have a trailing wildcard
        path_idx == path_parts.len() || self.has_trailing_wildcard
    }

    /// Get the number of literal segments (for prefix stripping).
    fn literal_prefix_len(&self) -> usize {
        let mut count = 0;
        for seg in &self.segments {
            match seg {
                PathSegment::Literal(_) => count += 1,
                PathSegment::Wildcard | PathSegment::Param(_) => count += 1,
                PathSegment::GlobStar => break,
            }
        }
        count
    }

    /// Strip the matched prefix from a path.
    #[must_use]
    pub fn strip_prefix(&self, path: &str) -> String {
        let path_parts: Vec<&str> = path.split('/').filter(|s| !s.is_empty()).collect();
        let prefix_len = self.literal_prefix_len();

        if prefix_len >= path_parts.len() {
            "/".to_string()
        } else {
            format!("/{}", path_parts[prefix_len..].join("/"))
        }
    }

    /// Apply a rewrite pattern to a path.
    #[must_use]
    pub fn rewrite(&self, _path: &str, rewrite: &str) -> String {
        // Simple rewrite - just use the rewrite pattern
        // In a full implementation, we'd support parameter substitution
        rewrite.to_string()
    }
}

/// Check if a pattern matches a value (supports * wildcard).
fn pattern_matches(pattern: &str, value: &str) -> bool {
    if pattern == "*" {
        return true;
    }

    if pattern.starts_with('*') && pattern.ends_with('*') {
        let inner = &pattern[1..pattern.len() - 1];
        return value.contains(inner);
    }

    if let Some(suffix) = pattern.strip_prefix('*') {
        return value.ends_with(suffix);
    }

    if let Some(prefix) = pattern.strip_suffix('*') {
        return value.starts_with(prefix);
    }

    pattern == value
}

/// HTTP request router.
#[derive(Debug)]
pub struct Router {
    /// Sorted routes (by priority, descending).
    routes: Vec<Arc<Route>>,
    /// Default backend.
    default_backend: Option<BackendConfig>,
}

impl Router {
    /// Create a new router.
    #[must_use]
    pub fn new() -> Self {
        Self {
            routes: Vec::new(),
            default_backend: None,
        }
    }

    /// Create a router from route configurations.
    pub fn from_configs(
        configs: Vec<RouteConfig>,
        default_backend: Option<BackendConfig>,
    ) -> HttpResult<Self> {
        let mut routes: Vec<Arc<Route>> = configs
            .into_iter()
            .map(|c| Route::from_config(c).map(Arc::new))
            .collect::<HttpResult<_>>()?;

        // Sort by priority (descending)
        routes.sort_by_key(|r| std::cmp::Reverse(r.priority()));

        Ok(Self {
            routes,
            default_backend,
        })
    }

    /// Add a route.
    pub fn add_route(&mut self, route: Route) {
        let route = Arc::new(route);
        self.routes.push(route);
        // Re-sort by priority
        self.routes.sort_by_key(|r| std::cmp::Reverse(r.priority()));
    }

    /// Set the default backend.
    pub fn set_default_backend(&mut self, backend: BackendConfig) {
        self.default_backend = Some(backend);
    }

    /// Find a matching route for a request.
    #[must_use]
    pub fn route(&self, request: &Request) -> Option<Arc<Route>> {
        for route in &self.routes {
            if route.matches(request) {
                debug!(
                    route = %route.name(),
                    method = %request.method(),
                    path = %request.path(),
                    "Route matched"
                );
                return Some(Arc::clone(route));
            }
        }
        None
    }

    /// Find a matching route or return the default backend.
    pub fn route_or_default(
        &self,
        request: &Request,
    ) -> HttpResult<(Option<Arc<Route>>, BackendConfig)> {
        if let Some(route) = self.route(request) {
            let backend = route.backend().clone();
            Ok((Some(route), backend))
        } else if let Some(ref default) = self.default_backend {
            Ok((None, default.clone()))
        } else {
            Err(HttpError::NoRoute {
                method: request.method().to_string(),
                path: request.path().to_string(),
            })
        }
    }

    /// Get the number of routes.
    #[must_use]
    pub fn route_count(&self) -> usize {
        self.routes.len()
    }

    /// Get all route names.
    #[must_use]
    pub fn route_names(&self) -> Vec<&str> {
        self.routes.iter().map(|r| r.name()).collect()
    }
}

impl Default for Router {
    fn default() -> Self {
        Self::new()
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
    fn test_path_pattern_literal() {
        let pattern = PathPattern::compile("/api/users").unwrap();
        assert!(pattern.matches("/api/users"));
        assert!(!pattern.matches("/api/posts"));
        assert!(!pattern.matches("/api"));
    }

    #[test]
    fn test_path_pattern_wildcard() {
        let pattern = PathPattern::compile("/api/*/details").unwrap();
        assert!(pattern.matches("/api/123/details"));
        assert!(pattern.matches("/api/abc/details"));
        assert!(!pattern.matches("/api/details"));
    }

    #[test]
    fn test_path_pattern_globstar() {
        let pattern = PathPattern::compile("/static/**").unwrap();
        assert!(pattern.matches("/static/js/app.js"));
        assert!(pattern.matches("/static/css/style.css"));
        assert!(pattern.matches("/static/"));
    }

    #[test]
    fn test_path_pattern_param() {
        let pattern = PathPattern::compile("/users/:id").unwrap();
        assert!(pattern.matches("/users/123"));
        assert!(pattern.matches("/users/abc"));
        assert!(!pattern.matches("/users"));
    }

    #[test]
    fn test_route_matching() {
        let config = RouteConfig {
            name: "api".to_string(),
            path: "/api/*".to_string(),
            methods: vec!["GET".to_string(), "POST".to_string()],
            host: None,
            headers: HashMap::new(),
            backend: BackendConfig {
                address: "127.0.0.1".to_string(),
                port: 3000,
                tls: false,
                verify_tls: true,
                connect_timeout: None,
                request_timeout: None,
            },
            priority: 0,
            strip_prefix: false,
            rewrite: None,
            middleware: Vec::new(),
        };

        let route = Route::from_config(config).unwrap();

        let get_req = make_request("GET", "/api/users");
        assert!(route.matches(&get_req));

        let post_req = make_request("POST", "/api/users");
        assert!(route.matches(&post_req));

        let delete_req = make_request("DELETE", "/api/users");
        assert!(!route.matches(&delete_req));
    }

    #[test]
    fn test_router_priority() {
        let mut router = Router::new();

        let low_priority = Route::from_config(RouteConfig {
            name: "catch-all".to_string(),
            path: "/**".to_string(),
            methods: vec![],
            host: None,
            headers: HashMap::new(),
            backend: BackendConfig {
                address: "127.0.0.1".to_string(),
                port: 3001,
                tls: false,
                verify_tls: true,
                connect_timeout: None,
                request_timeout: None,
            },
            priority: 0,
            strip_prefix: false,
            rewrite: None,
            middleware: Vec::new(),
        })
        .unwrap();

        let high_priority = Route::from_config(RouteConfig {
            name: "api".to_string(),
            path: "/api/**".to_string(),
            methods: vec![],
            host: None,
            headers: HashMap::new(),
            backend: BackendConfig {
                address: "127.0.0.1".to_string(),
                port: 3000,
                tls: false,
                verify_tls: true,
                connect_timeout: None,
                request_timeout: None,
            },
            priority: 10,
            strip_prefix: false,
            rewrite: None,
            middleware: Vec::new(),
        })
        .unwrap();

        router.add_route(low_priority);
        router.add_route(high_priority);

        let req = make_request("GET", "/api/users");
        let route = router.route(&req).unwrap();
        assert_eq!(route.name(), "api");
    }

    #[test]
    fn test_pattern_matches() {
        assert!(pattern_matches("*", "anything"));
        assert!(pattern_matches("api*", "api/users"));
        assert!(pattern_matches("*json", "application/json"));
        assert!(pattern_matches("*api*", "my-api-service"));
        assert!(!pattern_matches("exact", "not-exact"));
    }

    #[test]
    fn test_strip_prefix() {
        let pattern = PathPattern::compile("/api/v1").unwrap();
        assert_eq!(pattern.strip_prefix("/api/v1/users"), "/users");
        assert_eq!(pattern.strip_prefix("/api/v1/users/123"), "/users/123");
    }

    #[test]
    fn test_transform_path() {
        let config = RouteConfig {
            name: "api".to_string(),
            path: "/v1/api".to_string(),
            methods: vec![],
            host: None,
            headers: HashMap::new(),
            backend: BackendConfig {
                address: "127.0.0.1".to_string(),
                port: 3000,
                tls: false,
                verify_tls: true,
                connect_timeout: None,
                request_timeout: None,
            },
            priority: 0,
            strip_prefix: true,
            rewrite: None,
            middleware: Vec::new(),
        };

        let route = Route::from_config(config).unwrap();
        assert_eq!(route.transform_path("/v1/api/users"), "/users");
    }
}
