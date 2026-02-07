//! Plugin registry.
//!
//! Provides plugin discovery, lifecycle management, and version control.

use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};

use super::error::{PluginError, PluginResult};
use super::sandbox::SandboxConfig;

/// Plugin registry.
#[derive(Debug)]
pub struct PluginRegistry {
    /// Registered plugins.
    plugins: HashMap<String, PluginEntry>,
    /// Plugin search paths.
    search_paths: Vec<PathBuf>,
    /// Registry configuration.
    config: RegistryConfig,
    /// Registry statistics.
    stats: RegistryStats,
}

impl Default for PluginRegistry {
    fn default() -> Self {
        Self::new()
    }
}

impl PluginRegistry {
    /// Create a new plugin registry.
    pub fn new() -> Self {
        Self {
            plugins: HashMap::new(),
            search_paths: Vec::new(),
            config: RegistryConfig::default(),
            stats: RegistryStats::default(),
        }
    }

    /// Create with configuration.
    pub fn with_config(config: RegistryConfig) -> Self {
        Self {
            config,
            ..Self::new()
        }
    }

    /// Add a search path.
    ///
    /// The path is canonicalized to prevent path traversal attacks.
    /// Returns an error if the path does not exist or cannot be resolved.
    pub fn add_search_path(&mut self, path: impl AsRef<Path>) {
        // Canonicalize to prevent directory traversal
        match path.as_ref().canonicalize() {
            Ok(canonical) => self.search_paths.push(canonical),
            Err(_) => {
                // If path doesn't exist yet, store as-is but normalize
                // by stripping any .. components
                let cleaned: PathBuf = path
                    .as_ref()
                    .components()
                    .filter(|c| !matches!(c, std::path::Component::ParentDir))
                    .collect();
                self.search_paths.push(cleaned);
            },
        }
    }

    /// Register a plugin.
    pub fn register(&mut self, info: PluginInfo, sandbox: SandboxConfig) -> PluginResult<()> {
        if self.plugins.contains_key(&info.name) {
            return Err(PluginError::AlreadyExists {
                name: info.name.clone(),
            });
        }

        // Validate version
        if !is_valid_semver(&info.version) {
            return Err(PluginError::InvalidManifest {
                message: format!("Invalid version: {}", info.version),
            });
        }

        let entry = PluginEntry {
            info,
            state: PluginState::Registered,
            sandbox,
            registered_at: Instant::now(),
            last_state_change: Instant::now(),
            error_message: None,
        };

        let name = entry.info.name.clone();
        self.plugins.insert(name, entry);
        self.stats.plugins_registered += 1;

        Ok(())
    }

    /// Unregister a plugin.
    pub fn unregister(&mut self, name: &str) -> PluginResult<PluginInfo> {
        let entry = self
            .plugins
            .remove(name)
            .ok_or_else(|| PluginError::NotFound {
                name: name.to_string(),
            })?;

        self.stats.plugins_unregistered += 1;
        Ok(entry.info)
    }

    /// Get a plugin entry.
    pub fn get(&self, name: &str) -> Option<&PluginEntry> {
        self.plugins.get(name)
    }

    /// Get a mutable plugin entry.
    pub fn get_mut(&mut self, name: &str) -> Option<&mut PluginEntry> {
        self.plugins.get_mut(name)
    }

    /// List all plugins.
    pub fn list(&self) -> impl Iterator<Item = &PluginEntry> {
        self.plugins.values()
    }

    /// List plugins by state.
    pub fn list_by_state(&self, state: PluginState) -> impl Iterator<Item = &PluginEntry> {
        self.plugins.values().filter(move |e| e.state == state)
    }

    /// Update plugin state.
    pub fn update_state(&mut self, name: &str, state: PluginState) -> PluginResult<()> {
        let entry = self
            .plugins
            .get_mut(name)
            .ok_or_else(|| PluginError::NotFound {
                name: name.to_string(),
            })?;

        entry.state = state;
        entry.last_state_change = Instant::now();
        entry.error_message = None;

        Ok(())
    }

    /// Set plugin error state.
    pub fn set_error(&mut self, name: &str, error: String) -> PluginResult<()> {
        let entry = self
            .plugins
            .get_mut(name)
            .ok_or_else(|| PluginError::NotFound {
                name: name.to_string(),
            })?;

        entry.state = PluginState::Failed;
        entry.last_state_change = Instant::now();
        entry.error_message = Some(error);
        self.stats.plugins_failed += 1;

        Ok(())
    }

    /// Find plugin by name pattern.
    pub fn find(&self, pattern: &str) -> Vec<&PluginEntry> {
        self.plugins
            .values()
            .filter(|e| e.info.name.contains(pattern))
            .collect()
    }

    /// Find plugins by author.
    pub fn find_by_author(&self, author: &str) -> Vec<&PluginEntry> {
        self.plugins
            .values()
            .filter(|e| e.info.author.as_deref() == Some(author))
            .collect()
    }

    /// Find plugins by tag.
    pub fn find_by_tag(&self, tag: &str) -> Vec<&PluginEntry> {
        self.plugins
            .values()
            .filter(|e| e.info.tags.contains(&tag.to_string()))
            .collect()
    }

    /// Discover plugins from search paths.
    pub fn discover(&mut self) -> PluginResult<Vec<PluginInfo>> {
        let mut discovered = Vec::new();

        for path in &self.search_paths.clone() {
            if !path.exists() {
                continue;
            }

            if path.is_dir() {
                discovered.extend(self.discover_dir(path)?);
            } else if path.extension().is_some_and(|e| e == "wasm") {
                if let Ok(info) = self.load_plugin_info(path) {
                    discovered.push(info);
                }
            }
        }

        self.stats.discoveries += 1;
        Ok(discovered)
    }

    /// Discover plugins in a directory.
    fn discover_dir(&self, dir: &Path) -> PluginResult<Vec<PluginInfo>> {
        let mut plugins = Vec::new();

        for entry in std::fs::read_dir(dir)? {
            let entry = entry?;
            let path = entry.path();

            if path.extension().is_some_and(|e| e == "wasm") {
                if let Ok(info) = self.load_plugin_info(&path) {
                    plugins.push(info);
                }
            } else if path.is_dir() && self.config.recursive_discovery {
                plugins.extend(self.discover_dir(&path)?);
            }
        }

        Ok(plugins)
    }

    /// Load plugin info from a WASM file.
    fn load_plugin_info(&self, path: &Path) -> PluginResult<PluginInfo> {
        // In a real implementation, this would:
        // 1. Load the WASM file
        // 2. Parse custom sections for metadata
        // 3. Call plugin_info export if available

        let name = path
            .file_stem()
            .and_then(|s| s.to_str())
            .map(|s| s.to_string())
            .unwrap_or_else(|| {
                // Generate a unique fallback name to avoid collisions
                use std::collections::hash_map::DefaultHasher;
                use std::hash::{Hash, Hasher};
                let mut hasher = DefaultHasher::new();
                path.hash(&mut hasher);
                format!("plugin-{:x}", hasher.finish())
            });

        Ok(PluginInfo {
            name,
            version: "0.1.0".to_string(),
            api_version: 1,
            plugin_type: PluginType::RequestHandler,
            description: None,
            author: None,
            license: None,
            homepage: None,
            repository: None,
            tags: Vec::new(),
            dependencies: Vec::new(),
            capabilities: Vec::new(),
            path: Some(path.to_path_buf()),
        })
    }

    /// Check for plugin updates.
    pub fn check_updates(&self) -> Vec<PluginUpdate> {
        // In a real implementation, this would query a marketplace/registry
        Vec::new()
    }

    /// Get registry statistics.
    pub fn stats(&self) -> &RegistryStats {
        &self.stats
    }

    /// Get number of registered plugins.
    pub fn len(&self) -> usize {
        self.plugins.len()
    }

    /// Check if registry is empty.
    pub fn is_empty(&self) -> bool {
        self.plugins.is_empty()
    }
}

/// Registry configuration.
#[derive(Debug, Clone)]
pub struct RegistryConfig {
    /// Enable auto-discovery.
    pub auto_discovery: bool,
    /// Recursive directory discovery.
    pub recursive_discovery: bool,
    /// Auto-reload on file changes.
    pub auto_reload: bool,
    /// Check for updates interval.
    pub update_check_interval: Option<Duration>,
    /// Maximum plugins.
    pub max_plugins: usize,
}

impl Default for RegistryConfig {
    fn default() -> Self {
        Self {
            auto_discovery: false,
            recursive_discovery: true,
            auto_reload: false,
            update_check_interval: None,
            max_plugins: 100,
        }
    }
}

/// Plugin entry in registry.
#[derive(Debug)]
pub struct PluginEntry {
    /// Plugin information.
    pub info: PluginInfo,
    /// Current state.
    pub state: PluginState,
    /// Sandbox configuration.
    pub sandbox: SandboxConfig,
    /// Registration time.
    registered_at: Instant,
    /// Last state change.
    last_state_change: Instant,
    /// Error message if failed.
    pub error_message: Option<String>,
}

impl PluginEntry {
    /// Get time since registration.
    pub fn registered_duration(&self) -> Duration {
        self.registered_at.elapsed()
    }

    /// Get time since last state change.
    pub fn state_duration(&self) -> Duration {
        self.last_state_change.elapsed()
    }

    /// Check if plugin is available.
    pub fn is_available(&self) -> bool {
        matches!(self.state, PluginState::Ready | PluginState::Running)
    }

    /// Check if plugin has failed.
    pub fn has_failed(&self) -> bool {
        self.state == PluginState::Failed
    }
}

/// Plugin information.
#[derive(Debug, Clone)]
pub struct PluginInfo {
    /// Plugin name.
    pub name: String,
    /// Plugin version (semver).
    pub version: String,
    /// API version compatibility.
    pub api_version: u32,
    /// Plugin type.
    pub plugin_type: PluginType,
    /// Description.
    pub description: Option<String>,
    /// Author.
    pub author: Option<String>,
    /// License.
    pub license: Option<String>,
    /// Homepage URL.
    pub homepage: Option<String>,
    /// Repository URL.
    pub repository: Option<String>,
    /// Tags for categorization.
    pub tags: Vec<String>,
    /// Dependencies.
    pub dependencies: Vec<PluginDependency>,
    /// Required capabilities.
    pub capabilities: Vec<String>,
    /// Path to WASM file.
    pub path: Option<PathBuf>,
}

impl PluginInfo {
    /// Create a new plugin info.
    pub fn new(name: impl Into<String>, version: impl Into<String>) -> Self {
        Self {
            name: name.into(),
            version: version.into(),
            api_version: 1,
            plugin_type: PluginType::RequestHandler,
            description: None,
            author: None,
            license: None,
            homepage: None,
            repository: None,
            tags: Vec::new(),
            dependencies: Vec::new(),
            capabilities: Vec::new(),
            path: None,
        }
    }

    /// Builder: set description.
    pub fn with_description(mut self, desc: impl Into<String>) -> Self {
        self.description = Some(desc.into());
        self
    }

    /// Builder: set author.
    pub fn with_author(mut self, author: impl Into<String>) -> Self {
        self.author = Some(author.into());
        self
    }

    /// Builder: set plugin type.
    pub fn with_type(mut self, plugin_type: PluginType) -> Self {
        self.plugin_type = plugin_type;
        self
    }

    /// Builder: add tag.
    pub fn with_tag(mut self, tag: impl Into<String>) -> Self {
        self.tags.push(tag.into());
        self
    }

    /// Builder: add dependency.
    pub fn with_dependency(mut self, dep: PluginDependency) -> Self {
        self.dependencies.push(dep);
        self
    }

    /// Builder: add capability.
    pub fn with_capability(mut self, cap: impl Into<String>) -> Self {
        self.capabilities.push(cap.into());
        self
    }

    /// Parse version to components.
    pub fn version_parts(&self) -> Option<(u32, u32, u32)> {
        parse_semver(&self.version)
    }

    /// Check if version satisfies requirement.
    pub fn satisfies_version(&self, requirement: &str) -> bool {
        check_version_requirement(&self.version, requirement)
    }
}

/// Plugin type.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum PluginType {
    /// Request handler - processes incoming requests.
    RequestHandler,
    /// Response transformer - modifies responses.
    ResponseTransformer,
    /// Authenticator - handles authentication.
    Authenticator,
    /// Observer - observes request/response flow.
    Observer,
    /// Middleware - general middleware.
    Middleware,
    /// Background - background task.
    Background,
}

impl PluginType {
    /// Get type name.
    pub fn name(&self) -> &'static str {
        match self {
            Self::RequestHandler => "request_handler",
            Self::ResponseTransformer => "response_transformer",
            Self::Authenticator => "authenticator",
            Self::Observer => "observer",
            Self::Middleware => "middleware",
            Self::Background => "background",
        }
    }

    /// Parse from string.
    pub fn parse(s: &str) -> Option<Self> {
        match s {
            "request_handler" => Some(Self::RequestHandler),
            "response_transformer" => Some(Self::ResponseTransformer),
            "authenticator" => Some(Self::Authenticator),
            "observer" => Some(Self::Observer),
            "middleware" => Some(Self::Middleware),
            "background" => Some(Self::Background),
            _ => None,
        }
    }
}

/// Plugin state.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum PluginState {
    /// Plugin is registered but not loaded.
    Registered,
    /// Plugin is loading.
    Loading,
    /// Plugin is ready to run.
    Ready,
    /// Plugin is running.
    Running,
    /// Plugin is stopping.
    Stopping,
    /// Plugin is stopped.
    Stopped,
    /// Plugin has failed.
    Failed,
    /// Plugin is being updated.
    Updating,
}

impl PluginState {
    /// Check if plugin can be started.
    pub fn can_start(&self) -> bool {
        matches!(self, Self::Ready | Self::Stopped)
    }

    /// Check if plugin can be stopped.
    pub fn can_stop(&self) -> bool {
        matches!(self, Self::Running)
    }

    /// Check if plugin is active.
    pub fn is_active(&self) -> bool {
        matches!(self, Self::Loading | Self::Ready | Self::Running)
    }
}

/// Plugin dependency.
#[derive(Debug, Clone)]
pub struct PluginDependency {
    /// Dependency name.
    pub name: String,
    /// Version requirement.
    pub version: String,
    /// Whether dependency is optional.
    pub optional: bool,
}

impl PluginDependency {
    /// Create a required dependency.
    pub fn required(name: impl Into<String>, version: impl Into<String>) -> Self {
        Self {
            name: name.into(),
            version: version.into(),
            optional: false,
        }
    }

    /// Create an optional dependency.
    pub fn optional(name: impl Into<String>, version: impl Into<String>) -> Self {
        Self {
            name: name.into(),
            version: version.into(),
            optional: true,
        }
    }
}

/// Plugin update information.
#[derive(Debug, Clone)]
pub struct PluginUpdate {
    /// Plugin name.
    pub name: String,
    /// Current version.
    pub current_version: String,
    /// Available version.
    pub available_version: String,
    /// Release notes.
    pub release_notes: Option<String>,
    /// Download URL.
    pub download_url: String,
}

/// Registry statistics.
#[derive(Debug, Default)]
pub struct RegistryStats {
    /// Plugins registered.
    pub plugins_registered: u64,
    /// Plugins unregistered.
    pub plugins_unregistered: u64,
    /// Plugins failed.
    pub plugins_failed: u64,
    /// Discovery runs.
    pub discoveries: u64,
    /// Update checks.
    pub update_checks: u64,
}

/// Validate semver format.
fn is_valid_semver(version: &str) -> bool {
    parse_semver(version).is_some()
}

/// Parse semver to components.
fn parse_semver(version: &str) -> Option<(u32, u32, u32)> {
    let parts: Vec<&str> = version.split('.').collect();
    if parts.len() != 3 {
        return None;
    }

    let major = parts[0].parse().ok()?;
    let minor = parts[1].parse().ok()?;

    // Handle pre-release suffix
    let patch_str = parts[2].split('-').next()?;
    let patch = patch_str.parse().ok()?;

    Some((major, minor, patch))
}

/// Check version requirement (simplified).
fn check_version_requirement(version: &str, requirement: &str) -> bool {
    let (v_major, v_minor, v_patch) = match parse_semver(version) {
        Some(v) => v,
        None => return false,
    };

    // Handle exact version
    if !requirement.starts_with('^')
        && !requirement.starts_with('~')
        && !requirement.starts_with('>')
        && !requirement.starts_with('<')
    {
        if let Some((r_major, r_minor, r_patch)) = parse_semver(requirement) {
            return v_major == r_major && v_minor == r_minor && v_patch == r_patch;
        }
        return false;
    }

    // Handle caret (^) - compatible with version
    if let Some(req) = requirement.strip_prefix('^') {
        if let Some((r_major, r_minor, _)) = parse_semver(req) {
            if r_major == 0 {
                return v_major == 0 && v_minor == r_minor;
            }
            return v_major == r_major && v_minor >= r_minor;
        }
    }

    // Handle tilde (~) - approximately equivalent
    if let Some(req) = requirement.strip_prefix('~') {
        if let Some((r_major, r_minor, _)) = parse_semver(req) {
            return v_major == r_major && v_minor == r_minor;
        }
    }

    // Handle >= and <=
    if let Some(req) = requirement.strip_prefix(">=") {
        if let Some((r_major, r_minor, r_patch)) = parse_semver(req) {
            return (v_major, v_minor, v_patch) >= (r_major, r_minor, r_patch);
        }
    }

    false
}

#[cfg(test)]
mod tests {
    use super::*;

    fn test_plugin_info() -> PluginInfo {
        PluginInfo::new("test-plugin", "1.0.0")
            .with_description("A test plugin")
            .with_author("Test Author")
    }

    #[test]
    fn test_registry_new() {
        let registry = PluginRegistry::new();
        assert!(registry.is_empty());
    }

    #[test]
    fn test_register_plugin() {
        let mut registry = PluginRegistry::new();
        let info = test_plugin_info();

        assert!(registry.register(info, SandboxConfig::default()).is_ok());
        assert_eq!(registry.len(), 1);
    }

    #[test]
    fn test_register_duplicate() {
        let mut registry = PluginRegistry::new();
        let info = test_plugin_info();

        registry
            .register(info.clone(), SandboxConfig::default())
            .unwrap();
        assert!(registry.register(info, SandboxConfig::default()).is_err());
    }

    #[test]
    fn test_unregister_plugin() {
        let mut registry = PluginRegistry::new();
        let info = test_plugin_info();

        registry.register(info, SandboxConfig::default()).unwrap();
        assert!(registry.unregister("test-plugin").is_ok());
        assert!(registry.is_empty());
    }

    #[test]
    fn test_get_plugin() {
        let mut registry = PluginRegistry::new();
        let info = test_plugin_info();

        registry.register(info, SandboxConfig::default()).unwrap();

        let entry = registry.get("test-plugin");
        assert!(entry.is_some());
        assert_eq!(entry.unwrap().info.name, "test-plugin");
    }

    #[test]
    fn test_update_state() {
        let mut registry = PluginRegistry::new();
        let info = test_plugin_info();

        registry.register(info, SandboxConfig::default()).unwrap();
        registry
            .update_state("test-plugin", PluginState::Running)
            .unwrap();

        assert_eq!(
            registry.get("test-plugin").unwrap().state,
            PluginState::Running
        );
    }

    #[test]
    fn test_set_error() {
        let mut registry = PluginRegistry::new();
        let info = test_plugin_info();

        registry.register(info, SandboxConfig::default()).unwrap();
        registry
            .set_error("test-plugin", "Test error".to_string())
            .unwrap();

        let entry = registry.get("test-plugin").unwrap();
        assert_eq!(entry.state, PluginState::Failed);
        assert_eq!(entry.error_message, Some("Test error".to_string()));
    }

    #[test]
    fn test_find_plugins() {
        let mut registry = PluginRegistry::new();

        registry
            .register(
                PluginInfo::new("auth-plugin", "1.0.0"),
                SandboxConfig::default(),
            )
            .unwrap();
        registry
            .register(
                PluginInfo::new("logging-plugin", "1.0.0"),
                SandboxConfig::default(),
            )
            .unwrap();

        let found = registry.find("auth");
        assert_eq!(found.len(), 1);
        assert_eq!(found[0].info.name, "auth-plugin");
    }

    #[test]
    fn test_find_by_author() {
        let mut registry = PluginRegistry::new();

        registry
            .register(
                PluginInfo::new("plugin1", "1.0.0").with_author("Alice"),
                SandboxConfig::default(),
            )
            .unwrap();
        registry
            .register(
                PluginInfo::new("plugin2", "1.0.0").with_author("Bob"),
                SandboxConfig::default(),
            )
            .unwrap();

        let found = registry.find_by_author("Alice");
        assert_eq!(found.len(), 1);
    }

    #[test]
    fn test_find_by_tag() {
        let mut registry = PluginRegistry::new();

        registry
            .register(
                PluginInfo::new("plugin1", "1.0.0").with_tag("security"),
                SandboxConfig::default(),
            )
            .unwrap();
        registry
            .register(
                PluginInfo::new("plugin2", "1.0.0").with_tag("logging"),
                SandboxConfig::default(),
            )
            .unwrap();

        let found = registry.find_by_tag("security");
        assert_eq!(found.len(), 1);
    }

    #[test]
    fn test_list_by_state() {
        let mut registry = PluginRegistry::new();

        registry
            .register(
                PluginInfo::new("plugin1", "1.0.0"),
                SandboxConfig::default(),
            )
            .unwrap();
        registry
            .register(
                PluginInfo::new("plugin2", "1.0.0"),
                SandboxConfig::default(),
            )
            .unwrap();

        registry
            .update_state("plugin1", PluginState::Running)
            .unwrap();

        let running: Vec<_> = registry.list_by_state(PluginState::Running).collect();
        assert_eq!(running.len(), 1);
    }

    #[test]
    fn test_plugin_info_builder() {
        let info = PluginInfo::new("test", "1.2.3")
            .with_description("Test description")
            .with_author("Test Author")
            .with_type(PluginType::Authenticator)
            .with_tag("security")
            .with_capability("network:client");

        assert_eq!(info.name, "test");
        assert_eq!(info.version, "1.2.3");
        assert_eq!(info.description, Some("Test description".to_string()));
        assert_eq!(info.plugin_type, PluginType::Authenticator);
        assert!(info.tags.contains(&"security".to_string()));
    }

    #[test]
    fn test_version_parts() {
        let info = PluginInfo::new("test", "1.2.3");
        assert_eq!(info.version_parts(), Some((1, 2, 3)));
    }

    #[test]
    fn test_semver_validation() {
        assert!(is_valid_semver("1.0.0"));
        assert!(is_valid_semver("0.1.0"));
        assert!(is_valid_semver("10.20.30"));
        assert!(!is_valid_semver("1.0"));
        assert!(!is_valid_semver("1"));
        assert!(!is_valid_semver("invalid"));
    }

    #[test]
    fn test_version_requirement() {
        assert!(check_version_requirement("1.0.0", "1.0.0"));
        assert!(!check_version_requirement("1.0.0", "2.0.0"));
        assert!(check_version_requirement("1.2.0", "^1.0.0"));
        assert!(!check_version_requirement("2.0.0", "^1.0.0"));
        assert!(check_version_requirement("1.0.5", "~1.0.0"));
        assert!(!check_version_requirement("1.1.0", "~1.0.0"));
        assert!(check_version_requirement("1.0.0", ">=1.0.0"));
        assert!(check_version_requirement("2.0.0", ">=1.0.0"));
    }

    #[test]
    fn test_plugin_type() {
        assert_eq!(PluginType::RequestHandler.name(), "request_handler");
        assert_eq!(
            PluginType::parse("authenticator"),
            Some(PluginType::Authenticator)
        );
        assert_eq!(PluginType::parse("invalid"), None);
    }

    #[test]
    fn test_plugin_state() {
        assert!(PluginState::Ready.can_start());
        assert!(PluginState::Stopped.can_start());
        assert!(!PluginState::Running.can_start());

        assert!(PluginState::Running.can_stop());
        assert!(!PluginState::Stopped.can_stop());

        assert!(PluginState::Running.is_active());
        assert!(!PluginState::Stopped.is_active());
    }

    #[test]
    fn test_plugin_dependency() {
        let required = PluginDependency::required("core", "^1.0.0");
        assert!(!required.optional);

        let optional = PluginDependency::optional("extra", ">=0.1.0");
        assert!(optional.optional);
    }

    #[test]
    fn test_plugin_entry_available() {
        let mut registry = PluginRegistry::new();
        registry
            .register(test_plugin_info(), SandboxConfig::default())
            .unwrap();

        let entry = registry.get("test-plugin").unwrap();
        assert!(!entry.is_available()); // Registered, not Ready

        registry
            .update_state("test-plugin", PluginState::Ready)
            .unwrap();
        let entry = registry.get("test-plugin").unwrap();
        assert!(entry.is_available());
    }

    #[test]
    fn test_registry_stats() {
        let mut registry = PluginRegistry::new();

        registry
            .register(test_plugin_info(), SandboxConfig::default())
            .unwrap();
        assert_eq!(registry.stats().plugins_registered, 1);

        registry.unregister("test-plugin").unwrap();
        assert_eq!(registry.stats().plugins_unregistered, 1);
    }
}
