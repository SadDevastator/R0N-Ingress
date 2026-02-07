//! Module manifest and capability declarations.

use std::collections::HashSet;

/// Semantic version representation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SemVer {
    /// Major version.
    pub major: u32,
    /// Minor version.
    pub minor: u32,
    /// Patch version.
    pub patch: u32,
}

impl SemVer {
    /// Creates a new semantic version.
    #[must_use]
    pub const fn new(major: u32, minor: u32, patch: u32) -> Self {
        Self {
            major,
            minor,
            patch,
        }
    }
}

impl std::fmt::Display for SemVer {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}.{}.{}", self.major, self.minor, self.patch)
    }
}

/// Capabilities that a module can provide.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum Capability {
    /// Module can handle TCP connections.
    TcpListener,

    /// Module can handle UDP datagrams.
    UdpListener,

    /// Module can terminate TLS.
    TlsTermination,

    /// Module can perform TLS passthrough.
    TlsPassthrough,

    /// Module can perform load balancing.
    LoadBalancing,

    /// Module can collect and export metrics.
    Metrics,

    /// Module supports hot configuration reload.
    HotReload,

    /// Module can handle HTTP protocol.
    HttpProtocol,

    /// Module can handle MQTT protocol.
    MqttProtocol,

    /// Module can handle WebSocket protocol.
    WebSocketProtocol,

    /// Module provides WAF functionality.
    WebApplicationFirewall,

    /// Module provides rate limiting.
    RateLimiting,

    /// Custom capability.
    Custom(String),
}

/// A dependency on another module.
#[derive(Debug, Clone)]
pub struct Dependency {
    /// Name of the required module.
    pub name: String,

    /// Minimum required version (optional).
    pub min_version: Option<SemVer>,

    /// Whether this dependency is optional.
    pub optional: bool,
}

impl Dependency {
    /// Creates a new required dependency.
    #[must_use]
    pub fn required(name: impl Into<String>) -> Self {
        Self {
            name: name.into(),
            min_version: None,
            optional: false,
        }
    }

    /// Creates a new optional dependency.
    #[must_use]
    pub fn optional(name: impl Into<String>) -> Self {
        Self {
            name: name.into(),
            min_version: None,
            optional: true,
        }
    }

    /// Sets the minimum version requirement.
    #[must_use]
    pub fn with_min_version(mut self, version: SemVer) -> Self {
        self.min_version = Some(version);
        self
    }
}

/// Manifest describing a module's identity and capabilities.
#[derive(Debug, Clone)]
pub struct ModuleManifest {
    /// Unique name of the module.
    pub name: String,

    /// Human-readable description.
    pub description: String,

    /// Module version.
    pub version: SemVer,

    /// Capabilities provided by this module.
    pub capabilities: HashSet<Capability>,

    /// Dependencies on other modules.
    pub dependencies: Vec<Dependency>,

    /// Author information.
    pub author: Option<String>,

    /// License identifier.
    pub license: Option<String>,
}

impl ModuleManifest {
    /// Creates a new module manifest builder.
    #[must_use]
    pub fn builder(name: impl Into<String>) -> ModuleManifestBuilder {
        ModuleManifestBuilder::new(name)
    }

    /// Checks if the module has a specific capability.
    #[must_use]
    pub fn has_capability(&self, capability: &Capability) -> bool {
        self.capabilities.contains(capability)
    }

    /// Returns the list of required (non-optional) dependencies.
    #[must_use]
    pub fn required_dependencies(&self) -> Vec<&Dependency> {
        self.dependencies.iter().filter(|d| !d.optional).collect()
    }
}

/// Builder for creating module manifests.
#[derive(Debug)]
pub struct ModuleManifestBuilder {
    name: String,
    description: String,
    version: SemVer,
    capabilities: HashSet<Capability>,
    dependencies: Vec<Dependency>,
    author: Option<String>,
    license: Option<String>,
}

impl ModuleManifestBuilder {
    /// Creates a new builder with the given module name.
    #[must_use]
    pub fn new(name: impl Into<String>) -> Self {
        Self {
            name: name.into(),
            description: String::new(),
            version: SemVer::new(0, 1, 0),
            capabilities: HashSet::new(),
            dependencies: Vec::new(),
            author: None,
            license: None,
        }
    }

    /// Sets the module description.
    #[must_use]
    pub fn description(mut self, description: impl Into<String>) -> Self {
        self.description = description.into();
        self
    }

    /// Sets the module version.
    #[must_use]
    pub fn version(mut self, major: u32, minor: u32, patch: u32) -> Self {
        self.version = SemVer::new(major, minor, patch);
        self
    }

    /// Adds a capability.
    #[must_use]
    pub fn capability(mut self, capability: Capability) -> Self {
        self.capabilities.insert(capability);
        self
    }

    /// Adds multiple capabilities.
    #[must_use]
    pub fn capabilities(mut self, capabilities: impl IntoIterator<Item = Capability>) -> Self {
        self.capabilities.extend(capabilities);
        self
    }

    /// Adds a dependency.
    #[must_use]
    pub fn dependency(mut self, dependency: Dependency) -> Self {
        self.dependencies.push(dependency);
        self
    }

    /// Sets the author.
    #[must_use]
    pub fn author(mut self, author: impl Into<String>) -> Self {
        self.author = Some(author.into());
        self
    }

    /// Sets the license.
    #[must_use]
    pub fn license(mut self, license: impl Into<String>) -> Self {
        self.license = Some(license.into());
        self
    }

    /// Builds the manifest.
    #[must_use]
    pub fn build(self) -> ModuleManifest {
        ModuleManifest {
            name: self.name,
            description: self.description,
            version: self.version,
            capabilities: self.capabilities,
            dependencies: self.dependencies,
            author: self.author,
            license: self.license,
        }
    }
}
