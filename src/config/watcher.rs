//! Configuration file watcher for hot-reload support.
//!
//! Provides infrastructure for watching configuration files and triggering
//! reloads when changes are detected. Hot-reload is disabled by default.

use super::error::ConfigResult;
use super::loader::ConfigLoader;
use super::types::GatewayConfig;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::{Duration, SystemTime};
use tokio::sync::mpsc;
use tokio::sync::RwLock;

/// Configuration for the file watcher.
#[derive(Debug, Clone)]
pub struct WatcherConfig {
    /// Polling interval for file changes.
    pub poll_interval: Duration,
    /// Debounce duration (ignore rapid changes).
    pub debounce: Duration,
    /// Whether hot-reload is enabled.
    pub enabled: bool,
}

impl Default for WatcherConfig {
    fn default() -> Self {
        Self {
            poll_interval: Duration::from_secs(5),
            debounce: Duration::from_millis(500),
            enabled: false, // Disabled by default
        }
    }
}

impl WatcherConfig {
    /// Create a new watcher config with hot-reload enabled.
    #[must_use]
    pub fn enabled() -> Self {
        Self {
            enabled: true,
            ..Default::default()
        }
    }

    /// Set the poll interval.
    #[must_use]
    pub fn with_poll_interval(mut self, interval: Duration) -> Self {
        self.poll_interval = interval;
        self
    }

    /// Set the debounce duration.
    #[must_use]
    pub fn with_debounce(mut self, debounce: Duration) -> Self {
        self.debounce = debounce;
        self
    }
}

/// Event emitted when configuration changes.
#[derive(Debug, Clone)]
pub enum ConfigEvent {
    /// Configuration was reloaded successfully.
    Reloaded(Arc<GatewayConfig>),
    /// Configuration reload failed.
    Error(String),
}

/// Watches configuration files for changes.
pub struct ConfigWatcher {
    /// Path to the configuration file.
    config_path: PathBuf,
    /// Watcher configuration.
    watcher_config: WatcherConfig,
    /// Configuration loader.
    loader: ConfigLoader,
    /// Current configuration.
    current_config: Arc<RwLock<GatewayConfig>>,
    /// Last modification time.
    last_modified: Arc<RwLock<Option<SystemTime>>>,
    /// Shutdown signal.
    shutdown_tx: Option<mpsc::Sender<()>>,
}

impl ConfigWatcher {
    /// Create a new configuration watcher.
    ///
    /// # Errors
    ///
    /// Returns an error if the initial configuration cannot be loaded.
    pub fn new<P: AsRef<Path>>(
        config_path: P,
        loader: ConfigLoader,
        watcher_config: WatcherConfig,
    ) -> ConfigResult<Self> {
        let config_path = config_path.as_ref().to_path_buf();
        let initial_config = loader.load(&config_path)?;
        let last_modified = Self::get_modified_time(&config_path);

        Ok(Self {
            config_path,
            watcher_config,
            loader,
            current_config: Arc::new(RwLock::new(initial_config)),
            last_modified: Arc::new(RwLock::new(last_modified)),
            shutdown_tx: None,
        })
    }

    /// Get the current configuration.
    #[must_use]
    pub fn config(&self) -> Arc<RwLock<GatewayConfig>> {
        Arc::clone(&self.current_config)
    }

    /// Get the current configuration (blocking read).
    pub async fn get_config(&self) -> GatewayConfig {
        self.current_config.read().await.clone()
    }

    /// Start watching for configuration changes.
    ///
    /// Returns a receiver for configuration events.
    pub fn start(&mut self) -> mpsc::Receiver<ConfigEvent> {
        let (event_tx, event_rx) = mpsc::channel(16);
        let (shutdown_tx, mut shutdown_rx) = mpsc::channel::<()>(1);

        self.shutdown_tx = Some(shutdown_tx);

        if !self.watcher_config.enabled {
            // Hot-reload disabled, just return the receiver
            return event_rx;
        }

        let config_path = self.config_path.clone();
        let poll_interval = self.watcher_config.poll_interval;
        let current_config = Arc::clone(&self.current_config);
        let last_modified = Arc::clone(&self.last_modified);
        let loader = ConfigLoader::new(); // Create new loader for the task

        tokio::spawn(async move {
            let mut interval = tokio::time::interval(poll_interval);

            loop {
                tokio::select! {
                    _ = interval.tick() => {
                        if let Some(new_mtime) = Self::get_modified_time(&config_path) {
                            let should_reload = {
                                let last = last_modified.read().await;
                                last.map_or(true, |old| new_mtime > old)
                            };

                            if should_reload {
                                match loader.load(&config_path) {
                                    Ok(new_config) => {
                                        {
                                            let mut config = current_config.write().await;
                                            *config = new_config.clone();
                                        }
                                        {
                                            let mut mtime = last_modified.write().await;
                                            *mtime = Some(new_mtime);
                                        }
                                        let _ = event_tx.send(ConfigEvent::Reloaded(Arc::new(new_config))).await;
                                    }
                                    Err(e) => {
                                        let _ = event_tx.send(ConfigEvent::Error(e.to_string())).await;
                                    }
                                }
                            }
                        }
                    }
                    _ = shutdown_rx.recv() => {
                        break;
                    }
                }
            }
        });

        event_rx
    }

    /// Stop watching for configuration changes.
    pub async fn stop(&mut self) {
        if let Some(tx) = self.shutdown_tx.take() {
            let _ = tx.send(()).await;
        }
    }

    /// Force a reload of the configuration.
    ///
    /// # Errors
    ///
    /// Returns an error if the configuration cannot be loaded.
    pub async fn reload(&self) -> ConfigResult<GatewayConfig> {
        let new_config = self.loader.load(&self.config_path)?;
        {
            let mut config = self.current_config.write().await;
            *config = new_config.clone();
        }
        if let Some(mtime) = Self::get_modified_time(&self.config_path) {
            let mut last = self.last_modified.write().await;
            *last = Some(mtime);
        }
        Ok(new_config)
    }

    fn get_modified_time(path: &Path) -> Option<SystemTime> {
        std::fs::metadata(path).ok().and_then(|m| m.modified().ok())
    }
}

/// Builder for creating a watched configuration.
#[derive(Debug)]
pub struct WatchedConfigBuilder {
    config_path: PathBuf,
    loader: ConfigLoader,
    watcher_config: WatcherConfig,
}

impl WatchedConfigBuilder {
    /// Create a new builder.
    #[must_use]
    pub fn new<P: AsRef<Path>>(config_path: P) -> Self {
        Self {
            config_path: config_path.as_ref().to_path_buf(),
            loader: ConfigLoader::new(),
            watcher_config: WatcherConfig::default(),
        }
    }

    /// Set the configuration loader.
    #[must_use]
    pub fn with_loader(mut self, loader: ConfigLoader) -> Self {
        self.loader = loader;
        self
    }

    /// Enable hot-reload.
    #[must_use]
    pub fn with_hot_reload(mut self) -> Self {
        self.watcher_config.enabled = true;
        self
    }

    /// Set the poll interval.
    #[must_use]
    pub fn with_poll_interval(mut self, interval: Duration) -> Self {
        self.watcher_config.poll_interval = interval;
        self
    }

    /// Build the configuration watcher.
    ///
    /// # Errors
    ///
    /// Returns an error if the initial configuration cannot be loaded.
    pub fn build(self) -> ConfigResult<ConfigWatcher> {
        ConfigWatcher::new(self.config_path, self.loader, self.watcher_config)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::tempdir;

    #[test]
    fn test_watcher_config_default() {
        let config = WatcherConfig::default();
        assert!(!config.enabled);
        assert_eq!(config.poll_interval, Duration::from_secs(5));
    }

    #[test]
    fn test_watcher_config_enabled() {
        let config = WatcherConfig::enabled().with_poll_interval(Duration::from_secs(1));
        assert!(config.enabled);
        assert_eq!(config.poll_interval, Duration::from_secs(1));
    }

    #[tokio::test]
    async fn test_config_watcher_creation() {
        let dir = tempdir().unwrap();
        let config_path = dir.path().join("config.toml");

        std::fs::write(
            &config_path,
            r#"
            [gateway]
            name = "test-gateway"
        "#,
        )
        .unwrap();

        let watcher =
            ConfigWatcher::new(&config_path, ConfigLoader::new(), WatcherConfig::default())
                .unwrap();

        let config = watcher.get_config().await;
        assert_eq!(config.gateway.name, "test-gateway");
    }

    #[tokio::test]
    async fn test_config_watcher_force_reload() {
        let dir = tempdir().unwrap();
        let config_path = dir.path().join("config.toml");

        std::fs::write(
            &config_path,
            r#"
            [gateway]
            name = "initial"
        "#,
        )
        .unwrap();

        let watcher =
            ConfigWatcher::new(&config_path, ConfigLoader::new(), WatcherConfig::default())
                .unwrap();

        // Update the file
        std::fs::write(
            &config_path,
            r#"
            [gateway]
            name = "updated"
        "#,
        )
        .unwrap();

        // Force reload
        let config = watcher.reload().await.unwrap();
        assert_eq!(config.gateway.name, "updated");
    }

    #[test]
    fn test_watched_config_builder() {
        let dir = tempdir().unwrap();
        let config_path = dir.path().join("config.toml");

        std::fs::write(
            &config_path,
            r#"
            [gateway]
            name = "builder-test"
        "#,
        )
        .unwrap();

        let watcher = WatchedConfigBuilder::new(&config_path)
            .with_hot_reload()
            .with_poll_interval(Duration::from_secs(1))
            .build()
            .unwrap();

        assert!(watcher.watcher_config.enabled);
    }
}
