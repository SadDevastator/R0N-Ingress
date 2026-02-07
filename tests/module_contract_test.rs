#![cfg(unix)]
//! Integration tests for the Module Control Contract.

use r0n_ingress::ipc::{
    ControlCommand, ControlMessage, ControlResponse, IpcClient, IpcServer, MessageHandler,
    ResponseStatus,
};
use r0n_ingress::module::{
    Capability, MetricsPayload, ModuleConfig, ModuleContract, ModuleError, ModuleManifest,
    ModuleResult, ModuleStatus,
};
use std::sync::{Arc, Mutex};
use std::time::Duration;
use tempfile::tempdir;

/// A test module that implements the ModuleContract.
struct TestModule {
    name: String,
    status: ModuleStatus,
    config: Option<ModuleConfig>,
    start_count: u32,
    stop_count: u32,
}

impl TestModule {
    fn new(name: &str) -> Self {
        Self {
            name: name.to_string(),
            status: ModuleStatus::Stopped,
            config: None,
            start_count: 0,
            stop_count: 0,
        }
    }
}

impl ModuleContract for TestModule {
    fn manifest(&self) -> ModuleManifest {
        ModuleManifest::builder(&self.name)
            .description("Test module for integration tests")
            .version(1, 0, 0)
            .capability(Capability::TcpListener)
            .build()
    }

    fn init(&mut self, config: ModuleConfig) -> ModuleResult<()> {
        self.config = Some(config);
        self.status = ModuleStatus::Initializing;
        Ok(())
    }

    fn start(&mut self) -> ModuleResult<()> {
        if !matches!(
            self.status,
            ModuleStatus::Initializing | ModuleStatus::Stopped
        ) {
            return Err(ModuleError::InvalidState {
                current: self.status.to_string(),
                expected: "Initializing or Stopped".to_string(),
            });
        }
        self.status = ModuleStatus::Running;
        self.start_count += 1;
        Ok(())
    }

    fn stop(&mut self) -> ModuleResult<()> {
        self.status = ModuleStatus::Stopped;
        self.stop_count += 1;
        Ok(())
    }

    fn status(&self) -> ModuleStatus {
        self.status.clone()
    }

    fn metrics(&self) -> MetricsPayload {
        let mut metrics = MetricsPayload::new();
        metrics.counter("start_count", u64::from(self.start_count));
        metrics.counter("stop_count", u64::from(self.stop_count));
        metrics
    }
}

/// Message handler that wraps a module.
struct ModuleHandler {
    module: Mutex<TestModule>,
}

impl ModuleHandler {
    fn new(module: TestModule) -> Self {
        Self {
            module: Mutex::new(module),
        }
    }
}

impl MessageHandler for ModuleHandler {
    fn handle(&self, message: ControlMessage) -> ControlResponse {
        let mut module = self.module.lock().unwrap();

        match message.command {
            ControlCommand::Init { config: _ } => {
                let config = ModuleConfig::new();
                match module.init(config) {
                    Ok(()) => ControlResponse::ok(message.id),
                    Err(e) => ControlResponse::error(message.id, e.to_string()),
                }
            },
            ControlCommand::Start => match module.start() {
                Ok(()) => ControlResponse::ok(message.id),
                Err(e) => ControlResponse::error(message.id, e.to_string()),
            },
            ControlCommand::Stop => match module.stop() {
                Ok(()) => ControlResponse::ok(message.id),
                Err(e) => ControlResponse::error(message.id, e.to_string()),
            },
            ControlCommand::Status => {
                let status = module.status();
                let payload = format!("{}", status).into_bytes();
                ControlResponse::ok_with_payload(message.id, payload)
            },
            ControlCommand::Metrics => {
                let metrics = module.metrics();
                let payload = metrics.to_prometheus("test_module").into_bytes();
                ControlResponse::ok_with_payload(message.id, payload)
            },
            ControlCommand::Heartbeat => {
                if module.heartbeat() {
                    ControlResponse::ok(message.id)
                } else {
                    ControlResponse::with_status(message.id, ResponseStatus::Error)
                }
            },
            ControlCommand::Pause => match module.pause() {
                Ok(()) => ControlResponse::ok(message.id),
                Err(e) => ControlResponse::error(message.id, e.to_string()),
            },
            ControlCommand::Resume => match module.resume() {
                Ok(()) => ControlResponse::ok(message.id),
                Err(e) => ControlResponse::error(message.id, e.to_string()),
            },
            ControlCommand::Version => {
                let version = module.contract_version();
                let payload =
                    format!("{}.{}.{}", version.major, version.minor, version.patch).into_bytes();
                ControlResponse::ok_with_payload(message.id, payload)
            },
            ControlCommand::Reload { config: _ } => {
                ControlResponse::with_status(message.id, ResponseStatus::NotSupported)
            },
            ControlCommand::Shutdown => ControlResponse::ok(message.id),
        }
    }
}

#[tokio::test]
async fn test_module_lifecycle() {
    let dir = tempdir().unwrap();
    let socket_path = dir.path().join("module.sock");

    let module = TestModule::new("test-module");
    let handler = Arc::new(ModuleHandler::new(module));

    // Start server
    let server_socket_path = socket_path.clone();
    let server_handler = Arc::clone(&handler);
    let server_handle = tokio::spawn(async move {
        let mut server = IpcServer::new(&server_socket_path);
        server.start(server_handler).await.unwrap();
    });

    tokio::time::sleep(Duration::from_millis(100)).await;

    // Create client
    let client = IpcClient::new(&socket_path).with_timeout(Duration::from_secs(5));

    // Test init
    let response = client
        .send(ControlCommand::Init { config: vec![] })
        .await
        .unwrap();
    assert!(response.status.is_success());

    // Test start
    let response = client.start().await.unwrap();
    assert!(response.status.is_success());

    // Test status
    let response = client.status().await.unwrap();
    assert!(response.status.is_success());
    let status_str = String::from_utf8(response.payload.unwrap()).unwrap();
    assert_eq!(status_str, "running");

    // Test heartbeat
    let response = client.heartbeat().await.unwrap();
    assert!(response.status.is_success());

    // Test metrics
    let response = client.metrics().await.unwrap();
    assert!(response.status.is_success());
    let metrics_str = String::from_utf8(response.payload.unwrap()).unwrap();
    assert!(metrics_str.contains("start_count"));

    // Test stop
    let response = client.stop().await.unwrap();
    assert!(response.status.is_success());

    // Clean up
    server_handle.abort();
}

#[tokio::test]
async fn test_module_invalid_state_transition() {
    let dir = tempdir().unwrap();
    let socket_path = dir.path().join("module2.sock");

    let module = TestModule::new("test-module-2");
    let handler = Arc::new(ModuleHandler::new(module));

    let server_socket_path = socket_path.clone();
    let server_handler = Arc::clone(&handler);
    let server_handle = tokio::spawn(async move {
        let mut server = IpcServer::new(&server_socket_path);
        server.start(server_handler).await.unwrap();
    });

    tokio::time::sleep(Duration::from_millis(100)).await;

    let client = IpcClient::new(&socket_path).with_timeout(Duration::from_secs(5));

    // Try to start without init - should fail because state is Stopped
    // Actually in our implementation, Stopped is a valid state to start from
    // Let's test double start instead

    // Init first
    let response = client
        .send(ControlCommand::Init { config: vec![] })
        .await
        .unwrap();
    assert!(response.status.is_success());

    // Start
    let response = client.start().await.unwrap();
    assert!(response.status.is_success());

    // Try to start again - should fail (already running)
    let response = client.start().await.unwrap();
    assert!(!response.status.is_success());
    assert!(response.error.is_some());

    server_handle.abort();
}

#[test]
fn test_module_manifest_builder() {
    let manifest = ModuleManifest::builder("my-module")
        .description("A test module")
        .version(2, 1, 0)
        .capability(Capability::TcpListener)
        .capability(Capability::Metrics)
        .author("Test Author")
        .license("MIT")
        .build();

    assert_eq!(manifest.name, "my-module");
    assert_eq!(manifest.description, "A test module");
    assert_eq!(manifest.version.major, 2);
    assert_eq!(manifest.version.minor, 1);
    assert_eq!(manifest.version.patch, 0);
    assert!(manifest.has_capability(&Capability::TcpListener));
    assert!(manifest.has_capability(&Capability::Metrics));
    assert!(!manifest.has_capability(&Capability::UdpListener));
    assert_eq!(manifest.author, Some("Test Author".to_string()));
    assert_eq!(manifest.license, Some("MIT".to_string()));
}

#[test]
fn test_module_status_checks() {
    let running = ModuleStatus::Running;
    assert!(running.is_healthy());
    assert!(running.is_operational());
    assert!(!running.is_stopped());
    assert!(!running.is_error());

    let degraded = ModuleStatus::Degraded {
        reason: "test".to_string(),
    };
    assert!(!degraded.is_healthy());
    assert!(degraded.is_operational());

    let stopped = ModuleStatus::Stopped;
    assert!(!stopped.is_healthy());
    assert!(!stopped.is_operational());
    assert!(stopped.is_stopped());

    let error = ModuleStatus::Error {
        message: "test error".to_string(),
    };
    assert!(!error.is_healthy());
    assert!(!error.is_operational());
    assert!(error.is_error());
}
