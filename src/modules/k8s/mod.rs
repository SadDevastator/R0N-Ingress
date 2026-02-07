//! Kubernetes integration module
//!
//! Provides Kubernetes-native integration for R0N Gateway including:
//! - Ingress controller mode (Kubernetes Ingress resources)
//! - Service discovery (Endpoints, Services)
//! - Auto-scaling hooks (HPA metrics)
//! - ConfigMap/Secret integration

pub mod config;
pub mod discovery;
pub mod error;
pub mod handler;
pub mod ingress;
pub mod secrets;

pub use config::K8sConfig;
pub use discovery::{Endpoint, Service, ServiceDiscovery};
pub use error::{K8sError, K8sResult};
pub use handler::K8sHandler;
pub use ingress::{IngressBackend, IngressController, IngressRule};
pub use secrets::{SecretManager, SecretRef};

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_module_exports() {
        // Verify exports are accessible
        let _ = K8sConfig::default();
    }
}
