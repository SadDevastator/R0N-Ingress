//! Web Application Firewall Module
//!
//! Provides comprehensive protection against web-based attacks including:
//! - SQL injection detection
//! - Cross-site scripting (XSS) detection
//! - Path traversal detection
//! - Request body inspection
//! - Custom rule definitions
//! - OWASP Core Rule Set (CRS) compatibility

mod config;
mod detector;
mod engine;
mod error;
mod handler;
mod logging;
mod rules;

pub use config::{
    BypassCondition, BypassRule, DetectionMode, RuleAction, RuleSeverity, ThreatLogConfig,
    WafConfig, WafRuleConfig,
};
pub use detector::{
    DetectionResult, Detector, PathTraversalDetector, SqlInjectionDetector, XssDetector,
};
pub use engine::{RuleEngine, RuleMatch, ScanContext, ScanResult};
pub use error::{WafError, WafResult};
pub use handler::{ThreatInfo, WafHandler, WafStats};
pub use logging::{ThreatLog, ThreatLogEntry, ThreatLogger};
pub use rules::{
    CompiledRule, Operator, RuleCategory, RuleDefinition, RuleSet, RuleTarget, Transform,
};
