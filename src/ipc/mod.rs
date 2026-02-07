//! IPC (Inter-Process Communication) module for R0N Gateway.
//!
//! This module provides the communication layer between the R0N control plane
//! and gateway modules using Unix sockets and MessagePack serialization.

mod client;
mod heartbeat;
mod message;
mod server;

pub use client::{IpcClient, IpcClientError};
pub use heartbeat::{HeartbeatConfig, HeartbeatError, HeartbeatMonitor};
pub use message::{ControlCommand, ControlMessage, ControlResponse, ResponseStatus};
pub use server::{IpcServer, MessageHandler};
