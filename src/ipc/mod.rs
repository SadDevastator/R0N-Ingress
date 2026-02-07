//! IPC (Inter-Process Communication) module for R0N Gateway.
//!
//! This module provides the communication layer between the R0N control plane
//! and gateway modules using Unix sockets and MessagePack serialization.
//!
//! Note: The client, server, and heartbeat components require Unix domain
//! sockets and are only available on Unix platforms.

#[cfg(unix)]
mod client;
#[cfg(unix)]
mod heartbeat;
mod message;
#[cfg(unix)]
mod server;

#[cfg(unix)]
pub use client::{IpcClient, IpcClientError};
#[cfg(unix)]
pub use heartbeat::{HeartbeatConfig, HeartbeatError, HeartbeatMonitor};
pub use message::{ControlCommand, ControlMessage, ControlResponse, ResponseStatus};
#[cfg(unix)]
pub use server::{IpcServer, MessageHandler};
