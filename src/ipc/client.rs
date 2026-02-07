//! IPC Client for sending control messages.

use std::path::Path;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::UnixStream;
use tokio::time::timeout;

use super::message::{
    decode_frame_length, encode_frame, ControlCommand, ControlMessage, ControlResponse,
    FRAME_HEADER_SIZE,
};

/// IPC Client for communicating with modules.
pub struct IpcClient {
    /// Path to the Unix socket.
    socket_path: std::path::PathBuf,

    /// Message ID counter.
    next_id: AtomicU64,

    /// Default timeout for operations.
    timeout: Duration,
}

impl IpcClient {
    /// Creates a new IPC client for the given socket path.
    #[must_use]
    pub fn new(socket_path: impl AsRef<Path>) -> Self {
        Self {
            socket_path: socket_path.as_ref().to_path_buf(),
            next_id: AtomicU64::new(1),
            timeout: Duration::from_secs(30),
        }
    }

    /// Sets the default timeout for operations.
    #[must_use]
    pub fn with_timeout(mut self, timeout: Duration) -> Self {
        self.timeout = timeout;
        self
    }

    /// Sends a command and waits for a response.
    ///
    /// # Errors
    ///
    /// Returns an error if the connection fails or times out.
    pub async fn send(&self, command: ControlCommand) -> Result<ControlResponse, IpcClientError> {
        let id = self.next_id.fetch_add(1, Ordering::SeqCst);
        let message = ControlMessage::new(id, command);

        timeout(self.timeout, self.send_message(message))
            .await
            .map_err(|_| IpcClientError::Timeout)?
    }

    /// Sends a message and receives a response.
    async fn send_message(
        &self,
        message: ControlMessage,
    ) -> Result<ControlResponse, IpcClientError> {
        let mut stream = UnixStream::connect(&self.socket_path)
            .await
            .map_err(|e| IpcClientError::ConnectionFailed(e.to_string()))?;

        // Serialize message
        let msg_bytes = message
            .to_bytes()
            .map_err(|e| IpcClientError::SerializationError(e.to_string()))?;

        // Send framed message
        let frame = encode_frame(&msg_bytes);
        stream
            .write_all(&frame)
            .await
            .map_err(|e| IpcClientError::SendError(e.to_string()))?;
        stream
            .flush()
            .await
            .map_err(|e| IpcClientError::SendError(e.to_string()))?;

        // Read response header
        let mut header = [0u8; FRAME_HEADER_SIZE];
        stream
            .read_exact(&mut header)
            .await
            .map_err(|e| IpcClientError::ReceiveError(e.to_string()))?;

        // Decode response length
        let resp_len = decode_frame_length(&header)
            .ok_or_else(|| IpcClientError::ProtocolError("invalid response length".to_string()))?;

        // Read response body
        let mut body = vec![0u8; resp_len];
        stream
            .read_exact(&mut body)
            .await
            .map_err(|e| IpcClientError::ReceiveError(e.to_string()))?;

        // Deserialize response
        ControlResponse::from_bytes(&body)
            .map_err(|e| IpcClientError::DeserializationError(e.to_string()))
    }

    /// Sends a status request.
    ///
    /// # Errors
    ///
    /// Returns an error if the request fails.
    pub async fn status(&self) -> Result<ControlResponse, IpcClientError> {
        self.send(ControlCommand::Status).await
    }

    /// Sends a heartbeat request.
    ///
    /// # Errors
    ///
    /// Returns an error if the request fails.
    pub async fn heartbeat(&self) -> Result<ControlResponse, IpcClientError> {
        self.send(ControlCommand::Heartbeat).await
    }

    /// Sends a start command.
    ///
    /// # Errors
    ///
    /// Returns an error if the request fails.
    pub async fn start(&self) -> Result<ControlResponse, IpcClientError> {
        self.send(ControlCommand::Start).await
    }

    /// Sends a stop command.
    ///
    /// # Errors
    ///
    /// Returns an error if the request fails.
    pub async fn stop(&self) -> Result<ControlResponse, IpcClientError> {
        self.send(ControlCommand::Stop).await
    }

    /// Sends a metrics request.
    ///
    /// # Errors
    ///
    /// Returns an error if the request fails.
    pub async fn metrics(&self) -> Result<ControlResponse, IpcClientError> {
        self.send(ControlCommand::Metrics).await
    }
}

/// Errors that can occur during IPC client operations.
#[derive(Debug, thiserror::Error)]
pub enum IpcClientError {
    /// Failed to connect to the socket.
    #[error("connection failed: {0}")]
    ConnectionFailed(String),

    /// Failed to serialize message.
    #[error("serialization error: {0}")]
    SerializationError(String),

    /// Failed to send message.
    #[error("send error: {0}")]
    SendError(String),

    /// Failed to receive response.
    #[error("receive error: {0}")]
    ReceiveError(String),

    /// Failed to deserialize response.
    #[error("deserialization error: {0}")]
    DeserializationError(String),

    /// Protocol error.
    #[error("protocol error: {0}")]
    ProtocolError(String),

    /// Operation timed out.
    #[error("operation timed out")]
    Timeout,
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ipc::server::{IpcServer, MessageHandler};
    use std::sync::Arc;
    use tempfile::tempdir;

    struct EchoHandler;

    impl MessageHandler for EchoHandler {
        fn handle(&self, message: ControlMessage) -> ControlResponse {
            ControlResponse::ok(message.id)
        }
    }

    #[tokio::test]
    async fn test_client_server_communication() {
        let dir = tempdir().unwrap();
        let socket_path = dir.path().join("test.sock");

        let handler = Arc::new(EchoHandler);

        // Start server in background
        let server_socket_path = socket_path.clone();
        let server_handler = Arc::clone(&handler);
        let server_handle = tokio::spawn(async move {
            let mut server = IpcServer::new(&server_socket_path);
            server.start(server_handler).await.unwrap();
        });

        // Wait for server to start
        tokio::time::sleep(Duration::from_millis(100)).await;

        // Create client and send message
        let client = IpcClient::new(&socket_path).with_timeout(Duration::from_secs(5));

        let response = client.status().await.unwrap();
        assert!(response.status.is_success());

        // Clean up
        server_handle.abort();
    }
}
