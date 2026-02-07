//! IPC Server for receiving control messages.

use std::path::Path;
use std::sync::Arc;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{UnixListener, UnixStream};
use tokio::sync::mpsc;
use tracing::{debug, error, info, warn};

use super::message::{
    decode_frame_length, encode_frame, ControlMessage, ControlResponse, FRAME_HEADER_SIZE,
    MAX_MESSAGE_SIZE,
};

/// Handler trait for processing control messages.
pub trait MessageHandler: Send + Sync + 'static {
    /// Handles an incoming control message and returns a response.
    fn handle(&self, message: ControlMessage) -> ControlResponse;
}

/// IPC Server that listens on a Unix socket for control messages.
pub struct IpcServer {
    /// Path to the Unix socket.
    socket_path: std::path::PathBuf,

    /// Shutdown signal sender.
    shutdown_tx: Option<mpsc::Sender<()>>,
}

impl IpcServer {
    /// Creates a new IPC server bound to the given socket path.
    ///
    /// # Arguments
    ///
    /// * `socket_path` - Path where the Unix socket will be created.
    #[must_use]
    pub fn new(socket_path: impl AsRef<Path>) -> Self {
        Self {
            socket_path: socket_path.as_ref().to_path_buf(),
            shutdown_tx: None,
        }
    }

    /// Starts the server and listens for incoming connections.
    ///
    /// # Arguments
    ///
    /// * `handler` - The message handler to process incoming messages.
    ///
    /// # Errors
    ///
    /// Returns an error if the socket cannot be created.
    pub async fn start<H: MessageHandler>(
        &mut self,
        handler: Arc<H>,
    ) -> Result<(), std::io::Error> {
        // Remove existing socket if present
        if self.socket_path.exists() {
            std::fs::remove_file(&self.socket_path)?;
        }

        let listener = UnixListener::bind(&self.socket_path)?;
        info!("IPC server listening on {:?}", self.socket_path);

        let (shutdown_tx, mut shutdown_rx) = mpsc::channel::<()>(1);
        self.shutdown_tx = Some(shutdown_tx);

        loop {
            tokio::select! {
                accept_result = listener.accept() => {
                    match accept_result {
                        Ok((stream, _)) => {
                            let handler = Arc::clone(&handler);
                            tokio::spawn(async move {
                                if let Err(e) = Self::handle_connection(stream, handler).await {
                                    error!("Connection error: {}", e);
                                }
                            });
                        }
                        Err(e) => {
                            error!("Accept error: {}", e);
                        }
                    }
                }
                _ = shutdown_rx.recv() => {
                    info!("IPC server shutting down");
                    break;
                }
            }
        }

        // Clean up socket file
        if self.socket_path.exists() {
            let _ = std::fs::remove_file(&self.socket_path);
        }

        Ok(())
    }

    /// Handles a single client connection.
    async fn handle_connection<H: MessageHandler>(
        mut stream: UnixStream,
        handler: Arc<H>,
    ) -> Result<(), std::io::Error> {
        debug!("New IPC connection");

        loop {
            // Read frame header
            let mut header = [0u8; FRAME_HEADER_SIZE];
            match stream.read_exact(&mut header).await {
                Ok(_) => {},
                Err(e) if e.kind() == std::io::ErrorKind::UnexpectedEof => {
                    debug!("Client disconnected");
                    break;
                },
                Err(e) => return Err(e),
            }

            // Decode message length
            let msg_len = match decode_frame_length(&header) {
                Some(len) => len,
                None => {
                    warn!("Invalid message length");
                    continue;
                },
            };

            if msg_len > MAX_MESSAGE_SIZE {
                warn!("Message too large: {} bytes", msg_len);
                continue;
            }

            // Read message body
            let mut body = vec![0u8; msg_len];
            stream.read_exact(&mut body).await?;

            // Deserialize message
            let message = match ControlMessage::from_bytes(&body) {
                Ok(msg) => msg,
                Err(e) => {
                    warn!("Failed to deserialize message: {}", e);
                    continue;
                },
            };

            debug!("Received message: {:?}", message.command);

            // Handle message
            let response = handler.handle(message);

            // Serialize and send response
            let response_bytes = match response.to_bytes() {
                Ok(bytes) => bytes,
                Err(e) => {
                    error!("Failed to serialize response: {}", e);
                    continue;
                },
            };

            let frame = encode_frame(&response_bytes);
            stream.write_all(&frame).await?;
            stream.flush().await?;
        }

        Ok(())
    }

    /// Signals the server to shut down.
    pub async fn shutdown(&self) {
        if let Some(tx) = &self.shutdown_tx {
            let _ = tx.send(()).await;
        }
    }

    /// Returns the socket path.
    #[must_use]
    pub fn socket_path(&self) -> &Path {
        &self.socket_path
    }
}

impl Drop for IpcServer {
    fn drop(&mut self) {
        // Clean up socket file
        if self.socket_path.exists() {
            let _ = std::fs::remove_file(&self.socket_path);
        }
    }
}
