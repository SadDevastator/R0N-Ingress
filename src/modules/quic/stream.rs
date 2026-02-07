//! QUIC stream management

use super::error::{QuicError, QuicResult};
use std::collections::VecDeque;
use std::io::{self, Read, Write};

/// Stream ID (62-bit value)
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct StreamId(u64);

impl StreamId {
    /// Maximum stream ID value (62 bits)
    pub const MAX: u64 = (1 << 62) - 1;

    /// Create new stream ID
    pub fn new(id: u64) -> Self {
        Self(id & Self::MAX)
    }

    /// Get raw ID value
    pub fn id(&self) -> u64 {
        self.0
    }

    /// Check if client-initiated (even)
    pub fn is_client_initiated(&self) -> bool {
        self.0 & 0x01 == 0
    }

    /// Check if server-initiated (odd)
    pub fn is_server_initiated(&self) -> bool {
        self.0 & 0x01 == 1
    }

    /// Check if bidirectional
    pub fn is_bidirectional(&self) -> bool {
        self.0 & 0x02 == 0
    }

    /// Check if unidirectional
    pub fn is_unidirectional(&self) -> bool {
        self.0 & 0x02 == 2
    }

    /// Get stream type
    pub fn stream_type(&self) -> StreamType {
        if self.is_bidirectional() {
            StreamType::Bidirectional
        } else {
            StreamType::Unidirectional
        }
    }

    /// Get stream direction (for unidirectional)
    pub fn direction(&self) -> StreamDirection {
        match (self.is_client_initiated(), self.is_unidirectional()) {
            (true, true) => StreamDirection::ClientToServer,
            (false, true) => StreamDirection::ServerToClient,
            _ => StreamDirection::Both,
        }
    }

    /// Get next stream ID of the same type
    pub fn next(&self) -> Self {
        Self::new(self.0 + 4)
    }

    /// Check if valid
    pub fn is_valid(&self) -> bool {
        self.0 <= Self::MAX
    }

    /// Create client-initiated bidirectional stream ID
    pub fn client_bidi(n: u64) -> Self {
        Self::new(n * 4)
    }

    /// Create server-initiated bidirectional stream ID
    pub fn server_bidi(n: u64) -> Self {
        Self::new(n * 4 + 1)
    }

    /// Create client-initiated unidirectional stream ID
    pub fn client_uni(n: u64) -> Self {
        Self::new(n * 4 + 2)
    }

    /// Create server-initiated unidirectional stream ID
    pub fn server_uni(n: u64) -> Self {
        Self::new(n * 4 + 3)
    }
}

impl std::fmt::Display for StreamId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.0)
    }
}

impl From<u64> for StreamId {
    fn from(id: u64) -> Self {
        Self::new(id)
    }
}

/// Stream type
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum StreamType {
    /// Bidirectional stream (both sides can send/receive)
    Bidirectional,

    /// Unidirectional stream (one side sends, other receives)
    Unidirectional,
}

impl std::fmt::Display for StreamType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Bidirectional => write!(f, "bidirectional"),
            Self::Unidirectional => write!(f, "unidirectional"),
        }
    }
}

/// Stream direction
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum StreamDirection {
    /// Client to server only
    ClientToServer,

    /// Server to client only
    ServerToClient,

    /// Both directions (bidirectional)
    Both,
}

/// Stream state
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum StreamState {
    /// Stream is ready (not yet used)
    Ready,

    /// Send side is open
    SendOpen,

    /// Receive side is open
    RecvOpen,

    /// Both sides are open
    Open,

    /// Send side has sent FIN
    SendClosed,

    /// Receive side has received FIN
    RecvClosed,

    /// Stream is half-closed (send closed, receive open)
    HalfClosedLocal,

    /// Stream is half-closed (receive closed, send open)
    HalfClosedRemote,

    /// Stream is reset
    Reset,

    /// Stream is fully closed
    Closed,
}

impl StreamState {
    /// Check if can send
    pub fn can_send(&self) -> bool {
        matches!(
            self,
            Self::Ready | Self::SendOpen | Self::Open | Self::HalfClosedRemote
        )
    }

    /// Check if can receive
    pub fn can_receive(&self) -> bool {
        matches!(
            self,
            Self::Ready | Self::RecvOpen | Self::Open | Self::HalfClosedLocal
        )
    }

    /// Check if closed
    pub fn is_closed(&self) -> bool {
        matches!(self, Self::Closed | Self::Reset)
    }

    /// Check if reset
    pub fn is_reset(&self) -> bool {
        matches!(self, Self::Reset)
    }
}

impl std::fmt::Display for StreamState {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Ready => write!(f, "ready"),
            Self::SendOpen => write!(f, "send_open"),
            Self::RecvOpen => write!(f, "recv_open"),
            Self::Open => write!(f, "open"),
            Self::SendClosed => write!(f, "send_closed"),
            Self::RecvClosed => write!(f, "recv_closed"),
            Self::HalfClosedLocal => write!(f, "half_closed_local"),
            Self::HalfClosedRemote => write!(f, "half_closed_remote"),
            Self::Reset => write!(f, "reset"),
            Self::Closed => write!(f, "closed"),
        }
    }
}

/// Stream flow control
#[derive(Debug, Clone)]
pub struct StreamFlowControl {
    /// Max data we can receive on this stream
    pub max_data: u64,

    /// Data consumed on receive
    pub data_consumed: u64,

    /// Max data peer can receive on this stream
    pub peer_max_data: u64,

    /// Data sent
    pub data_sent: u64,
}

impl StreamFlowControl {
    /// Create with initial values
    pub fn new(max_data: u64, peer_max_data: u64) -> Self {
        Self {
            max_data,
            data_consumed: 0,
            peer_max_data,
            data_sent: 0,
        }
    }

    /// Available receive window
    pub fn receive_window(&self) -> u64 {
        self.max_data.saturating_sub(self.data_consumed)
    }

    /// Available send window
    pub fn send_window(&self) -> u64 {
        self.peer_max_data.saturating_sub(self.data_sent)
    }

    /// Record data consumed
    pub fn consume(&mut self, amount: u64) -> QuicResult<()> {
        let new_consumed = self.data_consumed.saturating_add(amount);
        if new_consumed > self.max_data {
            return Err(QuicError::FlowControl(format!(
                "stream flow control limit exceeded: {} > {}",
                new_consumed, self.max_data
            )));
        }
        self.data_consumed = new_consumed;
        Ok(())
    }

    /// Record data sent
    pub fn send(&mut self, amount: u64) -> QuicResult<()> {
        let new_sent = self.data_sent.saturating_add(amount);
        if new_sent > self.peer_max_data {
            return Err(QuicError::FlowControl(format!(
                "peer stream flow control limit exceeded: {} > {}",
                new_sent, self.peer_max_data
            )));
        }
        self.data_sent = new_sent;
        Ok(())
    }

    /// Update max data (from MAX_STREAM_DATA frame)
    pub fn update_max_data(&mut self, max_data: u64) {
        if max_data > self.max_data {
            self.max_data = max_data;
        }
    }

    /// Update peer max data
    pub fn update_peer_max_data(&mut self, max_data: u64) {
        if max_data > self.peer_max_data {
            self.peer_max_data = max_data;
        }
    }
}

impl Default for StreamFlowControl {
    fn default() -> Self {
        Self::new(1024 * 1024, 1024 * 1024) // 1 MB default
    }
}

/// Stream buffer for reassembly
#[derive(Debug, Default)]
pub struct StreamBuffer {
    /// Ordered data chunks
    chunks: VecDeque<StreamChunk>,

    /// Total buffered bytes
    buffered_bytes: usize,

    /// Next expected offset for reading
    read_offset: u64,

    /// FIN offset (if received)
    fin_offset: Option<u64>,

    /// Maximum buffer size
    max_buffer_size: usize,
}

/// A chunk of stream data
#[derive(Debug, Clone)]
struct StreamChunk {
    offset: u64,
    data: Vec<u8>,
}

impl StreamBuffer {
    /// Create new buffer
    pub fn new(max_size: usize) -> Self {
        Self {
            chunks: VecDeque::new(),
            buffered_bytes: 0,
            read_offset: 0,
            fin_offset: None,
            max_buffer_size: max_size,
        }
    }

    /// Insert data at offset
    pub fn insert(&mut self, offset: u64, data: &[u8], is_fin: bool) -> QuicResult<()> {
        if data.is_empty() && !is_fin {
            return Ok(());
        }

        // Check if this would exceed buffer size
        if self.buffered_bytes + data.len() > self.max_buffer_size {
            return Err(QuicError::FlowControl("stream buffer overflow".to_string()));
        }

        // Set FIN offset if present
        if is_fin {
            let fin_at = offset + data.len() as u64;
            if let Some(existing_fin) = self.fin_offset {
                if existing_fin != fin_at {
                    return Err(QuicError::Protocol("FIN offset mismatch".to_string()));
                }
            } else {
                self.fin_offset = Some(fin_at);
            }
        }

        // Check for duplicate/old data
        let end_offset = offset + data.len() as u64;
        if end_offset <= self.read_offset {
            // Already consumed this data
            return Ok(());
        }

        // Trim already-consumed prefix
        let (actual_offset, actual_data) = if offset < self.read_offset {
            let skip = (self.read_offset - offset) as usize;
            (self.read_offset, &data[skip..])
        } else {
            (offset, data)
        };

        if actual_data.is_empty() {
            return Ok(());
        }

        // Insert in order
        let chunk = StreamChunk {
            offset: actual_offset,
            data: actual_data.to_vec(),
        };

        // Find insertion point (maintain sorted order by offset)
        let pos = self.chunks.iter().position(|c| c.offset > actual_offset);
        match pos {
            Some(i) => self.chunks.insert(i, chunk),
            None => self.chunks.push_back(chunk),
        }

        self.buffered_bytes += actual_data.len();
        Ok(())
    }

    /// Read available contiguous data
    pub fn read(&mut self, buf: &mut [u8]) -> usize {
        let mut total_read = 0;

        while total_read < buf.len() && !self.chunks.is_empty() {
            let front = self.chunks.front().unwrap();

            // Check if this chunk is contiguous with read_offset
            if front.offset > self.read_offset {
                break; // Gap in data
            }

            // Calculate how much to read from this chunk
            let chunk_start = (self.read_offset - front.offset) as usize;
            let chunk_available = front.data.len() - chunk_start;
            let to_read = chunk_available.min(buf.len() - total_read);

            buf[total_read..total_read + to_read]
                .copy_from_slice(&front.data[chunk_start..chunk_start + to_read]);

            total_read += to_read;
            self.read_offset += to_read as u64;
            self.buffered_bytes -= to_read;

            // Remove chunk if fully consumed
            if chunk_start + to_read >= front.data.len() {
                self.chunks.pop_front();
            }
        }

        total_read
    }

    /// Check if FIN has been received and all data read
    pub fn is_finished(&self) -> bool {
        if let Some(fin_offset) = self.fin_offset {
            self.read_offset >= fin_offset
        } else {
            false
        }
    }

    /// Get buffered byte count
    pub fn len(&self) -> usize {
        self.buffered_bytes
    }

    /// Check if buffer is empty
    pub fn is_empty(&self) -> bool {
        self.buffered_bytes == 0
    }

    /// Get read offset
    pub fn read_offset(&self) -> u64 {
        self.read_offset
    }
}

/// QUIC Stream
pub struct Stream {
    /// Stream ID
    id: StreamId,

    /// Stream type
    stream_type: StreamType,

    /// Stream state
    state: StreamState,

    /// Flow control
    flow_control: StreamFlowControl,

    /// Receive buffer
    recv_buffer: StreamBuffer,

    /// Send buffer
    send_buffer: VecDeque<u8>,

    /// Send offset (next byte to send)
    send_offset: u64,

    /// FIN sent
    fin_sent: bool,

    /// FIN received
    fin_received: bool,

    /// Reset error code (if reset)
    reset_code: Option<u64>,

    /// Priority (0-255, lower is higher priority)
    priority: u8,
}

impl Stream {
    /// Create new stream
    pub fn new(id: StreamId, stream_type: StreamType) -> Self {
        Self {
            id,
            stream_type,
            state: StreamState::Ready,
            flow_control: StreamFlowControl::default(),
            recv_buffer: StreamBuffer::new(1024 * 1024), // 1 MB
            send_buffer: VecDeque::new(),
            send_offset: 0,
            fin_sent: false,
            fin_received: false,
            reset_code: None,
            priority: 128, // Default priority
        }
    }

    /// Get stream ID
    pub fn id(&self) -> StreamId {
        self.id
    }

    /// Get stream type
    pub fn stream_type(&self) -> StreamType {
        self.stream_type
    }

    /// Get stream state
    pub fn state(&self) -> StreamState {
        self.state
    }

    /// Set stream state
    pub fn set_state(&mut self, state: StreamState) {
        self.state = state;
    }

    /// Get flow control
    pub fn flow_control(&self) -> &StreamFlowControl {
        &self.flow_control
    }

    /// Get mutable flow control
    pub fn flow_control_mut(&mut self) -> &mut StreamFlowControl {
        &mut self.flow_control
    }

    /// Get priority
    pub fn priority(&self) -> u8 {
        self.priority
    }

    /// Set priority
    pub fn set_priority(&mut self, priority: u8) {
        self.priority = priority;
    }

    /// Queue data to send
    pub fn send(&mut self, data: &[u8]) -> QuicResult<()> {
        if !self.state.can_send() {
            return Err(QuicError::StreamClosed(self.id.id()));
        }

        // Check flow control
        let available = self.flow_control.send_window() as usize;
        if data.len() > available {
            return Err(QuicError::FlowControl(format!(
                "send window exceeded: {} > {}",
                data.len(),
                available
            )));
        }

        self.send_buffer.extend(data);
        self.flow_control.send(data.len() as u64)?;

        Ok(())
    }

    /// Get pending send data
    pub fn pending_send(&mut self, max_len: usize) -> Option<(u64, Vec<u8>)> {
        if self.send_buffer.is_empty() {
            return None;
        }

        let len = self.send_buffer.len().min(max_len);
        let data: Vec<u8> = self.send_buffer.drain(..len).collect();
        let offset = self.send_offset;
        self.send_offset += len as u64;

        Some((offset, data))
    }

    /// Check if has pending send data
    pub fn has_pending_send(&self) -> bool {
        !self.send_buffer.is_empty() || (self.fin_sent && !self.fin_received)
    }

    /// Receive data
    pub fn receive(&mut self, offset: u64, data: &[u8], is_fin: bool) -> QuicResult<()> {
        if !self.state.can_receive() {
            return Err(QuicError::StreamClosed(self.id.id()));
        }

        self.recv_buffer.insert(offset, data, is_fin)?;
        self.flow_control.consume(data.len() as u64)?;

        if is_fin {
            self.fin_received = true;
        }

        Ok(())
    }

    /// Read received data
    pub fn read(&mut self, buf: &mut [u8]) -> usize {
        self.recv_buffer.read(buf)
    }

    /// Check if receive is finished (FIN received and all data read)
    pub fn is_receive_finished(&self) -> bool {
        self.recv_buffer.is_finished()
    }

    /// Send FIN
    pub fn finish(&mut self) -> QuicResult<()> {
        if !self.state.can_send() {
            return Err(QuicError::StreamClosed(self.id.id()));
        }

        self.fin_sent = true;

        // Update state
        match self.state {
            StreamState::Ready | StreamState::SendOpen | StreamState::Open => {
                if self.fin_received {
                    self.state = StreamState::Closed;
                } else {
                    self.state = StreamState::HalfClosedLocal;
                }
            },
            StreamState::HalfClosedRemote => {
                self.state = StreamState::Closed;
            },
            _ => {},
        }

        Ok(())
    }

    /// Reset stream
    pub fn reset(&mut self, error_code: u64) {
        self.reset_code = Some(error_code);
        self.state = StreamState::Reset;
    }

    /// Get reset error code
    pub fn reset_code(&self) -> Option<u64> {
        self.reset_code
    }

    /// Check if FIN sent
    pub fn fin_sent(&self) -> bool {
        self.fin_sent
    }

    /// Check if FIN received
    pub fn fin_received(&self) -> bool {
        self.fin_received
    }
}

impl Read for Stream {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        let n = Stream::read(self, buf);
        if n == 0 && !buf.is_empty() {
            if self.is_receive_finished() {
                Ok(0) // EOF
            } else {
                Err(io::Error::new(
                    io::ErrorKind::WouldBlock,
                    "no data available",
                ))
            }
        } else {
            Ok(n)
        }
    }
}

impl Write for Stream {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        Stream::send(self, buf)
            .map(|_| buf.len())
            .map_err(|e| io::Error::other(e.to_string()))
    }

    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

impl std::fmt::Debug for Stream {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Stream")
            .field("id", &self.id)
            .field("type", &self.stream_type)
            .field("state", &self.state)
            .field("send_buffer_len", &self.send_buffer.len())
            .field("recv_buffer_len", &self.recv_buffer.len())
            .field("fin_sent", &self.fin_sent)
            .field("fin_received", &self.fin_received)
            .finish()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_stream_id_client_bidi() {
        let id = StreamId::client_bidi(0);
        assert!(id.is_client_initiated());
        assert!(id.is_bidirectional());
        assert_eq!(id.id(), 0);

        let id = StreamId::client_bidi(1);
        assert_eq!(id.id(), 4);
    }

    #[test]
    fn test_stream_id_server_bidi() {
        let id = StreamId::server_bidi(0);
        assert!(id.is_server_initiated());
        assert!(id.is_bidirectional());
        assert_eq!(id.id(), 1);
    }

    #[test]
    fn test_stream_id_client_uni() {
        let id = StreamId::client_uni(0);
        assert!(id.is_client_initiated());
        assert!(id.is_unidirectional());
        assert_eq!(id.id(), 2);
    }

    #[test]
    fn test_stream_id_server_uni() {
        let id = StreamId::server_uni(0);
        assert!(id.is_server_initiated());
        assert!(id.is_unidirectional());
        assert_eq!(id.id(), 3);
    }

    #[test]
    fn test_stream_id_next() {
        let id = StreamId::client_bidi(0);
        let next = id.next();
        assert_eq!(next.id(), 4);
        assert!(next.is_client_initiated());
        assert!(next.is_bidirectional());
    }

    #[test]
    fn test_stream_state() {
        assert!(StreamState::Ready.can_send());
        assert!(StreamState::Ready.can_receive());
        assert!(!StreamState::Closed.can_send());
        assert!(!StreamState::Closed.can_receive());
        assert!(StreamState::HalfClosedLocal.can_receive());
        assert!(!StreamState::HalfClosedLocal.can_send());
    }

    #[test]
    fn test_stream_buffer_insert_read() {
        let mut buf = StreamBuffer::new(1024);

        buf.insert(0, b"hello", false).unwrap();
        buf.insert(5, b" world", true).unwrap();

        let mut out = [0u8; 11];
        let n = buf.read(&mut out);
        assert_eq!(n, 11);
        assert_eq!(&out[..n], b"hello world");
        assert!(buf.is_finished());
    }

    #[test]
    fn test_stream_buffer_out_of_order() {
        let mut buf = StreamBuffer::new(1024);

        // Insert out of order
        buf.insert(5, b"world", false).unwrap();
        buf.insert(0, b"hello", false).unwrap();

        let mut out = [0u8; 10];
        let n = buf.read(&mut out);
        assert_eq!(n, 10);
        assert_eq!(&out[..n], b"helloworld");
    }

    #[test]
    fn test_stream_buffer_gap() {
        let mut buf = StreamBuffer::new(1024);

        buf.insert(0, b"hello", false).unwrap();
        buf.insert(10, b"world", false).unwrap(); // Gap at 5-9

        let mut out = [0u8; 20];
        let n = buf.read(&mut out);
        assert_eq!(n, 5); // Only "hello" is contiguous
        assert_eq!(&out[..n], b"hello");
    }

    #[test]
    fn test_stream_flow_control() {
        let mut fc = StreamFlowControl::new(1000, 1000);

        assert_eq!(fc.receive_window(), 1000);
        fc.consume(500).unwrap();
        assert_eq!(fc.receive_window(), 500);

        fc.send(300).unwrap();
        assert_eq!(fc.send_window(), 700);
    }

    #[test]
    fn test_stream_send_receive() {
        let id = StreamId::client_bidi(0);
        let mut stream = Stream::new(id, StreamType::Bidirectional);
        stream.set_state(StreamState::Open);

        // Send data
        stream.send(b"hello").unwrap();
        assert!(stream.has_pending_send());

        let (offset, data) = stream.pending_send(10).unwrap();
        assert_eq!(offset, 0);
        assert_eq!(&data, b"hello");

        // Receive data
        stream.receive(0, b"world", false).unwrap();
        let mut buf = [0u8; 10];
        let n = stream.read(&mut buf);
        assert_eq!(n, 5);
        assert_eq!(&buf[..n], b"world");
    }

    #[test]
    fn test_stream_finish() {
        let id = StreamId::client_bidi(0);
        let mut stream = Stream::new(id, StreamType::Bidirectional);
        stream.set_state(StreamState::Open);

        stream.finish().unwrap();
        assert!(stream.fin_sent());
        assert_eq!(stream.state(), StreamState::HalfClosedLocal);
    }

    #[test]
    fn test_stream_reset() {
        let id = StreamId::client_bidi(0);
        let mut stream = Stream::new(id, StreamType::Bidirectional);
        stream.set_state(StreamState::Open);

        stream.reset(0x01);
        assert!(stream.state().is_reset());
        assert_eq!(stream.reset_code(), Some(0x01));
    }
}
