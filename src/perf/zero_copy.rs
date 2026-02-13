//! Zero-copy buffer utilities.
//!
//! Provides zero-copy data handling for efficient I/O operations,
//! reducing memory allocations and copies in high-throughput scenarios.

use std::io::{self, Read, Write};
use std::ops::{Deref, Range};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;

/// A reference-counted, zero-copy buffer.
#[derive(Debug, Clone)]
pub struct SharedBuffer {
    data: Arc<Vec<u8>>,
    range: Range<usize>,
}

impl SharedBuffer {
    /// Create a new shared buffer from data.
    #[inline]
    pub fn new(data: Vec<u8>) -> Self {
        let len = data.len();
        Self {
            data: Arc::new(data),
            range: 0..len,
        }
    }

    /// Create from a slice (copies the data).
    #[inline]
    pub fn from_slice(data: &[u8]) -> Self {
        Self::new(data.to_vec())
    }

    /// Create an empty buffer.
    pub fn empty() -> Self {
        Self::new(Vec::new())
    }

    /// Get a slice of this buffer.
    pub fn slice(&self, range: Range<usize>) -> Self {
        let start = self.range.start + range.start;
        let end = self.range.start + range.end.min(self.len());
        Self {
            data: Arc::clone(&self.data),
            range: start..end,
        }
    }

    /// Get the length of the visible data.
    #[inline]
    pub fn len(&self) -> usize {
        self.range.len()
    }

    /// Check if empty.
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    /// Get the data as a slice.
    #[inline]
    pub fn as_slice(&self) -> &[u8] {
        &self.data[self.range.clone()]
    }

    /// Split at a position.
    pub fn split_at(&self, mid: usize) -> (Self, Self) {
        let mid = mid.min(self.len());
        let left = self.slice(0..mid);
        let right = self.slice(mid..self.len());
        (left, right)
    }

    /// Get reference count.
    pub fn ref_count(&self) -> usize {
        Arc::strong_count(&self.data)
    }

    /// Make the buffer unique (copy if shared).
    pub fn make_unique(&mut self) {
        if Arc::strong_count(&self.data) > 1 {
            let data = self.as_slice().to_vec();
            let len = data.len();
            self.data = Arc::new(data);
            self.range = 0..len;
        }
    }
}

impl Deref for SharedBuffer {
    type Target = [u8];

    fn deref(&self) -> &Self::Target {
        self.as_slice()
    }
}

impl AsRef<[u8]> for SharedBuffer {
    fn as_ref(&self) -> &[u8] {
        self.as_slice()
    }
}

impl From<Vec<u8>> for SharedBuffer {
    fn from(data: Vec<u8>) -> Self {
        Self::new(data)
    }
}

impl From<&[u8]> for SharedBuffer {
    fn from(data: &[u8]) -> Self {
        Self::from_slice(data)
    }
}

/// A chain of buffers for scatter-gather I/O.
#[derive(Debug, Default)]
pub struct BufferChain {
    buffers: Vec<SharedBuffer>,
    total_len: usize,
}

impl BufferChain {
    /// Create an empty chain.
    pub fn new() -> Self {
        Self::default()
    }

    /// Create with capacity.
    pub fn with_capacity(capacity: usize) -> Self {
        Self {
            buffers: Vec::with_capacity(capacity),
            total_len: 0,
        }
    }

    /// Add a buffer to the chain.
    #[inline]
    pub fn push(&mut self, buffer: SharedBuffer) {
        self.total_len += buffer.len();
        self.buffers.push(buffer);
    }

    /// Add from a slice.
    pub fn push_slice(&mut self, data: &[u8]) {
        self.push(SharedBuffer::from_slice(data));
    }

    /// Get total length.
    #[inline]
    pub fn len(&self) -> usize {
        self.total_len
    }

    /// Check if empty.
    pub fn is_empty(&self) -> bool {
        self.total_len == 0
    }

    /// Number of buffers.
    pub fn buffer_count(&self) -> usize {
        self.buffers.len()
    }

    /// Iterate over buffers.
    pub fn buffers(&self) -> impl Iterator<Item = &SharedBuffer> {
        self.buffers.iter()
    }

    /// Flatten into a single buffer.
    pub fn flatten(&self) -> SharedBuffer {
        if self.buffers.len() == 1 {
            return self.buffers[0].clone();
        }

        let mut data = Vec::with_capacity(self.total_len);
        for buf in &self.buffers {
            data.extend_from_slice(buf.as_slice());
        }
        SharedBuffer::new(data)
    }

    /// Clear the chain.
    pub fn clear(&mut self) {
        self.buffers.clear();
        self.total_len = 0;
    }

    /// Get a byte at index.
    pub fn get(&self, index: usize) -> Option<u8> {
        if index >= self.total_len {
            return None;
        }

        let mut offset = 0;
        for buf in &self.buffers {
            if index < offset + buf.len() {
                return Some(buf[index - offset]);
            }
            offset += buf.len();
        }
        None
    }
}

impl FromIterator<SharedBuffer> for BufferChain {
    fn from_iter<T: IntoIterator<Item = SharedBuffer>>(iter: T) -> Self {
        let mut chain = Self::new();
        for buf in iter {
            chain.push(buf);
        }
        chain
    }
}

/// I/O vector for scatter-gather operations.
#[derive(Debug)]
pub struct IoVec {
    /// Vector of slices.
    slices: Vec<(Arc<Vec<u8>>, Range<usize>)>,
}

impl IoVec {
    /// Create a new I/O vector.
    pub fn new() -> Self {
        Self { slices: Vec::new() }
    }

    /// Create with capacity.
    pub fn with_capacity(capacity: usize) -> Self {
        Self {
            slices: Vec::with_capacity(capacity),
        }
    }

    /// Add a buffer.
    pub fn push(&mut self, data: Vec<u8>) {
        let len = data.len();
        self.slices.push((Arc::new(data), 0..len));
    }

    /// Add a shared buffer.
    pub fn push_shared(&mut self, buffer: SharedBuffer) {
        self.slices.push((buffer.data, buffer.range));
    }

    /// Total length.
    pub fn len(&self) -> usize {
        self.slices.iter().map(|(_, r)| r.len()).sum()
    }

    /// Check if empty.
    pub fn is_empty(&self) -> bool {
        self.slices.is_empty() || self.len() == 0
    }

    /// Number of slices.
    pub fn slice_count(&self) -> usize {
        self.slices.len()
    }

    /// Clear all slices.
    pub fn clear(&mut self) {
        self.slices.clear();
    }
}

impl Default for IoVec {
    fn default() -> Self {
        Self::new()
    }
}

/// Zero-copy read buffer.
pub struct ReadBuffer {
    data: Vec<u8>,
    read_pos: usize,
    write_pos: usize,
}

impl ReadBuffer {
    /// Create a new read buffer.
    pub fn new(capacity: usize) -> Self {
        Self {
            data: vec![0u8; capacity],
            read_pos: 0,
            write_pos: 0,
        }
    }

    /// Get available data for reading.
    pub fn readable(&self) -> &[u8] {
        &self.data[self.read_pos..self.write_pos]
    }

    /// Get available space for writing.
    pub fn writable(&mut self) -> &mut [u8] {
        &mut self.data[self.write_pos..]
    }

    /// Advance read position.
    pub fn advance_read(&mut self, n: usize) {
        self.read_pos = (self.read_pos + n).min(self.write_pos);

        // Compact if needed
        if self.read_pos == self.write_pos {
            self.read_pos = 0;
            self.write_pos = 0;
        }
    }

    /// Advance write position.
    pub fn advance_write(&mut self, n: usize) {
        self.write_pos = (self.write_pos + n).min(self.data.len());
    }

    /// Get readable length.
    pub fn readable_len(&self) -> usize {
        self.write_pos - self.read_pos
    }

    /// Get writable length.
    pub fn writable_len(&self) -> usize {
        self.data.len() - self.write_pos
    }

    /// Compact the buffer.
    pub fn compact(&mut self) {
        if self.read_pos > 0 {
            let len = self.readable_len();
            self.data.copy_within(self.read_pos..self.write_pos, 0);
            self.read_pos = 0;
            self.write_pos = len;
        }
    }

    /// Clear the buffer.
    pub fn clear(&mut self) {
        self.read_pos = 0;
        self.write_pos = 0;
    }

    /// Get capacity.
    pub fn capacity(&self) -> usize {
        self.data.len()
    }

    /// Ensure writable space.
    pub fn ensure_writable(&mut self, min_size: usize) {
        if self.writable_len() < min_size {
            self.compact();
            if self.writable_len() < min_size {
                let new_cap = (self.data.len() + min_size).next_power_of_two();
                self.data.resize(new_cap, 0);
            }
        }
    }
}

impl std::fmt::Debug for ReadBuffer {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ReadBuffer")
            .field("capacity", &self.capacity())
            .field("readable", &self.readable_len())
            .field("writable", &self.writable_len())
            .finish()
    }
}

/// Zero-copy write buffer.
pub struct WriteBuffer {
    data: Vec<u8>,
    written: usize,
}

impl WriteBuffer {
    /// Create a new write buffer.
    pub fn new(capacity: usize) -> Self {
        Self {
            data: Vec::with_capacity(capacity),
            written: 0,
        }
    }

    /// Get data ready for writing out.
    pub fn pending(&self) -> &[u8] {
        &self.data[self.written..]
    }

    /// Mark bytes as written.
    pub fn advance(&mut self, n: usize) {
        self.written = (self.written + n).min(self.data.len());

        // Clear if fully written
        if self.written == self.data.len() {
            self.data.clear();
            self.written = 0;
        }
    }

    /// Get pending length.
    pub fn pending_len(&self) -> usize {
        self.data.len() - self.written
    }

    /// Add data to the buffer.
    pub fn append(&mut self, data: &[u8]) {
        self.data.extend_from_slice(data);
    }

    /// Check if buffer has pending data.
    pub fn has_pending(&self) -> bool {
        self.pending_len() > 0
    }

    /// Clear the buffer.
    pub fn clear(&mut self) {
        self.data.clear();
        self.written = 0;
    }

    /// Get capacity.
    pub fn capacity(&self) -> usize {
        self.data.capacity()
    }
}

impl std::fmt::Debug for WriteBuffer {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("WriteBuffer")
            .field("capacity", &self.capacity())
            .field("pending", &self.pending_len())
            .finish()
    }
}

impl Write for WriteBuffer {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        self.append(buf);
        Ok(buf.len())
    }

    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

/// Zero-copy reader trait.
pub trait ZeroCopyRead {
    /// Get a reference to readable data without copying.
    fn peek(&self) -> &[u8];

    /// Consume bytes from the reader.
    fn consume(&mut self, n: usize);

    /// Read without copying.
    fn read_zero_copy(&mut self, len: usize) -> Option<&[u8]>;
}

/// Zero-copy writer trait.
pub trait ZeroCopyWrite {
    /// Get a mutable reference to writable space.
    fn reserve(&mut self, len: usize) -> &mut [u8];

    /// Commit written bytes.
    fn commit(&mut self, n: usize);
}

impl ZeroCopyRead for ReadBuffer {
    fn peek(&self) -> &[u8] {
        self.readable()
    }

    fn consume(&mut self, n: usize) {
        self.advance_read(n);
    }

    fn read_zero_copy(&mut self, len: usize) -> Option<&[u8]> {
        if self.readable_len() >= len {
            let data = &self.data[self.read_pos..self.read_pos + len];
            Some(data)
        } else {
            None
        }
    }
}

/// Byte cursor for zero-copy parsing.
pub struct ByteCursor<'a> {
    data: &'a [u8],
    pos: usize,
}

impl<'a> ByteCursor<'a> {
    /// Create a new cursor.
    pub fn new(data: &'a [u8]) -> Self {
        Self { data, pos: 0 }
    }

    /// Get current position.
    pub fn position(&self) -> usize {
        self.pos
    }

    /// Get remaining data.
    pub fn remaining(&self) -> &'a [u8] {
        &self.data[self.pos..]
    }

    /// Get remaining length.
    pub fn remaining_len(&self) -> usize {
        self.data.len() - self.pos
    }

    /// Check if at end.
    pub fn is_empty(&self) -> bool {
        self.pos >= self.data.len()
    }

    /// Peek at next byte.
    pub fn peek(&self) -> Option<u8> {
        self.data.get(self.pos).copied()
    }

    /// Peek at next n bytes.
    pub fn peek_slice(&self, n: usize) -> Option<&'a [u8]> {
        if self.pos + n <= self.data.len() {
            Some(&self.data[self.pos..self.pos + n])
        } else {
            None
        }
    }

    /// Read a byte.
    pub fn read_u8(&mut self) -> Option<u8> {
        let byte = self.data.get(self.pos).copied()?;
        self.pos += 1;
        Some(byte)
    }

    /// Read a slice.
    pub fn read_slice(&mut self, n: usize) -> Option<&'a [u8]> {
        if self.pos + n <= self.data.len() {
            let slice = &self.data[self.pos..self.pos + n];
            self.pos += n;
            Some(slice)
        } else {
            None
        }
    }

    /// Read until a delimiter.
    pub fn read_until(&mut self, delim: u8) -> Option<&'a [u8]> {
        let start = self.pos;
        while self.pos < self.data.len() {
            if self.data[self.pos] == delim {
                let slice = &self.data[start..self.pos];
                self.pos += 1; // Skip delimiter
                return Some(slice);
            }
            self.pos += 1;
        }
        None
    }

    /// Skip bytes.
    pub fn skip(&mut self, n: usize) {
        self.pos = (self.pos + n).min(self.data.len());
    }

    /// Seek to position.
    pub fn seek(&mut self, pos: usize) {
        self.pos = pos.min(self.data.len());
    }
}

impl<'a> Read for ByteCursor<'a> {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        let remaining = self.remaining();
        let n = buf.len().min(remaining.len());
        buf[..n].copy_from_slice(&remaining[..n]);
        self.pos += n;
        Ok(n)
    }
}

/// Statistics for zero-copy operations.
#[derive(Debug, Default)]
pub struct ZeroCopyStats {
    /// Bytes read without copying.
    pub bytes_read_zero_copy: AtomicUsize,
    /// Bytes copied.
    pub bytes_copied: AtomicUsize,
    /// Zero-copy reads.
    pub zero_copy_reads: AtomicUsize,
    /// Regular reads.
    pub regular_reads: AtomicUsize,
}

impl ZeroCopyStats {
    /// Get zero-copy rate.
    pub fn zero_copy_rate(&self) -> f64 {
        let zc = self.bytes_read_zero_copy.load(Ordering::Relaxed);
        let copied = self.bytes_copied.load(Ordering::Relaxed);
        let total = zc + copied;
        if total == 0 {
            1.0
        } else {
            zc as f64 / total as f64
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_shared_buffer() {
        let buf = SharedBuffer::new(vec![1, 2, 3, 4, 5]);
        assert_eq!(buf.len(), 5);
        assert_eq!(buf.as_slice(), &[1, 2, 3, 4, 5]);
    }

    #[test]
    fn test_shared_buffer_slice() {
        let buf = SharedBuffer::new(vec![1, 2, 3, 4, 5]);
        let slice = buf.slice(1..4);
        assert_eq!(slice.as_slice(), &[2, 3, 4]);
        assert_eq!(buf.ref_count(), 2);
    }

    #[test]
    fn test_shared_buffer_split() {
        let buf = SharedBuffer::new(vec![1, 2, 3, 4, 5]);
        let (left, right) = buf.split_at(3);
        assert_eq!(left.as_slice(), &[1, 2, 3]);
        assert_eq!(right.as_slice(), &[4, 5]);
    }

    #[test]
    fn test_shared_buffer_make_unique() {
        let buf = SharedBuffer::new(vec![1, 2, 3]);
        let mut buf2 = buf.clone();

        assert_eq!(buf.ref_count(), 2);

        buf2.make_unique();
        assert_eq!(buf.ref_count(), 1);
        assert_eq!(buf2.ref_count(), 1);
    }

    #[test]
    fn test_buffer_chain() {
        let mut chain = BufferChain::new();
        chain.push_slice(&[1, 2, 3]);
        chain.push_slice(&[4, 5]);

        assert_eq!(chain.len(), 5);
        assert_eq!(chain.buffer_count(), 2);
    }

    #[test]
    fn test_buffer_chain_flatten() {
        let mut chain = BufferChain::new();
        chain.push_slice(&[1, 2, 3]);
        chain.push_slice(&[4, 5]);

        let flat = chain.flatten();
        assert_eq!(flat.as_slice(), &[1, 2, 3, 4, 5]);
    }

    #[test]
    fn test_buffer_chain_get() {
        let mut chain = BufferChain::new();
        chain.push_slice(&[1, 2, 3]);
        chain.push_slice(&[4, 5]);

        assert_eq!(chain.get(0), Some(1));
        assert_eq!(chain.get(3), Some(4));
        assert_eq!(chain.get(5), None);
    }

    #[test]
    fn test_io_vec() {
        let mut iov = IoVec::new();
        iov.push(vec![1, 2, 3]);
        iov.push(vec![4, 5]);

        assert_eq!(iov.len(), 5);
        assert_eq!(iov.slice_count(), 2);
    }

    #[test]
    fn test_read_buffer() {
        let mut buf = ReadBuffer::new(1024);

        // Write some data
        let writable = buf.writable();
        writable[..5].copy_from_slice(&[1, 2, 3, 4, 5]);
        buf.advance_write(5);

        assert_eq!(buf.readable_len(), 5);
        assert_eq!(buf.readable(), &[1, 2, 3, 4, 5]);

        buf.advance_read(3);
        assert_eq!(buf.readable(), &[4, 5]);
    }

    #[test]
    fn test_read_buffer_compact() {
        let mut buf = ReadBuffer::new(10);

        let writable = buf.writable();
        writable[..5].copy_from_slice(&[1, 2, 3, 4, 5]);
        buf.advance_write(5);
        buf.advance_read(3);

        buf.compact();
        assert_eq!(buf.readable(), &[4, 5]);
        assert!(buf.writable_len() > 5);
    }

    #[test]
    fn test_read_buffer_ensure_writable() {
        let mut buf = ReadBuffer::new(8);

        let writable = buf.writable();
        writable[..5].copy_from_slice(&[1, 2, 3, 4, 5]);
        buf.advance_write(5);

        buf.ensure_writable(10);
        assert!(buf.writable_len() >= 10);
    }

    #[test]
    fn test_write_buffer() {
        let mut buf = WriteBuffer::new(1024);

        buf.append(&[1, 2, 3, 4, 5]);
        assert_eq!(buf.pending_len(), 5);
        assert_eq!(buf.pending(), &[1, 2, 3, 4, 5]);

        buf.advance(3);
        assert_eq!(buf.pending(), &[4, 5]);
    }

    #[test]
    fn test_write_buffer_write_trait() {
        let mut buf = WriteBuffer::new(1024);
        buf.write_all(&[1, 2, 3]).unwrap();
        assert_eq!(buf.pending(), &[1, 2, 3]);
    }

    #[test]
    fn test_byte_cursor() {
        let data = [1, 2, 3, 4, 5];
        let mut cursor = ByteCursor::new(&data);

        assert_eq!(cursor.peek(), Some(1));
        assert_eq!(cursor.read_u8(), Some(1));
        assert_eq!(cursor.position(), 1);
        assert_eq!(cursor.remaining(), &[2, 3, 4, 5]);
    }

    #[test]
    fn test_byte_cursor_read_slice() {
        let data = [1, 2, 3, 4, 5];
        let mut cursor = ByteCursor::new(&data);

        assert_eq!(cursor.read_slice(3), Some([1, 2, 3].as_slice()));
        assert_eq!(cursor.remaining(), &[4, 5]);
    }

    #[test]
    fn test_byte_cursor_read_until() {
        let data = b"hello\nworld";
        let mut cursor = ByteCursor::new(data);

        assert_eq!(cursor.read_until(b'\n'), Some(b"hello".as_slice()));
        assert_eq!(cursor.remaining(), b"world");
    }

    #[test]
    fn test_byte_cursor_seek() {
        let data = [1, 2, 3, 4, 5];
        let mut cursor = ByteCursor::new(&data);

        cursor.seek(3);
        assert_eq!(cursor.position(), 3);
        assert_eq!(cursor.peek(), Some(4));

        cursor.skip(10); // Should clamp
        assert!(cursor.is_empty());
    }

    #[test]
    fn test_zero_copy_stats() {
        let stats = ZeroCopyStats::default();

        stats.bytes_read_zero_copy.store(800, Ordering::Relaxed);
        stats.bytes_copied.store(200, Ordering::Relaxed);

        assert!((stats.zero_copy_rate() - 0.8).abs() < 0.01);
    }

    #[test]
    fn test_read_buffer_zero_copy_trait() {
        let mut buf = ReadBuffer::new(1024);

        let writable = buf.writable();
        writable[..5].copy_from_slice(&[1, 2, 3, 4, 5]);
        buf.advance_write(5);

        assert_eq!(buf.peek(), &[1, 2, 3, 4, 5]);

        let data = buf.read_zero_copy(3).unwrap();
        assert_eq!(data, &[1, 2, 3]);

        buf.consume(3);
        assert_eq!(buf.peek(), &[4, 5]);
    }
}
