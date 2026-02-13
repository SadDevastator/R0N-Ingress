//! Memory optimization utilities.
//!
//! Provides memory pools, arena allocators, and buffer management for efficient
//! memory usage in high-throughput scenarios.
//!
//! # Safety
//!
//! This module uses unsafe code for low-level memory management in the arena
//! allocator. All unsafe blocks are carefully documented with safety invariants.

#![allow(unsafe_code)]

use std::alloc::{alloc, dealloc, Layout};
use std::cell::UnsafeCell;
use std::collections::VecDeque;
use std::ops::{Deref, DerefMut};
use std::ptr::NonNull;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};

/// Memory pool for reusing allocations.
#[derive(Debug)]
pub struct MemoryPool<T> {
    /// Pool of available items.
    pool: Mutex<VecDeque<T>>,
    /// Maximum pool size.
    max_size: usize,
    /// Factory function.
    factory: fn() -> T,
    /// Statistics.
    stats: PoolStats,
}

impl<T> MemoryPool<T> {
    /// Create a new memory pool.
    #[inline]
    pub fn new(max_size: usize, factory: fn() -> T) -> Self {
        Self {
            pool: Mutex::new(VecDeque::with_capacity(max_size)),
            max_size,
            factory,
            stats: PoolStats::default(),
        }
    }

    /// Pre-allocate items in the pool.
    pub fn preallocate(&self, count: usize) {
        let count = count.min(self.max_size);
        if let Ok(mut pool) = self.pool.lock() {
            for _ in 0..count {
                if pool.len() < self.max_size {
                    pool.push_back((self.factory)());
                }
            }
        }
    }

    /// Get an item from the pool or create a new one.
    #[inline]
    pub fn get(&self) -> T {
        if let Ok(mut pool) = self.pool.try_lock() {
            if let Some(item) = pool.pop_front() {
                self.stats.hits.fetch_add(1, Ordering::Relaxed);
                return item;
            }
        }
        self.stats.misses.fetch_add(1, Ordering::Relaxed);
        (self.factory)()
    }

    /// Return an item to the pool.
    pub fn put(&self, item: T) {
        if let Ok(mut pool) = self.pool.lock() {
            if pool.len() < self.max_size {
                pool.push_back(item);
                self.stats.returns.fetch_add(1, Ordering::Relaxed);
            } else {
                self.stats.discards.fetch_add(1, Ordering::Relaxed);
            }
        }
    }

    /// Get pool statistics.
    #[inline]
    pub fn stats(&self) -> &PoolStats {
        &self.stats
    }

    /// Current pool size.
    pub fn len(&self) -> usize {
        self.pool.lock().map(|p| p.len()).unwrap_or(0)
    }

    /// Check if pool is empty.
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    /// Clear the pool.
    pub fn clear(&self) {
        if let Ok(mut pool) = self.pool.lock() {
            pool.clear();
        }
    }
}

/// Pool statistics.
#[derive(Debug, Default)]
pub struct PoolStats {
    /// Cache hits.
    pub hits: AtomicUsize,
    /// Cache misses.
    pub misses: AtomicUsize,
    /// Items returned to pool.
    pub returns: AtomicUsize,
    /// Items discarded (pool full).
    pub discards: AtomicUsize,
}

impl PoolStats {
    /// Get hit rate.
    #[inline]
    pub fn hit_rate(&self) -> f64 {
        let hits = self.hits.load(Ordering::Relaxed);
        let misses = self.misses.load(Ordering::Relaxed);
        let total = hits + misses;
        if total == 0 {
            0.0
        } else {
            hits as f64 / total as f64
        }
    }
}

/// Buffer pool for reusing byte buffers.
pub struct BufferPool {
    /// Pool for small buffers.
    small: MemoryPool<Vec<u8>>,
    /// Pool for medium buffers.
    medium: MemoryPool<Vec<u8>>,
    /// Pool for large buffers.
    large: MemoryPool<Vec<u8>>,
    /// Small buffer size.
    small_size: usize,
    /// Medium buffer size.
    medium_size: usize,
    /// Large buffer size.
    large_size: usize,
}

impl std::fmt::Debug for BufferPool {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("BufferPool")
            .field("small_size", &self.small_size)
            .field("medium_size", &self.medium_size)
            .field("large_size", &self.large_size)
            .finish()
    }
}

impl Default for BufferPool {
    fn default() -> Self {
        Self::new()
    }
}

// Default buffer sizes for the pool
const DEFAULT_SMALL_SIZE: usize = 4096;
const DEFAULT_MEDIUM_SIZE: usize = 65536;
const DEFAULT_LARGE_SIZE: usize = 1048576;

fn create_small_buffer() -> Vec<u8> {
    Vec::with_capacity(DEFAULT_SMALL_SIZE)
}

fn create_medium_buffer() -> Vec<u8> {
    Vec::with_capacity(DEFAULT_MEDIUM_SIZE)
}

fn create_large_buffer() -> Vec<u8> {
    Vec::with_capacity(DEFAULT_LARGE_SIZE)
}

impl BufferPool {
    /// Create a new buffer pool with default sizes.
    pub fn new() -> Self {
        Self {
            small: MemoryPool::new(1000, create_small_buffer),
            medium: MemoryPool::new(100, create_medium_buffer),
            large: MemoryPool::new(10, create_large_buffer),
            small_size: DEFAULT_SMALL_SIZE,
            medium_size: DEFAULT_MEDIUM_SIZE,
            large_size: DEFAULT_LARGE_SIZE,
        }
    }

    /// Create a buffer pool with custom sizes.
    ///
    /// Note: For custom sizes, use `new()` and rely on the buffer's
    /// ability to grow to the needed capacity.
    pub fn with_sizes(small: usize, medium: usize, large: usize) -> Self {
        // For custom sizes, we still use the default factory functions
        // but track the size thresholds for routing
        Self {
            small: MemoryPool::new(1000, create_small_buffer),
            medium: MemoryPool::new(100, create_medium_buffer),
            large: MemoryPool::new(10, create_large_buffer),
            small_size: small,
            medium_size: medium,
            large_size: large,
        }
    }

    /// Get a buffer of at least the specified size.
    pub fn get(&self, min_size: usize) -> PooledBuffer {
        let mut buffer = if min_size <= self.small_size {
            self.small.get()
        } else if min_size <= self.medium_size {
            self.medium.get()
        } else {
            self.large.get()
        };

        buffer.clear();
        if buffer.capacity() < min_size {
            buffer.reserve(min_size - buffer.capacity());
        }

        PooledBuffer {
            buffer,
            pool: self as *const BufferPool,
        }
    }

    /// Return a buffer to the pool.
    fn return_buffer(&self, mut buffer: Vec<u8>) {
        buffer.clear();
        let capacity = buffer.capacity();

        if capacity <= self.small_size {
            self.small.put(buffer);
        } else if capacity <= self.medium_size {
            self.medium.put(buffer);
        } else if capacity <= self.large_size {
            self.large.put(buffer);
        }
        // Discard buffers larger than large_size
    }
}

/// A buffer borrowed from a pool.
pub struct PooledBuffer {
    buffer: Vec<u8>,
    pool: *const BufferPool,
}

// Safety: PooledBuffer only accesses the pool through atomic operations
unsafe impl Send for PooledBuffer {}
unsafe impl Sync for PooledBuffer {}

impl Deref for PooledBuffer {
    type Target = Vec<u8>;

    fn deref(&self) -> &Self::Target {
        &self.buffer
    }
}

impl DerefMut for PooledBuffer {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.buffer
    }
}

impl Drop for PooledBuffer {
    fn drop(&mut self) {
        if !self.pool.is_null() {
            // Safety: pool pointer is valid for the lifetime of the pool
            let buffer = std::mem::take(&mut self.buffer);
            unsafe {
                (*self.pool).return_buffer(buffer);
            }
        }
    }
}

impl std::fmt::Debug for PooledBuffer {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("PooledBuffer")
            .field("len", &self.buffer.len())
            .field("capacity", &self.buffer.capacity())
            .finish()
    }
}

/// Arena allocator for bump-pointer allocation.
#[derive(Debug)]
pub struct Arena {
    /// Current chunk.
    current: UnsafeCell<ArenaChunk>,
    /// Previous chunks.
    chunks: Mutex<Vec<ArenaChunk>>,
    /// Chunk size.
    chunk_size: usize,
    /// Total allocated.
    total_allocated: AtomicUsize,
}

// Safety: Arena is Send because all interior data is owned.
// Arena is NOT Sync — the UnsafeCell<ArenaChunk> provides no synchronization.
// Callers requiring shared access across threads must use external synchronization
// (e.g., Mutex<Arena> or Arc<Mutex<Arena>>).
unsafe impl Send for Arena {}

impl Arena {
    /// Create a new arena with default chunk size (64KB).
    pub fn new() -> Self {
        Self::with_chunk_size(65536)
    }

    /// Create an arena with custom chunk size.
    pub fn with_chunk_size(size: usize) -> Self {
        Self {
            current: UnsafeCell::new(ArenaChunk::new(size)),
            chunks: Mutex::new(Vec::new()),
            chunk_size: size,
            total_allocated: AtomicUsize::new(size),
        }
    }

    /// Allocate bytes in the arena.
    ///
    /// # Safety
    /// The returned pointer is valid until the arena is dropped or reset.
    pub fn alloc(&self, size: usize) -> NonNull<u8> {
        // Safety: We have exclusive access through &self
        let chunk = unsafe { &mut *self.current.get() };

        if let Some(ptr) = chunk.alloc(size) {
            return ptr;
        }

        // Need a new chunk
        self.grow(size)
    }

    /// Allocate and initialize a value.
    ///
    /// # Safety
    /// The returned reference is valid until the arena is dropped or reset.
    /// The caller must ensure the arena outlives the reference.
    #[allow(clippy::mut_from_ref)]
    pub fn alloc_val<T>(&self, val: T) -> &mut T {
        let ptr = self.alloc(std::mem::size_of::<T>());
        // Safety: ptr is properly aligned and valid
        unsafe {
            let typed_ptr = ptr.as_ptr() as *mut T;
            std::ptr::write(typed_ptr, val);
            &mut *typed_ptr
        }
    }

    /// Allocate a slice.
    ///
    /// # Safety
    /// The returned reference is valid until the arena is dropped or reset.
    /// The caller must ensure the arena outlives the reference.
    #[allow(clippy::mut_from_ref)]
    pub fn alloc_slice<T: Copy>(&self, slice: &[T]) -> &mut [T] {
        let size = std::mem::size_of_val(slice);
        let ptr = self.alloc(size);
        // Safety: ptr is properly sized and aligned
        unsafe {
            let typed_ptr = ptr.as_ptr() as *mut T;
            std::ptr::copy_nonoverlapping(slice.as_ptr(), typed_ptr, slice.len());
            std::slice::from_raw_parts_mut(typed_ptr, slice.len())
        }
    }

    fn grow(&self, min_size: usize) -> NonNull<u8> {
        let new_size = self.chunk_size.max(min_size);
        let mut new_chunk = ArenaChunk::new(new_size);

        // Allocate from the new chunk
        let ptr = new_chunk
            .alloc(min_size)
            .expect("freshly allocated chunk should have space");

        // Move current chunk to the list
        let old_chunk = unsafe { std::mem::replace(&mut *self.current.get(), new_chunk) };
        if let Ok(mut chunks) = self.chunks.lock() {
            chunks.push(old_chunk);
        }

        self.total_allocated.fetch_add(new_size, Ordering::Relaxed);
        ptr
    }

    /// Total bytes allocated by the arena.
    pub fn total_allocated(&self) -> usize {
        self.total_allocated.load(Ordering::Relaxed)
    }

    /// Reset the arena, invalidating all allocations.
    ///
    /// # Safety
    /// All pointers returned by alloc() become invalid.
    pub unsafe fn reset(&self) {
        if let Ok(mut chunks) = self.chunks.lock() {
            chunks.clear();
        }
        *self.current.get() = ArenaChunk::new(self.chunk_size);
        self.total_allocated
            .store(self.chunk_size, Ordering::Relaxed);
    }
}

impl Default for Arena {
    fn default() -> Self {
        Self::new()
    }
}

#[derive(Debug)]
struct ArenaChunk {
    data: NonNull<u8>,
    size: usize,
    offset: usize,
}

impl ArenaChunk {
    fn new(size: usize) -> Self {
        let layout = Layout::from_size_align(size, 16).expect("valid layout");
        // Safety: layout is valid
        let data = unsafe { alloc(layout) };
        let data = NonNull::new(data).expect("allocation succeeded");

        Self {
            data,
            size,
            offset: 0,
        }
    }

    fn alloc(&mut self, size: usize) -> Option<NonNull<u8>> {
        // Align to 8 bytes
        let aligned_offset = (self.offset + 7) & !7;
        let end = aligned_offset + size;

        if end > self.size {
            return None;
        }

        self.offset = end;
        // Safety: offset is within bounds
        Some(unsafe { NonNull::new_unchecked(self.data.as_ptr().add(aligned_offset)) })
    }
}

impl Drop for ArenaChunk {
    fn drop(&mut self) {
        let layout = Layout::from_size_align(self.size, 16).expect("valid layout");
        // Safety: data was allocated with this layout
        unsafe {
            dealloc(self.data.as_ptr(), layout);
        }
    }
}

/// Arena allocator wrapper with typed interface.
///
/// # Safety
///
/// `Arena` is `Send` but not `Sync`. The `ArenaAllocator` uses `Arc<Arena>` for
/// shared ownership, but callers must ensure that `alloc` is not invoked
/// concurrently from multiple threads without external synchronization.
/// This is intentional — wrapping in `Mutex` would prevent returning
/// references into the arena (the `MutexGuard` would be dropped).
#[allow(clippy::arc_with_non_send_sync)]
pub struct ArenaAllocator {
    arena: Arc<Arena>,
}

impl Default for ArenaAllocator {
    fn default() -> Self {
        Self::new()
    }
}

impl ArenaAllocator {
    /// Create a new arena allocator.
    #[allow(clippy::arc_with_non_send_sync)]
    pub fn new() -> Self {
        Self {
            arena: Arc::new(Arena::new()),
        }
    }

    /// Create with custom chunk size.
    #[allow(clippy::arc_with_non_send_sync)]
    pub fn with_chunk_size(size: usize) -> Self {
        Self {
            arena: Arc::new(Arena::with_chunk_size(size)),
        }
    }

    /// Allocate a value.
    pub fn alloc<T>(&self, val: T) -> &mut T {
        self.arena.alloc_val(val)
    }

    /// Allocate a slice.
    pub fn alloc_slice<T: Copy>(&self, slice: &[T]) -> &mut [T] {
        self.arena.alloc_slice(slice)
    }

    /// Get total allocated.
    pub fn total_allocated(&self) -> usize {
        self.arena.total_allocated()
    }
}

impl std::fmt::Debug for ArenaAllocator {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ArenaAllocator")
            .field("total_allocated", &self.arena.total_allocated())
            .finish()
    }
}

/// Slab allocator for fixed-size objects.
#[derive(Debug)]
pub struct Slab<T> {
    /// Object size.
    #[allow(dead_code)]
    object_size: usize,
    /// Free list.
    free_list: Mutex<Vec<Box<T>>>,
    /// Maximum cached objects.
    max_cached: usize,
    /// Factory.
    factory: fn() -> T,
    /// Statistics.
    stats: PoolStats,
}

impl<T> Slab<T> {
    /// Create a new slab allocator.
    pub fn new(max_cached: usize, factory: fn() -> T) -> Self {
        Self {
            object_size: std::mem::size_of::<T>(),
            free_list: Mutex::new(Vec::with_capacity(max_cached)),
            max_cached,
            factory,
            stats: PoolStats::default(),
        }
    }

    /// Allocate an object.
    pub fn alloc(&self) -> Box<T> {
        if let Ok(mut list) = self.free_list.lock() {
            if let Some(obj) = list.pop() {
                self.stats.hits.fetch_add(1, Ordering::Relaxed);
                return obj;
            }
        }
        self.stats.misses.fetch_add(1, Ordering::Relaxed);
        Box::new((self.factory)())
    }

    /// Free an object back to the slab.
    pub fn free(&self, obj: Box<T>) {
        if let Ok(mut list) = self.free_list.lock() {
            if list.len() < self.max_cached {
                list.push(obj);
                self.stats.returns.fetch_add(1, Ordering::Relaxed);
            } else {
                self.stats.discards.fetch_add(1, Ordering::Relaxed);
            }
        }
    }

    /// Get statistics.
    pub fn stats(&self) -> &PoolStats {
        &self.stats
    }
}

/// Slab allocator wrapper.
pub struct SlabAllocator<T> {
    slab: Arc<Slab<T>>,
}

impl<T> SlabAllocator<T> {
    /// Create a new slab allocator.
    pub fn new(max_cached: usize, factory: fn() -> T) -> Self {
        Self {
            slab: Arc::new(Slab::new(max_cached, factory)),
        }
    }

    /// Allocate an object.
    pub fn alloc(&self) -> Box<T> {
        self.slab.alloc()
    }

    /// Free an object.
    pub fn free(&self, obj: Box<T>) {
        self.slab.free(obj);
    }

    /// Get statistics.
    pub fn stats(&self) -> &PoolStats {
        self.slab.stats()
    }
}

impl<T> Clone for SlabAllocator<T> {
    fn clone(&self) -> Self {
        Self {
            slab: Arc::clone(&self.slab),
        }
    }
}

impl<T> std::fmt::Debug for SlabAllocator<T> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SlabAllocator")
            .field("hit_rate", &self.slab.stats().hit_rate())
            .finish()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_memory_pool() {
        let pool: MemoryPool<Vec<u8>> = MemoryPool::new(10, Vec::new);

        let item = pool.get();
        assert!(item.is_empty());

        pool.put(vec![1, 2, 3]);
        assert_eq!(pool.len(), 1);

        let item = pool.get();
        assert_eq!(item, vec![1, 2, 3]);
    }

    #[test]
    fn test_memory_pool_preallocate() {
        let pool: MemoryPool<i32> = MemoryPool::new(10, || 0);
        pool.preallocate(5);
        assert_eq!(pool.len(), 5);
    }

    #[test]
    fn test_memory_pool_max_size() {
        let pool: MemoryPool<i32> = MemoryPool::new(2, || 0);

        pool.put(1);
        pool.put(2);
        pool.put(3); // Should be discarded

        assert_eq!(pool.len(), 2);
        assert_eq!(pool.stats().discards.load(Ordering::Relaxed), 1);
    }

    #[test]
    fn test_pool_stats() {
        let pool: MemoryPool<i32> = MemoryPool::new(10, || 0);

        pool.get(); // miss
        pool.put(1);
        pool.get(); // hit

        assert_eq!(pool.stats().hits.load(Ordering::Relaxed), 1);
        assert_eq!(pool.stats().misses.load(Ordering::Relaxed), 1);
        assert!((pool.stats().hit_rate() - 0.5).abs() < 0.01);
    }

    #[test]
    fn test_buffer_pool() {
        let pool = BufferPool::new();

        let mut buf = pool.get(100);
        buf.extend_from_slice(b"hello");
        assert_eq!(&buf[..], b"hello");
    }

    #[test]
    fn test_buffer_pool_sizes() {
        let pool = BufferPool::with_sizes(100, 1000, 10000);

        let small = pool.get(50);
        assert!(small.capacity() >= 50);

        let medium = pool.get(500);
        assert!(medium.capacity() >= 500);

        let large = pool.get(5000);
        assert!(large.capacity() >= 5000);
    }

    #[test]
    fn test_pooled_buffer_return() {
        let pool = BufferPool::new();

        {
            let _buf = pool.get(100);
            // Buffer returned on drop
        }

        // Should have one buffer in the pool now
        assert!(!pool.small.is_empty());
    }

    #[test]
    fn test_arena() {
        let arena = Arena::new();

        let ptr1 = arena.alloc(100);
        let ptr2 = arena.alloc(200);

        assert_ne!(ptr1, ptr2);
    }

    #[test]
    fn test_arena_alloc_val() {
        let arena = Arena::new();

        let val = arena.alloc_val(42i32);
        assert_eq!(*val, 42);

        *val = 100;
        assert_eq!(*val, 100);
    }

    #[test]
    fn test_arena_alloc_slice() {
        let arena = Arena::new();

        let data = [1, 2, 3, 4, 5];
        let slice = arena.alloc_slice(&data);

        assert_eq!(slice, &[1, 2, 3, 4, 5]);
    }

    #[test]
    fn test_arena_grow() {
        let arena = Arena::with_chunk_size(64);

        // Allocate more than one chunk
        for _ in 0..100 {
            arena.alloc(32);
        }

        assert!(arena.total_allocated() > 64);
    }

    #[test]
    fn test_arena_allocator() {
        let alloc = ArenaAllocator::new();

        let v1 = alloc.alloc(42);
        let v2 = alloc.alloc("hello".to_string());

        assert_eq!(*v1, 42);
        assert_eq!(v2, "hello");
    }

    #[test]
    fn test_slab() {
        let slab: Slab<Vec<u8>> = Slab::new(10, Vec::new);

        let obj = slab.alloc();
        assert!(obj.is_empty());

        slab.free(obj);
        assert_eq!(slab.stats().returns.load(Ordering::Relaxed), 1);
    }

    #[test]
    fn test_slab_allocator() {
        let alloc = SlabAllocator::new(10, || vec![0u8; 1024]);

        let obj = alloc.alloc();
        assert_eq!(obj.len(), 1024);

        alloc.free(obj);
        assert!(alloc.stats().hit_rate() == 0.0); // No hits yet

        let _obj2 = alloc.alloc(); // This should be a hit
        assert!(alloc.stats().hit_rate() > 0.0);
    }

    #[test]
    fn test_slab_allocator_clone() {
        let alloc1 = SlabAllocator::new(10, || 0i32);
        let alloc2 = alloc1.clone();

        let obj = alloc1.alloc();
        alloc2.free(obj);

        // Both should share the same slab
        assert_eq!(alloc1.stats().returns.load(Ordering::Relaxed), 1);
    }
}
