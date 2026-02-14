#![allow(clippy::all)]
//! Benchmarks for R0N-Ingress performance internals.
//!
//! Tests: MemoryPool, BufferPool (tiered allocation), Arena/Slab allocators,
//! ConnectionPool acquire/release, zero-copy SharedBuffer, BufferChain,
//! ReadBuffer/WriteBuffer, ByteCursor.

use criterion::{criterion_group, criterion_main, BenchmarkId, Criterion};
use r0n_ingress::perf::{
    Arena, ArenaAllocator, BufferChain, BufferPool, ByteCursor, ConnectionPool, IoVec, MemoryPool,
    PoolConfig, ReadBuffer, SharedBuffer, Slab, SlabAllocator, WriteBuffer, ZeroCopyRead,
};
use std::hint::black_box;

// ---------------------------------------------------------------------------
// MemoryPool<T>
// ---------------------------------------------------------------------------

fn bench_memory_pool(c: &mut Criterion) {
    let mut group = c.benchmark_group("perf/memory_pool");

    group.bench_function("get_put_vec", |b| {
        let pool = MemoryPool::new(1024, || Vec::<u8>::with_capacity(4096));
        pool.preallocate(100);
        b.iter(|| {
            let item = pool.get();
            black_box(&item);
            pool.put(item);
        });
    });

    group.bench_function("get_miss_create", |b| {
        let pool = MemoryPool::new(0, || Vec::<u8>::with_capacity(4096));
        b.iter(|| {
            let item = pool.get();
            black_box(&item);
        });
    });

    group.bench_function("preallocate", |b| {
        b.iter_with_setup(
            || MemoryPool::new(1024, || Vec::<u8>::with_capacity(4096)),
            |pool| {
                pool.preallocate(100);
                black_box(pool.len());
            },
        );
    });

    group.bench_function("stats_hit_rate", |b| {
        let pool = MemoryPool::new(1024, || Vec::<u8>::with_capacity(4096));
        pool.preallocate(10);
        for _ in 0..20 {
            let v = pool.get();
            pool.put(v);
        }
        b.iter(|| {
            black_box(pool.stats().hit_rate());
        });
    });

    group.finish();
}

// ---------------------------------------------------------------------------
// BufferPool (tiered)
// ---------------------------------------------------------------------------

fn bench_buffer_pool(c: &mut Criterion) {
    let mut group = c.benchmark_group("perf/buffer_pool");
    let pool = BufferPool::new();

    for size in [64, 512, 4096, 16384, 65536, 1048576] {
        group.bench_with_input(BenchmarkId::new("get_buffer", size), &size, |b, &size| {
            b.iter(|| {
                let buf = pool.get(size);
                black_box(&*buf);
            });
        });
    }

    group.bench_function("get_put_cycle_small", |b| {
        b.iter(|| {
            let buf = pool.get(64);
            black_box(&*buf);
            drop(buf); // auto-return
        });
    });

    group.bench_function("get_put_cycle_medium", |b| {
        b.iter(|| {
            let buf = pool.get(8192);
            black_box(&*buf);
            drop(buf);
        });
    });

    group.bench_function("get_put_cycle_large", |b| {
        b.iter(|| {
            let buf = pool.get(262144);
            black_box(&*buf);
            drop(buf);
        });
    });

    group.finish();
}

// ---------------------------------------------------------------------------
// Arena allocator
// ---------------------------------------------------------------------------

fn bench_arena(c: &mut Criterion) {
    let mut group = c.benchmark_group("perf/arena");

    group.bench_function("alloc_small", |b| {
        let arena = Arena::new();
        b.iter(|| {
            black_box(arena.alloc(64));
        });
    });

    group.bench_function("alloc_val_i64", |b| {
        let arena = Arena::new();
        b.iter(|| {
            black_box(arena.alloc_val(42i64));
        });
    });

    group.bench_function("alloc_slice_256", |b| {
        let arena = Arena::new();
        let data = [0u8; 256];
        b.iter(|| {
            black_box(arena.alloc_slice(&data));
        });
    });

    for size in [64, 256, 1024, 4096] {
        group.bench_with_input(BenchmarkId::new("alloc", size), &size, |b, &size| {
            let arena = Arena::new();
            b.iter(|| {
                black_box(arena.alloc(size));
            });
        });
    }

    group.bench_function("total_allocated", |b| {
        let arena = Arena::new();
        for _ in 0..100 {
            arena.alloc(256);
        }
        b.iter(|| {
            black_box(arena.total_allocated());
        });
    });

    group.bench_function("batch_alloc_1000", |b| {
        b.iter_with_setup(Arena::new, |arena| {
            for _ in 0..1000 {
                arena.alloc(128);
            }
            black_box(arena.total_allocated());
        });
    });

    group.finish();
}

fn bench_arena_allocator(c: &mut Criterion) {
    let mut group = c.benchmark_group("perf/arena_allocator");

    group.bench_function("alloc_i64", |b| {
        let alloc = ArenaAllocator::new();
        b.iter(|| {
            black_box(alloc.alloc(42i64));
        });
    });

    group.bench_function("alloc_string_like", |b| {
        let alloc = ArenaAllocator::new();
        let data = [b'x'; 128];
        b.iter(|| {
            black_box(alloc.alloc_slice(&data));
        });
    });

    group.finish();
}

// ---------------------------------------------------------------------------
// Slab allocator
// ---------------------------------------------------------------------------

fn bench_slab(c: &mut Criterion) {
    let mut group = c.benchmark_group("perf/slab");

    group.bench_function("alloc_free_cycle", |b| {
        let slab: Slab<Vec<u8>> = Slab::new(1024, || Vec::with_capacity(4096));
        b.iter(|| {
            let obj = slab.alloc();
            black_box(&*obj);
            slab.free(obj);
        });
    });

    group.bench_function("alloc_only", |b| {
        let slab: Slab<Vec<u8>> = Slab::new(1024, || Vec::with_capacity(4096));
        // Pre-populate
        let mut objs = Vec::new();
        for _ in 0..100 {
            objs.push(slab.alloc());
        }
        for obj in objs {
            slab.free(obj);
        }
        b.iter(|| {
            let obj = slab.alloc();
            black_box(&*obj);
            slab.free(obj);
        });
    });

    group.bench_function("slab_stats", |b| {
        let slab: Slab<Vec<u8>> = Slab::new(1024, || Vec::with_capacity(4096));
        b.iter(|| {
            black_box(slab.stats().hit_rate());
        });
    });

    group.finish();
}

fn bench_slab_allocator(c: &mut Criterion) {
    let mut group = c.benchmark_group("perf/slab_allocator");

    group.bench_function("alloc_free", |b| {
        let alloc: SlabAllocator<[u8; 256]> = SlabAllocator::new(512, || [0u8; 256]);
        b.iter(|| {
            let obj = alloc.alloc();
            black_box(&*obj);
            alloc.free(obj);
        });
    });

    group.finish();
}

// ---------------------------------------------------------------------------
// ConnectionPool
// ---------------------------------------------------------------------------

fn bench_connection_pool(c: &mut Criterion) {
    let mut group = c.benchmark_group("perf/connection_pool");

    group.bench_function("acquire_release", |b| {
        let config = PoolConfig::new().min_size(10).max_size(100);
        let pool = ConnectionPool::new(config, || Ok(42u64)).unwrap();
        b.iter(|| {
            let conn = pool.acquire().unwrap();
            black_box(*conn);
            drop(conn);
        });
    });

    group.bench_function("try_acquire", |b| {
        let config = PoolConfig::new().min_size(5).max_size(50);
        let pool = ConnectionPool::new(config, || Ok(99u64)).unwrap();
        b.iter(|| {
            if let Some(conn) = pool.try_acquire() {
                black_box(*conn);
            }
        });
    });

    group.bench_function("metrics", |b| {
        let config = PoolConfig::new().min_size(5).max_size(50);
        let pool = ConnectionPool::new(config, || Ok(0u64)).unwrap();
        b.iter(|| {
            let m = pool.metrics();
            black_box(m.utilization());
            black_box(m.avg_wait_time());
            black_box(m.success_rate());
        });
    });

    group.bench_function("size_available", |b| {
        let config = PoolConfig::new().min_size(10).max_size(100);
        let pool = ConnectionPool::new(config, || Ok(0u64)).unwrap();
        b.iter(|| {
            black_box(pool.size());
            black_box(pool.available());
        });
    });

    group.finish();
}

// ---------------------------------------------------------------------------
// SharedBuffer (zero-copy)
// ---------------------------------------------------------------------------

fn bench_shared_buffer(c: &mut Criterion) {
    let mut group = c.benchmark_group("perf/shared_buffer");

    group.bench_function("create_from_vec", |b| {
        b.iter(|| {
            let data = vec![0u8; 4096];
            black_box(SharedBuffer::new(data));
        });
    });

    group.bench_function("create_from_slice", |b| {
        let data = vec![0u8; 4096];
        b.iter(|| {
            black_box(SharedBuffer::from_slice(&data));
        });
    });

    group.bench_function("clone_zero_copy", |b| {
        let buf = SharedBuffer::new(vec![0u8; 65536]);
        b.iter(|| {
            black_box(buf.clone());
        });
    });

    group.bench_function("slice", |b| {
        let buf = SharedBuffer::new(vec![0u8; 4096]);
        b.iter(|| {
            black_box(buf.slice(100..200));
        });
    });

    group.bench_function("split_at", |b| {
        let buf = SharedBuffer::new(vec![0u8; 4096]);
        b.iter(|| {
            black_box(buf.split_at(2048));
        });
    });

    group.bench_function("ref_count", |b| {
        let buf = SharedBuffer::new(vec![0u8; 1024]);
        let _clone = buf.clone();
        b.iter(|| {
            black_box(buf.ref_count());
        });
    });

    group.bench_function("make_unique", |b| {
        b.iter_with_setup(
            || {
                let buf = SharedBuffer::new(vec![0u8; 4096]);
                let _keep = buf.clone();
                buf
            },
            |mut buf| {
                buf.make_unique();
                black_box(&buf);
            },
        );
    });

    group.finish();
}

// ---------------------------------------------------------------------------
// BufferChain
// ---------------------------------------------------------------------------

fn bench_buffer_chain(c: &mut Criterion) {
    let mut group = c.benchmark_group("perf/buffer_chain");

    group.bench_function("push_buffers", |b| {
        b.iter_with_setup(BufferChain::new, |mut chain| {
            for _ in 0..10 {
                chain.push(SharedBuffer::new(vec![0u8; 1024]));
            }
            black_box(chain.len());
        });
    });

    group.bench_function("push_slice", |b| {
        let data = vec![0u8; 1024];
        let mut chain = BufferChain::new();
        b.iter(|| {
            chain.push_slice(&data);
            if chain.buffer_count() > 100 {
                chain.clear();
            }
        });
    });

    for count in [2, 10, 50] {
        group.bench_with_input(BenchmarkId::new("flatten", count), &count, |b, &count| {
            let mut chain = BufferChain::new();
            for _ in 0..count {
                chain.push(SharedBuffer::new(vec![0u8; 1024]));
            }
            b.iter(|| {
                black_box(chain.flatten());
            });
        });
    }

    group.bench_function("get_element", |b| {
        let mut chain = BufferChain::new();
        for i in 0..10u8 {
            chain.push(SharedBuffer::new(vec![i; 1024]));
        }
        b.iter(|| {
            black_box(chain.get(5000));
        });
    });

    group.finish();
}

// ---------------------------------------------------------------------------
// IoVec
// ---------------------------------------------------------------------------

fn bench_iovec(c: &mut Criterion) {
    let mut group = c.benchmark_group("perf/iovec");

    group.bench_function("push_vecs", |b| {
        b.iter_with_setup(IoVec::new, |mut iov| {
            for _ in 0..10 {
                iov.push(vec![0u8; 1024]);
            }
            black_box(iov.len());
        });
    });

    group.bench_function("push_shared", |b| {
        b.iter_with_setup(IoVec::new, |mut iov| {
            for _ in 0..10 {
                iov.push_shared(SharedBuffer::new(vec![0u8; 1024]));
            }
            black_box(iov.len());
        });
    });

    group.finish();
}

// ---------------------------------------------------------------------------
// ReadBuffer / WriteBuffer
// ---------------------------------------------------------------------------

fn bench_read_buffer(c: &mut Criterion) {
    let mut group = c.benchmark_group("perf/read_buffer");

    group.bench_function("write_read_cycle", |b| {
        let mut rb = ReadBuffer::new(8192);
        b.iter(|| {
            let wbuf = rb.writable();
            let n = wbuf.len().min(1024);
            for i in 0..n {
                wbuf[i] = 0;
            }
            rb.advance_write(n);
            black_box(rb.readable());
            rb.advance_read(n);
        });
    });

    group.bench_function("compact", |b| {
        let mut rb = ReadBuffer::new(8192);
        // Fill partially
        let n = rb.writable().len().min(4096);
        rb.advance_write(n);
        rb.advance_read(n / 2);
        b.iter(|| {
            rb.compact();
            black_box(rb.readable_len());
        });
    });

    group.bench_function("zero_copy_read", |b| {
        let mut rb = ReadBuffer::new(8192);
        let n = rb.writable().len().min(4096);
        for i in 0..n {
            rb.writable()[i] = (i % 256) as u8;
        }
        rb.advance_write(n);
        b.iter(|| {
            black_box(rb.peek());
            if let Some(data) = rb.read_zero_copy(100) {
                black_box(data);
            }
        });
    });

    group.finish();
}

fn bench_write_buffer(c: &mut Criterion) {
    let mut group = c.benchmark_group("perf/write_buffer");

    group.bench_function("append_small", |b| {
        let mut wb = WriteBuffer::new(8192);
        let data = [0u8; 64];
        b.iter(|| {
            wb.append(&data);
            if wb.pending_len() > 4096 {
                wb.clear();
            }
        });
    });

    group.bench_function("append_large", |b| {
        let mut wb = WriteBuffer::new(65536);
        let data = [0u8; 4096];
        b.iter(|| {
            wb.append(&data);
            if wb.pending_len() > 32768 {
                wb.clear();
            }
        });
    });

    group.bench_function("pending_advance", |b| {
        let mut wb = WriteBuffer::new(8192);
        wb.append(&[0u8; 1024]);
        b.iter(|| {
            black_box(wb.pending());
            if wb.has_pending() {
                wb.advance(wb.pending_len().min(64));
            }
            if !wb.has_pending() {
                wb.append(&[0u8; 1024]);
            }
        });
    });

    group.finish();
}

// ---------------------------------------------------------------------------
// ByteCursor
// ---------------------------------------------------------------------------

fn bench_byte_cursor(c: &mut Criterion) {
    let mut group = c.benchmark_group("perf/byte_cursor");

    let data: Vec<u8> = (0..4096).map(|i| (i % 256) as u8).collect();

    group.bench_function("sequential_read_u8", |b| {
        b.iter(|| {
            let mut cursor = ByteCursor::new(&data);
            while cursor.read_u8().is_some() {}
            black_box(cursor.position());
        });
    });

    group.bench_function("read_slice", |b| {
        b.iter(|| {
            let mut cursor = ByteCursor::new(&data);
            while let Some(s) = cursor.read_slice(128) {
                black_box(s);
            }
        });
    });

    group.bench_function("read_until_newline", |b| {
        let mut data_with_newlines = Vec::new();
        for _ in 0..100 {
            data_with_newlines.extend_from_slice(b"some data here\n");
        }
        b.iter(|| {
            let mut cursor = ByteCursor::new(&data_with_newlines);
            while let Some(line) = cursor.read_until(b'\n') {
                black_box(line);
            }
        });
    });

    group.bench_function("peek_operations", |b| {
        let cursor = ByteCursor::new(&data);
        b.iter(|| {
            black_box(cursor.peek());
            black_box(cursor.peek_slice(16));
            black_box(cursor.remaining_len());
            black_box(cursor.is_empty());
        });
    });

    group.bench_function("seek", |b| {
        let mut cursor = ByteCursor::new(&data);
        b.iter(|| {
            cursor.seek(0);
            cursor.seek(2048);
            cursor.seek(4095);
            cursor.seek(0);
            black_box(cursor.position());
        });
    });

    group.finish();
}

// ---------------------------------------------------------------------------
// Heap vs Pool vs Arena comparison
// ---------------------------------------------------------------------------

fn bench_allocation_comparison(c: &mut Criterion) {
    let mut group = c.benchmark_group("perf/alloc_comparison");
    group.sample_size(1000);

    // Heap allocation
    group.bench_function("heap_alloc_4k", |b| {
        b.iter(|| {
            let v: Vec<u8> = Vec::with_capacity(4096);
            black_box(v);
        });
    });

    // Pool allocation
    group.bench_function("pool_alloc_4k", |b| {
        let pool = BufferPool::new();
        b.iter(|| {
            let buf = pool.get(4096);
            black_box(&*buf);
            drop(buf);
        });
    });

    // Arena allocation
    group.bench_function("arena_alloc_4k", |b| {
        let arena = Arena::new();
        b.iter(|| {
            let ptr = arena.alloc(4096);
            black_box(ptr);
        });
    });

    // Slab allocation
    group.bench_function("slab_alloc_4k", |b| {
        let slab: Slab<[u8; 4096]> = Slab::new(256, || [0u8; 4096]);
        b.iter(|| {
            let obj = slab.alloc();
            black_box(&*obj);
            slab.free(obj);
        });
    });

    group.finish();
}

criterion_group!(
    benches,
    bench_memory_pool,
    bench_buffer_pool,
    bench_arena,
    bench_arena_allocator,
    bench_slab,
    bench_slab_allocator,
    bench_connection_pool,
    bench_shared_buffer,
    bench_buffer_chain,
    bench_iovec,
    bench_read_buffer,
    bench_write_buffer,
    bench_byte_cursor,
    bench_allocation_comparison,
);
criterion_main!(benches);
