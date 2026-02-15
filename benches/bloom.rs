//! Benchmarks for the bloom filter module.
//!
//! Run with: cargo bench --bench bloom

use criterion::{black_box, criterion_group, criterion_main, BenchmarkId, Criterion};
use fips::bloom::{BloomFilter, BloomState};
use fips::NodeAddr;
use std::collections::HashMap;

fn make_node_addr(val: u16) -> NodeAddr {
    let mut bytes = [0u8; 16];
    bytes[0..2].copy_from_slice(&val.to_le_bytes());
    NodeAddr::from_bytes(bytes)
}

/// Pre-populate a filter with `n` entries for realistic benchmarks.
fn populated_filter(n: u16) -> BloomFilter {
    let mut filter = BloomFilter::new();
    for i in 0..n {
        filter.insert(&make_node_addr(i));
    }
    filter
}

// ===== BloomFilter Benchmarks =====

fn bench_insert(c: &mut Criterion) {
    let mut group = c.benchmark_group("bloom_insert");

    let node = make_node_addr(9999);

    // Insert into empty filter
    group.bench_function("empty", |b| {
        b.iter(|| {
            let mut filter = BloomFilter::new();
            filter.insert(black_box(&node));
        })
    });

    // Insert into a filter with 400 entries (typical occupancy)
    let base = populated_filter(400);
    group.bench_function("400_entries", |b| {
        b.iter(|| {
            let mut filter = base.clone();
            filter.insert(black_box(&node));
        })
    });

    group.finish();
}

fn bench_contains(c: &mut Criterion) {
    let mut group = c.benchmark_group("bloom_contains");

    let present = make_node_addr(200);
    let absent = make_node_addr(9999);

    for &count in &[100, 400, 800] {
        let filter = populated_filter(count);

        group.bench_with_input(
            BenchmarkId::new("hit", count),
            &count,
            |b, _| {
                b.iter(|| filter.contains(black_box(&present)))
            },
        );

        group.bench_with_input(
            BenchmarkId::new("miss", count),
            &count,
            |b, _| {
                b.iter(|| filter.contains(black_box(&absent)))
            },
        );
    }

    group.finish();
}

fn bench_merge(c: &mut Criterion) {
    let mut group = c.benchmark_group("bloom_merge");

    for &count in &[100, 400, 800] {
        let filter_a = populated_filter(count);
        let filter_b = populated_filter(count + 500); // different entries

        group.bench_with_input(
            BenchmarkId::from_parameter(count),
            &count,
            |b, _| {
                b.iter(|| {
                    let mut target = filter_a.clone();
                    target.merge(black_box(&filter_b)).unwrap();
                })
            },
        );
    }

    group.finish();
}

fn bench_from_bytes(c: &mut Criterion) {
    let filter = populated_filter(400);
    let bytes = filter.as_bytes().to_vec();
    let hash_count = filter.hash_count();

    c.bench_function("bloom_from_bytes", |b| {
        b.iter(|| {
            BloomFilter::from_bytes(black_box(bytes.clone()), black_box(hash_count)).unwrap()
        })
    });
}

fn bench_fill_ratio(c: &mut Criterion) {
    let filter = populated_filter(400);

    c.bench_function("bloom_fill_ratio", |b| {
        b.iter(|| filter.fill_ratio())
    });
}

fn bench_estimated_count(c: &mut Criterion) {
    let filter = populated_filter(400);

    c.bench_function("bloom_estimated_count", |b| {
        b.iter(|| filter.estimated_count())
    });
}

fn bench_equality(c: &mut Criterion) {
    let mut group = c.benchmark_group("bloom_equality");

    let filter_a = populated_filter(400);
    let filter_b = filter_a.clone();
    let mut filter_c = filter_a.clone();
    filter_c.insert(&make_node_addr(9999));

    group.bench_function("equal", |b| {
        b.iter(|| black_box(&filter_a) == black_box(&filter_b))
    });

    group.bench_function("not_equal", |b| {
        b.iter(|| black_box(&filter_a) == black_box(&filter_c))
    });

    group.finish();
}

// ===== BloomState Benchmarks =====

fn bench_compute_outgoing_filter(c: &mut Criterion) {
    let mut group = c.benchmark_group("bloom_compute_outgoing");

    for &peer_count in &[2, 5, 10, 20] {
        let my_node = make_node_addr(0);
        let mut state = BloomState::new(my_node);
        state.add_leaf_dependent(make_node_addr(1));

        // Create peer filters with realistic content
        let mut peer_filters = HashMap::new();
        let mut peer_addrs = Vec::new();
        for i in 0..peer_count {
            let peer = make_node_addr(100 + i);
            peer_addrs.push(peer);
            let mut pf = BloomFilter::new();
            // Each peer knows about ~50 nodes
            for j in 0..50 {
                pf.insert(&make_node_addr(1000 + i * 50 + j));
            }
            peer_filters.insert(peer, pf);
        }

        let exclude = peer_addrs[0];

        group.bench_with_input(
            BenchmarkId::from_parameter(peer_count),
            &peer_count,
            |b, _| {
                b.iter(|| {
                    state.compute_outgoing_filter(
                        black_box(&exclude),
                        black_box(&peer_filters),
                    )
                })
            },
        );
    }

    group.finish();
}

fn bench_mark_changed_peers(c: &mut Criterion) {
    let mut group = c.benchmark_group("bloom_mark_changed_peers");

    for &peer_count in &[2, 5, 10, 20] {
        let my_node = make_node_addr(0);
        let mut state = BloomState::new(my_node);

        let mut peer_filters = HashMap::new();
        let mut peer_addrs = Vec::new();
        for i in 0..peer_count {
            let peer = make_node_addr(100 + i);
            peer_addrs.push(peer);
            let mut pf = BloomFilter::new();
            for j in 0..50 {
                pf.insert(&make_node_addr(1000 + i * 50 + j));
            }
            peer_filters.insert(peer, pf);
        }

        // Record initial outgoing filters so the benchmark measures
        // the change-detection comparison, not just "never sent"
        for &peer in &peer_addrs {
            let outgoing = state.compute_outgoing_filter(&peer, &peer_filters);
            state.record_sent_filter(peer, outgoing);
        }

        let source = peer_addrs[0];

        group.bench_with_input(
            BenchmarkId::new("steady_state", peer_count),
            &peer_count,
            |b, _| {
                b.iter(|| {
                    // Clone state so mark_changed_peers doesn't accumulate
                    let mut s = state.clone();
                    s.mark_changed_peers(
                        black_box(&source),
                        black_box(&peer_addrs),
                        black_box(&peer_filters),
                    );
                })
            },
        );
    }

    group.finish();
}

fn bench_base_filter(c: &mut Criterion) {
    let my_node = make_node_addr(0);
    let mut state = BloomState::new(my_node);
    for i in 1..=10 {
        state.add_leaf_dependent(make_node_addr(i));
    }

    c.bench_function("bloom_base_filter_10_deps", |b| {
        b.iter(|| state.base_filter())
    });
}

criterion_group!(
    benches,
    bench_insert,
    bench_contains,
    bench_merge,
    bench_from_bytes,
    bench_fill_ratio,
    bench_estimated_count,
    bench_equality,
    bench_compute_outgoing_filter,
    bench_mark_changed_peers,
    bench_base_filter,
);
criterion_main!(benches);
