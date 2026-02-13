//! End-to-end session establishment tests.

use super::*;
use crate::node::session::EndToEndState;
use crate::node::tests::spanning_tree::{
    cleanup_nodes, generate_random_edges, process_available_packets, run_tree_test,
    verify_tree_convergence, TestNode,
};
use crate::protocol::{SessionAck, SessionDatagram};

/// Populate all nodes' coordinate caches with each other's coords.
///
/// This enables routing between non-adjacent nodes (bloom filter + tree
/// routing both require cached destination coordinates).
fn populate_all_coord_caches(nodes: &mut [TestNode]) {
    let now_ms = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_millis() as u64;

    let all_coords: Vec<(NodeAddr, crate::tree::TreeCoordinate)> = nodes
        .iter()
        .map(|tn| {
            (
                *tn.node.node_addr(),
                tn.node.tree_state().my_coords().clone(),
            )
        })
        .collect();

    for tn in nodes.iter_mut() {
        for (addr, coords) in &all_coords {
            if addr != tn.node.node_addr() {
                tn.node
                    .coord_cache_mut()
                    .insert(*addr, coords.clone(), now_ms);
            }
        }
    }
}

// ============================================================================
// Unit tests: SessionEntry data structure
// ============================================================================

#[test]
fn test_session_entry_new_initiating() {
    use crate::noise::HandshakeState;

    let identity_a = Identity::generate();
    let identity_b = Identity::generate();

    let handshake = HandshakeState::new_initiator(
        identity_a.keypair(),
        identity_b.pubkey_full(),
    );

    let entry = crate::node::session::SessionEntry::new(
        *identity_b.node_addr(),
        identity_b.pubkey_full(),
        EndToEndState::Initiating(handshake),
        1000,
    );

    assert!(entry.state().is_initiating());
    assert!(!entry.state().is_established());
    assert!(!entry.state().is_responding());
    assert_eq!(entry.created_at(), 1000);
    assert_eq!(entry.last_activity(), 1000);
}

#[test]
fn test_session_entry_touch() {
    use crate::noise::HandshakeState;

    let identity_a = Identity::generate();
    let identity_b = Identity::generate();

    let handshake = HandshakeState::new_initiator(
        identity_a.keypair(),
        identity_b.pubkey_full(),
    );

    let mut entry = crate::node::session::SessionEntry::new(
        *identity_b.node_addr(),
        identity_b.pubkey_full(),
        EndToEndState::Initiating(handshake),
        1000,
    );

    entry.touch(2000);
    assert_eq!(entry.last_activity(), 2000);
    assert_eq!(entry.created_at(), 1000);
}

#[test]
fn test_session_table_operations() {
    use crate::noise::HandshakeState;

    let mut node = make_node();
    let identity_b = Identity::generate();

    let handshake = HandshakeState::new_initiator(
        node.identity().keypair(),
        identity_b.pubkey_full(),
    );

    let dest_addr = *identity_b.node_addr();
    let entry = crate::node::session::SessionEntry::new(
        dest_addr,
        identity_b.pubkey_full(),
        EndToEndState::Initiating(handshake),
        1000,
    );

    node.sessions.insert(dest_addr, entry);
    assert_eq!(node.session_count(), 1);
    assert!(node.get_session(&dest_addr).is_some());
    assert!(node.get_session(&make_node_addr(0xFF)).is_none());

    let removed = node.remove_session(&dest_addr);
    assert!(removed.is_some());
    assert_eq!(node.session_count(), 0);
}

// ============================================================================
// Integration tests: 2-node direct session establishment
// ============================================================================

#[tokio::test]
async fn test_session_direct_peer_handshake() {
    // Two directly connected nodes: A initiates a session with B
    let edges = vec![(0, 1)];
    let mut nodes = run_tree_test(2, &edges, false).await;
    verify_tree_convergence(&nodes);
    populate_all_coord_caches(&mut nodes);

    let node0_addr = *nodes[0].node.node_addr();
    let node1_addr = *nodes[1].node.node_addr();
    let node1_pubkey = nodes[1].node.identity().pubkey_full();

    // Node 0 initiates session with Node 1
    nodes[0]
        .node
        .initiate_session(node1_addr, node1_pubkey)
        .await
        .expect("initiate_session failed");

    // Node 0 should have a session in Initiating state
    assert_eq!(nodes[0].node.session_count(), 1);
    assert!(nodes[0]
        .node
        .get_session(&node1_addr)
        .unwrap()
        .state()
        .is_initiating());

    // Process packets: SessionSetup arrives at Node 1
    tokio::time::sleep(Duration::from_millis(20)).await;
    let count = process_available_packets(&mut nodes).await;
    assert!(count > 0, "Expected SessionSetup packet to arrive");

    // Node 1 should now have a session in Responding state
    assert_eq!(nodes[1].node.session_count(), 1);
    assert!(nodes[1]
        .node
        .get_session(&node0_addr)
        .unwrap()
        .state()
        .is_responding());

    // Process packets: SessionAck arrives at Node 0
    tokio::time::sleep(Duration::from_millis(20)).await;
    let count = process_available_packets(&mut nodes).await;
    assert!(count > 0, "Expected SessionAck packet to arrive");

    // Node 0 should now be Established
    assert!(nodes[0]
        .node
        .get_session(&node1_addr)
        .unwrap()
        .state()
        .is_established());

    cleanup_nodes(&mut nodes).await;
}

#[tokio::test]
async fn test_session_direct_peer_data_transfer() {
    // Two nodes: establish session, then send data
    let edges = vec![(0, 1)];
    let mut nodes = run_tree_test(2, &edges, false).await;
    verify_tree_convergence(&nodes);
    populate_all_coord_caches(&mut nodes);

    let node0_addr = *nodes[0].node.node_addr();
    let node1_addr = *nodes[1].node.node_addr();
    let node1_pubkey = nodes[1].node.identity().pubkey_full();

    // Establish session
    nodes[0]
        .node
        .initiate_session(node1_addr, node1_pubkey)
        .await
        .unwrap();
    tokio::time::sleep(Duration::from_millis(20)).await;
    process_available_packets(&mut nodes).await; // Setup → Node 1
    tokio::time::sleep(Duration::from_millis(20)).await;
    process_available_packets(&mut nodes).await; // Ack → Node 0

    assert!(nodes[0]
        .node
        .get_session(&node1_addr)
        .unwrap()
        .state()
        .is_established());

    // Send data from Node 0 to Node 1
    let test_data = b"Hello, FIPS session!";
    nodes[0]
        .node
        .send_session_data(&node1_addr, test_data)
        .await
        .expect("send_session_data failed");

    // Process packets: DataPacket arrives at Node 1
    tokio::time::sleep(Duration::from_millis(20)).await;
    let count = process_available_packets(&mut nodes).await;
    assert!(count > 0, "Expected DataPacket to arrive");

    // Node 1's session should now be Established (was Responding, transitions on first data)
    assert!(nodes[1]
        .node
        .get_session(&node0_addr)
        .unwrap()
        .state()
        .is_established());

    cleanup_nodes(&mut nodes).await;
}

// ============================================================================
// Integration tests: 3-node forwarded session
// ============================================================================

#[tokio::test]
async fn test_session_3node_forwarded_handshake() {
    // A—B—C: Node A initiates session with Node C through transit node B
    let edges = vec![(0, 1), (1, 2)];
    let mut nodes = run_tree_test(3, &edges, false).await;
    verify_tree_convergence(&nodes);
    populate_all_coord_caches(&mut nodes);

    let node0_addr = *nodes[0].node.node_addr();
    let node2_addr = *nodes[2].node.node_addr();
    let node2_pubkey = nodes[2].node.identity().pubkey_full();

    // Node 0 initiates session with Node 2
    nodes[0]
        .node
        .initiate_session(node2_addr, node2_pubkey)
        .await
        .expect("initiate_session failed");

    // Process: SessionSetup: 0→1 (forwarded by transit B)
    tokio::time::sleep(Duration::from_millis(20)).await;
    process_available_packets(&mut nodes).await;

    // Process: SessionSetup: 1→2 (arrives at destination C)
    tokio::time::sleep(Duration::from_millis(20)).await;
    process_available_packets(&mut nodes).await;

    // Node 2 should have a Responding session
    assert!(
        nodes[2].node.get_session(&node0_addr).is_some(),
        "Node 2 should have a session entry for Node 0"
    );
    assert!(nodes[2]
        .node
        .get_session(&node0_addr)
        .unwrap()
        .state()
        .is_responding());

    // Process: SessionAck: 2→1 (forwarded by transit B)
    tokio::time::sleep(Duration::from_millis(20)).await;
    process_available_packets(&mut nodes).await;

    // Process: SessionAck: 1→0 (arrives at initiator A)
    tokio::time::sleep(Duration::from_millis(20)).await;
    process_available_packets(&mut nodes).await;

    // Node 0 should now be Established
    assert!(nodes[0]
        .node
        .get_session(&node2_addr)
        .unwrap()
        .state()
        .is_established());

    // Transit node B should NOT have a session
    assert_eq!(
        nodes[1].node.session_count(),
        0,
        "Transit node should have no sessions"
    );

    cleanup_nodes(&mut nodes).await;
}

#[tokio::test]
async fn test_session_3node_forwarded_data() {
    // A—B—C: Establish session, send data end-to-end
    let edges = vec![(0, 1), (1, 2)];
    let mut nodes = run_tree_test(3, &edges, false).await;
    verify_tree_convergence(&nodes);
    populate_all_coord_caches(&mut nodes);

    let node0_addr = *nodes[0].node.node_addr();
    let node2_addr = *nodes[2].node.node_addr();
    let node2_pubkey = nodes[2].node.identity().pubkey_full();

    // Establish session (needs more hops)
    nodes[0]
        .node
        .initiate_session(node2_addr, node2_pubkey)
        .await
        .unwrap();

    // Drain packets until handshake completes (multi-hop needs several rounds)
    for _ in 0..10 {
        tokio::time::sleep(Duration::from_millis(20)).await;
        process_available_packets(&mut nodes).await;
    }

    assert!(
        nodes[0]
            .node
            .get_session(&node2_addr)
            .map(|s| s.state().is_established())
            .unwrap_or(false),
        "Session should be established after handshake rounds"
    );

    // Send data
    let test_data = b"End-to-end through transit node B";
    nodes[0]
        .node
        .send_session_data(&node2_addr, test_data)
        .await
        .expect("send_session_data failed");

    // Drain data packet through transit node
    for _ in 0..5 {
        tokio::time::sleep(Duration::from_millis(20)).await;
        process_available_packets(&mut nodes).await;
    }

    // Node 2 should have transitioned to Established on first data
    assert!(nodes[2]
        .node
        .get_session(&node0_addr)
        .unwrap()
        .state()
        .is_established());

    cleanup_nodes(&mut nodes).await;
}

// ============================================================================
// Edge cases
// ============================================================================

#[tokio::test]
async fn test_session_initiate_idempotent() {
    // Calling initiate_session twice should be idempotent
    let edges = vec![(0, 1)];
    let mut nodes = run_tree_test(2, &edges, false).await;
    verify_tree_convergence(&nodes);
    populate_all_coord_caches(&mut nodes);

    let node1_addr = *nodes[1].node.node_addr();
    let node1_pubkey = nodes[1].node.identity().pubkey_full();

    // First call
    nodes[0]
        .node
        .initiate_session(node1_addr, node1_pubkey)
        .await
        .unwrap();
    assert_eq!(nodes[0].node.session_count(), 1);

    // Second call should be a no-op
    nodes[0]
        .node
        .initiate_session(node1_addr, node1_pubkey)
        .await
        .unwrap();
    assert_eq!(nodes[0].node.session_count(), 1);

    cleanup_nodes(&mut nodes).await;
}

#[tokio::test]
async fn test_session_send_data_no_session_fails() {
    let mut node = make_node();
    let fake_addr = make_node_addr(0xAA);

    let result = node.send_session_data(&fake_addr, b"test").await;
    assert!(result.is_err(), "Should fail with no session");
}

#[tokio::test]
async fn test_session_ack_for_unknown_session() {
    // Receiving a SessionAck when we have no Initiating session should be dropped
    let edges = vec![(0, 1)];
    let mut nodes = run_tree_test(2, &edges, false).await;
    verify_tree_convergence(&nodes);

    let node0_addr = *nodes[0].node.node_addr();
    let node1_addr = *nodes[1].node.node_addr();

    // Fabricate a SessionAck and deliver directly
    let coords = nodes[1].node.tree_state().my_coords().clone();
    let ack = SessionAck::new(coords).with_handshake(vec![0u8; 33]);
    let datagram = SessionDatagram::new(node1_addr, node0_addr, ack.encode());

    // Send through link layer
    let encoded = datagram.encode();
    nodes[1]
        .node
        .send_encrypted_link_message(&node0_addr, &encoded)
        .await
        .unwrap();

    tokio::time::sleep(Duration::from_millis(20)).await;
    process_available_packets(&mut nodes).await;

    // Node 0 should have no sessions (ack was for unknown session)
    assert_eq!(nodes[0].node.session_count(), 0);

    cleanup_nodes(&mut nodes).await;
}

// ============================================================================
// Large-scale test: 100-node session establishment + bidirectional data
// ============================================================================

/// Drain packets until quiescent (2 consecutive idle rounds).
async fn drain_to_quiescence(nodes: &mut [TestNode]) {
    let mut idle_rounds = 0;
    for _ in 0..40 {
        tokio::time::sleep(Duration::from_millis(10)).await;
        let count = process_available_packets(nodes).await;
        if count == 0 {
            idle_rounds += 1;
            if idle_rounds >= 2 {
                break;
            }
        } else {
            idle_rounds = 0;
        }
    }
}

#[tokio::test]
async fn test_session_100_nodes() {
    use rand::rngs::StdRng;
    use rand::{Rng, SeedableRng};
    use std::sync::mpsc;
    use std::time::Instant;

    // Same random topology as other 100-node tests
    const NUM_NODES: usize = 100;
    const TARGET_EDGES: usize = 250;
    const SEED: u64 = 42;

    let start = Instant::now();

    let edges = generate_random_edges(NUM_NODES, TARGET_EDGES, SEED);
    let mut nodes = run_tree_test(NUM_NODES, &edges, false).await;
    verify_tree_convergence(&nodes);
    populate_all_coord_caches(&mut nodes);

    let setup_time = start.elapsed();

    // Collect identities: (node_addr, pubkey) for all nodes
    let all_info: Vec<(NodeAddr, secp256k1::PublicKey)> = nodes
        .iter()
        .map(|tn| {
            (
                *tn.node.node_addr(),
                tn.node.identity().pubkey_full(),
            )
        })
        .collect();

    // Each node picks one random target for its outbound session.
    // Use deterministic RNG so failures are reproducible.
    let mut rng = StdRng::seed_from_u64(SEED + 1);
    let mut session_pairs: Vec<(usize, usize)> = Vec::with_capacity(NUM_NODES);
    for src in 0..NUM_NODES {
        let mut dst = rng.gen_range(0..NUM_NODES);
        while dst == src {
            dst = rng.gen_range(0..NUM_NODES);
        }
        session_pairs.push((src, dst));
    }

    // === Phase 1: Establish all sessions ===

    let session_start = Instant::now();

    for &(src, dst) in &session_pairs {
        let (dest_addr, dest_pubkey) = all_info[dst];

        nodes[src]
            .node
            .initiate_session(dest_addr, dest_pubkey)
            .await
            .expect("initiate_session failed");

        drain_to_quiescence(&mut nodes).await;
    }

    drain_to_quiescence(&mut nodes).await;
    let session_time = session_start.elapsed();

    // Verify all initiator sessions reached Established before data phase
    let mut handshake_failures: Vec<(usize, usize)> = Vec::new();
    for &(src, dst) in &session_pairs {
        let dest_addr = all_info[dst].0;
        let ok = nodes[src]
            .node
            .get_session(&dest_addr)
            .map(|e| e.state().is_established())
            .unwrap_or(false);
        if !ok {
            handshake_failures.push((src, dst));
        }
    }
    assert!(
        handshake_failures.is_empty(),
        "Handshake failed for {} pairs (first: {:?})",
        handshake_failures.len(),
        handshake_failures.first()
    );

    // === Phase 2: Inject TUN receivers and snapshot link stats ===

    // Install a tun_tx on every node so delivered datagrams can be counted.
    let mut tun_receivers: Vec<mpsc::Receiver<Vec<u8>>> = Vec::with_capacity(NUM_NODES);
    for tn in nodes.iter_mut() {
        let (tx, rx) = mpsc::channel();
        tn.node.tun_tx = Some(tx);
        tun_receivers.push(rx);
    }

    // Snapshot per-peer link stats before data phase
    let link_pkts_sent_before: Vec<Vec<(NodeAddr, u64)>> = nodes
        .iter()
        .map(|tn| {
            tn.node
                .peers()
                .map(|p| (*p.node_addr(), p.link_stats().packets_sent))
                .collect()
        })
        .collect();

    // === Phase 3: Bidirectional data transfer ===
    //
    // For each session pair:
    //   1. Initiator sends one datagram to responder
    //      (this also transitions responder from Responding → Established)
    //   2. Responder sends one datagram back to initiator
    //
    // Batched per pair with draining between each.

    let data_start = Instant::now();
    let mut send_forward_ok = 0usize;
    let mut send_forward_err = 0usize;
    let mut send_reverse_ok = 0usize;
    let mut send_reverse_err = 0usize;

    for (pair_idx, &(src, dst)) in session_pairs.iter().enumerate() {
        let dest_addr = all_info[dst].0;
        let src_addr = all_info[src].0;

        // Forward: initiator → responder
        let fwd_payload = format!("fwd-{}", pair_idx).into_bytes();
        match nodes[src]
            .node
            .send_session_data(&dest_addr, &fwd_payload)
            .await
        {
            Ok(()) => send_forward_ok += 1,
            Err(_) => send_forward_err += 1,
        }

        drain_to_quiescence(&mut nodes).await;

        // Reverse: responder → initiator
        // (Responder should now be Established after receiving the forward datagram)
        let rev_payload = format!("rev-{}", pair_idx).into_bytes();
        match nodes[dst]
            .node
            .send_session_data(&src_addr, &rev_payload)
            .await
        {
            Ok(()) => send_reverse_ok += 1,
            Err(_) => send_reverse_err += 1,
        }

        drain_to_quiescence(&mut nodes).await;
    }

    let data_time = data_start.elapsed();

    // === Phase 4: Collect delivered datagrams from TUN receivers ===

    let mut delivered_per_node: Vec<Vec<Vec<u8>>> = Vec::with_capacity(NUM_NODES);
    for rx in tun_receivers.iter_mut() {
        let mut packets = Vec::new();
        while let Ok(pkt) = rx.try_recv() {
            packets.push(pkt);
        }
        delivered_per_node.push(packets);
    }

    let total_delivered: usize = delivered_per_node.iter().map(|v| v.len()).sum();

    // Verify each pair's forward and reverse datagrams arrived
    let mut fwd_delivered = 0usize;
    let mut rev_delivered = 0usize;
    let mut fwd_missing: Vec<(usize, usize)> = Vec::new();
    let mut rev_missing: Vec<(usize, usize)> = Vec::new();

    for (pair_idx, &(src, dst)) in session_pairs.iter().enumerate() {
        let fwd_payload = format!("fwd-{}", pair_idx).into_bytes();
        let rev_payload = format!("rev-{}", pair_idx).into_bytes();

        if delivered_per_node[dst].iter().any(|p| *p == fwd_payload) {
            fwd_delivered += 1;
        } else if fwd_missing.len() < 20 {
            fwd_missing.push((src, dst));
        }

        if delivered_per_node[src].iter().any(|p| *p == rev_payload) {
            rev_delivered += 1;
        } else if rev_missing.len() < 20 {
            rev_missing.push((src, dst));
        }
    }

    // === Phase 5: Final session state ===

    let mut total_established = 0usize;
    let mut total_responding = 0usize;
    let mut total_initiating = 0usize;
    let mut fully_established_nodes = 0usize;

    for tn in &nodes {
        let mut all_est = true;
        for (_, entry) in tn.node.sessions.iter() {
            if entry.state().is_established() {
                total_established += 1;
            } else if entry.state().is_responding() {
                total_responding += 1;
                all_est = false;
            } else {
                total_initiating += 1;
                all_est = false;
            }
        }
        if tn.node.session_count() > 0 && all_est {
            fully_established_nodes += 1;
        }
    }

    let session_counts: Vec<usize> = nodes
        .iter()
        .map(|tn| tn.node.session_count())
        .collect();
    let total_sessions: usize = session_counts.iter().sum();
    let min_sessions = *session_counts.iter().min().unwrap();
    let max_sessions = *session_counts.iter().max().unwrap();

    // === Phase 6: Link and routing statistics ===

    // Link stats delta: packets sent during data phase
    let mut data_link_pkts_sent: u64 = 0;
    let mut total_link_pkts_sent: u64 = 0;
    let mut total_link_pkts_recv: u64 = 0;
    let mut total_link_bytes_sent: u64 = 0;
    let mut total_link_bytes_recv: u64 = 0;

    for (i, tn) in nodes.iter().enumerate() {
        for peer in tn.node.peers() {
            let stats = peer.link_stats();
            // Delta for this peer since before data phase
            let before = link_pkts_sent_before[i]
                .iter()
                .find(|(addr, _)| addr == peer.node_addr())
                .map(|(_, pkts)| *pkts)
                .unwrap_or(0);
            data_link_pkts_sent += stats.packets_sent.saturating_sub(before);

            // Totals (cumulative since node creation)
            total_link_pkts_sent += stats.packets_sent;
            total_link_pkts_recv += stats.packets_recv;
            total_link_bytes_sent += stats.bytes_sent;
            total_link_bytes_recv += stats.bytes_recv;
        }
    }

    // Estimate average hop count from link packet overhead.
    // Each data datagram traverses N link hops, each producing 1 link send.
    // We sent 200 datagrams total (100 forward + 100 reverse).
    let total_data_datagrams = (send_forward_ok + send_reverse_ok) as u64;
    let avg_hops = if total_data_datagrams > 0 {
        data_link_pkts_sent as f64 / total_data_datagrams as f64
    } else {
        0.0
    };

    // Coord cache stats
    let coord_cache_sizes: Vec<usize> = nodes
        .iter()
        .map(|tn| tn.node.coord_cache().len())
        .collect();
    let total_coord_entries: usize = coord_cache_sizes.iter().sum();
    let min_coord = *coord_cache_sizes.iter().min().unwrap();
    let max_coord = *coord_cache_sizes.iter().max().unwrap();

    let route_cache_sizes: Vec<usize> = nodes
        .iter()
        .map(|tn| tn.node.route_cache().len())
        .collect();
    let total_route_entries: usize = route_cache_sizes.iter().sum();

    // === Report ===

    eprintln!("\n  === Session 100-Node Test ===");
    eprintln!(
        "  Topology: {} nodes, {} edges (seed {})",
        NUM_NODES,
        edges.len(),
        SEED
    );
    eprintln!(
        "  Session pairs: {} (1 outbound per node, random target)",
        session_pairs.len()
    );

    eprintln!("\n  --- Handshake ---");
    eprintln!(
        "  Initiator established: {}/{}",
        session_pairs.len(),
        session_pairs.len()
    );

    eprintln!("\n  --- Data Transfer ---");
    eprintln!(
        "  Forward (initiator->responder): {} sent, {} errors",
        send_forward_ok, send_forward_err
    );
    eprintln!(
        "  Reverse (responder->initiator): {} sent, {} errors",
        send_reverse_ok, send_reverse_err
    );
    eprintln!(
        "  TUN delivery: {} total ({} expected)",
        total_delivered,
        send_forward_ok + send_reverse_ok
    );
    eprintln!(
        "  Forward delivered: {}/{} | Reverse delivered: {}/{}",
        fwd_delivered, send_forward_ok, rev_delivered, send_reverse_ok
    );

    eprintln!("\n  --- Final Session State ---");
    eprintln!(
        "  Entries: {} total ({} established, {} responding, {} initiating)",
        total_sessions, total_established, total_responding, total_initiating
    );
    eprintln!(
        "  Per node: min={} max={} avg={:.1}",
        min_sessions,
        max_sessions,
        total_sessions as f64 / NUM_NODES as f64
    );
    eprintln!(
        "  All-established nodes: {}/{}",
        fully_established_nodes, NUM_NODES
    );

    eprintln!("\n  --- Routing ---");
    eprintln!(
        "  Data-phase link hops: {} ({:.1} avg hops/datagram over {} datagrams)",
        data_link_pkts_sent, avg_hops, total_data_datagrams
    );
    eprintln!(
        "  Lifetime link totals: {} pkts sent, {} pkts recv, {:.1} KB sent, {:.1} KB recv",
        total_link_pkts_sent,
        total_link_pkts_recv,
        total_link_bytes_sent as f64 / 1024.0,
        total_link_bytes_recv as f64 / 1024.0
    );
    eprintln!(
        "  Coord cache: total={} min={} max={} avg={:.1}",
        total_coord_entries,
        min_coord,
        max_coord,
        total_coord_entries as f64 / NUM_NODES as f64
    );
    eprintln!("  Route cache: total={}", total_route_entries);

    eprintln!("\n  --- Timing ---");
    eprintln!(
        "  Setup: {:.1}s | Handshake: {:.1}s | Data: {:.1}s | Total: {:.1}s",
        setup_time.as_secs_f64(),
        session_time.as_secs_f64(),
        data_time.as_secs_f64(),
        start.elapsed().as_secs_f64()
    );

    if !fwd_missing.is_empty() {
        eprintln!(
            "\n  First {} undelivered forward datagrams:",
            fwd_missing.len()
        );
        for &(src, dst) in &fwd_missing {
            eprintln!("    node {} -> node {}", src, dst);
        }
    }
    if !rev_missing.is_empty() {
        eprintln!(
            "\n  First {} undelivered reverse datagrams:",
            rev_missing.len()
        );
        for &(src, dst) in &rev_missing {
            eprintln!("    node {} <- node {}", src, dst);
        }
    }

    // === Assertions ===

    assert_eq!(
        send_forward_err, 0,
        "All forward sends should succeed"
    );
    assert_eq!(
        send_reverse_err, 0,
        "All reverse sends should succeed (responder Established after forward data)"
    );
    assert_eq!(
        fwd_delivered, send_forward_ok,
        "All forward datagrams should be delivered to responder TUN"
    );
    assert_eq!(
        rev_delivered, send_reverse_ok,
        "All reverse datagrams should be delivered to initiator TUN"
    );
    assert_eq!(
        total_established, total_sessions,
        "All {} session entries should be Established, \
         but {} responding, {} initiating",
        total_sessions, total_responding, total_initiating
    );

    cleanup_nodes(&mut nodes).await;
}
