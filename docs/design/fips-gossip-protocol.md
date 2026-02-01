# FIPS Gossip Protocol

This document specifies the wire formats and exchange rules for FIPS gossip
messages: TreeAnnounce, FilterAnnounce, and the discovery protocol
(LookupRequest/LookupResponse).

For conceptual background on how these protocols work:

- Spanning tree dynamics: [spanning-tree-dynamics.md](spanning-tree-dynamics.md)
- Routing design and bloom filter concepts: [fips-routing.md](fips-routing.md)

---

## 1. Message Type Summary

All gossip messages are link-layer messages, encrypted with per-peer Noise IK
session keys. They travel one hop (peer-to-peer), though their effects may
propagate further through subsequent gossip.

| Type | Purpose | Direction | Trigger |
|------|---------|-----------|---------|
| TreeAnnounce | Spanning tree state | Bidirectional | Peer connect, parent change, periodic |
| FilterAnnounce | Bloom filter reachability | Bidirectional | Peer connect, filter change |
| LookupRequest | Coordinate discovery | Flooded | Route cache miss |
| LookupResponse | Return coordinates | Routed back | LookupRequest reaches target |

---

## 2. TreeAnnounce

TreeAnnounce messages propagate spanning tree state between peers. Each node
announces its parent selection and ancestry, enabling peers to compute tree
coordinates and distances.

### 2.1 Wire Format

```text
TreeAnnounce {
    sequence: u64,              // Monotonic, increments on parent change
    timestamp: u64,             // Unix timestamp (seconds)
    parent: NodeId,             // 32 bytes, SHA-256(npub) of selected parent
    ancestry: Vec<AncestryEntry>,  // Path from self to root
    signature: Signature,       // 64 bytes, signs (sequence || timestamp || parent || ancestry)
}

AncestryEntry {
    node_id: NodeId,            // 32 bytes
    sequence: u64,              // That node's sequence number
    timestamp: u64,             // That node's timestamp
    signature: Signature,       // That node's signature over its declaration
}
```

### 2.2 Field Semantics

**sequence**: Incremented each time the node changes its parent declaration.
Higher sequence numbers supersede lower ones for conflict resolution.

**timestamp**: Used for distributed consistency. A declaration is considered
stale if `now - timestamp > ROOT_TIMEOUT` (default 60 minutes for root).

**parent**: The node_id of the selected parent. If `parent == self.node_id`,
the node is declaring itself as root.

**ancestry**: The chain from this node up to the root. The first entry is this
node's own declaration, followed by parent, grandparent, etc. Each entry is
signed by the declaring node, allowing verification of the entire chain.

### 2.3 Size Estimate

| Component | Size |
|-----------|------|
| sequence | 8 bytes |
| timestamp | 8 bytes |
| parent | 32 bytes |
| signature | 64 bytes |
| Per ancestry entry | 32 + 8 + 8 + 64 = 112 bytes |

For tree depth D: `112 + D * 112` bytes. At depth 10: ~1.2 KB.

### 2.4 Exchange Rules

**On peer connection:**

1. After Noise IK handshake completes, both peers send TreeAnnounce
2. Each peer processes the received announcement (see §2.5)
3. If processing triggers a parent change, send updated TreeAnnounce to all peers

**On parent change:**

1. Increment sequence number
2. Update timestamp
3. Sign new declaration
4. Send TreeAnnounce to all peers

**Periodic refresh:**

1. Root refreshes every 30 minutes (prevents stale root detection)
2. Non-root nodes forward root refresh when received
3. Nodes may refresh their own declaration periodically (implementation choice)

### 2.5 Processing Rules

When receiving TreeAnnounce from peer P:

```text
1. Verify signature on sender's declaration
2. Verify signatures on all ancestry entries
3. For each entry in ancestry:
   - If entry.sequence > stored.sequence: update stored entry
   - If entry.sequence == stored.sequence && entry.timestamp > stored.timestamp: update
   - Otherwise: keep existing entry
4. Update peer P's record with new ancestry
5. Re-evaluate parent selection:
   - If better path to root available: change parent, announce to all peers
   - Apply stability threshold to prevent flapping
```

### 2.6 Rate Limiting

To prevent announcement storms during reconvergence:

- Minimum interval between announcements to same peer: 500ms
- If change occurs during cooldown: mark pending, send after cooldown
- Coalesce multiple pending changes into single announcement

---

## 3. FilterAnnounce

FilterAnnounce messages propagate Bloom filter reachability information. Each
node's filter indicates which destinations are reachable through it.

### 3.1 Wire Format

```text
FilterAnnounce {
    filter: BloomFilter,        // 4096 bytes (32,768 bits)
    ttl: u8,                    // Remaining propagation hops
    sequence: u64,              // For freshness/deduplication
}

BloomFilter {
    bits: [u8; 4096],           // Bit array
    hash_count: u8,             // Number of hash functions (typically 7)
}
```

### 3.2 Field Semantics

**filter**: Contains node_ids reachable through this peer. Uses k=7 hash
functions for near-optimal false positive rate at expected fill levels.

**ttl**: Remaining propagation depth. Starts at K (typically 2), decremented
each hop. At TTL=0, entries are not propagated further.

**sequence**: Monotonic counter for this node's filter. Allows receivers to
detect stale or duplicate announcements.

### 3.3 Filter Contents

A node's outgoing filter to peer Q contains:

1. This node's own node_id
2. Node_ids of leaf-only dependents (nodes using this node as sole peer)
3. Entries from filters received from other peers (not Q) with TTL > 0

This creates K-hop reachability scope. With K=2, entries propagate ~4 hops
before TTL exhaustion.

### 3.4 Exchange Rules

**On peer connection:**

1. After TreeAnnounce exchange, send FilterAnnounce
2. Filter contains current reachability view

**On filter change:**

Triggering events:

- Peer connects or disconnects
- Received filter changes outgoing filter
- Local state change (new leaf dependent, become gateway)

Rate limiting:

- Minimum interval between filter announcements: 500ms
- Debounce rapid changes into single announcement

**Processing received filter:**

```text
1. Store: peer_filters[P] = received.filter
2. If received.ttl > 0:
   - Include entries in next announcement to other peers
   - Decrement TTL for propagated entries
3. Recompute own outgoing filters if changed
```

### 3.5 Filter Expiration

Bloom filters cannot remove individual entries. Expiration handled by:

- **Peer disconnect**: Remove that peer's filter entirely, recompute
- **Filter replacement**: Each FilterAnnounce replaces the previous one
- **Implicit timeout**: If no updates from peer within threshold, consider stale

---

## 4. LookupRequest

LookupRequest initiates coordinate discovery for destinations not covered by
local Bloom filters.

### 4.1 Wire Format

```text
LookupRequest {
    request_id: u64,            // Unique identifier for this request
    target: NodeId,             // 32 bytes, who we're looking for
    origin: NodeId,             // 32 bytes, who's asking
    origin_coords: Vec<NodeId>, // Origin's ancestry (for return path)
    ttl: u8,                    // Remaining propagation hops
    visited: CompactBloomFilter,// ~256 bytes, prevents loops
}

CompactBloomFilter {
    bits: [u8; 256],            // Smaller filter for visited set
    hash_count: u8,
}
```

### 4.2 Field Semantics

**request_id**: Randomly generated, used to match responses and detect
duplicates.

**target**: The node_id being searched for.

**origin**: The node_id of the original requester. Used for response routing.

**origin_coords**: The requester's current tree coordinates. Enables greedy
routing of the response back to origin.

**ttl**: Propagation limit. Prevents unbounded flooding.

**visited**: Compact Bloom filter tracking nodes that have seen this request.
Prevents redundant processing and loops.

### 4.3 Propagation Rules

When receiving LookupRequest:

```text
1. Check visited filter - if self likely present, drop (already processed)
2. Add self to visited filter
3. Decrement TTL

4. Check if target is local:
   - If target == self.node_id: generate LookupResponse
   - If target in local peer_filters: may respond on behalf (optional)

5. If TTL > 0 and not found locally:
   - Forward to peers not in visited filter
   - Optionally prioritize peers whose filter indicates target "maybe" present
```

### 4.4 Rate Limiting

- Track recently seen request_ids, drop duplicates
- Limit requests per origin per time window
- Limit total outstanding requests

---

## 5. LookupResponse

LookupResponse returns the target's coordinates to the requester.

### 5.1 Wire Format

```text
LookupResponse {
    request_id: u64,            // Echoes LookupRequest.request_id
    target: NodeId,             // 32 bytes, confirms who was found
    target_coords: Vec<NodeId>, // Target's ancestry (the key payload)
    proof: Signature,           // 64 bytes, target signs to prove existence
}
```

### 5.2 Field Semantics

**request_id**: Matches the original request, allowing requester to correlate.

**target**: Confirms the identity found.

**target_coords**: The target's current tree coordinates. This is the primary
payload - enables greedy routing to the target.

**proof**: Target's signature over `(request_id || target || target_coords)`.
Prevents malicious nodes from claiming reachability and blackholing traffic.

### 5.3 Routing

LookupResponse uses greedy tree routing based on `origin_coords` from the
request:

```text
1. Response created at target (or node with target in filter)
2. Each hop forwards toward origin using tree distance
3. Origin receives response, caches target_coords
```

### 5.4 Security

The proof signature is critical:

- Without it, any node could claim to be (or know) any target
- Requester verifies signature against target's known public key
- Invalid signatures cause response to be dropped

---

## 6. Message Type Codes

Within the link-layer message framing:

| Type Code | Message |
|-----------|---------|
| 0x10 | TreeAnnounce |
| 0x11 | FilterAnnounce |
| 0x12 | LookupRequest |
| 0x13 | LookupResponse |

These are carried inside the encrypted link-layer payload after Noise IK
handshake completion.

---

## 7. Timing Parameters

| Parameter | Default | Notes |
|-----------|---------|-------|
| ROOT_REFRESH_INTERVAL | 30 min | Root regenerates timestamp |
| ROOT_TIMEOUT | 60 min | Root declaration considered stale |
| TREE_ENTRY_TTL | 5-10 min | Individual entry expiration |
| FILTER_TTL_HOPS | 2 | Bloom filter propagation depth |
| ANNOUNCE_MIN_INTERVAL | 500 ms | Rate limit for announcements |
| LOOKUP_TTL | 8 | Discovery request propagation limit |
| LOOKUP_TIMEOUT | 5 sec | Time to wait for response |

---

## 8. Encoding

All multi-byte integers are little-endian. NodeId is 32 bytes (SHA-256 hash).
Signatures are 64 bytes (secp256k1 Schnorr).

Variable-length fields (ancestry, coordinates) are prefixed with a 2-byte
length count indicating number of entries.

```text
Vec<T> encoding:
  count: u16 (little-endian)
  items: T[count]
```

---

## References

- [spanning-tree-dynamics.md](spanning-tree-dynamics.md) - Tree protocol behavior
- [fips-routing.md](fips-routing.md) - Routing concepts and algorithms
- [fips-wire-protocol.md](fips-wire-protocol.md) - Link-layer framing
- [fips-session-protocol.md](fips-session-protocol.md) - End-to-end sessions
