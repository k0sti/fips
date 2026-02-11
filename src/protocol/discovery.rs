//! Discovery messages: LookupRequest and LookupResponse.

use crate::bloom::BloomFilter;
use crate::tree::TreeCoordinate;
use crate::NodeAddr;
use secp256k1::schnorr::Signature;

/// Request to discover a node's coordinates.
///
/// Flooded through the network with TTL limiting scope. The visited
/// filter prevents routing loops.
#[derive(Clone, Debug)]
pub struct LookupRequest {
    /// Unique request identifier.
    pub request_id: u64,
    /// Node we're looking for.
    pub target: NodeAddr,
    /// Who's asking (for response routing).
    pub origin: NodeAddr,
    /// Origin's coordinates (for return path).
    pub origin_coords: TreeCoordinate,
    /// Remaining propagation hops.
    pub ttl: u8,
    /// Visited nodes filter (loop prevention).
    pub visited: BloomFilter,
}

impl LookupRequest {
    /// Create a new lookup request.
    pub fn new(
        request_id: u64,
        target: NodeAddr,
        origin: NodeAddr,
        origin_coords: TreeCoordinate,
        ttl: u8,
    ) -> Self {
        // Small filter for visited tracking
        let visited = BloomFilter::with_params(256 * 8, 5).expect("valid params");
        Self {
            request_id,
            target,
            origin,
            origin_coords,
            ttl,
            visited,
        }
    }

    /// Generate a new request with a random ID.
    pub fn generate(
        target: NodeAddr,
        origin: NodeAddr,
        origin_coords: TreeCoordinate,
        ttl: u8,
    ) -> Self {
        use rand::Rng;
        let request_id = rand::thread_rng().r#gen();
        Self::new(request_id, target, origin, origin_coords, ttl)
    }

    /// Decrement TTL and add self to visited.
    ///
    /// Returns false if TTL was already 0.
    pub fn forward(&mut self, my_node_addr: &NodeAddr) -> bool {
        if self.ttl == 0 {
            return false;
        }
        self.ttl -= 1;
        self.visited.insert(my_node_addr);
        true
    }

    /// Check if this request can still be forwarded.
    pub fn can_forward(&self) -> bool {
        self.ttl > 0
    }

    /// Check if a node was already visited.
    pub fn was_visited(&self, node_addr: &NodeAddr) -> bool {
        self.visited.contains(node_addr)
    }
}

/// Response to a lookup request with target's coordinates.
///
/// Routed back to the origin using the origin_coords from the request.
#[derive(Clone, Debug)]
pub struct LookupResponse {
    /// Echoed request identifier.
    pub request_id: u64,
    /// The target node.
    pub target: NodeAddr,
    /// Target's coordinates in the tree.
    pub target_coords: TreeCoordinate,
    /// Proof that target authorized this response (signature over request).
    pub proof: Signature,
}

impl LookupResponse {
    /// Create a new lookup response.
    pub fn new(
        request_id: u64,
        target: NodeAddr,
        target_coords: TreeCoordinate,
        proof: Signature,
    ) -> Self {
        Self {
            request_id,
            target,
            target_coords,
            proof,
        }
    }

    /// Get the bytes that should be signed as proof.
    ///
    /// Format: request_id (8) || target (16)
    pub fn proof_bytes(request_id: u64, target: &NodeAddr) -> Vec<u8> {
        let mut bytes = Vec::with_capacity(24);
        bytes.extend_from_slice(&request_id.to_le_bytes());
        bytes.extend_from_slice(target.as_bytes());
        bytes
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_node_addr(val: u8) -> NodeAddr {
        let mut bytes = [0u8; 16];
        bytes[0] = val;
        NodeAddr::from_bytes(bytes)
    }

    fn make_coords(ids: &[u8]) -> TreeCoordinate {
        TreeCoordinate::from_addrs(ids.iter().map(|&v| make_node_addr(v)).collect()).unwrap()
    }

    #[test]
    fn test_lookup_request_forward() {
        let target = make_node_addr(1);
        let origin = make_node_addr(2);
        let coords = make_coords(&[2, 0]);
        let forwarder = make_node_addr(3);

        let mut request = LookupRequest::new(123, target, origin, coords, 5);

        assert!(request.can_forward());
        assert!(!request.was_visited(&forwarder));

        assert!(request.forward(&forwarder));

        assert_eq!(request.ttl, 4);
        assert!(request.was_visited(&forwarder));
    }

    #[test]
    fn test_lookup_request_ttl_exhausted() {
        let target = make_node_addr(1);
        let origin = make_node_addr(2);
        let coords = make_coords(&[2, 0]);

        let mut request = LookupRequest::new(123, target, origin, coords, 1);

        assert!(request.forward(&make_node_addr(3)));
        assert!(!request.can_forward());
        assert!(!request.forward(&make_node_addr(4)));
    }

    #[test]
    fn test_lookup_request_generate() {
        let target = make_node_addr(1);
        let origin = make_node_addr(2);
        let coords = make_coords(&[2, 0]);

        let req1 = LookupRequest::generate(target, origin, coords.clone(), 5);
        let req2 = LookupRequest::generate(target, origin, coords, 5);

        // Random IDs should differ
        assert_ne!(req1.request_id, req2.request_id);
    }

    #[test]
    fn test_lookup_response_proof_bytes() {
        let target = make_node_addr(42);
        let bytes = LookupResponse::proof_bytes(12345, &target);

        assert_eq!(bytes.len(), 24); // 8 + 16
        assert_eq!(&bytes[0..8], &12345u64.to_le_bytes());
        assert_eq!(&bytes[8..24], target.as_bytes());
    }
}
