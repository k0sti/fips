//! Discovery messages: LookupRequest and LookupResponse.

use crate::bloom::BloomFilter;
use crate::protocol::error::ProtocolError;
use crate::protocol::session::{decode_coords, encode_coords};
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

    /// Encode as wire format (includes msg_type byte).
    ///
    /// Format: `[0x30][request_id:8][target:16][origin:16][ttl:1]`
    ///         `[origin_coords_cnt:2][origin_coords:16×n]`
    ///         `[visited_hash_cnt:1][visited_bits:256]`
    pub fn encode(&self) -> Vec<u8> {
        let visited_bytes = self.visited.as_bytes();
        let mut buf = Vec::with_capacity(44 + self.origin_coords.depth() * 16 + 1 + visited_bytes.len());

        buf.push(0x30); // msg_type
        buf.extend_from_slice(&self.request_id.to_le_bytes());
        buf.extend_from_slice(self.target.as_bytes());
        buf.extend_from_slice(self.origin.as_bytes());
        buf.push(self.ttl);
        encode_coords(&self.origin_coords, &mut buf);
        buf.push(self.visited.hash_count());
        buf.extend_from_slice(visited_bytes);

        buf
    }

    /// Decode from wire format (after msg_type byte has been consumed).
    pub fn decode(payload: &[u8]) -> Result<Self, ProtocolError> {
        // Minimum: request_id(8) + target(16) + origin(16) + ttl(1)
        //          + coords_count(2) + hash_count(1) = 44 bytes
        if payload.len() < 44 {
            return Err(ProtocolError::MessageTooShort {
                expected: 44,
                got: payload.len(),
            });
        }

        let mut pos = 0;

        let request_id = u64::from_le_bytes(
            payload[pos..pos + 8]
                .try_into()
                .map_err(|_| ProtocolError::Malformed("bad request_id".into()))?,
        );
        pos += 8;

        let mut target_bytes = [0u8; 16];
        target_bytes.copy_from_slice(&payload[pos..pos + 16]);
        let target = NodeAddr::from_bytes(target_bytes);
        pos += 16;

        let mut origin_bytes = [0u8; 16];
        origin_bytes.copy_from_slice(&payload[pos..pos + 16]);
        let origin = NodeAddr::from_bytes(origin_bytes);
        pos += 16;

        let ttl = payload[pos];
        pos += 1;

        let (origin_coords, consumed) = decode_coords(&payload[pos..])?;
        pos += consumed;

        if payload.len() < pos + 1 {
            return Err(ProtocolError::MessageTooShort {
                expected: pos + 1,
                got: payload.len(),
            });
        }
        let hash_count = payload[pos];
        pos += 1;

        let filter_bytes = &payload[pos..];
        if filter_bytes.is_empty() {
            return Err(ProtocolError::Malformed("visited filter missing".into()));
        }

        let visited = BloomFilter::from_slice(filter_bytes, hash_count)
            .map_err(|e| ProtocolError::Malformed(format!("bad visited filter: {e}")))?;

        Ok(Self {
            request_id,
            target,
            origin,
            origin_coords,
            ttl,
            visited,
        })
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

    /// Encode as wire format (includes msg_type byte).
    ///
    /// Format: `[0x31][request_id:8][target:16][target_coords_cnt:2][target_coords:16×n][proof:64]`
    pub fn encode(&self) -> Vec<u8> {
        let mut buf = Vec::with_capacity(91 + self.target_coords.depth() * 16);

        buf.push(0x31); // msg_type
        buf.extend_from_slice(&self.request_id.to_le_bytes());
        buf.extend_from_slice(self.target.as_bytes());
        encode_coords(&self.target_coords, &mut buf);
        buf.extend_from_slice(self.proof.as_ref());

        buf
    }

    /// Decode from wire format (after msg_type byte has been consumed).
    pub fn decode(payload: &[u8]) -> Result<Self, ProtocolError> {
        // Minimum: request_id(8) + target(16) + coords_count(2) + proof(64) = 90
        if payload.len() < 90 {
            return Err(ProtocolError::MessageTooShort {
                expected: 90,
                got: payload.len(),
            });
        }

        let mut pos = 0;

        let request_id = u64::from_le_bytes(
            payload[pos..pos + 8]
                .try_into()
                .map_err(|_| ProtocolError::Malformed("bad request_id".into()))?,
        );
        pos += 8;

        let mut target_bytes = [0u8; 16];
        target_bytes.copy_from_slice(&payload[pos..pos + 16]);
        let target = NodeAddr::from_bytes(target_bytes);
        pos += 16;

        let (target_coords, consumed) = decode_coords(&payload[pos..])?;
        pos += consumed;

        if payload.len() < pos + 64 {
            return Err(ProtocolError::MessageTooShort {
                expected: pos + 64,
                got: payload.len(),
            });
        }
        let proof = Signature::from_slice(&payload[pos..pos + 64])
            .map_err(|_| ProtocolError::Malformed("bad proof signature".into()))?;

        Ok(Self {
            request_id,
            target,
            target_coords,
            proof,
        })
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

    #[test]
    fn test_lookup_request_encode_decode_roundtrip() {
        let target = make_node_addr(10);
        let origin = make_node_addr(20);
        let coords = make_coords(&[20, 0]);

        let mut request = LookupRequest::new(12345, target, origin, coords.clone(), 8);
        request.forward(&make_node_addr(30));

        let encoded = request.encode();
        assert_eq!(encoded[0], 0x30);

        let decoded = LookupRequest::decode(&encoded[1..]).unwrap();
        assert_eq!(decoded.request_id, 12345);
        assert_eq!(decoded.target, target);
        assert_eq!(decoded.origin, origin);
        assert_eq!(decoded.ttl, 7); // decremented by forward()
        assert!(decoded.was_visited(&make_node_addr(30)));
    }

    #[test]
    fn test_lookup_request_decode_too_short() {
        assert!(LookupRequest::decode(&[]).is_err());
        assert!(LookupRequest::decode(&[0u8; 40]).is_err());
    }

    #[test]
    fn test_lookup_response_encode_decode_roundtrip() {
        use secp256k1::Secp256k1;

        let target = make_node_addr(42);
        let coords = make_coords(&[42, 1, 0]);

        // Create a dummy signature for testing
        let secp = Secp256k1::new();
        let keypair = secp256k1::Keypair::new(&secp, &mut rand::thread_rng());
        let proof_data = LookupResponse::proof_bytes(999, &target);
        use sha2::Digest;
        let digest: [u8; 32] = sha2::Sha256::digest(&proof_data).into();
        let sig = secp.sign_schnorr(&digest, &keypair);

        let response = LookupResponse::new(999, target, coords.clone(), sig);

        let encoded = response.encode();
        assert_eq!(encoded[0], 0x31);

        let decoded = LookupResponse::decode(&encoded[1..]).unwrap();
        assert_eq!(decoded.request_id, 999);
        assert_eq!(decoded.target, target);
        assert_eq!(decoded.proof, sig);
    }

    #[test]
    fn test_lookup_response_decode_too_short() {
        assert!(LookupResponse::decode(&[]).is_err());
        assert!(LookupResponse::decode(&[0u8; 50]).is_err());
    }
}
