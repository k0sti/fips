//! FIPS Protocol Messages
//!
//! Wire format definitions for FIPS protocol communication across two layers:
//!
//! ## Link Layer (peer-to-peer, hop-by-hop)
//!
//! Messages exchanged between directly connected peers over Noise-encrypted
//! links. Includes spanning tree gossip, bloom filter propagation, discovery
//! protocol, and forwarding of session-layer datagrams.
//!
//! Link-layer peer authentication uses Noise IK (see `noise.rs`), which
//! establishes the encrypted channel before any of these messages are sent.
//!
//! ## Session Layer (end-to-end, between FIPS addresses)
//!
//! Messages exchanged between source and destination FIPS nodes, encrypted
//! with session keys that intermediate nodes cannot read. Includes session
//! establishment, IPv6 datagram encapsulation, and routing errors.
//!
//! Session-layer datagrams are carried as opaque payloads through the link
//! layer, encrypted end-to-end independently of per-hop link encryption.

use crate::bloom::BloomFilter;
use crate::tree::{CoordEntry, ParentDeclaration, TreeCoordinate};
use crate::NodeAddr;
use secp256k1::schnorr::Signature;
use std::fmt;
use thiserror::Error;

/// Protocol version for message compatibility.
pub const PROTOCOL_VERSION: u8 = 1;

/// Data packet header size in bytes (excluding payload).
/// flags(1) + hop_limit(1) + payload_length(2) + src_addr(16) + dest_addr(16) = 36
pub const DATA_HEADER_SIZE: usize = 36;

// ============================================================================
// Link Layer Message Types (peer-to-peer, hop-by-hop)
// ============================================================================

/// Handshake message type identifiers.
///
/// These messages are exchanged during Noise IK handshake before link
/// encryption is established. They use the same TLV framing as link
/// messages but payloads are not encrypted (except Noise-internal encryption).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u8)]
pub enum HandshakeMessageType {
    /// Noise IK message 1: initiator sends ephemeral + encrypted static.
    /// Payload: 82 bytes (33 ephemeral + 33 static + 16 tag).
    NoiseIKMsg1 = 0x01,

    /// Noise IK message 2: responder sends ephemeral.
    /// Payload: 33 bytes (ephemeral pubkey only).
    NoiseIKMsg2 = 0x02,
}

impl HandshakeMessageType {
    /// Try to convert from a byte.
    pub fn from_byte(b: u8) -> Option<Self> {
        match b {
            0x01 => Some(HandshakeMessageType::NoiseIKMsg1),
            0x02 => Some(HandshakeMessageType::NoiseIKMsg2),
            _ => None,
        }
    }

    /// Convert to a byte.
    pub fn to_byte(self) -> u8 {
        self as u8
    }

    /// Check if a byte represents a handshake message type.
    pub fn is_handshake(b: u8) -> bool {
        matches!(b, 0x01 | 0x02)
    }
}

impl fmt::Display for HandshakeMessageType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let name = match self {
            HandshakeMessageType::NoiseIKMsg1 => "NoiseIKMsg1",
            HandshakeMessageType::NoiseIKMsg2 => "NoiseIKMsg2",
        };
        write!(f, "{}", name)
    }
}

// ============================================================================
// Link-Layer Message Types
// ============================================================================

/// Link-layer message type identifiers.
///
/// These messages are exchanged between directly connected peers over
/// Noise-encrypted links. All payloads are encrypted with session keys
/// established during the Noise IK handshake.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u8)]
pub enum LinkMessageType {
    // Tree protocol (0x10-0x1F)
    /// Spanning tree state announcement.
    TreeAnnounce = 0x10,

    // Bloom filter (0x20-0x2F)
    /// Bloom filter reachability update.
    FilterAnnounce = 0x20,

    // Discovery (0x30-0x3F)
    /// Request to discover a node's coordinates.
    LookupRequest = 0x30,
    /// Response with target's coordinates.
    LookupResponse = 0x31,

    // Forwarding (0x40-0x4F)
    /// Encapsulated session-layer datagram for forwarding.
    /// Payload is opaque to intermediate nodes (end-to-end encrypted).
    SessionDatagram = 0x40,

    // Link Control (0x50-0x5F)
    /// Orderly disconnect notification before link closure.
    Disconnect = 0x50,
}

impl LinkMessageType {
    /// Try to convert from a byte.
    pub fn from_byte(b: u8) -> Option<Self> {
        match b {
            0x10 => Some(LinkMessageType::TreeAnnounce),
            0x20 => Some(LinkMessageType::FilterAnnounce),
            0x30 => Some(LinkMessageType::LookupRequest),
            0x31 => Some(LinkMessageType::LookupResponse),
            0x40 => Some(LinkMessageType::SessionDatagram),
            0x50 => Some(LinkMessageType::Disconnect),
            _ => None,
        }
    }

    /// Convert to a byte.
    pub fn to_byte(self) -> u8 {
        self as u8
    }
}

impl fmt::Display for LinkMessageType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let name = match self {
            LinkMessageType::TreeAnnounce => "TreeAnnounce",
            LinkMessageType::FilterAnnounce => "FilterAnnounce",
            LinkMessageType::LookupRequest => "LookupRequest",
            LinkMessageType::LookupResponse => "LookupResponse",
            LinkMessageType::SessionDatagram => "SessionDatagram",
            LinkMessageType::Disconnect => "Disconnect",
        };
        write!(f, "{}", name)
    }
}

// ============================================================================
// Disconnect Reason Codes
// ============================================================================

/// Reason for an orderly disconnect notification.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u8)]
pub enum DisconnectReason {
    /// Normal shutdown (operator requested).
    Shutdown = 0x00,
    /// Restarting (may reconnect soon).
    Restart = 0x01,
    /// Protocol error encountered.
    ProtocolError = 0x02,
    /// Transport failure.
    TransportFailure = 0x03,
    /// Resource exhaustion (memory, connections).
    ResourceExhaustion = 0x04,
    /// Authentication or security policy violation.
    SecurityViolation = 0x05,
    /// Configuration change (peer removed from config).
    ConfigurationChange = 0x06,
    /// Timeout or keepalive failure.
    Timeout = 0x07,
    /// Unspecified reason.
    Other = 0xFF,
}

impl DisconnectReason {
    /// Try to convert from a byte.
    pub fn from_byte(b: u8) -> Option<Self> {
        match b {
            0x00 => Some(DisconnectReason::Shutdown),
            0x01 => Some(DisconnectReason::Restart),
            0x02 => Some(DisconnectReason::ProtocolError),
            0x03 => Some(DisconnectReason::TransportFailure),
            0x04 => Some(DisconnectReason::ResourceExhaustion),
            0x05 => Some(DisconnectReason::SecurityViolation),
            0x06 => Some(DisconnectReason::ConfigurationChange),
            0x07 => Some(DisconnectReason::Timeout),
            0xFF => Some(DisconnectReason::Other),
            _ => None,
        }
    }

    /// Convert to a byte.
    pub fn to_byte(self) -> u8 {
        self as u8
    }
}

impl fmt::Display for DisconnectReason {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let name = match self {
            DisconnectReason::Shutdown => "Shutdown",
            DisconnectReason::Restart => "Restart",
            DisconnectReason::ProtocolError => "ProtocolError",
            DisconnectReason::TransportFailure => "TransportFailure",
            DisconnectReason::ResourceExhaustion => "ResourceExhaustion",
            DisconnectReason::SecurityViolation => "SecurityViolation",
            DisconnectReason::ConfigurationChange => "ConfigurationChange",
            DisconnectReason::Timeout => "Timeout",
            DisconnectReason::Other => "Other",
        };
        write!(f, "{}", name)
    }
}

// ============================================================================
// Disconnect Message
// ============================================================================

/// Orderly disconnect notification sent before closing a peer link.
///
/// Sent as a link-layer message (type 0x50) inside an encrypted frame.
/// Allows the receiving peer to immediately clean up state rather than
/// waiting for timeout-based detection.
///
/// ## Wire Format
///
/// | Offset | Field    | Size   | Notes                  |
/// |--------|----------|--------|------------------------|
/// | 0      | msg_type | 1 byte | 0x50                   |
/// | 1      | reason   | 1 byte | DisconnectReason value |
#[derive(Clone, Debug)]
pub struct Disconnect {
    /// Reason for disconnection.
    pub reason: DisconnectReason,
}

impl Disconnect {
    /// Create a new Disconnect message.
    pub fn new(reason: DisconnectReason) -> Self {
        Self { reason }
    }

    /// Encode as link-layer plaintext (msg_type + reason).
    pub fn encode(&self) -> [u8; 2] {
        [LinkMessageType::Disconnect.to_byte(), self.reason.to_byte()]
    }

    /// Decode from link-layer payload (after msg_type byte has been consumed).
    pub fn decode(payload: &[u8]) -> Result<Self, ProtocolError> {
        if payload.is_empty() {
            return Err(ProtocolError::MessageTooShort {
                expected: 1,
                got: 0,
            });
        }
        let reason = DisconnectReason::from_byte(payload[0]).unwrap_or(DisconnectReason::Other);
        Ok(Self { reason })
    }
}

// ============================================================================
// Session Layer Message Types (end-to-end, between FIPS addresses)
// ============================================================================

/// Session-layer message type identifiers.
///
/// These messages are exchanged end-to-end between FIPS nodes, encrypted
/// with session keys that intermediate nodes cannot read. They are carried
/// as payloads inside `LinkMessageType::SessionDatagram`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u8)]
pub enum SessionMessageType {
    // Session establishment (0x00-0x0F)
    /// Session setup with coordinates (warms router caches).
    SessionSetup = 0x00,
    /// Session acknowledgement.
    SessionAck = 0x01,

    // Data (0x10-0x1F)
    /// Encrypted IPv6 datagram payload.
    DataPacket = 0x10,

    // Errors (0x20-0x2F)
    /// Router cache miss - needs coordinates.
    CoordsRequired = 0x20,
    /// Routing failure (local minimum or unreachable).
    PathBroken = 0x21,
}

impl SessionMessageType {
    /// Try to convert from a byte.
    pub fn from_byte(b: u8) -> Option<Self> {
        match b {
            0x00 => Some(SessionMessageType::SessionSetup),
            0x01 => Some(SessionMessageType::SessionAck),
            0x10 => Some(SessionMessageType::DataPacket),
            0x20 => Some(SessionMessageType::CoordsRequired),
            0x21 => Some(SessionMessageType::PathBroken),
            _ => None,
        }
    }

    /// Convert to a byte.
    pub fn to_byte(self) -> u8 {
        self as u8
    }
}

impl fmt::Display for SessionMessageType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let name = match self {
            SessionMessageType::SessionSetup => "SessionSetup",
            SessionMessageType::SessionAck => "SessionAck",
            SessionMessageType::DataPacket => "DataPacket",
            SessionMessageType::CoordsRequired => "CoordsRequired",
            SessionMessageType::PathBroken => "PathBroken",
        };
        write!(f, "{}", name)
    }
}

// Legacy type alias for compatibility during transition
#[deprecated(note = "Use LinkMessageType or SessionMessageType instead")]
pub type MessageType = LinkMessageType;

/// Errors related to protocol message handling.
#[derive(Debug, Error)]
pub enum ProtocolError {
    #[error("invalid message type: 0x{0:02x}")]
    InvalidMessageType(u8),

    #[error("message too short: expected at least {expected}, got {got}")]
    MessageTooShort { expected: usize, got: usize },

    #[error("message too long: max {max}, got {got}")]
    MessageTooLong { max: usize, got: usize },

    #[error("invalid signature")]
    InvalidSignature,

    #[error("unsupported protocol version: {0}")]
    UnsupportedVersion(u8),

    #[error("malformed message: {0}")]
    Malformed(String),

    #[error("hop limit exceeded")]
    HopLimitExceeded,

    #[error("ttl expired")]
    TtlExpired,
}

// ============================================================================
// Link Layer Messages
// ============================================================================

// ============ Tree Protocol Messages ============

/// Spanning tree announcement carrying parent declaration and ancestry.
///
/// Sent to peers to propagate tree state. The declaration proves the
/// sender's parent selection; the ancestry provides path to root for
/// routing decisions.
#[derive(Clone, Debug)]
pub struct TreeAnnounce {
    /// The sender's parent declaration.
    pub declaration: ParentDeclaration,
    /// Full ancestry from sender to root.
    pub ancestry: TreeCoordinate,
}

impl TreeAnnounce {
    /// TreeAnnounce wire format version 1.
    pub const VERSION_1: u8 = 0x01;

    /// Minimum payload size (after msg_type stripped by dispatcher):
    /// version(1) + sequence(8) + timestamp(8) + parent(16) + ancestry_count(2) + signature(64) = 99
    const MIN_PAYLOAD_SIZE: usize = 99;

    /// Create a new TreeAnnounce message.
    pub fn new(declaration: ParentDeclaration, ancestry: TreeCoordinate) -> Self {
        Self {
            declaration,
            ancestry,
        }
    }

    /// Encode as link-layer plaintext (includes msg_type byte).
    ///
    /// The declaration must be signed. The encoded format is:
    /// ```text
    /// [0x10][version:1][sequence:8 LE][timestamp:8 LE][parent:16]
    /// [ancestry_count:2 LE][entries:32×n][signature:64]
    /// ```
    pub fn encode(&self) -> Result<Vec<u8>, ProtocolError> {
        let signature = self
            .declaration
            .signature()
            .ok_or(ProtocolError::InvalidSignature)?;

        let entries = self.ancestry.entries();
        let ancestry_count = entries.len() as u16;
        let size = 1 + Self::MIN_PAYLOAD_SIZE + entries.len() * CoordEntry::WIRE_SIZE;
        let mut buf = Vec::with_capacity(size);

        // msg_type
        buf.push(LinkMessageType::TreeAnnounce.to_byte());
        // version
        buf.push(Self::VERSION_1);
        // sequence (8 LE)
        buf.extend_from_slice(&self.declaration.sequence().to_le_bytes());
        // timestamp (8 LE)
        buf.extend_from_slice(&self.declaration.timestamp().to_le_bytes());
        // parent (16)
        buf.extend_from_slice(self.declaration.parent_id().as_bytes());
        // ancestry_count (2 LE)
        buf.extend_from_slice(&ancestry_count.to_le_bytes());
        // ancestry entries (32 bytes each)
        for entry in entries {
            buf.extend_from_slice(entry.node_addr.as_bytes()); // 16
            buf.extend_from_slice(&entry.sequence.to_le_bytes()); // 8
            buf.extend_from_slice(&entry.timestamp.to_le_bytes()); // 8
        }
        // outer signature (64)
        buf.extend_from_slice(signature.as_ref());

        Ok(buf)
    }

    /// Decode from link-layer payload (after msg_type byte stripped by dispatcher).
    ///
    /// The payload starts with the version byte.
    pub fn decode(payload: &[u8]) -> Result<Self, ProtocolError> {
        if payload.len() < Self::MIN_PAYLOAD_SIZE {
            return Err(ProtocolError::MessageTooShort {
                expected: Self::MIN_PAYLOAD_SIZE,
                got: payload.len(),
            });
        }

        let mut pos = 0;

        // version
        let version = payload[pos];
        pos += 1;
        if version != Self::VERSION_1 {
            return Err(ProtocolError::UnsupportedVersion(version));
        }

        // sequence (8 LE)
        let sequence = u64::from_le_bytes(
            payload[pos..pos + 8]
                .try_into()
                .map_err(|_| ProtocolError::Malformed("bad sequence".into()))?,
        );
        pos += 8;

        // timestamp (8 LE)
        let timestamp = u64::from_le_bytes(
            payload[pos..pos + 8]
                .try_into()
                .map_err(|_| ProtocolError::Malformed("bad timestamp".into()))?,
        );
        pos += 8;

        // parent (16)
        let parent = NodeAddr::from_bytes(
            payload[pos..pos + 16]
                .try_into()
                .map_err(|_| ProtocolError::Malformed("bad parent".into()))?,
        );
        pos += 16;

        // ancestry_count (2 LE)
        let ancestry_count = u16::from_le_bytes(
            payload[pos..pos + 2]
                .try_into()
                .map_err(|_| ProtocolError::Malformed("bad ancestry count".into()))?,
        ) as usize;
        pos += 2;

        // Validate remaining length: entries + signature
        let expected_remaining = ancestry_count * CoordEntry::WIRE_SIZE + 64;
        if payload.len() - pos < expected_remaining {
            return Err(ProtocolError::MessageTooShort {
                expected: pos + expected_remaining,
                got: payload.len(),
            });
        }

        // ancestry entries (32 bytes each)
        let mut entries = Vec::with_capacity(ancestry_count);
        for _ in 0..ancestry_count {
            let node_addr = NodeAddr::from_bytes(
                payload[pos..pos + 16]
                    .try_into()
                    .map_err(|_| ProtocolError::Malformed("bad entry node_addr".into()))?,
            );
            pos += 16;
            let entry_seq = u64::from_le_bytes(
                payload[pos..pos + 8]
                    .try_into()
                    .map_err(|_| ProtocolError::Malformed("bad entry sequence".into()))?,
            );
            pos += 8;
            let entry_ts = u64::from_le_bytes(
                payload[pos..pos + 8]
                    .try_into()
                    .map_err(|_| ProtocolError::Malformed("bad entry timestamp".into()))?,
            );
            pos += 8;
            entries.push(CoordEntry::new(node_addr, entry_seq, entry_ts));
        }

        // signature (64)
        let sig_bytes: [u8; 64] = payload[pos..pos + 64]
            .try_into()
            .map_err(|_| ProtocolError::Malformed("bad signature".into()))?;
        let signature = Signature::from_slice(&sig_bytes)
            .map_err(|_| ProtocolError::InvalidSignature)?;

        // The first entry's node_addr is the declaring node
        if entries.is_empty() {
            return Err(ProtocolError::Malformed(
                "ancestry must have at least one entry".into(),
            ));
        }
        let node_addr = entries[0].node_addr;

        let declaration =
            ParentDeclaration::with_signature(node_addr, parent, sequence, timestamp, signature);

        let ancestry = TreeCoordinate::new(entries)
            .map_err(|e| ProtocolError::Malformed(format!("bad ancestry: {}", e)))?;

        Ok(Self {
            declaration,
            ancestry,
        })
    }
}

// ============ Bloom Filter Messages ============

/// Bloom filter announcement for reachability propagation.
///
/// Sent to peers to advertise which destinations are reachable.
///
/// ## Wire Format (v1)
///
/// | Offset | Field       | Size     | Notes                           |
/// |--------|-------------|----------|----------------------------------|
/// | 0      | msg_type    | 1 byte   | 0x20                            |
/// | 1      | sequence    | 8 bytes  | LE u64                          |
/// | 9      | hash_count  | 1 byte   | Number of hash functions        |
/// | 10     | size_class  | 1 byte   | Filter size: 512 << size_class  |
/// | 11     | filter_bits | variable | 512 << size_class bytes         |
#[derive(Clone, Debug)]
pub struct FilterAnnounce {
    /// The bloom filter contents.
    pub filter: BloomFilter,
    /// Sequence number for freshness/dedup.
    pub sequence: u64,
    /// Number of hash functions used by the filter.
    pub hash_count: u8,
    /// Size class: filter size in bytes = 512 << size_class.
    /// v1 protocol requires size_class=1 (1 KB filters).
    pub size_class: u8,
}

impl FilterAnnounce {
    /// Create a new FilterAnnounce message with v1 defaults.
    pub fn new(filter: BloomFilter, sequence: u64) -> Self {
        Self {
            hash_count: filter.hash_count(),
            size_class: crate::bloom::V1_SIZE_CLASS,
            filter,
            sequence,
        }
    }

    /// Create with explicit size_class (for testing or future protocol versions).
    pub fn with_size_class(
        filter: BloomFilter,
        sequence: u64,
        size_class: u8,
    ) -> Self {
        Self {
            hash_count: filter.hash_count(),
            size_class,
            filter,
            sequence,
        }
    }

    /// Get the expected filter size in bytes for this size_class.
    pub fn filter_size_bytes(&self) -> usize {
        512 << self.size_class
    }

    /// Validate the filter matches the declared size_class.
    pub fn is_valid(&self) -> bool {
        self.filter.num_bytes() == self.filter_size_bytes()
            && self.filter.hash_count() == self.hash_count
    }

    /// Check if this is a v1-compliant filter (size_class=1).
    pub fn is_v1_compliant(&self) -> bool {
        self.size_class == crate::bloom::V1_SIZE_CLASS
    }

    /// Minimum payload size after msg_type is stripped:
    /// sequence(8) + hash_count(1) + size_class(1) = 10
    const MIN_PAYLOAD_SIZE: usize = 10;

    /// Maximum allowed size_class value.
    const MAX_SIZE_CLASS: u8 = 3;

    /// Encode as link-layer plaintext (includes msg_type byte).
    ///
    /// ```text
    /// [0x20][sequence:8 LE][hash_count:1][size_class:1][filter_bits:variable]
    /// ```
    pub fn encode(&self) -> Result<Vec<u8>, ProtocolError> {
        if !self.is_valid() {
            return Err(ProtocolError::Malformed(
                "filter size does not match size_class".into(),
            ));
        }

        let filter_bytes = self.filter.as_bytes();
        let size = 1 + Self::MIN_PAYLOAD_SIZE + filter_bytes.len();
        let mut buf = Vec::with_capacity(size);

        // msg_type
        buf.push(LinkMessageType::FilterAnnounce.to_byte());
        // sequence (8 LE)
        buf.extend_from_slice(&self.sequence.to_le_bytes());
        // hash_count
        buf.push(self.hash_count);
        // size_class
        buf.push(self.size_class);
        // filter_bits
        buf.extend_from_slice(filter_bytes);

        Ok(buf)
    }

    /// Decode from link-layer payload (after msg_type byte stripped by dispatcher).
    ///
    /// The payload starts with the sequence field.
    pub fn decode(payload: &[u8]) -> Result<Self, ProtocolError> {
        if payload.len() < Self::MIN_PAYLOAD_SIZE {
            return Err(ProtocolError::MessageTooShort {
                expected: Self::MIN_PAYLOAD_SIZE,
                got: payload.len(),
            });
        }

        let mut pos = 0;

        // sequence (8 LE)
        let sequence = u64::from_le_bytes(
            payload[pos..pos + 8]
                .try_into()
                .map_err(|_| ProtocolError::Malformed("bad sequence".into()))?,
        );
        pos += 8;

        // hash_count
        let hash_count = payload[pos];
        pos += 1;

        // size_class
        let size_class = payload[pos];
        pos += 1;

        // Validate size_class range
        if size_class > Self::MAX_SIZE_CLASS {
            return Err(ProtocolError::Malformed(format!(
                "invalid size_class: {size_class} (max {})",
                Self::MAX_SIZE_CLASS
            )));
        }

        // v1 compliance check
        if size_class != crate::bloom::V1_SIZE_CLASS {
            return Err(ProtocolError::Malformed(format!(
                "unsupported size_class: {size_class} (v1 requires {})",
                crate::bloom::V1_SIZE_CLASS
            )));
        }

        // Expected filter size from size_class
        let expected_filter_bytes = 512usize << size_class;
        let remaining = payload.len() - pos;
        if remaining != expected_filter_bytes {
            return Err(ProtocolError::MessageTooShort {
                expected: Self::MIN_PAYLOAD_SIZE + expected_filter_bytes,
                got: payload.len(),
            });
        }

        // Construct BloomFilter from bytes
        let filter =
            crate::bloom::BloomFilter::from_slice(&payload[pos..], hash_count).map_err(|e| {
                ProtocolError::Malformed(format!("invalid bloom filter: {e}"))
            })?;

        let announce = Self {
            filter,
            sequence,
            hash_count,
            size_class,
        };

        Ok(announce)
    }
}

// ============ Discovery Messages ============

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

// ============ Session Datagram (Link-Layer Encapsulation) ============

/// Encapsulated session-layer datagram for forwarding.
///
/// This is a link-layer message that carries an opaque, end-to-end encrypted
/// session-layer payload. Intermediate nodes route based on the destination
/// address but cannot decrypt the payload.
#[derive(Clone, Debug)]
pub struct SessionDatagram {
    /// Destination node address (for routing decisions).
    pub dest_addr: NodeAddr,
    /// Hop limit (decremented at each hop).
    pub hop_limit: u8,
    /// Encrypted session-layer payload (opaque to intermediate nodes).
    pub payload: Vec<u8>,
}

impl SessionDatagram {
    /// Create a new session datagram.
    pub fn new(dest_addr: NodeAddr, payload: Vec<u8>) -> Self {
        Self {
            dest_addr,
            hop_limit: 64,
            payload,
        }
    }

    /// Set the hop limit.
    pub fn with_hop_limit(mut self, hop_limit: u8) -> Self {
        self.hop_limit = hop_limit;
        self
    }

    /// Decrement hop limit, returning false if exhausted.
    pub fn decrement_hop_limit(&mut self) -> bool {
        if self.hop_limit > 0 {
            self.hop_limit -= 1;
            true
        } else {
            false
        }
    }

    /// Check if the datagram can be forwarded.
    pub fn can_forward(&self) -> bool {
        self.hop_limit > 0
    }
}

// ============================================================================
// Session Layer Messages (end-to-end, between FIPS addresses)
// ============================================================================

/// Session flags for setup options.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct SessionFlags {
    /// Request acknowledgement from destination.
    pub request_ack: bool,
    /// Set up bidirectional session.
    pub bidirectional: bool,
}

impl SessionFlags {
    /// Create default flags.
    pub fn new() -> Self {
        Self::default()
    }

    /// Set request_ack flag.
    pub fn with_ack(mut self) -> Self {
        self.request_ack = true;
        self
    }

    /// Set bidirectional flag.
    pub fn bidirectional(mut self) -> Self {
        self.bidirectional = true;
        self
    }

    /// Convert to a byte.
    pub fn to_byte(&self) -> u8 {
        let mut flags = 0u8;
        if self.request_ack {
            flags |= 0x01;
        }
        if self.bidirectional {
            flags |= 0x02;
        }
        flags
    }

    /// Convert from a byte.
    pub fn from_byte(byte: u8) -> Self {
        Self {
            request_ack: byte & 0x01 != 0,
            bidirectional: byte & 0x02 != 0,
        }
    }
}

/// Session setup to establish cached coordinate state.
///
/// Sent before data packets to warm router caches with coordinate
/// information. Routers along the path cache the mappings.
#[derive(Clone, Debug)]
pub struct SessionSetup {
    /// Source node address.
    pub src_addr: NodeAddr,
    /// Destination node address.
    pub dest_addr: NodeAddr,
    /// Source coordinates (for return path caching).
    pub src_coords: TreeCoordinate,
    /// Destination coordinates (for forward routing).
    pub dest_coords: TreeCoordinate,
    /// Session options.
    pub flags: SessionFlags,
}

impl SessionSetup {
    /// Create a new session setup message.
    pub fn new(
        src_addr: NodeAddr,
        dest_addr: NodeAddr,
        src_coords: TreeCoordinate,
        dest_coords: TreeCoordinate,
    ) -> Self {
        Self {
            src_addr,
            dest_addr,
            src_coords,
            dest_coords,
            flags: SessionFlags::new(),
        }
    }

    /// Set session flags.
    pub fn with_flags(mut self, flags: SessionFlags) -> Self {
        self.flags = flags;
        self
    }
}

/// Session acknowledgement.
///
/// Sent in response to SessionSetup when request_ack is set.
#[derive(Clone, Debug)]
pub struct SessionAck {
    /// Source node address (the acknowledger).
    pub src_addr: NodeAddr,
    /// Destination node address (original session initiator).
    pub dest_addr: NodeAddr,
    /// Acknowledger's coordinates.
    pub src_coords: TreeCoordinate,
}

impl SessionAck {
    /// Create a new session acknowledgement.
    pub fn new(src_addr: NodeAddr, dest_addr: NodeAddr, src_coords: TreeCoordinate) -> Self {
        Self {
            src_addr,
            dest_addr,
            src_coords,
        }
    }
}

// ============ Data Messages ============

/// Data packet flags.
///
/// ## Flag Bits
///
/// | Bit | Name           | Description                              |
/// |-----|----------------|------------------------------------------|
/// | 0   | COORDS_PRESENT | Coordinates follow the fixed header      |
/// | 1-7 | reserved       | Reserved for future use                  |
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct DataFlags {
    /// When set, source and destination coordinates follow the header.
    /// Used to warm router caches after receiving CoordsRequired.
    pub coords_present: bool,
    /// Reserved bits (preserved for forward compatibility).
    reserved: u8,
}

/// Bit 0: coordinates follow the header.
pub const DATA_FLAG_COORDS_PRESENT: u8 = 0x01;

impl DataFlags {
    /// Create default flags (no coordinates).
    pub fn new() -> Self {
        Self::default()
    }

    /// Create flags with COORDS_PRESENT set.
    pub fn with_coords() -> Self {
        Self {
            coords_present: true,
            reserved: 0,
        }
    }

    /// Set the coords_present flag.
    pub fn set_coords_present(&mut self, value: bool) {
        self.coords_present = value;
    }

    /// Convert to a byte.
    pub fn to_byte(&self) -> u8 {
        let mut flags = self.reserved & !DATA_FLAG_COORDS_PRESENT;
        if self.coords_present {
            flags |= DATA_FLAG_COORDS_PRESENT;
        }
        flags
    }

    /// Convert from a byte.
    pub fn from_byte(byte: u8) -> Self {
        Self {
            coords_present: byte & DATA_FLAG_COORDS_PRESENT != 0,
            reserved: byte & !DATA_FLAG_COORDS_PRESENT,
        }
    }
}

/// Minimal data packet with addresses only (no coordinates).
///
/// The 36-byte header contains:
/// - flags (1 byte)
/// - hop_limit (1 byte)
/// - payload_length (2 bytes)
/// - src_addr (16 bytes)
/// - dest_addr (16 bytes)
///
/// Routers use cached coordinates for routing decisions.
#[derive(Clone, Debug)]
pub struct DataPacket {
    /// Packet flags.
    pub flags: DataFlags,
    /// Hop limit (TTL).
    pub hop_limit: u8,
    /// Source node address.
    pub src_addr: NodeAddr,
    /// Destination node address.
    pub dest_addr: NodeAddr,
    /// Payload data.
    pub payload: Vec<u8>,
}

impl DataPacket {
    /// Create a new data packet.
    pub fn new(src_addr: NodeAddr, dest_addr: NodeAddr, payload: Vec<u8>) -> Self {
        Self {
            flags: DataFlags::new(),
            hop_limit: 64,
            src_addr,
            dest_addr,
            payload,
        }
    }

    /// Set the hop limit.
    pub fn with_hop_limit(mut self, hop_limit: u8) -> Self {
        self.hop_limit = hop_limit;
        self
    }

    /// Set the flags.
    pub fn with_flags(mut self, flags: DataFlags) -> Self {
        self.flags = flags;
        self
    }

    /// Decrement hop limit, returning false if exhausted.
    pub fn decrement_hop_limit(&mut self) -> bool {
        if self.hop_limit > 0 {
            self.hop_limit -= 1;
            true
        } else {
            false
        }
    }

    /// Check if the packet can be forwarded.
    pub fn can_forward(&self) -> bool {
        self.hop_limit > 0
    }

    /// Get the payload length.
    pub fn payload_len(&self) -> usize {
        self.payload.len()
    }

    /// Total packet size (header + payload).
    pub fn total_size(&self) -> usize {
        DATA_HEADER_SIZE + self.payload.len()
    }

    /// Header size in bytes.
    pub fn header_size(&self) -> usize {
        DATA_HEADER_SIZE
    }
}

// ============ Error Messages ============

/// Error indicating router cache miss - needs coordinates.
///
/// Sent back to the source when a router doesn't have cached
/// coordinates for the destination.
#[derive(Clone, Debug)]
pub struct CoordsRequired {
    /// Destination that couldn't be routed.
    pub dest_addr: NodeAddr,
    /// Router reporting the miss.
    pub reporter: NodeAddr,
}

impl CoordsRequired {
    /// Create a new CoordsRequired error.
    pub fn new(dest_addr: NodeAddr, reporter: NodeAddr) -> Self {
        Self { dest_addr, reporter }
    }
}

/// Error indicating routing failure (local minimum or unreachable).
///
/// Sent back to the source when greedy routing fails.
#[derive(Clone, Debug)]
pub struct PathBroken {
    /// Original source of the failed packet.
    pub original_src: NodeAddr,
    /// Destination that couldn't be reached.
    pub dest_addr: NodeAddr,
    /// Node that detected the failure.
    pub reporter: NodeAddr,
    /// Optional: last known coordinates of destination.
    pub last_known_coords: Option<TreeCoordinate>,
}

impl PathBroken {
    /// Create a new PathBroken error.
    pub fn new(original_src: NodeAddr, dest_addr: NodeAddr, reporter: NodeAddr) -> Self {
        Self {
            original_src,
            dest_addr,
            reporter,
            last_known_coords: None,
        }
    }

    /// Add last known coordinates.
    pub fn with_last_coords(mut self, coords: TreeCoordinate) -> Self {
        self.last_known_coords = Some(coords);
        self
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

    // ===== HandshakeMessageType Tests =====

    #[test]
    fn test_handshake_message_type_roundtrip() {
        let types = [
            HandshakeMessageType::NoiseIKMsg1,
            HandshakeMessageType::NoiseIKMsg2,
        ];

        for ty in types {
            let byte = ty.to_byte();
            let restored = HandshakeMessageType::from_byte(byte);
            assert_eq!(restored, Some(ty));
        }
    }

    #[test]
    fn test_handshake_message_type_invalid() {
        assert!(HandshakeMessageType::from_byte(0x00).is_none());
        assert!(HandshakeMessageType::from_byte(0x03).is_none());
        assert!(HandshakeMessageType::from_byte(0x10).is_none());
    }

    #[test]
    fn test_handshake_message_type_is_handshake() {
        assert!(HandshakeMessageType::is_handshake(0x01));
        assert!(HandshakeMessageType::is_handshake(0x02));
        assert!(!HandshakeMessageType::is_handshake(0x00));
        assert!(!HandshakeMessageType::is_handshake(0x10));
    }

    // ===== LinkMessageType Tests =====

    #[test]
    fn test_link_message_type_roundtrip() {
        let types = [
            LinkMessageType::TreeAnnounce,
            LinkMessageType::FilterAnnounce,
            LinkMessageType::LookupRequest,
            LinkMessageType::LookupResponse,
            LinkMessageType::SessionDatagram,
            LinkMessageType::Disconnect,
        ];

        for ty in types {
            let byte = ty.to_byte();
            let restored = LinkMessageType::from_byte(byte);
            assert_eq!(restored, Some(ty));
        }
    }

    #[test]
    fn test_link_message_type_invalid() {
        assert!(LinkMessageType::from_byte(0xFF).is_none());
        assert!(LinkMessageType::from_byte(0x00).is_none());
    }

    // ===== DisconnectReason Tests =====

    #[test]
    fn test_disconnect_reason_roundtrip() {
        let reasons = [
            DisconnectReason::Shutdown,
            DisconnectReason::Restart,
            DisconnectReason::ProtocolError,
            DisconnectReason::TransportFailure,
            DisconnectReason::ResourceExhaustion,
            DisconnectReason::SecurityViolation,
            DisconnectReason::ConfigurationChange,
            DisconnectReason::Timeout,
            DisconnectReason::Other,
        ];

        for reason in reasons {
            let byte = reason.to_byte();
            let restored = DisconnectReason::from_byte(byte);
            assert_eq!(restored, Some(reason));
        }
    }

    #[test]
    fn test_disconnect_reason_unknown_byte() {
        // Unrecognized bytes return None
        assert!(DisconnectReason::from_byte(0x08).is_none());
        assert!(DisconnectReason::from_byte(0x80).is_none());
        assert!(DisconnectReason::from_byte(0xFE).is_none());
    }

    // ===== Disconnect Message Tests =====

    #[test]
    fn test_disconnect_encode_decode() {
        let msg = Disconnect::new(DisconnectReason::Shutdown);
        let encoded = msg.encode();

        assert_eq!(encoded.len(), 2);
        assert_eq!(encoded[0], 0x50); // LinkMessageType::Disconnect
        assert_eq!(encoded[1], 0x00); // DisconnectReason::Shutdown

        // Decode from payload (after msg_type byte)
        let decoded = Disconnect::decode(&encoded[1..]).unwrap();
        assert_eq!(decoded.reason, DisconnectReason::Shutdown);
    }

    #[test]
    fn test_disconnect_all_reasons() {
        let reasons = [
            DisconnectReason::Shutdown,
            DisconnectReason::Restart,
            DisconnectReason::ProtocolError,
            DisconnectReason::Other,
        ];

        for reason in reasons {
            let msg = Disconnect::new(reason);
            let encoded = msg.encode();
            let decoded = Disconnect::decode(&encoded[1..]).unwrap();
            assert_eq!(decoded.reason, reason);
        }
    }

    #[test]
    fn test_disconnect_decode_empty_payload() {
        let result = Disconnect::decode(&[]);
        assert!(result.is_err());
    }

    #[test]
    fn test_disconnect_decode_unknown_reason() {
        // Unknown reason codes fall back to Other
        let decoded = Disconnect::decode(&[0x80]).unwrap();
        assert_eq!(decoded.reason, DisconnectReason::Other);
    }

    // ===== SessionMessageType Tests =====

    #[test]
    fn test_session_message_type_roundtrip() {
        let types = [
            SessionMessageType::SessionSetup,
            SessionMessageType::SessionAck,
            SessionMessageType::DataPacket,
            SessionMessageType::CoordsRequired,
            SessionMessageType::PathBroken,
        ];

        for ty in types {
            let byte = ty.to_byte();
            let restored = SessionMessageType::from_byte(byte);
            assert_eq!(restored, Some(ty));
        }
    }

    #[test]
    fn test_session_message_type_invalid() {
        assert!(SessionMessageType::from_byte(0xFF).is_none());
        assert!(SessionMessageType::from_byte(0x99).is_none());
    }

    // ===== SessionFlags Tests =====

    #[test]
    fn test_session_flags() {
        let flags = SessionFlags::new().with_ack().bidirectional();

        assert!(flags.request_ack);
        assert!(flags.bidirectional);

        let byte = flags.to_byte();
        let restored = SessionFlags::from_byte(byte);

        assert_eq!(flags, restored);
    }

    #[test]
    fn test_session_flags_default() {
        let flags = SessionFlags::new();
        assert!(!flags.request_ack);
        assert!(!flags.bidirectional);
        assert_eq!(flags.to_byte(), 0);
    }

    // ===== DataPacket Tests =====

    #[test]
    fn test_data_packet_size() {
        let packet = DataPacket::new(make_node_addr(1), make_node_addr(2), vec![0u8; 100]);

        // 36 byte header + 100 byte payload
        assert_eq!(packet.total_size(), 136);
        assert_eq!(packet.header_size(), 36);
        assert_eq!(packet.payload_len(), 100);
    }

    #[test]
    fn test_data_packet_hop_limit() {
        let mut packet = DataPacket::new(make_node_addr(1), make_node_addr(2), vec![]);

        packet.hop_limit = 2;
        assert!(packet.can_forward());

        assert!(packet.decrement_hop_limit());
        assert_eq!(packet.hop_limit, 1);

        assert!(packet.decrement_hop_limit());
        assert_eq!(packet.hop_limit, 0);
        assert!(!packet.can_forward());

        assert!(!packet.decrement_hop_limit());
        assert_eq!(packet.hop_limit, 0);
    }

    #[test]
    fn test_data_packet_builder() {
        let packet = DataPacket::new(make_node_addr(1), make_node_addr(2), vec![1, 2, 3])
            .with_hop_limit(32)
            .with_flags(DataFlags::from_byte(0x80));

        assert_eq!(packet.hop_limit, 32);
        assert_eq!(packet.flags.to_byte(), 0x80);
    }

    #[test]
    fn test_data_flags_coords_present() {
        // Default: no coords
        let flags = DataFlags::new();
        assert!(!flags.coords_present);
        assert_eq!(flags.to_byte(), 0x00);

        // With coords
        let flags = DataFlags::with_coords();
        assert!(flags.coords_present);
        assert_eq!(flags.to_byte(), 0x01);

        // Round-trip preserves flag
        let flags = DataFlags::from_byte(0x01);
        assert!(flags.coords_present);
        assert_eq!(flags.to_byte(), 0x01);

        // Reserved bits preserved
        let flags = DataFlags::from_byte(0x81); // coords + reserved bit 7
        assert!(flags.coords_present);
        assert_eq!(flags.to_byte(), 0x81);

        // Coords bit toggles independently
        let flags = DataFlags::from_byte(0x80); // only reserved bit 7
        assert!(!flags.coords_present);
        assert_eq!(flags.to_byte(), 0x80);
    }

    // ===== LookupRequest Tests =====

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

    // ===== LookupResponse Tests =====

    #[test]
    fn test_lookup_response_proof_bytes() {
        let target = make_node_addr(42);
        let bytes = LookupResponse::proof_bytes(12345, &target);

        assert_eq!(bytes.len(), 24); // 8 + 16
        assert_eq!(&bytes[0..8], &12345u64.to_le_bytes());
        assert_eq!(&bytes[8..24], target.as_bytes());
    }

    // ===== FilterAnnounce Tests =====

    #[test]
    fn test_filter_announce_size_class() {
        let filter = BloomFilter::new();
        let announce = FilterAnnounce::new(filter.clone(), 100);

        // v1 defaults
        assert_eq!(announce.size_class, 1);
        assert_eq!(announce.hash_count, 5);
        assert!(announce.is_v1_compliant());
        assert!(announce.is_valid());
        assert_eq!(announce.filter_size_bytes(), 1024);
    }

    #[test]
    fn test_filter_announce_with_size_class() {
        let filter = BloomFilter::with_params(2048 * 8, 7).unwrap();
        let announce = FilterAnnounce::with_size_class(filter, 100, 2);

        assert_eq!(announce.size_class, 2);
        assert_eq!(announce.hash_count, 7);
        assert!(!announce.is_v1_compliant());
        assert!(announce.is_valid());
        assert_eq!(announce.filter_size_bytes(), 2048);
    }

    #[test]
    fn test_filter_announce_encode_decode_roundtrip() {
        let mut filter = BloomFilter::new();
        filter.insert(&make_node_addr(42));
        filter.insert(&make_node_addr(99));
        let announce = FilterAnnounce::new(filter, 500);

        let encoded = announce.encode().unwrap();
        // msg_type(1) + sequence(8) + hash_count(1) + size_class(1) + filter(1024)
        assert_eq!(encoded.len(), 1035);
        assert_eq!(encoded[0], LinkMessageType::FilterAnnounce.to_byte());

        // Decode strips msg_type (as dispatcher does)
        let decoded = FilterAnnounce::decode(&encoded[1..]).unwrap();
        assert_eq!(decoded.sequence, 500);
        assert_eq!(decoded.hash_count, 5);
        assert_eq!(decoded.size_class, 1);
        assert!(decoded.is_valid());
        assert!(decoded.is_v1_compliant());

        // Filter contents preserved
        assert!(decoded.filter.contains(&make_node_addr(42)));
        assert!(decoded.filter.contains(&make_node_addr(99)));
        assert!(!decoded.filter.contains(&make_node_addr(1)));
    }

    #[test]
    fn test_filter_announce_decode_rejects_bad_size_class() {
        let filter = BloomFilter::new();
        let announce = FilterAnnounce::new(filter, 100);
        let mut encoded = announce.encode().unwrap();

        // Corrupt size_class byte (offset: 1 msg_type + 8 seq + 1 hash = 10)
        encoded[10] = 5; // invalid size_class > MAX_SIZE_CLASS

        let result = FilterAnnounce::decode(&encoded[1..]);
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("invalid size_class"));
    }

    #[test]
    fn test_filter_announce_decode_rejects_non_v1_size_class() {
        // Build a size_class=0 payload manually (valid range but not v1)
        let filter = BloomFilter::with_params(512 * 8, 5).unwrap();
        let announce = FilterAnnounce::with_size_class(filter, 100, 0);
        let encoded = announce.encode().unwrap();

        let result = FilterAnnounce::decode(&encoded[1..]);
        assert!(result.is_err());
        assert!(result
            .unwrap_err()
            .to_string()
            .contains("unsupported size_class"));
    }

    #[test]
    fn test_filter_announce_decode_rejects_truncated() {
        let result = FilterAnnounce::decode(&[0u8; 5]);
        assert!(result.is_err());
    }

    // ===== SessionSetup Tests =====

    #[test]
    fn test_session_setup() {
        let setup = SessionSetup::new(
            make_node_addr(1),
            make_node_addr(2),
            make_coords(&[1, 0]),
            make_coords(&[2, 0]),
        )
        .with_flags(SessionFlags::new().with_ack());

        assert!(setup.flags.request_ack);
        assert!(!setup.flags.bidirectional);
    }

    // ===== CoordsRequired Tests =====

    #[test]
    fn test_coords_required() {
        let err = CoordsRequired::new(make_node_addr(1), make_node_addr(2));

        assert_eq!(err.dest_addr, make_node_addr(1));
        assert_eq!(err.reporter, make_node_addr(2));
    }

    // ===== PathBroken Tests =====

    #[test]
    fn test_path_broken() {
        let err = PathBroken::new(make_node_addr(1), make_node_addr(2), make_node_addr(3))
            .with_last_coords(make_coords(&[2, 0]));

        assert!(err.last_known_coords.is_some());
    }

    // ===== TreeAnnounce Tests =====

    #[test]
    fn test_tree_announce() {
        let node = make_node_addr(1);
        let parent = make_node_addr(2);
        let decl = ParentDeclaration::new(node, parent, 1, 1000);
        let ancestry = make_coords(&[1, 2, 0]);

        let announce = TreeAnnounce::new(decl, ancestry);

        assert_eq!(announce.declaration.node_addr(), &node);
        assert_eq!(announce.ancestry.depth(), 2);
    }

    #[test]
    fn test_tree_announce_encode_decode_root() {
        use crate::identity::Identity;

        let identity = Identity::generate();
        let node_addr = *identity.node_addr();

        // Root declaration: parent == self
        let mut decl = ParentDeclaration::new(node_addr, node_addr, 1, 5000);
        decl.sign(&identity).unwrap();

        // Root ancestry: just the root itself
        let ancestry = TreeCoordinate::new(vec![CoordEntry::new(node_addr, 1, 5000)]).unwrap();

        let announce = TreeAnnounce::new(decl, ancestry);
        let encoded = announce.encode().unwrap();

        // msg_type (1) + version (1) + seq (8) + ts (8) + parent (16) + count (2) + 1 entry (32) + sig (64) = 132
        assert_eq!(encoded.len(), 132);
        assert_eq!(encoded[0], 0x10); // LinkMessageType::TreeAnnounce

        // Decode strips msg_type byte (as dispatcher does)
        let decoded = TreeAnnounce::decode(&encoded[1..]).unwrap();

        assert_eq!(decoded.declaration.node_addr(), &node_addr);
        assert_eq!(decoded.declaration.parent_id(), &node_addr);
        assert_eq!(decoded.declaration.sequence(), 1);
        assert_eq!(decoded.declaration.timestamp(), 5000);
        assert!(decoded.declaration.is_root());
        assert!(decoded.declaration.is_signed());
        assert_eq!(decoded.ancestry.depth(), 0); // root has depth 0
        assert_eq!(decoded.ancestry.entries().len(), 1);
        assert_eq!(decoded.ancestry.entries()[0].node_addr, node_addr);
        assert_eq!(decoded.ancestry.entries()[0].sequence, 1);
        assert_eq!(decoded.ancestry.entries()[0].timestamp, 5000);
    }

    #[test]
    fn test_tree_announce_encode_decode_depth3() {
        use crate::identity::Identity;

        let identity = Identity::generate();
        let node_addr = *identity.node_addr();
        let parent = make_node_addr(2);
        let grandparent = make_node_addr(3);
        let root = make_node_addr(4);

        let mut decl = ParentDeclaration::new(node_addr, parent, 5, 10000);
        decl.sign(&identity).unwrap();

        let ancestry = TreeCoordinate::new(vec![
            CoordEntry::new(node_addr, 5, 10000),
            CoordEntry::new(parent, 4, 9000),
            CoordEntry::new(grandparent, 3, 8000),
            CoordEntry::new(root, 2, 7000),
        ])
        .unwrap();

        let announce = TreeAnnounce::new(decl, ancestry);
        let encoded = announce.encode().unwrap();

        // 1 + 99 + 4*32 = 228
        assert_eq!(encoded.len(), 228);

        let decoded = TreeAnnounce::decode(&encoded[1..]).unwrap();

        assert_eq!(decoded.declaration.node_addr(), &node_addr);
        assert_eq!(decoded.declaration.parent_id(), &parent);
        assert_eq!(decoded.declaration.sequence(), 5);
        assert_eq!(decoded.declaration.timestamp(), 10000);
        assert!(!decoded.declaration.is_root());
        assert_eq!(decoded.ancestry.depth(), 3);
        assert_eq!(decoded.ancestry.entries().len(), 4);

        // Verify all entries preserved
        let entries = decoded.ancestry.entries();
        assert_eq!(entries[0].node_addr, node_addr);
        assert_eq!(entries[0].sequence, 5);
        assert_eq!(entries[1].node_addr, parent);
        assert_eq!(entries[1].sequence, 4);
        assert_eq!(entries[2].node_addr, grandparent);
        assert_eq!(entries[2].timestamp, 8000);
        assert_eq!(entries[3].node_addr, root);
        assert_eq!(entries[3].timestamp, 7000);

        // Root ID is last entry
        assert_eq!(decoded.ancestry.root_id(), &root);
    }

    #[test]
    fn test_tree_announce_decode_unsupported_version() {
        use crate::identity::Identity;

        let identity = Identity::generate();
        let node_addr = *identity.node_addr();

        let mut decl = ParentDeclaration::new(node_addr, node_addr, 1, 1000);
        decl.sign(&identity).unwrap();

        let ancestry = TreeCoordinate::new(vec![CoordEntry::new(node_addr, 1, 1000)]).unwrap();
        let announce = TreeAnnounce::new(decl, ancestry);
        let mut encoded = announce.encode().unwrap();

        // Corrupt version byte (byte index 1, after msg_type)
        encoded[1] = 0xFF;

        let result = TreeAnnounce::decode(&encoded[1..]);
        assert!(matches!(result, Err(ProtocolError::UnsupportedVersion(0xFF))));
    }

    #[test]
    fn test_tree_announce_decode_truncated() {
        // Way too short
        let result = TreeAnnounce::decode(&[0x01]);
        assert!(matches!(
            result,
            Err(ProtocolError::MessageTooShort { expected: 99, .. })
        ));

        // Just under minimum (98 bytes)
        let short = vec![0u8; 98];
        let result = TreeAnnounce::decode(&short);
        assert!(matches!(
            result,
            Err(ProtocolError::MessageTooShort { expected: 99, .. })
        ));
    }

    #[test]
    fn test_tree_announce_decode_ancestry_count_mismatch() {
        use crate::identity::Identity;

        let identity = Identity::generate();
        let node_addr = *identity.node_addr();

        let mut decl = ParentDeclaration::new(node_addr, node_addr, 1, 1000);
        decl.sign(&identity).unwrap();

        let ancestry = TreeCoordinate::new(vec![CoordEntry::new(node_addr, 1, 1000)]).unwrap();
        let announce = TreeAnnounce::new(decl, ancestry);
        let mut encoded = announce.encode().unwrap();

        // The ancestry_count is at offset: 1 (msg_type) + 1 (version) + 8 (seq) + 8 (ts) + 16 (parent) = 34
        // Set ancestry_count to 5 but we only have 1 entry's worth of data
        encoded[34] = 5;
        encoded[35] = 0;

        let result = TreeAnnounce::decode(&encoded[1..]);
        assert!(matches!(
            result,
            Err(ProtocolError::MessageTooShort { .. })
        ));
    }

    #[test]
    fn test_tree_announce_encode_unsigned_fails() {
        let node = make_node_addr(1);
        let decl = ParentDeclaration::new(node, node, 1, 1000);
        let ancestry = make_coords(&[1, 0]);

        let announce = TreeAnnounce::new(decl, ancestry);
        let result = announce.encode();
        assert!(matches!(result, Err(ProtocolError::InvalidSignature)));
    }
}
