//! Session-layer message types: setup, ack, data, and error messages.

use crate::tree::TreeCoordinate;
use crate::NodeAddr;
use std::fmt;

// ============================================================================
// Session Layer Message Types
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

// ============================================================================
// Session Flags
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

// ============================================================================
// Session Setup
// ============================================================================

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

// ============================================================================
// Session Ack
// ============================================================================

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

// ============================================================================
// Data Messages
// ============================================================================

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

/// Data packet header size in bytes (excluding payload).
/// flags(1) + hop_limit(1) + payload_length(2) + src_addr(16) + dest_addr(16) = 36
pub const DATA_HEADER_SIZE: usize = 36;

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

// ============================================================================
// Error Messages
// ============================================================================

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
}
