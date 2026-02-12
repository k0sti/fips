//! Session-layer message types: setup, ack, data, and error messages.

use crate::tree::TreeCoordinate;
use crate::NodeAddr;
use std::fmt;

// ============================================================================
// Session Layer Message Types
// ============================================================================

/// SessionDatagram payload message type identifiers.
///
/// These messages are carried as payloads inside `SessionDatagram` (link
/// message type 0x40). Session-layer messages (SessionSetup, SessionAck,
/// DataPacket) are end-to-end encrypted with session keys. Error signals
/// (CoordsRequired, PathBroken) are plaintext link-layer messages generated
/// by transit routers that cannot establish e2e sessions with the source.
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

    // Link-layer error signals (0x20-0x2F) — plaintext, from transit routers
    /// Router cache miss — needs coordinates (link-layer error signal).
    CoordsRequired = 0x20,
    /// Routing failure — local minimum or unreachable (link-layer error signal).
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
/// Carried inside a SessionDatagram envelope which provides src_addr and
/// dest_addr. The SessionSetup payload contains only coordinates and the
/// Noise handshake data needed for route cache warming and session
/// establishment.
#[derive(Clone, Debug)]
pub struct SessionSetup {
    /// Source coordinates (for return path caching).
    pub src_coords: TreeCoordinate,
    /// Destination coordinates (for forward routing).
    pub dest_coords: TreeCoordinate,
    /// Session options.
    pub flags: SessionFlags,
}

impl SessionSetup {
    /// Create a new session setup message.
    pub fn new(src_coords: TreeCoordinate, dest_coords: TreeCoordinate) -> Self {
        Self {
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
/// Carried inside a SessionDatagram envelope which provides src_addr and
/// dest_addr. The SessionAck payload contains the acknowledger's coordinates
/// for route cache warming.
#[derive(Clone, Debug)]
pub struct SessionAck {
    /// Acknowledger's coordinates.
    pub src_coords: TreeCoordinate,
}

impl SessionAck {
    /// Create a new session acknowledgement.
    pub fn new(src_coords: TreeCoordinate) -> Self {
        Self { src_coords }
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

/// DataPacket header size in bytes (excluding payload).
/// msg_type(1) + flags(1) + payload_length(2) = 4
/// (Addressing and hop_limit are in the SessionDatagram envelope.)
pub const DATA_HEADER_SIZE: usize = 4;

/// Encrypted application data carried inside a SessionDatagram.
///
/// The 4-byte header contains:
/// - msg_type (1 byte): 0x10
/// - flags (1 byte): COORDS_PRESENT, etc.
/// - payload_length (2 bytes)
///
/// Addressing (src_addr, dest_addr) and hop_limit are provided by the
/// enclosing SessionDatagram envelope. The total on-wire overhead for a
/// minimal data packet is 34 (SessionDatagram) + 4 (DataPacket) = 38 bytes.
#[derive(Clone, Debug)]
pub struct DataPacket {
    /// Packet flags.
    pub flags: DataFlags,
    /// Payload data (end-to-end encrypted application data).
    pub payload: Vec<u8>,
}

impl DataPacket {
    /// Create a new data packet.
    pub fn new(payload: Vec<u8>) -> Self {
        Self {
            flags: DataFlags::new(),
            payload,
        }
    }

    /// Set the flags.
    pub fn with_flags(mut self, flags: DataFlags) -> Self {
        self.flags = flags;
        self
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

/// Link-layer error signal indicating router cache miss.
///
/// Generated by a transit router when it cannot forward a SessionDatagram
/// due to missing cached coordinates for the destination. Carried inside
/// a new SessionDatagram addressed back to the original source
/// (src_addr=reporter, dest_addr=original_source). Plaintext — not
/// end-to-end encrypted, since the transit router has no session with
/// the source.
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
/// Carried inside a SessionDatagram addressed back to the original source.
/// The reporting router creates a new SessionDatagram with src_addr=reporter
/// and dest_addr=original_source, so the `original_src` field from the old
/// design is no longer needed — it's the SessionDatagram's dest_addr.
#[derive(Clone, Debug)]
pub struct PathBroken {
    /// Destination that couldn't be reached.
    pub dest_addr: NodeAddr,
    /// Node that detected the failure.
    pub reporter: NodeAddr,
    /// Optional: last known coordinates of destination.
    pub last_known_coords: Option<TreeCoordinate>,
}

impl PathBroken {
    /// Create a new PathBroken error.
    pub fn new(dest_addr: NodeAddr, reporter: NodeAddr) -> Self {
        Self {
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
        let packet = DataPacket::new(vec![0u8; 100]);

        // 4 byte header + 100 byte payload
        assert_eq!(packet.total_size(), 104);
        assert_eq!(packet.header_size(), 4);
        assert_eq!(packet.payload_len(), 100);
    }

    #[test]
    fn test_data_packet_builder() {
        let packet = DataPacket::new(vec![1, 2, 3])
            .with_flags(DataFlags::from_byte(0x80));

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
        let setup = SessionSetup::new(make_coords(&[1, 0]), make_coords(&[2, 0]))
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
        let err = PathBroken::new(make_node_addr(2), make_node_addr(3))
            .with_last_coords(make_coords(&[2, 0]));

        assert_eq!(err.dest_addr, make_node_addr(2));
        assert_eq!(err.reporter, make_node_addr(3));
        assert!(err.last_known_coords.is_some());
    }
}
