//! Link-layer message types: handshake, link control, disconnect, session datagram.

use super::ProtocolError;
use crate::NodeAddr;
use std::fmt;

// ============================================================================
// Handshake Message Types
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
// Session Datagram (Link-Layer Encapsulation)
// ============================================================================

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

// Legacy type alias for compatibility during transition
#[deprecated(note = "Use LinkMessageType or SessionMessageType instead")]
pub type MessageType = LinkMessageType;

#[cfg(test)]
mod tests {
    use super::*;

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
        let decoded = Disconnect::decode(&[0x80]).unwrap();
        assert_eq!(decoded.reason, DisconnectReason::Other);
    }
}
