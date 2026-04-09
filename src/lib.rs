//! FIPS: Free Internetworking Peering System
//!
//! A distributed, decentralized network routing protocol for mesh nodes
//! connecting over arbitrary transports.

pub mod version;
pub mod bloom;
pub mod cache;
pub mod config;
pub mod control;
pub mod identity;
pub mod mmp;
pub mod noise;
pub mod utils;
pub mod node;
pub mod peer;
pub mod protocol;
pub mod transport;
pub mod tree;
#[cfg(feature = "tun-support")]
pub mod upper;

// When tun-support is disabled, provide the config types directly
// (they're simple serde structs with no platform-specific deps)
#[cfg(not(feature = "tun-support"))]
pub mod upper {
    pub mod config {
        use serde::{Deserialize, Serialize};

        #[derive(Debug, Clone, Default, Serialize, Deserialize)]
        pub struct DnsConfig {
            #[serde(default)]
            pub enabled: bool,
            #[serde(default, skip_serializing_if = "Option::is_none")]
            pub bind_addr: Option<String>,
            #[serde(default, skip_serializing_if = "Option::is_none")]
            pub port: Option<u16>,
            #[serde(default, skip_serializing_if = "Option::is_none")]
            pub ttl: Option<u32>,
        }

        #[derive(Debug, Clone, Default, Serialize, Deserialize)]
        pub struct TunConfig {
            #[serde(default)]
            pub enabled: bool,
            #[serde(default, skip_serializing_if = "Option::is_none")]
            pub name: Option<String>,
            #[serde(default, skip_serializing_if = "Option::is_none")]
            pub mtu: Option<u16>,
        }
    }
}

#[cfg(not(feature = "tun-support"))]
pub use upper::config::{DnsConfig, TunConfig};

// Re-export identity types
pub use identity::{
    decode_npub, decode_nsec, decode_secret, encode_npub, encode_nsec, AuthChallenge, AuthResponse,
    FipsAddress, Identity, IdentityError, NodeAddr, PeerIdentity,
};

// Re-export config types
pub use config::{Config, ConfigError, IdentityConfig, TorConfig, UdpConfig};
#[cfg(feature = "tun-support")]
pub use upper::config::{DnsConfig, TunConfig};

// Re-export tree types
pub use tree::{CoordEntry, ParentDeclaration, TreeCoordinate, TreeError, TreeState};

// Re-export bloom filter types
pub use bloom::{BloomError, BloomFilter, BloomState};

// Re-export transport types
pub use transport::{
    packet_channel, DiscoveredPeer, Link, LinkDirection, LinkId, LinkState, LinkStats, PacketRx,
    PacketTx, ReceivedPacket, Transport, TransportAddr, TransportError, TransportHandle,
    TransportId, TransportState, TransportType,
};
pub use transport::udp::UdpTransport;

// Re-export protocol types
pub use protocol::{
    CoordsRequired, FilterAnnounce, HandshakeMessageType, LinkMessageType,
    LookupRequest, LookupResponse, PathBroken, ProtocolError, SessionAck, SessionDatagram,
    SessionFlags, SessionMessageType, SessionSetup, TreeAnnounce,
};

// Re-export cache types
pub use cache::{CacheEntry, CacheError, CacheStats, CoordCache};

// Re-export peer types
pub use peer::{
    cross_connection_winner, ActivePeer, ConnectivityState, HandshakeState, PeerConnection,
    PeerError, PeerSlot, PromotionResult,
};

// Re-export node types
pub use node::{Node, NodeError, NodeState};

