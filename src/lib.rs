//! FIPS: Federated Interoperable Peering System
//!
//! A distributed, decentralized network routing protocol for mesh nodes
//! connecting over arbitrary transports.

pub mod config;
pub mod identity;

pub use config::{Config, ConfigError, IdentityConfig};
pub use identity::{
    decode_npub, decode_nsec, decode_secret, encode_npub, encode_nsec, AuthChallenge, AuthResponse,
    FipsAddress, Identity, IdentityError, NodeId, PeerIdentity,
};
