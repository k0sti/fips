//! IPv6 Upper Layer Adaptation
//!
//! This module groups the components that bridge between the FIPS routing
//! layer and IPv6 applications: the TUN interface (packet I/O), DNS
//! responder (.fips domain resolution), and ICMPv6 handling (error
//! signaling and neighbor discovery).

pub mod config;
#[cfg(feature = "dns")]
pub mod dns;
#[cfg(feature = "tun-device")]
pub mod icmp;
#[cfg(feature = "tun-device")]
pub mod icmp_rate_limit;
#[cfg(feature = "tun-device")]
pub mod tcp_mss;
#[cfg(feature = "tun-device")]
pub mod tun;
