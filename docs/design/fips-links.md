# FIPS Link Protocols

FIPS nodes peer with each other over a variety of link types. This document
explores the requirements and characteristics of different link protocols
that FIPS can operate over.

## Design Principles

FIPS is a Layer 3 (network) protocol. It exposes an IPv6 interface to local
applications, with an address deterministically derived from the node's npub.
This means existing UDP, TCP, and other IP-based applications work unmodified
over FIPS.

However, this IPv6-over-links architecture requires care to avoid classic
encapsulation pitfalls. In particular, running TCP over a reliable link (like
TCP/IP overlay) creates "TCP-over-TCP" where retransmission and congestion
control mechanisms at both layers interact adversely. FIPS prefers unreliable
links for this reason.

FIPS treats underlying connectivity as abstract links, regardless of whether
those links are:

- True L2 protocols (Ethernet, Bluetooth)
- L4-over-L3 tunnels (UDP/IP) used as link substrate for NAT traversal
- Application-layer overlays (Tor, I2P)

Each link driver presents a uniform interface to the FIPS routing layer:
send/receive datagrams to/from a link-layer peer address.

## Link Protocol Characteristics

### Overlay Links (L3/L4 Substrate)

These links tunnel FIPS over an existing network layer, typically for internet
connectivity or anonymity. Overlay links are expected to be the majority in
early deployments, but all depend on existing IP/Internet infrastructure that
FIPS is ultimately designed to replace.

| Link | Encapsulation | Addressing | MTU | Latency | Reliability | Bandwidth | Discovery |
|------|---------------|------------|-----|---------|-------------|-----------|-----------|
| UDP/IP | UDP datagram | IP:port | 1280-1472 | 1-500ms | Unreliable | High | DNS-SD, Nostr |
| TCP/IP | Framed stream | IP:port | Stream | 10-500ms | Reliable | High | DNS-SD, Nostr |
| WebSocket | WS frames | URL | Stream | 10-500ms | Reliable | High | Nostr |
| Tor | TCP stream | .onion | Stream | 500ms-5s | Reliable | Low-Med | Static, Nostr |
| I2P | I2P datagram | Destination | ~32K | 1-10s | Unreliable | Low | I2P directory |

### Shared Medium Links

These links operate over broadcast or multicast-capable media where multiple
endpoints share the same physical or logical channel.

| Link | Encapsulation | Addressing | MTU | Latency | Reliability | Bandwidth | Discovery |
|------|---------------|------------|-----|---------|-------------|-----------|-----------|
| Ethernet | EtherType frame | MAC | 1500 | <1ms | Unreliable | High | Multicast |
| WiFi Direct | 802.11 frame | MAC | 1500 | 1-10ms | Unreliable | High | Service discovery |
| DOCSIS (Cable) | DOCSIS frame | MAC | 1500 | 10-50ms | Unreliable | 1M-1G | N/A (uses IP) |
| Bluetooth Classic | L2CAP | BD_ADDR | 672-64K | 10-100ms | Reliable | 2-3 Mbps | Inquiry + SDP |
| BLE | L2CAP CoC/GATT | BD_ADDR | 23-517 | 10-30ms | Reliable | 125K-2M | GATT advertising |
| Zigbee | 802.15.4 frame | 16/64-bit | ~100 | 15-30ms | Reliable | 250 kbps | Network scan |
| LoRa | Raw packet | Device addr | 51-222 | 100ms-10s | Unreliable | 0.3-50 kbps | Beacons |

### Point-to-Point Links

These links connect exactly two endpoints with no shared medium or addressing.

| Link   | Encapsulation   | Addressing | MTU      | Latency   | Reliability | Bandwidth | Discovery  |
|--------|-----------------|------------|----------|-----------|-------------|-----------|------------|
| Serial | SLIP/COBS frame | None (P2P) | 256-1500 | 1-100ms   | Reliable    | 9.6K-1M   | Configured |
| Dialup | PPP frame       | None (P2P) | 1500     | 100-200ms | Reliable    | 33.6-56K  | Configured |

### Notes

**MTU**: Minimum/maximum or typical range. FIPS must handle heterogeneous MTUs
across the mesh; the IPv6 minimum (1280) is a safe baseline for the FIPS
packet format.

**Latency**: Typical range from best-case to worst-case. Affects spanning tree
convergence and keepalive timing.

**Reliability**: Whether the link provides delivery guarantees. Unreliable
links may drop, reorder, or duplicate packets. FIPS must tolerate this at
the routing layer.

**Bandwidth**: Order of magnitude. Affects flow control and congestion
decisions, but FIPS routing itself is low-bandwidth (control plane only).

## UDP/IP as Primary Internet Link

For internet-connected nodes, UDP/IP is the recommended link protocol:

- **NAT traversal**: UDP hole punching enables peer connections through NAT
- **Firewall compatibility**: UDP outbound rarely blocked; stateful firewalls
  pass return traffic
- **No connection state**: Matches FIPS datagram model
- **Low overhead**: 8-byte UDP header is negligible
- **Avoids TCP-over-TCP**: As noted in Design Principles, unreliable links
  avoid adverse interactions with application-layer TCP

Raw IP with a custom protocol number would be cleaner but is blocked by most
NAT devices and firewalls, limiting deployment to networks without NAT.

## Link Driver Interface

Each link driver implements:

```rust
trait LinkDriver {
    type PeerAddr: Clone + Eq + Hash;

    /// Send a FIPS packet to a peer
    fn send(&self, peer: &Self::PeerAddr, data: &[u8]) -> Result<()>;

    /// Receive a FIPS packet (blocking)
    fn recv(&self) -> Result<(Self::PeerAddr, Vec<u8>)>;

    /// Link MTU (maximum FIPS packet size)
    fn mtu(&self) -> u16;

    /// Discover potential peers (link-specific mechanism)
    fn discover(&self) -> Result<Vec<Self::PeerAddr>>;
}
```

Link drivers handle any necessary framing, fragmentation, or encryption
at the link layer. The FIPS routing layer sees only FIPS packets.

## Topics for Further Design

- Framing protocols for stream-based links (TCP, WebSocket)
- Link-layer encryption requirements vs FIPS-layer encryption
- Congestion control and flow control per link type
- Multi-path: using multiple links to same peer
- Link quality metrics for parent selection
