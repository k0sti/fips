# FIPS TUN Driver Design

This document describes the design and implementation of the TUN interface
driver that connects FIPS to the local system's network stack.

## Overview

The TUN driver provides the interface between local applications and the FIPS
mesh network. It presents a virtual network interface (`fips0`) with the node's
FIPS address, allowing standard socket applications to communicate over the
mesh transparently.

## Architecture

```text
┌─────────────────────────────────────────────────────────────────┐
│                        Local System                              │
│  ┌──────────────┐                                               │
│  │ Applications │  (sockets using fd00::/8 addresses)           │
│  └──────┬───────┘                                               │
│         │                                                        │
│  ┌──────▼───────┐                                               │
│  │    Kernel    │  routing: fd00::/8 → fips0                    │
│  │  IPv6 Stack  │  local table intercepts traffic to self       │
│  └──────┬───────┘                                               │
└─────────┼───────────────────────────────────────────────────────┘
          │ raw IPv6 packets
┌─────────▼───────────────────────────────────────────────────────┐
│                      TUN Device (fips0)                          │
│  ┌─────────────────────────────────────────────────────────────┐│
│  │                    File Descriptor                          ││
│  │              (duplicated for reader/writer)                 ││
│  └──────────┬─────────────────────────────┬────────────────────┘│
│             │                             │                      │
│      ┌──────▼──────┐               ┌──────▼──────┐              │
│      │   Reader    │               │   Writer    │              │
│      │   Thread    │               │   Thread    │              │
│      │ (blocking)  │               │ (blocking)  │              │
│      └──────┬──────┘               └──────▲──────┘              │
│             │                             │                      │
└─────────────┼─────────────────────────────┼──────────────────────┘
              │                             │
              ▼                             │
       ┌─────────────┐              ┌───────┴───────┐
       │   Packet    │              │   TX Queue    │
       │  Processing │──────────────▶   (mpsc)      │
       │  (routing)  │              │               │
       └─────────────┘              └───────▲───────┘
                                            │
                                    (future: transports)
```

## Components

### TunDevice (`src/tun.rs`)

The main TUN device wrapper that handles creation, configuration, and lifecycle.

**Responsibilities:**

- Create TUN interface via `tun` crate
- Configure IPv6 address via netlink (`rtnetlink`)
- Set MTU and bring interface up
- Provide read access for incoming packets
- Create writer handle via fd duplication

**Lifecycle:**

1. **Startup**: Delete existing interface if present, create new
2. **Active**: Reader and writer threads operate independently
3. **Shutdown**: Delete interface via netlink, threads exit on I/O error

### TunWriter (`src/tun.rs`)

Services a queue of outbound packets and writes them to the TUN device.

**Design rationale:**

Multiple sources will need to write to TUN:

- ICMPv6 error responses (from packet processing)
- Inbound mesh traffic from peers (future: transports)
- Locally-generated control traffic (future)

A single writer thread with an mpsc queue provides:

- No contention on TUN writes
- Clean separation of concerns
- Easy addition of new packet sources via `TunTx::clone()`

### ICMPv6 Module (`src/icmp.rs`)

Generates RFC 4443 compliant ICMPv6 error messages.

**Currently implemented:**

- Type 1 Code 0: Destination Unreachable - No route

**Validation (when NOT to send errors):**

- Original packet was an ICMPv6 error (types 0-127)
- Source address is multicast (0xff prefix)
- Source address is unspecified (::)

**Response format:**

- Total size ≤ 1280 bytes (IPv6 minimum MTU)
- Includes as much of original packet as fits
- Proper checksum with pseudo-header

## Packet Flow

### Outbound (local → mesh)

1. Application sends to `fd00::/8` address
2. Kernel routes to `fips0` (requires manual route addition)
3. TUN reader receives raw IPv6 packet
4. Packet processing determines next hop
5. If routable: forward to transport (future)
6. If not routable: send ICMPv6 Destination Unreachable via TX queue

### Inbound (mesh → local)

1. Transport receives packet from peer (future)
2. Check destination address
3. If destination is self: write to TUN via TX queue
4. If destination is other: forward to next hop (transit)

### Local Address Guarantee

Packets arriving at the TUN reader are guaranteed NOT to be destined for
local addresses. The Linux kernel routing order ensures this:

1. **Local routing table** - intercepts traffic to addresses on this machine
2. **Main routing table** - routes `fd00::/8` to fips0

This means every packet in the TUN reader requires a routing decision.
No "is this for me?" check needed on the read path.

## Configuration

From `fips.yaml`:

```yaml
tun:
  enabled: true
  name: fips0
  mtu: 1400
```

**Parameters:**

| Field | Default | Description |
|-------|---------|-------------|
| `enabled` | `true` | Enable TUN interface |
| `name` | `fips0` | Interface name |
| `mtu` | `1400` | Maximum transmission unit |

## Privileges

TUN device creation requires `CAP_NET_ADMIN`. Options:

1. **Run as root**: `sudo ./fips`
2. **Set capability**: `sudo setcap cap_net_admin+ep ./target/debug/fips`
3. **Pre-created device**: Admin creates persistent TUN, FIPS just opens it

## Route Configuration

The kernel route must be added manually (not done by FIPS):

```bash
sudo ip -6 route add fd00::/8 dev fips0
```

This routes all FIPS addresses through the TUN interface.

## Implementation Status

### Completed

- [x] TUN device creation and configuration
- [x] IPv6 address assignment via netlink
- [x] Interface lifecycle (startup cleanup, graceful shutdown)
- [x] Reader thread with blocking I/O
- [x] Writer thread with mpsc queue
- [x] fd duplication for independent read/write
- [x] ICMPv6 Destination Unreachable (Type 1 Code 0)
- [x] Packet validation for ICMPv6 error generation

### Planned

- [ ] ICMPv6 Echo Reply (respond to ping)
- [ ] ICMPv6 Packet Too Big (PMTUD support)
- [ ] ICMPv6 Time Exceeded (hop limit)
- [ ] Rate limiting for ICMPv6 errors
- [ ] Integration with routing/forwarding logic
- [ ] Transit packet handling (decrement hop limit, forward)
- [ ] Automatic route management (add/remove fd00::/8 route)

## Testing

### Manual Testing

```bash
# Terminal 1: Run FIPS with debug logging
sudo RUST_LOG=debug ./target/debug/fips

# Terminal 2: Add route and test
sudo ip -6 route add fd00::/8 dev fips0
ping6 -c 1 fd00::1

# Expected: "Destination unreachable: No route" (not timeout)
```

### Verifying Local Routing

```bash
# Check that local address goes via loopback, not TUN
ip -6 route get <your-fips-address>
# Should show: local ... dev lo
```

## Dependencies

| Crate | Purpose |
|-------|---------|
| `tun` | TUN device creation |
| `rtnetlink` | Netlink interface configuration |
| `libc` | fd duplication (`dup`) |
| `futures` | Async netlink operations |

## References

- RFC 4443: ICMPv6 for IPv6
- RFC 4291: IPv6 Addressing Architecture
- Linux TUN/TAP documentation
