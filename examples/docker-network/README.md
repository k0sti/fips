# Docker Network Test Harness

Multi-node integration test for FIPS using Docker containers. Two topologies
are provided: a sparse mesh (5 nodes, 6 links) and a linear chain (5 nodes,
4 links). Both exercise the full FIPS stack including TUN devices, DNS
resolution, peer link encryption, spanning tree construction, and
discovery-driven multi-hop routing.

## Prerequisites

- Docker with the compose plugin
- Rust toolchain (for building the FIPS binary)

## Quick Start

Build the binary and copy it to the docker context:

```bash
./scripts/build.sh
```

### Mesh Topology

```bash
docker compose --profile mesh build
docker compose --profile mesh up -d
./scripts/ping-test.sh mesh      # 20/20 expected (with response times)
./scripts/iperf-test.sh mesh     # bandwidth test
docker compose --profile mesh down
```

### Chain Topology

```bash
docker compose --profile chain build
docker compose --profile chain up -d
./scripts/ping-test.sh chain     # 6/6 expected (with response times)
./scripts/iperf-test.sh chain    # bandwidth test
docker compose --profile chain down
```

## Mesh Topology

![Mesh Topology](docker-mesh-topology.svg)

Five nodes with 6 bidirectional UDP links forming a sparse, fully connected
graph. Not all nodes are direct peers — non-adjacent pairs require
discovery-driven multi-hop routing to establish end-to-end sessions.

The spanning tree is rooted at node A, which has the lexicographically
smallest `NodeAddr` (the first 16 bytes of `SHA-256(pubkey)`). Tree edges
are highlighted in blue in the diagram above.

The ping test exercises all 20 directed pairs (5 nodes x 4 targets each),
covering both direct-peer and multi-hop paths.

| Link | Type |
|------|------|
| A — D | tree edge (D's parent is A) |
| A — E | tree edge (E's parent is A) |
| C — D | tree edge (C's parent is D) |
| B — C | tree edge (B's parent is C) |
| D — E | non-tree link |
| C — E | non-tree link |

## Chain Topology

![Chain Topology](docker-chain-topology.svg)

Five nodes in a linear chain: A — B — C — D — E. Each node peers only with
its immediate neighbors. Multi-hop communication (e.g., A to E) requires the
discovery protocol to find routes through intermediate nodes.

The ping test covers:

- Adjacent hops: A→B, B→C (1 hop each)
- Multi-hop: A→C (2 hops), A→D (3 hops), A→E (4 hops)
- Reverse: E→A (4 hops)

## Performance Testing

The `iperf-test.sh` script measures bandwidth between nodes using iperf3:

```bash
./scripts/iperf-test.sh [mesh|chain]
```

The test runs iperf3 with the following parameters:

- Duration: 10 seconds (`-t 10`)
- Parallel streams: 8 (`-P 8`)
- Protocol: TCP over IPv6

This exercises the full FIPS stack including encryption, routing, and TUN device performance.

## Network Impairment

The `netem.sh` script simulates adverse network conditions using `tc`/`netem`
on all running containers:

```bash
./scripts/netem.sh [mesh|chain] <apply|remove|status> [options]
```

### Options

| Option | Description |
|--------|-------------|
| `--delay <ms>` | Fixed delay in milliseconds |
| `--jitter <ms>` | Delay variation (requires `--delay`) |
| `--loss <percent>` | Packet loss percentage |
| `--loss-corr <percent>` | Loss correlation for bursty loss |
| `--duplicate <percent>` | Packet duplication percentage |
| `--reorder <percent>` | Packet reordering probability (requires `--delay`) |
| `--corrupt <percent>` | Bit-level corruption percentage |

### Presets

| Preset | Parameters |
|--------|------------|
| `lossy` | 5% loss, 25% correlation |
| `congested` | 50ms delay, 20ms jitter, 2% loss |
| `terrible` | 100ms delay, 40ms jitter, 10% loss, 1% dup, 5% reorder |

### Examples

```bash
# Apply 50ms delay with 5% packet loss
./scripts/netem.sh mesh apply --delay 50 --loss 5

# Use a preset
./scripts/netem.sh chain apply --preset congested

# Check current rules
./scripts/netem.sh mesh status

# Remove all impairment
./scripts/netem.sh mesh remove
```

Rules are applied to egress on each container's `eth0` interface. With all
containers impaired equally, both directions of every link see the effect.
The script uses `tc qdisc replace` so it can be re-run safely without
removing rules first.

## Configuration Management

Node configurations are generated from templates to ensure consistency across all nodes:

### File Structure

```
configs/
├── node.template.yaml          # Single template for all node configs
├── topologies/
│   ├── mesh.yaml              # Mesh topology definition (reference)
│   └── chain.yaml             # Chain topology definition (reference)
└── [mesh|chain]/              # Original hand-written configs (deprecated)

generated-configs/              # Auto-generated configs (gitignored)
├── mesh/
│   ├── node-a.yaml
│   ├── node-b.yaml
│   └── ...
└── chain/
    ├── node-a.yaml
    └── ...
```

### Topology Files

The `configs/topologies/` directory contains YAML files documenting each network topology:

- Node identities (nsec, npub)
- Docker IP addresses
- Peer connections for each node

These files serve as reference documentation and make it easy to understand and modify network topologies.

### Generating Configs

The `scripts/generate-configs.sh` script reads the topology definitions (embedded in the script) and generates node configs into `generated-configs/`:

```bash
./scripts/generate-configs.sh [mesh|chain|all]
```

The build script (`scripts/build.sh`) automatically regenerates configs before building Docker images.

### Modifying Topologies

To change network topologies, edit the `get_mesh_peers()` or `get_chain_peers()` functions in `generate-configs.sh`, then update the corresponding YAML file in `configs/topologies/` for documentation.

## Node Identities

All nodes use deterministic test keys (not for production use).

| Node | npub | FIPS IPv6 Address | Docker IP |
|------|------|-------------------|-----------|
| A | `npub1sjlh2c3...` | `fd69:e08d:65cc:3a6b:...` | 172.20.0.10 |
| B | `npub1tdwa4vj...` | `fd8e:302c:287e:b48d:...` | 172.20.0.11 |
| C | `npub1cld9yay...` | `fdac:a221:4069:5044:...` | 172.20.0.12 |
| D | `npub1n9lpnv0...` | `fdb6:8411:a191:6d48:...` | 172.20.0.13 |
| E | `npub1wf8akf8...` | `fded:7dee:d386:a546:...` | 172.20.0.14 |

## Container Configuration

- **Base image**: debian:bookworm-slim
- **Capabilities**: `CAP_NET_ADMIN` (for TUN device creation)
- **Devices**: `/dev/net/tun` mapped into each container
- **DNS**: FIPS built-in resolver on `127.0.0.1:53`
- **Transport**: UDP on port 4000, MTU 1280
- **TUN**: `fips0` interface, MTU 1280

Each node resolves `<npub>.fips` DNS names to FIPS IPv6 addresses via its
local DNS responder, which primes the identity cache for session establishment.

## Troubleshooting

**Stale images after code changes**: Docker compose may cache old layers.
Force a clean rebuild:

```bash
docker compose --profile mesh build --no-cache
```

**Check node logs**:

```bash
docker logs fips-node-a
docker logs -f fips-node-c    # follow
```

**Verify DNS resolution inside a container**:

```bash
docker exec fips-node-a dig AAAA npub1tdwa4vjrjl33pcjdpf2t4p027nl86xrx24g4d3avg4vwvayr3g8qhd84le.fips @127.0.0.1
```

**Verify binary is up to date**: Compare hashes between the local build and
the binary inside the container:

```bash
md5sum examples/docker-network/fips
docker exec fips-node-a md5sum /usr/local/bin/fips
```

**Increase convergence time**: If tests fail intermittently, the 5-second
convergence wait in `ping-test.sh` may be insufficient. Edit the `sleep`
value at the top of the script.
