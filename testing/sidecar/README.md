# FIPS Sidecar

Run FIPS as a network sidecar container, Tailscale-style. A companion app
container shares the FIPS container's network namespace and can only
communicate over the FIPS mesh (`fd::/8` via `fips0`). Direct Docker bridge
access is blocked by iptables rules.

## Architecture

```
┌───────────────────────────────────────────────────┐
│ Shared network namespace                          │
│                                                   │
│ ┌───────────────┐    ┌──────────────────────────┐ │
│ │ fips-sidecar  │    │ fips-app                 │ │
│ │               │    │                          │ │
│ │ fips daemon   │    │ sleep infinity           │ │
│ │ fipsctl       │    │ (your workload here)     │ │
│ │ dnsmasq       │    │                          │ │
│ └───────────────┘    └──────────────────────────┘ │
│                                                   │
│ Interfaces:                                       │
│   lo    — loopback (unrestricted)                 │
│   eth0  — Docker bridge (iptables: FIPS only)     │
│   fips0 — FIPS TUN (unrestricted, fd::/8)         │
└───────────────────────────────────────────────────┘
```

The FIPS sidecar owns the network namespace and creates the `fips0` TUN
interface. The app container (`network_mode: service:fips`) sees the same
interfaces. iptables rules restrict eth0 to FIPS UDP transport only — the
app container cannot reach the Docker bridge or host network directly.

## Build

```
cd testing/sidecar
./scripts/build.sh
```

This compiles FIPS, copies the binaries into the Docker context, and builds
the sidecar image.

## Run (standalone)

```
docker compose up -d
```

With the default `.env`, FIPS starts with no peers. Verify the app container
can see the FIPS interface:

```
docker exec fips-app ip addr show fips0
```

## Run (with static mesh)

Start the static mesh first:

```
cd ../static
./scripts/build.sh
docker compose --profile mesh up -d
```

Then start the sidecar, pointing it at a mesh node. You need to join the
static mesh's Docker network so the sidecar can reach mesh nodes via IPv4
transport:

```
cd ../sidecar

# Use the static mesh's network (project name may vary — check with
# "docker network ls" for the exact name, typically "static_fips-net")
FIPS_NETWORK=static_fips-net \
FIPS_SUBNET=172.20.0.0/24 \
FIPS_IPV4=172.20.0.20 \
FIPS_PEER_NPUB=npub1n9lpnv0592cc2ps6nm0ca3qls642vx7yjsv35rkxqzj2vgds52sqgpverl \
FIPS_PEER_ADDR=172.20.0.13:4000 \
FIPS_PEER_ALIAS=node-d \
docker compose up -d
```

Verify the peer link:

```
docker exec fips-sidecar fipsctl show peers
docker exec fips-sidecar fipsctl show links
```

## Verify connectivity and isolation

From the app container:

```
# Ping a mesh node by npub (multi-hop through the mesh):
docker exec fips-app ping6 -c3 npub1sjlh2c3x9w7kjsqg2ay080n2lff2uvt325vpan33ke34rn8l5jcqawh57m.fips

# Fetch a web page from a mesh node over FIPS:
docker exec fips-app curl -6 "http://[fd69:e08d:65cc:3a6b:9c2c:2ac4:bd40:5e4b]:8000/"

# Docker bridge is blocked — this should fail:
docker exec fips-app ping -c1 -W2 172.20.0.13

# Loopback is allowed:
docker exec fips-app ping -c1 127.0.0.1
```

## Environment Variables

| Variable | Default | Description |
|---|---|---|
| `FIPS_NSEC` | *(required)* | Node secret key (hex or nsec1 bech32) |
| `FIPS_PEER_NPUB` | *(empty)* | Peer's npub to connect to |
| `FIPS_PEER_ADDR` | *(empty)* | Peer's transport address (e.g. `172.20.0.13:4000`) |
| `FIPS_PEER_ALIAS` | `peer` | Human-readable peer name |
| `FIPS_UDP_BIND` | `0.0.0.0:4000` | UDP transport bind address |
| `FIPS_TUN_MTU` | `1280` | TUN interface MTU |
| `FIPS_NETWORK` | `fips-sidecar-net` | Docker network name (set to join external network) |
| `FIPS_SUBNET` | `172.20.1.0/24` | Docker network subnet |
| `FIPS_IPV4` | `172.20.1.20` | Sidecar's IPv4 address on the Docker network |
| `RUST_LOG` | `info` | FIPS log level |
