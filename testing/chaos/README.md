# Stochastic Network Simulation

Automated stochastic network testing for FIPS. Generates random
topologies, spins up Docker containers, and applies configurable
stressors (network impairment, link flaps, traffic generation, node
churn) over a timed simulation run. Logs are collected and analyzed
automatically.

## Prerequisites

- Docker with the compose plugin
- Rust toolchain (for building the FIPS binary)
- Python 3 with `pyyaml` and `jinja2` packages

## Quick Start

```bash
./testing/chaos/scripts/build.sh
./testing/chaos/scripts/chaos.sh smoke-10
```

## Available Scenarios

| Scenario | Nodes | Topology         | Duration | Netem | Link Flaps | Traffic | Node Churn | Bandwidth |
| -------- | ----- | ---------------- | -------- | ----- | ---------- | ------- | ---------- | --------- |
| smoke-10 | 10    | random_geometric | 60s      | --    | --         | --      | --         | --        |
| chaos-10 | 10    | random_geometric | 120s     | yes   | yes        | yes     | --         | --        |
| churn-10 | 10    | random_geometric | 600s     | yes   | yes        | yes     | yes        | --        |
| churn-20 | 20    | erdos_renyi      | 600s     | yes   | yes        | yes     | yes        | yes       |

## CLI Options

| Option            | Description                          |
| ----------------- | ------------------------------------ |
| `-v`, `--verbose` | Enable debug logging                 |
| `--seed N`        | Override the scenario's random seed  |
| `--duration secs` | Override the scenario's duration     |
| `--list`          | List available scenarios             |

The scenario argument accepts either a name (`churn-10`) or a file
path (`scenarios/churn-10.yaml`).

## Scenario YAML Format

Annotated example based on `churn-10.yaml`:

```yaml
scenario:
  name: "churn-10"
  seed: 42                          # deterministic RNG seed
  duration_secs: 600                # total simulation time

topology:
  num_nodes: 10
  algorithm: random_geometric       # or erdos_renyi, chain
  params:
    radius: 0.5                     # algorithm-specific parameter
  ensure_connected: true            # retry until graph is connected
  subnet: "172.20.0.0/24"
  ip_start: 10                      # first node gets .10

netem:
  enabled: true
  default_policy:
    delay_ms: { min: 5, max: 50 }
    jitter_ms: { min: 1, max: 10 }
    loss_pct: { min: 0, max: 2 }
  mutation:
    interval_secs: { min: 20, max: 45 }  # re-roll interval
    fraction: 0.3                         # fraction of links mutated
    policies:                             # named policy profiles
      normal:
        delay_ms: [5, 20]
        loss_pct: [0, 1]
      degraded:
        delay_ms: [50, 100]
        jitter_ms: [10, 30]
        loss_pct: [3, 8]

link_flaps:
  enabled: true
  interval_secs: { min: 30, max: 60 }
  max_down_links: 2
  down_duration_secs: { min: 10, max: 30 }
  protect_connectivity: true        # never partition the graph

traffic:
  enabled: true
  max_concurrent: 3
  interval_secs: { min: 10, max: 30 }
  duration_secs: { min: 5, max: 15 }
  parallel_streams: 4

node_churn:
  enabled: true
  interval_secs: { min: 60, max: 180 }
  max_down_nodes: 1
  down_duration_secs: { min: 30, max: 90 }
  protect_connectivity: true        # never kill the last path

bandwidth:
  enabled: false                    # per-link HTB rate limiting
  tiers_mbps: [1, 10, 100, 1000]   # each link randomly assigned a tier

logging:
  rust_log: "debug"
  output_dir: "./sim-results"
```

## Topology Algorithms

| Algorithm        | Parameters          | Description                                               |
| ---------------- | ------------------- | --------------------------------------------------------- |
| random_geometric | radius (default 0.5)| Place nodes in unit square, connect pairs within radius   |
| erdos_renyi      | p (default 0.3)     | Include each edge independently with probability p        |
| chain            | --                  | Linear chain: n01--n02--...--nN                           |

When `ensure_connected` is true (default), the generator retries up to
50 times to produce a connected graph.

## Output

Results written to `sim-results/` (configurable via
`logging.output_dir`):

- `analysis.txt` -- Summary: panics, errors, sessions, metrics
- `metadata.txt` -- Seed, node count, edges, adjacency list
- `fips-node-nXX.log` -- Per-node log output

Exit code 0 on success, 2 if panics detected.

## Creating Custom Scenarios

1. Copy an existing scenario from `scenarios/`.
2. Adjust topology size, algorithm, and stressor parameters.
3. Run with `./testing/chaos/scripts/chaos.sh path/to/custom.yaml`.
