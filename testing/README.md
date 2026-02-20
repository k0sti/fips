# FIPS Testing

Integration and simulation test harnesses for FIPS, using Docker
containers running the full protocol stack.

## Test Harnesses

### [static/](static/) -- Static Docker Network

Fixed topologies (mesh, chain) with 5 nodes. Manual scripts for
building, config generation, connectivity tests (ping, iperf), and
network impairment (netem). Useful for deterministic debugging and
validating specific topology configurations.

### [chaos/](chaos/) -- Stochastic Simulation

Automated randomized testing with configurable node counts, topology
algorithms (random geometric, Erdos-Renyi, chain), and fault
injection (netem mutation, link flaps, traffic generation, node
churn). Scenarios are defined in YAML and executed via a Python
harness that manages the full lifecycle: topology generation, Docker
orchestration, fault scheduling, log collection, and analysis.
