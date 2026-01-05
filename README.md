# cl-hive

**The Coordination Layer for Core Lightning Fleets.**

## Overview
cl-hive is a plugin for Core Lightning that enables "Swarm Intelligence" across independent nodes. It handles:
- **PKI Authentication:** Secure handshakes between fleet members.
- **Shared State:** Gossip protocol for topology and liquidity visibility.
- **Distributed Governance:** Consensus banning and strategy sharing.

## Relationship to cl-revenue-ops
This plugin is the "Diplomat" that talks to other nodes. It is designed to work alongside [cl-revenue-ops](https://github.com/LightningGoats/cl-revenue-ops), which acts as the "CFO" managing local profitability.

## Documentation
See [docs/specs/](docs/specs/) for the architectural proposals.
