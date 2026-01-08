# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

cl-hive is a Core Lightning plugin implementing distributed "Swarm Intelligence" for Lightning node fleets. It coordinates multiple nodes through PKI authentication, shared state gossip, and distributed governance. Designed to work alongside [cl-revenue-ops](https://github.com/LightningGoats/cl-revenue-ops) which handles local fee/rebalancing decisions.

## Commands

```bash
# Run all tests
python3 -m pytest tests/

# Run specific test file
python3 -m pytest tests/test_planner.py

# Run with verbose output
python3 -m pytest tests/ -v
```

No build system - this is a CLN plugin deployed by copying `cl-hive.py` and `modules/` to the plugin directory.

## Architecture

```
cl-hive (Coordination Layer)
    ↓
cl-revenue-ops (Execution Layer)
    ↓
Core Lightning
```

### Three-Layer Design
- **cl-hive**: Manages fleet topology, membership, and consensus decisions
- **cl-revenue-ops**: Executes fee policies and rebalancing (called via RPC)
- **Core Lightning**: Underlying node operations and HSM-based crypto

### Module Organization

| Module | Purpose |
|--------|---------|
| `protocol.py` | BOLT 8 custom messages (magic: "HIVE" = 0x48495645, types 32769-32795) |
| `handshake.py` | PKI auth using CLN signmessage/checkmessage |
| `state_manager.py` | HiveMap distributed state + anti-entropy sync |
| `gossip.py` | Threshold-based gossip (10% capacity change) with 5-min heartbeat |
| `intent_manager.py` | Intent Lock protocol - Announce-Wait-Commit with lexicographic tie-breaker |
| `bridge.py` | Circuit Breaker pattern for cl-revenue-ops integration |
| `clboss_bridge.py` | CLBoss ignore/unignore for saturation control |
| `membership.py` | Two-tier system: Neophyte (probation) → Member (51% vouch quorum) |
| `contribution.py` | Forwarding stats and anti-leech detection |
| `planner.py` | Topology optimization - saturation analysis and guard mechanism |

### Key Patterns

**Thread Safety**:
- `RPC_LOCK` with 10-second timeout serializes all RPC calls
- `ThreadSafeRpcProxy` wraps the plugin.rpc object
- Thread-local SQLite connections with WAL mode

**Graceful Shutdown**:
- `shutdown_event` checked in all background loops
- Use `shutdown_event.wait(interval)` not `time.sleep()`

**Circuit Breaker** (in bridge.py):
- States: CLOSED → OPEN (after 3 failures) → HALF_OPEN (after 60s)
- All external plugin calls go through `safe_call()` wrapper

**Configuration Snapshot**:
- Use `config.snapshot()` at cycle start
- Never read mutable config mid-cycle

**Message Protocol**:
- 4-byte magic prefix filters non-Hive messages immediately
- "Peek & Check" pattern in custommsg hook
- JSON payload, max 65535 bytes per message

### Governance Modes

| Mode | Behavior |
|------|----------|
| `advisor` | Log decisions, queue to pending_actions, no auto-execution |
| `autonomous` | Execute within safety limits (budget cap, rate limit) |
| `oracle` | Delegate decisions to external API |

### Database Tables

`hive_members`, `intent_locks`, `hive_state`, `contribution_ledger`, `hive_bans`, `promotion_requests`, `hive_planner_log`, `pending_actions`

## Safety Constraints

These are non-negotiable:

1. **Fail closed**: On invalid input, RPC errors, schema mismatches → do nothing, log
2. **Bound everything**: Message sizes, list sizes, DB growth, caches, loop runtime
3. **No silent fund actions**: Never move funds unless governance mode explicitly allows
4. **Identity binding**: Sender peer_id must match claimed pubkey in payload
5. **DoS protection**: Max 200 remote intents cached, rate limits on all loops

## Planner Rules (Phase 6)

The Planner proposes topology changes but cannot open channels directly:
- May log decisions to `hive_planner_log`
- May create `pending_actions` entries in advisor mode
- May broadcast INTENT messages when governance mode allows
- Max 5 ignores per cycle
- 20% market share cap per target

## Development Notes

- Only external dependency: `pyln-client>=24.0`
- All crypto done via CLN HSM (signmessage/checkmessage) - no crypto libs imported
- Plugin options defined at top of `cl-hive.py` (16 configurable parameters)
- Background loops: intent_monitor_loop, membership_loop, planner_loop
