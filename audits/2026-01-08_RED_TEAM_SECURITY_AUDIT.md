# CL-HIVE RED TEAM SECURITY AUDIT

**Date:** 2026-01-08
**Auditor:** Red Team AI (Claude Opus 4.5)
**Codebase Version:** v0.1.0-dev (commit 0ac909a)
**Scope:** Phases 1-6 (Protocol, State, Intent, Bridge, Membership, Planner)

---

## EXECUTIVE RISK SUMMARY (TOP 5)

| Rank | Finding | Severity | Component | Risk |
|------|---------|----------|-----------|------|
| **1** | **UNBOUNDED REMOTE INTENT CACHE** | **HIGH** | intent_manager.py:166 | `_remote_intents` dict grows unbounded; malicious peer can spam INTENTs to OOM the node |
| **2** | **CONTRIBUTION LEDGER DB BLOAT** | **HIGH** | contribution.py, database.py | Rate limit bypass via multiple peers + no absolute cap = unbounded DB growth |
| **3** | **MISSING MEMBER VERIFICATION IN HANDLERS** | **HIGH** | cl-hive.py (multiple) | INTENT/GOSSIP handlers don't verify sender is Hive member |
| **4** | **GOSSIP PEER_ID BINDING IS SENDER-ONLY** | **MEDIUM** | gossip.py:271 | Gossip validates sender but not membership, enabling state pollution |
| **5** | **CIRCUIT BREAKER RESET VIA TIMING** | **MEDIUM** | bridge.py:117 | Attacker can force HALF_OPEN transition by waiting RESET_TIMEOUT, then succeed once to reset |

---

## FULL FINDINGS TABLE

### Phase 1-2: Protocol/State Findings

| ID | Severity | Component | Vulnerability | Exploit Path | Impact |
|----|----------|-----------|---------------|--------------|--------|
| **P1-01** | Medium | protocol.py:186 | `MAX_MESSAGE_BYTES` check after hex decode | Send 65535*2 hex chars = 131KB string before rejection | Memory spike during hex decode |
| **P1-02** | Low | protocol.py:200 | No rate limit on protocol version mismatch | Flood invalid version messages | Log spam, minor CPU |
| **P1-03** | Medium | handshake.py:440-446 | `MAX_PENDING_CHALLENGES=1000` but eviction is LRU by timestamp | Attacker sends 1000+ HELLOs to evict legitimate pending challenges | Denial of handshake for real candidates |
| **P1-04** | High | handshake.py:82-83 | `Ticket.from_base64` has no size limit on input | Send multi-MB base64 ticket in HELLO | Memory exhaustion, JSON parse bombs |
| **P2-01** | Medium | state_manager.py:356-396 | `apply_full_sync` accepts up to `MAX_FULL_SYNC_STATES=2000` | Malicious peer sends 2000 state entries per FULL_SYNC repeatedly | DB bloat, CPU exhaustion |
| **P2-02** | Low | gossip.py:96 | `_peer_gossip_times` dict never pruned | Accumulates entries for every peer ever seen | Slow memory leak |

### Phase 3: Intent Coordination Findings

| ID | Severity | Component | Vulnerability | Exploit Path | Impact |
|----|----------|-----------|---------------|--------------|--------|
| **P3-01** | **HIGH** | intent_manager.py:166 | `_remote_intents` dict unbounded | Attacker sends unique `intent_type:target:initiator` combinations continuously | OOM crash |
| **P3-02** | Medium | intent_manager.py:239-270 | No validation that remote initiator is a Hive member | Non-member can announce intents, forcing legitimate members to lose tie-breakers | Intent lock denial-of-service |
| **P3-03** | Medium | cl-hive.py:1255-1263 | Governance mode check happens AFTER commit | Intent committed to DB regardless of governance mode | State inconsistency, audit confusion |
| **P3-04** | Low | intent_manager.py:112-124 | `is_conflicting` doesn't check expiration | Expired intents can still be considered conflicting | Stale conflict detection |

### Phase 4: Integration Bridge Findings

| ID | Severity | Component | Vulnerability | Exploit Path | Impact |
|----|----------|-----------|---------------|--------------|--------|
| **P4-01** | Medium | bridge.py:117-119 | OPEN->HALF_OPEN transition purely time-based | Wait RESET_TIMEOUT, then succeed once = full reset | Circuit breaker bypass |
| **P4-02** | Medium | bridge.py:364-383 | `subprocess.run` with user-controlled method name | If attacker can influence `method` param, shell injection possible | Command injection (requires upstream bug) |
| **P4-03** | Low | bridge.py:274-278 | Plugin list parsing trusts `name` field contains "cl-revenue-ops" | Malicious plugin named "cl-revenue-ops-fake" could match | False positive detection |
| **P4-04** | Medium | bridge.py:391-441 | `safe_call` doesn't validate response schema | Malformed cl-revenue-ops response could crash on `.get()` | Unexpected exceptions |

### Phase 5: Membership & Governance Findings

| ID | Severity | Component | Vulnerability | Exploit Path | Impact |
|----|----------|-----------|---------------|--------------|--------|
| **P5-01** | Medium | cl-hive.py:handle_promotion | Vouch TTL window (7 days) allows accumulation | Failed promotion can accumulate more vouches over time | Gradual quorum gaming |
| **P5-02** | High | contribution.py:76-85 | Rate limit is per-peer but `_rate_limits` dict not pruned | If attacker controls N peers, can record 120*N events/hour | DB bloat |
| **P5-03** | High | database.py:506-522 | `record_contribution` has no absolute daily cap | Even with rate limit, 120 events/peer/hour * 50 peers * 24h = 144,000 rows/day | Unbounded DB growth |
| **P5-04** | Medium | membership.py:150-164 | `get_active_members` queries all members | With max_members=50+, this is O(n) per vouch check | CPU amplification |
| **P5-05** | Medium | cl-hive.py:1067-1069 | VOUCH handler checks `voucher_pubkey != peer_id` | Correctly catches sender mismatch | Properly mitigated by sig check |
| **P5-06** | Medium | membership.py:68-84 | `calculate_uptime` uses `now - last_change` without bounds | If last_change is in future (clock skew attack), uptime goes negative | Uptime manipulation |
| **P5-07** | Low | cl-hive.py:1095-1096 | Banned voucher check happens after signature verification | Wasted CPU on banned voucher signatures | Minor DoS |
| **P5-08** | Medium | database.py:602-614 | `add_promotion_vouch` replay window is VOUCH_TTL_SECONDS (7 days) | Vouch can be replayed within 7-day window | Quorum inflation risk |

### Cross-Cutting Findings

| ID | Severity | Component | Vulnerability | Exploit Path | Impact |
|----|----------|-----------|---------------|--------------|--------|
| **X-01** | Medium | cl-hive.py:78-112 | `RPC_LOCK` is global; any slow RPC blocks all threads | Trigger slow RPC (e.g., listchannels on large node) during critical path | Global stall |
| **X-02** | Low | Multiple | JSON parsing without depth limits | Deeply nested JSON payloads | Stack overflow (Python limit ~1000) |
| **X-03** | Medium | database.py:71-72 | Autocommit mode = no transaction rollback on partial failures | Multi-step operations can leave DB inconsistent | Data corruption |
| **X-04** | Low | cl-hive.py:518 | `import json` inside handler function | Repeated import overhead on every HELLO | Minor performance |

---

## EXPLOIT SKETCHES

### Exploit 1: REMOTE INTENT CACHE OOM (P3-01, HIGH)

**Vulnerable Code:** `intent_manager.py:166, 319-330`

```python
def record_remote_intent(self, intent: Intent) -> None:
    key = f"{intent.intent_type}:{intent.target}:{intent.initiator}"
    self._remote_intents[key] = intent  # NO SIZE LIMIT
```

**Attack Sequence:**

1. Attacker connects as peer (can be non-member, INTENT handler doesn't verify membership)
2. Attacker generates unique intents:
   ```python
   for i in range(1_000_000):
       target = sha256(f"target_{i}").hexdigest()[:64]
       send_intent(CHANNEL_OPEN, target, attacker_pubkey, time.time())
   ```
3. Each intent creates a new key in `_remote_intents`
4. Intent objects are ~200 bytes each
5. 1M intents = 200MB memory consumed

**Payload (repeated with varying target):**
```json
{
  "type": 32783,
  "payload": {
    "intent_type": "channel_open",
    "target": "<unique_64_hex_chars>",
    "initiator": "02attacker...",
    "timestamp": 1704067200,
    "expires_at": 1704067260
  }
}
```

**Impact:** Memory exhaustion, node becomes unresponsive or crashes.

---

### Exploit 2: CONTRIBUTION LEDGER DB BLOAT (P5-02/P5-03, HIGH)

**Vulnerable Code:** `contribution.py:76-85`, `database.py:506-522`

**Attack Sequence:**

1. Attacker controls multiple Lightning nodes (N nodes)
2. Each node joins Hive as neophyte
3. Each node generates forwarding events through the victim:
   - Send payments through victim node (via circular routes)
   - Each forward triggers `forward_event` hook
4. Rate limit: 120 events/peer/hour
5. With N=50 Sybil nodes: 120 * 50 * 24 = 144,000 rows/day
6. Each row: ~100 bytes -> 14.4 MB/day -> 5.2 GB/year

**Impact:** Database bloat leading to disk exhaustion, slow queries.

---

### Exploit 3: PENDING CHALLENGE EVICTION (P1-03, MEDIUM)

**Vulnerable Code:** `handshake.py:440-446`

```python
if len(self._pending_challenges) > MAX_PENDING_CHALLENGES:
    oldest = sorted(
        self._pending_challenges.items(),
        key=lambda item: item[1]["issued_at"]
    )
    for key, _ in oldest[: len(self._pending_challenges) - MAX_PENDING_CHALLENGES]:
        self._pending_challenges.pop(key, None)
```

**Attack Sequence:**

1. Legitimate candidate sends HELLO, gets challenge stored at T=0
2. Attacker rapidly sends 1001 HELLOs from different peer_ids
3. Each HELLO triggers `generate_challenge`, adding to dict
4. Eviction triggers, removes oldest entries (including legitimate candidate)
5. Legitimate candidate sends ATTEST, but challenge is gone
6. ATTEST rejected: "no pending challenge"

**Impact:** Denial of service for legitimate handshakes.

---

### Exploit 4: GOSSIP STATE POLLUTION

**Vulnerable Code:** `gossip.py:250-289`

```python
def process_gossip(self, sender_id: str, payload: Dict[str, Any]) -> bool:
    # Verify sender matches payload peer_id (prevent spoofing)
    if payload['peer_id'] != sender_id:
        return False

    # BUT: No check that sender_id is a Hive member!
    # ...
    return self.state_manager.update_peer_state(sender_id, payload)
```

**Attack:** Non-member peer connects and sends GOSSIP messages. The gossip is accepted because:
1. Magic prefix matches
2. sender_id == payload.peer_id
3. Version number validation passes

**Impact:** State cache polluted with non-member data, affecting fleet statistics and potentially topology decisions.

---

## MITIGATION GUIDANCE

### CRITICAL: P3-01 - Remote Intent Cache Bound

**Location:** `intent_manager.py:166`

```python
# intent_manager.py

MAX_REMOTE_INTENTS = 200  # Same as max_members * 4 (generous)

def record_remote_intent(self, intent: Intent) -> None:
    """Record remote intent with bounded cache."""
    key = f"{intent.intent_type}:{intent.target}:{intent.initiator}"

    # Enforce size limit with LRU eviction
    if len(self._remote_intents) >= MAX_REMOTE_INTENTS:
        # Evict oldest by timestamp
        oldest_key = min(
            self._remote_intents.keys(),
            key=lambda k: self._remote_intents[k].timestamp
        )
        del self._remote_intents[oldest_key]

    self._remote_intents[key] = intent
```

**Also add member verification in `handle_intent`:**
```python
# cl-hive.py:handle_intent
def handle_intent(peer_id: str, payload: Dict, plugin: Plugin) -> Dict:
    # ADD: Verify sender is a Hive member
    if not database.get_member(peer_id):
        plugin.log(f"INTENT from non-member {peer_id[:16]}...", level='warn')
        return {"result": "continue"}
    ...
```

---

### HIGH: P5-02/P5-03 - Contribution Ledger Caps

**Location:** `contribution.py`, `database.py`

```python
# contribution.py - Add absolute daily cap

MAX_CONTRIB_EVENTS_PER_DAY_TOTAL = 10000  # Absolute cap across all peers

class ContributionManager:
    def __init__(self, ...):
        ...
        self._daily_event_count = 0
        self._daily_reset_time = 0

    def _check_daily_cap(self) -> bool:
        now = int(time.time())
        day_start = now - (now % 86400)

        if self._daily_reset_time < day_start:
            self._daily_event_count = 0
            self._daily_reset_time = day_start

        if self._daily_event_count >= MAX_CONTRIB_EVENTS_PER_DAY_TOTAL:
            return False

        self._daily_event_count += 1
        return True

    def handle_forward_event(self, payload: Dict[str, Any]) -> None:
        if not self._check_daily_cap():
            return  # Silent drop
        ...

# database.py - Add row count check
def record_contribution(self, peer_id: str, direction: str, amount_sats: int) -> bool:
    conn = self._get_connection()

    # Check table size
    row_count = conn.execute(
        "SELECT COUNT(*) FROM contribution_ledger"
    ).fetchone()[0]

    if row_count >= 500000:  # Hard cap: 500k rows
        return False
    ...
```

---

### MEDIUM: P1-03 - Pending Challenge Protection

**Location:** `handshake.py:422-446`

```python
# handshake.py

CHALLENGE_RATE_LIMIT_PER_PEER = 3  # Max 3 challenges per peer per minute
_challenge_rate_limits: Dict[str, Tuple[int, int]] = {}

def generate_challenge(self, peer_id: str, requirements: int) -> Optional[str]:
    """Generate challenge with rate limiting."""
    now = int(time.time())

    # Rate limit check
    window_start, count = self._challenge_rate_limits.get(peer_id, (now, 0))
    if now - window_start < 60:
        if count >= CHALLENGE_RATE_LIMIT_PER_PEER:
            self._log(f"Rate limit exceeded for {peer_id[:16]}...", level='warn')
            return None
        count += 1
    else:
        window_start = now
        count = 1
    self._challenge_rate_limits[peer_id] = (window_start, count)

    # Proceed with challenge generation
    nonce = secrets.token_hex(NONCE_SIZE)
    ...
```

---

### MEDIUM: P4-01 - Circuit Breaker Hardening

**Location:** `bridge.py:81-162`

```python
# bridge.py

class CircuitBreaker:
    def __init__(self, name: str, max_failures: int = MAX_FAILURES,
                 reset_timeout: int = RESET_TIMEOUT,
                 min_successes_to_close: int = 3):  # NEW PARAMETER
        ...
        self._half_open_successes = 0
        self._min_successes_to_close = min_successes_to_close

    def record_success(self) -> None:
        """Record success with gradual recovery."""
        self._last_success_time = int(time.time())

        if self._state == CircuitState.HALF_OPEN:
            self._half_open_successes += 1
            if self._half_open_successes >= self._min_successes_to_close:
                self._state = CircuitState.CLOSED
                self._failure_count = 0
                self._half_open_successes = 0
        else:
            self._failure_count = max(0, self._failure_count - 1)
```

---

### MEDIUM: Gossip/Intent Member Verification

**Location:** `cl-hive.py:handle_gossip`, `cl-hive.py:handle_intent`

```python
# cl-hive.py - Add to BOTH handlers

def handle_gossip(peer_id: str, payload: Dict, plugin: Plugin) -> Dict:
    if not gossip_mgr:
        return {"result": "continue"}

    # ADD: Verify sender is a Hive member
    member = database.get_member(peer_id)
    if not member:
        plugin.log(f"GOSSIP from non-member {peer_id[:16]}...", level='debug')
        return {"result": "continue"}

    accepted = gossip_mgr.process_gossip(peer_id, payload)
    ...

def handle_intent(peer_id: str, payload: Dict, plugin: Plugin) -> Dict:
    if not intent_mgr:
        return {"result": "continue"}

    # ADD: Verify sender is a Hive member
    member = database.get_member(peer_id)
    if not member:
        plugin.log(f"INTENT from non-member {peer_id[:16]}...", level='warn')
        return {"result": "continue"}
    ...
```

---

### MEDIUM: X-01 - RPC Lock Timeout

**Location:** `cl-hive.py:78-112`

```python
# cl-hive.py

RPC_LOCK = threading.Lock()
RPC_LOCK_TIMEOUT = 10  # seconds

class ThreadSafeRpcProxy:
    def __getattr__(self, name):
        original_method = getattr(self._rpc, name)

        if callable(original_method):
            def thread_safe_method(*args, **kwargs):
                acquired = RPC_LOCK.acquire(timeout=RPC_LOCK_TIMEOUT)
                if not acquired:
                    raise TimeoutError(f"RPC lock timeout for {name}")
                try:
                    return original_method(*args, **kwargs)
                finally:
                    RPC_LOCK.release()
            return thread_safe_method
        else:
            return original_method
```

---

## REQUIRED TESTS

### Unit Tests

| Test ID | Target | Test Description | Pass Criteria |
|---------|--------|------------------|---------------|
| T-01 | `IntentManager._remote_intents` | Insert MAX_REMOTE_INTENTS+100 intents | Dict size never exceeds MAX_REMOTE_INTENTS |
| T-02 | `HandshakeManager.generate_challenge` | Call 10x rapidly for same peer_id | Returns None after 3 calls within 60s |
| T-03 | `ContributionManager.handle_forward_event` | Insert MAX_CONTRIB_EVENTS_PER_DAY_TOTAL+1 | Last insert silently dropped |
| T-04 | `database.record_contribution` | Check row count after 500k inserts | Returns False when cap reached |
| T-05 | `handle_gossip` | Send GOSSIP from non-member peer | Returns continue, no state update |
| T-06 | `handle_intent` | Send INTENT from non-member peer | Returns continue, not recorded |
| T-07 | `CircuitBreaker.record_success` | Call 1x in HALF_OPEN state | State still HALF_OPEN (not CLOSED) |
| T-08 | `CircuitBreaker.record_success` | Call 3x in HALF_OPEN state | State transitions to CLOSED |
| T-09 | `validate_promotion` | Vouch with mismatched request_id in sig | Signature verification fails |
| T-10 | `ThreadSafeRpcProxy` | Acquire lock, timeout after 10s | Raises TimeoutError |

### Integration Tests

| Test ID | Scenario | Test Description |
|---------|----------|------------------|
| IT-01 | Handshake DoS | Simulate 1001 concurrent HELLO from different peers, verify legitimate handshake completes |
| IT-02 | Intent Storm | Send 1000 unique INTENTs from malicious peer, verify memory stays under 50MB |
| IT-03 | Gossip Pollution | Non-member sends GOSSIP, verify state cache unchanged |
| IT-04 | Promotion Replay | Attempt vouch replay with different request_id, verify rejection |
| IT-05 | Contribution Storm | Generate 15k forward events in 1 hour, verify DB cap enforced |
| IT-06 | RPC Stall | Slow RPC + concurrent request, verify timeout works |

### Fuzz Tests

| Test ID | Target | Input Space | Oracle |
|---------|--------|-------------|--------|
| FZ-01 | `deserialize()` | Random bytes with HIVE magic prefix | No crash, returns (None, None) for invalid |
| FZ-02 | `Ticket.from_base64()` | Random base64 strings 0-10MB | No OOM, raises ValueError |
| FZ-03 | `validate_vouch()` | Random dicts with varying types | Returns False for invalid, no crash |
| FZ-04 | `apply_full_sync()` | Arrays of 0-5000 random state dicts | No crash, respects MAX_FULL_SYNC_STATES |
| FZ-05 | JSON depth bomb | Nested dicts 1000+ levels | No stack overflow |

### Property Tests (Hypothesis)

```python
from hypothesis import given, strategies as st

@given(st.binary(min_size=0, max_size=200000))
def test_deserialize_never_crashes(data):
    """deserialize() never raises on arbitrary input."""
    result = deserialize(data)
    assert result == (None, None) or isinstance(result[0], HiveMessageType)

@given(st.lists(st.fixed_dictionaries({
    'peer_id': st.text(min_size=1, max_size=128),
    'version': st.integers(min_value=0),
    'timestamp': st.integers(min_value=0),
}), min_size=0, max_size=3000))
def test_apply_full_sync_bounded(states):
    """apply_full_sync() respects bounds and never crashes."""
    sm = StateManager(mock_db)
    updated = sm.apply_full_sync(states)
    assert updated <= MAX_FULL_SYNC_STATES
```

---

## REGRESSION WATCHLIST

Areas likely to introduce vulnerabilities in future changes:

| Area | Risk | Watch For |
|------|------|-----------|
| **Message Type Additions** | New message types may skip member verification | Ensure all new handlers check `database.get_member(peer_id)` |
| **Governance Mode Expansion** | New modes may have edge cases | Test all code paths against all governance modes |
| **Phase 6 Planner Integration** | Planner actions may bypass Intent Lock | Ensure planner always creates Intent before action |
| **WebSocket/API Additions** | New interfaces may not use ThreadSafeRpcProxy | Audit any new RPC call paths |
| **Contribution Ratio Formula** | Changes may enable gaming | Verify monotonicity and bound checks |
| **Ticket Extensions** | New fields may not be in signature | Ensure `to_json()` includes all security-relevant fields |
| **Database Schema Changes** | New tables may lack pruning/caps | Audit every new table for growth bounds |
| **Background Thread Additions** | New threads may not respect shutdown_event | Verify all loops check `shutdown_event.is_set()` |
| **External Plugin Integration** | New bridges may lack Circuit Breakers | Require CB wrapper for all external calls |
| **Multi-Hive Support** | hive_id binding may be insufficient | Ensure all signatures include hive_id |

---

## SECURITY INVARIANT VERIFICATION

| Invariant | Status | Notes |
|-----------|--------|-------|
| No silent fund-moving actions in non-autonomous | PARTIAL | Intent commit happens regardless; only execution blocked |
| No unbounded inputs | **FAIL** | `_remote_intents`, `_peer_gossip_times`, contribution_ledger lack caps |
| No global stalls | PARTIAL | RPC_LOCK has no timeout; can deadlock |
| Identity binding | PASS | sender_id checked against payload.peer_id; signatures verify pubkey |
| Replay resistance | PARTIAL | 7-day VOUCH_TTL enables replay window; intents expire but no nonce |
| Determinism | PASS | Tie-breaker uses lexicographic pubkey comparison |
| Pruning | PARTIAL | contribution_ledger pruned at 45 days but no row cap |

---

## IMMEDIATE ACTION ITEMS (Prioritized)

### TODAY (Critical):
- [ ] Add `MAX_REMOTE_INTENTS` cap to `intent_manager.py`
- [ ] Add member verification to `handle_intent` and `handle_gossip`

### THIS WEEK (High):
- [ ] Implement contribution ledger row cap (500k)
- [ ] Add daily event cap to ContributionManager
- [ ] Add RPC lock timeout (10s)

### THIS SPRINT (Medium):
- [ ] Reduce VOUCH_TTL_SECONDS to 24 hours
- [ ] Implement request_id uniqueness enforcement
- [ ] Add challenge rate limiting
- [ ] Harden CircuitBreaker with multi-success requirement

### BACKLOG (Low):
- [ ] Add JSON depth limit (custom decoder)
- [ ] Prune `_peer_gossip_times` dict
- [ ] Move `import json` to top of cl-hive.py

---

## CONCLUSION

The cl-hive codebase demonstrates solid security foundations:
- Proper signature verification
- Magic prefix filtering
- Version checks
- Sender identity binding

However, **resource exhaustion vulnerabilities** are the primary concern. The unbounded caches and ledgers can be weaponized by adversarial peers.

**Key finding:** The code generally assumes connected peers are well-behaved Hive members, but **membership verification is missing from several critical handlers** (INTENT, GOSSIP). This allows non-members to pollute state and consume resources.

**Recommendation:** Adopt a "verify-then-process" pattern for ALL message handlers:
```python
def handle_X(peer_id, payload, plugin):
    if not database.get_member(peer_id):
        return {"result": "continue"}  # Fail closed
    # ... rest of handler
```

---

## SUMMARY STATISTICS

| Category | Count |
|----------|-------|
| **Total Findings** | 22 |
| **Critical** | 0 (revised down from initial assessment) |
| **High** | 4 |
| **Medium** | 11 |
| **Low** | 7 |

---

*End of Audit Report*
