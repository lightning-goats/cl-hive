#!/usr/bin/env python3
"""
cl-hive-oracle: AI Oracle Plugin for cl-hive

This plugin enables AI-powered decision making for Hive nodes by:
1. Connecting to AI provider APIs (Anthropic/Claude)
2. Processing incoming AI Oracle messages from the Hive network
3. Generating and sending AI Oracle responses
4. Managing operator attestations for AI responses
5. Tracking reciprocity and enforcing rate limits

REQUIRES: cl-hive plugin running with AI Oracle message handlers enabled

Usage:
    lightningd --plugin=/path/to/cl-hive-oracle.py \
        --hive-oracle-api-key=sk-ant-... \
        --hive-oracle-model=claude-sonnet-4-20250514
"""

import hashlib
import json
import logging
import os
import threading
import time
from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum
from typing import Any, Callable, Dict, List, Optional, Tuple

from pyln.client import Plugin

# ============================================================================
# Plugin Setup
# ============================================================================

plugin = Plugin()

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s - %(name)s - %(levelname)s - %(message)s"
)
log = logging.getLogger("cl-hive-oracle")

# ============================================================================
# Thread Safety
# ============================================================================

# RPC lock for thread-safe RPC calls
RPC_LOCK = threading.RLock()
RPC_LOCK_TIMEOUT = 10  # seconds


class ThreadSafeRpcProxy:
    """
    Thread-safe wrapper for plugin.rpc.

    All RPC calls are serialized through RPC_LOCK to prevent race conditions
    when multiple background threads access the RPC interface.
    """

    def __init__(self, rpc):
        self._rpc = rpc

    def call(self, method: str, payload: dict = None) -> dict:
        """Make a thread-safe RPC call."""
        acquired = RPC_LOCK.acquire(timeout=RPC_LOCK_TIMEOUT)
        if not acquired:
            log.error(f"RPC lock timeout for {method}")
            return {"error": "RPC lock timeout"}
        try:
            if payload is None:
                return self._rpc.call(method)
            return self._rpc.call(method, payload)
        finally:
            RPC_LOCK.release()

    def __getattr__(self, name: str):
        """Proxy attribute access to underlying RPC with locking."""
        attr = getattr(self._rpc, name)
        if callable(attr):
            def wrapped(*args, **kwargs):
                acquired = RPC_LOCK.acquire(timeout=RPC_LOCK_TIMEOUT)
                if not acquired:
                    log.error(f"RPC lock timeout for {name}")
                    raise TimeoutError(f"RPC lock timeout for {name}")
                try:
                    return attr(*args, **kwargs)
                finally:
                    RPC_LOCK.release()
            return wrapped
        return attr


# Thread-safe RPC proxy (initialized in init())
safe_rpc: Optional[ThreadSafeRpcProxy] = None

# ============================================================================
# Plugin Options
# ============================================================================

plugin.add_option(
    name="hive-oracle-enabled",
    default=True,
    description="Enable AI Oracle mode (requires API key)",
    opt_type="bool"
)

plugin.add_option(
    name="hive-oracle-provider",
    default="anthropic",
    description="AI provider: anthropic, openai, local",
    opt_type="string"
)

plugin.add_option(
    name="hive-oracle-api-key",
    default="",
    description="API key for AI provider (or set ANTHROPIC_API_KEY env var)",
    opt_type="string"
)

plugin.add_option(
    name="hive-oracle-model",
    default="claude-sonnet-4-20250514",
    description="AI model to use for decisions",
    opt_type="string"
)

plugin.add_option(
    name="hive-oracle-max-tokens",
    default=4096,
    description="Maximum tokens for AI responses",
    opt_type="int"
)

plugin.add_option(
    name="hive-oracle-timeout-seconds",
    default=30,
    description="API request timeout in seconds",
    opt_type="int"
)

plugin.add_option(
    name="hive-oracle-poll-interval",
    default=10,
    description="Interval in seconds to poll for incoming messages",
    opt_type="int"
)

plugin.add_option(
    name="hive-oracle-decision-interval",
    default=60,
    description="Interval in seconds to process pending decisions",
    opt_type="int"
)

plugin.add_option(
    name="hive-oracle-state-interval",
    default=300,
    description="Interval in seconds to broadcast state summary (5 min default)",
    opt_type="int"
)

# ============================================================================
# Constants
# ============================================================================

# Rate limits per message type (from spec section 6.3)
RATE_LIMITS = {
    "ai_state_summary": (1, 60),       # 1 per minute
    "ai_opportunity_signal": (10, 3600),  # 10 per hour
    "ai_task_request": (20, 3600),     # 20 per hour
    "ai_strategy_proposal": (5, 86400),  # 5 per day
    "ai_alert": (10, 3600),            # 10 per hour
}

# Default reciprocity threshold
RECIPROCITY_DEBT_LIMIT = -3.0
MAX_OUTSTANDING_TASKS = 5
DEBT_DECAY_DAYS = 30
DEBT_DECAY_FACTOR = 0.5


# ============================================================================
# Enums
# ============================================================================

class OracleState(Enum):
    """Oracle operational state."""
    INITIALIZING = "initializing"
    ACTIVE = "active"
    PAUSED = "paused"
    ERROR = "error"
    SHUTDOWN = "shutdown"


class DecisionType(Enum):
    """Types of decisions the oracle can make."""
    APPROVE = "approve"
    REJECT = "reject"
    DEFER = "defer"
    MODIFY = "modify"


# ============================================================================
# Data Classes
# ============================================================================

@dataclass
class OracleConfig:
    """Oracle configuration snapshot."""
    enabled: bool
    provider: str
    api_key: str
    model: str
    max_tokens: int
    timeout_seconds: int
    poll_interval: int
    decision_interval: int
    state_interval: int


@dataclass
class Attestation:
    """Operator attestation of AI response."""
    response_id: str
    model_claimed: str
    timestamp: int
    operator_pubkey: str
    api_endpoint: str
    response_hash: str
    operator_signature: str = ""


@dataclass
class ReciprocityLedger:
    """Track reciprocity balance with a peer."""
    peer_id: str
    balance: float = 0.0
    lifetime_requested: int = 0
    lifetime_fulfilled: int = 0
    last_request_timestamp: int = 0
    last_fulfillment_timestamp: int = 0
    outstanding_tasks: int = 0


@dataclass
class AIDecision:
    """Record of an AI decision."""
    decision_id: str
    timestamp: int
    action_type: str
    decision: str
    confidence: float
    reasoning_factors: List[str]
    attestation: Optional[Attestation] = None
    executed: bool = False
    result: str = ""


@dataclass
class OracleStats:
    """Oracle runtime statistics."""
    uptime_seconds: int = 0
    decisions_24h: int = 0
    decisions_pending: int = 0
    api_calls_24h: int = 0
    api_latency_avg_ms: float = 0.0
    api_success_rate_pct: float = 100.0
    messages_sent_24h: int = 0
    messages_received_24h: int = 0
    last_decision_timestamp: int = 0


# ============================================================================
# Global State
# ============================================================================

# Initialized in init()
our_pubkey: str = ""
config: Optional[OracleConfig] = None
state: OracleState = OracleState.INITIALIZING
stats: OracleStats = OracleStats()
shutdown_event: threading.Event = threading.Event()
start_time: float = 0.0

# Locks
state_lock = threading.Lock()
stats_lock = threading.Lock()

# Caches
reciprocity_ledgers: Dict[str, ReciprocityLedger] = {}
decision_history: List[AIDecision] = []
outgoing_rate_tracker: Dict[str, List[float]] = {}  # msg_type -> timestamps


# ============================================================================
# AI Provider Interface
# ============================================================================

class AIProvider:
    """Base class for AI providers."""

    def __init__(self, api_key: str, model: str, max_tokens: int, timeout: int):
        self.api_key = api_key
        self.model = model
        self.max_tokens = max_tokens
        self.timeout = timeout

    def complete(self, messages: List[Dict], system_prompt: str = "") -> Tuple[Optional[Dict], Optional[str]]:
        """
        Send completion request to AI provider.
        Returns (response_dict, error_message).
        """
        raise NotImplementedError


class AnthropicProvider(AIProvider):
    """Anthropic (Claude) API provider."""

    API_ENDPOINT = "https://api.anthropic.com/v1/messages"
    API_VERSION = "2023-06-01"

    def complete(self, messages: List[Dict], system_prompt: str = "") -> Tuple[Optional[Dict], Optional[str]]:
        """Send completion request to Anthropic API."""
        try:
            import urllib.request
            import urllib.error

            headers = {
                "Content-Type": "application/json",
                "x-api-key": self.api_key,
                "anthropic-version": self.API_VERSION,
            }

            data = {
                "model": self.model,
                "max_tokens": self.max_tokens,
                "messages": messages,
            }

            if system_prompt:
                data["system"] = system_prompt

            request = urllib.request.Request(
                self.API_ENDPOINT,
                data=json.dumps(data).encode("utf-8"),
                headers=headers,
                method="POST"
            )

            start_time = time.time()
            with urllib.request.urlopen(request, timeout=self.timeout) as response:
                latency_ms = (time.time() - start_time) * 1000
                result = json.loads(response.read().decode("utf-8"))
                result["_latency_ms"] = latency_ms
                return result, None

        except urllib.error.HTTPError as e:
            error_body = e.read().decode("utf-8") if e.fp else str(e)
            log.error(f"Anthropic API error {e.code}: {error_body}")
            return None, f"API error {e.code}: {error_body[:200]}"
        except urllib.error.URLError as e:
            log.error(f"Anthropic API connection error: {e.reason}")
            return None, f"Connection error: {e.reason}"
        except Exception as e:
            log.error(f"Anthropic API unexpected error: {e}")
            return None, f"Unexpected error: {str(e)[:200]}"


class LocalProvider(AIProvider):
    """Local/mock provider for testing."""

    def complete(self, messages: List[Dict], system_prompt: str = "") -> Tuple[Optional[Dict], Optional[str]]:
        """Return mock response for testing."""
        return {
            "id": f"mock_{int(time.time())}",
            "model": "mock-local",
            "content": [{"type": "text", "text": "Mock response"}],
            "_latency_ms": 10.0
        }, None


def get_provider(config: OracleConfig) -> Optional[AIProvider]:
    """Factory function to create AI provider instance."""
    api_key = config.api_key or os.environ.get("ANTHROPIC_API_KEY", "")

    if not api_key and config.provider != "local":
        log.error("No API key configured (set hive-oracle-api-key or ANTHROPIC_API_KEY)")
        return None

    if config.provider == "anthropic":
        return AnthropicProvider(
            api_key=api_key,
            model=config.model,
            max_tokens=config.max_tokens,
            timeout=config.timeout_seconds
        )
    elif config.provider == "local":
        return LocalProvider(
            api_key="",
            model="local",
            max_tokens=config.max_tokens,
            timeout=config.timeout_seconds
        )
    else:
        log.error(f"Unknown provider: {config.provider}")
        return None


# ============================================================================
# Attestation Functions
# ============================================================================

def create_attestation(
    api_response: Dict,
    node_pubkey: str,
    rpc: Any,
    provider: str = "anthropic"
) -> Optional[Attestation]:
    """
    Create operator-signed attestation of AI response.

    Per spec section 6.7.1, all AI decisions must include attestations.
    """
    try:
        response_id = api_response.get("id", f"unknown_{int(time.time())}")
        model_claimed = api_response.get("model", "unknown")
        timestamp = int(time.time())

        # Determine API endpoint
        api_endpoint = {
            "anthropic": "api.anthropic.com",
            "openai": "api.openai.com",
            "local": "localhost"
        }.get(provider, "unknown")

        # Hash the response
        response_hash = hashlib.sha256(
            json.dumps(api_response, sort_keys=True).encode()
        ).hexdigest()

        attestation = Attestation(
            response_id=response_id,
            model_claimed=model_claimed,
            timestamp=timestamp,
            operator_pubkey=node_pubkey,
            api_endpoint=api_endpoint,
            response_hash=response_hash
        )

        # Create signing payload (everything except signature)
        sign_payload = json.dumps({
            "response_id": attestation.response_id,
            "model_claimed": attestation.model_claimed,
            "timestamp": attestation.timestamp,
            "operator_pubkey": attestation.operator_pubkey,
            "api_endpoint": attestation.api_endpoint,
            "response_hash": attestation.response_hash
        }, sort_keys=True)

        # Sign with node's Lightning key via HSM
        sign_result = rpc.signmessage(sign_payload)
        attestation.operator_signature = sign_result.get("signature", "")

        return attestation

    except Exception as e:
        log.error(f"Failed to create attestation: {e}")
        return None


def attestation_to_dict(attestation: Attestation) -> Dict[str, Any]:
    """Convert attestation to dictionary for inclusion in messages."""
    return {
        "response_id": attestation.response_id,
        "model_claimed": attestation.model_claimed,
        "timestamp": attestation.timestamp,
        "operator_pubkey": attestation.operator_pubkey,
        "api_endpoint": attestation.api_endpoint,
        "response_hash": attestation.response_hash,
        "operator_signature": attestation.operator_signature
    }


# ============================================================================
# Reciprocity Tracking
# ============================================================================

def get_reciprocity_ledger(peer_id: str) -> ReciprocityLedger:
    """Get or create reciprocity ledger for a peer."""
    if peer_id not in reciprocity_ledgers:
        reciprocity_ledgers[peer_id] = ReciprocityLedger(peer_id=peer_id)
    return reciprocity_ledgers[peer_id]


def apply_debt_decay(ledger: ReciprocityLedger) -> None:
    """Apply debt decay per spec section 6.6."""
    if ledger.balance >= 0:
        return

    now = int(time.time())
    days_since_request = (now - ledger.last_request_timestamp) / 86400

    if days_since_request > DEBT_DECAY_DAYS:
        # Decay by 50% for debt older than 30 days
        ledger.balance = ledger.balance * DEBT_DECAY_FACTOR


def can_accept_task(requester_id: str) -> Tuple[bool, str]:
    """
    Check if we should accept a task from this peer.
    Per spec section 6.6.
    """
    ledger = get_reciprocity_ledger(requester_id)
    apply_debt_decay(ledger)

    # Reject chronic freeloaders
    if ledger.balance < RECIPROCITY_DEBT_LIMIT:
        return False, "reciprocity_debt_exceeded"

    # Reject rapid-fire requests
    if ledger.outstanding_tasks >= MAX_OUTSTANDING_TASKS:
        return False, "too_many_outstanding_requests"

    return True, ""


def record_task_requested(peer_id: str) -> None:
    """Record that we requested a task from a peer."""
    ledger = get_reciprocity_ledger(peer_id)
    ledger.balance -= 1.0
    ledger.lifetime_requested += 1
    ledger.last_request_timestamp = int(time.time())


def record_task_fulfilled(peer_id: str) -> None:
    """Record that a peer fulfilled our task request."""
    ledger = get_reciprocity_ledger(peer_id)
    ledger.balance += 1.0
    ledger.lifetime_fulfilled += 1
    ledger.last_fulfillment_timestamp = int(time.time())
    ledger.outstanding_tasks = max(0, ledger.outstanding_tasks - 1)


# ============================================================================
# Rate Limiting (Outgoing Messages)
# ============================================================================

def check_outgoing_rate(msg_type: str) -> Tuple[bool, str]:
    """Check if we can send a message of this type."""
    if msg_type not in RATE_LIMITS:
        return True, ""

    limit, window_seconds = RATE_LIMITS[msg_type]
    now = time.time()
    cutoff = now - window_seconds

    if msg_type not in outgoing_rate_tracker:
        outgoing_rate_tracker[msg_type] = []

    # Clean old entries
    outgoing_rate_tracker[msg_type] = [
        ts for ts in outgoing_rate_tracker[msg_type] if ts > cutoff
    ]

    if len(outgoing_rate_tracker[msg_type]) >= limit:
        return False, f"Rate limit: {limit} per {window_seconds}s"

    return True, ""


def record_outgoing_message(msg_type: str) -> None:
    """Record that we sent a message."""
    if msg_type not in outgoing_rate_tracker:
        outgoing_rate_tracker[msg_type] = []
    outgoing_rate_tracker[msg_type].append(time.time())


# ============================================================================
# Stats Tracking
# ============================================================================

def update_stats_api_call(latency_ms: float, success: bool) -> None:
    """Update API call statistics."""
    with stats_lock:
        stats.api_calls_24h += 1
        # Simple moving average for latency
        stats.api_latency_avg_ms = (
            stats.api_latency_avg_ms * 0.9 + latency_ms * 0.1
        )
        # Update success rate
        if success:
            stats.api_success_rate_pct = min(100.0, stats.api_success_rate_pct + 0.1)
        else:
            stats.api_success_rate_pct = max(0.0, stats.api_success_rate_pct - 1.0)


def update_stats_decision() -> None:
    """Record a decision was made."""
    with stats_lock:
        stats.decisions_24h += 1
        stats.last_decision_timestamp = int(time.time())


def update_stats_message_sent() -> None:
    """Record a message was sent."""
    with stats_lock:
        stats.messages_sent_24h += 1


def update_stats_message_received() -> None:
    """Record a message was received."""
    with stats_lock:
        stats.messages_received_24h += 1


def get_stats_snapshot() -> Dict[str, Any]:
    """Get current stats as a dictionary."""
    with stats_lock:
        uptime = int(time.time() - start_time) if start_time > 0 else 0
        return {
            "uptime_seconds": uptime,
            "decisions_24h": stats.decisions_24h,
            "decisions_pending": stats.decisions_pending,
            "api_calls_24h": stats.api_calls_24h,
            "api_latency_avg_ms": round(stats.api_latency_avg_ms, 2),
            "api_success_rate_pct": round(stats.api_success_rate_pct, 2),
            "messages_sent_24h": stats.messages_sent_24h,
            "messages_received_24h": stats.messages_received_24h,
            "last_decision_timestamp": stats.last_decision_timestamp
        }


# ============================================================================
# Message Generation (Stubs - to be implemented with protocol.py imports)
# ============================================================================

def generate_state_summary(rpc: Any, provider: AIProvider) -> Optional[Dict]:
    """
    Generate and broadcast AI_STATE_SUMMARY message via cl-hive RPC.

    This delegates to cl-hive's hive-ai-broadcast-state-summary command
    which handles node state query, message signing, and broadcast.

    Args:
        rpc: RPC interface to call cl-hive commands
        provider: AI provider instance (for confidence estimation)

    Returns:
        Dict with broadcast result, or None on error
    """
    try:
        # Determine current focus based on recent activity
        # For now, use maintenance as default
        current_focus = "maintenance"

        # Get stats for the message
        current_stats = get_stats_snapshot()

        # Create attestation if we have a recent API response
        attestation = None
        # Note: Attestation would be created when AI makes a decision

        result = rpc.call("hive-ai-broadcast-state-summary", {
            "current_focus": current_focus,
            "seeking_categories": [],
            "avoid_categories": [],
            "ai_confidence": 0.75,  # Default confidence when active
            "decisions_last_24h": current_stats.get("decisions_24h", 0),
            "strategy_alignment": "cooperative",
            "attestation": attestation
        })

        if result.get("error"):
            log.warning(f"State summary broadcast failed: {result['error']}")
            return None

        log.debug(f"State summary broadcast: {result.get('sent_count', 0)} peers")
        return result

    except Exception as e:
        log.error(f"Failed to generate state summary: {e}")
        return None


def generate_heartbeat(rpc: Any) -> Optional[Dict]:
    """
    Generate and broadcast AI_HEARTBEAT message via cl-hive RPC.

    This delegates to cl-hive's hive-ai-broadcast-heartbeat command
    which handles message creation, signing, and broadcast.

    Args:
        rpc: RPC interface to call cl-hive commands

    Returns:
        Dict with broadcast result, or None on error
    """
    try:
        # Get current stats
        current_stats = get_stats_snapshot()

        # Determine operational state
        if state == OracleState.ACTIVE:
            op_state = "active"
        elif state == OracleState.PAUSED:
            op_state = "paused"
        elif state == OracleState.ERROR:
            op_state = "degraded"
        else:
            op_state = "offline"

        result = rpc.call("hive-ai-broadcast-heartbeat", {
            "operational_state": op_state,
            "model_claimed": config.model if config else "",
            "model_version": "",  # Could extract from model name
            "uptime_seconds": current_stats.get("uptime_seconds", 0),
            "last_decision_timestamp": current_stats.get("last_decision_timestamp", 0),
            "decisions_24h": current_stats.get("decisions_24h", 0),
            "decisions_pending": current_stats.get("decisions_pending", 0),
            "api_latency_ms": int(current_stats.get("api_latency_avg_ms", 0)),
            "api_success_rate_pct": current_stats.get("api_success_rate_pct", 100.0),
            "error_rate_24h": 0.0,  # Could track this
            "supported_task_types": ["expand_to", "rebalance_toward", "adjust_fees", "probe_route"],
            "strategy_participation": True,
            "delegation_acceptance": True,
            "attestation": None
        })

        if result.get("error"):
            log.warning(f"Heartbeat broadcast failed: {result['error']}")
            return None

        log.debug(f"Heartbeat broadcast: {result.get('sent_count', 0)} peers")
        return result

    except Exception as e:
        log.error(f"Failed to generate heartbeat: {e}")
        return None


# ============================================================================
# Decision Making (Stubs - core AI logic)
# ============================================================================

def process_pending_action(action: Dict, rpc: Any, provider: AIProvider) -> Optional[AIDecision]:
    """
    Process a pending action through the AI oracle.

    This is the core decision-making function that:
    1. Formats the action as a prompt
    2. Sends to AI provider
    3. Parses the response
    4. Creates attestation
    5. Returns decision
    """
    action_id = action.get("id", 0)
    action_type = action.get("action_type", "unknown")
    payload = action.get("payload", {})

    log.info(f"Processing pending action {action_id}: {action_type}")

    # Build system prompt based on action type
    system_prompt = _build_decision_system_prompt(action_type)

    # Build user message with action context
    user_message = _build_decision_user_message(action, rpc)

    # Call AI provider
    response, error = provider.complete(
        [{"role": "user", "content": user_message}],
        system_prompt
    )

    if error:
        log.error(f"AI provider error for action {action_id}: {error}")
        update_stats_api_call(0, False)
        return None

    latency_ms = response.get("_latency_ms", 0)
    update_stats_api_call(latency_ms, True)

    # Parse the response
    decision_result = _parse_decision_response(response)
    if not decision_result:
        log.warning(f"Failed to parse AI response for action {action_id}")
        return None

    decision_type, confidence, reasoning_factors = decision_result

    # Create attestation
    attestation = create_attestation(response, our_pubkey, rpc, config.provider if config else "anthropic")

    # Build AIDecision
    decision = AIDecision(
        decision_id=f"dec_{action_id}_{int(time.time())}",
        timestamp=int(time.time()),
        action_type=action_type,
        decision=decision_type,
        confidence=confidence,
        reasoning_factors=reasoning_factors,
        attestation=attestation,
        executed=False,
        result=""
    )

    # Execute the decision via cl-hive RPC
    try:
        if decision_type == "approve":
            result = rpc.call("hive-action-execute", {"action_id": action_id})
            decision.executed = True
            decision.result = "executed"
            log.info(f"Action {action_id} approved and executed")
        elif decision_type == "reject":
            result = rpc.call("hive-action-reject", {
                "action_id": action_id,
                "reason": "ai_oracle_rejected",
                "factors": reasoning_factors
            })
            decision.result = "rejected"
            log.info(f"Action {action_id} rejected: {reasoning_factors}")
        elif decision_type == "defer":
            # Keep pending for next cycle
            decision.result = "deferred"
            log.info(f"Action {action_id} deferred for later")
        elif decision_type == "modify":
            # Modify would need to update the action - keep pending
            decision.result = "needs_modification"
            log.info(f"Action {action_id} needs modification")
    except Exception as e:
        log.error(f"Failed to execute decision for action {action_id}: {e}")
        decision.result = f"execution_error: {str(e)[:100]}"

    return decision


def _build_decision_system_prompt(action_type: str) -> str:
    """Build system prompt for decision making based on action type."""
    base_prompt = """You are an AI oracle managing a Lightning Network node as part of a coordinated fleet (Hive).
Your role is to make prudent decisions about node operations while maintaining safety and profitability.

DECISION FRAMEWORK:
- Approve actions that benefit the node and fleet
- Reject actions that are risky, unprofitable, or violate safety constraints
- Defer when more information is needed or timing is not optimal
- Always consider: liquidity impact, fee revenue, network position, risk

RESPONSE FORMAT (JSON only, no other text):
{
  "decision": "approve" | "reject" | "defer" | "modify",
  "confidence": 0.0-1.0,
  "reasoning_factors": ["factor1", "factor2", ...],
  "modifications": null | {...}
}

ALLOWED REASONING FACTORS:
- volume_elasticity, competitor_response, market_timing, alternative_available
- fee_trend, capacity_constraint, liquidity_need, reputation_score
- position_advantage, cost_benefit, risk_assessment, strategic_alignment
"""

    action_specific = {
        "channel_open": """
ACTION TYPE: Channel Open
Consider: target node quality, capacity allocation, fee potential, existing connectivity, on-chain fee cost.
Approve if: target is well-connected, good ROI expected, we have capacity.
Reject if: poor target, insufficient funds, already well-connected to target's region.""",

        "channel_close": """
ACTION TYPE: Channel Close
Consider: channel profitability, peer reliability, liquidity needs, on-chain fee cost.
Approve if: channel is consistently unprofitable or peer is unreliable.
Reject if: channel is profitable or closure timing is poor (high on-chain fees).""",

        "fee_adjustment": """
ACTION TYPE: Fee Adjustment
Consider: current market rates, volume elasticity, competitor fees, corridor demand.
Approve if: adjustment aligns with market and maintains competitiveness.
Reject if: change would price us out of market or undercut profitability.""",

        "rebalance": """
ACTION TYPE: Rebalance
Consider: cost vs benefit, liquidity distribution, expected routing volume.
Approve if: cost is reasonable and improves routing capacity.
Reject if: cost exceeds expected revenue improvement.""",

        "expansion": """
ACTION TYPE: Expansion (coordinated channel open)
Consider: fleet strategy, target importance, coordination benefits.
Approve if: improves fleet coverage and expected to be profitable.
Reject if: duplicates existing fleet coverage or poor target.""",
    }

    specific = action_specific.get(action_type, f"""
ACTION TYPE: {action_type}
Evaluate based on general safety and profitability criteria.""")

    return base_prompt + specific


def _build_decision_user_message(action: Dict, rpc: Any) -> str:
    """Build user message with action context for AI decision."""
    action_id = action.get("id", 0)
    action_type = action.get("action_type", "unknown")
    payload = action.get("payload", {})
    proposed_at = action.get("proposed_at", 0)

    # Get node context
    node_context = {}
    try:
        # Get basic node info
        info = rpc.call("getinfo")
        node_context["our_alias"] = info.get("alias", "")
        node_context["blockheight"] = info.get("blockheight", 0)

        # Get funds summary
        funds = rpc.call("listfunds")
        outputs = funds.get("outputs", [])
        channels = funds.get("channels", [])

        node_context["onchain_balance_sats"] = sum(o.get("amount_msat", 0) // 1000 for o in outputs if o.get("status") == "confirmed")
        node_context["channel_count"] = len(channels)
        node_context["total_channel_capacity_sats"] = sum(c.get("amount_msat", 0) // 1000 for c in channels)

    except Exception as e:
        log.warning(f"Failed to get node context: {e}")

    message = f"""PENDING ACTION FOR REVIEW:

Action ID: {action_id}
Action Type: {action_type}
Proposed At: {time.strftime('%Y-%m-%d %H:%M:%S UTC', time.gmtime(proposed_at))}

Payload:
{json.dumps(payload, indent=2)}

Node Context:
- Alias: {node_context.get('our_alias', 'unknown')}
- Block Height: {node_context.get('blockheight', 0)}
- On-chain Balance: {node_context.get('onchain_balance_sats', 0):,} sats
- Channel Count: {node_context.get('channel_count', 0)}
- Total Channel Capacity: {node_context.get('total_channel_capacity_sats', 0):,} sats

Please evaluate this action and provide your decision in the required JSON format."""

    return message


def _parse_decision_response(response: Dict) -> Optional[Tuple[str, float, List[str]]]:
    """Parse AI response to extract decision, confidence, and factors."""
    try:
        # Get text content from response
        content = response.get("content", [])
        if not content:
            return None

        text = ""
        for block in content:
            if block.get("type") == "text":
                text = block.get("text", "")
                break

        if not text:
            return None

        # Try to parse JSON from response
        # Handle case where JSON is embedded in markdown code block
        if "```json" in text:
            start = text.find("```json") + 7
            end = text.find("```", start)
            text = text[start:end].strip()
        elif "```" in text:
            start = text.find("```") + 3
            end = text.find("```", start)
            text = text[start:end].strip()

        # Parse JSON
        parsed = json.loads(text)

        decision = parsed.get("decision", "defer")
        if decision not in ["approve", "reject", "defer", "modify"]:
            decision = "defer"

        confidence = float(parsed.get("confidence", 0.5))
        confidence = max(0.0, min(1.0, confidence))

        reasoning_factors = parsed.get("reasoning_factors", [])
        if not isinstance(reasoning_factors, list):
            reasoning_factors = []

        # Validate factors against allowed list
        allowed_factors = {
            "volume_elasticity", "competitor_response", "market_timing", "alternative_available",
            "fee_trend", "capacity_constraint", "liquidity_need", "reputation_score",
            "position_advantage", "cost_benefit", "risk_assessment", "strategic_alignment"
        }
        reasoning_factors = [f for f in reasoning_factors if f in allowed_factors]

        return decision, confidence, reasoning_factors

    except json.JSONDecodeError as e:
        log.warning(f"Failed to parse JSON from AI response: {e}")
        return None
    except Exception as e:
        log.warning(f"Error parsing AI response: {e}")
        return None


def process_incoming_message(msg_type: str, payload: Dict, sender: str, rpc: Any, provider: AIProvider) -> None:
    """
    Process an incoming AI Oracle message.

    This determines the appropriate response (if any) to incoming messages.
    Handlers are organized by message category per spec section 3.1.
    """
    log.debug(f"process_incoming_message: {msg_type} from {sender[:16]}...")
    update_stats_message_received()

    # Route to appropriate handler based on message type
    handlers = {
        # Information Sharing (32800-32809)
        "ai_state_summary": _handle_state_summary,
        "ai_opportunity_signal": _handle_opportunity_signal,
        "ai_market_assessment": _handle_market_assessment,

        # Task Coordination (32810-32819)
        "ai_task_request": _handle_task_request,
        "ai_task_response": _handle_task_response,
        "ai_task_complete": _handle_task_complete,
        "ai_task_cancel": _handle_task_cancel,

        # Strategy Coordination (32820-32829)
        "ai_strategy_proposal": _handle_strategy_proposal,
        "ai_strategy_vote": _handle_strategy_vote,
        "ai_strategy_result": _handle_strategy_result,
        "ai_strategy_update": _handle_strategy_update,

        # Reasoning Exchange (32830-32839)
        "ai_reasoning_request": _handle_reasoning_request,
        "ai_reasoning_response": _handle_reasoning_response,

        # Health & Alerts (32840-32849)
        "ai_heartbeat": _handle_heartbeat,
        "ai_alert": _handle_alert,
    }

    handler = handlers.get(msg_type)
    if handler:
        try:
            handler(payload, sender, rpc, provider)
        except Exception as e:
            log.error(f"Error in handler for {msg_type}: {e}")
    else:
        log.warning(f"Unknown AI message type: {msg_type}")


# ============================================================================
# Message Handlers - Information Sharing
# ============================================================================

def _handle_state_summary(payload: Dict, sender: str, rpc: Any, provider: AIProvider) -> None:
    """Handle AI_STATE_SUMMARY - periodic state broadcast from peer AI."""
    # Just log for now - could be used for fleet awareness
    liquidity = payload.get("liquidity", {})
    priorities = payload.get("priorities", {})
    ai_meta = payload.get("ai_meta", {})

    log.debug(
        f"State summary from {sender[:16]}: "
        f"status={liquidity.get('status', 'unknown')}, "
        f"focus={priorities.get('current_focus', 'unknown')}, "
        f"confidence={ai_meta.get('confidence', 0):.2f}"
    )


def _handle_opportunity_signal(payload: Dict, sender: str, rpc: Any, provider: AIProvider) -> None:
    """Handle AI_OPPORTUNITY_SIGNAL - peer identified an opportunity."""
    opportunity = payload.get("opportunity", {})
    recommendation = payload.get("recommendation", {})
    volunteer = payload.get("volunteer", {})

    target = opportunity.get("target_node", "")[:16]
    opp_type = opportunity.get("opportunity_type", "unknown")
    action = recommendation.get("action", "unknown")
    confidence = recommendation.get("confidence", 0)

    log.info(
        f"Opportunity signal from {sender[:16]}: "
        f"target={target}..., type={opp_type}, action={action}, confidence={confidence:.2f}"
    )

    # If sender is volunteering and we have capacity, we might delegate
    # For now, just log and let decision loop handle if relevant


def _handle_market_assessment(payload: Dict, sender: str, rpc: Any, provider: AIProvider) -> None:
    """Handle AI_MARKET_ASSESSMENT - market analysis from peer."""
    assessment_type = payload.get("assessment_type", "unknown")
    recommendation = payload.get("recommendation", {})
    confidence = payload.get("confidence", 0)

    log.debug(
        f"Market assessment from {sender[:16]}: "
        f"type={assessment_type}, stance={recommendation.get('overall_stance', 'unknown')}, "
        f"confidence={confidence:.2f}"
    )


# ============================================================================
# Message Handlers - Task Coordination
# ============================================================================

def _handle_task_request(payload: Dict, sender: str, rpc: Any, provider: AIProvider) -> None:
    """Handle AI_TASK_REQUEST - peer requesting us to perform a task."""
    request_id = payload.get("request_id", "")
    task = payload.get("task", {})
    compensation = payload.get("compensation", {})

    task_type = task.get("task_type", "unknown")
    target = task.get("target", "")[:16] if task.get("target") else ""
    priority = task.get("priority", "normal")

    log.info(f"Task request from {sender[:16]}: {task_type} (priority={priority})")

    # Check reciprocity before accepting
    can_accept, reason = can_accept_task(sender)
    if not can_accept:
        log.info(f"Rejecting task from {sender[:16]}: {reason}")
        _send_task_response(rpc, sender, request_id, "reject", reason)
        return

    # Check rate limits
    can_send, rate_reason = check_outgoing_rate("ai_task_response")
    if not can_send:
        log.warning(f"Rate limited, cannot respond to task request: {rate_reason}")
        return

    # Evaluate task using AI
    response = _evaluate_task_request(task, sender, rpc, provider)

    if response == "accept":
        # Record that sender has an outstanding task
        ledger = get_reciprocity_ledger(sender)
        ledger.outstanding_tasks += 1
        log.info(f"Accepting task {request_id} from {sender[:16]}")
    else:
        log.info(f"Declining task {request_id} from {sender[:16]}: {response}")

    _send_task_response(rpc, sender, request_id, response, "")


def _evaluate_task_request(task: Dict, sender: str, rpc: Any, provider: AIProvider) -> str:
    """Use AI to evaluate whether to accept a task request."""
    task_type = task.get("task_type", "unknown")
    parameters = task.get("parameters", {})

    # Simple evaluation - could be enhanced with full AI call
    supported_tasks = ["expand_to", "rebalance_toward", "adjust_fees", "probe_route"]
    if task_type not in supported_tasks:
        return "reject"

    # Check if we have capacity for expand_to
    if task_type == "expand_to":
        amount = parameters.get("amount_sats", 0)
        try:
            funds = rpc.call("listfunds")
            outputs = funds.get("outputs", [])
            onchain = sum(o.get("amount_msat", 0) // 1000 for o in outputs if o.get("status") == "confirmed")
            if onchain < amount + 50000:  # Need buffer for fees
                return "reject"
        except Exception:
            return "defer"

    return "accept"


def _send_task_response(rpc: Any, target: str, request_id: str, response: str, reason: str) -> None:
    """Send task response to peer via cl-hive RPC."""
    try:
        result = rpc.call("hive-ai-send-task-response", {
            "target_node": target,
            "request_id": request_id,
            "response": response,
            "reason": reason
        })
        if result.get("error"):
            log.warning(f"Failed to send task response: {result['error']}")
        else:
            record_outgoing_message("ai_task_response")
            update_stats_message_sent()
    except Exception as e:
        log.error(f"Error sending task response: {e}")


def _handle_task_response(payload: Dict, sender: str, rpc: Any, provider: AIProvider) -> None:
    """Handle AI_TASK_RESPONSE - response to our task request."""
    request_id = payload.get("request_id", "")
    response = payload.get("response", "reject")
    acceptance = payload.get("acceptance", {})

    log.info(f"Task response from {sender[:16]}: {response} for {request_id}")

    if response == "accept":
        # They accepted our task - track it
        record_task_requested(sender)
        log.info(f"Task {request_id} accepted by {sender[:16]}")
    elif response == "reject":
        rejection = payload.get("rejection", {})
        reason = rejection.get("reason", "unknown")
        log.info(f"Task {request_id} rejected by {sender[:16]}: {reason}")


def _handle_task_complete(payload: Dict, sender: str, rpc: Any, provider: AIProvider) -> None:
    """Handle AI_TASK_COMPLETE - notification that delegated task is done."""
    request_id = payload.get("request_id", "")
    status = payload.get("status", "unknown")
    result = payload.get("result", {})

    log.info(f"Task complete from {sender[:16]}: {request_id} status={status}")

    if status == "success":
        # Credit them for completing the task
        record_task_fulfilled(sender)
        log.info(f"Task {request_id} completed successfully by {sender[:16]}")

        # Log learnings if provided
        learnings = payload.get("learnings", {})
        if learnings.get("recommended_for_future"):
            log.debug(f"Peer {sender[:16]} recommended for future tasks")


def _handle_task_cancel(payload: Dict, sender: str, rpc: Any, provider: AIProvider) -> None:
    """Handle AI_TASK_CANCEL - requester canceling a task."""
    request_id = payload.get("request_id", "")
    reason = payload.get("reason", "unknown")

    log.info(f"Task cancel from {sender[:16]}: {request_id} reason={reason}")

    # Decrement outstanding tasks if we had one pending
    ledger = get_reciprocity_ledger(sender)
    if ledger.outstanding_tasks > 0:
        ledger.outstanding_tasks -= 1


# ============================================================================
# Message Handlers - Strategy Coordination
# ============================================================================

def _handle_strategy_proposal(payload: Dict, sender: str, rpc: Any, provider: AIProvider) -> None:
    """Handle AI_STRATEGY_PROPOSAL - fleet strategy proposal."""
    proposal_id = payload.get("proposal_id", "")
    strategy = payload.get("strategy", {})
    voting = payload.get("voting", {})

    strategy_type = strategy.get("strategy_type", "unknown")
    name = strategy.get("name", "unnamed")
    deadline = voting.get("voting_deadline_timestamp", 0)

    log.info(
        f"Strategy proposal from {sender[:16]}: "
        f"{strategy_type} - {name} (proposal_id={proposal_id})"
    )

    # Evaluate the proposal using AI
    vote = _evaluate_strategy_proposal(strategy, voting, sender, rpc, provider)

    # Send our vote
    if vote:
        _send_strategy_vote(rpc, proposal_id, vote, sender)


def _evaluate_strategy_proposal(
    strategy: Dict,
    voting: Dict,
    proposer: str,
    rpc: Any,
    provider: AIProvider
) -> Optional[str]:
    """Use AI to evaluate a strategy proposal and decide vote."""
    strategy_type = strategy.get("strategy_type", "unknown")
    expected_outcomes = strategy.get("expected_outcomes", {})
    risks = strategy.get("risks", [])

    # Simple heuristic evaluation - could use full AI
    # Approve if expected positive outcome with reasonable confidence
    revenue_change = expected_outcomes.get("revenue_change_pct", 0)
    confidence = expected_outcomes.get("confidence", 0)
    opt_out_allowed = strategy.get("opt_out_allowed", False)

    if revenue_change > 0 and confidence > 0.5:
        if opt_out_allowed or len(risks) == 0:
            return "approve"
        elif len(risks) <= 2:
            return "approve"

    # Abstain if uncertain
    if confidence < 0.3:
        return "abstain"

    return "reject"


def _send_strategy_vote(rpc: Any, proposal_id: str, vote: str, proposer: str) -> None:
    """Send strategy vote via cl-hive RPC."""
    try:
        # Check rate limit
        can_send, reason = check_outgoing_rate("ai_strategy_vote")
        if not can_send:
            log.warning(f"Rate limited, cannot send strategy vote: {reason}")
            return

        result = rpc.call("hive-ai-send-strategy-vote", {
            "proposal_id": proposal_id,
            "vote": vote,
            "rationale": {
                "factors": ["cost_benefit", "risk_assessment"],
                "confidence_in_proposal": 0.6
            }
        })

        if result.get("error"):
            log.warning(f"Failed to send strategy vote: {result['error']}")
        else:
            record_outgoing_message("ai_strategy_vote")
            update_stats_message_sent()
            log.info(f"Voted {vote} on proposal {proposal_id}")

    except Exception as e:
        log.error(f"Error sending strategy vote: {e}")


def _handle_strategy_vote(payload: Dict, sender: str, rpc: Any, provider: AIProvider) -> None:
    """Handle AI_STRATEGY_VOTE - peer's vote on a proposal."""
    proposal_id = payload.get("proposal_id", "")
    vote = payload.get("vote", "abstain")

    log.debug(f"Strategy vote from {sender[:16]}: {vote} on {proposal_id}")


def _handle_strategy_result(payload: Dict, sender: str, rpc: Any, provider: AIProvider) -> None:
    """Handle AI_STRATEGY_RESULT - outcome of strategy vote."""
    proposal_id = payload.get("proposal_id", "")
    result = payload.get("result", "unknown")
    voting_summary = payload.get("voting_summary", {})

    votes_for = voting_summary.get("votes_for", 0)
    votes_against = voting_summary.get("votes_against", 0)
    approval_pct = voting_summary.get("approval_pct", 0)

    log.info(
        f"Strategy result for {proposal_id}: {result} "
        f"({votes_for} for, {votes_against} against, {approval_pct:.1f}% approval)"
    )


def _handle_strategy_update(payload: Dict, sender: str, rpc: Any, provider: AIProvider) -> None:
    """Handle AI_STRATEGY_UPDATE - progress on active strategy."""
    proposal_id = payload.get("proposal_id", "")
    progress = payload.get("progress", {})
    metrics = payload.get("metrics", {})

    phase = progress.get("phase", "unknown")
    completion = progress.get("completion_pct", 0)
    on_track = metrics.get("on_track", False)

    log.debug(
        f"Strategy update for {proposal_id}: "
        f"phase={phase}, {completion:.1f}% complete, on_track={on_track}"
    )


# ============================================================================
# Message Handlers - Reasoning Exchange
# ============================================================================

def _handle_reasoning_request(payload: Dict, sender: str, rpc: Any, provider: AIProvider) -> None:
    """Handle AI_REASONING_REQUEST - peer asking for our reasoning."""
    request_id = payload.get("request_id", "")
    context = payload.get("context", {})
    detail_level = payload.get("detail_level", "summary")

    reference_type = context.get("reference_type", "unknown")
    reference_id = context.get("reference_id", "")

    log.info(f"Reasoning request from {sender[:16]}: {reference_type} ({reference_id})")

    # Check reciprocity
    can_accept, reason = can_accept_task(sender)
    if not can_accept:
        log.info(f"Rejecting reasoning request from {sender[:16]}: {reason}")
        return

    # For now, send a simple response
    # Could be enhanced to use AI for detailed reasoning
    _send_reasoning_response(rpc, sender, request_id, reference_type)


def _send_reasoning_response(rpc: Any, target: str, request_id: str, reference_type: str) -> None:
    """Send reasoning response to peer."""
    try:
        result = rpc.call("hive-ai-send-reasoning-response", {
            "target_node": target,
            "request_id": request_id,
            "reasoning": {
                "conclusion": "neutral",
                "decision_factors": [
                    {
                        "factor_type": "cost_benefit",
                        "weight": 0.5,
                        "assessment": "neutral",
                        "confidence": 0.6
                    }
                ],
                "overall_confidence": 0.6,
                "data_sources": ["local_state"]
            }
        })

        if result.get("error"):
            log.warning(f"Failed to send reasoning response: {result['error']}")
        else:
            record_outgoing_message("ai_reasoning_response")
            update_stats_message_sent()

    except Exception as e:
        log.error(f"Error sending reasoning response: {e}")


def _handle_reasoning_response(payload: Dict, sender: str, rpc: Any, provider: AIProvider) -> None:
    """Handle AI_REASONING_RESPONSE - peer's reasoning explanation."""
    request_id = payload.get("request_id", "")
    reasoning = payload.get("reasoning", {})

    conclusion = reasoning.get("conclusion", "unknown")
    confidence = reasoning.get("overall_confidence", 0)

    log.debug(f"Reasoning response from {sender[:16]}: {conclusion} (confidence={confidence:.2f})")


# ============================================================================
# Message Handlers - Health & Alerts
# ============================================================================

def _handle_heartbeat(payload: Dict, sender: str, rpc: Any, provider: AIProvider) -> None:
    """Handle AI_HEARTBEAT - peer AI health status."""
    ai_status = payload.get("ai_status", {})
    health_metrics = payload.get("health_metrics", {})

    op_state = ai_status.get("operational_state", "unknown")
    model = ai_status.get("model", "unknown")
    decisions_24h = ai_status.get("decisions_24h", 0)

    log.debug(
        f"Heartbeat from {sender[:16]}: "
        f"state={op_state}, model={model}, decisions_24h={decisions_24h}"
    )


def _handle_alert(payload: Dict, sender: str, rpc: Any, provider: AIProvider) -> None:
    """Handle AI_ALERT - important alert from peer AI."""
    alert = payload.get("alert", {})
    recommendation = payload.get("recommendation", {})

    severity = alert.get("severity", "info")
    category = alert.get("category", "unknown")
    alert_type = alert.get("alert_type", "unknown")
    summary = alert.get("summary", "")

    # Log alerts appropriately based on severity
    if severity == "critical":
        log.warning(f"ALERT from {sender[:16]}: [{category}] {alert_type} - {summary}")
    elif severity == "warning":
        log.warning(f"Alert from {sender[:16]}: [{category}] {alert_type}")
    else:
        log.info(f"Alert from {sender[:16]}: [{category}] {alert_type}")

    # Could trigger automatic response based on alert type
    # For now, just log


# ============================================================================
# Background Loops
# ============================================================================

def message_poll_loop(rpc: Any, provider: AIProvider, poll_interval: int) -> None:
    """
    Background loop to poll for and process incoming AI messages.

    Queries the AIMessageStore in cl-hive for unprocessed messages.
    """
    log.info(f"Starting message poll loop (interval: {poll_interval}s)")

    while not shutdown_event.is_set():
        try:
            if state != OracleState.ACTIVE:
                shutdown_event.wait(poll_interval)
                continue

            # Query cl-hive for unprocessed AI messages
            # The hive-ai-inbox command should be exposed by cl-hive
            try:
                result = rpc.call("hive-ai-inbox", {"limit": 50})
                messages = result.get("messages", [])

                for msg in messages:
                    msg_type = msg.get("msg_type", "")
                    payload = msg.get("payload", {})
                    sender = msg.get("sender_id", "")
                    msg_id = msg.get("msg_id", "")

                    process_incoming_message(msg_type, payload, sender, rpc, provider)

                    # Mark as processed
                    try:
                        rpc.call("hive-ai-mark-processed", {"msg_id": msg_id})
                    except Exception as e:
                        log.warning(f"Failed to mark message {msg_id} as processed: {e}")

            except Exception as e:
                # hive-ai-inbox may not exist yet - that's ok during development
                log.debug(f"Could not poll AI inbox: {e}")

        except Exception as e:
            log.error(f"Error in message poll loop: {e}")

        shutdown_event.wait(poll_interval)

    log.info("Message poll loop stopped")


def decision_loop(rpc: Any, provider: AIProvider, decision_interval: int) -> None:
    """
    Background loop to process pending decisions.

    Queries cl-hive for pending_actions that need oracle decisions.
    """
    log.info(f"Starting decision loop (interval: {decision_interval}s)")

    while not shutdown_event.is_set():
        try:
            if state != OracleState.ACTIVE:
                shutdown_event.wait(decision_interval)
                continue

            # Query cl-hive for pending actions
            try:
                result = rpc.call("hive-pending-actions", {"status": "pending"})
                actions = result.get("actions", [])

                with stats_lock:
                    stats.decisions_pending = len(actions)

                for action in actions:
                    decision = process_pending_action(action, rpc, provider)
                    if decision:
                        update_stats_decision()
                        decision_history.append(decision)
                        # Trim history to last 1000
                        if len(decision_history) > 1000:
                            decision_history.pop(0)

            except Exception as e:
                log.debug(f"Could not query pending actions: {e}")

        except Exception as e:
            log.error(f"Error in decision loop: {e}")

        shutdown_event.wait(decision_interval)

    log.info("Decision loop stopped")


def state_broadcast_loop(rpc: Any, provider: AIProvider, state_interval: int) -> None:
    """
    Background loop to periodically broadcast AI_STATE_SUMMARY.

    Per spec, this should broadcast every heartbeat interval (default 5 min).
    """
    log.info(f"Starting state broadcast loop (interval: {state_interval}s)")

    while not shutdown_event.is_set():
        try:
            if state != OracleState.ACTIVE:
                shutdown_event.wait(state_interval)
                continue

            # Check rate limit
            can_send, reason = check_outgoing_rate("ai_state_summary")
            if not can_send:
                log.debug(f"Skipping state summary: {reason}")
                shutdown_event.wait(state_interval)
                continue

            # Generate and broadcast state summary
            # Note: generate_state_summary() handles the full broadcast via
            # hive-ai-broadcast-state-summary RPC call
            result = generate_state_summary(rpc, provider)
            if result:
                record_outgoing_message("ai_state_summary")
                update_stats_message_sent()

        except Exception as e:
            log.error(f"Error in state broadcast loop: {e}")

        shutdown_event.wait(state_interval)

    log.info("State broadcast loop stopped")


# ============================================================================
# RPC Commands
# ============================================================================

@plugin.method("hive-oracle-status")
def oracle_status(plugin: Plugin) -> Dict[str, Any]:
    """
    Check oracle health and connection status.

    Returns current state, configuration, and statistics.
    """
    current_stats = get_stats_snapshot()

    return {
        "state": state.value,
        "enabled": config.enabled if config else False,
        "provider": config.provider if config else "none",
        "model": config.model if config else "none",
        "our_pubkey": our_pubkey,
        "stats": current_stats,
        "reciprocity_peers": len(reciprocity_ledgers),
        "decision_history_count": len(decision_history)
    }


@plugin.method("hive-oracle-history")
def oracle_history(plugin: Plugin, limit: int = 20) -> Dict[str, Any]:
    """
    View recent AI decisions.

    Returns the last N decisions with their reasoning and attestations.
    """
    limit = min(limit, 100)  # Cap at 100

    history = []
    for decision in decision_history[-limit:]:
        entry = {
            "decision_id": decision.decision_id,
            "timestamp": decision.timestamp,
            "action_type": decision.action_type,
            "decision": decision.decision,
            "confidence": decision.confidence,
            "reasoning_factors": decision.reasoning_factors,
            "executed": decision.executed,
            "result": decision.result
        }
        if decision.attestation:
            entry["attestation"] = attestation_to_dict(decision.attestation)
        history.append(entry)

    return {
        "count": len(history),
        "total": len(decision_history),
        "decisions": history
    }


@plugin.method("hive-oracle-pause")
def oracle_pause(plugin: Plugin) -> Dict[str, Any]:
    """
    Temporarily pause AI decision making.

    The oracle will stop processing new decisions but continue
    receiving messages. Use hive-oracle-resume to restart.
    """
    global state

    with state_lock:
        if state == OracleState.ACTIVE:
            state = OracleState.PAUSED
            log.info("Oracle paused")
            return {"status": "paused", "previous_state": "active"}
        else:
            return {"status": state.value, "message": "Oracle not active"}


@plugin.method("hive-oracle-resume")
def oracle_resume(plugin: Plugin) -> Dict[str, Any]:
    """
    Resume AI decision making after pause.
    """
    global state

    with state_lock:
        if state == OracleState.PAUSED:
            state = OracleState.ACTIVE
            log.info("Oracle resumed")
            return {"status": "active", "previous_state": "paused"}
        else:
            return {"status": state.value, "message": "Oracle not paused"}


@plugin.method("hive-oracle-override")
def oracle_override(
    plugin: Plugin,
    action_id: int,
    decision: str,
    reason: str = ""
) -> Dict[str, Any]:
    """
    Human override of a pending decision.

    Allows operator to approve/reject an action manually, bypassing
    the AI oracle. This is logged as a manual override.
    """
    if decision not in ["approve", "reject", "defer"]:
        return {"error": "Invalid decision. Use: approve, reject, defer"}

    try:
        # Call cl-hive to execute the override
        result = plugin.rpc.call("hive-action-override", {
            "action_id": action_id,
            "decision": decision,
            "reason": reason or "manual_operator_override",
            "source": "oracle_override"
        })

        log.info(f"Manual override: action {action_id} -> {decision}")

        return {
            "status": "success",
            "action_id": action_id,
            "decision": decision,
            "reason": reason or "manual_operator_override"
        }

    except Exception as e:
        log.error(f"Override failed: {e}")
        return {"error": str(e)}


@plugin.method("hive-oracle-reciprocity")
def oracle_reciprocity(plugin: Plugin, peer_id: str = "") -> Dict[str, Any]:
    """
    View reciprocity ledger with peers.

    Shows task completion balance with each peer.
    """
    if peer_id:
        if peer_id in reciprocity_ledgers:
            ledger = reciprocity_ledgers[peer_id]
            return {
                "peer_id": peer_id,
                "balance": ledger.balance,
                "lifetime_requested": ledger.lifetime_requested,
                "lifetime_fulfilled": ledger.lifetime_fulfilled,
                "outstanding_tasks": ledger.outstanding_tasks,
                "last_request": datetime.fromtimestamp(
                    ledger.last_request_timestamp
                ).isoformat() if ledger.last_request_timestamp else None,
                "last_fulfillment": datetime.fromtimestamp(
                    ledger.last_fulfillment_timestamp
                ).isoformat() if ledger.last_fulfillment_timestamp else None
            }
        else:
            return {"error": f"No reciprocity data for peer {peer_id[:16]}..."}

    # Return summary of all peers
    peers = []
    for pid, ledger in reciprocity_ledgers.items():
        peers.append({
            "peer_id": pid[:16] + "...",
            "balance": ledger.balance,
            "outstanding": ledger.outstanding_tasks
        })

    return {
        "peer_count": len(peers),
        "peers": sorted(peers, key=lambda x: x["balance"])
    }


# ============================================================================
# Initialization
# ============================================================================

@plugin.init()
def init(options: Dict, configuration: Dict, plugin: Plugin) -> None:
    """Initialize the oracle plugin."""
    global our_pubkey, config, state, start_time, safe_rpc

    log.info("Initializing cl-hive-oracle...")

    # Initialize thread-safe RPC wrapper
    safe_rpc = ThreadSafeRpcProxy(plugin.rpc)

    # Get node info
    try:
        info = safe_rpc.getinfo()
        our_pubkey = info.get("id", "")
        log.info(f"Node pubkey: {our_pubkey[:16]}...")
    except Exception as e:
        log.error(f"Failed to get node info: {e}")
        state = OracleState.ERROR
        return

    # Load configuration
    config = OracleConfig(
        enabled=options.get("hive-oracle-enabled", True),
        provider=options.get("hive-oracle-provider", "anthropic"),
        api_key=options.get("hive-oracle-api-key", ""),
        model=options.get("hive-oracle-model", "claude-sonnet-4-20250514"),
        max_tokens=options.get("hive-oracle-max-tokens", 4096),
        timeout_seconds=options.get("hive-oracle-timeout-seconds", 30),
        poll_interval=options.get("hive-oracle-poll-interval", 10),
        decision_interval=options.get("hive-oracle-decision-interval", 60),
        state_interval=options.get("hive-oracle-state-interval", 300)
    )

    if not config.enabled:
        log.info("Oracle disabled via configuration")
        state = OracleState.PAUSED
        return

    # Initialize AI provider
    provider = get_provider(config)
    if not provider:
        log.error("Failed to initialize AI provider")
        state = OracleState.ERROR
        return

    # Test API connection
    log.info(f"Testing {config.provider} API connection...")
    response, error = provider.complete(
        [{"role": "user", "content": "Reply with 'ok'"}],
        "You are a test. Reply only with 'ok'."
    )

    if error:
        log.error(f"API test failed: {error}")
        log.warning("Oracle starting in ERROR state - check API key")
        state = OracleState.ERROR
    else:
        log.info(f"API test successful (latency: {response.get('_latency_ms', 0):.0f}ms)")
        state = OracleState.ACTIVE

    start_time = time.time()

    # Start background threads (using safe_rpc for thread safety)
    if state == OracleState.ACTIVE:
        threading.Thread(
            target=message_poll_loop,
            args=(safe_rpc, provider, config.poll_interval),
            daemon=True,
            name="oracle-poll"
        ).start()

        threading.Thread(
            target=decision_loop,
            args=(safe_rpc, provider, config.decision_interval),
            daemon=True,
            name="oracle-decision"
        ).start()

        threading.Thread(
            target=state_broadcast_loop,
            args=(safe_rpc, provider, config.state_interval),
            daemon=True,
            name="oracle-broadcast"
        ).start()

    log.info(f"cl-hive-oracle initialized (state: {state.value})")


@plugin.subscribe("shutdown")
def on_shutdown(plugin: Plugin, **kwargs) -> None:
    """Handle shutdown notification."""
    global state

    log.info("Shutting down cl-hive-oracle...")
    state = OracleState.SHUTDOWN
    shutdown_event.set()


# ============================================================================
# Main Entry Point
# ============================================================================

if __name__ == "__main__":
    plugin.run()
