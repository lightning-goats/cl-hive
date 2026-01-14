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
    # TODO: Implement with proper prompt engineering
    log.debug(f"process_pending_action: {action.get('action_type', 'unknown')}")
    return None


def process_incoming_message(msg_type: str, payload: Dict, sender: str, rpc: Any, provider: AIProvider) -> None:
    """
    Process an incoming AI Oracle message.

    This determines the appropriate response (if any) to incoming messages.
    """
    # TODO: Implement message type handlers
    log.debug(f"process_incoming_message: {msg_type} from {sender[:16]}...")
    update_stats_message_received()


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

            # Generate and send state summary
            summary = generate_state_summary(rpc, provider)
            if summary:
                try:
                    # Broadcast via cl-hive
                    rpc.call("hive-broadcast", {
                        "msg_type": "ai_state_summary",
                        "payload": summary
                    })
                    record_outgoing_message("ai_state_summary")
                    update_stats_message_sent()
                    log.debug("Broadcast AI_STATE_SUMMARY")
                except Exception as e:
                    log.warning(f"Failed to broadcast state summary: {e}")

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
    global our_pubkey, config, state, start_time

    log.info("Initializing cl-hive-oracle...")

    # Get node info
    try:
        info = plugin.rpc.getinfo()
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

    # Start background threads
    if state == OracleState.ACTIVE:
        threading.Thread(
            target=message_poll_loop,
            args=(plugin.rpc, provider, config.poll_interval),
            daemon=True,
            name="oracle-poll"
        ).start()

        threading.Thread(
            target=decision_loop,
            args=(plugin.rpc, provider, config.decision_interval),
            daemon=True,
            name="oracle-decision"
        ).start()

        threading.Thread(
            target=state_broadcast_loop,
            args=(plugin.rpc, provider, config.state_interval),
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
