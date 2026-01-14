"""
Protocol module for cl-hive

Implements BOLT 8 custom message types for Hive communication.

Wire Format:
    All messages use a 4-byte magic prefix (0x48495645 = "HIVE") to avoid
    collisions with other plugins using the experimental message range.

    ┌────────────────────┬────────────────────────────────────┐
    │  Magic Bytes (4)   │           Payload (N)              │
    ├────────────────────┼────────────────────────────────────┤
    │     0x48495645     │  [Message-Type-Specific Content]   │
    │     ("HIVE")       │                                    │
    └────────────────────┴────────────────────────────────────┘

Message ID Range: 32769 - 33000 (Odd numbers for safe ignoring by non-Hive peers)
"""

import hashlib
import json
import time
from enum import IntEnum
from typing import Dict, Any, List, Optional, Tuple
from dataclasses import dataclass, field


# =============================================================================
# CONSTANTS
# =============================================================================

# 4-byte magic prefix: ASCII "HIVE" = 0x48 0x49 0x56 0x45
HIVE_MAGIC = b'HIVE'
HIVE_MAGIC_HEX = 0x48495645

# Protocol version for compatibility checks
PROTOCOL_VERSION = 1

# Maximum message size in bytes (post-hex decode)
MAX_MESSAGE_BYTES = 65535

# =============================================================================
# MESSAGE TYPES
# =============================================================================

class HiveMessageType(IntEnum):
    """
    BOLT 8 custom message IDs for Hive protocol.
    
    Uses odd numbers in experimental range (32768+) so non-Hive nodes
    can safely ignore unknown messages per BOLT 1.
    
    MVP Messages (Phase 1):
        HELLO, CHALLENGE, ATTEST, WELCOME
    
    Deferred Messages:
        GOSSIP (Phase 2), INTENT (Phase 3), VOUCH/BAN/PROMOTION (Phase 5)
    """
    # Phase 1: Handshake
    HELLO = 32769       # Ticket presentation
    CHALLENGE = 32771   # Nonce for proof-of-identity
    ATTEST = 32773      # Signed manifest + nonce response
    WELCOME = 32775     # Session established, HiveID assigned
    
    # Phase 2: State Sync (deferred)
    GOSSIP = 32777      # State update broadcast
    STATE_HASH = 32779  # Anti-entropy hash exchange
    FULL_SYNC = 32781   # Full state sync request/response
    
    # Phase 3: Coordination (deferred)
    INTENT = 32783      # Intent lock announcement
    INTENT_ACK = 32785  # Intent acknowledgment
    INTENT_ABORT = 32787  # Intent abort notification
    
    # Phase 5: Governance (deferred)
    VOUCH = 32789       # Member vouching for promotion
    BAN = 32791         # Ban announcement (executed ban)
    PROMOTION = 32793   # Promotion confirmation
    PROMOTION_REQUEST = 32795  # Neophyte requesting promotion
    MEMBER_LEFT = 32797  # Member voluntarily leaving hive
    BAN_PROPOSAL = 32799  # Propose banning a member (requires vote)
    BAN_VOTE = 32801     # Vote on a pending ban proposal

    # Phase 6: Channel Coordination
    PEER_AVAILABLE = 32803  # Notify hive that a peer is available for channels
    EXPANSION_NOMINATE = 32805  # Nominate self to open channel (Phase 6.4)
    EXPANSION_ELECT = 32807     # Announce elected member for expansion (Phase 6.4)

    # Phase 7: Cooperative Fee Coordination
    FEE_INTELLIGENCE = 32809    # Share fee observations with hive
    LIQUIDITY_NEED = 32811      # Broadcast rebalancing needs
    HEALTH_REPORT = 32813       # NNLB health status report
    ROUTE_PROBE = 32815         # Share routing observations (Phase 4)
    PEER_REPUTATION = 32817     # Share peer reputation observations (Phase 5)

    # ==========================================================================
    # AI Oracle Protocol (Phase 8) - Message Range: 32800-32849
    # ==========================================================================
    # Information Sharing (32800-32809)
    AI_STATE_SUMMARY = 32800        # Periodic AI state broadcast
    AI_OPPORTUNITY_SIGNAL = 32801   # AI signals opportunity to fleet
    AI_MARKET_ASSESSMENT = 32802    # AI shares market analysis

    # Task Coordination (32810-32819) - Note: Shares range with existing types
    # These use 32810+ but existing types use odd numbers, so no collision
    AI_TASK_REQUEST = 32819         # AI requests task from peer (avoiding 32810-32817)
    AI_TASK_RESPONSE = 32821        # Response to task request (reusing)
    AI_TASK_COMPLETE = 32823        # Task completion notification
    AI_TASK_CANCEL = 32825          # Task cancellation

    # Strategy Coordination (32820-32829) - Note: 32821/32823/32825 reused above
    AI_STRATEGY_PROPOSAL = 32827    # Fleet-wide strategy proposal
    AI_STRATEGY_VOTE = 32829        # Vote on strategy
    AI_STRATEGY_RESULT = 32831      # Strategy voting result
    AI_STRATEGY_UPDATE = 32833      # Strategy progress update

    # Reasoning Exchange (32830-32839) - Note: 32831/32833 reused above
    AI_REASONING_REQUEST = 32835    # Request reasoning from AI
    AI_REASONING_RESPONSE = 32837   # Detailed reasoning response

    # Health & Alerts (32840-32849)
    AI_HEARTBEAT = 32841            # Extended AI heartbeat
    AI_ALERT = 32843                # AI raises fleet alert


# =============================================================================
# PHASE 5 VALIDATION CONSTANTS
# =============================================================================

# Maximum number of vouches allowed in a promotion message
MAX_VOUCHES_IN_PROMOTION = 50

# Maximum length of request_id
MAX_REQUEST_ID_LEN = 64

# Vouch validity window (7 days)
VOUCH_TTL_SECONDS = 7 * 24 * 3600


# =============================================================================
# PAYLOAD STRUCTURES
# =============================================================================

@dataclass
class HelloPayload:
    """HIVE_HELLO message payload - Ticket presentation."""
    ticket: str         # Base64-encoded signed ticket
    protocol_version: int = PROTOCOL_VERSION


@dataclass
class ChallengePayload:
    """HIVE_CHALLENGE message payload - Nonce for authentication."""
    nonce: str          # 32-byte random hex string
    hive_id: str        # Hive identifier (for multi-hive future)


@dataclass  
class AttestPayload:
    """HIVE_ATTEST message payload - Signed manifest + nonce response."""
    pubkey: str         # Node public key (66 hex chars)
    version: str        # Plugin version string
    features: list      # Supported features ["splice", "dual-fund", ...]
    nonce_signature: str  # signmessage(nonce) result
    manifest_signature: str  # signmessage(manifest_json) result


@dataclass
class WelcomePayload:
    """HIVE_WELCOME message payload - Session established."""
    hive_id: str        # Assigned Hive identifier
    tier: str           # 'neophyte', 'member', or 'admin'
    member_count: int   # Current Hive size
    state_hash: str     # Current state hash for anti-entropy


# =============================================================================
# PHASE 7: FEE INTELLIGENCE PAYLOADS
# =============================================================================

@dataclass
class FeeIntelligencePayload:
    """
    FEE_INTELLIGENCE message payload - Share fee observations with hive.

    Enables cooperative fee setting by sharing observations about
    external peers' fee elasticity and routing performance.
    """
    reporter_id: str              # Who observed this (must match sender)
    target_peer_id: str           # External peer being reported on
    timestamp: int                # Unix timestamp of observation
    signature: str                # Required signature over payload

    # Current fee configuration
    our_fee_ppm: int              # Fee we charge to this peer
    their_fee_ppm: int            # Fee they charge us (if known)

    # Performance metrics (observation period)
    forward_count: int            # Number of forwards through this peer
    forward_volume_sats: int      # Total volume routed
    revenue_sats: int             # Fees earned from this peer

    # Flow analysis
    flow_direction: str           # 'source', 'sink', 'balanced'
    utilization_pct: float        # Channel utilization (0.0-1.0)

    # Elasticity observation (optional)
    last_fee_change_ppm: int = 0  # Previous fee rate (for elasticity calc)
    volume_delta_pct: float = 0.0 # Volume change after fee change

    # Confidence
    days_observed: int = 1        # How long we've observed this peer


@dataclass
class LiquidityNeedPayload:
    """
    LIQUIDITY_NEED message payload - Broadcast rebalancing needs.

    Enables cooperative rebalancing by sharing liquidity requirements.
    """
    reporter_id: str              # Who needs liquidity
    timestamp: int
    signature: str

    # What we need
    need_type: str                # 'inbound', 'outbound', 'rebalance'
    target_peer_id: str           # External peer (or hive member)
    amount_sats: int              # How much we need
    urgency: str                  # 'critical', 'high', 'medium', 'low'
    max_fee_ppm: int              # Maximum fee we'll pay

    # Why we need it
    reason: str                   # 'channel_depleted', 'opportunity', 'nnlb_assist'
    current_balance_pct: float    # Current local balance percentage

    # Reciprocity - what we can offer
    can_provide_inbound: int = 0  # Sats of inbound we can provide
    can_provide_outbound: int = 0 # Sats of outbound we can provide


@dataclass
class HealthReportPayload:
    """
    HEALTH_REPORT message payload - NNLB health status.

    Periodic health report for No Node Left Behind coordination.
    Allows hive to identify who needs help.
    """
    reporter_id: str
    timestamp: int
    signature: str

    # Self-reported health scores (0-100)
    overall_health: int
    capacity_score: int
    revenue_score: int
    connectivity_score: int

    # Specific needs (optional flags)
    needs_inbound: bool = False
    needs_outbound: bool = False
    needs_channels: bool = False

    # Willingness to help others
    can_provide_assistance: bool = False
    assistance_budget_sats: int = 0


@dataclass
class RouteProbePayload:
    """
    ROUTE_PROBE message payload - Routing intelligence.

    Share payment path quality observations to build collective
    routing intelligence across the hive.
    """
    reporter_id: str
    timestamp: int
    signature: str

    # Route definition
    destination: str           # Final destination pubkey
    path: List[str]            # Intermediate hops (pubkeys)

    # Probe results
    success: bool              # Did the probe succeed
    latency_ms: int            # Round-trip time in milliseconds
    failure_reason: str = ""   # If failed: 'temporary', 'permanent', 'capacity'
    failure_hop: int = -1      # Which hop failed (0-indexed, -1 if success)

    # Capacity observations
    estimated_capacity_sats: int = 0  # Max amount that would succeed

    # Fee observations
    total_fee_ppm: int = 0     # Total fees for this route
    per_hop_fees: List[int] = field(default_factory=list)  # Fee at each hop

    # Amount probed
    amount_probed_sats: int = 0


@dataclass
class PeerReputationPayload:
    """
    PEER_REPUTATION message payload - External peer reputation sharing.

    Share reputation observations about external (non-hive) peers to
    build collective intelligence about peer reliability and behavior.
    """
    reporter_id: str           # Who observed this
    timestamp: int
    signature: str

    # Target peer (external)
    peer_id: str               # External peer being reported on

    # Reliability metrics
    uptime_pct: float = 1.0    # How often peer is online (0-1)
    response_time_ms: int = 0  # Average HTLC response time
    force_close_count: int = 0 # Number of force closes initiated by peer

    # Behavior metrics
    fee_stability: float = 1.0 # How stable are their fees (0-1)
    htlc_success_rate: float = 1.0  # % of HTLCs that succeed (0-1)

    # Channel metrics
    channel_age_days: int = 0  # How long we've had channel with them
    total_routed_sats: int = 0 # Total volume routed through this peer

    # Warnings (optional)
    warnings: List[str] = field(default_factory=list)  # Specific issues

    # Observation period
    observation_days: int = 7  # How many days this report covers


# =============================================================================
# AI ORACLE PROTOCOL PAYLOADS (Phase 8)
# =============================================================================

@dataclass
class AIStateSummaryPayload:
    """
    AI_STATE_SUMMARY message payload - Periodic AI state broadcast.

    Sent by AI agents to share their current state and priorities with the hive.
    Uses bucketed values for privacy (no exact balance disclosure).

    Frequency: Every heartbeat interval (default 5 minutes)
    Delivery: Broadcast to all Hive members
    """
    node_id: str            # Sender's node public key
    timestamp: int          # Unix timestamp
    sequence: int           # Monotonic sequence number
    signature: str          # PKI signature of message hash

    # Liquidity state (bucketed for privacy)
    liquidity_status: str           # "healthy", "constrained", "critical"
    capacity_tier: str              # "small", "medium", "large", "xlarge"
    outbound_status: str            # "adequate", "low", "critical"
    inbound_status: str             # "adequate", "low", "critical"
    channel_count_tier: str         # "few", "medium", "many"
    utilization_bucket: str         # "low", "moderate", "high", "critical"

    # Current priorities
    current_focus: str              # "expansion", "consolidation", "maintenance", "defensive"
    seeking_categories: List[str] = field(default_factory=list)  # Node categories being targeted
    avoid_categories: List[str] = field(default_factory=list)    # Categories to avoid
    capacity_seeking: bool = False  # Looking for capacity
    budget_status: str = "available"  # "available", "limited", "exhausted"

    # Capabilities
    can_open_channels: bool = True
    can_accept_tasks: bool = True
    expansion_capacity_tier: str = "medium"  # "none", "small", "medium", "large"
    feerate_tolerance: str = "normal"        # "tight", "normal", "flexible"

    # AI metadata
    ai_confidence: float = 0.5          # AI's confidence level (0-1)
    decisions_last_24h: int = 0         # Decisions made in last 24 hours
    strategy_alignment: str = "cooperative"  # "cooperative", "competitive", "neutral"

    # Operator attestation (required for AI messages)
    attestation: Optional[Dict[str, Any]] = None


@dataclass
class AIHeartbeatPayload:
    """
    AI_HEARTBEAT message payload - Extended heartbeat with AI status.

    Sent periodically to indicate AI agent health and capabilities.

    Frequency: Every heartbeat interval
    Delivery: Broadcast to all Hive members
    """
    node_id: str            # Sender's node public key
    timestamp: int          # Unix timestamp
    sequence: int           # Monotonic sequence number
    signature: str          # PKI signature

    # AI operational status
    operational_state: str      # "active", "degraded", "offline", "paused"
    model_claimed: str          # Model identifier (e.g., "claude-sonnet-4-20250514")
    model_version: str = ""     # Version string
    uptime_seconds: int = 0     # How long AI has been running
    last_decision_timestamp: int = 0  # Last decision made
    decisions_24h: int = 0      # Decisions in last 24 hours
    decisions_pending: int = 0  # Pending decisions

    # Health metrics
    api_latency_ms: int = 0           # AI provider latency
    api_success_rate_pct: float = 100.0  # Success rate percentage
    memory_usage_pct: float = 0.0     # Memory usage percentage
    error_rate_24h: float = 0.0       # Error rate in last 24 hours

    # Capabilities
    max_decisions_per_hour: int = 100
    supported_task_types: List[str] = field(default_factory=list)
    strategy_participation: bool = True
    delegation_acceptance: bool = True

    # Operator attestation
    attestation: Optional[Dict[str, Any]] = None


@dataclass
class AIOpportunitySignalPayload:
    """
    AI_OPPORTUNITY_SIGNAL message payload - AI signals opportunity to fleet.

    Sent when an AI identifies a potential opportunity worth coordinating on.

    Delivery: Broadcast to all Hive members
    """
    node_id: str            # Sender's node public key
    timestamp: int          # Unix timestamp
    signal_id: str          # Unique signal identifier
    signature: str          # PKI signature

    # Target information
    target_node: str            # Target node pubkey
    opportunity_type: str       # "high_value_target", "underserved", "fee_arbitrage", etc.
    target_alias: str = ""      # Target node alias (if known)
    category: str = ""          # Node category (e.g., "routing_hub", "exchange")

    # Analysis data
    target_capacity_sats: int = 0
    target_channel_count: int = 0
    current_hive_share_pct: float = 0.0
    optimal_hive_share_pct: float = 0.0
    share_gap_pct: float = 0.0
    estimated_daily_volume_sats: int = 0
    avg_fee_rate_ppm: int = 0

    # Recommendation
    recommended_action: str = "expand"  # "expand", "consolidate", "monitor"
    urgency: str = "medium"             # "low", "medium", "high", "critical"
    suggested_capacity_sats: int = 0
    estimated_roi_annual_pct: float = 0.0
    confidence: float = 0.5

    # Volunteer information
    volunteer_willing: bool = False
    volunteer_capacity_sats: int = 0
    volunteer_position_score: float = 0.0

    # Reasoning factors (enum values only, no free text)
    reasoning_factors: List[str] = field(default_factory=list)

    # Operator attestation
    attestation: Optional[Dict[str, Any]] = None


@dataclass
class AIAlertPayload:
    """
    AI_ALERT message payload - AI raises alert for fleet attention.

    Sent when an AI detects a security issue, opportunity, or other event
    that requires fleet attention.

    Delivery: Broadcast to all Hive members
    """
    node_id: str            # Sender's node public key
    timestamp: int          # Unix timestamp
    alert_id: str           # Unique alert identifier
    signature: str          # PKI signature

    # Alert classification
    severity: str               # "info", "warning", "critical"
    category: str               # "security", "performance", "opportunity", "system", "network"
    alert_type: str             # Specific type within category

    # Details (structured, no free text)
    source_node: str = ""       # Source of the issue (if applicable)
    affected_channels: List[str] = field(default_factory=list)
    metric_name: str = ""       # Relevant metric name
    metric_value: float = 0.0   # Metric value
    threshold: float = 0.0      # Threshold that was crossed
    pattern: str = ""           # Detected pattern (enum value)
    time_window_minutes: int = 0  # Time window for detection

    # Impact assessment
    immediate_risk: str = "low"     # "none", "low", "medium", "high"
    potential_risk: str = "low"     # "none", "low", "medium", "high"
    affected_hive_members: int = 0

    # Recommendation
    recommended_action: str = "monitor"  # "monitor", "investigate", "respond", "escalate"
    action_urgency: str = "normal"       # "low", "normal", "high", "immediate"

    # Auto-response
    auto_response_taken: str = "none"    # Action taken automatically
    auto_response_reason: str = ""       # Why (or why not) auto-response

    # Operator attestation
    attestation: Optional[Dict[str, Any]] = None


# =============================================================================
# AI ORACLE PROTOCOL - TASK COORDINATION PAYLOADS (Phase 8.2)
# =============================================================================

@dataclass
class AITaskRequestPayload:
    """
    AI_TASK_REQUEST message payload - AI requests task from another node.

    Sent when an AI wants to delegate a task to another hive member.

    Delivery: Direct to target node
    """
    node_id: str            # Sender's node public key (requester)
    target_node: str        # Target node to perform the task
    timestamp: int          # Unix timestamp
    request_id: str         # Unique request identifier
    signature: str          # PKI signature

    # Task definition
    task_type: str          # "expand_to", "rebalance_toward", "probe_route", etc.
    task_target: str        # Target of the task (pubkey, scid, etc.)
    task_priority: str = "normal"  # "low", "normal", "high", "critical"
    task_deadline_timestamp: int = 0  # When task must be completed by

    # Task parameters (type-specific)
    amount_sats: int = 0
    max_fee_sats: int = 0
    max_fee_ppm: int = 0
    min_channels: int = 1
    max_channels: int = 1

    # Context
    selection_factors: List[str] = field(default_factory=list)
    opportunity_signal_id: str = ""
    fleet_benefit_metric: str = ""
    fleet_benefit_from: float = 0.0
    fleet_benefit_to: float = 0.0

    # Compensation (reciprocity tracking per spec section 6.6)
    compensation_offer_type: str = "reciprocal"  # "reciprocal", "paid", "goodwill"
    compensation_credit_value: float = 1.0
    compensation_current_balance: float = 0.0
    compensation_lifetime_requested: int = 0
    compensation_lifetime_fulfilled: int = 0

    # Fallback behavior
    fallback_if_rejected: str = "will_handle_self"
    fallback_if_timeout: str = "will_handle_self"

    # Operator attestation
    attestation: Optional[Dict[str, Any]] = None


@dataclass
class AITaskResponsePayload:
    """
    AI_TASK_RESPONSE message payload - Response to task request.

    Sent in response to an AI_TASK_REQUEST.

    Delivery: Direct to requesting node
    """
    node_id: str            # Sender's node public key (responder)
    timestamp: int          # Unix timestamp
    request_id: str         # Request ID being responded to
    signature: str          # PKI signature

    # Response
    response: str           # "accept", "accept_modified", "reject", "defer", "counter"

    # Acceptance details (if accepting)
    estimated_completion_timestamp: int = 0
    actual_amount_sats: int = 0
    actual_max_fee_sats: int = 0
    estimated_fee_sats: int = 0
    conditions: List[str] = field(default_factory=list)

    # Rejection/defer details
    rejection_reason: str = ""          # "insufficient_liquidity", "too_busy", etc.
    defer_until_timestamp: int = 0      # If deferring, when available
    counter_parameters: Dict[str, Any] = field(default_factory=dict)

    # Response factors (enum values only)
    response_factors: List[str] = field(default_factory=list)

    # Operator attestation
    attestation: Optional[Dict[str, Any]] = None


@dataclass
class AITaskCompletePayload:
    """
    AI_TASK_COMPLETE message payload - Task completion notification.

    Sent when a delegated task is complete.

    Delivery: Direct to requesting node
    """
    node_id: str            # Sender's node public key (task executor)
    timestamp: int          # Unix timestamp
    request_id: str         # Request ID that was completed
    signature: str          # PKI signature

    # Status
    status: str             # "success", "partial", "failed", "cancelled"

    # Result details
    task_type: str = ""
    task_target: str = ""

    # Outcome (type-specific)
    channel_opened: bool = False
    scid: str = ""
    capacity_sats: int = 0
    actual_fee_sats: int = 0
    funding_txid: str = ""
    amount_rebalanced_sats: int = 0
    route_found: bool = False
    fee_updated: bool = False
    new_fee_ppm: int = 0

    # Failure details (if failed)
    failure_reason: str = ""
    failure_details: str = ""

    # Learnings (structured observations)
    target_responsiveness: str = ""     # "fast", "normal", "slow", "unresponsive"
    connection_quality: str = ""        # "excellent", "good", "fair", "poor"
    recommended_for_future: bool = True
    observed_traits: List[str] = field(default_factory=list)

    # Compensation status
    reciprocal_credit_earned: bool = False
    credit_expires_timestamp: int = 0

    # Operator attestation
    attestation: Optional[Dict[str, Any]] = None


@dataclass
class AITaskCancelPayload:
    """
    AI_TASK_CANCEL message payload - Cancel a previously requested task.

    Sent by the requester to cancel a pending task.

    Delivery: Direct to task executor
    """
    node_id: str            # Sender's node public key (original requester)
    timestamp: int          # Unix timestamp
    request_id: str         # Request ID to cancel
    signature: str          # PKI signature

    # Cancellation reason (enum value)
    reason: str             # "opportunity_expired", "timeout", "no_longer_needed", etc.

    # Operator attestation
    attestation: Optional[Dict[str, Any]] = None


# =============================================================================
# AI ORACLE PROTOCOL - STRATEGY COORDINATION PAYLOADS (Phase 8.3)
# =============================================================================

@dataclass
class AIStrategyProposalPayload:
    """
    AI_STRATEGY_PROPOSAL message payload - Fleet-wide strategy proposal.

    Sent when an AI proposes a coordinated strategy for the hive.
    Requires quorum approval before execution.

    Delivery: Broadcast to all Hive members
    """
    node_id: str            # Proposer's node public key
    timestamp: int          # Unix timestamp
    proposal_id: str        # Unique proposal identifier
    signature: str          # PKI signature

    # Strategy definition
    strategy_type: str      # "fee_coordination", "expansion_campaign", etc.
    strategy_name: str = "" # Human-readable name
    strategy_summary: str = ""  # Brief description (enum-based, not free text)

    # Objectives (enum values from allowed set)
    objectives: List[str] = field(default_factory=list)

    # Parameters (type-specific)
    target_corridor: str = ""
    target_nodes: List[str] = field(default_factory=list)
    fee_floor_ppm: int = 0
    fee_ceiling_ppm: int = 0
    duration_hours: int = 0
    ramp_up_hours: int = 0
    amount_sats: int = 0

    # Expected outcomes
    expected_revenue_change_pct: float = 0.0
    expected_volume_change_pct: float = 0.0
    expected_net_benefit_pct: float = 0.0
    outcome_confidence: float = 0.5

    # Risk assessment (structured)
    risks: List[Dict[str, Any]] = field(default_factory=list)

    # Opt-out policy
    opt_out_allowed: bool = True
    opt_out_penalty: str = "none"  # "none", "reputation", "exclusion"

    # Voting parameters
    approval_threshold_pct: float = 51.0
    min_participation_pct: float = 60.0
    voting_deadline_timestamp: int = 0
    execution_delay_hours: int = 24
    vote_weight: str = "equal"  # "equal", "capacity_weighted"

    # Proposer commitment
    proposer_will_participate: bool = True
    proposer_capacity_committed_sats: int = 0

    # Operator attestation
    attestation: Optional[Dict[str, Any]] = None


@dataclass
class AIStrategyVotePayload:
    """
    AI_STRATEGY_VOTE message payload - Vote on strategy proposal.

    Sent by hive members to vote on a strategy proposal.
    Votes are public for verifiability.

    Delivery: Broadcast to all Hive members
    """
    node_id: str            # Voter's node public key
    timestamp: int          # Unix timestamp
    proposal_id: str        # Proposal being voted on
    signature: str          # PKI signature

    # Vote
    vote: str               # "approve", "approve_with_amendments", "reject", "abstain"
    vote_hash: str = ""     # sha256(proposal_id || node_id || vote || timestamp || nonce)
    nonce: str = ""         # Random 32-byte hex for vote hash

    # Rationale (enum-based factors only)
    rationale_factors: List[str] = field(default_factory=list)
    confidence_in_proposal: float = 0.5

    # Commitment (if approving)
    will_participate: bool = False
    capacity_committed_sats: int = 0
    conditions: List[str] = field(default_factory=list)

    # Amendments (if approve_with_amendments)
    amendments: List[Dict[str, Any]] = field(default_factory=list)

    # Operator attestation
    attestation: Optional[Dict[str, Any]] = None


@dataclass
class AIStrategyResultPayload:
    """
    AI_STRATEGY_RESULT message payload - Strategy voting result announcement.

    Sent by the proposal originator to announce the voting result.
    Recipients MUST verify vote_proofs before accepting.

    Delivery: Broadcast to all Hive members
    """
    node_id: str            # Announcer's node public key (proposal originator)
    timestamp: int          # Unix timestamp
    proposal_id: str        # Proposal ID
    signature: str          # PKI signature

    # Result
    result: str             # "adopted", "rejected", "expired", "cancelled"

    # Voting summary
    votes_for: int = 0
    votes_against: int = 0
    abstentions: int = 0
    eligible_voters: int = 0
    quorum_met: bool = False
    approval_pct: float = 0.0
    participation_pct: float = 0.0

    # Vote proofs (for verification)
    vote_proofs: List[Dict[str, Any]] = field(default_factory=list)

    # Execution details (if adopted)
    effective_timestamp: int = 0
    coordinator_node: str = ""
    participants: List[str] = field(default_factory=list)
    opt_outs: List[str] = field(default_factory=list)

    # Amendments incorporated
    amendments_incorporated: List[Dict[str, Any]] = field(default_factory=list)

    # Operator attestation
    attestation: Optional[Dict[str, Any]] = None


@dataclass
class AIStrategyUpdatePayload:
    """
    AI_STRATEGY_UPDATE message payload - Strategy progress update.

    Sent periodically during strategy execution to report progress.

    Delivery: Broadcast to strategy participants
    """
    node_id: str            # Reporter's node public key (coordinator)
    timestamp: int          # Unix timestamp
    proposal_id: str        # Strategy proposal ID
    signature: str          # PKI signature

    # Progress
    phase: str              # "preparation", "execution", "completed", "aborted"
    hours_elapsed: int = 0
    hours_remaining: int = 0
    completion_pct: float = 0.0

    # Metrics
    revenue_change_pct: float = 0.0
    volume_change_pct: float = 0.0
    participant_compliance_pct: float = 100.0
    on_track: bool = True

    # Participant status
    participant_status: List[Dict[str, Any]] = field(default_factory=list)

    # Issues (enum values)
    issues: List[str] = field(default_factory=list)

    # Recommendation
    recommendation: str = "continue"  # "continue", "adjust", "abort", "extend"

    # Operator attestation
    attestation: Optional[Dict[str, Any]] = None


# =============================================================================
# AI ORACLE PROTOCOL - REASONING & MARKET PAYLOADS (Phase 8.4)
# =============================================================================

@dataclass
class AIReasoningRequestPayload:
    """
    AI_REASONING_REQUEST message payload - Request detailed reasoning from AI.

    Sent when an AI wants to understand another AI's decision-making process.

    Delivery: Direct to target node
    """
    node_id: str            # Requester's node public key
    target_node: str        # Target AI's node public key
    timestamp: int          # Unix timestamp
    request_id: str         # Unique request identifier
    signature: str          # PKI signature

    # Context for the request
    reference_type: str     # "strategy_vote", "task_response", "opportunity", "alert"
    reference_id: str = ""  # ID of the referenced item
    question_type: str = "full_reasoning"  # "full_reasoning", "key_factors", "data_sources"

    # Detail level requested
    detail_level: str = "summary"  # "brief", "summary", "full"

    # Operator attestation
    attestation: Optional[Dict[str, Any]] = None


@dataclass
class AIReasoningResponsePayload:
    """
    AI_REASONING_RESPONSE message payload - Detailed reasoning response.

    Sent in response to AI_REASONING_REQUEST.
    All fields use schema-defined enums to prevent prompt injection.

    Delivery: Direct to requesting node
    """
    node_id: str            # Responder's node public key
    timestamp: int          # Unix timestamp
    request_id: str         # Request ID being responded to
    signature: str          # PKI signature

    # Conclusion (enum-based)
    conclusion: str = ""    # "risk_exceeds_reward", "reward_exceeds_risk", etc.

    # Decision factors (structured, enum-based)
    decision_factors: List[Dict[str, Any]] = field(default_factory=list)

    # Confidence
    overall_confidence: float = 0.5

    # Data sources used (enum values)
    data_sources: List[str] = field(default_factory=list)

    # Alternative recommendation (if applicable)
    alternative_strategy_type: str = ""
    alternative_target_metric: str = ""
    alternative_expected_change_pct: float = 0.0
    alternative_risk_level: str = ""

    # Meta information
    reasoning_time_ms: int = 0
    tokens_used: int = 0

    # Operator attestation
    attestation: Optional[Dict[str, Any]] = None


@dataclass
class AIMarketAssessmentPayload:
    """
    AI_MARKET_ASSESSMENT message payload - AI shares market analysis.

    Sent when market conditions change significantly or periodically.

    Delivery: Broadcast to all Hive members
    Frequency: On significant changes or hourly
    """
    node_id: str            # Assessor's node public key
    timestamp: int          # Unix timestamp
    assessment_id: str      # Unique assessment identifier
    signature: str          # PKI signature

    # Assessment type and scope
    assessment_type: str    # "fee_trend", "volume_trend", "competition", "opportunity"
    time_horizon: str = "short_term"  # "immediate", "short_term", "medium_term", "long_term"

    # Market data (bucketed/aggregated)
    avg_network_fee_ppm: int = 0
    fee_change_24h_pct: float = 0.0
    mempool_depth_tier: str = "normal"  # "empty", "light", "normal", "congested", "critical"
    mempool_fee_rate_tier: str = "normal"  # "low", "normal", "elevated", "high", "extreme"
    block_fullness_tier: str = "normal"  # "empty", "light", "normal", "full", "congested"

    # Corridor analysis (list of structured entries)
    corridor_analysis: List[Dict[str, Any]] = field(default_factory=list)

    # Recommendation
    overall_stance: str = "neutral"  # "defensive", "neutral", "opportunistic", "aggressive"
    fee_direction: str = "hold"  # "lower", "hold", "raise_floor", "raise_ceiling"
    expansion_timing: str = "neutral"  # "unfavorable", "neutral", "favorable", "optimal"
    rebalance_urgency: str = "normal"  # "low", "normal", "high", "critical"

    # Confidence and freshness
    confidence: float = 0.5
    data_freshness_seconds: int = 0

    # Operator attestation
    attestation: Optional[Dict[str, Any]] = None


# =============================================================================
# PHASE 7 VALIDATION CONSTANTS
# =============================================================================

# Fee intelligence bounds
MAX_FEE_PPM = 10000              # Maximum fee rate (1%)
MAX_VOLUME_SATS = 1_000_000_000_000  # 10k BTC max volume
MAX_DAYS_OBSERVED = 365          # Maximum observation period
FEE_INTELLIGENCE_MAX_AGE = 3600  # 1 hour max message age

# Liquidity need bounds
MAX_LIQUIDITY_AMOUNT = 100_000_000_000  # 1000 BTC max
VALID_NEED_TYPES = {'inbound', 'outbound', 'rebalance'}
VALID_URGENCY_LEVELS = {'critical', 'high', 'medium', 'low'}
VALID_FLOW_DIRECTIONS = {'source', 'sink', 'balanced'}

# Health report bounds
MAX_HEALTH_SCORE = 100
MIN_HEALTH_SCORE = 0

# Rate limits (count, period_seconds)
FEE_INTELLIGENCE_RATE_LIMIT = (10, 3600)    # 10 per hour per sender
LIQUIDITY_NEED_RATE_LIMIT = (5, 3600)       # 5 per hour per sender
HEALTH_REPORT_RATE_LIMIT = (1, 3600)        # 1 per hour per sender
ROUTE_PROBE_RATE_LIMIT = (20, 3600)         # 20 per hour per sender
PEER_REPUTATION_RATE_LIMIT = (5, 86400)     # 5 per day per sender

# Route probe constants
MAX_PATH_LENGTH = 20                        # Maximum hops in a path
MAX_LATENCY_MS = 60000                      # 60 seconds max latency
MAX_CAPACITY_SATS = 1_000_000_000           # 1 BTC max capacity per route
VALID_FAILURE_REASONS = {"", "temporary", "permanent", "capacity", "unknown"}

# Peer reputation constants
MAX_RESPONSE_TIME_MS = 60000                # 60 seconds max response time
MAX_FORCE_CLOSE_COUNT = 100                 # Reasonable max for tracking
MAX_CHANNEL_AGE_DAYS = 3650                 # 10 years max
MAX_OBSERVATION_DAYS = 365                  # 1 year max observation period
MAX_WARNINGS_COUNT = 10                     # Max warnings per report
MAX_WARNING_LENGTH = 200                    # Max length of each warning
VALID_WARNINGS = {
    "fee_spike",           # Sudden fee increase
    "force_close",         # Initiated force close
    "htlc_timeout",        # HTLC timeouts
    "offline_frequent",    # Frequently offline
    "channel_reject",      # Rejected channel opens
    "routing_failure",     # High routing failure rate
    "slow_response",       # Slow HTLC processing
    "fee_manipulation",    # Suspected fee manipulation
    "capacity_drain",      # Draining liquidity
    "other",               # Other issues
}


# =============================================================================
# AI ORACLE PROTOCOL VALIDATION CONSTANTS (Phase 8)
# =============================================================================

# Rate limits (count, period_seconds) per spec section 6.3
AI_STATE_SUMMARY_RATE_LIMIT = (1, 60)           # 1 per minute per node
AI_OPPORTUNITY_SIGNAL_RATE_LIMIT = (10, 3600)   # 10 per hour per node
AI_TASK_REQUEST_RATE_LIMIT = (20, 3600)         # 20 per hour per node
AI_STRATEGY_PROPOSAL_RATE_LIMIT = (5, 86400)    # 5 per day per node
AI_ALERT_RATE_LIMIT = (10, 3600)                # 10 per hour per node
AI_HEARTBEAT_RATE_LIMIT = (1, 60)               # 1 per minute per node
AI_REASONING_REQUEST_RATE_LIMIT = (10, 3600)    # 10 per hour per node

# Message freshness (replay prevention)
AI_MESSAGE_MAX_AGE_SECONDS = 300                # 5 minutes max age

# AI State Summary enums
VALID_LIQUIDITY_STATUS = {"healthy", "constrained", "critical"}
VALID_CAPACITY_TIER = {"small", "medium", "large", "xlarge"}
VALID_STATUS_LEVEL = {"adequate", "low", "critical"}
VALID_CHANNEL_COUNT_TIER = {"few", "medium", "many"}
VALID_UTILIZATION_BUCKET = {"low", "moderate", "high", "critical"}
VALID_CURRENT_FOCUS = {"expansion", "consolidation", "maintenance", "defensive"}
VALID_BUDGET_STATUS = {"available", "limited", "exhausted"}
VALID_EXPANSION_CAPACITY_TIER = {"none", "small", "medium", "large"}
VALID_FEERATE_TOLERANCE = {"tight", "normal", "flexible"}
VALID_STRATEGY_ALIGNMENT = {"cooperative", "competitive", "neutral"}

# AI Heartbeat enums
VALID_OPERATIONAL_STATE = {"active", "degraded", "offline", "paused"}

# AI Opportunity Signal enums
VALID_OPPORTUNITY_TYPE = {
    "high_value_target",    # Well-connected node with routing potential
    "underserved",          # Node with low hive share vs optimal
    "fee_arbitrage",        # Fee mispricing opportunity
    "liquidity_need",       # Hive member needs inbound/outbound
    "defensive",            # Competitor activity requires response
    "emerging",             # New node showing growth signals
}
VALID_OPPORTUNITY_ACTION = {"expand", "consolidate", "monitor"}

# AI Alert enums
VALID_ALERT_SEVERITY = {"info", "warning", "critical"}
VALID_ALERT_CATEGORY = {"security", "performance", "opportunity", "system", "network"}
VALID_ALERT_TYPES = {
    # Security
    "probing_detected", "force_close_attempt", "unusual_htlc_pattern",
    # Performance
    "high_failure_rate", "liquidity_crisis", "fee_war",
    # Opportunity
    "flash_opportunity", "competitor_retreat", "volume_surge",
    # System
    "ai_degraded", "api_unavailable", "budget_exhausted",
    # Network
    "mempool_spike", "block_congestion", "gossip_storm",
}
VALID_RISK_LEVEL = {"none", "low", "medium", "high"}
VALID_ALERT_ACTION = {"monitor", "investigate", "respond", "escalate"}
VALID_ACTION_URGENCY = {"low", "normal", "high", "immediate"}

# Reasoning factors (exhaustive list per spec section 6.4)
VALID_REASONING_FACTORS = {
    "volume_elasticity", "competitor_response", "market_timing", "alternative_available",
    "fee_trend", "capacity_constraint", "liquidity_need", "reputation_score",
    "position_advantage", "cost_benefit", "risk_assessment", "strategic_alignment",
    # Additional common factors
    "high_volume", "low_hive_share", "strong_fee_potential", "good_position",
    "existing_peer", "lower_hop_count", "better_position_score",
    "sufficient_liquidity", "good_connection", "reciprocity_balance_positive",
}

# Conclusion types for reasoning responses
VALID_CONCLUSION_TYPES = {
    "risk_exceeds_reward", "reward_exceeds_risk", "neutral", "insufficient_data",
    "defer_decision", "escalate_to_human",
}

# Node category types (for seeking_categories, avoid_categories)
VALID_NODE_CATEGORIES = {
    "routing_hub", "exchange", "wallet_provider", "merchant", "lsp",
    "gaming", "social", "mining_pool", "custodial", "institutional",
}

# Task types (for AI_TASK_REQUEST)
VALID_AI_TASK_TYPES = {
    "expand_to",          # Open channel to target
    "rebalance_toward",   # Push liquidity toward target
    "probe_route",        # Test route viability
    "gather_intel",       # Research a node
    "adjust_fees",        # Change fee on corridor
    "close_channel",      # Close a channel
}

# Bounds
MAX_SIGNAL_ID_LEN = 64
MAX_ALERT_ID_LEN = 64
MAX_REQUEST_ID_LEN_AI = 64
MAX_SEEKING_CATEGORIES = 10
MAX_AVOID_CATEGORIES = 10
MAX_AFFECTED_CHANNELS = 50
MAX_REASONING_FACTORS = 20
MAX_SUPPORTED_TASK_TYPES = 20
MAX_SEQUENCE_NUMBER = 2 ** 63 - 1  # int64 max

# Attestation constants
ATTESTATION_MAX_AGE_SECONDS = 300   # 5 minutes

# =============================================================================
# AI ORACLE - TASK COORDINATION CONSTANTS (Phase 8.2)
# =============================================================================

# Task priorities
VALID_TASK_PRIORITIES = {"low", "normal", "high", "critical"}

# Task response types
VALID_TASK_RESPONSES = {
    "accept",           # Will perform the task as requested
    "accept_modified",  # Will perform with modified parameters
    "reject",           # Cannot or will not perform
    "defer",            # Can perform later
    "counter",          # Proposes alternative terms
}

# Task completion status
VALID_TASK_STATUS = {
    "success",      # Task completed successfully
    "partial",      # Task partially completed
    "failed",       # Task failed
    "cancelled",    # Task was cancelled
}

# Task rejection reasons
VALID_REJECTION_REASONS = {
    "insufficient_liquidity",   # Not enough funds
    "too_busy",                 # Too many pending tasks
    "reciprocity_debt",         # Requester owes too much
    "target_unavailable",       # Target node not reachable
    "fee_too_low",              # Compensation insufficient
    "risk_too_high",            # Risk assessment negative
    "policy_violation",         # Violates node policy
    "capability_missing",       # Can't perform this task type
    "deadline_impossible",      # Can't meet deadline
    "other",                    # Other reason
}

# Task cancellation reasons
VALID_CANCEL_REASONS = {
    "opportunity_expired",      # Opportunity no longer valid
    "timeout",                  # Task took too long
    "no_longer_needed",         # Requester no longer needs it
    "better_alternative",       # Found better option
    "error_detected",           # Error in original request
    "other",                    # Other reason
}

# Compensation offer types
VALID_COMPENSATION_TYPES = {"reciprocal", "paid", "goodwill"}

# Fallback behaviors
VALID_FALLBACK_BEHAVIORS = {
    "will_handle_self",         # Requester will do it themselves
    "will_delegate_other",      # Will ask someone else
    "will_abandon",             # Will give up
    "will_retry_later",         # Will try again later
}

# Target responsiveness (learnings)
VALID_RESPONSIVENESS = {"fast", "normal", "slow", "unresponsive"}

# Connection quality (learnings)
VALID_CONNECTION_QUALITY = {"excellent", "good", "fair", "poor"}

# Observed traits (learnings)
VALID_OBSERVED_TRAITS = {
    "quick_acceptance",         # Accepts connections quickly
    "stable_connection",        # Reliable connectivity
    "professional_operator",    # Well-maintained node
    "high_uptime",              # Rarely offline
    "good_liquidity",           # Well-funded channels
    "fast_forwarding",          # Quick HTLC processing
    "reasonable_fees",          # Fair fee structure
    "responsive_to_changes",    # Adapts to network changes
    "cooperative",              # Works well with others
    "slow_acceptance",          # Takes long to accept
    "unstable_connection",      # Frequent disconnects
    "fee_volatility",           # Frequent fee changes
    "liquidity_issues",         # Often low on funds
}

# Selection factors (context)
VALID_SELECTION_FACTORS = {
    "existing_peer",            # Already connected
    "lower_hop_count",          # Closer in graph
    "better_position_score",    # Better network position
    "higher_capacity",          # More channel capacity
    "lower_fees",               # Cheaper routing
    "better_uptime",            # More reliable
    "reciprocity_positive",     # They owe us
    "geographic_diversity",     # Different region
    "random_selection",         # Randomly chosen
}

# Fleet benefit metrics
VALID_FLEET_METRICS = {
    "hive_share_pct",           # Percentage of target's channels
    "total_capacity_sats",      # Total hive capacity
    "routing_diversity",        # Number of unique routes
    "fee_revenue_sats",         # Expected fee revenue
    "network_centrality",       # Graph centrality score
}

# Response factors (for AI_TASK_RESPONSE)
VALID_RESPONSE_FACTORS = {
    "sufficient_liquidity",     # Have enough funds
    "good_connection",          # Well connected to target
    "reciprocity_balance_positive",  # They owe us
    "within_risk_tolerance",    # Risk is acceptable
    "aligns_with_strategy",     # Fits our strategy
    "deadline_achievable",      # Can meet deadline
    "fee_acceptable",           # Compensation is fair
    "capacity_available",       # Have spare capacity
    "insufficient_liquidity",   # Not enough funds
    "poor_connection",          # Poorly connected
    "reciprocity_negative",     # We owe them too much
    "risk_too_high",            # Risk unacceptable
    "conflicts_with_strategy",  # Doesn't fit strategy
    "deadline_impossible",      # Can't meet deadline
    "busy",                     # Too many tasks
}

# Task coordination bounds
MAX_TASK_CONDITIONS = 10
MAX_OBSERVED_TRAITS = 10
MAX_SELECTION_FACTORS = 10
MAX_RESPONSE_FACTORS = 10
MAX_CHANNELS_PER_TASK = 10
MAX_TASK_AMOUNT_SATS = 1_000_000_000_000  # 10k BTC
MAX_TASK_FEE_SATS = 10_000_000            # 0.1 BTC max fee
MAX_TASK_FEE_PPM = 10000                  # 1% max PPM
RECIPROCITY_DEBT_LIMIT = -3.0             # Max debt before rejection
MAX_OUTSTANDING_TASKS_PER_PEER = 5        # Per spec section 6.6

# =============================================================================
# AI ORACLE - STRATEGY COORDINATION CONSTANTS (Phase 8.3)
# =============================================================================

# Strategy types
VALID_STRATEGY_TYPES = {
    "fee_coordination",     # Align fees across hive for corridor
    "expansion_campaign",   # Coordinated expansion to target(s)
    "rebalance_ring",       # Circular rebalancing among members
    "defensive",            # Response to competitive threat
    "liquidity_sharing",    # Redistribute liquidity within hive
    "channel_cleanup",      # Coordinated closure of unprofitable channels
}

# Strategy objectives (enum values for objectives field)
VALID_STRATEGY_OBJECTIVES = {
    "increase_revenue",             # Increase fee revenue
    "reduce_undercutting",          # Stop internal competition
    "establish_fee_floor",          # Set minimum fees
    "expand_market_share",          # Grow hive share
    "improve_liquidity",            # Better liquidity distribution
    "reduce_rebalance_costs",       # Lower rebalancing expenses
    "counter_competitor",           # Respond to competitive action
    "optimize_topology",            # Improve channel structure
    "close_unprofitable",           # Remove bad channels
    "onboard_new_target",           # Add new node to network
}

# Vote options
VALID_VOTE_OPTIONS = {
    "approve",                  # Support as-is
    "approve_with_amendments",  # Support with changes
    "reject",                   # Oppose
    "abstain",                  # No position
}

# Strategy result types
VALID_STRATEGY_RESULTS = {
    "adopted",      # Strategy was approved and will execute
    "rejected",     # Strategy was voted down
    "expired",      # Voting deadline passed without quorum
    "cancelled",    # Proposer cancelled before completion
}

# Strategy phases
VALID_STRATEGY_PHASES = {
    "preparation",  # Getting ready to execute
    "execution",    # Currently executing
    "completed",    # Successfully finished
    "aborted",      # Stopped early
}

# Strategy update recommendations
VALID_STRATEGY_RECOMMENDATIONS = {
    "continue",     # Keep executing as planned
    "adjust",       # Modify parameters
    "abort",        # Stop execution
    "extend",       # Extend duration
}

# Vote weight methods
VALID_VOTE_WEIGHTS = {"equal", "capacity_weighted"}

# Opt-out penalties
VALID_OPT_OUT_PENALTIES = {"none", "reputation", "exclusion"}

# Participant status values
VALID_PARTICIPANT_STATUS = {
    "compliant",        # Following the strategy
    "partial",          # Partially compliant
    "non_compliant",    # Not following
    "offline",          # Node offline
    "opted_out",        # Legitimately opted out
}

# Strategy rationale factors (for voting)
VALID_STRATEGY_RATIONALE_FACTORS = {
    "corridor_underpricing",        # Current fees too low
    "reasonable_elasticity",        # Volume won't drop too much
    "adequate_mitigation",          # Risks are addressed
    "strong_roi_potential",         # Good return expected
    "timing_favorable",             # Good time to act
    "competitive_necessity",        # Must respond to threat
    "liquidity_benefit",            # Improves liquidity
    "topology_improvement",         # Better network position
    "excessive_risk",               # Too risky
    "poor_timing",                  # Bad time to act
    "insufficient_data",            # Not enough information
    "conflicts_with_policy",        # Against node policy
    "resource_constraints",         # Can't commit resources
}

# Strategy issues (for updates)
VALID_STRATEGY_ISSUES = {
    "participant_dropout",          # Member left strategy
    "lower_than_expected_revenue",  # Revenue below target
    "higher_than_expected_cost",    # Costs above target
    "competitor_response",          # Competitors reacting
    "network_conditions_changed",   # Market conditions changed
    "technical_difficulties",       # Implementation issues
    "quorum_at_risk",               # Participation dropping
}

# Strategy coordination bounds
MAX_PROPOSAL_ID_LEN = 64
MAX_STRATEGY_NAME_LEN = 100
MAX_STRATEGY_OBJECTIVES = 10
MAX_TARGET_NODES = 50
MAX_RISKS = 10
MAX_VOTE_PROOFS = 100
MAX_PARTICIPANTS = 200
MAX_AMENDMENTS = 10
MAX_PARTICIPANT_STATUS = 200
MAX_STRATEGY_ISSUES = 20
MAX_STRATEGY_CONDITIONS = 10
MAX_NONCE_LEN = 64
MAX_VOTE_HASH_LEN = 128
MAX_DURATION_HOURS = 8760  # 1 year max
MAX_RAMP_UP_HOURS = 720    # 30 days max
MAX_EXECUTION_DELAY_HOURS = 168  # 1 week max


# =============================================================================
# AI ORACLE - REASONING & MARKET CONSTANTS (Phase 8.4)
# =============================================================================

# Reasoning request reference types
VALID_REASONING_REFERENCE_TYPES = {
    "strategy_vote",    # Question about a strategy vote
    "task_response",    # Question about a task response
    "opportunity",      # Question about an opportunity signal
    "alert",            # Question about an alert
    "state_summary",    # Question about state summary
    "market_assessment", # Question about market assessment
}

# Question types for reasoning requests
VALID_REASONING_QUESTION_TYPES = {
    "full_reasoning",   # Complete reasoning chain
    "key_factors",      # Main decision factors only
    "data_sources",     # Data sources used
    "alternatives",     # Alternative considerations
}

# Detail levels for reasoning requests
VALID_REASONING_DETAIL_LEVELS = {"brief", "summary", "full"}

# Reasoning conclusions (enum values for conclusion field)
VALID_REASONING_CONCLUSIONS = {
    "risk_exceeds_reward",      # Risk too high relative to potential gain
    "reward_exceeds_risk",      # Potential gain justifies risk
    "insufficient_data",        # Not enough information to decide
    "conflicts_with_policy",    # Against node's operational policy
    "resource_unavailable",     # Don't have required resources
    "timing_unfavorable",       # Bad timing for action
    "better_alternative",       # Found a better option
    "aligned_with_strategy",    # Fits current strategy
    "neutral",                  # No strong opinion either way
}

# Decision factor types
VALID_DECISION_FACTOR_TYPES = {
    "volume_elasticity",        # Volume response to fee changes
    "competitor_response",      # Expected competitor behavior
    "market_timing",            # Market conditions assessment
    "alternative_available",    # Availability of alternatives
    "risk_exposure",            # Risk level assessment
    "resource_requirement",     # Resource needs
    "historical_performance",   # Past performance data
    "network_position",         # Position in network
    "liquidity_impact",         # Effect on liquidity
    "fee_potential",            # Revenue potential
}

# Decision factor assessments
VALID_FACTOR_ASSESSMENTS = {
    "very_low", "low", "moderate", "high", "very_high",
    "favorable", "unfavorable", "neutral",
    "likely_undercut", "likely_match", "likely_ignore",
    "yes", "no", "partial",
    "clearing", "building", "stable",
}

# Data sources for reasoning
VALID_DATA_SOURCES = {
    "local_forwarding_history_30d",
    "local_forwarding_history_7d",
    "fee_experiment_results",
    "competitor_fee_monitoring",
    "mempool_analysis",
    "gossip_network_data",
    "hive_state_data",
    "historical_strategy_outcomes",
    "peer_reputation_data",
    "channel_performance_data",
}

# Alternative risk levels
VALID_ALTERNATIVE_RISK_LEVELS = {"low", "moderate", "high", "critical"}

# Market assessment types
VALID_MARKET_ASSESSMENT_TYPES = {
    "fee_trend",        # Fee market analysis
    "volume_trend",     # Volume analysis
    "competition",      # Competitive landscape
    "opportunity",      # Opportunity assessment
    "risk",             # Risk assessment
    "comprehensive",    # Full market analysis
}

# Time horizons for market assessment
VALID_TIME_HORIZONS = {
    "immediate",        # Next few hours
    "short_term",       # Next 1-7 days
    "medium_term",      # Next 1-4 weeks
    "long_term",        # Next 1-3 months
}

# Mempool depth tiers
VALID_MEMPOOL_DEPTH_TIERS = {"empty", "light", "normal", "congested", "critical"}

# Mempool fee rate tiers
VALID_MEMPOOL_FEE_RATE_TIERS = {"low", "normal", "elevated", "high", "extreme"}

# Block fullness tiers
VALID_BLOCK_FULLNESS_TIERS = {"empty", "light", "normal", "full", "congested"}

# Market stance recommendations
VALID_MARKET_STANCES = {"defensive", "neutral", "opportunistic", "aggressive"}

# Fee direction recommendations
VALID_FEE_DIRECTIONS = {"lower", "hold", "raise_floor", "raise_ceiling"}

# Expansion timing recommendations
VALID_EXPANSION_TIMING = {"unfavorable", "neutral", "favorable", "optimal"}

# Corridor volume trends
VALID_VOLUME_TRENDS = {"decreasing", "stable", "increasing"}

# Corridor competition levels
VALID_COMPETITION_LEVELS = {"low", "moderate", "high", "extreme"}

# Corridor hive positions
VALID_CORRIDOR_POSITIONS = {"weak", "moderate", "strong", "dominant"}

# Reasoning and market bounds
MAX_REASONING_REQUEST_ID_LEN = 64
MAX_REFERENCE_ID_LEN = 128
MAX_DECISION_FACTORS = 20
MAX_DATA_SOURCES = 20
MAX_REASONING_TIME_MS = 60000  # 60 seconds max
MAX_TOKENS_USED = 100000       # 100k tokens max
MAX_ASSESSMENT_ID_LEN = 64
MAX_CORRIDOR_ANALYSIS = 50     # Max corridors to analyze
MAX_CORRIDOR_NAME_LEN = 100
MAX_DATA_FRESHNESS_SECONDS = 3600  # 1 hour max freshness


# =============================================================================
# SERIALIZATION
# =============================================================================

def serialize(msg_type: HiveMessageType, payload: Dict[str, Any]) -> bytes:
    """
    Serialize a Hive message for transmission via sendcustommsg.
    
    Format: MAGIC (4 bytes) + JSON payload
    
    Args:
        msg_type: HiveMessageType enum value
        payload: Dictionary to serialize as JSON
        
    Returns:
        bytes: Wire-ready message with magic prefix
        
    Example:
        >>> data = serialize(HiveMessageType.HELLO, {"ticket": "abc123..."})
        >>> data[:4]
        b'HIVE'
    """
    # Add message type to payload for deserialization
    envelope = {
        "type": int(msg_type),
        "version": PROTOCOL_VERSION,
        "payload": payload
    }
    
    # JSON encode
    json_bytes = json.dumps(envelope, separators=(',', ':')).encode('utf-8')
    
    # Prepend magic
    return HIVE_MAGIC + json_bytes


def deserialize(data: bytes) -> Tuple[Optional[HiveMessageType], Optional[Dict[str, Any]]]:
    """
    Deserialize a Hive message received via custommsg hook.
    
    Performs magic byte verification before attempting JSON parse.
    
    Args:
        data: Raw bytes from custommsg event
        
    Returns:
        Tuple of (message_type, payload) if valid Hive message
        Tuple of (None, None) if magic check fails or parse error
        
    Example:
        >>> msg_type, payload = deserialize(data)
        >>> if msg_type is None:
        ...     return {"result": "continue"}  # Not our message
    """
    # Peek & Check: Verify magic prefix
    if len(data) < 4 or len(data) > MAX_MESSAGE_BYTES:
        return (None, None)
    
    if data[:4] != HIVE_MAGIC:
        return (None, None)
    
    # Strip magic and parse JSON
    try:
        json_data = data[4:].decode('utf-8')
        envelope = json.loads(json_data)
        
        if envelope.get('version') != PROTOCOL_VERSION:
            return (None, None)

        msg_type = HiveMessageType(envelope['type'])
        payload = envelope.get('payload', {})
        if not isinstance(payload, dict):
            return (None, None)
        
        return (msg_type, payload)
        
    except (json.JSONDecodeError, KeyError, ValueError) as e:
        # Malformed message - log would go here in production
        return (None, None)


def is_hive_message(data: bytes) -> bool:
    """
    Quick check if data is a Hive message (magic prefix only).
    
    Use this for fast rejection in custommsg hook before full deserialization.
    
    Args:
        data: Raw bytes from custommsg event
        
    Returns:
        True if magic prefix matches, False otherwise
    """
    return len(data) >= 4 and data[:4] == HIVE_MAGIC


# =============================================================================
# PHASE 5 PAYLOAD VALIDATION
# =============================================================================

def _valid_request_id(request_id: Any) -> bool:
    if not isinstance(request_id, str):
        return False
    if not request_id or len(request_id) > MAX_REQUEST_ID_LEN:
        return False
    return all(c in "0123456789abcdef" for c in request_id)


def validate_promotion_request(payload: Dict[str, Any]) -> bool:
    """Validate PROMOTION_REQUEST payload schema."""
    if not isinstance(payload, dict):
        return False
    target_pubkey = payload.get("target_pubkey")
    request_id = payload.get("request_id")
    timestamp = payload.get("timestamp")
    if not isinstance(target_pubkey, str) or not target_pubkey:
        return False
    if not _valid_request_id(request_id):
        return False
    if not isinstance(timestamp, int) or timestamp < 0:
        return False
    return True


def validate_vouch(payload: Dict[str, Any]) -> bool:
    """Validate VOUCH payload schema."""
    if not isinstance(payload, dict):
        return False
    required = ["target_pubkey", "request_id", "timestamp", "voucher_pubkey", "sig"]
    for key in required:
        if key not in payload:
            return False
    if not isinstance(payload["target_pubkey"], str) or not payload["target_pubkey"]:
        return False
    if not _valid_request_id(payload["request_id"]):
        return False
    if not isinstance(payload["timestamp"], int) or payload["timestamp"] < 0:
        return False
    if not isinstance(payload["voucher_pubkey"], str) or not payload["voucher_pubkey"]:
        return False
    if not isinstance(payload["sig"], str) or not payload["sig"]:
        return False
    return True


def validate_promotion(payload: Dict[str, Any]) -> bool:
    """Validate PROMOTION payload schema and vouch list caps."""
    if not isinstance(payload, dict):
        return False
    target_pubkey = payload.get("target_pubkey")
    request_id = payload.get("request_id")
    vouches = payload.get("vouches")
    if not isinstance(target_pubkey, str) or not target_pubkey:
        return False
    if not _valid_request_id(request_id):
        return False
    if not isinstance(vouches, list):
        return False
    if len(vouches) > MAX_VOUCHES_IN_PROMOTION:
        return False
    for vouch in vouches:
        if not validate_vouch(vouch):
            return False
        if vouch.get("target_pubkey") != target_pubkey:
            return False
        if vouch.get("request_id") != request_id:
            return False
    return True


def validate_member_left(payload: Dict[str, Any]) -> bool:
    """Validate MEMBER_LEFT payload schema."""
    if not isinstance(payload, dict):
        return False
    peer_id = payload.get("peer_id")
    timestamp = payload.get("timestamp")
    reason = payload.get("reason")
    signature = payload.get("signature")

    # peer_id must be valid pubkey (66 hex chars)
    if not isinstance(peer_id, str) or len(peer_id) != 66:
        return False
    if not all(c in "0123456789abcdef" for c in peer_id):
        return False

    # timestamp must be positive integer
    if not isinstance(timestamp, int) or timestamp < 0:
        return False

    # reason must be a non-empty string
    if not isinstance(reason, str) or not reason:
        return False

    # signature must be present (zbase encoded)
    if not isinstance(signature, str) or not signature:
        return False

    return True


def _valid_pubkey(pubkey: Any) -> bool:
    """Check if value is a valid 66-char hex pubkey."""
    if not isinstance(pubkey, str) or len(pubkey) != 66:
        return False
    return all(c in "0123456789abcdef" for c in pubkey)


def validate_ban_proposal(payload: Dict[str, Any]) -> bool:
    """Validate BAN_PROPOSAL payload schema."""
    if not isinstance(payload, dict):
        return False

    target_peer_id = payload.get("target_peer_id")
    proposer_peer_id = payload.get("proposer_peer_id")
    proposal_id = payload.get("proposal_id")
    reason = payload.get("reason")
    timestamp = payload.get("timestamp")
    signature = payload.get("signature")

    # Validate pubkeys
    if not _valid_pubkey(target_peer_id):
        return False
    if not _valid_pubkey(proposer_peer_id):
        return False

    # proposal_id must be valid hex string
    if not _valid_request_id(proposal_id):
        return False

    # reason must be non-empty string
    if not isinstance(reason, str) or not reason or len(reason) > 500:
        return False

    # timestamp must be positive integer
    if not isinstance(timestamp, int) or timestamp < 0:
        return False

    # signature must be present
    if not isinstance(signature, str) or not signature:
        return False

    return True


def validate_ban_vote(payload: Dict[str, Any]) -> bool:
    """Validate BAN_VOTE payload schema."""
    if not isinstance(payload, dict):
        return False

    proposal_id = payload.get("proposal_id")
    voter_peer_id = payload.get("voter_peer_id")
    vote = payload.get("vote")  # "approve" or "reject"
    timestamp = payload.get("timestamp")
    signature = payload.get("signature")

    # proposal_id must be valid hex string
    if not _valid_request_id(proposal_id):
        return False

    # voter must be valid pubkey
    if not _valid_pubkey(voter_peer_id):
        return False

    # vote must be "approve" or "reject"
    if vote not in ("approve", "reject"):
        return False

    # timestamp must be positive integer
    if not isinstance(timestamp, int) or timestamp < 0:
        return False

    # signature must be present
    if not isinstance(signature, str) or not signature:
        return False

    return True


def validate_peer_available(payload: Dict[str, Any]) -> bool:
    """
    Validate PEER_AVAILABLE payload schema.

    SECURITY: Requires cryptographic signature from the reporter.
    """
    if not isinstance(payload, dict):
        return False

    target_peer_id = payload.get("target_peer_id")
    reporter_peer_id = payload.get("reporter_peer_id")
    event_type = payload.get("event_type")
    timestamp = payload.get("timestamp")
    signature = payload.get("signature")

    # target_peer_id must be valid pubkey (the external peer)
    if not _valid_pubkey(target_peer_id):
        return False

    # reporter_peer_id must be valid pubkey (the hive member reporting)
    if not _valid_pubkey(reporter_peer_id):
        return False

    # event_type must be a valid string
    valid_event_types = (
        'channel_open',      # New channel opened
        'channel_close',     # Channel closed (any type)
        'remote_close',      # Remote peer initiated close
        'local_close',       # Local node initiated close
        'mutual_close',      # Mutual close
        'channel_expired',   # Channel expired/timeout
        'peer_quality'       # Periodic quality report
    )
    if event_type not in valid_event_types:
        return False

    # timestamp must be positive integer
    if not isinstance(timestamp, int) or timestamp < 0:
        return False

    # SECURITY: Signature must be present (zbase encoded)
    if not isinstance(signature, str) or len(signature) < 10:
        return False

    # Optional numeric fields - validate if present
    optional_int_fields = [
        'capacity_sats', 'channel_id', 'duration_days',
        'total_revenue_sats', 'total_rebalance_cost_sats', 'net_pnl_sats',
        'forward_count', 'forward_volume_sats', 'our_fee_ppm', 'their_fee_ppm',
        'our_funding_sats', 'their_funding_sats'
    ]
    for field in optional_int_fields:
        val = payload.get(field)
        if val is not None and not isinstance(val, int):
            return False

    optional_float_fields = ['routing_score', 'profitability_score']
    for field in optional_float_fields:
        val = payload.get(field)
        if val is not None and not isinstance(val, (int, float)):
            return False

    return True


def get_peer_available_signing_payload(payload: Dict[str, Any]) -> str:
    """
    Get the canonical payload string for signing PEER_AVAILABLE messages.

    The signature covers core fields that identify the event, in sorted order.
    """
    signing_fields = {
        "target_peer_id": payload.get("target_peer_id", ""),
        "reporter_peer_id": payload.get("reporter_peer_id", ""),
        "event_type": payload.get("event_type", ""),
        "timestamp": payload.get("timestamp", 0),
        "capacity_sats": payload.get("capacity_sats", 0),
    }
    return json.dumps(signing_fields, sort_keys=True, separators=(',', ':'))


# =============================================================================
# PHASE 2: STATE MANAGEMENT MESSAGE VALIDATION
# =============================================================================

def validate_gossip(payload: Dict[str, Any]) -> bool:
    """
    Validate GOSSIP payload schema.

    SECURITY: Requires cryptographic signature from the sender.
    """
    if not isinstance(payload, dict):
        return False

    sender_id = payload.get("sender_id")
    timestamp = payload.get("timestamp")
    signature = payload.get("signature")

    # sender_id must be valid pubkey
    if not _valid_pubkey(sender_id):
        return False

    # timestamp must be positive integer
    if not isinstance(timestamp, int) or timestamp < 0:
        return False

    # SECURITY: Signature must be present
    if not isinstance(signature, str) or len(signature) < 10:
        return False

    # version must be a positive integer if present
    version = payload.get("version")
    if version is not None and (not isinstance(version, int) or version < 0):
        return False

    return True


def compute_gossip_data_hash(payload: Dict[str, Any]) -> str:
    """
    Compute a hash of the GOSSIP data fields.

    SECURITY: This hash is included in the signature to prevent
    data tampering while keeping the signing payload small.
    """
    data_fields = {
        "capacity_sats": payload.get("capacity_sats", 0),
        "available_sats": payload.get("available_sats", 0),
        "fee_policy": payload.get("fee_policy", {}),
        "topology": sorted(payload.get("topology", [])),  # Sort for determinism
    }
    json_str = json.dumps(data_fields, sort_keys=True, separators=(',', ':'))
    return hashlib.sha256(json_str.encode('utf-8')).hexdigest()


def get_gossip_signing_payload(payload: Dict[str, Any]) -> str:
    """
    Get the canonical payload string for signing GOSSIP messages.

    SECURITY: The signature covers:
    - sender_id: Identity of sender
    - timestamp: Replay protection
    - version: State version for conflict resolution
    - fleet_hash: Overall fleet state hash
    - data_hash: Hash of actual gossip data (fee_policy, topology, capacity)

    This prevents data tampering attacks where an attacker modifies
    the fee policies or topology while keeping the signature valid.
    """
    data_hash = compute_gossip_data_hash(payload)

    signing_fields = {
        "sender_id": payload.get("sender_id", ""),
        "timestamp": payload.get("timestamp", 0),
        "version": payload.get("version", 0),
        "fleet_hash": payload.get("fleet_hash", ""),
        "data_hash": data_hash,
    }
    return json.dumps(signing_fields, sort_keys=True, separators=(',', ':'))


def validate_state_hash(payload: Dict[str, Any]) -> bool:
    """
    Validate STATE_HASH payload schema.

    SECURITY: Requires cryptographic signature from the sender.
    """
    if not isinstance(payload, dict):
        return False

    sender_id = payload.get("sender_id")
    fleet_hash = payload.get("fleet_hash")
    timestamp = payload.get("timestamp")
    signature = payload.get("signature")

    # sender_id must be valid pubkey
    if not _valid_pubkey(sender_id):
        return False

    # fleet_hash must be a string
    if not isinstance(fleet_hash, str) or not fleet_hash:
        return False

    # timestamp must be positive integer
    if not isinstance(timestamp, int) or timestamp < 0:
        return False

    # SECURITY: Signature must be present
    if not isinstance(signature, str) or len(signature) < 10:
        return False

    return True


def get_state_hash_signing_payload(payload: Dict[str, Any]) -> str:
    """
    Get the canonical payload string for signing STATE_HASH messages.

    The signature covers core fields in sorted order.
    """
    signing_fields = {
        "sender_id": payload.get("sender_id", ""),
        "fleet_hash": payload.get("fleet_hash", ""),
        "timestamp": payload.get("timestamp", 0),
        "peer_count": payload.get("peer_count", 0),
    }
    return json.dumps(signing_fields, sort_keys=True, separators=(',', ':'))


def validate_full_sync(payload: Dict[str, Any]) -> bool:
    """
    Validate FULL_SYNC payload schema.

    SECURITY: Requires cryptographic signature from the sender.
    This is critical as FULL_SYNC contains membership lists.
    """
    if not isinstance(payload, dict):
        return False

    sender_id = payload.get("sender_id")
    fleet_hash = payload.get("fleet_hash")
    timestamp = payload.get("timestamp")
    signature = payload.get("signature")
    states = payload.get("states")

    # sender_id must be valid pubkey
    if not _valid_pubkey(sender_id):
        return False

    # fleet_hash must be a string
    if not isinstance(fleet_hash, str):
        return False

    # timestamp must be positive integer
    if not isinstance(timestamp, int) or timestamp < 0:
        return False

    # SECURITY: Signature must be present
    if not isinstance(signature, str) or len(signature) < 10:
        return False

    # states must be a list (can be empty)
    if not isinstance(states, list):
        return False

    # Limit states to prevent DoS
    if len(states) > 500:
        return False

    return True


def compute_members_hash(members: list) -> str:
    """
    Compute a deterministic hash of the members list.

    SECURITY: This hash is included in the FULL_SYNC signature to prevent
    membership injection attacks. Without this, an attacker could modify
    the members array while keeping the signature valid.

    Args:
        members: List of member dicts with peer_id, tier, joined_at

    Returns:
        Hex-encoded SHA256 hash of the sorted members array
    """
    if not members:
        return ""

    # Extract minimal fields and sort by peer_id for determinism
    member_tuples = [
        {
            "peer_id": m.get("peer_id", ""),
            "tier": m.get("tier", ""),
            "joined_at": m.get("joined_at", 0),
        }
        for m in members
    ]
    member_tuples.sort(key=lambda x: x["peer_id"])

    json_str = json.dumps(member_tuples, sort_keys=True, separators=(',', ':'))
    return hashlib.sha256(json_str.encode('utf-8')).hexdigest()


def compute_states_hash(states: list) -> str:
    """
    Compute a deterministic hash of the states list.

    SECURITY: This allows receivers to verify that received states
    match the signed fleet_hash, preventing state injection attacks.

    Algorithm matches StateManager.calculate_fleet_hash():
    1. Extract minimal tuples: (peer_id, version, timestamp)
    2. Sort by peer_id (lexicographic)
    3. Serialize to JSON with sorted keys
    4. SHA256 hash the result

    Args:
        states: List of state dicts from FULL_SYNC

    Returns:
        Hex-encoded SHA256 hash of the sorted state tuples
    """
    if not states:
        return ""

    # Extract minimal state tuples (matching StateManager algorithm)
    state_tuples = [
        {
            "peer_id": s.get("peer_id", ""),
            "version": s.get("version", 0),
            "timestamp": s.get("last_update", s.get("timestamp", 0)),
        }
        for s in states
    ]

    # Sort by peer_id for determinism
    state_tuples.sort(key=lambda x: x["peer_id"])

    # Serialize and hash
    json_str = json.dumps(state_tuples, sort_keys=True, separators=(',', ':'))
    return hashlib.sha256(json_str.encode('utf-8')).hexdigest()


def get_full_sync_signing_payload(payload: Dict[str, Any]) -> str:
    """
    Get the canonical payload string for signing FULL_SYNC messages.

    SECURITY: The signature covers:
    - sender_id: Identity of sender
    - fleet_hash: Cryptographic digest of states (verified separately)
    - members_hash: Cryptographic digest of members list
    - timestamp: Replay protection

    This prevents both state tampering AND membership injection attacks.
    """
    members = payload.get("members", [])
    members_hash = compute_members_hash(members)

    signing_fields = {
        "sender_id": payload.get("sender_id", ""),
        "fleet_hash": payload.get("fleet_hash", ""),
        "members_hash": members_hash,
        "timestamp": payload.get("timestamp", 0),
    }
    return json.dumps(signing_fields, sort_keys=True, separators=(',', ':'))


# =============================================================================
# PHASE 3: INTENT MESSAGE VALIDATION
# =============================================================================

def validate_intent_abort(payload: Dict[str, Any]) -> bool:
    """
    Validate INTENT_ABORT payload schema.

    SECURITY: Requires cryptographic signature from the initiator.
    Only the intent owner can abort their own intent.
    """
    if not isinstance(payload, dict):
        return False

    intent_type = payload.get("intent_type")
    target = payload.get("target")
    initiator = payload.get("initiator")
    timestamp = payload.get("timestamp")
    signature = payload.get("signature")

    # intent_type must be a valid string
    valid_intent_types = ('channel_open', 'channel_close', 'rebalance')
    if intent_type not in valid_intent_types:
        return False

    # target must be valid pubkey
    if not _valid_pubkey(target):
        return False

    # initiator must be valid pubkey (the one aborting their intent)
    if not _valid_pubkey(initiator):
        return False

    # timestamp must be positive integer
    if not isinstance(timestamp, int) or timestamp < 0:
        return False

    # SECURITY: Signature must be present
    if not isinstance(signature, str) or len(signature) < 10:
        return False

    return True


def get_intent_abort_signing_payload(payload: Dict[str, Any]) -> str:
    """
    Get the canonical payload string for signing INTENT_ABORT messages.

    The signature proves the initiator is voluntarily aborting their intent.
    """
    signing_fields = {
        "intent_type": payload.get("intent_type", ""),
        "target": payload.get("target", ""),
        "initiator": payload.get("initiator", ""),
        "timestamp": payload.get("timestamp", 0),
        "reason": payload.get("reason", ""),
    }
    return json.dumps(signing_fields, sort_keys=True, separators=(',', ':'))


# =============================================================================
# HELPER FUNCTIONS
# =============================================================================

def create_hello(ticket: str) -> bytes:
    """Create a HIVE_HELLO message."""
    return serialize(HiveMessageType.HELLO, {
        "ticket": ticket,
        "protocol_version": PROTOCOL_VERSION
    })


def create_challenge(nonce: str, hive_id: str) -> bytes:
    """Create a HIVE_CHALLENGE message."""
    return serialize(HiveMessageType.CHALLENGE, {
        "nonce": nonce,
        "hive_id": hive_id
    })


def create_attest(pubkey: str, version: str, features: list,
                  nonce_signature: str, manifest_signature: str,
                  manifest: Dict[str, Any]) -> bytes:
    """Create a HIVE_ATTEST message."""
    return serialize(HiveMessageType.ATTEST, {
        "pubkey": pubkey,
        "version": version,
        "features": features,
        "nonce_signature": nonce_signature,
        "manifest_signature": manifest_signature,
        "manifest": manifest
    })


def create_welcome(hive_id: str, tier: str, member_count: int,
                   state_hash: str) -> bytes:
    """Create a HIVE_WELCOME message."""
    return serialize(HiveMessageType.WELCOME, {
        "hive_id": hive_id,
        "tier": tier,
        "member_count": member_count,
        "state_hash": state_hash
    })


def create_peer_available(target_peer_id: str, reporter_peer_id: str,
                          event_type: str, timestamp: int,
                          signature: str = "",
                          channel_id: str = "",
                          capacity_sats: int = 0,
                          routing_score: float = 0.0,
                          profitability_score: float = 0.0,
                          reason: str = "",
                          # Profitability data from cl-revenue-ops
                          duration_days: int = 0,
                          total_revenue_sats: int = 0,
                          total_rebalance_cost_sats: int = 0,
                          net_pnl_sats: int = 0,
                          forward_count: int = 0,
                          forward_volume_sats: int = 0,
                          our_fee_ppm: int = 0,
                          their_fee_ppm: int = 0,
                          # Channel funding info (for opens)
                          our_funding_sats: int = 0,
                          their_funding_sats: int = 0,
                          opener: str = "") -> bytes:
    """
    Create a PEER_AVAILABLE message.

    Used to notify hive members about channel events for topology awareness.
    Sent when:
    - A channel opens (local or remote initiated)
    - A channel closes (any type)
    - A peer's routing quality is exceptional

    Args:
        target_peer_id: The external peer involved
        reporter_peer_id: The hive member reporting (our pubkey)
        event_type: 'channel_open', 'channel_close', 'remote_close', 'local_close',
                    'mutual_close', 'channel_expired', or 'peer_quality'
        timestamp: Unix timestamp
        channel_id: The channel short ID
        capacity_sats: Channel capacity
        routing_score: Peer's routing quality score (0-1)
        profitability_score: Overall profitability score (0-1)
        reason: Human-readable reason

        # Profitability data (for closures):
        duration_days: How long the channel was open
        total_revenue_sats: Total routing fees earned
        total_rebalance_cost_sats: Total rebalancing costs
        net_pnl_sats: Net profit/loss
        forward_count: Number of forwards routed
        forward_volume_sats: Total volume routed
        our_fee_ppm: Fee rate we charged
        their_fee_ppm: Fee rate they charged us

        # Funding info (for opens):
        our_funding_sats: Amount we funded
        their_funding_sats: Amount they funded
        opener: Who opened: 'local' or 'remote'

    Returns:
        Serialized PEER_AVAILABLE message
    """
    payload = {
        "target_peer_id": target_peer_id,
        "reporter_peer_id": reporter_peer_id,
        "event_type": event_type,
        "timestamp": timestamp,
        "reason": reason
    }

    # Add non-zero optional fields to reduce message size
    if channel_id:
        payload["channel_id"] = channel_id
    if capacity_sats:
        payload["capacity_sats"] = capacity_sats
    if routing_score:
        payload["routing_score"] = routing_score
    if profitability_score:
        payload["profitability_score"] = profitability_score

    # Profitability data
    if duration_days:
        payload["duration_days"] = duration_days
    if total_revenue_sats:
        payload["total_revenue_sats"] = total_revenue_sats
    if total_rebalance_cost_sats:
        payload["total_rebalance_cost_sats"] = total_rebalance_cost_sats
    if net_pnl_sats:
        payload["net_pnl_sats"] = net_pnl_sats
    if forward_count:
        payload["forward_count"] = forward_count
    if forward_volume_sats:
        payload["forward_volume_sats"] = forward_volume_sats
    if our_fee_ppm:
        payload["our_fee_ppm"] = our_fee_ppm
    if their_fee_ppm:
        payload["their_fee_ppm"] = their_fee_ppm

    # Funding info
    if our_funding_sats:
        payload["our_funding_sats"] = our_funding_sats
    if their_funding_sats:
        payload["their_funding_sats"] = their_funding_sats
    if opener:
        payload["opener"] = opener

    # SECURITY: Signature is required
    if signature:
        payload["signature"] = signature

    return serialize(HiveMessageType.PEER_AVAILABLE, payload)


# =============================================================================
# PHASE 6.4: COOPERATIVE EXPANSION PROTOCOL
# =============================================================================

def get_expansion_nominate_signing_payload(payload: Dict[str, Any]) -> str:
    """
    Get the canonical payload string for signing EXPANSION_NOMINATE messages.

    The signature covers all fields except the signature itself, in sorted order.
    """
    signing_fields = {
        "round_id": payload.get("round_id", ""),
        "target_peer_id": payload.get("target_peer_id", ""),
        "nominator_id": payload.get("nominator_id", ""),
        "timestamp": payload.get("timestamp", 0),
        "available_liquidity_sats": payload.get("available_liquidity_sats", 0),
        "quality_score": payload.get("quality_score", 0.5),
        "has_existing_channel": payload.get("has_existing_channel", False),
        "channel_count": payload.get("channel_count", 0),
    }
    return json.dumps(signing_fields, sort_keys=True, separators=(',', ':'))


def validate_expansion_nominate(payload: Dict[str, Any]) -> bool:
    """
    Validate EXPANSION_NOMINATE payload schema.

    This message is sent by hive members to express interest in opening
    a channel to a target peer during a cooperative expansion round.

    SECURITY: Requires a valid cryptographic signature from the nominator.
    """
    if not isinstance(payload, dict):
        return False

    # Required fields
    round_id = payload.get("round_id")
    target_peer_id = payload.get("target_peer_id")
    nominator_id = payload.get("nominator_id")
    timestamp = payload.get("timestamp")
    signature = payload.get("signature")

    # round_id must be a non-empty string
    if not isinstance(round_id, str) or len(round_id) < 8:
        return False

    # Pubkeys must be valid
    if not _valid_pubkey(target_peer_id):
        return False
    if not _valid_pubkey(nominator_id):
        return False

    # Timestamp must be valid
    if not isinstance(timestamp, int) or timestamp < 0:
        return False

    # Signature must be present (zbase encoded string)
    if not isinstance(signature, str) or len(signature) < 10:
        return False

    # Optional: Check numeric fields
    available_liquidity = payload.get("available_liquidity_sats", 0)
    if not isinstance(available_liquidity, int) or available_liquidity < 0:
        return False

    quality_score = payload.get("quality_score", 0.5)
    if not isinstance(quality_score, (int, float)) or not (0 <= quality_score <= 1):
        return False

    return True


def get_expansion_elect_signing_payload(payload: Dict[str, Any]) -> str:
    """
    Get the canonical payload string for signing EXPANSION_ELECT messages.

    The signature covers all fields except the signature itself, in sorted order.
    """
    signing_fields = {
        "round_id": payload.get("round_id", ""),
        "target_peer_id": payload.get("target_peer_id", ""),
        "elected_id": payload.get("elected_id", ""),
        "coordinator_id": payload.get("coordinator_id", ""),
        "timestamp": payload.get("timestamp", 0),
        "channel_size_sats": payload.get("channel_size_sats", 0),
        "quality_score": payload.get("quality_score", 0.5),
        "nomination_count": payload.get("nomination_count", 0),
    }
    return json.dumps(signing_fields, sort_keys=True, separators=(',', ':'))


def validate_expansion_elect(payload: Dict[str, Any]) -> bool:
    """
    Validate EXPANSION_ELECT payload schema.

    This message announces which hive member has been elected to open
    a channel to the target peer.

    SECURITY: Requires a valid cryptographic signature from the coordinator
    who ran the election.
    """
    if not isinstance(payload, dict):
        return False

    # Required fields
    round_id = payload.get("round_id")
    target_peer_id = payload.get("target_peer_id")
    elected_id = payload.get("elected_id")
    coordinator_id = payload.get("coordinator_id")
    timestamp = payload.get("timestamp")
    signature = payload.get("signature")

    # round_id must be a non-empty string
    if not isinstance(round_id, str) or len(round_id) < 8:
        return False

    # Pubkeys must be valid
    if not _valid_pubkey(target_peer_id):
        return False
    if not _valid_pubkey(elected_id):
        return False
    if not _valid_pubkey(coordinator_id):
        return False

    # Timestamp must be valid
    if not isinstance(timestamp, int) or timestamp < 0:
        return False

    # Signature must be present (zbase encoded string)
    if not isinstance(signature, str) or len(signature) < 10:
        return False

    # channel_size_sats must be positive if present
    channel_size = payload.get("channel_size_sats", 0)
    if not isinstance(channel_size, int) or channel_size < 0:
        return False

    return True


def create_expansion_nominate(
    round_id: str,
    target_peer_id: str,
    nominator_id: str,
    timestamp: int,
    signature: str,
    available_liquidity_sats: int = 0,
    quality_score: float = 0.5,
    has_existing_channel: bool = False,
    channel_count: int = 0,
    reason: str = ""
) -> bytes:
    """
    Create an EXPANSION_NOMINATE message.

    Sent by hive members to express interest in opening a channel to a target
    during a cooperative expansion round.

    SECURITY: The signature must be created using signmessage() over the
    canonical payload returned by get_expansion_nominate_signing_payload().

    Args:
        round_id: Unique identifier for this expansion round
        target_peer_id: The external peer to potentially open a channel to
        nominator_id: The hive member nominating themselves
        timestamp: Unix timestamp
        signature: zbase-encoded signature from signmessage()
        available_liquidity_sats: Nominator's available onchain balance
        quality_score: Nominator's calculated quality score for the target
        has_existing_channel: Whether nominator already has a channel to target
        channel_count: Total number of channels the nominator has
        reason: Optional reason for nomination

    Returns:
        Serialized EXPANSION_NOMINATE message
    """
    payload = {
        "round_id": round_id,
        "target_peer_id": target_peer_id,
        "nominator_id": nominator_id,
        "timestamp": timestamp,
        "signature": signature,
        "available_liquidity_sats": available_liquidity_sats,
        "quality_score": quality_score,
        "has_existing_channel": has_existing_channel,
        "channel_count": channel_count,
    }

    if reason:
        payload["reason"] = reason

    return serialize(HiveMessageType.EXPANSION_NOMINATE, payload)


def create_expansion_elect(
    round_id: str,
    target_peer_id: str,
    elected_id: str,
    coordinator_id: str,
    timestamp: int,
    signature: str,
    channel_size_sats: int = 0,
    quality_score: float = 0.5,
    nomination_count: int = 0,
    reason: str = ""
) -> bytes:
    """
    Create an EXPANSION_ELECT message.

    Broadcast to announce which hive member has been elected to open
    a channel to the target peer.

    SECURITY: The signature must be created using signmessage() over the
    canonical payload returned by get_expansion_elect_signing_payload().
    The coordinator_id identifies who ran the election and signed the message.

    Args:
        round_id: Unique identifier for this expansion round
        target_peer_id: The external peer to open a channel to
        elected_id: The hive member elected to open the channel
        coordinator_id: The hive member who ran the election and signed
        timestamp: Unix timestamp
        signature: zbase-encoded signature from signmessage()
        channel_size_sats: Recommended channel size
        quality_score: Target's quality score
        nomination_count: Number of nominations received
        reason: Reason for election

    Returns:
        Serialized EXPANSION_ELECT message
    """
    payload = {
        "round_id": round_id,
        "target_peer_id": target_peer_id,
        "elected_id": elected_id,
        "coordinator_id": coordinator_id,
        "timestamp": timestamp,
        "signature": signature,
        "channel_size_sats": channel_size_sats,
        "quality_score": quality_score,
        "nomination_count": nomination_count,
    }

    if reason:
        payload["reason"] = reason

    return serialize(HiveMessageType.EXPANSION_ELECT, payload)


# =============================================================================
# PHASE 7: FEE INTELLIGENCE SIGNING & VALIDATION
# =============================================================================

def get_fee_intelligence_signing_payload(payload: Dict[str, Any]) -> str:
    """
    Get the canonical string to sign for FEE_INTELLIGENCE messages.

    Includes all critical fields to prevent tampering:
    - reporter_id, target_peer_id, timestamp
    - Fee and performance metrics
    - Flow analysis data

    Args:
        payload: FEE_INTELLIGENCE message payload

    Returns:
        Canonical string for signmessage()
    """
    return (
        f"FEE_INTELLIGENCE:"
        f"{payload.get('reporter_id', '')}:"
        f"{payload.get('target_peer_id', '')}:"
        f"{payload.get('timestamp', 0)}:"
        f"{payload.get('our_fee_ppm', 0)}:"
        f"{payload.get('their_fee_ppm', 0)}:"
        f"{payload.get('forward_count', 0)}:"
        f"{payload.get('forward_volume_sats', 0)}:"
        f"{payload.get('revenue_sats', 0)}:"
        f"{payload.get('flow_direction', '')}:"
        f"{payload.get('utilization_pct', 0.0):.4f}"
    )


def validate_fee_intelligence_payload(payload: Dict[str, Any]) -> bool:
    """
    Validate a FEE_INTELLIGENCE payload.

    SECURITY: Bounds all values to prevent manipulation and overflow.

    Args:
        payload: FEE_INTELLIGENCE message payload

    Returns:
        True if valid, False otherwise
    """
    import time as time_module

    # Required string fields
    reporter_id = payload.get("reporter_id")
    target_peer_id = payload.get("target_peer_id")
    signature = payload.get("signature")

    if not isinstance(reporter_id, str) or not reporter_id:
        return False
    if not isinstance(target_peer_id, str) or not target_peer_id:
        return False
    if not isinstance(signature, str) or len(signature) < 10:
        return False

    # Timestamp freshness
    timestamp = payload.get("timestamp", 0)
    if not isinstance(timestamp, int) or timestamp < 0:
        return False
    if abs(time_module.time() - timestamp) > FEE_INTELLIGENCE_MAX_AGE:
        return False

    # Fee bounds
    our_fee_ppm = payload.get("our_fee_ppm", 0)
    their_fee_ppm = payload.get("their_fee_ppm", 0)
    if not isinstance(our_fee_ppm, int) or not (0 <= our_fee_ppm <= MAX_FEE_PPM):
        return False
    if not isinstance(their_fee_ppm, int) or not (0 <= their_fee_ppm <= MAX_FEE_PPM):
        return False

    # Volume bounds (prevent overflow)
    forward_count = payload.get("forward_count", 0)
    forward_volume_sats = payload.get("forward_volume_sats", 0)
    revenue_sats = payload.get("revenue_sats", 0)

    if not isinstance(forward_count, int) or forward_count < 0:
        return False
    if not isinstance(forward_volume_sats, int) or not (0 <= forward_volume_sats <= MAX_VOLUME_SATS):
        return False
    if not isinstance(revenue_sats, int) or not (0 <= revenue_sats <= MAX_VOLUME_SATS):
        return False

    # Flow direction
    flow_direction = payload.get("flow_direction", "")
    if flow_direction and flow_direction not in VALID_FLOW_DIRECTIONS:
        return False

    # Utilization bounds
    utilization_pct = payload.get("utilization_pct", 0.0)
    if not isinstance(utilization_pct, (int, float)) or not (0 <= utilization_pct <= 1):
        return False

    # Days observed bounds
    days_observed = payload.get("days_observed", 1)
    if not isinstance(days_observed, int) or not (1 <= days_observed <= MAX_DAYS_OBSERVED):
        return False

    return True


def get_liquidity_need_signing_payload(payload: Dict[str, Any]) -> str:
    """
    Get the canonical string to sign for LIQUIDITY_NEED messages.

    Args:
        payload: LIQUIDITY_NEED message payload

    Returns:
        Canonical string for signmessage()
    """
    return (
        f"LIQUIDITY_NEED:"
        f"{payload.get('reporter_id', '')}:"
        f"{payload.get('timestamp', 0)}:"
        f"{payload.get('need_type', '')}:"
        f"{payload.get('target_peer_id', '')}:"
        f"{payload.get('amount_sats', 0)}:"
        f"{payload.get('urgency', '')}:"
        f"{payload.get('max_fee_ppm', 0)}"
    )


def validate_liquidity_need_payload(payload: Dict[str, Any]) -> bool:
    """
    Validate a LIQUIDITY_NEED payload.

    Args:
        payload: LIQUIDITY_NEED message payload

    Returns:
        True if valid, False otherwise
    """
    # Required string fields
    reporter_id = payload.get("reporter_id")
    target_peer_id = payload.get("target_peer_id")
    signature = payload.get("signature")

    if not isinstance(reporter_id, str) or not reporter_id:
        return False
    if not isinstance(target_peer_id, str) or not target_peer_id:
        return False
    if not isinstance(signature, str) or len(signature) < 10:
        return False

    # Timestamp
    timestamp = payload.get("timestamp", 0)
    if not isinstance(timestamp, int) or timestamp < 0:
        return False

    # Need type validation
    need_type = payload.get("need_type")
    if need_type not in VALID_NEED_TYPES:
        return False

    # Urgency validation
    urgency = payload.get("urgency")
    if urgency not in VALID_URGENCY_LEVELS:
        return False

    # Amount bounds
    amount_sats = payload.get("amount_sats", 0)
    if not isinstance(amount_sats, int) or not (0 < amount_sats <= MAX_LIQUIDITY_AMOUNT):
        return False

    # Fee bounds
    max_fee_ppm = payload.get("max_fee_ppm", 0)
    if not isinstance(max_fee_ppm, int) or not (0 <= max_fee_ppm <= MAX_FEE_PPM):
        return False

    # Balance percentage
    current_balance_pct = payload.get("current_balance_pct", 0.0)
    if not isinstance(current_balance_pct, (int, float)) or not (0 <= current_balance_pct <= 1):
        return False

    return True


def get_health_report_signing_payload(payload: Dict[str, Any]) -> str:
    """
    Get the canonical string to sign for HEALTH_REPORT messages.

    Args:
        payload: HEALTH_REPORT message payload

    Returns:
        Canonical string for signmessage()
    """
    return (
        f"HEALTH_REPORT:"
        f"{payload.get('reporter_id', '')}:"
        f"{payload.get('timestamp', 0)}:"
        f"{payload.get('overall_health', 0)}:"
        f"{payload.get('capacity_score', 0)}:"
        f"{payload.get('revenue_score', 0)}:"
        f"{payload.get('connectivity_score', 0)}"
    )


def validate_health_report_payload(payload: Dict[str, Any]) -> bool:
    """
    Validate a HEALTH_REPORT payload.

    Args:
        payload: HEALTH_REPORT message payload

    Returns:
        True if valid, False otherwise
    """
    # Required string fields
    reporter_id = payload.get("reporter_id")
    signature = payload.get("signature")

    if not isinstance(reporter_id, str) or not reporter_id:
        return False
    if not isinstance(signature, str) or len(signature) < 10:
        return False

    # Timestamp
    timestamp = payload.get("timestamp", 0)
    if not isinstance(timestamp, int) or timestamp < 0:
        return False

    # Health scores (0-100)
    for score_field in ['overall_health', 'capacity_score', 'revenue_score', 'connectivity_score']:
        score = payload.get(score_field, 0)
        if not isinstance(score, int) or not (MIN_HEALTH_SCORE <= score <= MAX_HEALTH_SCORE):
            return False

    # Assistance budget bounds
    assistance_budget = payload.get("assistance_budget_sats", 0)
    if not isinstance(assistance_budget, int) or assistance_budget < 0:
        return False

    return True


def get_route_probe_signing_payload(payload: Dict[str, Any]) -> str:
    """
    Get the canonical string to sign for ROUTE_PROBE messages.

    Args:
        payload: ROUTE_PROBE message payload

    Returns:
        Canonical string for signmessage()
    """
    # Sort path to make signing deterministic
    path = payload.get("path", [])
    path_str = ",".join(sorted(path)) if path else ""

    return (
        f"ROUTE_PROBE:"
        f"{payload.get('reporter_id', '')}:"
        f"{payload.get('destination', '')}:"
        f"{payload.get('timestamp', 0)}:"
        f"{path_str}:"
        f"{payload.get('success', False)}:"
        f"{payload.get('latency_ms', 0)}:"
        f"{payload.get('total_fee_ppm', 0)}"
    )


def validate_route_probe_payload(payload: Dict[str, Any]) -> bool:
    """
    Validate a ROUTE_PROBE payload.

    Args:
        payload: ROUTE_PROBE message payload

    Returns:
        True if valid, False otherwise
    """
    # Required string fields
    reporter_id = payload.get("reporter_id")
    destination = payload.get("destination")
    signature = payload.get("signature")

    if not isinstance(reporter_id, str) or not reporter_id:
        return False
    if not isinstance(destination, str) or not destination:
        return False
    if not isinstance(signature, str) or len(signature) < 10:
        return False

    # Timestamp
    timestamp = payload.get("timestamp", 0)
    if not isinstance(timestamp, int) or timestamp < 0:
        return False

    # Path validation
    path = payload.get("path", [])
    if not isinstance(path, list):
        return False
    if len(path) > MAX_PATH_LENGTH:
        return False
    for hop in path:
        if not isinstance(hop, str):
            return False

    # Success must be boolean
    success = payload.get("success")
    if not isinstance(success, bool):
        return False

    # Latency bounds
    latency_ms = payload.get("latency_ms", 0)
    if not isinstance(latency_ms, int) or not (0 <= latency_ms <= MAX_LATENCY_MS):
        return False

    # Failure reason validation
    failure_reason = payload.get("failure_reason", "")
    if failure_reason not in VALID_FAILURE_REASONS:
        return False

    # Failure hop must be valid index or -1
    failure_hop = payload.get("failure_hop", -1)
    if not isinstance(failure_hop, int):
        return False
    if failure_hop != -1 and (failure_hop < 0 or failure_hop >= len(path)):
        return False

    # Capacity bounds
    estimated_capacity = payload.get("estimated_capacity_sats", 0)
    if not isinstance(estimated_capacity, int) or not (0 <= estimated_capacity <= MAX_CAPACITY_SATS):
        return False

    # Fee bounds
    total_fee_ppm = payload.get("total_fee_ppm", 0)
    if not isinstance(total_fee_ppm, int) or not (0 <= total_fee_ppm <= MAX_FEE_PPM * MAX_PATH_LENGTH):
        return False

    # Per-hop fees validation
    per_hop_fees = payload.get("per_hop_fees", [])
    if not isinstance(per_hop_fees, list):
        return False
    for fee in per_hop_fees:
        if not isinstance(fee, int) or fee < 0:
            return False

    # Amount probed bounds
    amount_probed = payload.get("amount_probed_sats", 0)
    if not isinstance(amount_probed, int) or amount_probed < 0:
        return False

    return True


def create_route_probe(
    reporter_id: str,
    destination: str,
    path: List[str],
    success: bool,
    latency_ms: int,
    rpc,
    failure_reason: str = "",
    failure_hop: int = -1,
    estimated_capacity_sats: int = 0,
    total_fee_ppm: int = 0,
    per_hop_fees: List[int] = None,
    amount_probed_sats: int = 0
) -> Optional[bytes]:
    """
    Create a signed ROUTE_PROBE message.

    Args:
        reporter_id: Hive member reporting this probe
        destination: Final destination pubkey
        path: List of intermediate hop pubkeys
        success: Whether probe succeeded
        latency_ms: Round-trip time in milliseconds
        rpc: RPC interface for signing
        failure_reason: Reason for failure (if any)
        failure_hop: Index of failing hop (if any)
        estimated_capacity_sats: Estimated route capacity
        total_fee_ppm: Total fees for route
        per_hop_fees: Fee at each hop
        amount_probed_sats: Amount that was probed

    Returns:
        Serialized and signed ROUTE_PROBE message, or None on error
    """
    timestamp = int(time.time())

    payload = {
        "reporter_id": reporter_id,
        "destination": destination,
        "timestamp": timestamp,
        "path": path,
        "success": success,
        "latency_ms": latency_ms,
        "failure_reason": failure_reason,
        "failure_hop": failure_hop,
        "estimated_capacity_sats": estimated_capacity_sats,
        "total_fee_ppm": total_fee_ppm,
        "per_hop_fees": per_hop_fees or [],
        "amount_probed_sats": amount_probed_sats,
    }

    # Sign the payload
    signing_message = get_route_probe_signing_payload(payload)
    try:
        sig_result = rpc.signmessage(signing_message)
        payload["signature"] = sig_result["zbase"]
    except Exception:
        return None

    return serialize(HiveMessageType.ROUTE_PROBE, payload)


def get_peer_reputation_signing_payload(payload: Dict[str, Any]) -> str:
    """
    Generate signing payload for PEER_REPUTATION message.

    Creates a deterministic string for signature verification.

    Args:
        payload: PEER_REPUTATION payload dict

    Returns:
        Canonical string for signing
    """
    return (
        f"HIVE_PEER_REPUTATION:"
        f"{payload.get('reporter_id', '')}:"
        f"{payload.get('peer_id', '')}:"
        f"{payload.get('timestamp', 0)}:"
        f"{payload.get('uptime_pct', 1.0):.2f}:"
        f"{payload.get('htlc_success_rate', 1.0):.2f}:"
        f"{payload.get('force_close_count', 0)}"
    )


def validate_peer_reputation_payload(payload: Dict[str, Any]) -> bool:
    """
    Validate a PEER_REPUTATION payload.

    Args:
        payload: PEER_REPUTATION message payload

    Returns:
        True if valid, False otherwise
    """
    # Required string fields
    reporter_id = payload.get("reporter_id")
    peer_id = payload.get("peer_id")
    signature = payload.get("signature")

    if not isinstance(reporter_id, str) or not reporter_id:
        return False
    if not isinstance(peer_id, str) or not peer_id:
        return False
    if not isinstance(signature, str) or len(signature) < 10:
        return False

    # Timestamp
    timestamp = payload.get("timestamp", 0)
    if not isinstance(timestamp, int) or timestamp < 0:
        return False

    # Uptime percentage bounds (0-1)
    uptime_pct = payload.get("uptime_pct", 1.0)
    if not isinstance(uptime_pct, (int, float)) or not (0 <= uptime_pct <= 1):
        return False

    # Response time bounds
    response_time_ms = payload.get("response_time_ms", 0)
    if not isinstance(response_time_ms, int) or not (0 <= response_time_ms <= MAX_RESPONSE_TIME_MS):
        return False

    # Force close count bounds
    force_close_count = payload.get("force_close_count", 0)
    if not isinstance(force_close_count, int) or not (0 <= force_close_count <= MAX_FORCE_CLOSE_COUNT):
        return False

    # Fee stability bounds (0-1)
    fee_stability = payload.get("fee_stability", 1.0)
    if not isinstance(fee_stability, (int, float)) or not (0 <= fee_stability <= 1):
        return False

    # HTLC success rate bounds (0-1)
    htlc_success_rate = payload.get("htlc_success_rate", 1.0)
    if not isinstance(htlc_success_rate, (int, float)) or not (0 <= htlc_success_rate <= 1):
        return False

    # Channel age bounds
    channel_age_days = payload.get("channel_age_days", 0)
    if not isinstance(channel_age_days, int) or not (0 <= channel_age_days <= MAX_CHANNEL_AGE_DAYS):
        return False

    # Total routed bounds
    total_routed_sats = payload.get("total_routed_sats", 0)
    if not isinstance(total_routed_sats, int) or total_routed_sats < 0:
        return False

    # Observation days bounds
    observation_days = payload.get("observation_days", 7)
    if not isinstance(observation_days, int) or not (1 <= observation_days <= MAX_OBSERVATION_DAYS):
        return False

    # Warnings validation
    warnings = payload.get("warnings", [])
    if not isinstance(warnings, list):
        return False
    if len(warnings) > MAX_WARNINGS_COUNT:
        return False
    for warning in warnings:
        if not isinstance(warning, str):
            return False
        if len(warning) > MAX_WARNING_LENGTH:
            return False
        # Warning must be from valid set
        if warning and warning not in VALID_WARNINGS:
            return False

    return True


def create_peer_reputation(
    reporter_id: str,
    peer_id: str,
    rpc,
    uptime_pct: float = 1.0,
    response_time_ms: int = 0,
    force_close_count: int = 0,
    fee_stability: float = 1.0,
    htlc_success_rate: float = 1.0,
    channel_age_days: int = 0,
    total_routed_sats: int = 0,
    warnings: List[str] = None,
    observation_days: int = 7
) -> Optional[bytes]:
    """
    Create a signed PEER_REPUTATION message.

    Args:
        reporter_id: Hive member reporting this observation
        peer_id: External peer being reported on
        rpc: RPC interface for signing
        uptime_pct: Peer uptime percentage (0-1)
        response_time_ms: Average HTLC response time
        force_close_count: Number of force closes by peer
        fee_stability: Fee stability score (0-1)
        htlc_success_rate: HTLC success rate (0-1)
        channel_age_days: Channel age in days
        total_routed_sats: Total volume routed through peer
        warnings: List of warning codes
        observation_days: Days covered by this report

    Returns:
        Serialized and signed PEER_REPUTATION message, or None on error
    """
    timestamp = int(time.time())

    payload = {
        "reporter_id": reporter_id,
        "peer_id": peer_id,
        "timestamp": timestamp,
        "uptime_pct": uptime_pct,
        "response_time_ms": response_time_ms,
        "force_close_count": force_close_count,
        "fee_stability": fee_stability,
        "htlc_success_rate": htlc_success_rate,
        "channel_age_days": channel_age_days,
        "total_routed_sats": total_routed_sats,
        "warnings": warnings or [],
        "observation_days": observation_days,
    }

    # Sign the payload
    signing_message = get_peer_reputation_signing_payload(payload)
    try:
        sig_result = rpc.signmessage(signing_message)
        payload["signature"] = sig_result["zbase"]
    except Exception:
        return None

    return serialize(HiveMessageType.PEER_REPUTATION, payload)


def create_fee_intelligence(
    reporter_id: str,
    target_peer_id: str,
    timestamp: int,
    signature: str,
    our_fee_ppm: int,
    their_fee_ppm: int,
    forward_count: int,
    forward_volume_sats: int,
    revenue_sats: int,
    flow_direction: str,
    utilization_pct: float,
    last_fee_change_ppm: int = 0,
    volume_delta_pct: float = 0.0,
    days_observed: int = 1
) -> bytes:
    """
    Create a FEE_INTELLIGENCE message.

    SECURITY: The signature must be created using signmessage() over the
    canonical payload returned by get_fee_intelligence_signing_payload().

    Args:
        reporter_id: Hive member reporting this observation
        target_peer_id: External peer being reported on
        timestamp: Unix timestamp
        signature: zbase-encoded signature from signmessage()
        our_fee_ppm: Fee we charge to this peer
        their_fee_ppm: Fee they charge us
        forward_count: Number of forwards
        forward_volume_sats: Total volume routed
        revenue_sats: Fees earned
        flow_direction: 'source', 'sink', or 'balanced'
        utilization_pct: Channel utilization (0.0-1.0)
        last_fee_change_ppm: Previous fee rate (for elasticity)
        volume_delta_pct: Volume change after fee change
        days_observed: How long this peer has been observed

    Returns:
        Serialized FEE_INTELLIGENCE message
    """
    payload = {
        "reporter_id": reporter_id,
        "target_peer_id": target_peer_id,
        "timestamp": timestamp,
        "signature": signature,
        "our_fee_ppm": our_fee_ppm,
        "their_fee_ppm": their_fee_ppm,
        "forward_count": forward_count,
        "forward_volume_sats": forward_volume_sats,
        "revenue_sats": revenue_sats,
        "flow_direction": flow_direction,
        "utilization_pct": utilization_pct,
        "last_fee_change_ppm": last_fee_change_ppm,
        "volume_delta_pct": volume_delta_pct,
        "days_observed": days_observed,
    }

    return serialize(HiveMessageType.FEE_INTELLIGENCE, payload)


def create_liquidity_need(
    reporter_id: str,
    timestamp: int,
    signature: str,
    need_type: str,
    target_peer_id: str,
    amount_sats: int,
    urgency: str,
    max_fee_ppm: int,
    reason: str,
    current_balance_pct: float,
    can_provide_inbound: int = 0,
    can_provide_outbound: int = 0
) -> bytes:
    """
    Create a LIQUIDITY_NEED message.

    SECURITY: The signature must be created using signmessage() over the
    canonical payload returned by get_liquidity_need_signing_payload().

    Args:
        reporter_id: Hive member needing liquidity
        timestamp: Unix timestamp
        signature: zbase-encoded signature from signmessage()
        need_type: 'inbound', 'outbound', or 'rebalance'
        target_peer_id: External peer (or hive member)
        amount_sats: How much liquidity needed
        urgency: 'critical', 'high', 'medium', or 'low'
        max_fee_ppm: Maximum fee willing to pay
        reason: Why liquidity is needed
        current_balance_pct: Current local balance percentage
        can_provide_inbound: Sats of inbound we can provide
        can_provide_outbound: Sats of outbound we can provide

    Returns:
        Serialized LIQUIDITY_NEED message
    """
    payload = {
        "reporter_id": reporter_id,
        "timestamp": timestamp,
        "signature": signature,
        "need_type": need_type,
        "target_peer_id": target_peer_id,
        "amount_sats": amount_sats,
        "urgency": urgency,
        "max_fee_ppm": max_fee_ppm,
        "reason": reason,
        "current_balance_pct": current_balance_pct,
        "can_provide_inbound": can_provide_inbound,
        "can_provide_outbound": can_provide_outbound,
    }

    return serialize(HiveMessageType.LIQUIDITY_NEED, payload)


def create_health_report(
    reporter_id: str,
    timestamp: int,
    signature: str,
    overall_health: int,
    capacity_score: int,
    revenue_score: int,
    connectivity_score: int,
    needs_inbound: bool = False,
    needs_outbound: bool = False,
    needs_channels: bool = False,
    can_provide_assistance: bool = False,
    assistance_budget_sats: int = 0
) -> bytes:
    """
    Create a HEALTH_REPORT message.

    SECURITY: The signature must be created using signmessage() over the
    canonical payload returned by get_health_report_signing_payload().

    Args:
        reporter_id: Hive member reporting their health
        timestamp: Unix timestamp
        signature: zbase-encoded signature from signmessage()
        overall_health: Overall health score (0-100)
        capacity_score: Capacity score (0-100)
        revenue_score: Revenue score (0-100)
        connectivity_score: Connectivity score (0-100)
        needs_inbound: Whether node needs inbound liquidity
        needs_outbound: Whether node needs outbound liquidity
        needs_channels: Whether node needs more channels
        can_provide_assistance: Whether node can help others
        assistance_budget_sats: How much node can spend helping

    Returns:
        Serialized HEALTH_REPORT message
    """
    payload = {
        "reporter_id": reporter_id,
        "timestamp": timestamp,
        "signature": signature,
        "overall_health": overall_health,
        "capacity_score": capacity_score,
        "revenue_score": revenue_score,
        "connectivity_score": connectivity_score,
        "needs_inbound": needs_inbound,
        "needs_outbound": needs_outbound,
        "needs_channels": needs_channels,
        "can_provide_assistance": can_provide_assistance,
        "assistance_budget_sats": assistance_budget_sats,
    }

    return serialize(HiveMessageType.HEALTH_REPORT, payload)


# =============================================================================
# AI ORACLE PROTOCOL - VALIDATION FUNCTIONS (Phase 8)
# =============================================================================

def validate_attestation(attestation: Optional[Dict[str, Any]]) -> bool:
    """
    Validate an operator attestation object.

    Per spec section 6.7.1, attestations prove the operator claims
    this message was generated by an AI.

    Args:
        attestation: Attestation dict or None

    Returns:
        True if valid (or None/missing), False if malformed
    """
    if attestation is None:
        return True  # Optional field

    if not isinstance(attestation, dict):
        return False

    # Required fields
    required = ["response_id", "model_claimed", "timestamp", "operator_pubkey",
                "api_endpoint", "response_hash", "operator_signature"]
    for field in required:
        if field not in attestation:
            return False

    # Timestamp freshness
    ts = attestation.get("timestamp", 0)
    if not isinstance(ts, int) or ts < 0:
        return False

    # Pubkey validation
    operator_pubkey = attestation.get("operator_pubkey", "")
    if not _valid_pubkey(operator_pubkey):
        return False

    # Signature must be present
    sig = attestation.get("operator_signature", "")
    if not isinstance(sig, str) or len(sig) < 10:
        return False

    return True


def validate_ai_state_summary_payload(payload: Dict[str, Any]) -> bool:
    """
    Validate an AI_STATE_SUMMARY payload.

    SECURITY: Validates all enum fields against allowed values to prevent
    prompt injection attacks. Rejects unknown values per spec section 6.4.

    Args:
        payload: AI_STATE_SUMMARY message payload

    Returns:
        True if valid, False otherwise
    """
    import time as time_module

    if not isinstance(payload, dict):
        return False

    # Required fields
    node_id = payload.get("node_id")
    timestamp = payload.get("timestamp")
    sequence = payload.get("sequence")
    signature = payload.get("signature")

    # Node ID must be valid pubkey
    if not _valid_pubkey(node_id):
        return False

    # Timestamp validation and freshness check
    if not isinstance(timestamp, int) or timestamp < 0:
        return False
    if abs(time_module.time() - timestamp) > AI_MESSAGE_MAX_AGE_SECONDS:
        return False

    # Sequence must be positive integer
    if not isinstance(sequence, int) or sequence < 0 or sequence > MAX_SEQUENCE_NUMBER:
        return False

    # Signature must be present
    if not isinstance(signature, str) or len(signature) < 10:
        return False

    # Liquidity state enums
    liquidity_status = payload.get("liquidity_status", "")
    if liquidity_status and liquidity_status not in VALID_LIQUIDITY_STATUS:
        return False

    capacity_tier = payload.get("capacity_tier", "")
    if capacity_tier and capacity_tier not in VALID_CAPACITY_TIER:
        return False

    outbound_status = payload.get("outbound_status", "")
    if outbound_status and outbound_status not in VALID_STATUS_LEVEL:
        return False

    inbound_status = payload.get("inbound_status", "")
    if inbound_status and inbound_status not in VALID_STATUS_LEVEL:
        return False

    channel_count_tier = payload.get("channel_count_tier", "")
    if channel_count_tier and channel_count_tier not in VALID_CHANNEL_COUNT_TIER:
        return False

    utilization_bucket = payload.get("utilization_bucket", "")
    if utilization_bucket and utilization_bucket not in VALID_UTILIZATION_BUCKET:
        return False

    # Priority enums
    current_focus = payload.get("current_focus", "")
    if current_focus and current_focus not in VALID_CURRENT_FOCUS:
        return False

    budget_status = payload.get("budget_status", "available")
    if budget_status not in VALID_BUDGET_STATUS:
        return False

    # Category lists
    seeking_categories = payload.get("seeking_categories", [])
    if not isinstance(seeking_categories, list) or len(seeking_categories) > MAX_SEEKING_CATEGORIES:
        return False
    for cat in seeking_categories:
        if not isinstance(cat, str) or (cat and cat not in VALID_NODE_CATEGORIES):
            return False

    avoid_categories = payload.get("avoid_categories", [])
    if not isinstance(avoid_categories, list) or len(avoid_categories) > MAX_AVOID_CATEGORIES:
        return False
    for cat in avoid_categories:
        if not isinstance(cat, str) or (cat and cat not in VALID_NODE_CATEGORIES):
            return False

    # Capability enums
    expansion_capacity_tier = payload.get("expansion_capacity_tier", "medium")
    if expansion_capacity_tier not in VALID_EXPANSION_CAPACITY_TIER:
        return False

    feerate_tolerance = payload.get("feerate_tolerance", "normal")
    if feerate_tolerance not in VALID_FEERATE_TOLERANCE:
        return False

    # AI metadata
    ai_confidence = payload.get("ai_confidence", 0.5)
    if not isinstance(ai_confidence, (int, float)) or not (0 <= ai_confidence <= 1):
        return False

    decisions_last_24h = payload.get("decisions_last_24h", 0)
    if not isinstance(decisions_last_24h, int) or decisions_last_24h < 0:
        return False

    strategy_alignment = payload.get("strategy_alignment", "cooperative")
    if strategy_alignment not in VALID_STRATEGY_ALIGNMENT:
        return False

    # Attestation validation
    attestation = payload.get("attestation")
    if not validate_attestation(attestation):
        return False

    return True


def validate_ai_heartbeat_payload(payload: Dict[str, Any]) -> bool:
    """
    Validate an AI_HEARTBEAT payload.

    Args:
        payload: AI_HEARTBEAT message payload

    Returns:
        True if valid, False otherwise
    """
    import time as time_module

    if not isinstance(payload, dict):
        return False

    # Required fields
    node_id = payload.get("node_id")
    timestamp = payload.get("timestamp")
    sequence = payload.get("sequence")
    signature = payload.get("signature")

    # Node ID must be valid pubkey
    if not _valid_pubkey(node_id):
        return False

    # Timestamp validation and freshness check
    if not isinstance(timestamp, int) or timestamp < 0:
        return False
    if abs(time_module.time() - timestamp) > AI_MESSAGE_MAX_AGE_SECONDS:
        return False

    # Sequence must be positive integer
    if not isinstance(sequence, int) or sequence < 0 or sequence > MAX_SEQUENCE_NUMBER:
        return False

    # Signature must be present
    if not isinstance(signature, str) or len(signature) < 10:
        return False

    # Operational state enum
    operational_state = payload.get("operational_state", "")
    if operational_state and operational_state not in VALID_OPERATIONAL_STATE:
        return False

    # Model must be a string
    model_claimed = payload.get("model_claimed", "")
    if not isinstance(model_claimed, str):
        return False

    # Numeric bounds
    uptime_seconds = payload.get("uptime_seconds", 0)
    if not isinstance(uptime_seconds, int) or uptime_seconds < 0:
        return False

    api_latency_ms = payload.get("api_latency_ms", 0)
    if not isinstance(api_latency_ms, int) or api_latency_ms < 0:
        return False

    api_success_rate_pct = payload.get("api_success_rate_pct", 100.0)
    if not isinstance(api_success_rate_pct, (int, float)) or not (0 <= api_success_rate_pct <= 100):
        return False

    memory_usage_pct = payload.get("memory_usage_pct", 0.0)
    if not isinstance(memory_usage_pct, (int, float)) or not (0 <= memory_usage_pct <= 100):
        return False

    error_rate_24h = payload.get("error_rate_24h", 0.0)
    if not isinstance(error_rate_24h, (int, float)) or error_rate_24h < 0:
        return False

    max_decisions_per_hour = payload.get("max_decisions_per_hour", 100)
    if not isinstance(max_decisions_per_hour, int) or max_decisions_per_hour < 0:
        return False

    # Task types list
    supported_task_types = payload.get("supported_task_types", [])
    if not isinstance(supported_task_types, list) or len(supported_task_types) > MAX_SUPPORTED_TASK_TYPES:
        return False
    for task_type in supported_task_types:
        if not isinstance(task_type, str) or (task_type and task_type not in VALID_AI_TASK_TYPES):
            return False

    # Attestation validation
    attestation = payload.get("attestation")
    if not validate_attestation(attestation):
        return False

    return True


def validate_ai_opportunity_signal_payload(payload: Dict[str, Any]) -> bool:
    """
    Validate an AI_OPPORTUNITY_SIGNAL payload.

    Args:
        payload: AI_OPPORTUNITY_SIGNAL message payload

    Returns:
        True if valid, False otherwise
    """
    import time as time_module

    if not isinstance(payload, dict):
        return False

    # Required fields
    node_id = payload.get("node_id")
    timestamp = payload.get("timestamp")
    signal_id = payload.get("signal_id")
    signature = payload.get("signature")
    target_node = payload.get("target_node")
    opportunity_type = payload.get("opportunity_type")

    # Node ID must be valid pubkey
    if not _valid_pubkey(node_id):
        return False

    # Target node must be valid pubkey
    if not _valid_pubkey(target_node):
        return False

    # Timestamp validation and freshness check
    if not isinstance(timestamp, int) or timestamp < 0:
        return False
    if abs(time_module.time() - timestamp) > AI_MESSAGE_MAX_AGE_SECONDS:
        return False

    # Signal ID validation
    if not isinstance(signal_id, str) or not signal_id or len(signal_id) > MAX_SIGNAL_ID_LEN:
        return False

    # Signature must be present
    if not isinstance(signature, str) or len(signature) < 10:
        return False

    # Opportunity type enum
    if opportunity_type not in VALID_OPPORTUNITY_TYPE:
        return False

    # Category validation (optional)
    category = payload.get("category", "")
    if category and category not in VALID_NODE_CATEGORIES:
        return False

    # Action enum
    recommended_action = payload.get("recommended_action", "expand")
    if recommended_action not in VALID_OPPORTUNITY_ACTION:
        return False

    # Urgency enum
    urgency = payload.get("urgency", "medium")
    if urgency not in VALID_URGENCY_LEVELS:
        return False

    # Confidence bounds
    confidence = payload.get("confidence", 0.5)
    if not isinstance(confidence, (int, float)) or not (0 <= confidence <= 1):
        return False

    # Numeric bounds
    for field in ["target_capacity_sats", "target_channel_count", "suggested_capacity_sats",
                  "estimated_daily_volume_sats", "avg_fee_rate_ppm", "volunteer_capacity_sats"]:
        val = payload.get(field, 0)
        if not isinstance(val, int) or val < 0:
            return False

    # Percentage bounds
    for field in ["current_hive_share_pct", "optimal_hive_share_pct", "share_gap_pct",
                  "estimated_roi_annual_pct", "volunteer_position_score"]:
        val = payload.get(field, 0.0)
        if not isinstance(val, (int, float)):
            return False

    # Reasoning factors validation
    reasoning_factors = payload.get("reasoning_factors", [])
    if not isinstance(reasoning_factors, list) or len(reasoning_factors) > MAX_REASONING_FACTORS:
        return False
    for factor in reasoning_factors:
        if not isinstance(factor, str) or (factor and factor not in VALID_REASONING_FACTORS):
            return False

    # Attestation validation
    attestation = payload.get("attestation")
    if not validate_attestation(attestation):
        return False

    return True


def validate_ai_alert_payload(payload: Dict[str, Any]) -> bool:
    """
    Validate an AI_ALERT payload.

    Args:
        payload: AI_ALERT message payload

    Returns:
        True if valid, False otherwise
    """
    import time as time_module

    if not isinstance(payload, dict):
        return False

    # Required fields
    node_id = payload.get("node_id")
    timestamp = payload.get("timestamp")
    alert_id = payload.get("alert_id")
    signature = payload.get("signature")
    severity = payload.get("severity")
    category = payload.get("category")
    alert_type = payload.get("alert_type")

    # Node ID must be valid pubkey
    if not _valid_pubkey(node_id):
        return False

    # Timestamp validation and freshness check
    if not isinstance(timestamp, int) or timestamp < 0:
        return False
    if abs(time_module.time() - timestamp) > AI_MESSAGE_MAX_AGE_SECONDS:
        return False

    # Alert ID validation
    if not isinstance(alert_id, str) or not alert_id or len(alert_id) > MAX_ALERT_ID_LEN:
        return False

    # Signature must be present
    if not isinstance(signature, str) or len(signature) < 10:
        return False

    # Severity enum
    if severity not in VALID_ALERT_SEVERITY:
        return False

    # Category enum
    if category not in VALID_ALERT_CATEGORY:
        return False

    # Alert type enum
    if alert_type not in VALID_ALERT_TYPES:
        return False

    # Risk level enums
    immediate_risk = payload.get("immediate_risk", "low")
    if immediate_risk not in VALID_RISK_LEVEL:
        return False

    potential_risk = payload.get("potential_risk", "low")
    if potential_risk not in VALID_RISK_LEVEL:
        return False

    # Action enums
    recommended_action = payload.get("recommended_action", "monitor")
    if recommended_action not in VALID_ALERT_ACTION:
        return False

    action_urgency = payload.get("action_urgency", "normal")
    if action_urgency not in VALID_ACTION_URGENCY:
        return False

    # Affected channels validation
    affected_channels = payload.get("affected_channels", [])
    if not isinstance(affected_channels, list) or len(affected_channels) > MAX_AFFECTED_CHANNELS:
        return False
    for channel in affected_channels:
        if not isinstance(channel, str):
            return False

    # Numeric bounds
    affected_hive_members = payload.get("affected_hive_members", 0)
    if not isinstance(affected_hive_members, int) or affected_hive_members < 0:
        return False

    time_window_minutes = payload.get("time_window_minutes", 0)
    if not isinstance(time_window_minutes, int) or time_window_minutes < 0:
        return False

    # Attestation validation
    attestation = payload.get("attestation")
    if not validate_attestation(attestation):
        return False

    return True


# =============================================================================
# AI ORACLE PROTOCOL - TASK COORDINATION VALIDATION (Phase 8.2)
# =============================================================================

def validate_ai_task_request_payload(payload: Dict[str, Any]) -> bool:
    """
    Validate an AI_TASK_REQUEST payload.

    SECURITY: Validates all enum fields against allowed values.
    Also validates reciprocity constraints per spec section 6.6.

    Args:
        payload: AI_TASK_REQUEST message payload

    Returns:
        True if valid, False otherwise
    """
    import time as time_module

    if not isinstance(payload, dict):
        return False

    # Required fields
    node_id = payload.get("node_id")
    target_node = payload.get("target_node")
    timestamp = payload.get("timestamp")
    request_id = payload.get("request_id")
    signature = payload.get("signature")
    task_type = payload.get("task_type")
    task_target = payload.get("task_target")

    # Node IDs must be valid pubkeys
    if not _valid_pubkey(node_id):
        return False
    if not _valid_pubkey(target_node):
        return False

    # Timestamp validation and freshness check
    if not isinstance(timestamp, int) or timestamp < 0:
        return False
    if abs(time_module.time() - timestamp) > AI_MESSAGE_MAX_AGE_SECONDS:
        return False

    # Request ID validation
    if not isinstance(request_id, str) or not request_id or len(request_id) > MAX_REQUEST_ID_LEN_AI:
        return False

    # Signature must be present
    if not isinstance(signature, str) or len(signature) < 10:
        return False

    # Task type validation
    if task_type not in VALID_AI_TASK_TYPES:
        return False

    # Task target validation (pubkey or scid depending on task type)
    if not isinstance(task_target, str) or not task_target:
        return False

    # Task priority validation
    task_priority = payload.get("task_priority", "normal")
    if task_priority not in VALID_TASK_PRIORITIES:
        return False

    # Task deadline validation
    task_deadline = payload.get("task_deadline_timestamp", 0)
    if not isinstance(task_deadline, int) or task_deadline < 0:
        return False

    # Amount bounds
    amount_sats = payload.get("amount_sats", 0)
    if not isinstance(amount_sats, int) or amount_sats < 0 or amount_sats > MAX_TASK_AMOUNT_SATS:
        return False

    max_fee_sats = payload.get("max_fee_sats", 0)
    if not isinstance(max_fee_sats, int) or max_fee_sats < 0 or max_fee_sats > MAX_TASK_FEE_SATS:
        return False

    max_fee_ppm = payload.get("max_fee_ppm", 0)
    if not isinstance(max_fee_ppm, int) or max_fee_ppm < 0 or max_fee_ppm > MAX_TASK_FEE_PPM:
        return False

    # Channel count bounds
    min_channels = payload.get("min_channels", 1)
    max_channels = payload.get("max_channels", 1)
    if not isinstance(min_channels, int) or min_channels < 0 or min_channels > MAX_CHANNELS_PER_TASK:
        return False
    if not isinstance(max_channels, int) or max_channels < min_channels or max_channels > MAX_CHANNELS_PER_TASK:
        return False

    # Selection factors validation
    selection_factors = payload.get("selection_factors", [])
    if not isinstance(selection_factors, list) or len(selection_factors) > MAX_SELECTION_FACTORS:
        return False
    for factor in selection_factors:
        if not isinstance(factor, str) or (factor and factor not in VALID_SELECTION_FACTORS):
            return False

    # Fleet benefit metric validation
    fleet_benefit_metric = payload.get("fleet_benefit_metric", "")
    if fleet_benefit_metric and fleet_benefit_metric not in VALID_FLEET_METRICS:
        return False

    # Compensation validation
    compensation_offer_type = payload.get("compensation_offer_type", "reciprocal")
    if compensation_offer_type not in VALID_COMPENSATION_TYPES:
        return False

    compensation_credit_value = payload.get("compensation_credit_value", 1.0)
    if not isinstance(compensation_credit_value, (int, float)) or compensation_credit_value < 0:
        return False

    # Fallback behavior validation
    fallback_if_rejected = payload.get("fallback_if_rejected", "will_handle_self")
    if fallback_if_rejected not in VALID_FALLBACK_BEHAVIORS:
        return False

    fallback_if_timeout = payload.get("fallback_if_timeout", "will_handle_self")
    if fallback_if_timeout not in VALID_FALLBACK_BEHAVIORS:
        return False

    # Attestation validation
    attestation = payload.get("attestation")
    if not validate_attestation(attestation):
        return False

    return True


def validate_ai_task_response_payload(payload: Dict[str, Any]) -> bool:
    """
    Validate an AI_TASK_RESPONSE payload.

    Args:
        payload: AI_TASK_RESPONSE message payload

    Returns:
        True if valid, False otherwise
    """
    import time as time_module

    if not isinstance(payload, dict):
        return False

    # Required fields
    node_id = payload.get("node_id")
    timestamp = payload.get("timestamp")
    request_id = payload.get("request_id")
    signature = payload.get("signature")
    response = payload.get("response")

    # Node ID must be valid pubkey
    if not _valid_pubkey(node_id):
        return False

    # Timestamp validation and freshness check
    if not isinstance(timestamp, int) or timestamp < 0:
        return False
    if abs(time_module.time() - timestamp) > AI_MESSAGE_MAX_AGE_SECONDS:
        return False

    # Request ID validation
    if not isinstance(request_id, str) or not request_id or len(request_id) > MAX_REQUEST_ID_LEN_AI:
        return False

    # Signature must be present
    if not isinstance(signature, str) or len(signature) < 10:
        return False

    # Response type validation
    if response not in VALID_TASK_RESPONSES:
        return False

    # Timestamp bounds
    estimated_completion = payload.get("estimated_completion_timestamp", 0)
    if not isinstance(estimated_completion, int) or estimated_completion < 0:
        return False

    defer_until = payload.get("defer_until_timestamp", 0)
    if not isinstance(defer_until, int) or defer_until < 0:
        return False

    # Amount bounds
    actual_amount = payload.get("actual_amount_sats", 0)
    if not isinstance(actual_amount, int) or actual_amount < 0 or actual_amount > MAX_TASK_AMOUNT_SATS:
        return False

    actual_max_fee = payload.get("actual_max_fee_sats", 0)
    if not isinstance(actual_max_fee, int) or actual_max_fee < 0 or actual_max_fee > MAX_TASK_FEE_SATS:
        return False

    estimated_fee = payload.get("estimated_fee_sats", 0)
    if not isinstance(estimated_fee, int) or estimated_fee < 0 or estimated_fee > MAX_TASK_FEE_SATS:
        return False

    # Conditions validation
    conditions = payload.get("conditions", [])
    if not isinstance(conditions, list) or len(conditions) > MAX_TASK_CONDITIONS:
        return False

    # Rejection reason validation
    rejection_reason = payload.get("rejection_reason", "")
    if rejection_reason and rejection_reason not in VALID_REJECTION_REASONS:
        return False

    # Response factors validation
    response_factors = payload.get("response_factors", [])
    if not isinstance(response_factors, list) or len(response_factors) > MAX_RESPONSE_FACTORS:
        return False
    for factor in response_factors:
        if not isinstance(factor, str) or (factor and factor not in VALID_RESPONSE_FACTORS):
            return False

    # Attestation validation
    attestation = payload.get("attestation")
    if not validate_attestation(attestation):
        return False

    return True


def validate_ai_task_complete_payload(payload: Dict[str, Any]) -> bool:
    """
    Validate an AI_TASK_COMPLETE payload.

    Args:
        payload: AI_TASK_COMPLETE message payload

    Returns:
        True if valid, False otherwise
    """
    import time as time_module

    if not isinstance(payload, dict):
        return False

    # Required fields
    node_id = payload.get("node_id")
    timestamp = payload.get("timestamp")
    request_id = payload.get("request_id")
    signature = payload.get("signature")
    status = payload.get("status")

    # Node ID must be valid pubkey
    if not _valid_pubkey(node_id):
        return False

    # Timestamp validation and freshness check
    if not isinstance(timestamp, int) or timestamp < 0:
        return False
    if abs(time_module.time() - timestamp) > AI_MESSAGE_MAX_AGE_SECONDS:
        return False

    # Request ID validation
    if not isinstance(request_id, str) or not request_id or len(request_id) > MAX_REQUEST_ID_LEN_AI:
        return False

    # Signature must be present
    if not isinstance(signature, str) or len(signature) < 10:
        return False

    # Status validation
    if status not in VALID_TASK_STATUS:
        return False

    # Task type validation (optional but if present must be valid)
    task_type = payload.get("task_type", "")
    if task_type and task_type not in VALID_AI_TASK_TYPES:
        return False

    # Numeric bounds
    capacity_sats = payload.get("capacity_sats", 0)
    if not isinstance(capacity_sats, int) or capacity_sats < 0 or capacity_sats > MAX_TASK_AMOUNT_SATS:
        return False

    actual_fee_sats = payload.get("actual_fee_sats", 0)
    if not isinstance(actual_fee_sats, int) or actual_fee_sats < 0 or actual_fee_sats > MAX_TASK_FEE_SATS:
        return False

    amount_rebalanced = payload.get("amount_rebalanced_sats", 0)
    if not isinstance(amount_rebalanced, int) or amount_rebalanced < 0 or amount_rebalanced > MAX_TASK_AMOUNT_SATS:
        return False

    new_fee_ppm = payload.get("new_fee_ppm", 0)
    if not isinstance(new_fee_ppm, int) or new_fee_ppm < 0 or new_fee_ppm > MAX_TASK_FEE_PPM:
        return False

    # Learnings validation
    target_responsiveness = payload.get("target_responsiveness", "")
    if target_responsiveness and target_responsiveness not in VALID_RESPONSIVENESS:
        return False

    connection_quality = payload.get("connection_quality", "")
    if connection_quality and connection_quality not in VALID_CONNECTION_QUALITY:
        return False

    observed_traits = payload.get("observed_traits", [])
    if not isinstance(observed_traits, list) or len(observed_traits) > MAX_OBSERVED_TRAITS:
        return False
    for trait in observed_traits:
        if not isinstance(trait, str) or (trait and trait not in VALID_OBSERVED_TRAITS):
            return False

    # Credit expiry validation
    credit_expires = payload.get("credit_expires_timestamp", 0)
    if not isinstance(credit_expires, int) or credit_expires < 0:
        return False

    # Attestation validation
    attestation = payload.get("attestation")
    if not validate_attestation(attestation):
        return False

    return True


def validate_ai_task_cancel_payload(payload: Dict[str, Any]) -> bool:
    """
    Validate an AI_TASK_CANCEL payload.

    Args:
        payload: AI_TASK_CANCEL message payload

    Returns:
        True if valid, False otherwise
    """
    import time as time_module

    if not isinstance(payload, dict):
        return False

    # Required fields
    node_id = payload.get("node_id")
    timestamp = payload.get("timestamp")
    request_id = payload.get("request_id")
    signature = payload.get("signature")
    reason = payload.get("reason")

    # Node ID must be valid pubkey
    if not _valid_pubkey(node_id):
        return False

    # Timestamp validation and freshness check
    if not isinstance(timestamp, int) or timestamp < 0:
        return False
    if abs(time_module.time() - timestamp) > AI_MESSAGE_MAX_AGE_SECONDS:
        return False

    # Request ID validation
    if not isinstance(request_id, str) or not request_id or len(request_id) > MAX_REQUEST_ID_LEN_AI:
        return False

    # Signature must be present
    if not isinstance(signature, str) or len(signature) < 10:
        return False

    # Reason validation
    if reason not in VALID_CANCEL_REASONS:
        return False

    # Attestation validation
    attestation = payload.get("attestation")
    if not validate_attestation(attestation):
        return False

    return True


# =============================================================================
# AI ORACLE PROTOCOL - STRATEGY COORDINATION VALIDATION (Phase 8.3)
# =============================================================================

def validate_ai_strategy_proposal_payload(payload: Dict[str, Any]) -> bool:
    """
    Validate an AI_STRATEGY_PROPOSAL payload.

    Args:
        payload: AI_STRATEGY_PROPOSAL message payload

    Returns:
        True if valid, False otherwise
    """
    import time as time_module

    if not isinstance(payload, dict):
        return False

    # Required fields
    node_id = payload.get("node_id")
    timestamp = payload.get("timestamp")
    proposal_id = payload.get("proposal_id")
    signature = payload.get("signature")
    strategy_type = payload.get("strategy_type")

    # Node ID must be valid pubkey
    if not _valid_pubkey(node_id):
        return False

    # Timestamp validation and freshness check
    if not isinstance(timestamp, int) or timestamp < 0:
        return False
    if abs(time_module.time() - timestamp) > AI_MESSAGE_MAX_AGE_SECONDS:
        return False

    # Proposal ID validation
    if not isinstance(proposal_id, str) or not proposal_id or len(proposal_id) > MAX_PROPOSAL_ID_LEN:
        return False

    # Signature must be present
    if not isinstance(signature, str) or len(signature) < 10:
        return False

    # Strategy type must be from allowed set
    if strategy_type not in VALID_STRATEGY_TYPES:
        return False

    # Optional: strategy name
    strategy_name = payload.get("strategy_name", "")
    if not isinstance(strategy_name, str) or len(strategy_name) > MAX_STRATEGY_NAME_LEN:
        return False

    # Objectives must be from allowed set
    objectives = payload.get("objectives", [])
    if not isinstance(objectives, list) or len(objectives) > MAX_STRATEGY_OBJECTIVES:
        return False
    for obj in objectives:
        if obj not in VALID_STRATEGY_OBJECTIVES:
            return False

    # Target nodes validation
    target_nodes = payload.get("target_nodes", [])
    if not isinstance(target_nodes, list) or len(target_nodes) > MAX_TARGET_NODES:
        return False
    for node in target_nodes:
        if not _valid_pubkey(node):
            return False

    # Fee bounds validation
    fee_floor = payload.get("fee_floor_ppm", 0)
    fee_ceiling = payload.get("fee_ceiling_ppm", 0)
    if not isinstance(fee_floor, int) or fee_floor < 0 or fee_floor > MAX_FEE_PPM:
        return False
    if not isinstance(fee_ceiling, int) or fee_ceiling < 0 or fee_ceiling > MAX_FEE_PPM:
        return False
    if fee_ceiling > 0 and fee_floor > fee_ceiling:
        return False

    # Duration validation
    duration_hours = payload.get("duration_hours", 0)
    if not isinstance(duration_hours, int) or duration_hours < 0 or duration_hours > MAX_DURATION_HOURS:
        return False

    ramp_up_hours = payload.get("ramp_up_hours", 0)
    if not isinstance(ramp_up_hours, int) or ramp_up_hours < 0 or ramp_up_hours > MAX_RAMP_UP_HOURS:
        return False

    # Expected outcomes validation (percentages)
    for field in ["expected_revenue_change_pct", "expected_volume_change_pct", "expected_net_benefit_pct"]:
        value = payload.get(field, 0.0)
        if not isinstance(value, (int, float)):
            return False

    outcome_confidence = payload.get("outcome_confidence", 0.5)
    if not isinstance(outcome_confidence, (int, float)) or outcome_confidence < 0.0 or outcome_confidence > 1.0:
        return False

    # Risks validation
    risks = payload.get("risks", [])
    if not isinstance(risks, list) or len(risks) > MAX_RISKS:
        return False

    # Opt-out penalty validation
    opt_out_penalty = payload.get("opt_out_penalty", "none")
    if opt_out_penalty not in VALID_OPT_OUT_PENALTIES:
        return False

    # Voting parameters validation
    approval_threshold = payload.get("approval_threshold_pct", 51.0)
    if not isinstance(approval_threshold, (int, float)) or approval_threshold < 0 or approval_threshold > 100:
        return False

    min_participation = payload.get("min_participation_pct", 60.0)
    if not isinstance(min_participation, (int, float)) or min_participation < 0 or min_participation > 100:
        return False

    voting_deadline = payload.get("voting_deadline_timestamp", 0)
    if not isinstance(voting_deadline, int) or voting_deadline < 0:
        return False

    execution_delay = payload.get("execution_delay_hours", 24)
    if not isinstance(execution_delay, int) or execution_delay < 0 or execution_delay > MAX_EXECUTION_DELAY_HOURS:
        return False

    vote_weight = payload.get("vote_weight", "equal")
    if vote_weight not in VALID_VOTE_WEIGHTS:
        return False

    # Proposer commitment validation
    proposer_capacity = payload.get("proposer_capacity_committed_sats", 0)
    if not isinstance(proposer_capacity, int) or proposer_capacity < 0:
        return False

    # Attestation validation
    attestation = payload.get("attestation")
    if not validate_attestation(attestation):
        return False

    return True


def validate_ai_strategy_vote_payload(payload: Dict[str, Any]) -> bool:
    """
    Validate an AI_STRATEGY_VOTE payload.

    Args:
        payload: AI_STRATEGY_VOTE message payload

    Returns:
        True if valid, False otherwise
    """
    import time as time_module

    if not isinstance(payload, dict):
        return False

    # Required fields
    node_id = payload.get("node_id")
    timestamp = payload.get("timestamp")
    proposal_id = payload.get("proposal_id")
    signature = payload.get("signature")
    vote = payload.get("vote")

    # Node ID must be valid pubkey
    if not _valid_pubkey(node_id):
        return False

    # Timestamp validation and freshness check
    if not isinstance(timestamp, int) or timestamp < 0:
        return False
    if abs(time_module.time() - timestamp) > AI_MESSAGE_MAX_AGE_SECONDS:
        return False

    # Proposal ID validation
    if not isinstance(proposal_id, str) or not proposal_id or len(proposal_id) > MAX_PROPOSAL_ID_LEN:
        return False

    # Signature must be present
    if not isinstance(signature, str) or len(signature) < 10:
        return False

    # Vote must be from allowed set
    if vote not in VALID_VOTE_OPTIONS:
        return False

    # Vote hash validation (for verifiability)
    vote_hash = payload.get("vote_hash", "")
    if not isinstance(vote_hash, str) or len(vote_hash) > MAX_VOTE_HASH_LEN:
        return False

    # Nonce validation
    nonce = payload.get("nonce", "")
    if not isinstance(nonce, str) or len(nonce) > MAX_NONCE_LEN:
        return False

    # Rationale factors must be from allowed set
    rationale_factors = payload.get("rationale_factors", [])
    if not isinstance(rationale_factors, list) or len(rationale_factors) > len(VALID_STRATEGY_RATIONALE_FACTORS):
        return False
    for factor in rationale_factors:
        if factor not in VALID_STRATEGY_RATIONALE_FACTORS:
            return False

    # Confidence validation
    confidence = payload.get("confidence_in_proposal", 0.5)
    if not isinstance(confidence, (int, float)) or confidence < 0.0 or confidence > 1.0:
        return False

    # Capacity commitment validation
    capacity_committed = payload.get("capacity_committed_sats", 0)
    if not isinstance(capacity_committed, int) or capacity_committed < 0:
        return False

    # Conditions validation
    conditions = payload.get("conditions", [])
    if not isinstance(conditions, list) or len(conditions) > MAX_STRATEGY_CONDITIONS:
        return False

    # Amendments validation
    amendments = payload.get("amendments", [])
    if not isinstance(amendments, list) or len(amendments) > MAX_AMENDMENTS:
        return False

    # Attestation validation
    attestation = payload.get("attestation")
    if not validate_attestation(attestation):
        return False

    return True


def validate_ai_strategy_result_payload(payload: Dict[str, Any]) -> bool:
    """
    Validate an AI_STRATEGY_RESULT payload.

    Args:
        payload: AI_STRATEGY_RESULT message payload

    Returns:
        True if valid, False otherwise
    """
    import time as time_module

    if not isinstance(payload, dict):
        return False

    # Required fields
    node_id = payload.get("node_id")
    timestamp = payload.get("timestamp")
    proposal_id = payload.get("proposal_id")
    signature = payload.get("signature")
    result = payload.get("result")

    # Node ID must be valid pubkey
    if not _valid_pubkey(node_id):
        return False

    # Timestamp validation and freshness check
    if not isinstance(timestamp, int) or timestamp < 0:
        return False
    if abs(time_module.time() - timestamp) > AI_MESSAGE_MAX_AGE_SECONDS:
        return False

    # Proposal ID validation
    if not isinstance(proposal_id, str) or not proposal_id or len(proposal_id) > MAX_PROPOSAL_ID_LEN:
        return False

    # Signature must be present
    if not isinstance(signature, str) or len(signature) < 10:
        return False

    # Result must be from allowed set
    if result not in VALID_STRATEGY_RESULTS:
        return False

    # Vote counts validation
    votes_for = payload.get("votes_for", 0)
    votes_against = payload.get("votes_against", 0)
    abstentions = payload.get("abstentions", 0)
    eligible_voters = payload.get("eligible_voters", 0)

    for count in [votes_for, votes_against, abstentions, eligible_voters]:
        if not isinstance(count, int) or count < 0 or count > MAX_PARTICIPANTS:
            return False

    # Percentage validations
    approval_pct = payload.get("approval_pct", 0.0)
    participation_pct = payload.get("participation_pct", 0.0)
    for pct in [approval_pct, participation_pct]:
        if not isinstance(pct, (int, float)) or pct < 0 or pct > 100:
            return False

    # Vote proofs validation (bounded list)
    vote_proofs = payload.get("vote_proofs", [])
    if not isinstance(vote_proofs, list) or len(vote_proofs) > MAX_VOTE_PROOFS:
        return False

    # Participants validation
    participants = payload.get("participants", [])
    if not isinstance(participants, list) or len(participants) > MAX_PARTICIPANTS:
        return False
    for node in participants:
        if not _valid_pubkey(node):
            return False

    # Opt-outs validation
    opt_outs = payload.get("opt_outs", [])
    if not isinstance(opt_outs, list) or len(opt_outs) > MAX_PARTICIPANTS:
        return False
    for node in opt_outs:
        if not _valid_pubkey(node):
            return False

    # Amendments incorporated validation
    amendments = payload.get("amendments_incorporated", [])
    if not isinstance(amendments, list) or len(amendments) > MAX_AMENDMENTS:
        return False

    # Attestation validation
    attestation = payload.get("attestation")
    if not validate_attestation(attestation):
        return False

    return True


def validate_ai_strategy_update_payload(payload: Dict[str, Any]) -> bool:
    """
    Validate an AI_STRATEGY_UPDATE payload.

    Args:
        payload: AI_STRATEGY_UPDATE message payload

    Returns:
        True if valid, False otherwise
    """
    import time as time_module

    if not isinstance(payload, dict):
        return False

    # Required fields
    node_id = payload.get("node_id")
    timestamp = payload.get("timestamp")
    proposal_id = payload.get("proposal_id")
    signature = payload.get("signature")
    phase = payload.get("phase")

    # Node ID must be valid pubkey
    if not _valid_pubkey(node_id):
        return False

    # Timestamp validation and freshness check
    if not isinstance(timestamp, int) or timestamp < 0:
        return False
    if abs(time_module.time() - timestamp) > AI_MESSAGE_MAX_AGE_SECONDS:
        return False

    # Proposal ID validation
    if not isinstance(proposal_id, str) or not proposal_id or len(proposal_id) > MAX_PROPOSAL_ID_LEN:
        return False

    # Signature must be present
    if not isinstance(signature, str) or len(signature) < 10:
        return False

    # Phase must be from allowed set
    if phase not in VALID_STRATEGY_PHASES:
        return False

    # Hours validation
    hours_elapsed = payload.get("hours_elapsed", 0)
    hours_remaining = payload.get("hours_remaining", 0)
    for hours in [hours_elapsed, hours_remaining]:
        if not isinstance(hours, int) or hours < 0 or hours > MAX_DURATION_HOURS:
            return False

    # Completion percentage validation
    completion_pct = payload.get("completion_pct", 0.0)
    if not isinstance(completion_pct, (int, float)) or completion_pct < 0 or completion_pct > 100:
        return False

    # Metric validations (percentages can be negative for decreases)
    for field in ["revenue_change_pct", "volume_change_pct"]:
        value = payload.get(field, 0.0)
        if not isinstance(value, (int, float)):
            return False

    compliance_pct = payload.get("participant_compliance_pct", 100.0)
    if not isinstance(compliance_pct, (int, float)) or compliance_pct < 0 or compliance_pct > 100:
        return False

    # Participant status validation
    participant_status = payload.get("participant_status", [])
    if not isinstance(participant_status, list) or len(participant_status) > MAX_PARTICIPANT_STATUS:
        return False

    # Issues validation (must be from allowed set)
    issues = payload.get("issues", [])
    if not isinstance(issues, list) or len(issues) > MAX_STRATEGY_ISSUES:
        return False
    for issue in issues:
        if issue not in VALID_STRATEGY_ISSUES:
            return False

    # Recommendation must be from allowed set
    recommendation = payload.get("recommendation", "continue")
    if recommendation not in VALID_STRATEGY_RECOMMENDATIONS:
        return False

    # Attestation validation
    attestation = payload.get("attestation")
    if not validate_attestation(attestation):
        return False

    return True


# =============================================================================
# AI ORACLE PROTOCOL - REASONING & MARKET VALIDATION (Phase 8.4)
# =============================================================================

def validate_ai_reasoning_request_payload(payload: Dict[str, Any]) -> bool:
    """
    Validate an AI_REASONING_REQUEST payload.

    Args:
        payload: AI_REASONING_REQUEST message payload

    Returns:
        True if valid, False otherwise
    """
    import time as time_module

    if not isinstance(payload, dict):
        return False

    # Required fields
    node_id = payload.get("node_id")
    target_node = payload.get("target_node")
    timestamp = payload.get("timestamp")
    request_id = payload.get("request_id")
    signature = payload.get("signature")
    reference_type = payload.get("reference_type")

    # Node IDs must be valid pubkeys
    if not _valid_pubkey(node_id):
        return False
    if not _valid_pubkey(target_node):
        return False

    # Timestamp validation and freshness check
    if not isinstance(timestamp, int) or timestamp < 0:
        return False
    if abs(time_module.time() - timestamp) > AI_MESSAGE_MAX_AGE_SECONDS:
        return False

    # Request ID validation
    if not isinstance(request_id, str) or not request_id or len(request_id) > MAX_REASONING_REQUEST_ID_LEN:
        return False

    # Signature must be present
    if not isinstance(signature, str) or len(signature) < 10:
        return False

    # Reference type must be from allowed set
    if reference_type not in VALID_REASONING_REFERENCE_TYPES:
        return False

    # Reference ID validation
    reference_id = payload.get("reference_id", "")
    if not isinstance(reference_id, str) or len(reference_id) > MAX_REFERENCE_ID_LEN:
        return False

    # Question type must be from allowed set
    question_type = payload.get("question_type", "full_reasoning")
    if question_type not in VALID_REASONING_QUESTION_TYPES:
        return False

    # Detail level must be from allowed set
    detail_level = payload.get("detail_level", "summary")
    if detail_level not in VALID_REASONING_DETAIL_LEVELS:
        return False

    # Attestation validation
    attestation = payload.get("attestation")
    if not validate_attestation(attestation):
        return False

    return True


def validate_ai_reasoning_response_payload(payload: Dict[str, Any]) -> bool:
    """
    Validate an AI_REASONING_RESPONSE payload.

    Args:
        payload: AI_REASONING_RESPONSE message payload

    Returns:
        True if valid, False otherwise
    """
    import time as time_module

    if not isinstance(payload, dict):
        return False

    # Required fields
    node_id = payload.get("node_id")
    timestamp = payload.get("timestamp")
    request_id = payload.get("request_id")
    signature = payload.get("signature")

    # Node ID must be valid pubkey
    if not _valid_pubkey(node_id):
        return False

    # Timestamp validation and freshness check
    if not isinstance(timestamp, int) or timestamp < 0:
        return False
    if abs(time_module.time() - timestamp) > AI_MESSAGE_MAX_AGE_SECONDS:
        return False

    # Request ID validation
    if not isinstance(request_id, str) or not request_id or len(request_id) > MAX_REASONING_REQUEST_ID_LEN:
        return False

    # Signature must be present
    if not isinstance(signature, str) or len(signature) < 10:
        return False

    # Conclusion must be from allowed set (or empty)
    conclusion = payload.get("conclusion", "")
    if conclusion and conclusion not in VALID_REASONING_CONCLUSIONS:
        return False

    # Decision factors validation
    decision_factors = payload.get("decision_factors", [])
    if not isinstance(decision_factors, list) or len(decision_factors) > MAX_DECISION_FACTORS:
        return False
    for factor in decision_factors:
        if not isinstance(factor, dict):
            return False
        # Validate factor type if present
        factor_type = factor.get("factor_type")
        if factor_type and factor_type not in VALID_DECISION_FACTOR_TYPES:
            return False
        # Validate assessment if present
        assessment = factor.get("assessment")
        if assessment and assessment not in VALID_FACTOR_ASSESSMENTS:
            return False

    # Overall confidence validation
    overall_confidence = payload.get("overall_confidence", 0.5)
    if not isinstance(overall_confidence, (int, float)) or overall_confidence < 0.0 or overall_confidence > 1.0:
        return False

    # Data sources validation
    data_sources = payload.get("data_sources", [])
    if not isinstance(data_sources, list) or len(data_sources) > MAX_DATA_SOURCES:
        return False
    for source in data_sources:
        if source not in VALID_DATA_SOURCES:
            return False

    # Alternative recommendation validation
    alt_strategy_type = payload.get("alternative_strategy_type", "")
    if alt_strategy_type and alt_strategy_type not in VALID_STRATEGY_TYPES:
        return False

    alt_risk_level = payload.get("alternative_risk_level", "")
    if alt_risk_level and alt_risk_level not in VALID_ALTERNATIVE_RISK_LEVELS:
        return False

    # Meta validation
    reasoning_time_ms = payload.get("reasoning_time_ms", 0)
    if not isinstance(reasoning_time_ms, int) or reasoning_time_ms < 0 or reasoning_time_ms > MAX_REASONING_TIME_MS:
        return False

    tokens_used = payload.get("tokens_used", 0)
    if not isinstance(tokens_used, int) or tokens_used < 0 or tokens_used > MAX_TOKENS_USED:
        return False

    # Attestation validation
    attestation = payload.get("attestation")
    if not validate_attestation(attestation):
        return False

    return True


def validate_ai_market_assessment_payload(payload: Dict[str, Any]) -> bool:
    """
    Validate an AI_MARKET_ASSESSMENT payload.

    Args:
        payload: AI_MARKET_ASSESSMENT message payload

    Returns:
        True if valid, False otherwise
    """
    import time as time_module

    if not isinstance(payload, dict):
        return False

    # Required fields
    node_id = payload.get("node_id")
    timestamp = payload.get("timestamp")
    assessment_id = payload.get("assessment_id")
    signature = payload.get("signature")
    assessment_type = payload.get("assessment_type")

    # Node ID must be valid pubkey
    if not _valid_pubkey(node_id):
        return False

    # Timestamp validation and freshness check
    if not isinstance(timestamp, int) or timestamp < 0:
        return False
    if abs(time_module.time() - timestamp) > AI_MESSAGE_MAX_AGE_SECONDS:
        return False

    # Assessment ID validation
    if not isinstance(assessment_id, str) or not assessment_id or len(assessment_id) > MAX_ASSESSMENT_ID_LEN:
        return False

    # Signature must be present
    if not isinstance(signature, str) or len(signature) < 10:
        return False

    # Assessment type must be from allowed set
    if assessment_type not in VALID_MARKET_ASSESSMENT_TYPES:
        return False

    # Time horizon must be from allowed set
    time_horizon = payload.get("time_horizon", "short_term")
    if time_horizon not in VALID_TIME_HORIZONS:
        return False

    # Market data validation
    avg_network_fee = payload.get("avg_network_fee_ppm", 0)
    if not isinstance(avg_network_fee, int) or avg_network_fee < 0 or avg_network_fee > MAX_FEE_PPM:
        return False

    fee_change = payload.get("fee_change_24h_pct", 0.0)
    if not isinstance(fee_change, (int, float)):
        return False

    # Mempool tiers validation
    mempool_depth_tier = payload.get("mempool_depth_tier", "normal")
    if mempool_depth_tier not in VALID_MEMPOOL_DEPTH_TIERS:
        return False

    mempool_fee_rate_tier = payload.get("mempool_fee_rate_tier", "normal")
    if mempool_fee_rate_tier not in VALID_MEMPOOL_FEE_RATE_TIERS:
        return False

    block_fullness_tier = payload.get("block_fullness_tier", "normal")
    if block_fullness_tier not in VALID_BLOCK_FULLNESS_TIERS:
        return False

    # Corridor analysis validation
    corridor_analysis = payload.get("corridor_analysis", [])
    if not isinstance(corridor_analysis, list) or len(corridor_analysis) > MAX_CORRIDOR_ANALYSIS:
        return False
    for corridor in corridor_analysis:
        if not isinstance(corridor, dict):
            return False
        # Validate corridor name
        corridor_name = corridor.get("corridor", "")
        if not isinstance(corridor_name, str) or len(corridor_name) > MAX_CORRIDOR_NAME_LEN:
            return False
        # Validate volume trend
        volume_trend = corridor.get("volume_trend")
        if volume_trend and volume_trend not in VALID_VOLUME_TRENDS:
            return False
        # Validate fee trend
        fee_trend = corridor.get("fee_trend")
        if fee_trend and fee_trend not in VALID_VOLUME_TRENDS:  # Same enum
            return False
        # Validate competition
        competition = corridor.get("competition")
        if competition and competition not in VALID_COMPETITION_LEVELS:
            return False
        # Validate hive position
        hive_position = corridor.get("hive_position")
        if hive_position and hive_position not in VALID_CORRIDOR_POSITIONS:
            return False

    # Recommendation validation
    overall_stance = payload.get("overall_stance", "neutral")
    if overall_stance not in VALID_MARKET_STANCES:
        return False

    fee_direction = payload.get("fee_direction", "hold")
    if fee_direction not in VALID_FEE_DIRECTIONS:
        return False

    expansion_timing = payload.get("expansion_timing", "neutral")
    if expansion_timing not in VALID_EXPANSION_TIMING:
        return False

    rebalance_urgency = payload.get("rebalance_urgency", "normal")
    if rebalance_urgency not in VALID_URGENCY_LEVELS:
        return False

    # Confidence validation
    confidence = payload.get("confidence", 0.5)
    if not isinstance(confidence, (int, float)) or confidence < 0.0 or confidence > 1.0:
        return False

    # Data freshness validation
    data_freshness = payload.get("data_freshness_seconds", 0)
    if not isinstance(data_freshness, int) or data_freshness < 0 or data_freshness > MAX_DATA_FRESHNESS_SECONDS:
        return False

    # Attestation validation
    attestation = payload.get("attestation")
    if not validate_attestation(attestation):
        return False

    return True


# =============================================================================
# AI ORACLE PROTOCOL - SIGNING PAYLOAD FUNCTIONS (Phase 8)
# =============================================================================

def get_ai_state_summary_signing_payload(payload: Dict[str, Any]) -> str:
    """
    Get the canonical string for signing AI_STATE_SUMMARY messages.

    The signature covers identity, timing, and core state fields.

    Args:
        payload: AI_STATE_SUMMARY message payload

    Returns:
        Canonical string for signmessage()
    """
    signing_fields = {
        "node_id": payload.get("node_id", ""),
        "timestamp": payload.get("timestamp", 0),
        "sequence": payload.get("sequence", 0),
        "liquidity_status": payload.get("liquidity_status", ""),
        "capacity_tier": payload.get("capacity_tier", ""),
        "current_focus": payload.get("current_focus", ""),
        "ai_confidence": payload.get("ai_confidence", 0.5),
    }
    return json.dumps(signing_fields, sort_keys=True, separators=(',', ':'))


def get_ai_heartbeat_signing_payload(payload: Dict[str, Any]) -> str:
    """
    Get the canonical string for signing AI_HEARTBEAT messages.

    Args:
        payload: AI_HEARTBEAT message payload

    Returns:
        Canonical string for signmessage()
    """
    signing_fields = {
        "node_id": payload.get("node_id", ""),
        "timestamp": payload.get("timestamp", 0),
        "sequence": payload.get("sequence", 0),
        "operational_state": payload.get("operational_state", ""),
        "model_claimed": payload.get("model_claimed", ""),
        "decisions_24h": payload.get("decisions_24h", 0),
    }
    return json.dumps(signing_fields, sort_keys=True, separators=(',', ':'))


def get_ai_opportunity_signal_signing_payload(payload: Dict[str, Any]) -> str:
    """
    Get the canonical string for signing AI_OPPORTUNITY_SIGNAL messages.

    Args:
        payload: AI_OPPORTUNITY_SIGNAL message payload

    Returns:
        Canonical string for signmessage()
    """
    signing_fields = {
        "node_id": payload.get("node_id", ""),
        "timestamp": payload.get("timestamp", 0),
        "signal_id": payload.get("signal_id", ""),
        "target_node": payload.get("target_node", ""),
        "opportunity_type": payload.get("opportunity_type", ""),
        "recommended_action": payload.get("recommended_action", ""),
        "urgency": payload.get("urgency", ""),
        "confidence": payload.get("confidence", 0.5),
    }
    return json.dumps(signing_fields, sort_keys=True, separators=(',', ':'))


def get_ai_alert_signing_payload(payload: Dict[str, Any]) -> str:
    """
    Get the canonical string for signing AI_ALERT messages.

    Args:
        payload: AI_ALERT message payload

    Returns:
        Canonical string for signmessage()
    """
    signing_fields = {
        "node_id": payload.get("node_id", ""),
        "timestamp": payload.get("timestamp", 0),
        "alert_id": payload.get("alert_id", ""),
        "severity": payload.get("severity", ""),
        "category": payload.get("category", ""),
        "alert_type": payload.get("alert_type", ""),
        "immediate_risk": payload.get("immediate_risk", "low"),
        "affected_hive_members": payload.get("affected_hive_members", 0),
    }
    return json.dumps(signing_fields, sort_keys=True, separators=(',', ':'))


# =============================================================================
# AI ORACLE PROTOCOL - TASK COORDINATION SIGNING FUNCTIONS (Phase 8.2)
# =============================================================================

def get_ai_task_request_signing_payload(payload: Dict[str, Any]) -> str:
    """
    Get the canonical string for signing AI_TASK_REQUEST messages.

    Args:
        payload: AI_TASK_REQUEST message payload

    Returns:
        Canonical string for signmessage()
    """
    signing_fields = {
        "node_id": payload.get("node_id", ""),
        "target_node": payload.get("target_node", ""),
        "timestamp": payload.get("timestamp", 0),
        "request_id": payload.get("request_id", ""),
        "task_type": payload.get("task_type", ""),
        "task_target": payload.get("task_target", ""),
        "amount_sats": payload.get("amount_sats", 0),
        "task_priority": payload.get("task_priority", "normal"),
    }
    return json.dumps(signing_fields, sort_keys=True, separators=(',', ':'))


def get_ai_task_response_signing_payload(payload: Dict[str, Any]) -> str:
    """
    Get the canonical string for signing AI_TASK_RESPONSE messages.

    Args:
        payload: AI_TASK_RESPONSE message payload

    Returns:
        Canonical string for signmessage()
    """
    signing_fields = {
        "node_id": payload.get("node_id", ""),
        "timestamp": payload.get("timestamp", 0),
        "request_id": payload.get("request_id", ""),
        "response": payload.get("response", ""),
        "estimated_completion_timestamp": payload.get("estimated_completion_timestamp", 0),
        "estimated_fee_sats": payload.get("estimated_fee_sats", 0),
    }
    return json.dumps(signing_fields, sort_keys=True, separators=(',', ':'))


def get_ai_task_complete_signing_payload(payload: Dict[str, Any]) -> str:
    """
    Get the canonical string for signing AI_TASK_COMPLETE messages.

    Args:
        payload: AI_TASK_COMPLETE message payload

    Returns:
        Canonical string for signmessage()
    """
    signing_fields = {
        "node_id": payload.get("node_id", ""),
        "timestamp": payload.get("timestamp", 0),
        "request_id": payload.get("request_id", ""),
        "status": payload.get("status", ""),
        "task_type": payload.get("task_type", ""),
        "actual_fee_sats": payload.get("actual_fee_sats", 0),
        "reciprocal_credit_earned": payload.get("reciprocal_credit_earned", False),
    }
    return json.dumps(signing_fields, sort_keys=True, separators=(',', ':'))


def get_ai_task_cancel_signing_payload(payload: Dict[str, Any]) -> str:
    """
    Get the canonical string for signing AI_TASK_CANCEL messages.

    Args:
        payload: AI_TASK_CANCEL message payload

    Returns:
        Canonical string for signmessage()
    """
    signing_fields = {
        "node_id": payload.get("node_id", ""),
        "timestamp": payload.get("timestamp", 0),
        "request_id": payload.get("request_id", ""),
        "reason": payload.get("reason", ""),
    }
    return json.dumps(signing_fields, sort_keys=True, separators=(',', ':'))


# =============================================================================
# AI ORACLE PROTOCOL - STRATEGY COORDINATION SIGNING FUNCTIONS (Phase 8.3)
# =============================================================================

def get_ai_strategy_proposal_signing_payload(payload: Dict[str, Any]) -> str:
    """
    Get the canonical string for signing AI_STRATEGY_PROPOSAL messages.

    Signature covers identity, timing, strategy definition, and voting parameters.

    Args:
        payload: AI_STRATEGY_PROPOSAL message payload

    Returns:
        Canonical string for signmessage()
    """
    signing_fields = {
        "node_id": payload.get("node_id", ""),
        "timestamp": payload.get("timestamp", 0),
        "proposal_id": payload.get("proposal_id", ""),
        "strategy_type": payload.get("strategy_type", ""),
        "objectives": payload.get("objectives", []),
        "fee_floor_ppm": payload.get("fee_floor_ppm", 0),
        "fee_ceiling_ppm": payload.get("fee_ceiling_ppm", 0),
        "duration_hours": payload.get("duration_hours", 0),
        "approval_threshold_pct": payload.get("approval_threshold_pct", 51.0),
        "voting_deadline_timestamp": payload.get("voting_deadline_timestamp", 0),
    }
    return json.dumps(signing_fields, sort_keys=True, separators=(',', ':'))


def get_ai_strategy_vote_signing_payload(payload: Dict[str, Any]) -> str:
    """
    Get the canonical string for signing AI_STRATEGY_VOTE messages.

    Signature covers identity, timing, vote decision, and commitment.

    Args:
        payload: AI_STRATEGY_VOTE message payload

    Returns:
        Canonical string for signmessage()
    """
    signing_fields = {
        "node_id": payload.get("node_id", ""),
        "timestamp": payload.get("timestamp", 0),
        "proposal_id": payload.get("proposal_id", ""),
        "vote": payload.get("vote", ""),
        "vote_hash": payload.get("vote_hash", ""),
        "will_participate": payload.get("will_participate", False),
        "capacity_committed_sats": payload.get("capacity_committed_sats", 0),
    }
    return json.dumps(signing_fields, sort_keys=True, separators=(',', ':'))


def get_ai_strategy_result_signing_payload(payload: Dict[str, Any]) -> str:
    """
    Get the canonical string for signing AI_STRATEGY_RESULT messages.

    Signature covers identity, timing, result, and vote summary.

    Args:
        payload: AI_STRATEGY_RESULT message payload

    Returns:
        Canonical string for signmessage()
    """
    signing_fields = {
        "node_id": payload.get("node_id", ""),
        "timestamp": payload.get("timestamp", 0),
        "proposal_id": payload.get("proposal_id", ""),
        "result": payload.get("result", ""),
        "votes_for": payload.get("votes_for", 0),
        "votes_against": payload.get("votes_against", 0),
        "quorum_met": payload.get("quorum_met", False),
        "approval_pct": payload.get("approval_pct", 0.0),
    }
    return json.dumps(signing_fields, sort_keys=True, separators=(',', ':'))


def get_ai_strategy_update_signing_payload(payload: Dict[str, Any]) -> str:
    """
    Get the canonical string for signing AI_STRATEGY_UPDATE messages.

    Signature covers identity, timing, phase, progress, and recommendation.

    Args:
        payload: AI_STRATEGY_UPDATE message payload

    Returns:
        Canonical string for signmessage()
    """
    signing_fields = {
        "node_id": payload.get("node_id", ""),
        "timestamp": payload.get("timestamp", 0),
        "proposal_id": payload.get("proposal_id", ""),
        "phase": payload.get("phase", ""),
        "completion_pct": payload.get("completion_pct", 0.0),
        "on_track": payload.get("on_track", True),
        "recommendation": payload.get("recommendation", "continue"),
    }
    return json.dumps(signing_fields, sort_keys=True, separators=(',', ':'))


# =============================================================================
# AI ORACLE PROTOCOL - REASONING & MARKET SIGNING FUNCTIONS (Phase 8.4)
# =============================================================================

def get_ai_reasoning_request_signing_payload(payload: Dict[str, Any]) -> str:
    """
    Get the canonical string for signing AI_REASONING_REQUEST messages.

    Signature covers identity, timing, target, and request context.

    Args:
        payload: AI_REASONING_REQUEST message payload

    Returns:
        Canonical string for signmessage()
    """
    signing_fields = {
        "node_id": payload.get("node_id", ""),
        "target_node": payload.get("target_node", ""),
        "timestamp": payload.get("timestamp", 0),
        "request_id": payload.get("request_id", ""),
        "reference_type": payload.get("reference_type", ""),
        "reference_id": payload.get("reference_id", ""),
        "detail_level": payload.get("detail_level", "summary"),
    }
    return json.dumps(signing_fields, sort_keys=True, separators=(',', ':'))


def get_ai_reasoning_response_signing_payload(payload: Dict[str, Any]) -> str:
    """
    Get the canonical string for signing AI_REASONING_RESPONSE messages.

    Signature covers identity, timing, conclusion, and confidence.

    Args:
        payload: AI_REASONING_RESPONSE message payload

    Returns:
        Canonical string for signmessage()
    """
    signing_fields = {
        "node_id": payload.get("node_id", ""),
        "timestamp": payload.get("timestamp", 0),
        "request_id": payload.get("request_id", ""),
        "conclusion": payload.get("conclusion", ""),
        "overall_confidence": payload.get("overall_confidence", 0.5),
        "reasoning_time_ms": payload.get("reasoning_time_ms", 0),
    }
    return json.dumps(signing_fields, sort_keys=True, separators=(',', ':'))


def get_ai_market_assessment_signing_payload(payload: Dict[str, Any]) -> str:
    """
    Get the canonical string for signing AI_MARKET_ASSESSMENT messages.

    Signature covers identity, timing, assessment type, and key recommendations.

    Args:
        payload: AI_MARKET_ASSESSMENT message payload

    Returns:
        Canonical string for signmessage()
    """
    signing_fields = {
        "node_id": payload.get("node_id", ""),
        "timestamp": payload.get("timestamp", 0),
        "assessment_id": payload.get("assessment_id", ""),
        "assessment_type": payload.get("assessment_type", ""),
        "overall_stance": payload.get("overall_stance", "neutral"),
        "fee_direction": payload.get("fee_direction", "hold"),
        "confidence": payload.get("confidence", 0.5),
    }
    return json.dumps(signing_fields, sort_keys=True, separators=(',', ':'))


# =============================================================================
# AI ORACLE PROTOCOL - CREATE HELPER FUNCTIONS (Phase 8)
# =============================================================================

def create_ai_state_summary(
    node_id: str,
    timestamp: int,
    sequence: int,
    rpc,
    liquidity_status: str = "healthy",
    capacity_tier: str = "medium",
    outbound_status: str = "adequate",
    inbound_status: str = "adequate",
    channel_count_tier: str = "medium",
    utilization_bucket: str = "moderate",
    current_focus: str = "maintenance",
    seeking_categories: List[str] = None,
    avoid_categories: List[str] = None,
    capacity_seeking: bool = False,
    budget_status: str = "available",
    can_open_channels: bool = True,
    can_accept_tasks: bool = True,
    expansion_capacity_tier: str = "medium",
    feerate_tolerance: str = "normal",
    ai_confidence: float = 0.5,
    decisions_last_24h: int = 0,
    strategy_alignment: str = "cooperative",
    attestation: Dict[str, Any] = None
) -> Optional[bytes]:
    """
    Create a signed AI_STATE_SUMMARY message.

    Args:
        node_id: Sender's node public key
        timestamp: Unix timestamp
        sequence: Monotonic sequence number
        rpc: RPC interface for signing
        liquidity_status: "healthy", "constrained", "critical"
        capacity_tier: "small", "medium", "large", "xlarge"
        outbound_status: "adequate", "low", "critical"
        inbound_status: "adequate", "low", "critical"
        channel_count_tier: "few", "medium", "many"
        utilization_bucket: "low", "moderate", "high", "critical"
        current_focus: "expansion", "consolidation", "maintenance", "defensive"
        seeking_categories: Categories being targeted
        avoid_categories: Categories to avoid
        capacity_seeking: Looking for capacity
        budget_status: "available", "limited", "exhausted"
        can_open_channels: Can open new channels
        can_accept_tasks: Can accept task delegations
        expansion_capacity_tier: "none", "small", "medium", "large"
        feerate_tolerance: "tight", "normal", "flexible"
        ai_confidence: AI confidence level (0-1)
        decisions_last_24h: Decisions made in last 24 hours
        strategy_alignment: "cooperative", "competitive", "neutral"
        attestation: Operator attestation object

    Returns:
        Serialized and signed AI_STATE_SUMMARY message, or None on error
    """
    payload = {
        "node_id": node_id,
        "timestamp": timestamp,
        "sequence": sequence,
        "liquidity_status": liquidity_status,
        "capacity_tier": capacity_tier,
        "outbound_status": outbound_status,
        "inbound_status": inbound_status,
        "channel_count_tier": channel_count_tier,
        "utilization_bucket": utilization_bucket,
        "current_focus": current_focus,
        "seeking_categories": seeking_categories or [],
        "avoid_categories": avoid_categories or [],
        "capacity_seeking": capacity_seeking,
        "budget_status": budget_status,
        "can_open_channels": can_open_channels,
        "can_accept_tasks": can_accept_tasks,
        "expansion_capacity_tier": expansion_capacity_tier,
        "feerate_tolerance": feerate_tolerance,
        "ai_confidence": ai_confidence,
        "decisions_last_24h": decisions_last_24h,
        "strategy_alignment": strategy_alignment,
    }

    if attestation:
        payload["attestation"] = attestation

    # Sign the payload
    signing_message = get_ai_state_summary_signing_payload(payload)
    try:
        sig_result = rpc.signmessage(signing_message)
        payload["signature"] = sig_result["zbase"]
    except Exception:
        return None

    return serialize(HiveMessageType.AI_STATE_SUMMARY, payload)


def create_ai_heartbeat(
    node_id: str,
    timestamp: int,
    sequence: int,
    rpc,
    operational_state: str = "active",
    model_claimed: str = "",
    model_version: str = "",
    uptime_seconds: int = 0,
    last_decision_timestamp: int = 0,
    decisions_24h: int = 0,
    decisions_pending: int = 0,
    api_latency_ms: int = 0,
    api_success_rate_pct: float = 100.0,
    memory_usage_pct: float = 0.0,
    error_rate_24h: float = 0.0,
    max_decisions_per_hour: int = 100,
    supported_task_types: List[str] = None,
    strategy_participation: bool = True,
    delegation_acceptance: bool = True,
    attestation: Dict[str, Any] = None
) -> Optional[bytes]:
    """
    Create a signed AI_HEARTBEAT message.

    Args:
        node_id: Sender's node public key
        timestamp: Unix timestamp
        sequence: Monotonic sequence number
        rpc: RPC interface for signing
        operational_state: "active", "degraded", "offline", "paused"
        model_claimed: Model identifier
        model_version: Version string
        uptime_seconds: How long AI has been running
        last_decision_timestamp: Last decision made
        decisions_24h: Decisions in last 24 hours
        decisions_pending: Pending decisions
        api_latency_ms: AI provider latency
        api_success_rate_pct: Success rate percentage
        memory_usage_pct: Memory usage percentage
        error_rate_24h: Error rate in last 24 hours
        max_decisions_per_hour: Max decisions per hour
        supported_task_types: Supported task types
        strategy_participation: Participates in strategies
        delegation_acceptance: Accepts task delegations
        attestation: Operator attestation object

    Returns:
        Serialized and signed AI_HEARTBEAT message, or None on error
    """
    payload = {
        "node_id": node_id,
        "timestamp": timestamp,
        "sequence": sequence,
        "operational_state": operational_state,
        "model_claimed": model_claimed,
        "model_version": model_version,
        "uptime_seconds": uptime_seconds,
        "last_decision_timestamp": last_decision_timestamp,
        "decisions_24h": decisions_24h,
        "decisions_pending": decisions_pending,
        "api_latency_ms": api_latency_ms,
        "api_success_rate_pct": api_success_rate_pct,
        "memory_usage_pct": memory_usage_pct,
        "error_rate_24h": error_rate_24h,
        "max_decisions_per_hour": max_decisions_per_hour,
        "supported_task_types": supported_task_types or [],
        "strategy_participation": strategy_participation,
        "delegation_acceptance": delegation_acceptance,
    }

    if attestation:
        payload["attestation"] = attestation

    # Sign the payload
    signing_message = get_ai_heartbeat_signing_payload(payload)
    try:
        sig_result = rpc.signmessage(signing_message)
        payload["signature"] = sig_result["zbase"]
    except Exception:
        return None

    return serialize(HiveMessageType.AI_HEARTBEAT, payload)


def create_ai_opportunity_signal(
    node_id: str,
    timestamp: int,
    signal_id: str,
    target_node: str,
    opportunity_type: str,
    rpc,
    target_alias: str = "",
    category: str = "",
    target_capacity_sats: int = 0,
    target_channel_count: int = 0,
    current_hive_share_pct: float = 0.0,
    optimal_hive_share_pct: float = 0.0,
    share_gap_pct: float = 0.0,
    estimated_daily_volume_sats: int = 0,
    avg_fee_rate_ppm: int = 0,
    recommended_action: str = "expand",
    urgency: str = "medium",
    suggested_capacity_sats: int = 0,
    estimated_roi_annual_pct: float = 0.0,
    confidence: float = 0.5,
    volunteer_willing: bool = False,
    volunteer_capacity_sats: int = 0,
    volunteer_position_score: float = 0.0,
    reasoning_factors: List[str] = None,
    attestation: Dict[str, Any] = None
) -> Optional[bytes]:
    """
    Create a signed AI_OPPORTUNITY_SIGNAL message.

    Args:
        node_id: Sender's node public key
        timestamp: Unix timestamp
        signal_id: Unique signal identifier
        target_node: Target node pubkey
        opportunity_type: Type of opportunity
        rpc: RPC interface for signing
        target_alias: Target node alias
        category: Node category
        target_capacity_sats: Target's total capacity
        target_channel_count: Target's channel count
        current_hive_share_pct: Current hive share percentage
        optimal_hive_share_pct: Optimal hive share percentage
        share_gap_pct: Gap between current and optimal
        estimated_daily_volume_sats: Estimated daily volume
        avg_fee_rate_ppm: Average fee rate
        recommended_action: "expand", "consolidate", "monitor"
        urgency: "low", "medium", "high", "critical"
        suggested_capacity_sats: Suggested channel capacity
        estimated_roi_annual_pct: Estimated annual ROI
        confidence: Confidence level (0-1)
        volunteer_willing: Willing to volunteer
        volunteer_capacity_sats: Available capacity for volunteering
        volunteer_position_score: Position score for volunteering
        reasoning_factors: List of reasoning factor enum values
        attestation: Operator attestation object

    Returns:
        Serialized and signed AI_OPPORTUNITY_SIGNAL message, or None on error
    """
    payload = {
        "node_id": node_id,
        "timestamp": timestamp,
        "signal_id": signal_id,
        "target_node": target_node,
        "opportunity_type": opportunity_type,
        "target_alias": target_alias,
        "category": category,
        "target_capacity_sats": target_capacity_sats,
        "target_channel_count": target_channel_count,
        "current_hive_share_pct": current_hive_share_pct,
        "optimal_hive_share_pct": optimal_hive_share_pct,
        "share_gap_pct": share_gap_pct,
        "estimated_daily_volume_sats": estimated_daily_volume_sats,
        "avg_fee_rate_ppm": avg_fee_rate_ppm,
        "recommended_action": recommended_action,
        "urgency": urgency,
        "suggested_capacity_sats": suggested_capacity_sats,
        "estimated_roi_annual_pct": estimated_roi_annual_pct,
        "confidence": confidence,
        "volunteer_willing": volunteer_willing,
        "volunteer_capacity_sats": volunteer_capacity_sats,
        "volunteer_position_score": volunteer_position_score,
        "reasoning_factors": reasoning_factors or [],
    }

    if attestation:
        payload["attestation"] = attestation

    # Sign the payload
    signing_message = get_ai_opportunity_signal_signing_payload(payload)
    try:
        sig_result = rpc.signmessage(signing_message)
        payload["signature"] = sig_result["zbase"]
    except Exception:
        return None

    return serialize(HiveMessageType.AI_OPPORTUNITY_SIGNAL, payload)


def create_ai_alert(
    node_id: str,
    timestamp: int,
    alert_id: str,
    severity: str,
    category: str,
    alert_type: str,
    rpc,
    source_node: str = "",
    affected_channels: List[str] = None,
    metric_name: str = "",
    metric_value: float = 0.0,
    threshold: float = 0.0,
    pattern: str = "",
    time_window_minutes: int = 0,
    immediate_risk: str = "low",
    potential_risk: str = "low",
    affected_hive_members: int = 0,
    recommended_action: str = "monitor",
    action_urgency: str = "normal",
    auto_response_taken: str = "none",
    auto_response_reason: str = "",
    attestation: Dict[str, Any] = None
) -> Optional[bytes]:
    """
    Create a signed AI_ALERT message.

    Args:
        node_id: Sender's node public key
        timestamp: Unix timestamp
        alert_id: Unique alert identifier
        severity: "info", "warning", "critical"
        category: "security", "performance", "opportunity", "system", "network"
        alert_type: Specific alert type
        rpc: RPC interface for signing
        source_node: Source of the issue
        affected_channels: List of affected channel IDs
        metric_name: Relevant metric name
        metric_value: Metric value
        threshold: Threshold crossed
        pattern: Detected pattern
        time_window_minutes: Time window for detection
        immediate_risk: "none", "low", "medium", "high"
        potential_risk: "none", "low", "medium", "high"
        affected_hive_members: Number of affected members
        recommended_action: "monitor", "investigate", "respond", "escalate"
        action_urgency: "low", "normal", "high", "immediate"
        auto_response_taken: Auto-response taken
        auto_response_reason: Reason for auto-response
        attestation: Operator attestation object

    Returns:
        Serialized and signed AI_ALERT message, or None on error
    """
    payload = {
        "node_id": node_id,
        "timestamp": timestamp,
        "alert_id": alert_id,
        "severity": severity,
        "category": category,
        "alert_type": alert_type,
        "source_node": source_node,
        "affected_channels": affected_channels or [],
        "metric_name": metric_name,
        "metric_value": metric_value,
        "threshold": threshold,
        "pattern": pattern,
        "time_window_minutes": time_window_minutes,
        "immediate_risk": immediate_risk,
        "potential_risk": potential_risk,
        "affected_hive_members": affected_hive_members,
        "recommended_action": recommended_action,
        "action_urgency": action_urgency,
        "auto_response_taken": auto_response_taken,
        "auto_response_reason": auto_response_reason,
    }

    if attestation:
        payload["attestation"] = attestation

    # Sign the payload
    signing_message = get_ai_alert_signing_payload(payload)
    try:
        sig_result = rpc.signmessage(signing_message)
        payload["signature"] = sig_result["zbase"]
    except Exception:
        return None

    return serialize(HiveMessageType.AI_ALERT, payload)


# =============================================================================
# AI ORACLE PROTOCOL - TASK COORDINATION CREATE FUNCTIONS (Phase 8.2)
# =============================================================================

def create_ai_task_request(
    node_id: str,
    target_node: str,
    timestamp: int,
    request_id: str,
    task_type: str,
    task_target: str,
    rpc,
    task_priority: str = "normal",
    task_deadline_timestamp: int = 0,
    amount_sats: int = 0,
    max_fee_sats: int = 0,
    max_fee_ppm: int = 0,
    min_channels: int = 1,
    max_channels: int = 1,
    selection_factors: List[str] = None,
    opportunity_signal_id: str = "",
    fleet_benefit_metric: str = "",
    fleet_benefit_from: float = 0.0,
    fleet_benefit_to: float = 0.0,
    compensation_offer_type: str = "reciprocal",
    compensation_credit_value: float = 1.0,
    compensation_current_balance: float = 0.0,
    compensation_lifetime_requested: int = 0,
    compensation_lifetime_fulfilled: int = 0,
    fallback_if_rejected: str = "will_handle_self",
    fallback_if_timeout: str = "will_handle_self",
    attestation: Dict[str, Any] = None
) -> Optional[bytes]:
    """
    Create a signed AI_TASK_REQUEST message.

    Args:
        node_id: Sender's node public key (requester)
        target_node: Target node to perform the task
        timestamp: Unix timestamp
        request_id: Unique request identifier
        task_type: Type of task ("expand_to", "rebalance_toward", etc.)
        task_target: Target of the task (pubkey, scid, etc.)
        rpc: RPC interface for signing
        task_priority: "low", "normal", "high", "critical"
        task_deadline_timestamp: When task must be completed by
        amount_sats: Amount in satoshis (if applicable)
        max_fee_sats: Maximum fee to pay
        max_fee_ppm: Maximum fee rate in PPM
        min_channels: Minimum channels to open
        max_channels: Maximum channels to open
        selection_factors: Why this target was selected
        opportunity_signal_id: Related opportunity signal
        fleet_benefit_metric: Fleet benefit metric name
        fleet_benefit_from: Current value
        fleet_benefit_to: Target value
        compensation_offer_type: "reciprocal", "paid", "goodwill"
        compensation_credit_value: Credit value for this task
        compensation_current_balance: Current reciprocity balance
        compensation_lifetime_requested: Total requests made
        compensation_lifetime_fulfilled: Total requests fulfilled
        fallback_if_rejected: What to do if rejected
        fallback_if_timeout: What to do on timeout
        attestation: Operator attestation object

    Returns:
        Serialized and signed AI_TASK_REQUEST message, or None on error
    """
    payload = {
        "node_id": node_id,
        "target_node": target_node,
        "timestamp": timestamp,
        "request_id": request_id,
        "task_type": task_type,
        "task_target": task_target,
        "task_priority": task_priority,
        "task_deadline_timestamp": task_deadline_timestamp,
        "amount_sats": amount_sats,
        "max_fee_sats": max_fee_sats,
        "max_fee_ppm": max_fee_ppm,
        "min_channels": min_channels,
        "max_channels": max_channels,
        "selection_factors": selection_factors or [],
        "opportunity_signal_id": opportunity_signal_id,
        "fleet_benefit_metric": fleet_benefit_metric,
        "fleet_benefit_from": fleet_benefit_from,
        "fleet_benefit_to": fleet_benefit_to,
        "compensation_offer_type": compensation_offer_type,
        "compensation_credit_value": compensation_credit_value,
        "compensation_current_balance": compensation_current_balance,
        "compensation_lifetime_requested": compensation_lifetime_requested,
        "compensation_lifetime_fulfilled": compensation_lifetime_fulfilled,
        "fallback_if_rejected": fallback_if_rejected,
        "fallback_if_timeout": fallback_if_timeout,
    }

    if attestation:
        payload["attestation"] = attestation

    # Sign the payload
    signing_message = get_ai_task_request_signing_payload(payload)
    try:
        sig_result = rpc.signmessage(signing_message)
        payload["signature"] = sig_result["zbase"]
    except Exception:
        return None

    return serialize(HiveMessageType.AI_TASK_REQUEST, payload)


def create_ai_task_response(
    node_id: str,
    timestamp: int,
    request_id: str,
    response: str,
    rpc,
    estimated_completion_timestamp: int = 0,
    actual_amount_sats: int = 0,
    actual_max_fee_sats: int = 0,
    estimated_fee_sats: int = 0,
    conditions: List[str] = None,
    rejection_reason: str = "",
    defer_until_timestamp: int = 0,
    counter_parameters: Dict[str, Any] = None,
    response_factors: List[str] = None,
    attestation: Dict[str, Any] = None
) -> Optional[bytes]:
    """
    Create a signed AI_TASK_RESPONSE message.

    Args:
        node_id: Sender's node public key (responder)
        timestamp: Unix timestamp
        request_id: Request ID being responded to
        response: "accept", "accept_modified", "reject", "defer", "counter"
        rpc: RPC interface for signing
        estimated_completion_timestamp: When task will be done
        actual_amount_sats: Actual amount (if modified)
        actual_max_fee_sats: Actual max fee (if modified)
        estimated_fee_sats: Estimated fee to pay
        conditions: Conditions for acceptance
        rejection_reason: Why rejecting (if applicable)
        defer_until_timestamp: When available (if deferring)
        counter_parameters: Counter-offer parameters
        response_factors: Factors influencing response
        attestation: Operator attestation object

    Returns:
        Serialized and signed AI_TASK_RESPONSE message, or None on error
    """
    payload = {
        "node_id": node_id,
        "timestamp": timestamp,
        "request_id": request_id,
        "response": response,
        "estimated_completion_timestamp": estimated_completion_timestamp,
        "actual_amount_sats": actual_amount_sats,
        "actual_max_fee_sats": actual_max_fee_sats,
        "estimated_fee_sats": estimated_fee_sats,
        "conditions": conditions or [],
        "rejection_reason": rejection_reason,
        "defer_until_timestamp": defer_until_timestamp,
        "counter_parameters": counter_parameters or {},
        "response_factors": response_factors or [],
    }

    if attestation:
        payload["attestation"] = attestation

    # Sign the payload
    signing_message = get_ai_task_response_signing_payload(payload)
    try:
        sig_result = rpc.signmessage(signing_message)
        payload["signature"] = sig_result["zbase"]
    except Exception:
        return None

    return serialize(HiveMessageType.AI_TASK_RESPONSE, payload)


def create_ai_task_complete(
    node_id: str,
    timestamp: int,
    request_id: str,
    status: str,
    rpc,
    task_type: str = "",
    task_target: str = "",
    channel_opened: bool = False,
    scid: str = "",
    capacity_sats: int = 0,
    actual_fee_sats: int = 0,
    funding_txid: str = "",
    amount_rebalanced_sats: int = 0,
    route_found: bool = False,
    fee_updated: bool = False,
    new_fee_ppm: int = 0,
    failure_reason: str = "",
    failure_details: str = "",
    target_responsiveness: str = "",
    connection_quality: str = "",
    recommended_for_future: bool = True,
    observed_traits: List[str] = None,
    reciprocal_credit_earned: bool = False,
    credit_expires_timestamp: int = 0,
    attestation: Dict[str, Any] = None
) -> Optional[bytes]:
    """
    Create a signed AI_TASK_COMPLETE message.

    Args:
        node_id: Sender's node public key (task executor)
        timestamp: Unix timestamp
        request_id: Request ID that was completed
        status: "success", "partial", "failed", "cancelled"
        rpc: RPC interface for signing
        task_type: Type of task completed
        task_target: Target of the task
        channel_opened: Whether channel was opened
        scid: Short channel ID (if channel opened)
        capacity_sats: Channel capacity (if opened)
        actual_fee_sats: Actual fee paid
        funding_txid: Funding transaction ID
        amount_rebalanced_sats: Amount rebalanced (if rebalance)
        route_found: Whether route was found (if probe)
        fee_updated: Whether fee was updated
        new_fee_ppm: New fee rate
        failure_reason: Why task failed (if applicable)
        failure_details: Additional failure details
        target_responsiveness: Target's responsiveness
        connection_quality: Connection quality assessment
        recommended_for_future: Recommend for future tasks
        observed_traits: Observed traits of target
        reciprocal_credit_earned: Whether credit was earned
        credit_expires_timestamp: When credit expires
        attestation: Operator attestation object

    Returns:
        Serialized and signed AI_TASK_COMPLETE message, or None on error
    """
    payload = {
        "node_id": node_id,
        "timestamp": timestamp,
        "request_id": request_id,
        "status": status,
        "task_type": task_type,
        "task_target": task_target,
        "channel_opened": channel_opened,
        "scid": scid,
        "capacity_sats": capacity_sats,
        "actual_fee_sats": actual_fee_sats,
        "funding_txid": funding_txid,
        "amount_rebalanced_sats": amount_rebalanced_sats,
        "route_found": route_found,
        "fee_updated": fee_updated,
        "new_fee_ppm": new_fee_ppm,
        "failure_reason": failure_reason,
        "failure_details": failure_details,
        "target_responsiveness": target_responsiveness,
        "connection_quality": connection_quality,
        "recommended_for_future": recommended_for_future,
        "observed_traits": observed_traits or [],
        "reciprocal_credit_earned": reciprocal_credit_earned,
        "credit_expires_timestamp": credit_expires_timestamp,
    }

    if attestation:
        payload["attestation"] = attestation

    # Sign the payload
    signing_message = get_ai_task_complete_signing_payload(payload)
    try:
        sig_result = rpc.signmessage(signing_message)
        payload["signature"] = sig_result["zbase"]
    except Exception:
        return None

    return serialize(HiveMessageType.AI_TASK_COMPLETE, payload)


def create_ai_task_cancel(
    node_id: str,
    timestamp: int,
    request_id: str,
    reason: str,
    rpc,
    attestation: Dict[str, Any] = None
) -> Optional[bytes]:
    """
    Create a signed AI_TASK_CANCEL message.

    Args:
        node_id: Sender's node public key (original requester)
        timestamp: Unix timestamp
        request_id: Request ID to cancel
        reason: Cancellation reason
        rpc: RPC interface for signing
        attestation: Operator attestation object

    Returns:
        Serialized and signed AI_TASK_CANCEL message, or None on error
    """
    payload = {
        "node_id": node_id,
        "timestamp": timestamp,
        "request_id": request_id,
        "reason": reason,
    }

    if attestation:
        payload["attestation"] = attestation

    # Sign the payload
    signing_message = get_ai_task_cancel_signing_payload(payload)
    try:
        sig_result = rpc.signmessage(signing_message)
        payload["signature"] = sig_result["zbase"]
    except Exception:
        return None

    return serialize(HiveMessageType.AI_TASK_CANCEL, payload)


# =============================================================================
# AI ORACLE PROTOCOL - STRATEGY COORDINATION CREATE FUNCTIONS (Phase 8.3)
# =============================================================================

def create_ai_strategy_proposal(
    node_id: str,
    timestamp: int,
    proposal_id: str,
    strategy_type: str,
    rpc,
    strategy_name: str = "",
    strategy_summary: str = "",
    objectives: List[str] = None,
    target_corridor: str = "",
    target_nodes: List[str] = None,
    fee_floor_ppm: int = 0,
    fee_ceiling_ppm: int = 0,
    duration_hours: int = 0,
    ramp_up_hours: int = 0,
    amount_sats: int = 0,
    expected_revenue_change_pct: float = 0.0,
    expected_volume_change_pct: float = 0.0,
    expected_net_benefit_pct: float = 0.0,
    outcome_confidence: float = 0.5,
    risks: List[Dict[str, Any]] = None,
    opt_out_allowed: bool = True,
    opt_out_penalty: str = "none",
    approval_threshold_pct: float = 51.0,
    min_participation_pct: float = 60.0,
    voting_deadline_timestamp: int = 0,
    execution_delay_hours: int = 24,
    vote_weight: str = "equal",
    proposer_will_participate: bool = True,
    proposer_capacity_committed_sats: int = 0,
    attestation: Dict[str, Any] = None
) -> Optional[bytes]:
    """
    Create a signed AI_STRATEGY_PROPOSAL message.

    Args:
        node_id: Proposer's node public key
        timestamp: Unix timestamp
        proposal_id: Unique proposal identifier
        strategy_type: Type of strategy ("fee_coordination", etc.)
        rpc: RPC interface for signing
        strategy_name: Human-readable name
        strategy_summary: Brief description (enum-based)
        objectives: Strategy objectives
        target_corridor: Target corridor identifier
        target_nodes: Target node pubkeys
        fee_floor_ppm: Minimum fee in PPM
        fee_ceiling_ppm: Maximum fee in PPM
        duration_hours: Strategy duration
        ramp_up_hours: Ramp-up period
        amount_sats: Amount in satoshis (if applicable)
        expected_revenue_change_pct: Expected revenue change
        expected_volume_change_pct: Expected volume change
        expected_net_benefit_pct: Expected net benefit
        outcome_confidence: Confidence in outcomes (0-1)
        risks: Risk assessment list
        opt_out_allowed: Whether opt-out is allowed
        opt_out_penalty: Penalty for opt-out
        approval_threshold_pct: Approval threshold percentage
        min_participation_pct: Minimum participation percentage
        voting_deadline_timestamp: Voting deadline
        execution_delay_hours: Delay before execution
        vote_weight: Vote weighting method
        proposer_will_participate: Proposer participation commitment
        proposer_capacity_committed_sats: Proposer capacity commitment
        attestation: Operator attestation object

    Returns:
        Serialized and signed AI_STRATEGY_PROPOSAL message, or None on error
    """
    payload = {
        "node_id": node_id,
        "timestamp": timestamp,
        "proposal_id": proposal_id,
        "strategy_type": strategy_type,
        "strategy_name": strategy_name,
        "strategy_summary": strategy_summary,
        "objectives": objectives or [],
        "target_corridor": target_corridor,
        "target_nodes": target_nodes or [],
        "fee_floor_ppm": fee_floor_ppm,
        "fee_ceiling_ppm": fee_ceiling_ppm,
        "duration_hours": duration_hours,
        "ramp_up_hours": ramp_up_hours,
        "amount_sats": amount_sats,
        "expected_revenue_change_pct": expected_revenue_change_pct,
        "expected_volume_change_pct": expected_volume_change_pct,
        "expected_net_benefit_pct": expected_net_benefit_pct,
        "outcome_confidence": outcome_confidence,
        "risks": risks or [],
        "opt_out_allowed": opt_out_allowed,
        "opt_out_penalty": opt_out_penalty,
        "approval_threshold_pct": approval_threshold_pct,
        "min_participation_pct": min_participation_pct,
        "voting_deadline_timestamp": voting_deadline_timestamp,
        "execution_delay_hours": execution_delay_hours,
        "vote_weight": vote_weight,
        "proposer_will_participate": proposer_will_participate,
        "proposer_capacity_committed_sats": proposer_capacity_committed_sats,
    }

    if attestation:
        payload["attestation"] = attestation

    # Sign the payload
    signing_message = get_ai_strategy_proposal_signing_payload(payload)
    try:
        sig_result = rpc.signmessage(signing_message)
        payload["signature"] = sig_result["zbase"]
    except Exception:
        return None

    return serialize(HiveMessageType.AI_STRATEGY_PROPOSAL, payload)


def create_ai_strategy_vote(
    node_id: str,
    timestamp: int,
    proposal_id: str,
    vote: str,
    rpc,
    vote_hash: str = "",
    nonce: str = "",
    rationale_factors: List[str] = None,
    confidence_in_proposal: float = 0.5,
    will_participate: bool = False,
    capacity_committed_sats: int = 0,
    conditions: List[str] = None,
    amendments: List[Dict[str, Any]] = None,
    attestation: Dict[str, Any] = None
) -> Optional[bytes]:
    """
    Create a signed AI_STRATEGY_VOTE message.

    Args:
        node_id: Voter's node public key
        timestamp: Unix timestamp
        proposal_id: Proposal being voted on
        vote: Vote choice ("approve", "reject", etc.)
        rpc: RPC interface for signing
        vote_hash: sha256(proposal_id || node_id || vote || timestamp || nonce)
        nonce: Random 32-byte hex for vote hash
        rationale_factors: Factors influencing vote decision
        confidence_in_proposal: Confidence level (0-1)
        will_participate: Commitment to participate if adopted
        capacity_committed_sats: Capacity being committed
        conditions: Conditions for participation
        amendments: Proposed amendments (if approve_with_amendments)
        attestation: Operator attestation object

    Returns:
        Serialized and signed AI_STRATEGY_VOTE message, or None on error
    """
    payload = {
        "node_id": node_id,
        "timestamp": timestamp,
        "proposal_id": proposal_id,
        "vote": vote,
        "vote_hash": vote_hash,
        "nonce": nonce,
        "rationale_factors": rationale_factors or [],
        "confidence_in_proposal": confidence_in_proposal,
        "will_participate": will_participate,
        "capacity_committed_sats": capacity_committed_sats,
        "conditions": conditions or [],
        "amendments": amendments or [],
    }

    if attestation:
        payload["attestation"] = attestation

    # Sign the payload
    signing_message = get_ai_strategy_vote_signing_payload(payload)
    try:
        sig_result = rpc.signmessage(signing_message)
        payload["signature"] = sig_result["zbase"]
    except Exception:
        return None

    return serialize(HiveMessageType.AI_STRATEGY_VOTE, payload)


def create_ai_strategy_result(
    node_id: str,
    timestamp: int,
    proposal_id: str,
    result: str,
    rpc,
    votes_for: int = 0,
    votes_against: int = 0,
    abstentions: int = 0,
    eligible_voters: int = 0,
    quorum_met: bool = False,
    approval_pct: float = 0.0,
    participation_pct: float = 0.0,
    vote_proofs: List[Dict[str, Any]] = None,
    effective_timestamp: int = 0,
    coordinator_node: str = "",
    participants: List[str] = None,
    opt_outs: List[str] = None,
    amendments_incorporated: List[Dict[str, Any]] = None,
    attestation: Dict[str, Any] = None
) -> Optional[bytes]:
    """
    Create a signed AI_STRATEGY_RESULT message.

    Args:
        node_id: Announcer's node public key (proposal originator)
        timestamp: Unix timestamp
        proposal_id: Proposal ID
        result: Voting result ("adopted", "rejected", etc.)
        rpc: RPC interface for signing
        votes_for: Number of votes in favor
        votes_against: Number of votes against
        abstentions: Number of abstentions
        eligible_voters: Total eligible voters
        quorum_met: Whether quorum was achieved
        approval_pct: Approval percentage
        participation_pct: Participation percentage
        vote_proofs: Proofs for vote verification
        effective_timestamp: When strategy takes effect
        coordinator_node: Strategy coordinator
        participants: List of participating nodes
        opt_outs: List of nodes that opted out
        amendments_incorporated: Amendments that were adopted
        attestation: Operator attestation object

    Returns:
        Serialized and signed AI_STRATEGY_RESULT message, or None on error
    """
    payload = {
        "node_id": node_id,
        "timestamp": timestamp,
        "proposal_id": proposal_id,
        "result": result,
        "votes_for": votes_for,
        "votes_against": votes_against,
        "abstentions": abstentions,
        "eligible_voters": eligible_voters,
        "quorum_met": quorum_met,
        "approval_pct": approval_pct,
        "participation_pct": participation_pct,
        "vote_proofs": vote_proofs or [],
        "effective_timestamp": effective_timestamp,
        "coordinator_node": coordinator_node,
        "participants": participants or [],
        "opt_outs": opt_outs or [],
        "amendments_incorporated": amendments_incorporated or [],
    }

    if attestation:
        payload["attestation"] = attestation

    # Sign the payload
    signing_message = get_ai_strategy_result_signing_payload(payload)
    try:
        sig_result = rpc.signmessage(signing_message)
        payload["signature"] = sig_result["zbase"]
    except Exception:
        return None

    return serialize(HiveMessageType.AI_STRATEGY_RESULT, payload)


def create_ai_strategy_update(
    node_id: str,
    timestamp: int,
    proposal_id: str,
    phase: str,
    rpc,
    hours_elapsed: int = 0,
    hours_remaining: int = 0,
    completion_pct: float = 0.0,
    revenue_change_pct: float = 0.0,
    volume_change_pct: float = 0.0,
    participant_compliance_pct: float = 100.0,
    on_track: bool = True,
    participant_status: List[Dict[str, Any]] = None,
    issues: List[str] = None,
    recommendation: str = "continue",
    attestation: Dict[str, Any] = None
) -> Optional[bytes]:
    """
    Create a signed AI_STRATEGY_UPDATE message.

    Args:
        node_id: Reporter's node public key (coordinator)
        timestamp: Unix timestamp
        proposal_id: Strategy proposal ID
        phase: Current phase ("preparation", "execution", etc.)
        rpc: RPC interface for signing
        hours_elapsed: Hours since strategy started
        hours_remaining: Hours until completion
        completion_pct: Completion percentage
        revenue_change_pct: Revenue change percentage
        volume_change_pct: Volume change percentage
        participant_compliance_pct: Participant compliance percentage
        on_track: Whether strategy is on track
        participant_status: Status of each participant
        issues: Current issues (from allowed set)
        recommendation: Recommendation ("continue", "adjust", etc.)
        attestation: Operator attestation object

    Returns:
        Serialized and signed AI_STRATEGY_UPDATE message, or None on error
    """
    payload = {
        "node_id": node_id,
        "timestamp": timestamp,
        "proposal_id": proposal_id,
        "phase": phase,
        "hours_elapsed": hours_elapsed,
        "hours_remaining": hours_remaining,
        "completion_pct": completion_pct,
        "revenue_change_pct": revenue_change_pct,
        "volume_change_pct": volume_change_pct,
        "participant_compliance_pct": participant_compliance_pct,
        "on_track": on_track,
        "participant_status": participant_status or [],
        "issues": issues or [],
        "recommendation": recommendation,
    }

    if attestation:
        payload["attestation"] = attestation

    # Sign the payload
    signing_message = get_ai_strategy_update_signing_payload(payload)
    try:
        sig_result = rpc.signmessage(signing_message)
        payload["signature"] = sig_result["zbase"]
    except Exception:
        return None

    return serialize(HiveMessageType.AI_STRATEGY_UPDATE, payload)


# =============================================================================
# AI ORACLE PROTOCOL - REASONING & MARKET CREATE FUNCTIONS (Phase 8.4)
# =============================================================================

def create_ai_reasoning_request(
    node_id: str,
    target_node: str,
    timestamp: int,
    request_id: str,
    reference_type: str,
    rpc,
    reference_id: str = "",
    question_type: str = "full_reasoning",
    detail_level: str = "summary",
    attestation: Dict[str, Any] = None
) -> Optional[bytes]:
    """
    Create a signed AI_REASONING_REQUEST message.

    Args:
        node_id: Requester's node public key
        target_node: Target AI's node public key
        timestamp: Unix timestamp
        request_id: Unique request identifier
        reference_type: Type of referenced item ("strategy_vote", etc.)
        rpc: RPC interface for signing
        reference_id: ID of the referenced item
        question_type: Type of question ("full_reasoning", etc.)
        detail_level: Detail level requested ("brief", "summary", "full")
        attestation: Operator attestation object

    Returns:
        Serialized and signed AI_REASONING_REQUEST message, or None on error
    """
    payload = {
        "node_id": node_id,
        "target_node": target_node,
        "timestamp": timestamp,
        "request_id": request_id,
        "reference_type": reference_type,
        "reference_id": reference_id,
        "question_type": question_type,
        "detail_level": detail_level,
    }

    if attestation:
        payload["attestation"] = attestation

    # Sign the payload
    signing_message = get_ai_reasoning_request_signing_payload(payload)
    try:
        sig_result = rpc.signmessage(signing_message)
        payload["signature"] = sig_result["zbase"]
    except Exception:
        return None

    return serialize(HiveMessageType.AI_REASONING_REQUEST, payload)


def create_ai_reasoning_response(
    node_id: str,
    timestamp: int,
    request_id: str,
    rpc,
    conclusion: str = "",
    decision_factors: List[Dict[str, Any]] = None,
    overall_confidence: float = 0.5,
    data_sources: List[str] = None,
    alternative_strategy_type: str = "",
    alternative_target_metric: str = "",
    alternative_expected_change_pct: float = 0.0,
    alternative_risk_level: str = "",
    reasoning_time_ms: int = 0,
    tokens_used: int = 0,
    attestation: Dict[str, Any] = None
) -> Optional[bytes]:
    """
    Create a signed AI_REASONING_RESPONSE message.

    Args:
        node_id: Responder's node public key
        timestamp: Unix timestamp
        request_id: Request ID being responded to
        rpc: RPC interface for signing
        conclusion: Reasoning conclusion (enum value)
        decision_factors: List of decision factors with weights
        overall_confidence: Overall confidence level (0-1)
        data_sources: Data sources used (enum values)
        alternative_strategy_type: Alternative strategy type
        alternative_target_metric: Target metric for alternative
        alternative_expected_change_pct: Expected change percentage
        alternative_risk_level: Risk level of alternative
        reasoning_time_ms: Time spent reasoning
        tokens_used: Tokens used for reasoning
        attestation: Operator attestation object

    Returns:
        Serialized and signed AI_REASONING_RESPONSE message, or None on error
    """
    payload = {
        "node_id": node_id,
        "timestamp": timestamp,
        "request_id": request_id,
        "conclusion": conclusion,
        "decision_factors": decision_factors or [],
        "overall_confidence": overall_confidence,
        "data_sources": data_sources or [],
        "alternative_strategy_type": alternative_strategy_type,
        "alternative_target_metric": alternative_target_metric,
        "alternative_expected_change_pct": alternative_expected_change_pct,
        "alternative_risk_level": alternative_risk_level,
        "reasoning_time_ms": reasoning_time_ms,
        "tokens_used": tokens_used,
    }

    if attestation:
        payload["attestation"] = attestation

    # Sign the payload
    signing_message = get_ai_reasoning_response_signing_payload(payload)
    try:
        sig_result = rpc.signmessage(signing_message)
        payload["signature"] = sig_result["zbase"]
    except Exception:
        return None

    return serialize(HiveMessageType.AI_REASONING_RESPONSE, payload)


def create_ai_market_assessment(
    node_id: str,
    timestamp: int,
    assessment_id: str,
    assessment_type: str,
    rpc,
    time_horizon: str = "short_term",
    avg_network_fee_ppm: int = 0,
    fee_change_24h_pct: float = 0.0,
    mempool_depth_tier: str = "normal",
    mempool_fee_rate_tier: str = "normal",
    block_fullness_tier: str = "normal",
    corridor_analysis: List[Dict[str, Any]] = None,
    overall_stance: str = "neutral",
    fee_direction: str = "hold",
    expansion_timing: str = "neutral",
    rebalance_urgency: str = "normal",
    confidence: float = 0.5,
    data_freshness_seconds: int = 0,
    attestation: Dict[str, Any] = None
) -> Optional[bytes]:
    """
    Create a signed AI_MARKET_ASSESSMENT message.

    Args:
        node_id: Assessor's node public key
        timestamp: Unix timestamp
        assessment_id: Unique assessment identifier
        assessment_type: Type of assessment ("fee_trend", etc.)
        rpc: RPC interface for signing
        time_horizon: Time horizon ("immediate", "short_term", etc.)
        avg_network_fee_ppm: Average network fee in PPM
        fee_change_24h_pct: Fee change in last 24 hours
        mempool_depth_tier: Mempool depth tier
        mempool_fee_rate_tier: Mempool fee rate tier
        block_fullness_tier: Block fullness tier
        corridor_analysis: List of corridor analysis entries
        overall_stance: Market stance recommendation
        fee_direction: Fee direction recommendation
        expansion_timing: Expansion timing recommendation
        rebalance_urgency: Rebalance urgency level
        confidence: Confidence level (0-1)
        data_freshness_seconds: Data freshness in seconds
        attestation: Operator attestation object

    Returns:
        Serialized and signed AI_MARKET_ASSESSMENT message, or None on error
    """
    payload = {
        "node_id": node_id,
        "timestamp": timestamp,
        "assessment_id": assessment_id,
        "assessment_type": assessment_type,
        "time_horizon": time_horizon,
        "avg_network_fee_ppm": avg_network_fee_ppm,
        "fee_change_24h_pct": fee_change_24h_pct,
        "mempool_depth_tier": mempool_depth_tier,
        "mempool_fee_rate_tier": mempool_fee_rate_tier,
        "block_fullness_tier": block_fullness_tier,
        "corridor_analysis": corridor_analysis or [],
        "overall_stance": overall_stance,
        "fee_direction": fee_direction,
        "expansion_timing": expansion_timing,
        "rebalance_urgency": rebalance_urgency,
        "confidence": confidence,
        "data_freshness_seconds": data_freshness_seconds,
    }

    if attestation:
        payload["attestation"] = attestation

    # Sign the payload
    signing_message = get_ai_market_assessment_signing_payload(payload)
    try:
        sig_result = rpc.signmessage(signing_message)
        payload["signature"] = sig_result["zbase"]
    except Exception:
        return None

    return serialize(HiveMessageType.AI_MARKET_ASSESSMENT, payload)


# =============================================================================
# AI MESSAGE ENCODING UTILITY
# =============================================================================


def encode_ai_message(msg_type: HiveMessageType, payload: Dict[str, Any]) -> bytes:
    """
    Encode an AI Oracle message for transmission.

    This is a convenience wrapper around serialize() for AI messages.
    The payload should already include all required fields and the signature.

    Args:
        msg_type: HiveMessageType enum value (must be an AI_* type)
        payload: Complete message payload with signature

    Returns:
        bytes: Wire-ready message with magic prefix

    Raises:
        ValueError: If msg_type is not an AI Oracle message type

    Example:
        >>> payload = {"node_id": "03abc...", "timestamp": 1705234567, ...}
        >>> msg_bytes = encode_ai_message(HiveMessageType.AI_STATE_SUMMARY, payload)
    """
    # Validate this is an AI message type
    ai_types = {
        HiveMessageType.AI_STATE_SUMMARY,
        HiveMessageType.AI_HEARTBEAT,
        HiveMessageType.AI_OPPORTUNITY_SIGNAL,
        HiveMessageType.AI_ALERT,
        HiveMessageType.AI_TASK_REQUEST,
        HiveMessageType.AI_TASK_RESPONSE,
        HiveMessageType.AI_TASK_COMPLETE,
        HiveMessageType.AI_TASK_CANCEL,
        HiveMessageType.AI_STRATEGY_PROPOSAL,
        HiveMessageType.AI_STRATEGY_VOTE,
        HiveMessageType.AI_STRATEGY_RESULT,
        HiveMessageType.AI_STRATEGY_UPDATE,
        HiveMessageType.AI_REASONING_REQUEST,
        HiveMessageType.AI_REASONING_RESPONSE,
        HiveMessageType.AI_MARKET_ASSESSMENT,
    }

    if msg_type not in ai_types:
        raise ValueError(f"Not an AI message type: {msg_type.name}")

    return serialize(msg_type, payload)
