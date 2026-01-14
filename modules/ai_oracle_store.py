"""
AI Oracle Message Store

Stores, validates, and manages AI Oracle Protocol messages.
This module provides the storage layer for AI-to-AI communication,
allowing the oracle plugin to process messages asynchronously.

Per spec: All messages are validated for:
- PKI signatures (via CLN signmessage/checkmessage)
- Rate limits (per sender, per message type)
- Schema validation (enum-only fields to prevent prompt injection)
"""

import json
import time
import threading
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Any, Tuple
from collections import defaultdict

from .protocol import (
    HiveMessageType,
    # Validation functions
    validate_ai_state_summary_payload,
    validate_ai_heartbeat_payload,
    validate_ai_opportunity_signal_payload,
    validate_ai_alert_payload,
    validate_ai_task_request_payload,
    validate_ai_task_response_payload,
    validate_ai_task_complete_payload,
    validate_ai_task_cancel_payload,
    validate_ai_strategy_proposal_payload,
    validate_ai_strategy_vote_payload,
    validate_ai_strategy_result_payload,
    validate_ai_strategy_update_payload,
    validate_ai_reasoning_request_payload,
    validate_ai_reasoning_response_payload,
    validate_ai_market_assessment_payload,
    # Rate limits
    AI_STATE_SUMMARY_RATE_LIMIT,
    AI_OPPORTUNITY_SIGNAL_RATE_LIMIT,
    AI_TASK_REQUEST_RATE_LIMIT,
    AI_STRATEGY_PROPOSAL_RATE_LIMIT,
    AI_ALERT_RATE_LIMIT,
    AI_HEARTBEAT_RATE_LIMIT,
    AI_REASONING_REQUEST_RATE_LIMIT,
    # Message max age
    AI_MESSAGE_MAX_AGE_SECONDS,
)


# =============================================================================
# RATE LIMITER
# =============================================================================

class AIMessageRateLimiter:
    """
    Per-sender, per-message-type rate limiter for AI Oracle messages.

    Uses sliding window approach with configurable limits per message type.
    """

    def __init__(self):
        self._lock = threading.Lock()
        # {(sender_id, msg_type): [timestamps]}
        self._windows: Dict[Tuple[str, str], List[float]] = defaultdict(list)

        # Rate limits: (max_count, window_seconds)
        self._limits = {
            HiveMessageType.AI_STATE_SUMMARY: AI_STATE_SUMMARY_RATE_LIMIT,
            HiveMessageType.AI_OPPORTUNITY_SIGNAL: AI_OPPORTUNITY_SIGNAL_RATE_LIMIT,
            HiveMessageType.AI_TASK_REQUEST: AI_TASK_REQUEST_RATE_LIMIT,
            HiveMessageType.AI_TASK_RESPONSE: AI_TASK_REQUEST_RATE_LIMIT,  # Same as request
            HiveMessageType.AI_TASK_COMPLETE: AI_TASK_REQUEST_RATE_LIMIT,
            HiveMessageType.AI_TASK_CANCEL: AI_TASK_REQUEST_RATE_LIMIT,
            HiveMessageType.AI_STRATEGY_PROPOSAL: AI_STRATEGY_PROPOSAL_RATE_LIMIT,
            HiveMessageType.AI_STRATEGY_VOTE: AI_STRATEGY_PROPOSAL_RATE_LIMIT,
            HiveMessageType.AI_STRATEGY_RESULT: AI_STRATEGY_PROPOSAL_RATE_LIMIT,
            HiveMessageType.AI_STRATEGY_UPDATE: AI_STRATEGY_PROPOSAL_RATE_LIMIT,
            HiveMessageType.AI_ALERT: AI_ALERT_RATE_LIMIT,
            HiveMessageType.AI_HEARTBEAT: AI_HEARTBEAT_RATE_LIMIT,
            HiveMessageType.AI_REASONING_REQUEST: AI_REASONING_REQUEST_RATE_LIMIT,
            HiveMessageType.AI_REASONING_RESPONSE: AI_REASONING_REQUEST_RATE_LIMIT,
            HiveMessageType.AI_MARKET_ASSESSMENT: AI_OPPORTUNITY_SIGNAL_RATE_LIMIT,
        }

    def check_and_record(self, sender_id: str, msg_type: HiveMessageType) -> Tuple[bool, str]:
        """
        Check if message is within rate limit and record if allowed.

        Returns:
            (allowed, reason) - True if allowed, False with reason if rate limited
        """
        limit = self._limits.get(msg_type)
        if not limit:
            return True, ""

        max_count, window_seconds = limit
        key = (sender_id, msg_type.name)
        now = time.time()

        with self._lock:
            # Clean old entries
            self._windows[key] = [
                ts for ts in self._windows[key]
                if now - ts < window_seconds
            ]

            # Check limit
            if len(self._windows[key]) >= max_count:
                return False, f"Rate limit exceeded: {max_count} per {window_seconds}s"

            # Record this message
            self._windows[key].append(now)
            return True, ""

    def clear_sender(self, sender_id: str):
        """Clear all rate limit history for a sender."""
        with self._lock:
            keys_to_remove = [k for k in self._windows if k[0] == sender_id]
            for key in keys_to_remove:
                del self._windows[key]


# =============================================================================
# MESSAGE STORAGE
# =============================================================================

@dataclass
class StoredAIMessage:
    """A stored AI Oracle message."""
    msg_id: str                     # Unique message ID
    msg_type: HiveMessageType       # Message type
    sender_id: str                  # Sender's node pubkey
    timestamp: int                  # Message timestamp
    payload: Dict[str, Any]         # Full message payload
    received_at: float              # When we received it
    processed: bool = False         # Has it been processed?
    process_result: str = ""        # Result of processing


class AIMessageStore:
    """
    Storage and management for AI Oracle messages.

    Provides:
    - Message storage with validation
    - Signature verification
    - Rate limiting
    - Message retrieval for processing
    - Cleanup of old messages
    """

    # Maximum messages to keep in memory per type
    MAX_MESSAGES_PER_TYPE = 100

    # How long to keep processed messages (seconds)
    PROCESSED_MESSAGE_TTL = 3600  # 1 hour

    def __init__(self, database, plugin, our_pubkey: str):
        """
        Initialize the AI message store.

        Args:
            database: HiveDatabase instance
            plugin: ThreadSafeRpcProxy for RPC calls
            our_pubkey: Our node's public key
        """
        self.database = database
        self.plugin = plugin
        self.our_pubkey = our_pubkey
        self._lock = threading.Lock()

        # In-memory message queues by type
        self._messages: Dict[HiveMessageType, List[StoredAIMessage]] = defaultdict(list)

        # Rate limiter
        self._rate_limiter = AIMessageRateLimiter()

        # Validator map
        self._validators = {
            HiveMessageType.AI_STATE_SUMMARY: validate_ai_state_summary_payload,
            HiveMessageType.AI_HEARTBEAT: validate_ai_heartbeat_payload,
            HiveMessageType.AI_OPPORTUNITY_SIGNAL: validate_ai_opportunity_signal_payload,
            HiveMessageType.AI_ALERT: validate_ai_alert_payload,
            HiveMessageType.AI_TASK_REQUEST: validate_ai_task_request_payload,
            HiveMessageType.AI_TASK_RESPONSE: validate_ai_task_response_payload,
            HiveMessageType.AI_TASK_COMPLETE: validate_ai_task_complete_payload,
            HiveMessageType.AI_TASK_CANCEL: validate_ai_task_cancel_payload,
            HiveMessageType.AI_STRATEGY_PROPOSAL: validate_ai_strategy_proposal_payload,
            HiveMessageType.AI_STRATEGY_VOTE: validate_ai_strategy_vote_payload,
            HiveMessageType.AI_STRATEGY_RESULT: validate_ai_strategy_result_payload,
            HiveMessageType.AI_STRATEGY_UPDATE: validate_ai_strategy_update_payload,
            HiveMessageType.AI_REASONING_REQUEST: validate_ai_reasoning_request_payload,
            HiveMessageType.AI_REASONING_RESPONSE: validate_ai_reasoning_response_payload,
            HiveMessageType.AI_MARKET_ASSESSMENT: validate_ai_market_assessment_payload,
        }

        # Initialize database table
        self._init_database()

    def _init_database(self):
        """Create the AI messages table if it doesn't exist."""
        try:
            conn = self.database._get_connection()
            cursor = conn.cursor()
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS ai_messages (
                    msg_id TEXT PRIMARY KEY,
                    msg_type INTEGER NOT NULL,
                    sender_id TEXT NOT NULL,
                    timestamp INTEGER NOT NULL,
                    payload TEXT NOT NULL,
                    received_at REAL NOT NULL,
                    processed INTEGER DEFAULT 0,
                    process_result TEXT DEFAULT '',
                    created_at REAL DEFAULT (strftime('%s', 'now'))
                )
            """)
            cursor.execute("""
                CREATE INDEX IF NOT EXISTS idx_ai_messages_type
                ON ai_messages(msg_type, processed)
            """)
            cursor.execute("""
                CREATE INDEX IF NOT EXISTS idx_ai_messages_sender
                ON ai_messages(sender_id, timestamp)
            """)
            conn.commit()
        except Exception:
            pass  # Table may already exist

    def store_message(
        self,
        peer_id: str,
        msg_type: HiveMessageType,
        payload: Dict[str, Any]
    ) -> Dict[str, Any]:
        """
        Validate and store an incoming AI Oracle message.

        Args:
            peer_id: Sender's peer ID
            msg_type: Message type
            payload: Message payload

        Returns:
            {"success": True} or {"error": "reason"}
        """
        # Get validator for this message type
        validator = self._validators.get(msg_type)
        if not validator:
            return {"error": f"Unknown message type: {msg_type.name}"}

        # Validate payload schema
        if not validator(payload):
            return {"error": "Payload validation failed"}

        # Verify sender matches claimed node_id
        claimed_node_id = payload.get("node_id", "")
        if claimed_node_id != peer_id:
            return {"error": "Sender mismatch: peer_id != node_id"}

        # Check rate limit
        allowed, reason = self._rate_limiter.check_and_record(peer_id, msg_type)
        if not allowed:
            return {"error": reason}

        # Verify signature
        signature = payload.get("signature", "")
        if not self._verify_signature(peer_id, msg_type, payload, signature):
            return {"error": "Signature verification failed"}

        # Generate message ID
        timestamp = payload.get("timestamp", int(time.time()))
        msg_id = self._generate_msg_id(msg_type, peer_id, timestamp, payload)

        # Create stored message
        stored_msg = StoredAIMessage(
            msg_id=msg_id,
            msg_type=msg_type,
            sender_id=peer_id,
            timestamp=timestamp,
            payload=payload,
            received_at=time.time(),
            processed=False,
        )

        # Store in memory
        with self._lock:
            messages = self._messages[msg_type]
            messages.append(stored_msg)

            # Trim if too many messages
            if len(messages) > self.MAX_MESSAGES_PER_TYPE:
                # Remove oldest unprocessed or oldest processed
                messages.sort(key=lambda m: (m.processed, m.received_at))
                self._messages[msg_type] = messages[-self.MAX_MESSAGES_PER_TYPE:]

        # Store in database
        self._store_to_database(stored_msg)

        return {"success": True, "msg_id": msg_id}

    def _verify_signature(
        self,
        peer_id: str,
        msg_type: HiveMessageType,
        payload: Dict[str, Any],
        signature: str
    ) -> bool:
        """
        Verify the PKI signature on a message.

        Uses the appropriate signing payload function to reconstruct
        what was signed, then verifies using checkmessage.
        """
        from .protocol import (
            get_ai_state_summary_signing_payload,
            get_ai_heartbeat_signing_payload,
            get_ai_opportunity_signal_signing_payload,
            get_ai_alert_signing_payload,
            get_ai_task_request_signing_payload,
            get_ai_task_response_signing_payload,
            get_ai_task_complete_signing_payload,
            get_ai_task_cancel_signing_payload,
            get_ai_strategy_proposal_signing_payload,
            get_ai_strategy_vote_signing_payload,
            get_ai_strategy_result_signing_payload,
            get_ai_strategy_update_signing_payload,
            get_ai_reasoning_request_signing_payload,
            get_ai_reasoning_response_signing_payload,
            get_ai_market_assessment_signing_payload,
        )

        # Get the signing payload function
        signing_funcs = {
            HiveMessageType.AI_STATE_SUMMARY: get_ai_state_summary_signing_payload,
            HiveMessageType.AI_HEARTBEAT: get_ai_heartbeat_signing_payload,
            HiveMessageType.AI_OPPORTUNITY_SIGNAL: get_ai_opportunity_signal_signing_payload,
            HiveMessageType.AI_ALERT: get_ai_alert_signing_payload,
            HiveMessageType.AI_TASK_REQUEST: get_ai_task_request_signing_payload,
            HiveMessageType.AI_TASK_RESPONSE: get_ai_task_response_signing_payload,
            HiveMessageType.AI_TASK_COMPLETE: get_ai_task_complete_signing_payload,
            HiveMessageType.AI_TASK_CANCEL: get_ai_task_cancel_signing_payload,
            HiveMessageType.AI_STRATEGY_PROPOSAL: get_ai_strategy_proposal_signing_payload,
            HiveMessageType.AI_STRATEGY_VOTE: get_ai_strategy_vote_signing_payload,
            HiveMessageType.AI_STRATEGY_RESULT: get_ai_strategy_result_signing_payload,
            HiveMessageType.AI_STRATEGY_UPDATE: get_ai_strategy_update_signing_payload,
            HiveMessageType.AI_REASONING_REQUEST: get_ai_reasoning_request_signing_payload,
            HiveMessageType.AI_REASONING_RESPONSE: get_ai_reasoning_response_signing_payload,
            HiveMessageType.AI_MARKET_ASSESSMENT: get_ai_market_assessment_signing_payload,
        }

        signing_func = signing_funcs.get(msg_type)
        if not signing_func:
            return False

        try:
            # Reconstruct signing message
            signing_message = signing_func(payload)

            # Verify signature using checkmessage
            result = self.plugin.rpc.checkmessage(
                message=signing_message,
                zbase=signature,
                pubkey=peer_id
            )
            return result.get("verified", False)
        except Exception:
            return False

    def _generate_msg_id(
        self,
        msg_type: HiveMessageType,
        sender_id: str,
        timestamp: int,
        payload: Dict[str, Any]
    ) -> str:
        """Generate a unique message ID."""
        import hashlib

        # Use existing ID if present
        for id_field in ["request_id", "proposal_id", "assessment_id", "alert_id"]:
            if id_field in payload:
                return f"{msg_type.name}:{payload[id_field]}"

        # Generate from content
        content = f"{msg_type.name}:{sender_id}:{timestamp}"
        return hashlib.sha256(content.encode()).hexdigest()[:32]

    def _store_to_database(self, msg: StoredAIMessage):
        """Store message in database for persistence."""
        try:
            conn = self.database._get_connection()
            cursor = conn.cursor()
            cursor.execute("""
                INSERT OR REPLACE INTO ai_messages
                (msg_id, msg_type, sender_id, timestamp, payload, received_at, processed, process_result)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?)
            """, (
                msg.msg_id,
                int(msg.msg_type),
                msg.sender_id,
                msg.timestamp,
                json.dumps(msg.payload),
                msg.received_at,
                1 if msg.processed else 0,
                msg.process_result,
            ))
            conn.commit()
        except Exception:
            pass  # Best effort storage

    def get_unprocessed(
        self,
        msg_type: Optional[HiveMessageType] = None,
        limit: int = 50
    ) -> List[StoredAIMessage]:
        """
        Get unprocessed messages, optionally filtered by type.

        Args:
            msg_type: Filter by message type (None for all)
            limit: Maximum messages to return

        Returns:
            List of unprocessed messages, oldest first
        """
        with self._lock:
            if msg_type:
                messages = [
                    m for m in self._messages.get(msg_type, [])
                    if not m.processed
                ]
            else:
                messages = []
                for type_messages in self._messages.values():
                    messages.extend(m for m in type_messages if not m.processed)

            # Sort by timestamp (oldest first)
            messages.sort(key=lambda m: m.timestamp)
            return messages[:limit]

    def mark_processed(self, msg_id: str, result: str = "success"):
        """Mark a message as processed."""
        with self._lock:
            for type_messages in self._messages.values():
                for msg in type_messages:
                    if msg.msg_id == msg_id:
                        msg.processed = True
                        msg.process_result = result
                        self._store_to_database(msg)
                        return

    def get_peer_state(self, peer_id: str) -> Optional[Dict[str, Any]]:
        """Get the latest state summary from a peer."""
        with self._lock:
            summaries = self._messages.get(HiveMessageType.AI_STATE_SUMMARY, [])
            peer_summaries = [m for m in summaries if m.sender_id == peer_id]
            if peer_summaries:
                # Return newest
                peer_summaries.sort(key=lambda m: m.timestamp, reverse=True)
                return peer_summaries[0].payload
        return None

    def get_pending_tasks(self, for_node: Optional[str] = None) -> List[StoredAIMessage]:
        """Get pending task requests, optionally for a specific node."""
        with self._lock:
            requests = self._messages.get(HiveMessageType.AI_TASK_REQUEST, [])
            if for_node:
                return [
                    m for m in requests
                    if not m.processed and m.payload.get("target_node") == for_node
                ]
            return [m for m in requests if not m.processed]

    def get_active_proposals(self) -> List[StoredAIMessage]:
        """Get active strategy proposals."""
        with self._lock:
            proposals = self._messages.get(HiveMessageType.AI_STRATEGY_PROPOSAL, [])
            now = time.time()
            return [
                m for m in proposals
                if not m.processed and
                m.payload.get("voting_deadline_timestamp", 0) > now
            ]

    def cleanup_old_messages(self, max_age_seconds: int = 86400):
        """Remove old processed messages."""
        now = time.time()
        cutoff = now - max_age_seconds

        with self._lock:
            for msg_type in self._messages:
                self._messages[msg_type] = [
                    m for m in self._messages[msg_type]
                    if not m.processed or m.received_at > cutoff
                ]

        # Also clean database
        try:
            conn = self.database._get_connection()
            cursor = conn.cursor()
            cursor.execute("""
                DELETE FROM ai_messages
                WHERE processed = 1 AND received_at < ?
            """, (cutoff,))
            conn.commit()
        except Exception:
            pass

    def get_stats(self) -> Dict[str, Any]:
        """Get statistics about stored messages."""
        with self._lock:
            stats = {
                "total_messages": 0,
                "unprocessed": 0,
                "by_type": {},
            }

            for msg_type, messages in self._messages.items():
                type_stats = {
                    "total": len(messages),
                    "unprocessed": len([m for m in messages if not m.processed]),
                }
                stats["by_type"][msg_type.name] = type_stats
                stats["total_messages"] += type_stats["total"]
                stats["unprocessed"] += type_stats["unprocessed"]

            return stats
