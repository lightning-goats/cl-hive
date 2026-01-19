"""
Opportunity Scanner for Proactive AI Advisor

Scans all available data sources to identify optimization opportunities:
- Phase 7.1: Anticipatory Liquidity predictions
- Phase 7.2: Physarum channel lifecycle
- Phase 7.4: Time-based fee optimization
- Revenue-ops: Profitability analysis
- Velocity alerts: Critical depletion/saturation
- Planner analysis: Topology improvements

Usage:
    from opportunity_scanner import OpportunityScanner

    scanner = OpportunityScanner(mcp_client, db)
    opportunities = await scanner.scan_all(node_name, state)
"""

import asyncio
import time
from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum
from typing import Any, Dict, List, Optional, Tuple


# =============================================================================
# Enums and Constants
# =============================================================================

class OpportunityType(Enum):
    """Types of optimization opportunities."""
    # Fee-related
    PEAK_HOUR_FEE = "peak_hour_fee"
    LOW_HOUR_FEE = "low_hour_fee"
    COMPETITOR_UNDERCUT = "competitor_undercut"
    BLEEDER_FIX = "bleeder_fix"
    STAGNANT_CHANNEL = "stagnant_channel"

    # Balance-related
    CRITICAL_DEPLETION = "critical_depletion"
    CRITICAL_SATURATION = "critical_saturation"
    PREEMPTIVE_REBALANCE = "preemptive_rebalance"
    IMBALANCED_CHANNEL = "imbalanced_channel"

    # Config-related
    CONFIG_TUNING = "config_tuning"
    POLICY_CHANGE = "policy_change"

    # Topology
    CHANNEL_OPEN = "channel_open"
    CHANNEL_CLOSE = "channel_close"
    UNDERSERVED_TARGET = "underserved_target"


class ActionType(Enum):
    """Types of actions the advisor can take."""
    FEE_CHANGE = "fee_change"
    REBALANCE = "rebalance"
    CONFIG_CHANGE = "config_change"
    POLICY_CHANGE = "policy_change"
    CHANNEL_OPEN = "channel_open"
    CHANNEL_CLOSE = "channel_close"
    FLAG_FOR_REVIEW = "flag_for_review"


class ActionClassification(Enum):
    """How an action should be handled."""
    AUTO_EXECUTE = "auto_execute"      # Safe to execute automatically
    QUEUE_FOR_REVIEW = "queue_review"  # Queue for human review
    REQUIRE_APPROVAL = "require_approval"  # Must be explicitly approved


# Safety constraints
SAFETY_CONSTRAINTS = {
    # Channel operations ALWAYS require approval
    "channel_open_always_approve": True,
    "channel_close_always_approve": True,

    # Fee bounds
    "absolute_min_fee_ppm": 25,
    "absolute_max_fee_ppm": 5000,
    "max_fee_change_pct_per_cycle": 25,  # Max 25% change per 3h cycle

    # Rebalancing bounds
    "max_rebalance_cost_pct": 2.0,      # Never pay >2% for rebalance
    "max_single_rebalance_sats": 500_000,  # 500k sat cap per operation
    "max_daily_rebalance_spend_sats": 50_000,  # 50k sat daily fee cap

    # On-chain reserve
    "min_onchain_sats": 600_000,        # Always keep 600k on-chain

    # Rate limits per cycle
    "fee_changes_per_cycle": 10,         # Max 10 fee changes per 3h
    "rebalances_per_cycle": 5,           # Max 5 rebalances per 3h

    # Confidence requirements
    "min_confidence_auto_execute": 0.8,
    "min_confidence_for_queue": 0.5,
}


# =============================================================================
# Data Classes
# =============================================================================

@dataclass
class Opportunity:
    """A detected optimization opportunity."""
    opportunity_type: OpportunityType
    action_type: ActionType
    channel_id: Optional[str]
    peer_id: Optional[str]
    node_name: str

    # Scoring
    priority_score: float  # 0-1, higher = more important
    confidence_score: float  # 0-1, higher = more certain
    roi_estimate: float  # Expected return on investment

    # Details
    description: str
    reasoning: str
    recommended_action: str
    predicted_benefit: int  # Estimated benefit in sats

    # Classification
    classification: ActionClassification
    auto_execute_safe: bool

    # Context
    current_state: Dict[str, Any] = field(default_factory=dict)
    detected_at: int = 0

    # Final adjusted scores (set by learning engine)
    final_score: float = 0.0
    adjusted_confidence: float = 0.0
    goal_alignment_bonus: float = 0.0

    def __post_init__(self):
        if self.detected_at == 0:
            self.detected_at = int(time.time())

    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary for serialization."""
        return {
            "opportunity_type": self.opportunity_type.value,
            "action_type": self.action_type.value,
            "channel_id": self.channel_id,
            "peer_id": self.peer_id,
            "node_name": self.node_name,
            "priority_score": round(self.priority_score, 4),
            "confidence_score": round(self.confidence_score, 4),
            "roi_estimate": round(self.roi_estimate, 4),
            "description": self.description,
            "reasoning": self.reasoning,
            "recommended_action": self.recommended_action,
            "predicted_benefit": self.predicted_benefit,
            "classification": self.classification.value,
            "auto_execute_safe": self.auto_execute_safe,
            "final_score": round(self.final_score, 4),
            "adjusted_confidence": round(self.adjusted_confidence, 4),
            "goal_alignment_bonus": round(self.goal_alignment_bonus, 4),
            "detected_at": self.detected_at
        }


# =============================================================================
# Opportunity Scanner
# =============================================================================

class OpportunityScanner:
    """
    Scans all data sources for optimization opportunities.

    Integrates with:
    - Phase 7.1: Anticipatory liquidity predictions
    - Phase 7.2: Physarum channel lifecycle
    - Phase 7.4: Time-based fee optimization
    - Revenue-ops: Profitability analysis
    - Advisor DB: Velocity tracking
    """

    def __init__(self, mcp_client, db):
        """
        Initialize opportunity scanner.

        Args:
            mcp_client: Client for calling MCP tools
            db: AdvisorDB instance
        """
        self.mcp = mcp_client
        self.db = db

    async def scan_all(
        self,
        node_name: str,
        state: Dict[str, Any]
    ) -> List[Opportunity]:
        """
        Scan all data sources and return prioritized opportunities.

        Args:
            node_name: Node to scan
            state: Current node state from analyze_node_state()

        Returns:
            List of Opportunity objects, sorted by priority
        """
        opportunities = []

        # Scan each data source in parallel
        results = await asyncio.gather(
            self._scan_velocity_alerts(node_name, state),
            self._scan_profitability(node_name, state),
            self._scan_time_based_fees(node_name, state),
            self._scan_anticipatory_liquidity(node_name, state),
            self._scan_imbalanced_channels(node_name, state),
            self._scan_config_opportunities(node_name, state),
            return_exceptions=True
        )

        # Collect all opportunities
        for result in results:
            if isinstance(result, Exception):
                # Log but don't fail
                continue
            if result:
                opportunities.extend(result)

        # Sort by priority
        opportunities.sort(key=lambda x: x.priority_score, reverse=True)

        return opportunities

    async def _scan_velocity_alerts(
        self,
        node_name: str,
        state: Dict[str, Any]
    ) -> List[Opportunity]:
        """Scan for critical velocity (depletion/saturation) issues."""
        opportunities = []

        velocities = state.get("velocities", {})
        critical_channels = velocities.get("channels", [])

        for ch in critical_channels:
            channel_id = ch.get("channel_id")
            trend = ch.get("trend")
            hours_until = ch.get("hours_until_depleted") or ch.get("hours_until_full")
            urgency = ch.get("urgency", "low")

            if not hours_until or hours_until > 48:
                continue

            # Critical depletion
            if trend == "depleting" and hours_until < 24:
                priority = 0.95 if hours_until < 6 else 0.85 if hours_until < 12 else 0.7
                opp = Opportunity(
                    opportunity_type=OpportunityType.CRITICAL_DEPLETION,
                    action_type=ActionType.REBALANCE,
                    channel_id=channel_id,
                    peer_id=None,
                    node_name=node_name,
                    priority_score=priority,
                    confidence_score=ch.get("confidence", 0.7),
                    roi_estimate=0.8,  # High ROI - prevents lost routing
                    description=f"Channel {channel_id} depleting in {hours_until:.0f}h",
                    reasoning=f"Velocity {ch.get('velocity_pct_per_hour', 0):.2f}%/h, "
                              f"current balance {ch.get('current_balance_ratio', 0):.0%}",
                    recommended_action="Rebalance to restore outbound liquidity",
                    predicted_benefit=5000,  # Estimated routing saved
                    classification=ActionClassification.AUTO_EXECUTE if hours_until < 12
                                   else ActionClassification.QUEUE_FOR_REVIEW,
                    auto_execute_safe=hours_until < 12 and priority > 0.8,
                    current_state=ch
                )
                opportunities.append(opp)

            # Critical saturation
            elif trend == "filling" and hours_until < 24:
                priority = 0.9 if hours_until < 6 else 0.75 if hours_until < 12 else 0.6
                opp = Opportunity(
                    opportunity_type=OpportunityType.CRITICAL_SATURATION,
                    action_type=ActionType.FEE_CHANGE,
                    channel_id=channel_id,
                    peer_id=None,
                    node_name=node_name,
                    priority_score=priority,
                    confidence_score=ch.get("confidence", 0.7),
                    roi_estimate=0.6,
                    description=f"Channel {channel_id} saturating in {hours_until:.0f}h",
                    reasoning=f"Inbound velocity {abs(ch.get('velocity_pct_per_hour', 0)):.2f}%/h",
                    recommended_action="Reduce fees to encourage outbound flow",
                    predicted_benefit=2000,
                    classification=ActionClassification.AUTO_EXECUTE if hours_until < 12
                                   else ActionClassification.QUEUE_FOR_REVIEW,
                    auto_execute_safe=hours_until < 12,
                    current_state=ch
                )
                opportunities.append(opp)

        return opportunities

    async def _scan_profitability(
        self,
        node_name: str,
        state: Dict[str, Any]
    ) -> List[Opportunity]:
        """Scan for profitability-related opportunities."""
        opportunities = []

        prof_list = state.get("profitability", [])
        dashboard = state.get("dashboard", {})
        bleeders = dashboard.get("bleeder_warnings", [])

        # Bleeder channels need attention
        for bleeder in bleeders:
            channel_id = bleeder.get("channel_id") or bleeder.get("scid")
            if not channel_id:
                continue

            opp = Opportunity(
                opportunity_type=OpportunityType.BLEEDER_FIX,
                action_type=ActionType.POLICY_CHANGE,
                channel_id=channel_id,
                peer_id=bleeder.get("peer_id"),
                node_name=node_name,
                priority_score=0.85,
                confidence_score=0.8,
                roi_estimate=0.9,  # High ROI - stops bleeding
                description=f"Bleeder channel {channel_id} losing money",
                reasoning=f"Consistently negative ROI, needs intervention",
                recommended_action="Apply static fee policy or flag for closure review",
                predicted_benefit=bleeder.get("estimated_loss_sats", 1000),
                classification=ActionClassification.QUEUE_FOR_REVIEW,
                auto_execute_safe=False,
                current_state=bleeder
            )
            opportunities.append(opp)

        # Stagnant channels (100% local, no flow)
        for ch in prof_list:
            if ch.get("balance_ratio", 0) > 0.95 and ch.get("forward_count", 0) == 0:
                channel_id = ch.get("channel_id") or ch.get("scid")
                opp = Opportunity(
                    opportunity_type=OpportunityType.STAGNANT_CHANNEL,
                    action_type=ActionType.FEE_CHANGE,
                    channel_id=channel_id,
                    peer_id=ch.get("peer_id"),
                    node_name=node_name,
                    priority_score=0.6,
                    confidence_score=0.75,
                    roi_estimate=0.5,
                    description=f"Stagnant channel {channel_id} - 100% local, no flow",
                    reasoning="Channel is fully local with no routing activity",
                    recommended_action="Lower fees to attract outbound flow",
                    predicted_benefit=500,
                    classification=ActionClassification.AUTO_EXECUTE,
                    auto_execute_safe=True,
                    current_state=ch
                )
                opportunities.append(opp)

        return opportunities

    async def _scan_time_based_fees(
        self,
        node_name: str,
        state: Dict[str, Any]
    ) -> List[Opportunity]:
        """Scan for time-based fee optimization opportunities (Phase 7.4)."""
        opportunities = []

        # Get current hour and check for patterns
        current_hour = datetime.now().hour

        channels = state.get("channels", [])

        for ch in channels:
            channel_id = ch.get("short_channel_id") or ch.get("channel_id")
            if not channel_id:
                continue

            # Get channel history to detect patterns
            history = self.db.get_channel_history(node_name, channel_id, hours=168)  # 1 week

            if len(history) < 24:  # Need at least 24 data points
                continue

            # Simple pattern detection - look for consistent flow at certain hours
            hour_flows = {}
            for h in history:
                ts = h.get("timestamp", 0)
                if ts:
                    hour = datetime.fromtimestamp(ts).hour
                    if hour not in hour_flows:
                        hour_flows[hour] = []
                    hour_flows[hour].append(h.get("forward_count", 0))

            # Check if current hour is typically high or low activity
            if current_hour in hour_flows and len(hour_flows[current_hour]) >= 3:
                avg_current = sum(hour_flows[current_hour]) / len(hour_flows[current_hour])
                all_averages = [sum(v) / len(v) for v in hour_flows.values() if len(v) >= 3]

                if all_averages:
                    overall_avg = sum(all_averages) / len(all_averages)

                    # Peak hour: higher than average
                    if avg_current > overall_avg * 1.3:
                        opp = Opportunity(
                            opportunity_type=OpportunityType.PEAK_HOUR_FEE,
                            action_type=ActionType.FEE_CHANGE,
                            channel_id=channel_id,
                            peer_id=ch.get("peer_id"),
                            node_name=node_name,
                            priority_score=0.65,
                            confidence_score=min(0.9, len(hour_flows[current_hour]) / 10),
                            roi_estimate=0.7,
                            description=f"Peak hour detected for channel {channel_id}",
                            reasoning=f"Hour {current_hour} activity {avg_current:.0f} vs avg {overall_avg:.0f}",
                            recommended_action="Temporarily increase fees (+15-25%)",
                            predicted_benefit=int(avg_current * 0.2),
                            classification=ActionClassification.AUTO_EXECUTE,
                            auto_execute_safe=True,
                            current_state={"hour": current_hour, "avg_flow": avg_current}
                        )
                        opportunities.append(opp)

                    # Low hour: lower than average
                    elif avg_current < overall_avg * 0.5:
                        opp = Opportunity(
                            opportunity_type=OpportunityType.LOW_HOUR_FEE,
                            action_type=ActionType.FEE_CHANGE,
                            channel_id=channel_id,
                            peer_id=ch.get("peer_id"),
                            node_name=node_name,
                            priority_score=0.5,
                            confidence_score=min(0.85, len(hour_flows[current_hour]) / 10),
                            roi_estimate=0.4,
                            description=f"Low activity hour for channel {channel_id}",
                            reasoning=f"Hour {current_hour} activity {avg_current:.0f} vs avg {overall_avg:.0f}",
                            recommended_action="Temporarily decrease fees (-10-15%) to attract flow",
                            predicted_benefit=int(overall_avg * 0.1),
                            classification=ActionClassification.AUTO_EXECUTE,
                            auto_execute_safe=True,
                            current_state={"hour": current_hour, "avg_flow": avg_current}
                        )
                        opportunities.append(opp)

        return opportunities

    async def _scan_anticipatory_liquidity(
        self,
        node_name: str,
        state: Dict[str, Any]
    ) -> List[Opportunity]:
        """Scan for anticipatory liquidity opportunities (Phase 7.1)."""
        opportunities = []

        # Get predictions from context if available
        context = state.get("context", {})
        predictions = context.get("liquidity_predictions", [])

        for pred in predictions:
            channel_id = pred.get("channel_id")
            hours_ahead = pred.get("hours_ahead", 24)
            depletion_risk = pred.get("depletion_risk", 0)
            saturation_risk = pred.get("saturation_risk", 0)
            recommended_action = pred.get("recommended_action", "monitor")

            if recommended_action == "preemptive_rebalance" and depletion_risk > 0.5:
                opp = Opportunity(
                    opportunity_type=OpportunityType.PREEMPTIVE_REBALANCE,
                    action_type=ActionType.REBALANCE,
                    channel_id=channel_id,
                    peer_id=pred.get("peer_id"),
                    node_name=node_name,
                    priority_score=0.6 + depletion_risk * 0.3,
                    confidence_score=pred.get("confidence", 0.6),
                    roi_estimate=0.65,
                    description=f"Preemptive rebalance recommended for {channel_id}",
                    reasoning=f"Predicted depletion in {hours_ahead}h with {depletion_risk:.0%} risk",
                    recommended_action="Rebalance before predicted depletion",
                    predicted_benefit=3000,
                    classification=ActionClassification.QUEUE_FOR_REVIEW,
                    auto_execute_safe=False,
                    current_state=pred
                )
                opportunities.append(opp)

        return opportunities

    async def _scan_imbalanced_channels(
        self,
        node_name: str,
        state: Dict[str, Any]
    ) -> List[Opportunity]:
        """Scan for imbalanced channels needing attention."""
        opportunities = []

        channels = state.get("channels", [])

        for ch in channels:
            channel_id = ch.get("short_channel_id") or ch.get("channel_id")
            if not channel_id:
                continue

            local_msat = ch.get("to_us_msat", 0)
            if isinstance(local_msat, str):
                local_msat = int(local_msat.replace("msat", ""))
            capacity_msat = ch.get("total_msat", 0)
            if isinstance(capacity_msat, str):
                capacity_msat = int(capacity_msat.replace("msat", ""))

            if capacity_msat == 0:
                continue

            balance_ratio = local_msat / capacity_msat

            # Very imbalanced (< 15% or > 85%)
            if balance_ratio < 0.15 or balance_ratio > 0.85:
                direction = "depleted" if balance_ratio < 0.15 else "saturated"
                opp = Opportunity(
                    opportunity_type=OpportunityType.IMBALANCED_CHANNEL,
                    action_type=ActionType.REBALANCE if balance_ratio < 0.3 else ActionType.FEE_CHANGE,
                    channel_id=channel_id,
                    peer_id=ch.get("peer_id"),
                    node_name=node_name,
                    priority_score=0.55 if 0.15 <= balance_ratio <= 0.85 else 0.7,
                    confidence_score=0.85,
                    roi_estimate=0.5,
                    description=f"Channel {channel_id} is {direction} ({balance_ratio:.0%} local)",
                    reasoning=f"Balance {balance_ratio:.0%} is far from ideal 50%",
                    recommended_action="Rebalance" if balance_ratio < 0.3 else "Adjust fees to attract outflow",
                    predicted_benefit=1500,
                    classification=ActionClassification.QUEUE_FOR_REVIEW,
                    auto_execute_safe=False,
                    current_state={"balance_ratio": balance_ratio}
                )
                opportunities.append(opp)

        return opportunities

    async def _scan_config_opportunities(
        self,
        node_name: str,
        state: Dict[str, Any]
    ) -> List[Opportunity]:
        """Scan for configuration tuning opportunities."""
        opportunities = []

        summary = state.get("summary", {})
        dashboard = state.get("dashboard", {})

        # If many underwater channels, suggest config changes
        underwater_pct = summary.get("underwater_pct", 0)
        if underwater_pct > 40:
            opp = Opportunity(
                opportunity_type=OpportunityType.CONFIG_TUNING,
                action_type=ActionType.CONFIG_CHANGE,
                channel_id=None,
                peer_id=None,
                node_name=node_name,
                priority_score=0.7,
                confidence_score=0.75,
                roi_estimate=0.6,
                description=f"High underwater channel rate ({underwater_pct:.0f}%)",
                reasoning="Many channels unprofitable - review fee controller settings",
                recommended_action="Consider increasing hill_climbing_aggression or min_fee_ppm",
                predicted_benefit=5000,
                classification=ActionClassification.QUEUE_FOR_REVIEW,
                auto_execute_safe=False,
                current_state={"underwater_pct": underwater_pct}
            )
            opportunities.append(opp)

        # If ROC is very low, suggest config review
        roc_pct = summary.get("roc_pct", 0)
        if roc_pct < 0.1:
            opp = Opportunity(
                opportunity_type=OpportunityType.CONFIG_TUNING,
                action_type=ActionType.CONFIG_CHANGE,
                channel_id=None,
                peer_id=None,
                node_name=node_name,
                priority_score=0.65,
                confidence_score=0.7,
                roi_estimate=0.7,
                description=f"Very low ROC ({roc_pct:.2f}%)",
                reasoning="Return on capital below sustainable threshold",
                recommended_action="Review overall fee strategy and channel selection",
                predicted_benefit=10000,
                classification=ActionClassification.QUEUE_FOR_REVIEW,
                auto_execute_safe=False,
                current_state={"roc_pct": roc_pct}
            )
            opportunities.append(opp)

        return opportunities

    def classify_opportunity(self, opp: Opportunity) -> ActionClassification:
        """
        Classify an opportunity for appropriate handling.

        Args:
            opp: Opportunity to classify

        Returns:
            ActionClassification indicating how to handle
        """
        # Channel operations always require approval
        if opp.action_type in [ActionType.CHANNEL_OPEN, ActionType.CHANNEL_CLOSE]:
            return ActionClassification.REQUIRE_APPROVAL

        # High confidence + safe action type = auto execute
        if (opp.confidence_score >= SAFETY_CONSTRAINTS["min_confidence_auto_execute"]
            and opp.auto_execute_safe):
            return ActionClassification.AUTO_EXECUTE

        # Medium confidence = queue for review
        if opp.confidence_score >= SAFETY_CONSTRAINTS["min_confidence_for_queue"]:
            return ActionClassification.QUEUE_FOR_REVIEW

        # Low confidence = require explicit approval
        return ActionClassification.REQUIRE_APPROVAL

    def filter_safe_opportunities(
        self,
        opportunities: List[Opportunity]
    ) -> Tuple[List[Opportunity], List[Opportunity], List[Opportunity]]:
        """
        Separate opportunities by safety classification.

        Returns:
            Tuple of (auto_execute, queue_review, require_approval) lists
        """
        auto_execute = []
        queue_review = []
        require_approval = []

        for opp in opportunities:
            classification = self.classify_opportunity(opp)
            opp.classification = classification

            if classification == ActionClassification.AUTO_EXECUTE:
                auto_execute.append(opp)
            elif classification == ActionClassification.QUEUE_FOR_REVIEW:
                queue_review.append(opp)
            else:
                require_approval.append(opp)

        return auto_execute, queue_review, require_approval
