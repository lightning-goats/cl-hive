#!/usr/bin/env python3
"""
Test script for the new member onboarding scanner.

This script:
1. Gathers hive member data from Polar nodes
2. Simulates the opportunity scanner's new member detection
3. Shows what channel recommendations would be generated

Usage:
    python3 test_onboarding_scanner.py
"""

import asyncio
import json
import subprocess
import sys
import time
from dataclasses import dataclass
from enum import Enum
from typing import Any, Dict, List, Optional

# Add tools directory to path
sys.path.insert(0, '/home/sat/cl-hive/tools')

from advisor_db import AdvisorDB


class OpportunityType(str, Enum):
    NEW_MEMBER_CHANNEL = "new_member_channel"


class ActionType(str, Enum):
    CHANNEL_OPEN = "channel_open"


@dataclass
class Opportunity:
    opportunity_type: OpportunityType
    action_type: ActionType
    peer_id: str
    node_name: str
    priority_score: float
    confidence_score: float
    description: str
    reasoning: str
    suggested_action: str


def run_cli(node: str, command: str) -> dict:
    """Run lightning-cli command on a Polar node."""
    full_cmd = [
        "docker", "exec", f"polar-n1-{node}",
        "lightning-cli",
        "--lightning-dir=/home/clightning/.lightning",
        "--network=regtest",
        command
    ]
    try:
        result = subprocess.run(full_cmd, capture_output=True, text=True, timeout=30)
        if result.returncode == 0:
            return json.loads(result.stdout)
        else:
            print(f"  Error on {node}: {result.stderr[:100]}")
            return {}
    except Exception as e:
        print(f"  Exception on {node}: {e}")
        return {}


def gather_state(node: str) -> Dict[str, Any]:
    """Gather node state for the scanner."""
    print(f"Gathering state from {node}...")

    state = {}

    # Get node info
    node_info = run_cli(node, "getinfo")
    state["node_info"] = node_info

    # Get hive members
    hive_members = run_cli(node, "hive-members")
    state["hive_members"] = hive_members

    # Get channels
    channels = run_cli(node, "listpeerchannels")
    state["channels"] = channels.get("channels", [])

    # Get expansion recommendations for strategic targets
    expansion = run_cli(node, "hive-expansion-recommendations")
    state["expansion_recommendations"] = expansion.get("recommendations", [])

    return state


def scan_new_member_opportunities(
    node_name: str,
    state: Dict[str, Any],
    db: AdvisorDB
) -> List[Opportunity]:
    """
    Scan for new hive member onboarding opportunities.

    This is a simplified version of the scanner for testing.
    """
    opportunities = []

    # Get hive members from state
    hive_members = state.get("hive_members", {})
    members_list = hive_members.get("members", [])

    if not members_list:
        print("  No hive members found in state")
        return opportunities

    print(f"  Found {len(members_list)} hive members")

    # Get our node's pubkey
    node_info = state.get("node_info", {})
    our_pubkey = node_info.get("id", "")
    print(f"  Our pubkey: {our_pubkey[:16]}...")

    # Get existing channels to understand current topology
    channels = state.get("channels", [])
    our_peers = set()
    for ch in channels:
        peer_id = ch.get("peer_id")
        if peer_id:
            our_peers.add(peer_id)
    print(f"  We have channels to {len(our_peers)} peers")

    # Get expansion recommendations for strategic targets
    expansion_recs = state.get("expansion_recommendations", [])
    strategic_targets = [r.get("target_full") for r in expansion_recs[:5]]

    # Check for recently joined members (neophytes or recently promoted)
    for member in members_list:
        member_pubkey = member.get("pubkey") or member.get("peer_id")
        tier = member.get("tier", "unknown")
        joined_at = member.get("joined_at", 0)

        if not member_pubkey:
            continue

        # Skip ourselves
        if member_pubkey == our_pubkey:
            continue

        # Check if this is a new member (neophyte or recently joined)
        is_neophyte = tier == "neophyte"
        is_recent = False
        if joined_at:
            age_days = (time.time() - joined_at) / 86400
            is_recent = age_days < 30  # Joined in last 30 days

        print(f"  Checking {member_pubkey[:16]}... tier={tier}, neophyte={is_neophyte}, recent={is_recent}")

        # Skip if not new
        if not is_neophyte and not is_recent:
            print(f"    -> Skipping (not new)")
            continue

        # Check if already onboarded (using advisor DB)
        onboard_key = f"onboarded_{member_pubkey[:16]}"
        if db.get_metadata(onboard_key):
            print(f"    -> Already onboarded")
            continue

        # Check if we already have a channel to this member
        if member_pubkey in our_peers:
            print(f"    -> We have a channel to them")

            # Suggest strategic openings FOR them
            for target in strategic_targets[:2]:
                if target and target != member_pubkey:
                    opp = Opportunity(
                        opportunity_type=OpportunityType.NEW_MEMBER_CHANNEL,
                        action_type=ActionType.CHANNEL_OPEN,
                        peer_id=target,
                        node_name=node_name,
                        priority_score=0.6,
                        confidence_score=0.7,
                        description=f"New member {member_pubkey[:16]}... should open channel to strategic target {target[:16]}...",
                        reasoning="Helps new member integrate with fleet topology",
                        suggested_action=f"Suggest {member_pubkey[:16]}... opens 2M sat channel to {target[:16]}..."
                    )
                    opportunities.append(opp)
        else:
            print(f"    -> We DON'T have a channel to them - OPPORTUNITY!")

            # We don't have a channel to this new member - suggest opening one
            opp = Opportunity(
                opportunity_type=OpportunityType.NEW_MEMBER_CHANNEL,
                action_type=ActionType.CHANNEL_OPEN,
                peer_id=member_pubkey,
                node_name=node_name,
                priority_score=0.7,
                confidence_score=0.8,
                description=f"Open channel to new hive member {member_pubkey[:16]}... ({tier})",
                reasoning=f"New {tier} member needs fleet connectivity",
                suggested_action=f"Open 2,000,000 sat channel to {member_pubkey[:16]}..."
            )
            opportunities.append(opp)

    return opportunities


def main():
    print("=" * 60)
    print("NEW MEMBER ONBOARDING SCANNER TEST")
    print("=" * 60)
    print()

    # Initialize advisor DB
    db = AdvisorDB('/home/sat/cl-hive/tools/advisor.db')

    # Test from each hive member's perspective
    nodes = ["alice", "bob", "carol", "dave"]

    all_opportunities = []

    for node in nodes:
        print()
        print(f"{'=' * 60}")
        print(f"SCANNING FROM {node.upper()}'s PERSPECTIVE")
        print(f"{'=' * 60}")

        state = gather_state(node)
        opportunities = scan_new_member_opportunities(node, state, db)

        print()
        print(f"  Found {len(opportunities)} opportunities:")
        for opp in opportunities:
            print(f"    - {opp.description}")
            print(f"      Action: {opp.suggested_action}")
            print(f"      Priority: {opp.priority_score:.2f}, Confidence: {opp.confidence_score:.2f}")

        all_opportunities.extend(opportunities)

    print()
    print("=" * 60)
    print("SUMMARY")
    print("=" * 60)
    print(f"Total opportunities found: {len(all_opportunities)}")

    # Group by peer
    by_peer = {}
    for opp in all_opportunities:
        if opp.peer_id not in by_peer:
            by_peer[opp.peer_id] = []
        by_peer[opp.peer_id].append(opp)

    print()
    print("Opportunities by target peer:")
    for peer_id, opps in by_peer.items():
        print(f"  {peer_id[:16]}...: {len(opps)} suggestions")
        for opp in opps:
            print(f"    - From {opp.node_name}: {opp.description}")


if __name__ == "__main__":
    main()
