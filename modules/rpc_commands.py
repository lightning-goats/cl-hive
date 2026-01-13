"""
RPC Command Handlers for cl-hive

This module contains the implementation logic for hive-* RPC commands.
The actual @plugin.method() decorators remain in cl-hive.py, which creates
thin wrappers that call these handler functions.

Design Pattern:
    - Each handler receives a HiveContext with all dependencies
    - Handlers are pure functions that can be easily tested
    - Permission checks are done via check_permission() helper
"""

from dataclasses import dataclass
from typing import Any, Dict, Optional


@dataclass
class HiveContext:
    """
    Context object holding all dependencies for RPC command handlers.

    This bundles the global state that commands need access to,
    making dependencies explicit and handlers testable.
    """
    database: Any  # HiveDatabase
    config: Any    # HiveConfig
    safe_plugin: Any  # ThreadSafePluginProxy
    our_pubkey: str
    vpn_transport: Any = None  # VPNTransportManager
    planner: Any = None  # Planner
    quality_scorer: Any = None  # PeerQualityScorer
    bridge: Any = None  # Bridge
    intent_mgr: Any = None  # IntentManager
    membership_mgr: Any = None  # MembershipManager
    coop_expansion_mgr: Any = None  # CooperativeExpansionManager


def check_permission(ctx: HiveContext, required_tier: str) -> Optional[Dict[str, Any]]:
    """
    Check if the local node has the required tier for an RPC command.

    Args:
        ctx: HiveContext with database and our_pubkey
        required_tier: 'admin' or 'member'

    Returns:
        None if permission granted, or error dict if denied
    """
    if not ctx.our_pubkey or not ctx.database:
        return {"error": "Not initialized"}

    member = ctx.database.get_member(ctx.our_pubkey)
    if not member:
        return {"error": "Not a Hive member", "required_tier": required_tier}

    current_tier = member.get('tier', 'neophyte')

    if required_tier == 'admin':
        if current_tier != 'admin':
            return {
                "error": "permission_denied",
                "message": "This command requires admin privileges",
                "current_tier": current_tier,
                "required_tier": "admin"
            }
    elif required_tier == 'member':
        if current_tier not in ('admin', 'member'):
            return {
                "error": "permission_denied",
                "message": "This command requires member or admin privileges",
                "current_tier": current_tier,
                "required_tier": "member"
            }

    return None  # Permission granted


# =============================================================================
# VPN COMMANDS
# =============================================================================

def vpn_status(ctx: HiveContext, peer_id: str = None) -> Dict[str, Any]:
    """
    Get VPN transport status and configuration.

    Shows the current VPN transport mode, configured subnets, peer mappings,
    and which hive members are connected via VPN.

    Args:
        ctx: HiveContext
        peer_id: Optional - Get VPN info for a specific peer

    Returns:
        Dict with VPN transport configuration and status.
    """
    if not ctx.vpn_transport:
        return {"error": "VPN transport not initialized"}

    if peer_id:
        # Get info for specific peer
        peer_info = ctx.vpn_transport.get_peer_vpn_info(peer_id)
        if peer_info:
            return {
                "peer_id": peer_id,
                **peer_info
            }
        return {
            "peer_id": peer_id,
            "message": "No VPN info for this peer"
        }

    # Return full status
    return ctx.vpn_transport.get_status()


def vpn_add_peer(ctx: HiveContext, pubkey: str, vpn_address: str) -> Dict[str, Any]:
    """
    Add or update a VPN peer mapping.

    Maps a node's pubkey to its VPN address for routing hive gossip.

    Args:
        ctx: HiveContext
        pubkey: Node pubkey
        vpn_address: VPN address in format ip:port or just ip (default port 9735)

    Returns:
        Dict with result.

    Permission: Admin only
    """
    # Permission check: Admin only
    perm_error = check_permission(ctx, 'admin')
    if perm_error:
        return perm_error

    if not ctx.vpn_transport:
        return {"error": "VPN transport not initialized"}

    # Parse address
    if ':' in vpn_address:
        ip, port_str = vpn_address.rsplit(':', 1)
        port = int(port_str)
    else:
        ip = vpn_address
        port = 9735

    success = ctx.vpn_transport.add_vpn_peer(pubkey, ip, port)
    if success:
        return {
            "success": True,
            "pubkey": pubkey,
            "vpn_address": f"{ip}:{port}",
            "message": "VPN peer mapping added"
        }
    return {
        "success": False,
        "error": "Failed to add peer - max peers may be reached"
    }


def vpn_remove_peer(ctx: HiveContext, pubkey: str) -> Dict[str, Any]:
    """
    Remove a VPN peer mapping.

    Args:
        ctx: HiveContext
        pubkey: Node pubkey to remove

    Returns:
        Dict with result.

    Permission: Admin only
    """
    # Permission check: Admin only
    perm_error = check_permission(ctx, 'admin')
    if perm_error:
        return perm_error

    if not ctx.vpn_transport:
        return {"error": "VPN transport not initialized"}

    success = ctx.vpn_transport.remove_vpn_peer(pubkey)
    if success:
        return {
            "success": True,
            "pubkey": pubkey,
            "message": "VPN peer mapping removed"
        }
    return {
        "success": False,
        "pubkey": pubkey,
        "message": "Peer not found in VPN mappings"
    }


# =============================================================================
# STATUS/CONFIG COMMANDS
# =============================================================================

def status(ctx: HiveContext) -> Dict[str, Any]:
    """
    Get current Hive status and membership info.

    Returns:
        Dict with hive state, member count, governance mode, etc.
    """
    if not ctx.database:
        return {"error": "Hive not initialized"}

    members = ctx.database.get_all_members()
    member_count = len([m for m in members if m['tier'] == 'member'])
    neophyte_count = len([m for m in members if m['tier'] == 'neophyte'])
    admin_count = len([m for m in members if m['tier'] == 'admin'])

    return {
        "status": "active" if members else "genesis_required",
        "governance_mode": ctx.config.governance_mode if ctx.config else "unknown",
        "members": {
            "total": len(members),
            "admin": admin_count,
            "member": member_count,
            "neophyte": neophyte_count,
        },
        "limits": {
            "max_members": ctx.config.max_members if ctx.config else 50,
            "market_share_cap": ctx.config.market_share_cap_pct if ctx.config else 0.20,
        },
        "version": "0.1.0-dev",
    }


def get_config(ctx: HiveContext) -> Dict[str, Any]:
    """
    Get current Hive configuration values.

    Shows all config options and their current values. Useful for verifying
    hot-reload changes made via `lightning-cli setconfig`.

    Returns:
        Dict with all current config values and metadata.
    """
    if not ctx.config:
        return {"error": "Hive not initialized"}

    return {
        "config_version": ctx.config._version,
        "hot_reload_enabled": True,
        "immutable": {
            "db_path": ctx.config.db_path,
        },
        "governance": {
            "governance_mode": ctx.config.governance_mode,
            "autonomous_budget_per_day": ctx.config.autonomous_budget_per_day,
            "autonomous_actions_per_hour": ctx.config.autonomous_actions_per_hour,
            "oracle_url": ctx.config.oracle_url,
            "oracle_timeout_seconds": ctx.config.oracle_timeout_seconds,
        },
        "membership": {
            "membership_enabled": ctx.config.membership_enabled,
            "auto_vouch_enabled": ctx.config.auto_vouch_enabled,
            "auto_promote_enabled": ctx.config.auto_promote_enabled,
            "ban_autotrigger_enabled": ctx.config.ban_autotrigger_enabled,
            "neophyte_fee_discount_pct": ctx.config.neophyte_fee_discount_pct,
            "member_fee_ppm": ctx.config.member_fee_ppm,
            "probation_days": ctx.config.probation_days,
            "vouch_threshold_pct": ctx.config.vouch_threshold_pct,
            "min_vouch_count": ctx.config.min_vouch_count,
            "max_members": ctx.config.max_members,
        },
        "protocol": {
            "market_share_cap_pct": ctx.config.market_share_cap_pct,
            "intent_hold_seconds": ctx.config.intent_hold_seconds,
            "intent_expire_seconds": ctx.config.intent_expire_seconds,
            "gossip_threshold_pct": ctx.config.gossip_threshold_pct,
            "heartbeat_interval": ctx.config.heartbeat_interval,
        },
        "planner": {
            "planner_interval": ctx.config.planner_interval,
            "planner_enable_expansions": ctx.config.planner_enable_expansions,
            "planner_min_channel_sats": ctx.config.planner_min_channel_sats,
            "planner_max_channel_sats": ctx.config.planner_max_channel_sats,
            "planner_default_channel_sats": ctx.config.planner_default_channel_sats,
        },
        "vpn": ctx.vpn_transport.get_status() if ctx.vpn_transport else {"enabled": False},
    }


def members(ctx: HiveContext) -> Dict[str, Any]:
    """
    List all Hive members with their tier and stats.

    Returns:
        Dict with list of all members and their details.
    """
    if not ctx.database:
        return {"error": "Hive not initialized"}

    all_members = ctx.database.get_all_members()
    return {
        "count": len(all_members),
        "members": all_members,
    }
