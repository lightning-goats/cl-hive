#!/usr/bin/env python3
"""
cl-hive: Distributed Swarm Intelligence for Lightning Node Fleets

This plugin implements "The Hive" protocol, enabling independent Lightning nodes
to function as a coordinated swarm. It provides:
- Zero-cost capital teleportation between fleet members
- Coordinated topology optimization (anti-overlap)
- Distributed immunity via shared ban lists
- Intent Lock protocol for conflict-free coordination

ARCHITECTURE:
-------------
cl-hive is a COORDINATION layer that sits ABOVE cl-revenue-ops.
It uses cl-revenue-ops PolicyManager for fee control (strategy=hive)
and the Strategic Rebalance Exemption for load balancing.

    cl-hive (Coordination)
         │
         ▼
    cl-revenue-ops (Execution)
         │
         ▼
    Core Lightning

DEPENDENCIES:
- cl-revenue-ops v1.4.0+ (PolicyManager with HIVE strategy)
- pyln-client: Core Lightning plugin framework

Author: Lightning Goats Team
License: MIT
"""

import os
import signal
import threading
from typing import Dict, Optional, Any

from pyln.client import Plugin, RpcError

# Import our modules
from modules.config import HiveConfig
from modules.database import HiveDatabase

# Initialize the plugin
plugin = Plugin()

# =============================================================================
# GRACEFUL SHUTDOWN SUPPORT
# =============================================================================
# This event signals all background threads to exit cleanly.
# When `lightning-cli plugin stop cl-hive` is called, CLN sends SIGTERM.

shutdown_event = threading.Event()

# =============================================================================
# THREAD-SAFE RPC WRAPPER
# =============================================================================
# pyln-client's RPC is not inherently thread-safe for concurrent calls.
# This lock serializes all RPC calls to prevent race conditions.

RPC_LOCK = threading.Lock()


class ThreadSafeRpcProxy:
    """
    A thread-safe proxy for the plugin's RPC interface.
    
    Ensures all RPC calls are serialized through a lock, preventing
    race conditions when multiple background threads make concurrent
    calls to lightningd.
    """
    
    def __init__(self, rpc):
        """Wrap the original RPC object."""
        self._rpc = rpc
    
    def __getattr__(self, name):
        """Intercept attribute access to wrap RPC method calls."""
        original_method = getattr(self._rpc, name)
        
        if callable(original_method):
            def thread_safe_method(*args, **kwargs):
                with RPC_LOCK:
                    return original_method(*args, **kwargs)
            return thread_safe_method
        else:
            return original_method
    
    def call(self, method_name, payload=None):
        """Thread-safe wrapper for the generic RPC call method."""
        with RPC_LOCK:
            if payload:
                return self._rpc.call(method_name, payload)
            return self._rpc.call(method_name)


class ThreadSafePluginProxy:
    """
    A proxy for the Plugin object that provides thread-safe RPC access.
    
    Allows modules to use the same interface (self.plugin.rpc.method())
    while ensuring all RPC calls are serialized through the lock.
    """
    
    def __init__(self, plugin):
        """Wrap the original plugin with a thread-safe RPC proxy."""
        self._plugin = plugin
        self.rpc = ThreadSafeRpcProxy(plugin.rpc)
    
    def log(self, message, level='info'):
        """Delegate logging to the original plugin."""
        self._plugin.log(message, level=level)
    
    def __getattr__(self, name):
        """Delegate all other attribute access to the original plugin."""
        return getattr(self._plugin, name)


# =============================================================================
# GLOBAL INSTANCES (initialized in init)
# =============================================================================

database: Optional[HiveDatabase] = None
config: Optional[HiveConfig] = None
safe_plugin: Optional[ThreadSafePluginProxy] = None


# =============================================================================
# PLUGIN OPTIONS
# =============================================================================

plugin.add_option(
    name='hive-db-path',
    default='~/.lightning/cl_hive.db',
    description='Path to the SQLite database for Hive state'
)

plugin.add_option(
    name='hive-governance-mode',
    default='advisor',
    description='Governance mode: advisor (human approval), autonomous (auto-execute), oracle (external API)'
)

plugin.add_option(
    name='hive-neophyte-fee-discount',
    default='0.5',
    description='Fee discount for Neophyte members (0.5 = 50% of public rate)'
)

plugin.add_option(
    name='hive-member-fee-ppm',
    default='0',
    description='Fee charged to full Hive members (default: 0 = free)'
)

plugin.add_option(
    name='hive-probation-days',
    default='30',
    description='Minimum days as Neophyte before promotion eligibility'
)

plugin.add_option(
    name='hive-vouch-threshold',
    default='0.51',
    description='Percentage of member vouches required for promotion (0.51 = 51%)'
)

plugin.add_option(
    name='hive-min-vouch-count',
    default='3',
    description='Minimum number of vouches required for promotion'
)

plugin.add_option(
    name='hive-max-members',
    default='50',
    description='Maximum Hive members (Dunbar cap for gossip efficiency)'
)

plugin.add_option(
    name='hive-market-share-cap',
    default='0.20',
    description='Maximum market share per target (0.20 = 20%, anti-monopoly)'
)

plugin.add_option(
    name='hive-intent-hold-seconds',
    default='60',
    description='Hold period before committing an Intent (conflict resolution)'
)

plugin.add_option(
    name='hive-gossip-threshold',
    default='0.10',
    description='Capacity change threshold to trigger gossip (0.10 = 10%)'
)

plugin.add_option(
    name='hive-heartbeat-interval',
    default='300',
    description='Heartbeat broadcast interval in seconds (default: 5 min)'
)


# =============================================================================
# INITIALIZATION
# =============================================================================

@plugin.init()
def init(options: Dict[str, Any], configuration: Dict[str, Any], plugin: Plugin, **kwargs):
    """
    Initialize the cl-hive plugin.
    
    Steps:
    1. Parse and validate options
    2. Initialize database
    3. Create thread-safe plugin proxy
    4. Verify cl-revenue-ops dependency
    5. Set up signal handlers for graceful shutdown
    """
    global database, config, safe_plugin
    
    plugin.log("cl-hive: Initializing Swarm Intelligence layer...")
    
    # Create thread-safe plugin proxy
    safe_plugin = ThreadSafePluginProxy(plugin)
    
    # Build configuration from options
    config = HiveConfig(
        db_path=options.get('hive-db-path', '~/.lightning/cl_hive.db'),
        governance_mode=options.get('hive-governance-mode', 'advisor'),
        neophyte_fee_discount_pct=float(options.get('hive-neophyte-fee-discount', '0.5')),
        member_fee_ppm=int(options.get('hive-member-fee-ppm', '0')),
        probation_days=int(options.get('hive-probation-days', '30')),
        vouch_threshold_pct=float(options.get('hive-vouch-threshold', '0.51')),
        min_vouch_count=int(options.get('hive-min-vouch-count', '3')),
        max_members=int(options.get('hive-max-members', '50')),
        market_share_cap_pct=float(options.get('hive-market-share-cap', '0.20')),
        intent_hold_seconds=int(options.get('hive-intent-hold-seconds', '60')),
        gossip_threshold_pct=float(options.get('hive-gossip-threshold', '0.10')),
        heartbeat_interval=int(options.get('hive-heartbeat-interval', '300')),
    )
    
    # Initialize database
    database = HiveDatabase(config.db_path, safe_plugin)
    database.initialize()
    plugin.log(f"cl-hive: Database initialized at {config.db_path}")
    
    # Verify cl-revenue-ops dependency (Circuit Breaker pattern)
    try:
        status = safe_plugin.rpc.call("revenue-status")
        version = status.get("version", "unknown")
        plugin.log(f"cl-hive: Found cl-revenue-ops {version}")
        
        # Check minimum version (v1.4.0+ required for Strategic Exemption)
        # For now, just log - full version parsing can be added later
        if "1.4" not in version and "1.5" not in version and "2." not in version:
            plugin.log(
                f"cl-hive: WARNING - cl-revenue-ops {version} may not support HIVE strategy. "
                "Recommended: v1.4.0+",
                level='warn'
            )
    except RpcError as e:
        plugin.log(
            f"cl-hive: WARNING - cl-revenue-ops not detected ({e}). "
            "Hive policy integration will be unavailable.",
            level='warn'
        )
    except Exception as e:
        plugin.log(f"cl-hive: Error checking cl-revenue-ops: {e}", level='warn')
    
    # Set up graceful shutdown handler
    def handle_shutdown_signal(signum, frame):
        plugin.log("cl-hive: Received shutdown signal, cleaning up...")
        shutdown_event.set()
    
    try:
        signal.signal(signal.SIGTERM, handle_shutdown_signal)
        signal.signal(signal.SIGINT, handle_shutdown_signal)
    except Exception as e:
        plugin.log(f"cl-hive: Could not set signal handlers: {e}", level='debug')
    
    plugin.log("cl-hive: Initialization complete. Swarm Intelligence ready.")


# =============================================================================
# RPC COMMANDS
# =============================================================================

@plugin.method("hive-status")
def hive_status(plugin: Plugin):
    """
    Get current Hive status and membership info.
    
    Returns:
        Dict with hive state, member count, governance mode, etc.
    """
    if not database:
        return {"error": "Hive not initialized"}
    
    members = database.get_all_members()
    member_count = len([m for m in members if m['tier'] == 'member'])
    neophyte_count = len([m for m in members if m['tier'] == 'neophyte'])
    admin_count = len([m for m in members if m['tier'] == 'admin'])
    
    return {
        "status": "active" if members else "genesis_required",
        "governance_mode": config.governance_mode if config else "unknown",
        "members": {
            "total": len(members),
            "admin": admin_count,
            "member": member_count,
            "neophyte": neophyte_count,
        },
        "limits": {
            "max_members": config.max_members if config else 50,
            "market_share_cap": config.market_share_cap_pct if config else 0.20,
        },
        "version": "0.1.0-dev",
    }


@plugin.method("hive-members")
def hive_members(plugin: Plugin):
    """
    List all Hive members with their tier and stats.
    
    Returns:
        List of member records with tier, contribution ratio, uptime, etc.
    """
    if not database:
        return {"error": "Hive not initialized"}
    
    members = database.get_all_members()
    return {
        "count": len(members),
        "members": members,
    }


@plugin.method("hive-genesis")
def hive_genesis(plugin: Plugin):
    """
    Initialize this node as the Genesis (Admin) node of a new Hive.
    
    This creates the first member record with admin privileges.
    Can only be called once per Hive.
    
    Returns:
        Dict with genesis status and admin ticket
    """
    if not database or not safe_plugin:
        return {"error": "Hive not initialized"}
    
    # Check if genesis already occurred
    members = database.get_all_members()
    if members:
        return {"error": "Hive already has members. Genesis can only be called once."}
    
    # Get our node ID
    try:
        info = safe_plugin.rpc.getinfo()
        our_id = info.get("id", "")
    except Exception as e:
        return {"error": f"Could not get node info: {e}"}
    
    if not our_id:
        return {"error": "Could not determine node ID"}
    
    # Create admin record
    import time
    now = int(time.time())
    
    database.add_member(
        peer_id=our_id,
        tier='admin',
        joined_at=now,
        promoted_at=now,
    )
    
    plugin.log(f"cl-hive: Genesis complete. Node {our_id[:16]}... is now Hive Admin.")
    
    return {
        "status": "genesis_complete",
        "admin_id": our_id,
        "message": "This node is now the Genesis Admin. Use 'hive-invite' to add members.",
    }


# =============================================================================
# MAIN
# =============================================================================

plugin.run()
