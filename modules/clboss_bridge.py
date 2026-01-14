"""
CLBoss Bridge Module for cl-hive (Optional Integration).

CLBoss is NOT required for cl-hive to function. This module provides optional
integration with CLBoss when it is installed.

If CLBoss IS installed (ksedgwic/clboss fork):
- Detect availability from plugin list
- Unmanage peers to prevent CLBoss channel opens to saturated targets
- Coordinate with cl-revenue-ops for fee/rebalance management

If CLBoss is NOT installed:
- All methods gracefully return False or empty results
- Hive uses native cooperative expansion for topology management
- No warnings or errors are logged

CLBoss Management Tags (ksedgwic/clboss fork):
- open: Channel opening (managed by cl-hive)
- close: Channel closing
- lnfee: Fee management (delegated to cl-revenue-ops)
- balance: Rebalancing (delegated to cl-revenue-ops)
"""

from typing import Any, Dict, List, Optional

from pyln.client import RpcError


# CLBoss management tags (ksedgwic/clboss fork)
class ClbossTags:
    """CLBoss management tags for clboss-unmanage/clboss-manage commands."""
    OPEN = "open"      # Channel opening
    CLOSE = "close"    # Channel closing
    FEE = "lnfee"      # Fee management (handled by cl-revenue-ops)
    BALANCE = "balance"  # Rebalancing (handled by cl-revenue-ops)


class CLBossBridge:
    """Gateway wrapper around CLBoss RPC calls.

    Uses the ksedgwic/clboss fork which provides:
    - clboss-unmanage <nodeid> <tags>: Stop managing peer for specified tags
    - clboss-manage <nodeid> <tags>: Resume managing peer for specified tags
    - clboss-status: Get CLBoss status
    - clboss-unmanaged-list: List unmanaged peers

    The Hive primarily uses the 'open' tag to prevent CLBoss from opening
    channels to saturated targets. Fee/balance tags are managed by cl-revenue-ops.
    """

    def __init__(self, rpc, plugin=None):
        self.rpc = rpc
        self.plugin = plugin
        self._available = False
        self._supports_unmanage = True  # Assume true until proven otherwise

    def _log(self, msg: str, level: str = "info") -> None:
        if self.plugin:
            self.plugin.log(f"[CLBossBridge] {msg}", level=level)

    def detect_clboss(self) -> bool:
        """Detect whether CLBoss is registered and active."""
        try:
            plugins = self.rpc.plugin("list")
            for entry in plugins.get("plugins", []):
                if "clboss" in entry.get("name", "").lower():
                    self._available = entry.get("active", False)
                    if self._available:
                        self._log("CLBoss detected and available")
                    return self._available
            self._available = False
            return False
        except Exception as exc:
            self._available = False
            self._log(f"CLBoss detection failed: {exc}", level="warn")
            return False

    def unmanage_open(self, peer_id: str) -> bool:
        """Tell CLBoss to stop opening channels to this peer.

        This is used to prevent CLBoss from opening channels to saturated
        targets where the Hive already has sufficient capacity.

        Args:
            peer_id: The node ID to unmanage

        Returns:
            True if successful, False otherwise
        """
        return self._unmanage(peer_id, ClbossTags.OPEN)

    def manage_open(self, peer_id: str) -> bool:
        """Tell CLBoss to resume opening channels to this peer.

        Called when a target is no longer saturated.
        Uses clboss-unmanage with empty string to restore full management,
        as clboss-manage may not exist in all versions.

        Args:
            peer_id: The node ID to re-manage

        Returns:
            True if successful, False otherwise
        """
        # Per CLBoss docs, empty string restores full management
        # This is more compatible than clboss-manage which may not exist
        return self._unmanage(peer_id, "")

    def _unmanage(self, peer_id: str, tags: str) -> bool:
        """Tell CLBoss to stop managing a peer for specified tags.

        Args:
            peer_id: The node ID
            tags: Comma-separated tags (open, close, lnfee, balance)

        Returns:
            True if successful or already unmanaged
        """
        if not self._available:
            self._log(f"CLBoss not available, cannot unmanage {peer_id[:16]}...")
            return False

        if not self._supports_unmanage:
            return False

        try:
            # Use positional args: nodeid, tags
            self.rpc.call("clboss-unmanage", [peer_id, tags])
            self._log(f"CLBoss unmanage {peer_id[:16]}... for '{tags}'")
            return True
        except RpcError as exc:
            msg = str(exc).lower()
            if "unknown command" in msg or "method not found" in msg:
                self._supports_unmanage = False
                self._log("CLBoss does not support clboss-unmanage", level="warn")
            elif "not managed" in msg or "already unmanaged" in msg:
                # Already unmanaged - that's fine
                return True
            else:
                self._log(f"CLBoss unmanage failed: {exc}", level="warn")
            return False

    def _manage(self, peer_id: str, tags: str) -> bool:
        """Tell CLBoss to resume managing a peer for specified tags.

        Args:
            peer_id: The node ID
            tags: Comma-separated tags (open, close, lnfee, balance)

        Returns:
            True if successful or already managed
        """
        if not self._available or not self._supports_unmanage:
            return False

        try:
            # Use positional args: nodeid, tags
            self.rpc.call("clboss-manage", [peer_id, tags])
            self._log(f"CLBoss manage {peer_id[:16]}... for '{tags}'")
            return True
        except RpcError as exc:
            msg = str(exc).lower()
            if "already managed" in msg:
                return True
            self._log(f"CLBoss manage failed: {exc}", level="warn")
            return False

    def get_unmanaged_list(self) -> List[Dict[str, Any]]:
        """Get list of peers currently unmanaged by CLBoss.

        Returns:
            List of unmanaged peer entries, or empty list if unavailable
        """
        if not self._available:
            return []

        try:
            result = self.rpc.call("clboss-unmanaged-list")
            return result.get("unmanaged", [])
        except RpcError:
            return []

    def supports_unmanage(self) -> bool:
        """Check if CLBoss supports the unmanage commands.

        Returns:
            True if clboss-unmanage is available
        """
        return self._available and self._supports_unmanage

    def get_status(self) -> Dict[str, Any]:
        """Get CLBoss bridge status for diagnostics."""
        if not self._available:
            return {
                "clboss_installed": False,
                "note": "CLBoss not installed (optional) - using native expansion control",
                "coordination_method": "native_cooperative_expansion"
            }

        status = {
            "clboss_installed": True,
            "clboss_available": self._available,
            "supports_unmanage": self._supports_unmanage,
            "coordination_method": "clboss-unmanage" if self._supports_unmanage else "intent_lock_only"
        }

        try:
            clboss_status = self.rpc.call("clboss-status")
            status["clboss_version"] = clboss_status.get("info", {}).get("version", "unknown")
        except RpcError:
            status["clboss_version"] = "unknown"

        return status


# Legacy compatibility aliases
def ignore_peer(bridge: CLBossBridge, peer_id: str) -> bool:
    """Legacy alias for unmanage_open. Deprecated."""
    return bridge.unmanage_open(peer_id)


def unignore_peer(bridge: CLBossBridge, peer_id: str) -> bool:
    """Legacy alias for manage_open. Deprecated."""
    return bridge.manage_open(peer_id)
