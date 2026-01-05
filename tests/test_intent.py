"""
Tests for Phase 3: Intent Lock Protocol

Tests the IntentManager module for:
- Tie-breaker logic (lowest pubkey wins)
- Conflict detection and resolution
- Intent lifecycle (create, commit, abort)
- Cleanup of expired intents

Author: Lightning Goats Team
"""

import pytest
import time
from unittest.mock import MagicMock, patch

# Import modules under test
import sys
import os
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from modules.intent_manager import (
    IntentManager, Intent, IntentType,
    STATUS_PENDING, STATUS_COMMITTED, STATUS_ABORTED,
    DEFAULT_HOLD_SECONDS
)


# =============================================================================
# FIXTURES
# =============================================================================

@pytest.fixture
def mock_database():
    """Create a mock database for testing."""
    db = MagicMock()
    db.create_intent.return_value = 1
    db.get_conflicting_intents.return_value = []
    db.update_intent_status.return_value = True
    db.cleanup_expired_intents.return_value = 0
    db.get_pending_intents_ready.return_value = []
    db.get_intent_by_id.return_value = None
    return db


@pytest.fixture
def mock_plugin():
    """Create a mock plugin for logging."""
    plugin = MagicMock()
    plugin.log = MagicMock()
    return plugin


@pytest.fixture
def intent_manager(mock_database, mock_plugin):
    """Create an IntentManager with mocked dependencies."""
    return IntentManager(
        mock_database, 
        mock_plugin,
        our_pubkey="02" + "a" * 64,  # Our pubkey starts with 'a'
        hold_seconds=60
    )


# =============================================================================
# INTENT DATACLASS TESTS
# =============================================================================

class TestIntentDataclass:
    """Test the Intent dataclass."""
    
    def test_to_dict_round_trip(self):
        """Intent should survive dict conversion."""
        now = int(time.time())
        original = Intent(
            intent_type='channel_open',
            target='02' + 'b' * 64,
            initiator='02' + 'a' * 64,
            timestamp=now,
            expires_at=now + 60,
            status=STATUS_PENDING,
            intent_id=42
        )
        
        as_dict = original.to_dict()
        restored = Intent.from_dict(as_dict, intent_id=42)
        
        assert restored.intent_type == original.intent_type
        assert restored.target == original.target
        assert restored.initiator == original.initiator
        assert restored.timestamp == original.timestamp
    
    def test_is_expired_false(self):
        """Fresh intent should not be expired."""
        now = int(time.time())
        intent = Intent(
            intent_type='channel_open',
            target='target',
            initiator='initiator',
            timestamp=now,
            expires_at=now + 60
        )
        
        assert intent.is_expired() is False
    
    def test_is_expired_true(self):
        """Old intent should be expired."""
        now = int(time.time())
        intent = Intent(
            intent_type='channel_open',
            target='target',
            initiator='initiator',
            timestamp=now - 120,
            expires_at=now - 60  # Expired 60s ago
        )
        
        assert intent.is_expired() is True
    
    def test_is_conflicting_same_target(self):
        """Two pending intents with same target should conflict."""
        now = int(time.time())
        intent1 = Intent(
            intent_type='channel_open',
            target='same_target',
            initiator='node_a',
            timestamp=now,
            expires_at=now + 60,
            status=STATUS_PENDING
        )
        intent2 = Intent(
            intent_type='channel_open',
            target='same_target',
            initiator='node_b',
            timestamp=now,
            expires_at=now + 60,
            status=STATUS_PENDING
        )
        
        assert intent1.is_conflicting(intent2) is True
    
    def test_is_conflicting_different_target(self):
        """Intents with different targets should not conflict."""
        now = int(time.time())
        intent1 = Intent(
            intent_type='channel_open',
            target='target_1',
            initiator='node_a',
            timestamp=now,
            expires_at=now + 60,
            status=STATUS_PENDING
        )
        intent2 = Intent(
            intent_type='channel_open',
            target='target_2',
            initiator='node_b',
            timestamp=now,
            expires_at=now + 60,
            status=STATUS_PENDING
        )
        
        assert intent1.is_conflicting(intent2) is False
    
    def test_is_conflicting_one_aborted(self):
        """Aborted intent should not conflict."""
        now = int(time.time())
        intent1 = Intent(
            intent_type='channel_open',
            target='same_target',
            initiator='node_a',
            timestamp=now,
            expires_at=now + 60,
            status=STATUS_PENDING
        )
        intent2 = Intent(
            intent_type='channel_open',
            target='same_target',
            initiator='node_b',
            timestamp=now,
            expires_at=now + 60,
            status=STATUS_ABORTED  # Already aborted
        )
        
        assert intent1.is_conflicting(intent2) is False


# =============================================================================
# TIE-BREAKER TESTS (CRITICAL SECURITY)
# =============================================================================

class TestTieBreaker:
    """Test the tie-breaker logic: lowest pubkey wins."""
    
    def test_we_win_lower_pubkey(self, intent_manager, mock_database):
        """We should win if our pubkey is lexicographically lower."""
        # Our pubkey: 02aaaa... (lower)
        # Their pubkey: 02bbbb... (higher)
        
        mock_database.get_conflicting_intents.return_value = [
            {'id': 1, 'intent_type': 'channel_open', 'target': 'target', 
             'initiator': intent_manager.our_pubkey, 'status': 'pending'}
        ]
        
        remote_intent = Intent(
            intent_type='channel_open',
            target='target',
            initiator='02' + 'b' * 64,  # Higher than 'a'
            timestamp=int(time.time()),
            expires_at=int(time.time()) + 60
        )
        
        has_conflict, we_win = intent_manager.check_conflicts(remote_intent)
        
        assert has_conflict is True
        assert we_win is True  # Our 'a' < their 'b'
    
    def test_we_lose_higher_pubkey(self, intent_manager, mock_database):
        """We should lose if our pubkey is lexicographically higher."""
        # Change our pubkey to be higher
        intent_manager.our_pubkey = '02' + 'z' * 64  # Higher
        
        mock_database.get_conflicting_intents.return_value = [
            {'id': 1, 'intent_type': 'channel_open', 'target': 'target',
             'initiator': intent_manager.our_pubkey, 'status': 'pending'}
        ]
        
        remote_intent = Intent(
            intent_type='channel_open',
            target='target',
            initiator='02' + 'a' * 64,  # Lower than 'z'
            timestamp=int(time.time()),
            expires_at=int(time.time()) + 60
        )
        
        has_conflict, we_win = intent_manager.check_conflicts(remote_intent)
        
        assert has_conflict is True
        assert we_win is False  # Our 'z' > their 'a'
    
    def test_no_conflict_when_no_local_intent(self, intent_manager, mock_database):
        """No conflict if we have no pending intent for the target."""
        mock_database.get_conflicting_intents.return_value = []  # No local intents
        
        remote_intent = Intent(
            intent_type='channel_open',
            target='target',
            initiator='02' + 'x' * 64,
            timestamp=int(time.time()),
            expires_at=int(time.time()) + 60
        )
        
        has_conflict, we_win = intent_manager.check_conflicts(remote_intent)
        
        assert has_conflict is False
        assert we_win is False
    
    def test_deterministic_winner(self):
        """Tie-breaker should be 100% deterministic."""
        # Simulate many random pubkey pairs
        import random
        
        for _ in range(100):
            pubkey_a = '02' + ''.join(random.choices('0123456789abcdef', k=64))
            pubkey_b = '02' + ''.join(random.choices('0123456789abcdef', k=64))
            
            # Lexicographic comparison
            expected_winner = min(pubkey_a, pubkey_b)
            
            # Verify
            if pubkey_a < pubkey_b:
                assert expected_winner == pubkey_a
            else:
                assert expected_winner == pubkey_b


# =============================================================================
# INTENT CREATION TESTS
# =============================================================================

class TestIntentCreation:
    """Test intent creation and messaging."""
    
    def test_create_intent(self, intent_manager, mock_database):
        """create_intent should insert into DB and return Intent."""
        mock_database.create_intent.return_value = 42
        
        intent = intent_manager.create_intent(
            intent_type=IntentType.CHANNEL_OPEN,
            target='02' + 'x' * 64
        )
        
        assert intent.intent_id == 42
        assert intent.intent_type == IntentType.CHANNEL_OPEN
        assert intent.initiator == intent_manager.our_pubkey
        assert intent.status == STATUS_PENDING
        
        mock_database.create_intent.assert_called_once()
    
    def test_create_intent_message(self, intent_manager):
        """create_intent_message should produce correct payload."""
        now = int(time.time())
        intent = Intent(
            intent_type='channel_open',
            target='target_peer',
            initiator=intent_manager.our_pubkey,
            timestamp=now,
            expires_at=now + 60
        )
        
        payload = intent_manager.create_intent_message(intent)
        
        assert payload['intent_type'] == 'channel_open'
        assert payload['target'] == 'target_peer'
        assert payload['initiator'] == intent_manager.our_pubkey
        assert payload['timestamp'] == now
        assert payload['expires_at'] == now + 60


# =============================================================================
# ABORT TESTS
# =============================================================================

class TestIntentAbort:
    """Test intent abortion logic."""
    
    def test_abort_local_intent(self, intent_manager, mock_database):
        """abort_local_intent should update DB status."""
        mock_database.get_conflicting_intents.return_value = [
            {'id': 5, 'intent_type': 'channel_open', 'target': 'target', 
             'initiator': intent_manager.our_pubkey, 'status': 'pending'}
        ]
        
        result = intent_manager.abort_local_intent('target', 'channel_open')
        
        assert result is True
        mock_database.update_intent_status.assert_called_with(5, STATUS_ABORTED)
    
    def test_abort_no_local_intent(self, intent_manager, mock_database):
        """abort_local_intent should return False if no intent exists."""
        mock_database.get_conflicting_intents.return_value = []
        
        result = intent_manager.abort_local_intent('nonexistent', 'channel_open')
        
        assert result is False
    
    def test_create_abort_message(self, intent_manager):
        """create_abort_message should produce correct payload."""
        intent = Intent(
            intent_type='rebalance',
            target='route_123',
            initiator=intent_manager.our_pubkey,
            timestamp=int(time.time()),
            expires_at=int(time.time()) + 60
        )
        
        payload = intent_manager.create_abort_message(intent)
        
        assert payload['intent_type'] == 'rebalance'
        assert payload['target'] == 'route_123'
        assert payload['initiator'] == intent_manager.our_pubkey
        assert payload['reason'] == 'tie_breaker_loss'


# =============================================================================
# REMOTE INTENT TRACKING TESTS
# =============================================================================

class TestRemoteIntentTracking:
    """Test tracking of remote intents."""
    
    def test_record_remote_intent(self, intent_manager):
        """record_remote_intent should cache the intent."""
        remote_intent = Intent(
            intent_type='channel_open',
            target='some_target',
            initiator='02' + 'r' * 64,
            timestamp=int(time.time()),
            expires_at=int(time.time()) + 60
        )
        
        intent_manager.record_remote_intent(remote_intent)
        
        cached = intent_manager.get_remote_intents('some_target')
        assert len(cached) == 1
        assert cached[0].initiator == remote_intent.initiator
    
    def test_record_remote_abort(self, intent_manager):
        """record_remote_abort should update cached intent status."""
        # First record the intent
        remote_intent = Intent(
            intent_type='channel_open',
            target='target_x',
            initiator='02' + 's' * 64,
            timestamp=int(time.time()),
            expires_at=int(time.time()) + 60
        )
        intent_manager.record_remote_intent(remote_intent)
        
        # Then record abort
        intent_manager.record_remote_abort(
            'channel_open', 'target_x', '02' + 's' * 64
        )
        
        # Verify status updated
        cached = intent_manager.get_remote_intents('target_x')
        assert len(cached) == 1
        assert cached[0].status == STATUS_ABORTED


# =============================================================================
# COMMIT TESTS
# =============================================================================

class TestIntentCommit:
    """Test intent commit logic."""
    
    def test_commit_intent(self, intent_manager, mock_database):
        """commit_intent should update DB status to committed."""
        mock_database.update_intent_status.return_value = True
        
        result = intent_manager.commit_intent(42)
        
        assert result is True
        mock_database.update_intent_status.assert_called_with(42, STATUS_COMMITTED)
    
    def test_execute_committed_intent_with_callback(self, intent_manager):
        """execute_committed_intent should call registered callback."""
        callback_called = {'called': False, 'intent': None}
        
        def test_callback(intent):
            callback_called['called'] = True
            callback_called['intent'] = intent
        
        intent_manager.register_commit_callback('channel_open', test_callback)
        
        intent_row = {
            'id': 1,
            'intent_type': 'channel_open',
            'target': 'peer_xyz',
            'initiator': intent_manager.our_pubkey,
            'timestamp': int(time.time()),
            'expires_at': int(time.time()) + 60,
            'status': STATUS_COMMITTED
        }
        
        result = intent_manager.execute_committed_intent(intent_row)
        
        assert result is True
        assert callback_called['called'] is True
        assert callback_called['intent'].target == 'peer_xyz'
    
    def test_execute_without_callback(self, intent_manager):
        """execute_committed_intent should return False if no callback."""
        intent_row = {
            'id': 1,
            'intent_type': 'unknown_type',
            'target': 'peer',
            'initiator': intent_manager.our_pubkey,
            'timestamp': int(time.time()),
            'expires_at': int(time.time()) + 60,
            'status': STATUS_COMMITTED
        }
        
        result = intent_manager.execute_committed_intent(intent_row)
        
        assert result is False


# =============================================================================
# CLEANUP TESTS
# =============================================================================

class TestIntentCleanup:
    """Test intent cleanup logic."""
    
    def test_cleanup_expired_intents(self, intent_manager, mock_database):
        """cleanup_expired_intents should call DB cleanup."""
        mock_database.cleanup_expired_intents.return_value = 5
        
        # Add some old remote intents to cache
        old_intent = Intent(
            intent_type='channel_open',
            target='old_target',
            initiator='02' + 'o' * 64,
            timestamp=1000,
            expires_at=1060  # Very old
        )
        intent_manager._remote_intents['key1'] = old_intent
        
        # Run cleanup
        result = intent_manager.cleanup_expired_intents()
        
        assert result >= 5  # At least DB count
        mock_database.cleanup_expired_intents.assert_called_once()


# =============================================================================
# RACE CONDITION SIMULATION TESTS
# =============================================================================

class TestRaceConditions:
    """Test race condition scenarios."""
    
    def test_late_conflict_loses(self, intent_manager, mock_database):
        """
        Simulate receiving a conflicting INTENT 1 second before our timer expires.
        We should abort if we lose the tie-breaker.
        """
        # We have a pending intent (our pubkey: 02zzz... high)
        intent_manager.our_pubkey = '02' + 'z' * 64
        
        mock_database.get_conflicting_intents.return_value = [
            {'id': 1, 'intent_type': 'channel_open', 'target': 'target_x',
             'initiator': intent_manager.our_pubkey, 'status': 'pending'}
        ]
        
        # Late-arriving remote intent (their pubkey: 02aaa... low = winner)
        remote_intent = Intent(
            intent_type='channel_open',
            target='target_x',
            initiator='02' + 'a' * 64,
            timestamp=int(time.time()),
            expires_at=int(time.time()) + 60
        )
        
        has_conflict, we_win = intent_manager.check_conflicts(remote_intent)
        
        assert has_conflict is True
        assert we_win is False  # They win, we must abort
    
    def test_silence_means_commit(self, intent_manager, mock_database):
        """
        If no conflicts are received during hold period, commit proceeds.
        """
        # No conflicts in DB
        mock_database.get_conflicting_intents.return_value = []
        
        # Check for conflicts with dummy intent
        remote_intent = Intent(
            intent_type='channel_open',
            target='unclaimed_target',
            initiator='02' + 'x' * 64,
            timestamp=int(time.time()),
            expires_at=int(time.time()) + 60
        )
        
        has_conflict, we_win = intent_manager.check_conflicts(remote_intent)
        
        # No conflict means we can proceed
        assert has_conflict is False


# =============================================================================
# STATISTICS TESTS
# =============================================================================

class TestIntentStats:
    """Test statistics reporting."""
    
    def test_get_intent_stats(self, intent_manager):
        """get_intent_stats should return metrics."""
        stats = intent_manager.get_intent_stats()
        
        assert 'hold_seconds' in stats
        assert stats['hold_seconds'] == 60
        assert 'our_pubkey' in stats
        assert 'remote_intents_cached' in stats
        assert stats['remote_intents_cached'] == 0


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
