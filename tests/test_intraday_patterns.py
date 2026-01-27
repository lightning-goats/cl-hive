"""
Tests for Kalman-enhanced intra-day pattern detection.

Tests the IntraDayPattern, IntraDayForecast dataclasses and the
intra-day pattern detection methods in AnticipatoryLiquidityManager.
"""
import math
import pytest
import time
from datetime import datetime
from collections import defaultdict


class TestIntraDayPhaseAndPatternType:
    """Tests for IntraDayPhase and PatternType enums."""

    def test_intraday_phases(self):
        """Test all intra-day phases exist."""
        from modules.anticipatory_liquidity import IntraDayPhase

        phases = [
            IntraDayPhase.EARLY_MORNING,
            IntraDayPhase.MORNING,
            IntraDayPhase.AFTERNOON,
            IntraDayPhase.EVENING,
            IntraDayPhase.NIGHT,
            IntraDayPhase.OVERNIGHT,
        ]
        assert len(phases) == 6

    def test_pattern_types(self):
        """Test all pattern types exist."""
        from modules.anticipatory_liquidity import PatternType

        types = [
            PatternType.SURGE,
            PatternType.DRAIN,
            PatternType.ACTIVE,
            PatternType.QUIET,
            PatternType.TRANSITION,
        ]
        assert len(types) == 5


class TestIntraDayPattern:
    """Tests for IntraDayPattern dataclass."""

    def test_basic_initialization(self):
        """Test basic pattern initialization."""
        from modules.anticipatory_liquidity import (
            IntraDayPattern, IntraDayPhase, PatternType
        )

        pattern = IntraDayPattern(
            channel_id="123x1x0",
            phase=IntraDayPhase.MORNING,
            pattern_type=PatternType.SURGE,
            hour_start=8,
            hour_end=12,
            avg_velocity=0.025,
            velocity_std=0.005,
            kalman_confidence=0.8,
            sample_confidence=0.7,
            sample_count=15,
            avg_flow_magnitude=50000,
            consistency=0.85
        )

        assert pattern.channel_id == "123x1x0"
        assert pattern.phase == IntraDayPhase.MORNING
        assert pattern.pattern_type == PatternType.SURGE
        assert pattern.avg_velocity == 0.025

    def test_combined_confidence(self):
        """Test combined confidence calculation."""
        from modules.anticipatory_liquidity import (
            IntraDayPattern, IntraDayPhase, PatternType, INTRADAY_KALMAN_WEIGHT
        )

        pattern = IntraDayPattern(
            channel_id="123x1x0",
            phase=IntraDayPhase.MORNING,
            pattern_type=PatternType.ACTIVE,
            hour_start=8,
            hour_end=12,
            avg_velocity=0.015,
            velocity_std=0.003,
            kalman_confidence=0.9,
            sample_confidence=0.6,
            sample_count=10,
            avg_flow_magnitude=30000,
            consistency=0.8
        )

        expected = INTRADAY_KALMAN_WEIGHT * 0.9 + (1 - INTRADAY_KALMAN_WEIGHT) * 0.6
        assert pattern.combined_confidence == pytest.approx(expected, abs=0.01)

    def test_is_actionable_true(self):
        """Test actionable pattern detection."""
        from modules.anticipatory_liquidity import (
            IntraDayPattern, IntraDayPhase, PatternType
        )

        pattern = IntraDayPattern(
            channel_id="123x1x0",
            phase=IntraDayPhase.EVENING,
            pattern_type=PatternType.DRAIN,
            hour_start=17,
            hour_end=21,
            avg_velocity=-0.03,
            velocity_std=0.005,
            kalman_confidence=0.85,
            sample_confidence=0.75,
            sample_count=20,
            avg_flow_magnitude=80000,
            consistency=0.9,
            is_regime_stable=True
        )

        assert pattern.is_actionable

    def test_is_actionable_false_low_samples(self):
        """Test non-actionable pattern with low samples."""
        from modules.anticipatory_liquidity import (
            IntraDayPattern, IntraDayPhase, PatternType
        )

        pattern = IntraDayPattern(
            channel_id="123x1x0",
            phase=IntraDayPhase.OVERNIGHT,
            pattern_type=PatternType.QUIET,
            hour_start=0,
            hour_end=5,
            avg_velocity=0.001,
            velocity_std=0.001,
            kalman_confidence=0.8,
            sample_confidence=0.3,
            sample_count=2,  # Too few samples
            avg_flow_magnitude=5000,
            consistency=0.5
        )

        assert not pattern.is_actionable

    def test_is_actionable_false_regime_unstable(self):
        """Test non-actionable pattern with unstable regime."""
        from modules.anticipatory_liquidity import (
            IntraDayPattern, IntraDayPhase, PatternType
        )

        pattern = IntraDayPattern(
            channel_id="123x1x0",
            phase=IntraDayPhase.AFTERNOON,
            pattern_type=PatternType.TRANSITION,
            hour_start=12,
            hour_end=17,
            avg_velocity=0.01,
            velocity_std=0.02,
            kalman_confidence=0.7,
            sample_confidence=0.8,
            sample_count=15,
            avg_flow_magnitude=40000,
            consistency=0.6,
            is_regime_stable=False  # Regime change detected
        )

        assert not pattern.is_actionable

    def test_to_dict(self):
        """Test serialization to dict."""
        from modules.anticipatory_liquidity import (
            IntraDayPattern, IntraDayPhase, PatternType
        )

        pattern = IntraDayPattern(
            channel_id="123x1x0",
            phase=IntraDayPhase.MORNING,
            pattern_type=PatternType.SURGE,
            hour_start=8,
            hour_end=12,
            avg_velocity=0.025,
            velocity_std=0.005,
            kalman_confidence=0.8,
            sample_confidence=0.7,
            sample_count=15,
            avg_flow_magnitude=50000,
            consistency=0.85
        )

        d = pattern.to_dict()

        assert d["channel_id"] == "123x1x0"
        assert d["phase"] == "morning"
        assert d["pattern_type"] == "surge"
        assert d["hours"] == "08:00-12:00"
        assert "combined_confidence" in d
        assert "is_actionable" in d


class TestIntraDayForecast:
    """Tests for IntraDayForecast dataclass."""

    def test_basic_initialization(self):
        """Test basic forecast initialization."""
        from modules.anticipatory_liquidity import (
            IntraDayForecast, IntraDayPhase
        )

        forecast = IntraDayForecast(
            channel_id="123x1x0",
            current_phase=IntraDayPhase.MORNING,
            next_phase=IntraDayPhase.AFTERNOON,
            hours_until_transition=2.5,
            expected_velocity=-0.015,
            velocity_confidence=0.75,
            expected_direction="outbound",
            recommended_action="preposition",
            action_urgency="soon",
            optimal_action_window=(10, 12),
            depletion_risk_increase=0.25,
            saturation_risk_increase=0.0
        )

        assert forecast.channel_id == "123x1x0"
        assert forecast.expected_direction == "outbound"
        assert forecast.recommended_action == "preposition"

    def test_to_dict(self):
        """Test serialization to dict."""
        from modules.anticipatory_liquidity import (
            IntraDayForecast, IntraDayPhase
        )

        forecast = IntraDayForecast(
            channel_id="123x1x0",
            current_phase=IntraDayPhase.AFTERNOON,
            next_phase=IntraDayPhase.EVENING,
            hours_until_transition=1.0,
            expected_velocity=0.02,
            velocity_confidence=0.8,
            expected_direction="inbound",
            recommended_action="raise_fees",
            action_urgency="immediate",
            optimal_action_window=(15, 17),
            depletion_risk_increase=0.0,
            saturation_risk_increase=0.2
        )

        d = forecast.to_dict()

        assert d["channel_id"] == "123x1x0"
        assert d["current_phase"] == "afternoon"
        assert d["next_phase"] == "evening"
        assert d["optimal_action_window"] == "15:00-17:00"
        assert d["action_urgency"] == "immediate"


class TestIntraDayPatternDetection:
    """Tests for intra-day pattern detection methods."""

    def test_detect_intraday_patterns_insufficient_data(self, mock_manager):
        """Test detection with insufficient data returns empty."""
        patterns = mock_manager.detect_intraday_patterns("123x1x0")
        assert patterns == []

    def test_detect_intraday_patterns_with_data(self, mock_manager_with_samples):
        """Test detection with sufficient data."""
        patterns = mock_manager_with_samples.detect_intraday_patterns("123x1x0")

        # Should detect patterns for buckets with enough samples
        assert len(patterns) > 0

    def test_get_phase_for_hour(self, mock_manager):
        """Test phase determination for different hours."""
        from modules.anticipatory_liquidity import IntraDayPhase

        # Early morning
        assert mock_manager._get_phase_for_hour(6) == IntraDayPhase.EARLY_MORNING

        # Morning
        assert mock_manager._get_phase_for_hour(9) == IntraDayPhase.MORNING

        # Afternoon
        assert mock_manager._get_phase_for_hour(14) == IntraDayPhase.AFTERNOON

        # Evening
        assert mock_manager._get_phase_for_hour(19) == IntraDayPhase.EVENING

        # Night
        assert mock_manager._get_phase_for_hour(22) == IntraDayPhase.NIGHT

        # Overnight
        assert mock_manager._get_phase_for_hour(3) == IntraDayPhase.OVERNIGHT

    def test_get_next_phase(self, mock_manager):
        """Test next phase calculation."""
        from modules.anticipatory_liquidity import IntraDayPhase

        assert mock_manager._get_next_phase(IntraDayPhase.OVERNIGHT) == IntraDayPhase.EARLY_MORNING
        assert mock_manager._get_next_phase(IntraDayPhase.EARLY_MORNING) == IntraDayPhase.MORNING
        assert mock_manager._get_next_phase(IntraDayPhase.MORNING) == IntraDayPhase.AFTERNOON
        assert mock_manager._get_next_phase(IntraDayPhase.AFTERNOON) == IntraDayPhase.EVENING
        assert mock_manager._get_next_phase(IntraDayPhase.EVENING) == IntraDayPhase.NIGHT
        assert mock_manager._get_next_phase(IntraDayPhase.NIGHT) == IntraDayPhase.OVERNIGHT


class TestIntraDayForecastGeneration:
    """Tests for forecast generation."""

    def test_get_intraday_forecast_no_patterns(self, mock_manager):
        """Test forecast with no patterns returns None."""
        forecast = mock_manager.get_intraday_forecast("123x1x0")
        assert forecast is None

    def test_determine_intraday_action_high_drain_risk(self, mock_manager):
        """Test action determination for high drain risk."""
        from modules.anticipatory_liquidity import (
            IntraDayPattern, IntraDayPhase, PatternType
        )

        pattern = IntraDayPattern(
            channel_id="123x1x0",
            phase=IntraDayPhase.EVENING,
            pattern_type=PatternType.DRAIN,
            hour_start=17,
            hour_end=21,
            avg_velocity=-0.03,
            velocity_std=0.005,
            kalman_confidence=0.85,
            sample_confidence=0.8,
            sample_count=20,
            avg_flow_magnitude=100000,
            consistency=0.9,
            is_regime_stable=True
        )

        action, urgency = mock_manager._determine_intraday_action(
            current_local_pct=0.3,  # Low balance
            next_pattern=pattern,
            hours_until=1.5,  # Soon
            depletion_risk_increase=0.35,
            saturation_risk_increase=0.0
        )

        assert action == "preposition"
        assert urgency == "immediate"

    def test_determine_intraday_action_surge_period(self, mock_manager):
        """Test action determination for incoming surge."""
        from modules.anticipatory_liquidity import (
            IntraDayPattern, IntraDayPhase, PatternType
        )

        pattern = IntraDayPattern(
            channel_id="123x1x0",
            phase=IntraDayPhase.EVENING,
            pattern_type=PatternType.SURGE,
            hour_start=17,
            hour_end=21,
            avg_velocity=0.025,
            velocity_std=0.004,
            kalman_confidence=0.8,
            sample_confidence=0.75,
            sample_count=18,
            avg_flow_magnitude=80000,
            consistency=0.85,
            is_regime_stable=True
        )

        action, urgency = mock_manager._determine_intraday_action(
            current_local_pct=0.7,  # High balance
            next_pattern=pattern,
            hours_until=1.0,
            depletion_risk_increase=0.0,
            saturation_risk_increase=0.35  # Must exceed 0.3 threshold
        )

        # Should recommend lowering fees to handle incoming surge
        assert action == "lower_fees"
        assert urgency == "immediate"

    def test_determine_intraday_action_quiet_rebalance_opportunity(self, mock_manager):
        """Test action for quiet period with imbalanced channel."""
        from modules.anticipatory_liquidity import (
            IntraDayPattern, IntraDayPhase, PatternType
        )

        pattern = IntraDayPattern(
            channel_id="123x1x0",
            phase=IntraDayPhase.OVERNIGHT,
            pattern_type=PatternType.QUIET,
            hour_start=0,
            hour_end=5,
            avg_velocity=0.002,
            velocity_std=0.001,
            kalman_confidence=0.7,
            sample_confidence=0.6,
            sample_count=12,
            avg_flow_magnitude=10000,
            consistency=0.7,
            is_regime_stable=True
        )

        action, urgency = mock_manager._determine_intraday_action(
            current_local_pct=0.2,  # Very low balance
            next_pattern=pattern,
            hours_until=3.0,
            depletion_risk_increase=0.05,
            saturation_risk_increase=0.0
        )

        assert action == "preposition"
        assert urgency == "planned"


class TestIntraDaySummary:
    """Tests for intra-day summary generation."""

    def test_get_intraday_summary_empty(self, mock_manager):
        """Test summary with no data."""
        summary = mock_manager.get_intraday_summary()

        assert summary["total_patterns"] == 0
        assert summary["actionable_patterns"] == 0

    def test_get_intraday_summary_structure(self, mock_manager):
        """Test summary structure."""
        summary = mock_manager.get_intraday_summary()

        assert "total_patterns" in summary
        assert "actionable_patterns" in summary
        assert "patterns_by_type" in summary
        assert "total_forecasts" in summary
        assert "urgent_forecasts" in summary
        assert "patterns" in summary
        assert "forecasts" in summary


# =============================================================================
# Fixtures
# =============================================================================

@pytest.fixture
def mock_manager():
    """Create a mock AnticipatoryLiquidityManager."""
    from modules.anticipatory_liquidity import AnticipatoryLiquidityManager

    class MockDatabase:
        def record_flow_sample(self, **kwargs):
            pass

        def get_flow_samples(self, **kwargs):
            return []

    manager = AnticipatoryLiquidityManager(
        database=MockDatabase(),
        plugin=None,
        state_manager=None,
        our_id="03test123"
    )

    return manager


@pytest.fixture
def mock_manager_with_samples():
    """Create a mock manager with pre-populated flow samples."""
    from modules.anticipatory_liquidity import (
        AnticipatoryLiquidityManager, HourlyFlowSample
    )

    # Pre-generate samples so MockDatabase can return them
    now = int(time.time())
    samples = []

    # Generate 14 days of hourly samples
    for day in range(14):
        for hour in range(24):
            timestamp = now - (day * 86400) - ((23 - hour) * 3600)

            # Simulate different flow patterns by time of day
            if 8 <= hour < 12:  # Morning: high outbound
                net_flow = -50000 + (day % 3) * 10000
            elif 17 <= hour < 21:  # Evening: high inbound
                net_flow = 60000 - (day % 3) * 10000
            elif 0 <= hour < 5:  # Overnight: quiet
                net_flow = 5000 - (day % 2) * 3000
            else:  # Other: moderate
                net_flow = 20000 - (day % 4) * 15000

            sample = {
                "channel_id": "123x1x0",
                "hour": hour,
                "day_of_week": day % 7,
                "inbound_sats": max(0, net_flow),
                "outbound_sats": max(0, -net_flow),
                "net_flow_sats": net_flow,
                "timestamp": timestamp
            }
            samples.append(sample)

    class MockDatabase:
        def record_flow_sample(self, **kwargs):
            pass

        def get_flow_samples(self, **kwargs):
            # Return the pre-generated samples as database rows
            return samples

    manager = AnticipatoryLiquidityManager(
        database=MockDatabase(),
        plugin=None,
        state_manager=None,
        our_id="03test123"
    )

    return manager
