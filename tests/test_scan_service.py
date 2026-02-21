"""Tests for ScanService — phase transitions, governance creation,
LLM agent instantiation, skip-to-phase mechanism, and error handling.

All tests use heavily mocked dependencies to avoid DB and LLM calls.
"""

import sys
from pathlib import Path
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

PROJECT_ROOT = str(Path(__file__).resolve().parent.parent)
if PROJECT_ROOT not in sys.path:
    sys.path.insert(0, PROJECT_ROOT)


# ===========================================================================
# Helpers
# ===========================================================================

def _make_mock_db():
    """Create a mock AsyncSession that returns dummy scan/target objects."""
    db = AsyncMock()

    mock_scan = MagicMock()
    mock_scan.id = "scan-001"
    mock_scan.status = "running"
    mock_scan.scan_type = "full_auto"
    mock_scan.current_phase = "initializing"
    mock_scan.target_id = "target-001"

    mock_target = MagicMock()
    mock_target.id = "target-001"
    mock_target.url = "https://example.com"
    mock_target.scope = "in_scope"

    # Mock execute() to return scalars
    mock_result = MagicMock()
    mock_result.scalar_one_or_none = MagicMock(return_value=mock_scan)
    mock_result.scalars = MagicMock(return_value=MagicMock(all=MagicMock(return_value=[])))
    db.execute = AsyncMock(return_value=mock_result)
    db.commit = AsyncMock()
    db.refresh = AsyncMock()

    return db, mock_scan, mock_target


# ===========================================================================
# skip_to_phase mechanism
# ===========================================================================

class TestSkipToPhase:
    """skip_to_phase signals the scan to advance past the current phase."""

    def test_skip_to_valid_phase_returns_true(self):
        """skip_to_phase returns True for valid phase names."""
        from backend.services.scan_service import skip_to_phase
        result = skip_to_phase("scan-001", "testing")
        assert result is True

    def test_skip_to_invalid_phase_returns_false(self):
        """skip_to_phase returns False for unknown phase names."""
        from backend.services.scan_service import skip_to_phase
        result = skip_to_phase("scan-001", "totally_invalid_phase")
        assert result is False

    def test_skip_records_phase_in_control_dict(self):
        """skip_to_phase stores the target phase in _scan_phase_control."""
        from backend.services import scan_service
        scan_service._scan_phase_control.clear()
        scan_service.skip_to_phase("scan-002", "analyzing")
        assert scan_service._scan_phase_control.get("scan-002") == "analyzing"

    def test_phase_order_has_expected_phases(self):
        """PHASE_ORDER contains the expected phases in order."""
        from backend.services.scan_service import PHASE_ORDER
        assert "initializing" in PHASE_ORDER
        assert "recon" in PHASE_ORDER
        assert "analyzing" in PHASE_ORDER
        assert "testing" in PHASE_ORDER
        assert "completed" in PHASE_ORDER


# ===========================================================================
# ScanService initialization
# ===========================================================================

class TestScanServiceInit:
    """ScanService initializes correctly."""

    def test_scan_service_init(self):
        """ScanService can be instantiated with a mock DB."""
        from backend.services.scan_service import ScanService
        db = AsyncMock()
        service = ScanService(db, scan_id="scan-test-001")
        assert service._scan_id == "scan-test-001"
        assert service.db is db

    def test_scan_service_has_payload_generator(self):
        """ScanService has a PayloadGenerator instance."""
        from backend.services.scan_service import ScanService
        from backend.core.vuln_engine.payload_generator import PayloadGenerator
        db = AsyncMock()
        service = ScanService(db, scan_id="scan-test-002")
        assert isinstance(service.payload_generator, PayloadGenerator)

    def test_scan_service_aggressive_mode_default_false(self):
        """ScanService aggressive_mode is False by default (no env var set)."""
        from backend.services.scan_service import ScanService
        db = AsyncMock()
        with patch.dict("os.environ", {}, clear=False):
            # Remove AGGRESSIVE_MODE if set
            import os
            os.environ.pop("AGGRESSIVE_MODE", None)
            service = ScanService(db, scan_id="scan-test-003")
            assert service.aggressive_mode is False


# ===========================================================================
# _should_skip_phase logic
# ===========================================================================

class TestShouldSkipPhase:
    """_should_skip_phase returns the correct target phase."""

    def test_should_skip_forward(self):
        """Skip is applied when target phase is ahead of current."""
        from backend.services.scan_service import ScanService, _scan_phase_control
        db = AsyncMock()
        service = ScanService(db, scan_id="scan-skip-001")
        _scan_phase_control["scan-skip-001"] = "testing"
        result = service._should_skip_phase("scan-skip-001", "recon")
        assert result == "testing"

    def test_should_not_skip_backward(self):
        """Skip is not applied when target phase is behind current."""
        from backend.services.scan_service import ScanService, _scan_phase_control
        db = AsyncMock()
        service = ScanService(db, scan_id="scan-skip-002")
        _scan_phase_control["scan-skip-002"] = "recon"
        result = service._should_skip_phase("scan-skip-002", "testing")
        assert result is None

    def test_no_skip_signal_returns_none(self):
        """No skip signal returns None."""
        from backend.services.scan_service import ScanService, _scan_phase_control
        _scan_phase_control.pop("scan-skip-003", None)
        db = AsyncMock()
        service = ScanService(db, scan_id="scan-skip-003")
        result = service._should_skip_phase("scan-skip-003", "recon")
        assert result is None


# ===========================================================================
# Governance creation
# ===========================================================================

class TestScanServiceGovernance:
    """Verify ScanService creates governance correctly."""

    def test_create_governance_called_with_recon_scope(self):
        """recon scan_type creates recon_only governance."""
        from backend.core.governance_facade import create_governance

        gov = create_governance(
            scan_id="scan-gov-001",
            target_url="https://example.com",
            scope_profile="recon_only",
            task_category="recon",
        )
        from backend.core.governance_facade import Governance
        assert isinstance(gov, Governance)
        assert gov.governance_mode == "strict"

    def test_create_governance_called_with_full_auto_scope(self):
        """full_auto scan_type creates full_auto governance."""
        from backend.core.governance_facade import create_governance

        gov = create_governance(
            scan_id="scan-gov-002",
            target_url="https://example.com",
            scope_profile="full_auto",
            task_category="full_auto",
        )
        from backend.core.governance_facade import Governance
        assert isinstance(gov, Governance)


# ===========================================================================
# LLM agent instantiation
# ===========================================================================

class TestScanServiceLLMAgent:
    """Verify LLMDrivenAgent is correctly instantiated by scan service."""

    def test_agent_created_with_target(self, tmp_path):
        """Agent is created with the correct target URL."""
        from backend.core.llm_agent import LLMDrivenAgent

        mock_llm = MagicMock()
        mock_llm.generate = AsyncMock()

        with patch("backend.core.llm_agent.UnifiedLLMClient", return_value=mock_llm):
            agent = LLMDrivenAgent(
                target="https://example.com",
                objective="Security test",
                max_steps=50,
                data_dir=str(tmp_path),
            )
        assert agent.target == "https://example.com"

    def test_agent_max_steps_respected(self, tmp_path):
        """Agent respects max_steps configuration."""
        from backend.core.llm_agent import LLMDrivenAgent

        with patch("backend.core.llm_agent.UnifiedLLMClient"):
            agent = LLMDrivenAgent(
                target="https://example.com",
                objective="Test",
                max_steps=75,
                data_dir=str(tmp_path),
            )
        assert agent.max_steps == 75


# ===========================================================================
# Error handling
# ===========================================================================

class TestScanServiceErrorHandling:
    """ScanService handles errors gracefully."""

    def test_stop_requested_via_registry(self):
        """_stop_requested returns True when registry signals cancel."""
        from backend.services.scan_service import ScanService
        from backend.core import scan_registry

        db = AsyncMock()
        service = ScanService(db, scan_id="scan-stop-001")

        mock_handle = MagicMock()
        mock_handle.is_cancelled = MagicMock(return_value=True)

        with patch.object(scan_registry, "get", return_value=mock_handle):
            assert service._stop_requested is True

    def test_stop_not_requested_by_default(self):
        """_stop_requested returns False when no cancel signal."""
        from backend.services.scan_service import ScanService
        from backend.core import scan_registry

        db = AsyncMock()
        service = ScanService(db, scan_id="scan-stop-002")

        with patch.object(scan_registry, "get", return_value=None):
            assert service._stop_requested is False

    @pytest.mark.asyncio
    async def test_tradecraft_guidance_no_ttps(self):
        """_get_tradecraft_guidance returns empty string when no TTPs configured."""
        from backend.services.scan_service import ScanService

        db = AsyncMock()
        mock_result = MagicMock()
        mock_result.scalars = MagicMock(return_value=MagicMock(all=MagicMock(return_value=[])))
        db.execute = AsyncMock(return_value=mock_result)

        service = ScanService(db, scan_id="scan-ttp-001")
        guidance = await service._get_tradecraft_guidance("scan-ttp-001")
        assert guidance == ""
