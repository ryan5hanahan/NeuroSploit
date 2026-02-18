"""
Tests for governance API endpoints and WebSocket broadcasts (Phase 4).

Covers:
  - WebSocket broadcast methods exist and are callable
  - Governance API router is importable and has expected endpoints
  - Default violation callback (WS) is created by factory
  - Default DB persist callback is created by factory
  - GovernanceViolationRecord model has to_dict()
  - API router registered in main app
"""

import pytest
from unittest.mock import MagicMock, AsyncMock, patch
import asyncio

from backend.core.governance_facade import (
    Governance,
    create_governance,
    _make_ws_violation_callback,
    _make_db_persist_fn,
)
from backend.core.governance_gate import GovernanceViolation
from backend.models.governance_violation import GovernanceViolationRecord


# ===================================================================
# WebSocket broadcast methods
# ===================================================================

class TestWebSocketBroadcasts:

    def test_manager_has_governance_violation_method(self):
        from backend.api.websocket import ConnectionManager
        mgr = ConnectionManager()
        assert hasattr(mgr, "broadcast_governance_violation")
        assert asyncio.iscoroutinefunction(mgr.broadcast_governance_violation)

    def test_manager_has_governance_stats_method(self):
        from backend.api.websocket import ConnectionManager
        mgr = ConnectionManager()
        assert hasattr(mgr, "broadcast_governance_stats")
        assert asyncio.iscoroutinefunction(mgr.broadcast_governance_stats)

    @pytest.mark.asyncio
    async def test_broadcast_governance_violation_sends_correct_type(self):
        from backend.api.websocket import ConnectionManager
        mgr = ConnectionManager()
        sent_messages = []

        async def mock_send(scan_id, message):
            sent_messages.append(message)

        mgr.send_to_scan = mock_send
        await mgr.broadcast_governance_violation("scan-1", {"action": "sqlmap"})

        assert len(sent_messages) == 1
        assert sent_messages[0]["type"] == "governance_violation"
        assert sent_messages[0]["scan_id"] == "scan-1"
        assert sent_messages[0]["violation"]["action"] == "sqlmap"

    @pytest.mark.asyncio
    async def test_broadcast_governance_stats_sends_correct_type(self):
        from backend.api.websocket import ConnectionManager
        mgr = ConnectionManager()
        sent_messages = []

        async def mock_send(scan_id, message):
            sent_messages.append(message)

        mgr.send_to_scan = mock_send
        await mgr.broadcast_governance_stats("scan-1", {"total": 5})

        assert len(sent_messages) == 1
        assert sent_messages[0]["type"] == "governance_stats"
        assert sent_messages[0]["stats"]["total"] == 5


# ===================================================================
# Default callbacks from factory
# ===================================================================

class TestDefaultCallbacks:

    def test_factory_creates_default_ws_callback(self):
        gov = create_governance(
            scan_id="t1", target_url="https://example.com",
            governance_mode="strict",
        )
        # Should have a non-None violation_callback
        assert gov._violation_callback is not None

    def test_factory_creates_default_db_persist(self):
        gov = create_governance(
            scan_id="t1", target_url="https://example.com",
            governance_mode="strict",
        )
        assert gov._db_persist_fn is not None

    def test_custom_callback_overrides_default(self):
        custom = MagicMock()
        gov = create_governance(
            scan_id="t1", target_url="https://example.com",
            governance_mode="strict",
            violation_callback=custom,
        )
        assert gov._violation_callback is custom

    def test_custom_db_persist_overrides_default(self):
        custom = MagicMock()
        gov = create_governance(
            scan_id="t1", target_url="https://example.com",
            governance_mode="strict",
            db_persist_fn=custom,
        )
        assert gov._db_persist_fn is custom

    def test_ws_callback_does_not_crash_without_loop(self):
        """WS callback should gracefully handle no running event loop."""
        callback = _make_ws_violation_callback("t1")
        violation = GovernanceViolation(
            scan_id="t1", phase="recon", action="sqlmap",
            action_category="exploitation", allowed_categories=[],
        )
        # Should not raise even without an event loop
        callback(violation)

    def test_db_persist_does_not_crash_without_loop(self):
        """DB persist should gracefully handle no running event loop."""
        persist = _make_db_persist_fn("t1")
        violation = GovernanceViolation(
            scan_id="t1", phase="recon", action="sqlmap",
            action_category="exploitation", allowed_categories=[],
        )
        # Should not raise even without an event loop
        persist(violation)


# ===================================================================
# GovernanceViolationRecord model
# ===================================================================

class TestGovernanceViolationRecordModel:

    def test_to_dict_has_expected_keys(self):
        from datetime import datetime
        record = GovernanceViolationRecord(
            id="test-id",
            scan_id="scan-1",
            layer="phase",
            phase="recon",
            action="sqlmap",
            action_category="exploitation",
            allowed_categories=["passive_recon", "active_recon"],
            disposition="blocked",
            detail="test detail",
            created_at=datetime(2026, 1, 1),
        )
        d = record.to_dict()
        assert d["id"] == "test-id"
        assert d["scan_id"] == "scan-1"
        assert d["layer"] == "phase"
        assert d["phase"] == "recon"
        assert d["action"] == "sqlmap"
        assert d["disposition"] == "blocked"
        assert d["detail"] == "test detail"
        assert "2026" in d["created_at"]

    def test_model_tablename(self):
        assert GovernanceViolationRecord.__tablename__ == "governance_violations"


# ===================================================================
# Governance API router
# ===================================================================

class TestGovernanceAPIRouter:

    def test_router_importable(self):
        from backend.api.v1.governance import router
        assert router is not None

    def test_router_has_violations_endpoint(self):
        from backend.api.v1.governance import router
        routes = [r.path for r in router.routes]
        assert "/scans/{scan_id}/governance/violations" in routes

    def test_router_has_stats_endpoint(self):
        from backend.api.v1.governance import router
        routes = [r.path for r in router.routes]
        assert "/scans/{scan_id}/governance/stats" in routes

    def test_router_registered_in_main_app(self):
        from backend.main import app
        paths = [r.path for r in app.routes]
        # Check that governance prefix is registered
        governance_paths = [p for p in paths if "governance" in p]
        assert len(governance_paths) >= 2


# ===================================================================
# Integration: violation triggers both callbacks
# ===================================================================

class TestViolationCallbackIntegration:

    def test_check_action_fires_both_callbacks(self):
        ws_violations = []
        db_violations = []

        gov = create_governance(
            scan_id="t1", target_url="https://example.com",
            governance_mode="strict",
            violation_callback=lambda v: ws_violations.append(v),
            db_persist_fn=lambda v: db_violations.append(v),
        )
        gov.set_phase("recon")
        gov.check_action("sqlmap")

        assert len(ws_violations) == 1
        assert len(db_violations) == 1
        assert ws_violations[0].action == "sqlmap"
        assert db_violations[0].layer == "phase"

    def test_scope_violation_fires_callbacks(self):
        ws_violations = []
        db_violations = []

        gov = create_governance(
            scan_id="t1", target_url="https://example.com",
            scope_profile="vuln_lab", vuln_type="xss_reflected",
            governance_mode="strict",
            violation_callback=lambda v: ws_violations.append(v),
            db_persist_fn=lambda v: db_violations.append(v),
        )
        gov.filter_vuln_types(["sqli_error", "xss_reflected"])

        scope_ws = [v for v in ws_violations if v.layer == "scope"]
        scope_db = [v for v in db_violations if v.layer == "scope"]
        assert len(scope_ws) == 1
        assert len(scope_db) == 1

    def test_no_violation_no_callback(self):
        ws_violations = []
        db_violations = []

        gov = create_governance(
            scan_id="t1", target_url="https://example.com",
            governance_mode="strict",
            violation_callback=lambda v: ws_violations.append(v),
            db_persist_fn=lambda v: db_violations.append(v),
        )
        gov.set_phase("full_auto")
        gov.check_action("sqlmap")  # allowed in full_auto

        assert len(ws_violations) == 0
        assert len(db_violations) == 0
