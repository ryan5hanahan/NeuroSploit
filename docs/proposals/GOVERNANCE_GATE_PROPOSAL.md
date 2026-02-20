# Implementation Proposal: Enhanced Governance — Phase-Scoped Action Enforcement

**Author:** sploit.ai Team
**Date:** 2026-02-13
**Status:** PROPOSAL

---

## Problem Statement

sploit.ai currently has no mechanism to prevent phase-inappropriate actions. A scan configured for **recon-only** can still trigger exploitation payloads if the LLM agent or chain engine escalates beyond its mandate. Similarly, nothing prevents the payload generator from firing during the analysis phase, or the autonomous scanner from launching active probes during a passive-recon task.

**Concrete example:** A user selects `recon_full` (TaskCategory.RECON). The agent runs subdomain enumeration, but then the chain engine discovers an exposed admin panel and autonomously escalates to `default_credentials` and `auth_bypass` testing — a clear scope violation.

The system needs a **governance layer** that enforces phase boundaries as hard constraints, not just suggestions.

---

## Design Principles

1. **Deny by default** — Actions not explicitly permitted for the current phase are blocked.
2. **Fail loud** — Violations produce structured audit events (not silent drops).
3. **Centralized policy** — One source of truth for what each phase allows.
4. **Non-bypassable at runtime** — The LLM agent, chain engine, and tool calls all pass through the same gate.
5. **Configurable** — Operators can customize policies per scan or globally.

---

## Architecture

### New Module: `backend/core/governance.py`

A single enforcement layer inserted into the request path between action intent and action execution.

```
┌─────────────────────────────────────────────────────┐
│                   Action Source                       │
│  (AutonomousAgent / ChainEngine / MCP Tool / API)    │
└──────────────────────┬──────────────────────────────┘
                       │
                       ▼
              ┌────────────────┐
              │  GovernanceGate │  ◄── Policy (phase → allowed actions)
              │                │  ◄── Current phase from ScanContext
              │  allow / deny  │  ──► AuditLog on deny
              └───────┬────────┘
                      │ (allowed only)
                      ▼
              ┌────────────────┐
              │  Execute Action │
              └────────────────┘
```

### Core Components

#### 1. `PhasePolicy` — The Ruleset

Defines what each phase is allowed to do. Actions are classified into **action categories**:

| Action Category     | Description                                      | Examples                                              |
|---------------------|--------------------------------------------------|-------------------------------------------------------|
| `passive_recon`     | Non-intrusive information gathering              | DNS lookup, CT logs, WHOIS, Wayback                   |
| `active_recon`      | Direct interaction for discovery                 | Port scan, HTTP probing, crawling, tech detection     |
| `analysis`          | Processing collected data, no new requests       | LLM analysis, attack surface mapping, plan generation |
| `vulnerability_scan`| Sending test payloads to detect vulnerabilities  | Nuclei templates, SQLi probes, XSS payloads          |
| `exploitation`      | Confirming exploitability with active payloads   | Payload delivery, PoC execution, auth bypass          |
| `post_exploitation` | Actions after confirmed exploitation             | Privilege escalation, lateral movement, data access   |
| `reporting`         | Report generation, no target interaction         | Report build, finding export, summary generation      |

Default phase-to-permission mapping:

```python
DEFAULT_PHASE_POLICY = {
    "recon": {
        "allowed": ["passive_recon", "active_recon", "analysis"],
        "denied":  ["vulnerability_scan", "exploitation", "post_exploitation"],
    },
    "passive_recon": {
        "allowed": ["passive_recon", "analysis"],
        "denied":  ["active_recon", "vulnerability_scan", "exploitation", "post_exploitation"],
    },
    "analyzing": {
        "allowed": ["analysis", "passive_recon"],
        "denied":  ["active_recon", "vulnerability_scan", "exploitation", "post_exploitation"],
    },
    "testing": {
        "allowed": ["passive_recon", "active_recon", "analysis", "vulnerability_scan"],
        "denied":  ["exploitation", "post_exploitation"],
    },
    "exploitation": {
        "allowed": ["passive_recon", "active_recon", "analysis", "vulnerability_scan", "exploitation"],
        "denied":  ["post_exploitation"],
    },
    "full_auto": {
        "allowed": ["passive_recon", "active_recon", "analysis", "vulnerability_scan", "exploitation"],
        "denied":  ["post_exploitation"],
    },
    "reporting": {
        "allowed": ["reporting", "analysis"],
        "denied":  ["active_recon", "vulnerability_scan", "exploitation", "post_exploitation"],
    },
}
```

#### 2. `ActionClassifier` — Mapping Actions to Categories

Every tool, MCP call, and internal method gets classified:

```python
ACTION_CLASSIFICATION = {
    # Tools → category
    "subfinder":            "active_recon",
    "httpx":                "active_recon",
    "nmap":                 "active_recon",
    "katana":               "active_recon",
    "gau":                  "passive_recon",
    "waybackurls":          "passive_recon",
    "nuclei":               "vulnerability_scan",
    "sqlmap":               "exploitation",
    "commix":               "exploitation",
    "hydra":                "exploitation",
    "ffuf":                 "active_recon",
    "nikto":                "vulnerability_scan",

    # MCP tools → category
    "screenshot_capture":   "active_recon",
    "payload_delivery":     "exploitation",
    "dns_lookup":           "passive_recon",
    "port_scan":            "active_recon",
    "technology_detect":    "active_recon",
    "subdomain_enumerate":  "active_recon",
    "save_finding":         "analysis",
    "get_vuln_prompt":      "analysis",
    "execute_nuclei":       "vulnerability_scan",
    "execute_naabu":        "active_recon",
    "sandbox_exec":         "exploitation",    # conservative default

    # Internal methods → category
    "_test_payload":        "vulnerability_scan",
    "_scan_for_vuln_type":  "vulnerability_scan",
    "_test_security_headers": "vulnerability_scan",
    "_test_cors":           "vulnerability_scan",
    "_run_recon_only":      "active_recon",
    "_run_full_auto":       "exploitation",    # full auto includes exploitation
    "_generate_report":     "reporting",
}
```

New or unclassified actions default to the **most restrictive** category (`exploitation`) so unknown tools are blocked during recon by default. This can be overridden in config.

#### 3. `GovernanceGate` — The Enforcer

```python
class GovernanceGate:
    """Central enforcement point for phase-scoped action governance."""

    def __init__(self, scan_id: str, phase_policy: dict = None):
        self.scan_id = scan_id
        self.policy = phase_policy or DEFAULT_PHASE_POLICY
        self.current_phase: str = "initializing"
        self.violations: List[GovernanceViolation] = []
        self.strict_mode: bool = True  # False = warn only, True = block

    def set_phase(self, phase: str):
        """Update the current scan phase."""
        self.current_phase = phase

    def check(self, action: str, context: dict = None) -> GovernanceDecision:
        """
        Check whether an action is permitted in the current phase.

        Returns GovernanceDecision with:
          - allowed: bool
          - action_category: str (classified category)
          - reason: str (human-readable)
          - violation: GovernanceViolation | None
        """
        category = ActionClassifier.classify(action)
        phase_rules = self.policy.get(self.current_phase, {})
        allowed_categories = phase_rules.get("allowed", [])

        if category in allowed_categories:
            return GovernanceDecision(allowed=True, action_category=category)

        # VIOLATION
        violation = GovernanceViolation(
            scan_id=self.scan_id,
            phase=self.current_phase,
            action=action,
            action_category=category,
            allowed_categories=allowed_categories,
            context=context or {},
            timestamp=datetime.utcnow(),
        )
        self.violations.append(violation)

        if self.strict_mode:
            return GovernanceDecision(
                allowed=False,
                action_category=category,
                reason=f"BLOCKED: '{action}' (category: {category}) is not permitted "
                       f"during phase '{self.current_phase}'. "
                       f"Allowed categories: {allowed_categories}",
                violation=violation,
            )
        else:
            # Warn-only mode: log but allow
            return GovernanceDecision(
                allowed=True,
                action_category=category,
                reason=f"WARNING: '{action}' (category: {category}) violates policy "
                       f"for phase '{self.current_phase}' (warn-only mode)",
                violation=violation,
            )

    def get_violations(self) -> List[GovernanceViolation]:
        """Return all violations recorded during this scan."""
        return self.violations
```

#### 4. `GovernanceViolation` — Audit Record

```python
@dataclass
class GovernanceViolation:
    scan_id: str
    phase: str
    action: str
    action_category: str
    allowed_categories: List[str]
    context: dict              # caller, target URL, payload hash, etc.
    timestamp: datetime
    disposition: str = "blocked"  # "blocked" | "warned"
```

Violations are:
- Persisted to the database (new `governance_violations` table)
- Broadcast via WebSocket to the UI in real-time
- Included in scan reports as an appendix

---

## Integration Points

### A. ScanService (`scan_service.py`)

The `GovernanceGate` is instantiated at scan start and passed through the execution pipeline:

```python
async def execute_scan(self, scan_id: str):
    # ... existing setup ...

    # Initialize governance
    phase_policy = scan.config.get("governance_policy", DEFAULT_PHASE_POLICY)
    gate = GovernanceGate(scan_id, phase_policy)

    # Derive effective phase from scan type / task category
    if scan.config.get("task_category") == "recon":
        gate.set_phase("recon")
    elif scan.config.get("task_category") == "passive_recon":
        gate.set_phase("passive_recon")
    # ... etc

    # Pass gate to all downstream components
    self.gate = gate

    # Phase transitions update the gate
    scan.current_phase = "recon"
    gate.set_phase("recon")
    # ...
```

### B. AutonomousAgent (`autonomous_agent.py`)

The agent checks the gate before every action:

```python
async def _test_payload(self, url, param, payload, vuln_type, ...):
    # Governance check BEFORE sending any request
    decision = self.gate.check("_test_payload", {
        "url": url, "vuln_type": vuln_type, "param": param
    })
    if not decision.allowed:
        await self._log("governance", decision.reason)
        return None  # Skip this action

    # ... existing payload testing logic ...
```

The `execute()` dispatch also validates mode-phase consistency:

```python
async def execute(self):
    if self.mode == OperationMode.RECON_ONLY:
        self.gate.set_phase("recon")
    elif self.mode == OperationMode.ANALYZE_ONLY:
        self.gate.set_phase("analyzing")
    # ...
    # Phase is now locked for the duration of this mode
```

### C. ChainEngine (`chain_engine.py`)

The chain engine is a primary escalation vector. Governance blocks derived actions that exceed phase scope:

```python
def on_finding(self, finding: Finding) -> List[DerivedTarget]:
    derived = self._apply_chain_rules(finding)

    # Filter derived targets through governance
    permitted = []
    for target in derived:
        decision = self.gate.check(target.vuln_type, {
            "trigger": finding.vulnerability_type,
            "chain_depth": target.depth,
        })
        if decision.allowed:
            permitted.append(target)
        else:
            self._log_chain_blocked(finding, target, decision)

    return permitted
```

### D. MCP Server (`core/mcp_server.py`)

Every MCP tool call passes through the gate:

```python
async def _handle_tool_call(self, tool_name: str, arguments: dict):
    if self.gate:
        decision = self.gate.check(tool_name, arguments)
        if not decision.allowed:
            return {"error": decision.reason, "governance_violation": True}

    # ... existing tool dispatch ...
```

### E. RequestEngine (`request_engine.py`)

Optional secondary check — the request engine can verify that the request's intent matches the phase:

```python
async def request(self, method, url, **kwargs):
    # If a governance gate is attached, classify and check
    if self.gate:
        # Heuristic: requests with payloads in body/params → vulnerability_scan
        action_hint = kwargs.get("_governance_action", "active_recon")
        decision = self.gate.check(action_hint, {"url": url, "method": method})
        if not decision.allowed:
            return GovernanceBlockedResponse(decision)

    # ... existing request logic ...
```

---

## Database Changes

### New Table: `governance_violations`

```sql
CREATE TABLE governance_violations (
    id          TEXT PRIMARY KEY,
    scan_id     TEXT NOT NULL REFERENCES scans(id) ON DELETE CASCADE,
    phase       TEXT NOT NULL,
    action      TEXT NOT NULL,
    action_category TEXT NOT NULL,
    allowed_categories TEXT NOT NULL,  -- JSON array
    context     TEXT,                  -- JSON object
    disposition TEXT NOT NULL DEFAULT 'blocked',  -- blocked | warned
    created_at  DATETIME DEFAULT CURRENT_TIMESTAMP
);
CREATE INDEX idx_gov_violations_scan ON governance_violations(scan_id);
```

### Scan Model Extension

```python
# In Scan model, add:
governance_mode: Mapped[str] = mapped_column(
    String(20), default="strict"
)  # "strict" | "warn" | "off"
governance_violations_count: Mapped[int] = mapped_column(Integer, default=0)
```

---

## Configuration

### Per-Scan Override (via `scan.config`)

Users can customize governance per scan at creation time:

```json
{
  "governance": {
    "mode": "strict",
    "policy_overrides": {
      "recon": {
        "allowed": ["passive_recon", "active_recon", "analysis", "vulnerability_scan"]
      }
    }
  }
}
```

This allows a user to explicitly expand recon scope to include vuln scanning if desired, while keeping the default restrictive.

### Global Config (`config/config.json`)

```json
{
  "governance": {
    "enabled": true,
    "default_mode": "strict",
    "unclassified_action_default": "exploitation",
    "custom_classifications": {
      "my_custom_tool": "active_recon"
    }
  }
}
```

---

## OperationMode → Phase Mapping

The existing `OperationMode` enum maps directly to governance phases:

| OperationMode   | Governance Phase Lock | Allowed Escalation        |
|-----------------|----------------------|---------------------------|
| `RECON_ONLY`    | `recon`              | None — stays in recon     |
| `ANALYZE_ONLY`  | `analyzing`          | None — no active testing  |
| `PROMPT_ONLY`   | `full_auto`          | AI-directed, all phases   |
| `FULL_AUTO`     | Progressive          | recon → analyzing → testing → exploitation |
| `AUTO_PENTEST`  | Progressive          | Same as FULL_AUTO         |

For progressive modes (`FULL_AUTO`, `AUTO_PENTEST`), the gate phase advances with `ScanService` phase transitions. For locked modes (`RECON_ONLY`, `ANALYZE_ONLY`), the phase never advances — the gate enforces a ceiling.

---

## TaskCategory Enforcement

The `TaskCategory` from `task_library.py` maps to a maximum allowed phase:

```python
TASK_CATEGORY_PHASE_CEILING = {
    "recon":          "recon",          # Cannot escalate past recon
    "vulnerability":  "testing",        # Can scan, cannot exploit
    "exploitation":   "exploitation",   # Full exploitation permitted
    "reporting":      "reporting",      # Read-only, no testing
    "custom":         "full_auto",      # User-defined, defaults to full
    "full_auto":      "full_auto",      # Everything permitted
}
```

When a scan starts with a task from the library, the governance gate reads the task's category and applies the ceiling. The scan's phase can never exceed this ceiling regardless of what the LLM agent or chain engine attempts.

---

## WebSocket Events

New event types for real-time governance visibility:

```python
# Violation event
{
    "type": "governance_violation",
    "scan_id": "...",
    "data": {
        "action": "payload_delivery",
        "category": "exploitation",
        "phase": "recon",
        "disposition": "blocked",
        "reason": "exploitation not permitted during recon phase"
    }
}

# Phase ceiling info
{
    "type": "governance_info",
    "scan_id": "...",
    "data": {
        "phase": "recon",
        "ceiling": "recon",
        "allowed_categories": ["passive_recon", "active_recon", "analysis"]
    }
}
```

---

## UI Changes

### Scan Configuration Panel

- New "Governance Mode" selector: **Strict** (default) | **Warn Only** | **Off**
- Phase ceiling indicator showing what the selected task type permits
- Tooltip explaining the implications of each mode

### Scan Dashboard

- Governance violation counter badge (red) in the scan header
- Expandable violation log panel showing blocked actions with timestamps
- Phase indicator showing current phase and ceiling

### Report Appendix

- "Governance Summary" section in generated reports
- Count of violations by category
- List of blocked actions (useful for audit trails)

---

## File Summary

| File | Change Type | Description |
|------|-------------|-------------|
| `backend/core/governance.py` | **NEW** | GovernanceGate, ActionClassifier, PhasePolicy, GovernanceViolation, GovernanceDecision |
| `backend/models/governance_violation.py` | **NEW** | SQLAlchemy model for persisted violations |
| `backend/models/scan.py` | MODIFY | Add `governance_mode`, `governance_violations_count` columns |
| `backend/services/scan_service.py` | MODIFY | Instantiate GovernanceGate, pass to pipeline, update phase transitions |
| `backend/core/autonomous_agent.py` | MODIFY | Accept gate, check before `_test_payload`, `_scan_for_vuln_type`, and mode dispatch |
| `backend/core/chain_engine.py` | MODIFY | Filter derived targets through gate |
| `backend/core/request_engine.py` | MODIFY | Optional gate check on outbound requests |
| `core/mcp_server.py` | MODIFY | Gate check on every tool call |
| `backend/core/task_library.py` | MODIFY | Add `phase_ceiling` to TaskCategory mapping |
| `backend/api/v1/scans.py` | MODIFY | Accept governance config in scan creation payload |
| `backend/api/v1/agent.py` | MODIFY | Pass gate to AutonomousAgent |
| `backend/api/websocket.py` | MODIFY | Add governance violation broadcast methods |
| `config/config.json` | MODIFY | Add global governance defaults |
| `frontend/src/components/ScanConfig.tsx` | MODIFY | Governance mode selector UI |
| `frontend/src/components/ScanDashboard.tsx` | MODIFY | Violation counter and log panel |
| `backend/models/__init__.py` | MODIFY | Export GovernanceViolation model |

---

## Migration Path

1. **Phase 1 — Core enforcement** (`governance.py`, model, scan_service integration). Ship with `warn` mode as default so existing workflows are not disrupted.
2. **Phase 2 — Deep integration** (autonomous_agent, chain_engine, MCP server, request_engine). Switch default to `strict`.
3. **Phase 3 — UI & reporting** (frontend components, report appendix).
4. **Phase 4 — Policy customization** (per-scan overrides, custom classifications, config UI).

---

## Testing Strategy

- **Unit tests**: `GovernanceGate.check()` against every phase/action combination in the default policy. Verify all 7 phases × 7 categories = 49 decisions.
- **Integration tests**: Start a scan with `RECON_ONLY` mode, inject an exploitation tool call, verify it is blocked and a violation record is created.
- **Chain escalation test**: Trigger a finding during recon, verify the chain engine does not generate exploitation-category derived targets.
- **Warn-mode test**: Same scenarios with `warn` mode, verify actions execute but violations are still logged.
- **Config override test**: Override policy to allow `vulnerability_scan` during recon, verify it passes.

---

## Risk Assessment

| Risk | Mitigation |
|------|-----------|
| Over-blocking legitimate actions | Classification table reviewed against all 100 vuln types; warn-mode available for debugging |
| Performance overhead per request | `GovernanceGate.check()` is O(1) dict lookup — negligible |
| LLM prompt injection bypassing gate | Gate operates at code level, not prompt level — LLM cannot bypass it |
| Breaking existing scan workflows | Phase 1 ships in warn-mode; strict-mode is opt-in until Phase 2 |
| Unclassified new tools being blocked | Defaults to most-restrictive; explicit classification required; config override available |
