# Proposal: Landing Page Redesign

## Problem

The current HomePage (`/`) has four separate "recent" sections (scans, findings, agent operations, activity feed) plus two stat grids and a chart — seven distinct sections that require significant scrolling and present overlapping information. The activity feed already contains scan, vulnerability, agent, and report events, making the dedicated "Recent Scans" and "Recent Findings" sections redundant. Key operational context (what's running right now, what needs attention) gets buried below stat cards.

**Current layout (top to bottom):**
1. Quick Actions header + "New Operation" button
2. Scan Stats (4 cards: total, running, completed, stopped)
3. Vulnerability Stats (4 cards: total, critical, high, medium)
4. Vulnerability Distribution (stacked bar chart)
5. Recent Agent Operations (3 items)
6. Recent Scans (5 items)
7. Recent Findings (5 items)
8. Activity Feed (15 items)

**Issues:**
- 8 stat cards consume the entire viewport before any actionable content
- "Recent Scans" and "Recent Findings" duplicate data already in the activity feed
- "Recent Agent Operations" is separate from scans despite both being assessment activities
- No at-a-glance view of what's actively running or what needs attention
- Vulnerability distribution chart is low-value on the landing page (better on a findings detail view)
- No trending data — are things getting better or worse?

---

## Proposed Layout

Consolidate into **four sections** that fit in two viewport heights and answer the three questions users have when they land:

1. **What's happening right now?** (Live Operations)
2. **What's the big picture?** (Key Metrics)
3. **What needs my attention?** (Unreviewed Findings)
4. **What happened recently?** (Unified Timeline)

### Section 1: Command Bar (sticky top, ~48px)

A persistent top bar with:
- **"New Operation"** button (primary CTA, links to `/agent`)
- **Quick target input** — paste a URL and press Enter to go to `/agent?target=<url>` with pre-filled target
- **Global search** (future) — search across findings, scans, operations

```
┌─────────────────────────────────────────────────────────────────────┐
│  [+ New Operation]   [ Enter target URL...              ] [Go]     │
└─────────────────────────────────────────────────────────────────────┘
```

### Section 2: Live Operations + Key Metrics (first viewport)

Split into two columns: left 60% for live operations, right 40% for metrics.

**Left: Live Operations Panel**

A unified list of currently-running and recently-completed operations (agent ops + scans), sorted by recency. Each card shows:
- Status indicator (pulsing dot for running, checkmark for done)
- Target URL (truncated)
- Type badge: "Agent" or "Scan"
- Progress: steps used / max steps (agent) or phase name (scan)
- Findings count with severity dots (colored circles: red=critical, orange=high, yellow=medium)
- Duration (running timer or completed time)
- Click to navigate to detail page

Show max 5 items. "Running" items always sort to top.

```
┌─ Live Operations ──────────────────────┐  ┌─ Key Metrics ─────────┐
│                                        │  │                       │
│  🟢 https://target.com                 │  │  Operations     12    │
│  Agent · Step 34/100 · 3 findings      │  │  ──────────           │
│  ████████░░░░░░ 34%  ·  12m running    │  │  Running    ●  2     │
│                                        │  │  Completed  ✓  8     │
│  🟢 https://api.example.com            │  │  Stopped    ■  2     │
│  Agent · Step 67/100 · 7 findings      │  │                       │
│  ████████████░░ 67%  ·  28m running    │  │  Findings      47    │
│                                        │  │  ──────────           │
│  ✓  https://app.staging.io             │  │  Critical   ●  3     │
│  Agent · 100/100 · 5 findings          │  │  High       ●  11    │
│  Completed · 45m · 2h ago              │  │  Medium     ●  18    │
│                                        │  │  Low        ●  15    │
│  ✓  https://shop.test.com              │  │                       │
│  Agent · 50/50 (stopped) · 2 findings  │  │  Trend (7d)           │
│  Stopped · 22m · 5h ago               │  │  ▁▂▃▅▇█▅  +12 new   │
│                                        │  │                       │
│  [ View all operations → ]             │  │  Est. Cost   $47.82  │
└────────────────────────────────────────┘  └───────────────────────┘
```

**Right: Key Metrics Panel**

Compact vertical stack replacing the current 8 stat cards:
- **Operations summary** — total count with running/completed/stopped breakdown (3 inline badges)
- **Findings summary** — total count with critical/high/medium/low breakdown (4 colored badges)
- **7-day sparkline** — tiny bar chart showing findings-per-day trend
- **Estimated cost** — total cost across all operations (from cost_tracker)

### Section 3: Attention Required (second viewport, top half)

A filtered findings list showing only **unreviewed high/critical findings** — the items that actually need human attention. Each row shows:
- Severity badge (CRITICAL / HIGH)
- Vulnerability title
- Target + endpoint
- Source operation (link)
- Time discovered
- Quick action buttons: "Review" (opens detail), "Dismiss" (marks reviewed)

If no unreviewed findings exist, show a success state: "All findings reviewed" with a green checkmark.

```
┌─ Attention Required (4 unreviewed) ──────────────────────────────────┐
│                                                                       │
│  CRITICAL  SQL Injection in /api/users?id=                           │
│  https://target.com · Agent Op #a3f2 · 12m ago     [Review] [Dismiss]│
│                                                                       │
│  HIGH  Broken Access Control on /api/admin/users                     │
│  https://target.com · Agent Op #a3f2 · 14m ago     [Review] [Dismiss]│
│                                                                       │
│  HIGH  Stored XSS in comment field                                   │
│  https://app.staging.io · Agent Op #b7c1 · 2h ago  [Review] [Dismiss]│
│                                                                       │
│  HIGH  JWT None Algorithm Accepted                                    │
│  https://api.example.com · Agent Op #c9d0 · 5h ago [Review] [Dismiss]│
│                                                                       │
└───────────────────────────────────────────────────────────────────────┘
```

### Section 4: Timeline (second viewport, bottom half)

The existing activity feed, but redesigned as a compact timeline with type icons and better density. Merges all event types (operations started/completed, findings discovered, reports generated) into one chronological stream.

Each entry is a single line:
- Type icon (Bot=agent, Bug=finding, FileText=report)
- Description (e.g., "Agent operation started on target.com")
- Severity/status badge (inline, small)
- Relative timestamp ("2m ago")

Show 15 items with "Load more" at bottom.

```
┌─ Timeline ────────────────────────────────────────────────────────────┐
│  🤖  Agent operation started on https://target.com          2m ago   │
│  🐛  CRITICAL SQL Injection found on /api/users             12m ago  │
│  🐛  HIGH Broken Access Control on /api/admin               14m ago  │
│  🤖  Agent operation completed on https://app.staging.io    2h ago   │
│  📄  Report generated for https://app.staging.io            2h ago   │
│  🐛  HIGH Stored XSS in comment field                       2h ago   │
│  🤖  Agent operation stopped on https://shop.test.com       5h ago   │
│  ...                                                                  │
│  [ Load more ]                                                        │
└───────────────────────────────────────────────────────────────────────┘
```

---

## What Gets Removed

| Current Section | Disposition |
|----------------|-------------|
| Scan Stats (4 cards) | **Merged** into Key Metrics (compact badges) |
| Vulnerability Stats (4 cards) | **Merged** into Key Metrics (compact badges) |
| Vulnerability Distribution chart | **Removed** from landing page (move to Reports or a dedicated Analytics page) |
| Recent Agent Operations (3 items) | **Replaced** by Live Operations (unified with scans) |
| Recent Scans (5 items) | **Replaced** by Live Operations (unified with agent ops) |
| Recent Findings (5 items) | **Replaced** by Attention Required (filtered to actionable items) |
| Activity Feed (15 items) | **Kept** as Timeline (same data, tighter presentation) |

---

## Backend Changes

### New Endpoint: `GET /api/v1/dashboard/attention`

Returns unreviewed high/critical findings across all operations and scans.

```python
# Request
GET /api/v1/dashboard/attention?limit=10

# Response
{
  "findings": [
    {
      "id": "vuln-uuid",
      "title": "SQL Injection in /api/users",
      "severity": "critical",
      "cvss_score": 9.8,
      "target": "https://target.com",
      "endpoint": "/api/users?id=",
      "source_type": "agent_operation",  # or "scan"
      "source_id": "op-uuid",
      "source_label": "Agent Op #a3f2",
      "discovered_at": "2026-02-19T18:30:00Z",
      "validation_status": "verified",
      "reviewed": false
    }
  ],
  "total_unreviewed": 4
}
```

This requires adding a `reviewed` boolean field to the Vulnerability model (default `false`), or using `validation_status` as a proxy (anything still `"pending"` is unreviewed).

### New Endpoint: `GET /api/v1/dashboard/live-operations`

Returns a unified list of recent operations and scans, sorted by recency with running items first.

```python
# Request
GET /api/v1/dashboard/live-operations?limit=5

# Response
{
  "operations": [
    {
      "id": "op-uuid",
      "type": "agent",          # "agent" or "scan"
      "target": "https://target.com",
      "status": "running",       # running, completed, stopped, failed
      "objective": "Full security assessment",
      "progress": 34,            # percentage
      "progress_label": "Step 34/100",
      "findings_count": 3,
      "severity_breakdown": {"critical": 1, "high": 1, "medium": 1, "low": 0},
      "duration_seconds": 720,
      "started_at": "2026-02-19T18:00:00Z",
      "completed_at": null,
      "cost_usd": 2.45
    }
  ]
}
```

### Modified Endpoint: `GET /api/v1/dashboard/stats`

Add a `trend` object to the existing stats response:

```python
{
  "scans": { ... },           # existing
  "vulnerabilities": { ... }, # existing
  "endpoints": { ... },       # existing
  "trend": {                  # NEW
    "period_days": 7,
    "findings_by_day": [2, 3, 5, 8, 12, 15, 12],
    "net_new_findings": 12,
    "total_cost_usd": 47.82
  }
}
```

### No Changes Required

The existing endpoints already provide the data for the Timeline section:
- `GET /api/v1/dashboard/activity-feed` — works as-is

---

## Frontend Changes

### Files Modified

| File | Change |
|------|--------|
| `frontend/src/pages/HomePage.tsx` | Rewrite — replace 8 sections with 4 consolidated sections |
| `frontend/src/services/api.ts` | Add `dashboardApi.getAttention()` and `dashboardApi.getLiveOperations()` methods |

### Files Added

| File | Purpose |
|------|---------|
| `frontend/src/components/dashboard/LiveOperations.tsx` | Unified operations list with progress bars |
| `frontend/src/components/dashboard/KeyMetrics.tsx` | Compact metric badges + sparkline |
| `frontend/src/components/dashboard/AttentionRequired.tsx` | Filtered high/critical findings with actions |
| `frontend/src/components/dashboard/Timeline.tsx` | Compact activity timeline |
| `frontend/src/components/dashboard/CommandBar.tsx` | Quick target input + new operation button |

### Files Removed

None — existing components stay for use on other pages.

---

## Interaction Details

### Polling Strategy
- **Live Operations**: Poll every 5s when any operation is running, 30s otherwise (matches AgentDetailPage pattern)
- **Attention Required**: Poll every 30s (findings don't change frequently)
- **Timeline**: Poll every 30s
- **Key Metrics**: Poll every 30s

### Navigation
- Click any Live Operation card → navigate to `/agent/:operationId` (agent) or `/scan/:scanId` (scan)
- Click "Review" on Attention Required → navigate to finding detail (in the source operation/scan page)
- Click any Timeline entry → navigate to the relevant detail page
- Click "View all operations" → navigate to `/agent`
- Quick target input → navigate to `/agent?target=<url>`

### Responsive Behavior
- Desktop (>1024px): Two-column layout for Section 2 (operations + metrics side by side)
- Tablet (768-1024px): Single column, metrics collapse to horizontal row
- Mobile (<768px): Full-width stacked sections, Command Bar stays sticky

---

## Migration

This is a non-breaking change. The old API endpoints remain available. The new endpoints are additive. The `HomePage.tsx` rewrite replaces the component in-place — same route (`/`), new content.

---

## Summary

| Metric | Before | After |
|--------|--------|-------|
| Sections | 8 | 4 |
| Stat cards | 8 | 0 (replaced by compact badges) |
| Redundant "recent" lists | 3 | 0 |
| API calls on load | 4 | 4 (different endpoints) |
| Scroll to see actionable items | ~2 viewports | 0 (above the fold) |
| Shows what's running | Partial (agent ops only) | Yes (unified operations) |
| Shows what needs attention | No | Yes (filtered unreviewed findings) |
| Shows cost | No | Yes (per-operation + total) |
| Shows trend | No | Yes (7-day sparkline) |
