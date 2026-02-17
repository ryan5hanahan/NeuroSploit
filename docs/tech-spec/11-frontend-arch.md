# Frontend Architecture

## Overview

React 18 single-page application built with Vite and TypeScript. Tailwind CSS for styling. Axios for HTTP API calls. React Router for client-side navigation. WebSocket for real-time scan updates.

## Project Structure

```
frontend/src/
├── App.tsx                    # Route definitions (17 routes)
├── main.tsx                   # React entry point
├── index.css                  # Tailwind imports
├── pages/                     # 17 page components
│   ├── HomePage.tsx           # Dashboard
│   ├── AutoPentestPage.tsx    # Auto pentest launcher
│   ├── VulnLabPage.tsx        # Vulnerability lab
│   ├── TerminalAgentPage.tsx  # Terminal agent
│   ├── NewScanPage.tsx        # New scan form
│   ├── ScanDetailsPage.tsx    # Scan details (live updates)
│   ├── CompareScanPage.tsx    # Scan comparison
│   ├── AgentStatusPage.tsx    # Agent status
│   ├── TaskLibraryPage.tsx    # Task library
│   ├── PromptsPage.tsx        # Prompt management
│   ├── TradecraftPage.tsx     # TTP library
│   ├── RealtimeTaskPage.tsx   # Real-time monitoring
│   ├── SchedulerPage.tsx      # Scan scheduling
│   ├── SandboxDashboardPage.tsx # Sandbox management
│   ├── ReportsPage.tsx        # Report listing
│   ├── ReportViewPage.tsx     # Report viewer
│   └── SettingsPage.tsx       # Settings and configuration
├── components/
│   └── layout/
│       └── Layout.tsx         # Shared layout with sidebar navigation
└── api/                       # Axios API client
```

## Routing

17 routes defined in `App.tsx`, all wrapped in the `Layout` component:

```tsx
<Layout>
  <Routes>
    <Route path="/" element={<HomePage />} />
    <Route path="/auto" element={<AutoPentestPage />} />
    <Route path="/vuln-lab" element={<VulnLabPage />} />
    <Route path="/terminal" element={<TerminalAgentPage />} />
    <Route path="/scan/new" element={<NewScanPage />} />
    <Route path="/scan/:scanId" element={<ScanDetailsPage />} />
    <Route path="/compare" element={<CompareScanPage />} />
    <Route path="/agent/:agentId" element={<AgentStatusPage />} />
    <Route path="/tasks" element={<TaskLibraryPage />} />
    <Route path="/prompts" element={<PromptsPage />} />
    <Route path="/tradecraft" element={<TradecraftPage />} />
    <Route path="/realtime" element={<RealtimeTaskPage />} />
    <Route path="/scheduler" element={<SchedulerPage />} />
    <Route path="/sandboxes" element={<SandboxDashboardPage />} />
    <Route path="/reports" element={<ReportsPage />} />
    <Route path="/reports/:reportId" element={<ReportViewPage />} />
    <Route path="/settings" element={<SettingsPage />} />
  </Routes>
</Layout>
```

## API Communication

- HTTP client: Axios
- Base URL: proxied to backend in development (Vite proxy config)
- Production: same origin served by nginx (frontend container) which proxies `/api/` to the backend container
- Real-time: WebSocket connection to `/ws/scan/{scan_id}` for live scan updates

## State Management

- React hooks (`useState`, `useEffect`) for local component state
- No global state library (no Redux, Zustand, or similar)
- API responses cached in component-level state
- WebSocket state managed per-component (ScanDetailsPage)

## Key Pages

### SettingsPage

Settings management with feature toggles and API configuration.

**LLM Provider Configuration:**
- Provider selector: Claude, OpenAI, OpenRouter, Bedrock, Ollama, Gemini
- API key inputs with masked display (shows `has_X_key` boolean, never raw keys)
- Model name input
- Max output tokens input
- Test LLM Connection button (calls `/api/v1/settings/test-llm`)

**Feature Toggles** (persisted to `.env` via settings API):
- Model Routing (`ENABLE_MODEL_ROUTING`)
- Knowledge Augmentation (`ENABLE_KNOWLEDGE_AUGMENTATION`)
- Browser Validation (`ENABLE_BROWSER_VALIDATION`)
- Extended Thinking (`ENABLE_EXTENDED_THINKING`)
- Aggressive Mode (`AGGRESSIVE_MODE`)
- Tracing (`ENABLE_TRACING`)
- Persistent Memory (`ENABLE_PERSISTENT_MEMORY`)
- Bug Bounty Integration (`ENABLE_BUGBOUNTY_INTEGRATION`)

**Scan Defaults:**
- Max Concurrent Scans (numeric input)
- Default Scan Type (quick/full/custom)
- Recon Enabled By Default (toggle)

**OSINT API Keys:**
- Shodan (`SHODAN_API_KEY`)
- Censys (`CENSYS_API_ID`, `CENSYS_API_SECRET`)
- VirusTotal (`VIRUSTOTAL_API_KEY`)
- BuiltWith (`BUILTWITH_API_KEY`)

**Database Management:**
- Clear database button
- Database stats display
- Installed tools check

### ScanDetailsPage

Real-time scan monitoring with WebSocket connection.

- **Progress**: Progress bar with percentage and current phase indicator
- **Log stream**: Live log viewer updated via WebSocket messages
- **Findings table**: Vulnerability list with severity badges, validation status, affected endpoints
- **Endpoints list**: Discovered endpoints with technologies and parameters
- **Scan controls**: Stop, Pause, Resume, Skip-to-phase buttons

### VulnLabPage

Isolated vulnerability testing interface.

- **Vulnerability type selector**: 11 categories (Injection, XSS, File Inclusion, SSRF/XXE, Auth/Session, Deserialization, Misconfiguration, Logic, API, Client-Side, Other), each with subtypes totaling 100+ vulnerability types
- **Target URL input**: URL to test against
- **Auth configuration**: Auth type selector with credential input
- **CTF mode**: Toggle for CTF pipeline, agent count (2-6), custom flag patterns, flag submission URL
- **Challenge history**: Table of past challenges with status, result, findings counts, duration

### NewScanPage

Scan creation form.

- Target URL(s) input
- Scan type selection (quick/full/custom)
- Recon toggle
- Auth configuration (cookie, bearer, basic, header)
- Custom headers input
- Custom prompt / prompt library selection
- Tradecraft TTP selection

### ReportsPage / ReportViewPage

Report listing and viewer.

- Reports list with scan association, format, generation type (auto/manual), partial flag
- Report viewer renders HTML report content (from `report_generator.py` output)

### CompareScanPage

Side-by-side scan comparison.

- Select two completed scans
- Structured diff of vulnerabilities (new, resolved, persistent)
- Severity distribution comparison

## Build Configuration

| Tool | Purpose |
|------|---------|
| Vite | Bundler, dev server, HMR |
| TypeScript | Type checking |
| Tailwind CSS | Utility-first styling |
| React Router | Client-side routing |
| Axios | HTTP client |

Production build outputs to `frontend/dist/`, served by nginx in the frontend container.
