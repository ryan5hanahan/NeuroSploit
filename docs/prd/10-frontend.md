# Frontend

## Overview

React/TypeScript single-page application providing the web UI for NeuroSploit. Built with Vite, styled with Tailwind CSS, and connected to the FastAPI backend via REST API and WebSocket.

## Pages

| Route | Page | Description |
|-------|------|-------------|
| `/` | HomePage | Dashboard with scan overview, recent activity, severity charts |
| `/auto` | AutoPentestPage | One-click autonomous pentest launcher |
| `/vuln-lab` | VulnLabPage | Vulnerability lab: select vuln type, configure target, launch isolated tests. CTF mode toggle. |
| `/terminal` | TerminalAgentPage | Interactive terminal-style agent interface |
| `/scan/new` | NewScanPage | Create new scan: target URLs, scan type, auth config, custom prompt, tradecraft selection |
| `/scan/:scanId` | ScanDetailsPage | Live scan view: progress bar, phase indicator, real-time logs, findings list, endpoints, WebSocket updates |
| `/compare` | CompareScanPage | Side-by-side scan comparison with vulnerability diff |
| `/agent/:agentId` | AgentStatusPage | Agent execution details and real-time status |
| `/tasks` | TaskLibraryPage | Browse and manage agent tasks |
| `/prompts` | PromptsPage | Prompt library management |
| `/tradecraft` | TradecraftPage | Tradecraft TTP library (MITRE ATT&CK aligned) |
| `/realtime` | RealtimeTaskPage | Real-time task monitoring |
| `/scheduler` | SchedulerPage | Scan scheduling configuration |
| `/sandboxes` | SandboxDashboardPage | Docker sandbox container management |
| `/reports` | ReportsPage | Report listing and download |
| `/reports/:reportId` | ReportViewPage | Full report viewer with HTML rendering |
| `/settings` | SettingsPage | LLM provider config, API keys, feature toggles, installed tools check, DB management |

17 routes total.

## Key UI Features

### Real-Time Scan Updates
WebSocket connection to `/ws/scan/{scan_id}` provides live updates during scan execution. The `ScanDetailsPage` renders a progress bar, phase indicator, streaming log output, and an incrementally updated findings list.

### Severity Color Coding
Consistent severity-based color scheme used throughout the application:

| Severity | Color |
|----------|-------|
| Critical | Red |
| High | Orange |
| Medium | Yellow |
| Low | Blue |
| Info | Gray |

### Settings Page
Organized into sections:
- **LLM Provider**: Select and configure the active LLM provider
- **API Keys**: Input fields for provider API keys (Anthropic, OpenAI, Gemini, OpenRouter)
- **Advanced Features**: Toggle switches for `ENABLE_MODEL_ROUTING`, `ENABLE_BROWSER_VALIDATION`, `ENABLE_KNOWLEDGE_AUGMENTATION`, `ENABLE_EXTENDED_THINKING`, `AGGRESSIVE_MODE`, `RECON_ENABLED_BY_DEFAULT`
- **Scan Defaults**: `MAX_CONCURRENT_SCANS`, `DEFAULT_SCAN_TYPE`
- **OSINT Integration**: OSINT tool configuration
- **Database Management**: Database maintenance operations

### Navigation
Responsive sidebar navigation with dark theme. All routes accessible from the sidebar.

## Tech Stack

| Technology | Purpose |
|-----------|---------|
| React 18 | UI framework |
| TypeScript | Type-safe JavaScript |
| Vite | Build tool and dev server |
| Tailwind CSS | Utility-first styling |
| React Router | Client-side routing |
| Axios | HTTP API client |
| WebSocket | Real-time scan updates |

## Build and Deployment

### Development
```bash
npm run dev
```
Vite dev server on port 3000. API requests are proxied to the FastAPI backend on port 8000.

### Production Build
```bash
npm run build
```
Produces static files in `frontend/dist/`. The FastAPI backend serves these via a catch-all route, enabling single-origin deployment without a separate static file server.

### Docker
`docker/Dockerfile.frontend` builds the React application and serves it via nginx on port 80 (mapped to host port 8080 in docker-compose).

## API Communication

- **REST**: Axios-based HTTP client for all CRUD operations against `/api/v1/*` endpoints.
- **WebSocket**: Native WebSocket connection for live scan monitoring at `/ws/scan/{scan_id}`.
- **Settings persistence**: `PUT /api/v1/settings` writes configuration to both in-memory state and `.env` file on the backend.

## Limitations

- No user authentication or role-based access control.
- Dark theme only -- no light theme or theme toggle.
- No offline support or PWA features.
- WebSocket reconnection is basic (no exponential backoff on disconnect).
