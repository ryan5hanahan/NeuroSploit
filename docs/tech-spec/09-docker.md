# Docker

## Overview

Multi-stage Docker builds for backend (full and lite variants) and frontend. Docker Compose orchestrates four services: backend, frontend, mitmproxy (optional), and interactsh (optional).

## Dockerfile.backend (Full)

File: `docker/Dockerfile.backend`

### Stage 1: Go Tools Builder

- Base image: `golang:1.22-alpine`
- Installs `git` via apk
- Builds ProjectDiscovery and community Go tools in three parallel batches:

**Batch 1** (parallel):
- subfinder, httpx, nuclei, waybackurls, ffuf

**Batch 2** (parallel):
- katana, dnsx, gau, gf, qsreplace

**Batch 3** (parallel):
- dalfox, gobuster, gospider, anew

**Optional** (non-fatal if build fails):
- naabu, hakrawler

All tools installed via `go install` to `/go/bin/`.

### Stage 2: Python Dependencies

- Base image: `python:3.11-slim`
- Installs from `backend/requirements.txt` with `--user` flag
- Additional pip installs: `arjun`, `wafw00f`, `playwright>=1.40.0`

### Stage 3: Final Runtime

- Base image: `python:3.11-slim`
- System packages via apt: `curl`, `wget`, `git`, `dnsutils`, `nmap`, `sqlmap`, `jq`, `ca-certificates`, `libpcap0.8`
- Copies Go binaries from Stage 1: `/go/bin/` -> `/usr/local/bin/`
- Copies Python packages from Stage 2: `/root/.local` -> `/root/.local`
- Installs Playwright Chromium browser: `python -m playwright install --with-deps chromium`
- Application code copied:
  - `backend/` -- FastAPI application
  - `core/` -- Shared core modules (sandbox, MCP, opsec, browser validator)
  - `config/` -- config.json, opsec_profiles.json
  - `prompts/` -- Prompt template files
  - `tools/` -- Tool wrapper scripts
  - `models/` -- Bug bounty dataset
- **Note**: `agents/` directory is NOT copied (CLI-only)
- Creates data directories: `data/reports`, `data/scans`, `data/recon`, `/root/.config/nuclei`
- Downloads wordlists to `/opt/wordlists/`: `common.txt`, `subdomains-5000.txt` (from SecLists)
- Updates nuclei templates (silent, non-fatal)
- Healthcheck: `curl -f http://localhost:8000/api/health` every 30s
- Exposes port 8000
- CMD: `uvicorn backend.main:app --host 0.0.0.0 --port 8000`

## Dockerfile.backend.lite (Dev)

File: `docker/Dockerfile.backend.lite`

Single-stage build for faster development iteration. No Go security tools.

- Base image: `python:3.11-slim`
- System packages: `curl`, `ca-certificates`, Chromium dependencies (libnss3, libatk, libcups2, libdrm2, libxkbcommon0, etc.)
- Installs from `backend/requirements.txt` + `playwright>=1.40.0`
- Installs Playwright Chromium: `python -m playwright install chromium`
- Same application code as full build: `backend/`, `core/`, `config/`, `prompts/`, `tools/`, `models/`
- Creates data directories: `data/reports`, `data/scans`, `data/recon`
- Same healthcheck and CMD as full build

## Dockerfile.frontend

File: `docker/Dockerfile.frontend`

Two-stage build:

### Build Stage
- Base image: `node:20-alpine`
- `npm install` from `frontend/package*.json`
- `npm run build` outputs to `dist/`

### Production Stage
- Base image: `nginx:alpine`
- Copies `dist/` -> `/usr/share/nginx/html`
- Copies `docker/nginx.conf` -> `/etc/nginx/conf.d/default.conf`
- Exposes port 80
- CMD: `nginx -g "daemon off;"`

## docker-compose.yml

### Services

#### backend

| Setting | Value |
|---------|-------|
| Build context | `.` (project root) |
| Dockerfile | `docker/Dockerfile.backend` |
| Container name | `sploitai-backend` |
| env_file | `.env` |
| Environment overrides | `ANTHROPIC_API_KEY`, `OPENAI_API_KEY`, `DATABASE_URL`, `ENABLE_BROWSER_VALIDATION` |
| Volumes | `sploitai-data:/app/data`, `/var/run/docker.sock:/var/run/docker.sock` |
| Ports | `8000:8000` |
| Restart | `unless-stopped` |
| Healthcheck | `curl -f http://localhost:8000/api/health` every 30s, timeout 10s, 3 retries |

The Docker socket mount enables the sandbox manager to create/exec into sandbox containers from within the backend container.

#### frontend

| Setting | Value |
|---------|-------|
| Build context | `.` (project root) |
| Dockerfile | `docker/Dockerfile.frontend` |
| Container name | `sploitai-frontend` |
| Ports | `8080:80` |
| Depends on | `backend` (condition: `service_healthy`) |
| Restart | `unless-stopped` |

#### mitmproxy (profile: proxy)

| Setting | Value |
|---------|-------|
| Image | `mitmproxy/mitmproxy:latest` |
| Container name | `sploitai-mitmproxy` |
| Profile | `proxy` (only starts with `--profile proxy`) |
| Entrypoint | `mitmweb --web-host 0.0.0.0 --web-port 8082 --listen-port 8081 --set web_open_browser=false --set flow_detail=2` |
| Ports | `8081:8081` (proxy), `8082:8082` (web UI) |
| Volumes | `mitmproxy-data:/home/mitmproxy/.mitmproxy`, `mitmproxy-captures:/captures` |
| Healthcheck | `wget --spider -q http://localhost:8082` every 15s |
| Resource limits | Memory: 1G, CPU: 1.0 |

#### interactsh (profile: oob)

| Setting | Value |
|---------|-------|
| Image | `projectdiscovery/interactsh-server:latest` |
| Container name | `sploitai-interactsh` |
| Profile | `oob` (only starts with `--profile oob`) |
| Command | `-domain ${INTERACTSH_DOMAIN:-interact.local} -ip 0.0.0.0` |
| Ports | `8083:80`, `8084:443` |
| Resource limits | Memory: 512M, CPU: 0.5 |

### Volumes

| Volume | Purpose |
|--------|---------|
| `sploitai-data` | Persistent SQLite database and scan data (`/app/data`) |
| `mitmproxy-data` | mitmproxy TLS certificates |
| `mitmproxy-captures` | Captured HTTP traffic |

### Network

```yaml
networks:
  default:
    name: sploitai-network
```

All services share `sploitai-network`. Sandbox containers are also attached to this network for inter-container communication (e.g., sandbox -> mitmproxy proxy routing).

## Build Commands

```bash
# Rebuild backend with full security tools
docker compose build backend

# Rebuild frontend
docker compose build frontend

# Start core services (backend + frontend)
docker compose up -d

# Start with mitmproxy OPSEC proxy
docker compose --profile proxy up -d

# Start with interactsh OOB detection
docker compose --profile oob up -d

# Start everything
docker compose --profile proxy --profile oob up -d

# Use lite backend for development (edit docker-compose.yml dockerfile field)
# dockerfile: docker/Dockerfile.backend.lite
docker compose build backend && docker compose up -d
```

## Container Relationships

```
frontend (nginx:80) --depends_on--> backend (uvicorn:8000)
                                      |
                                      |--(docker.sock)--> sandbox containers (sploitai-kali)
                                      |--(HTTP_PROXY)---> mitmproxy (8081) [when proxy profile active]
                                      |--(poll)---------> interactsh (80) [when oob profile active]
```

## Key Notes

- `.env` file is injected at startup via `env_file:` -- it is read-only inside the container. Runtime settings changes via the Settings API persist to in-memory dict and `os.environ`, but do not survive container restarts.
- The Docker socket mount (`/var/run/docker.sock`) is required for sandbox container management. Without it, sandbox features are unavailable but the backend still runs.
- Both Dockerfiles (full and lite) include Playwright + Chromium for browser validation support.
- The `agents/` directory is intentionally excluded from all backend Docker builds -- it contains CLI-only code.
