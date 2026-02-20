## Status: COMPLETED
Rename executed on 2026-02-20.

# Project Rename & Upstream Severance Plan

**Branch:** `chore/project-rename-plan`
**Date:** 2026-02-19

---

## 1. Sever Upstream

```bash
git remote remove upstream
```

The repo at `ryan5hanahan/sploit.ai` becomes the sole origin. GitHub will no longer show "forked from CyberSecurityUP/sploit.ai". To fully remove the fork relationship, use GitHub Support or recreate the repo from a fresh push.

---

## 2. Name Candidates

| Name | Vibe | Domain-style | Notes |
|------|------|-------------|-------|
| **Aegis** | Shield / protection | `aegis-sec` | Greek mythological shield. Strong, clean. |
| **Spectra** | Spectrum of attacks | `spectra-sec` | Analytical, multi-vector feel. |
| **Pentacle** | Pentest + oracle | `pentacle` | Wordplay on pentest. Occult overtones (may be a feature or bug). |
| **Hadal** | Deepest ocean zone | `hadal-sec` | "Goes deeper than anyone else." Obscure, memorable. |
| **Obsidian** | Dark, sharp glass | `obsidian-sec` | Already used by note-taking app — possible confusion. |
| **Ironclad** | Armored / unbreakable | `ironclad` | Defensive connotation but works for offensive audit. |
| **Chimera** | Multi-headed beast | `chimera-sec` | Multi-agent, multi-LLM, multi-vector. |
| **Vaelstrom** | Stylized "maelstrom" | `vaelstrom` | Chaotic, overwhelming force. Unique spelling = available. |
| **Axiom** | Self-evident truth | `axiom-sec` | "The findings speak for themselves." Clean, enterprise-friendly. |
| **Wraith** | Phantom / ghost | `wraith-sec` | Stealth-oriented. Popular in gaming — could clash. |
| **Nullpoint** | Zero-day / null byte | `nullpoint` | Technical. Hacker-adjacent. |
| **Breach** | Direct, aggressive | `breach` | Says what it does. Possibly too generic. |
| **Talon** | Claw / strike | `talon-sec` | Sharp, fast. Already used by CrowdStrike subsidiary. |
| **Meridian** | Line of longitude | `meridian-sec` | "Complete coverage." Enterprise-friendly. |
| **Praetor** | Roman commander | `praetor-sec` | Authority, command. Fits autonomous agent theme. |

---

## 3. Scope of Rename

**443+ references** across the codebase in 10 categories:

### 3a. Critical Path (breaks the app if missed)

| Category | Count | Files | Example |
|----------|-------|-------|---------|
| Database filename | 5 | `backend/config.py`, `docker-compose*.yml`, `.env.example`, `migrations/run_migrations.py` | `sploitai.db` |
| Docker container names | 12 | `docker-compose.yml`, `docker-compose.lite.yml`, `docker-compose.kali.yml` | `sploitai-backend`, `sploitai-frontend` |
| Docker image names | 4 | `core/container_pool.py`, `core/kali_sandbox.py`, `backend/core/tool_executor.py` | `sploitai-kali:latest`, `sploitai-tools:latest` |
| Docker volume/network | 3 | `docker-compose*.yml` | `sploitai-data`, `sploitai-network` |
| Docker labels | 5 | `core/kali_sandbox.py`, `core/container_pool.py`, `Dockerfile.kali` | `sploitai.type`, `sploitai.scan_id` |
| Package names | 3 | `frontend/package.json`, `pyproject.toml` | `sploitai-frontend`, `sploitai` |
| Backend APP_NAME | 1 | `backend/config.py` | `sploit.ai v3` |
| Zustand persist key | 1 | `frontend/src/store/index.ts` | `sploitai-scan-store` |
| MCP server name | 2 | `core/mcp_server.py`, `config/config.json` | `sploitai-tools` |
| Inter-container hostnames | 6 | `core/mcp_tools_proxy.py`, `core/sandbox_manager.py` | `sploitai-mitmproxy` |
| Scheduler DB | 1 | `core/scheduler.py` | `sploitai_scheduler.db` |
| Cache directory | 1 | `backend/core/osint/exploitdb_client.py` | `/tmp/sploitai_exploitdb` |

### 3b. User-Facing (visible in UI/reports but won't crash)

| Category | Count | Files |
|----------|-------|-------|
| Frontend UI text | 6 | `Sidebar.tsx`, `Header.tsx`, `HomePage.tsx`, `SettingsPage.tsx`, `index.html` |
| Report branding | 8 | `report_generator.py`, `report_engine/generator.py`, `agent_generator.py`, `AgentStatusPage.tsx` |
| System prompts | 2 | `autonomous_agent.py`, `agent.py` |
| User-Agent headers | 12 | `autonomous_scanner.py`, `scan_service.py`, `ctf_coordinator.py`, various testers |
| Report download filenames | 2 | `AgentStatusPage.tsx` |
| CLI prompt | 1 | `sploitai.py` |

### 3c. Internal (comments, docstrings, test markers)

| Category | Count | Files |
|----------|-------|-------|
| Module docstrings (`"""sploit.ai v3 -`) | ~60 | All `backend/` modules |
| Payload test markers | 15 | `payload_generator.py`, `injection.py`, `logic.py`, `advanced_injection.py`, `file_access.py` |
| Documentation (`.md`) | ~200 | `README.md`, `QUICKSTART.md`, `docs/`, `use-cases/` |
| Shell scripts | 10 | `rebuild.sh`, `start.sh`, `install_tools.sh`, `build-kali.sh` |
| Benchmark runner | 8 | `tools/benchmark_runner.py` |

---

## 4. Execution Plan

### Phase 1: Sever upstream + rename repo
1. `git remote remove upstream`
2. Rename GitHub repo via Settings (ryan5hanahan/sploit.ai -> ryan5hanahan/NewName)
3. Update local remote: `git remote set-url origin https://github.com/ryan5hanahan/NewName.git`

### Phase 2: Critical path rename (one atomic commit)
- Database filename (`sploitai.db` -> `newname.db`) + migration script to rename existing file
- All `docker-compose*.yml` container/volume/network names
- Docker image references in Python (`sploitai-kali`, `sploitai-tools`, `sploitai-sandbox`)
- Docker labels in Python + Dockerfiles
- `backend/config.py` APP_NAME + DATABASE_URL
- `frontend/package.json` name
- `pyproject.toml` name
- Zustand persist key (will clear users' local storage — acceptable)
- MCP server name + config.json
- Inter-container hostnames in proxy/sandbox code
- `.env.example`

### Phase 3: User-facing rename
- Frontend UI text (Sidebar, Header, HomePage, SettingsPage, index.html title)
- Report templates (HTML headers, footers, branding)
- System prompts ("You are sploit.ai" -> "You are NewName")
- User-Agent strings
- Report download filenames
- CLI prompt string

### Phase 4: Internal cleanup
- Module docstrings (bulk `sed` — low risk)
- Payload test markers (change `sploitai` -> `newname` in injection/detection strings)
- README, QUICKSTART, docs/, use-cases/
- Shell scripts
- Benchmark runner references

### Phase 5: Verify
- Docker build all images
- Run frontend + backend
- Verify no "sploitai" in browser network tab or UI
- Verify container names changed
- Verify reports generate with new branding
- Grep entire repo for old name — should only appear in git history

---

## 5. Risks

| Risk | Mitigation |
|------|-----------|
| Existing `sploitai.db` won't be found after rename | Migration script renames file on startup |
| Docker volumes named `sploitai-data` orphaned | Document: users must `docker compose down -v` and rebuild |
| Zustand localStorage key change | Users lose cached dashboard state (acceptable — refreshes on load) |
| Payload markers used for detection | Must update both payload strings AND response-matching logic in sync |
| GitHub redirect from old repo name | GitHub auto-redirects for a while, but external links will eventually break |
| `sploitai-mitmproxy` hostname baked into proxy code | Must update `docker-compose.yml` service name AND Python hostname references together |
