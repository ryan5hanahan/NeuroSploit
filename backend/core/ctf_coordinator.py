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
from typing import Dict, List, Any, Optional, Callable
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

            # Phase 2: LLM Analysis + work distribution
            await self._progress_callback(25, "ctf_pipeline:analysis")
            assignments = await self._run_analysis_phase()
            if self._cancelled:
                return self._build_final_report(start_time)

            # Phase 3: Parallel testing
            await self._progress_callback(35, "ctf_pipeline:testing")
            await self._run_testing_phase(assignments)

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
        """Launch N-1 testing agents in parallel."""
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
