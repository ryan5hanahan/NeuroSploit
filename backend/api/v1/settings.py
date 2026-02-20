"""
NeuroSploit v3 - Settings API Endpoints
"""
import asyncio
import os
import re
import time
from pathlib import Path
from typing import Optional, Dict
from fastapi import APIRouter, Depends, HTTPException, Request
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select, delete, text
from pydantic import BaseModel

from backend.db.database import get_db, engine
from backend.models import Scan, Target, Endpoint, Vulnerability, VulnerabilityTest, Report
from backend.models.llm_test_result import LlmTestResult

router = APIRouter()

# Path to .env file (project root)
ENV_FILE_PATH = Path(__file__).parent.parent.parent.parent / ".env"


def _sanitize_env_value(value: str) -> str:
    """Sanitize a value for safe .env file inclusion.

    Prevents newline injection (which could create extra KEY=VALUE lines)
    and strips control characters that could corrupt the file.
    """
    # Remove newlines, carriage returns, and null bytes
    sanitized = value.replace("\n", "").replace("\r", "").replace("\0", "")
    # If value contains spaces, quotes, or special chars, wrap in quotes
    if any(c in sanitized for c in (" ", "'", '"', "#", "=", "$", "`")):
        # Escape existing double quotes and wrap
        sanitized = '"' + sanitized.replace('"', '\\"') + '"'
    return sanitized


def _update_env_file(updates: Dict[str, str]) -> bool:
    """
    Update key=value pairs in the .env file without breaking formatting.
    - If the key exists (even commented out), update its value
    - If the key doesn't exist, append it
    - Preserves comments and blank lines
    - Sanitizes values to prevent newline injection
    """
    if not ENV_FILE_PATH.exists():
        return False

    try:
        lines = ENV_FILE_PATH.read_text().splitlines()
        updated_keys = set()

        new_lines = []
        for line in lines:
            stripped = line.strip()
            matched = False

            for key, value in updates.items():
                # Match: KEY=..., # KEY=..., #KEY=...
                pattern = rf'^#?\s*{re.escape(key)}\s*='
                if re.match(pattern, stripped):
                    # Replace with uncommented key=sanitized_value
                    new_lines.append(f"{key}={_sanitize_env_value(value)}")
                    updated_keys.add(key)
                    matched = True
                    break

            if not matched:
                new_lines.append(line)

        # Append any keys that weren't found in existing file
        for key, value in updates.items():
            if key not in updated_keys:
                new_lines.append(f"{key}={_sanitize_env_value(value)}")

        # Write back with trailing newline
        ENV_FILE_PATH.write_text("\n".join(new_lines) + "\n")
        return True
    except Exception as e:
        print(f"Warning: Failed to update .env file: {e}")
        return False


class SettingsUpdate(BaseModel):
    """Settings update schema"""
    llm_provider: Optional[str] = None
    anthropic_api_key: Optional[str] = None
    openai_api_key: Optional[str] = None
    openrouter_api_key: Optional[str] = None
    aws_access_key_id: Optional[str] = None
    aws_secret_access_key: Optional[str] = None
    aws_session_token: Optional[str] = None
    aws_bedrock_region: Optional[str] = None
    aws_bedrock_model: Optional[str] = None
    llm_model: Optional[str] = None
    max_concurrent_scans: Optional[int] = None
    aggressive_mode: Optional[bool] = None
    default_scan_type: Optional[str] = None
    recon_enabled_by_default: Optional[bool] = None
    enable_model_routing: Optional[bool] = None
    enable_knowledge_augmentation: Optional[bool] = None
    enable_browser_validation: Optional[bool] = None
    enable_extended_thinking: Optional[bool] = None
    max_output_tokens: Optional[int] = None
    # OSINT API keys
    shodan_api_key: Optional[str] = None
    censys_api_id: Optional[str] = None
    censys_api_secret: Optional[str] = None
    virustotal_api_key: Optional[str] = None
    builtwith_api_key: Optional[str] = None
    # Per-tier model selection (used when model routing is enabled)
    model_fast: Optional[str] = None
    model_balanced: Optional[str] = None
    model_deep: Optional[str] = None
    # Per-tier provider overrides (mix providers across tiers)
    provider_fast: Optional[str] = None
    provider_balanced: Optional[str] = None
    provider_deep: Optional[str] = None
    # Tracing & memory
    enable_tracing: Optional[bool] = None
    enable_persistent_memory: Optional[bool] = None
    # Bug bounty
    enable_bugbounty_integration: Optional[bool] = None
    hackerone_api_token: Optional[str] = None
    hackerone_username: Optional[str] = None
    # Cost tracking
    cost_budget_per_scan: Optional[float] = None
    cost_warn_at_pct: Optional[float] = None
    enable_cost_tracking: Optional[bool] = None
    # Security testing
    enable_waf_evasion: Optional[bool] = None
    waf_confidence_threshold: Optional[float] = None
    confidence_pivot_threshold: Optional[int] = None
    confidence_reject_threshold: Optional[int] = None
    # Scan tuning
    default_timeout: Optional[int] = None
    max_requests_per_second: Optional[int] = None
    # Vulnerability enrichment
    nvd_api_key: Optional[str] = None
    enable_vuln_enrichment: Optional[bool] = None


class SettingsResponse(BaseModel):
    """Settings response schema"""
    llm_provider: str = "claude"
    has_anthropic_key: bool = False
    has_openai_key: bool = False
    has_openrouter_key: bool = False
    has_aws_bedrock_config: bool = False
    max_concurrent_scans: int = 3
    aggressive_mode: bool = False
    default_scan_type: str = "full"
    recon_enabled_by_default: bool = True
    enable_model_routing: bool = False
    enable_knowledge_augmentation: bool = False
    enable_browser_validation: bool = False
    enable_extended_thinking: bool = False
    max_output_tokens: Optional[int] = None
    aws_bedrock_region: str = "us-east-1"
    aws_bedrock_model: str = ""
    llm_model: str = ""
    # Per-tier model selection
    model_fast: str = ""
    model_balanced: str = ""
    model_deep: str = ""
    # Per-tier provider overrides
    provider_fast: str = ""
    provider_balanced: str = ""
    provider_deep: str = ""
    # OSINT API key presence (masked)
    has_shodan_key: bool = False
    has_censys_key: bool = False
    has_virustotal_key: bool = False
    has_builtwith_key: bool = False
    # Tracing & memory
    enable_tracing: bool = False
    enable_persistent_memory: bool = True
    # Bug bounty
    enable_bugbounty_integration: bool = False
    has_hackerone_config: bool = False
    # Cost tracking
    cost_budget_per_scan: float = 5.00
    cost_warn_at_pct: float = 80.0
    enable_cost_tracking: bool = True
    # Security testing
    enable_waf_evasion: bool = True
    waf_confidence_threshold: float = 0.7
    confidence_pivot_threshold: int = 30
    confidence_reject_threshold: int = 40
    # Scan tuning
    default_timeout: int = 30
    max_requests_per_second: int = 10
    # Vulnerability enrichment
    has_nvd_key: bool = False
    enable_vuln_enrichment: bool = True


def _load_settings_from_env() -> dict:
    """
    Load settings from environment variables / .env file on startup.
    This ensures settings persist across server restarts and browser sessions.
    """
    from dotenv import load_dotenv
    # Re-read .env file to pick up disk-persisted values
    if ENV_FILE_PATH.exists():
        load_dotenv(ENV_FILE_PATH, override=True)

    def _env_bool(key: str, default: bool = False) -> bool:
        val = os.getenv(key, "").strip().lower()
        if val in ("true", "1", "yes"):
            return True
        if val in ("false", "0", "no"):
            return False
        return default

    def _env_int(key: str, default=None):
        val = os.getenv(key, "").strip()
        if val:
            try:
                return int(val)
            except ValueError:
                pass
        return default

    def _env_float(key: str, default=None):
        val = os.getenv(key, "").strip()
        if val:
            try:
                return float(val)
            except ValueError:
                pass
        return default

    # Detect provider from env override or from which keys are set
    provider = os.getenv("DEFAULT_LLM_PROVIDER", "").strip().lower()
    if not provider:
        if os.getenv("ANTHROPIC_API_KEY"):
            provider = "claude"
        elif os.getenv("OPENAI_API_KEY"):
            provider = "openai"
        elif os.getenv("OPENROUTER_API_KEY"):
            provider = "openrouter"
        elif os.getenv("AWS_ACCESS_KEY_ID") or os.getenv("AWS_PROFILE"):
            provider = "bedrock"
        else:
            provider = "claude"

    return {
        "llm_provider": provider,
        "anthropic_api_key": os.getenv("ANTHROPIC_API_KEY", ""),
        "openai_api_key": os.getenv("OPENAI_API_KEY", ""),
        "openrouter_api_key": os.getenv("OPENROUTER_API_KEY", ""),
        "gemini_api_key": os.getenv("GEMINI_API_KEY", ""),
        "aws_access_key_id": os.getenv("AWS_ACCESS_KEY_ID", ""),
        "aws_secret_access_key": os.getenv("AWS_SECRET_ACCESS_KEY", ""),
        "aws_session_token": os.getenv("AWS_SESSION_TOKEN", ""),
        "aws_bedrock_region": os.getenv("AWS_BEDROCK_REGION", "us-east-1"),
        "aws_bedrock_model": os.getenv("AWS_BEDROCK_MODEL", ""),
        "llm_model": os.getenv("DEFAULT_LLM_MODEL", ""),
        "max_concurrent_scans": _env_int("MAX_CONCURRENT_SCANS", 3),
        "aggressive_mode": _env_bool("AGGRESSIVE_MODE", False),
        "default_scan_type": os.getenv("DEFAULT_SCAN_TYPE", "full"),
        "recon_enabled_by_default": _env_bool("RECON_ENABLED_BY_DEFAULT", True),
        "enable_model_routing": _env_bool("ENABLE_MODEL_ROUTING", False),
        "model_fast": os.getenv("LLM_MODEL_FAST", ""),
        "model_balanced": os.getenv("LLM_MODEL_BALANCED", ""),
        "model_deep": os.getenv("LLM_MODEL_DEEP", ""),
        "provider_fast": os.getenv("LLM_PROVIDER_FAST", ""),
        "provider_balanced": os.getenv("LLM_PROVIDER_BALANCED", ""),
        "provider_deep": os.getenv("LLM_PROVIDER_DEEP", ""),
        "enable_knowledge_augmentation": _env_bool("ENABLE_KNOWLEDGE_AUGMENTATION", False),
        "enable_browser_validation": _env_bool("ENABLE_BROWSER_VALIDATION", False),
        "enable_extended_thinking": _env_bool("ENABLE_EXTENDED_THINKING", False),
        "max_output_tokens": _env_int("MAX_OUTPUT_TOKENS", None),
        # OSINT API keys
        "shodan_api_key": os.getenv("SHODAN_API_KEY", ""),
        "censys_api_id": os.getenv("CENSYS_API_ID", ""),
        "censys_api_secret": os.getenv("CENSYS_API_SECRET", ""),
        "virustotal_api_key": os.getenv("VIRUSTOTAL_API_KEY", ""),
        "builtwith_api_key": os.getenv("BUILTWITH_API_KEY", ""),
        # Tracing & memory
        "enable_tracing": _env_bool("ENABLE_TRACING", False),
        "enable_persistent_memory": _env_bool("ENABLE_PERSISTENT_MEMORY", True),
        # Bug bounty
        "enable_bugbounty_integration": _env_bool("ENABLE_BUGBOUNTY_INTEGRATION", False),
        "hackerone_api_token": os.getenv("HACKERONE_API_TOKEN", ""),
        "hackerone_username": os.getenv("HACKERONE_USERNAME", ""),
        # Cost tracking
        "cost_budget_per_scan": _env_float("COST_BUDGET_PER_SCAN", 5.00),
        "cost_warn_at_pct": _env_float("COST_WARN_AT_PCT", 80.0),
        "enable_cost_tracking": _env_bool("ENABLE_COST_TRACKING", True),
        # Security testing
        "enable_waf_evasion": _env_bool("ENABLE_WAF_EVASION", True),
        "waf_confidence_threshold": _env_float("WAF_CONFIDENCE_THRESHOLD", 0.7),
        "confidence_pivot_threshold": _env_int("CONFIDENCE_PIVOT_THRESHOLD", 30),
        "confidence_reject_threshold": _env_int("CONFIDENCE_REJECT_THRESHOLD", 40),
        # Scan tuning
        "default_timeout": _env_int("DEFAULT_TIMEOUT", 30),
        "max_requests_per_second": _env_int("MAX_REQUESTS_PER_SECOND", 10),
        # Vulnerability enrichment
        "nvd_api_key": os.getenv("NVD_API_KEY", ""),
        "enable_vuln_enrichment": _env_bool("ENABLE_VULN_ENRICHMENT", True),
    }


# Load settings from .env on module import (server start)
_settings = _load_settings_from_env()


@router.get("", response_model=SettingsResponse)
async def get_settings():
    """Get current settings"""
    import os
    return SettingsResponse(
        llm_provider=_settings["llm_provider"],
        has_anthropic_key=bool(_settings["anthropic_api_key"] or os.getenv("ANTHROPIC_API_KEY")),
        has_openai_key=bool(_settings["openai_api_key"] or os.getenv("OPENAI_API_KEY")),
        has_openrouter_key=bool(_settings["openrouter_api_key"] or os.getenv("OPENROUTER_API_KEY")),
        has_aws_bedrock_config=bool(
            _settings.get("aws_access_key_id") or os.getenv("AWS_ACCESS_KEY_ID") or os.getenv("AWS_PROFILE")
        ),
        max_concurrent_scans=_settings["max_concurrent_scans"],
        aggressive_mode=_settings["aggressive_mode"],
        default_scan_type=_settings["default_scan_type"],
        recon_enabled_by_default=_settings["recon_enabled_by_default"],
        enable_model_routing=_settings["enable_model_routing"],
        enable_knowledge_augmentation=_settings["enable_knowledge_augmentation"],
        enable_browser_validation=_settings["enable_browser_validation"],
        enable_extended_thinking=_settings["enable_extended_thinking"],
        max_output_tokens=_settings["max_output_tokens"],
        aws_bedrock_region=_settings.get("aws_bedrock_region", "us-east-1"),
        aws_bedrock_model=_settings.get("aws_bedrock_model", ""),
        llm_model=_settings.get("llm_model", ""),
        model_fast=_settings.get("model_fast", ""),
        model_balanced=_settings.get("model_balanced", ""),
        model_deep=_settings.get("model_deep", ""),
        provider_fast=_settings.get("provider_fast", ""),
        provider_balanced=_settings.get("provider_balanced", ""),
        provider_deep=_settings.get("provider_deep", ""),
        has_shodan_key=bool(_settings.get("shodan_api_key") or os.getenv("SHODAN_API_KEY")),
        has_censys_key=bool(
            (_settings.get("censys_api_id") or os.getenv("CENSYS_API_ID"))
            and (_settings.get("censys_api_secret") or os.getenv("CENSYS_API_SECRET"))
        ),
        has_virustotal_key=bool(_settings.get("virustotal_api_key") or os.getenv("VIRUSTOTAL_API_KEY")),
        has_builtwith_key=bool(_settings.get("builtwith_api_key") or os.getenv("BUILTWITH_API_KEY")),
        enable_tracing=_settings["enable_tracing"],
        enable_persistent_memory=_settings["enable_persistent_memory"],
        enable_bugbounty_integration=_settings["enable_bugbounty_integration"],
        has_hackerone_config=bool(
            (_settings.get("hackerone_api_token") or os.getenv("HACKERONE_API_TOKEN"))
            and (_settings.get("hackerone_username") or os.getenv("HACKERONE_USERNAME"))
        ),
        # Cost tracking
        cost_budget_per_scan=_settings["cost_budget_per_scan"],
        cost_warn_at_pct=_settings["cost_warn_at_pct"],
        enable_cost_tracking=_settings["enable_cost_tracking"],
        # Security testing
        enable_waf_evasion=_settings["enable_waf_evasion"],
        waf_confidence_threshold=_settings["waf_confidence_threshold"],
        confidence_pivot_threshold=_settings["confidence_pivot_threshold"],
        confidence_reject_threshold=_settings["confidence_reject_threshold"],
        # Scan tuning
        default_timeout=_settings["default_timeout"],
        max_requests_per_second=_settings["max_requests_per_second"],
        # Vulnerability enrichment
        has_nvd_key=bool(_settings.get("nvd_api_key") or os.getenv("NVD_API_KEY")),
        enable_vuln_enrichment=_settings.get("enable_vuln_enrichment", True),
    )


@router.put("", response_model=SettingsResponse)
async def update_settings(settings_data: SettingsUpdate):
    """Update settings - persists to memory, env vars, AND .env file"""
    env_updates: Dict[str, str] = {}

    if settings_data.llm_provider is not None:
        _settings["llm_provider"] = settings_data.llm_provider
        os.environ["DEFAULT_LLM_PROVIDER"] = settings_data.llm_provider
        env_updates["DEFAULT_LLM_PROVIDER"] = settings_data.llm_provider

    if settings_data.anthropic_api_key is not None:
        _settings["anthropic_api_key"] = settings_data.anthropic_api_key
        if settings_data.anthropic_api_key:
            os.environ["ANTHROPIC_API_KEY"] = settings_data.anthropic_api_key
            env_updates["ANTHROPIC_API_KEY"] = settings_data.anthropic_api_key

    if settings_data.openai_api_key is not None:
        _settings["openai_api_key"] = settings_data.openai_api_key
        if settings_data.openai_api_key:
            os.environ["OPENAI_API_KEY"] = settings_data.openai_api_key
            env_updates["OPENAI_API_KEY"] = settings_data.openai_api_key

    if settings_data.openrouter_api_key is not None:
        _settings["openrouter_api_key"] = settings_data.openrouter_api_key
        if settings_data.openrouter_api_key:
            os.environ["OPENROUTER_API_KEY"] = settings_data.openrouter_api_key
            env_updates["OPENROUTER_API_KEY"] = settings_data.openrouter_api_key

    if settings_data.aws_access_key_id is not None:
        _settings["aws_access_key_id"] = settings_data.aws_access_key_id
        if settings_data.aws_access_key_id:
            os.environ["AWS_ACCESS_KEY_ID"] = settings_data.aws_access_key_id
            env_updates["AWS_ACCESS_KEY_ID"] = settings_data.aws_access_key_id

    if settings_data.aws_secret_access_key is not None:
        _settings["aws_secret_access_key"] = settings_data.aws_secret_access_key
        if settings_data.aws_secret_access_key:
            os.environ["AWS_SECRET_ACCESS_KEY"] = settings_data.aws_secret_access_key
            env_updates["AWS_SECRET_ACCESS_KEY"] = settings_data.aws_secret_access_key

    if settings_data.aws_session_token is not None:
        _settings["aws_session_token"] = settings_data.aws_session_token
        if settings_data.aws_session_token:
            os.environ["AWS_SESSION_TOKEN"] = settings_data.aws_session_token
            env_updates["AWS_SESSION_TOKEN"] = settings_data.aws_session_token

    if settings_data.aws_bedrock_region is not None:
        _settings["aws_bedrock_region"] = settings_data.aws_bedrock_region
        os.environ["AWS_BEDROCK_REGION"] = settings_data.aws_bedrock_region
        env_updates["AWS_BEDROCK_REGION"] = settings_data.aws_bedrock_region

    if settings_data.aws_bedrock_model is not None:
        _settings["aws_bedrock_model"] = settings_data.aws_bedrock_model
        if settings_data.aws_bedrock_model:
            os.environ["AWS_BEDROCK_MODEL"] = settings_data.aws_bedrock_model
            env_updates["AWS_BEDROCK_MODEL"] = settings_data.aws_bedrock_model

    if settings_data.llm_model is not None:
        _settings["llm_model"] = settings_data.llm_model
        os.environ["DEFAULT_LLM_MODEL"] = settings_data.llm_model
        env_updates["DEFAULT_LLM_MODEL"] = settings_data.llm_model

    if settings_data.max_concurrent_scans is not None:
        _settings["max_concurrent_scans"] = settings_data.max_concurrent_scans
        os.environ["MAX_CONCURRENT_SCANS"] = str(settings_data.max_concurrent_scans)
        env_updates["MAX_CONCURRENT_SCANS"] = str(settings_data.max_concurrent_scans)

    if settings_data.aggressive_mode is not None:
        _settings["aggressive_mode"] = settings_data.aggressive_mode
        val = str(settings_data.aggressive_mode).lower()
        os.environ["AGGRESSIVE_MODE"] = val
        env_updates["AGGRESSIVE_MODE"] = val

    if settings_data.default_scan_type is not None:
        _settings["default_scan_type"] = settings_data.default_scan_type
        os.environ["DEFAULT_SCAN_TYPE"] = settings_data.default_scan_type
        env_updates["DEFAULT_SCAN_TYPE"] = settings_data.default_scan_type

    if settings_data.recon_enabled_by_default is not None:
        _settings["recon_enabled_by_default"] = settings_data.recon_enabled_by_default
        val = str(settings_data.recon_enabled_by_default).lower()
        os.environ["RECON_ENABLED_BY_DEFAULT"] = val
        env_updates["RECON_ENABLED_BY_DEFAULT"] = val

    if settings_data.enable_model_routing is not None:
        _settings["enable_model_routing"] = settings_data.enable_model_routing
        val = str(settings_data.enable_model_routing).lower()
        os.environ["ENABLE_MODEL_ROUTING"] = val
        env_updates["ENABLE_MODEL_ROUTING"] = val

    # Per-tier model overrides
    for field_name, env_key in [
        ("model_fast", "LLM_MODEL_FAST"),
        ("model_balanced", "LLM_MODEL_BALANCED"),
        ("model_deep", "LLM_MODEL_DEEP"),
    ]:
        val = getattr(settings_data, field_name, None)
        if val is not None:
            _settings[field_name] = val
            os.environ[env_key] = val
            env_updates[env_key] = val

    # Per-tier provider overrides
    for field_name, env_key in [
        ("provider_fast", "LLM_PROVIDER_FAST"),
        ("provider_balanced", "LLM_PROVIDER_BALANCED"),
        ("provider_deep", "LLM_PROVIDER_DEEP"),
    ]:
        val = getattr(settings_data, field_name, None)
        if val is not None:
            _settings[field_name] = val
            os.environ[env_key] = val
            env_updates[env_key] = val

    if settings_data.enable_knowledge_augmentation is not None:
        _settings["enable_knowledge_augmentation"] = settings_data.enable_knowledge_augmentation
        val = str(settings_data.enable_knowledge_augmentation).lower()
        os.environ["ENABLE_KNOWLEDGE_AUGMENTATION"] = val
        env_updates["ENABLE_KNOWLEDGE_AUGMENTATION"] = val

    if settings_data.enable_browser_validation is not None:
        _settings["enable_browser_validation"] = settings_data.enable_browser_validation
        val = str(settings_data.enable_browser_validation).lower()
        os.environ["ENABLE_BROWSER_VALIDATION"] = val
        env_updates["ENABLE_BROWSER_VALIDATION"] = val

    if settings_data.enable_extended_thinking is not None:
        _settings["enable_extended_thinking"] = settings_data.enable_extended_thinking
        val = str(settings_data.enable_extended_thinking).lower()
        os.environ["ENABLE_EXTENDED_THINKING"] = val
        env_updates["ENABLE_EXTENDED_THINKING"] = val

    if settings_data.max_output_tokens is not None:
        _settings["max_output_tokens"] = settings_data.max_output_tokens
        if settings_data.max_output_tokens:
            os.environ["MAX_OUTPUT_TOKENS"] = str(settings_data.max_output_tokens)
            env_updates["MAX_OUTPUT_TOKENS"] = str(settings_data.max_output_tokens)

    # Tracing, memory, bug bounty, enrichment toggles
    for field_name, env_key in [
        ("enable_tracing", "ENABLE_TRACING"),
        ("enable_persistent_memory", "ENABLE_PERSISTENT_MEMORY"),
        ("enable_bugbounty_integration", "ENABLE_BUGBOUNTY_INTEGRATION"),
        ("enable_vuln_enrichment", "ENABLE_VULN_ENRICHMENT"),
    ]:
        val = getattr(settings_data, field_name, None)
        if val is not None:
            _settings[field_name] = val
            str_val = str(val).lower()
            os.environ[env_key] = str_val
            env_updates[env_key] = str_val

    # OSINT API keys
    for field_name, env_key in [
        ("shodan_api_key", "SHODAN_API_KEY"),
        ("censys_api_id", "CENSYS_API_ID"),
        ("censys_api_secret", "CENSYS_API_SECRET"),
        ("virustotal_api_key", "VIRUSTOTAL_API_KEY"),
        ("builtwith_api_key", "BUILTWITH_API_KEY"),
        ("hackerone_api_token", "HACKERONE_API_TOKEN"),
        ("hackerone_username", "HACKERONE_USERNAME"),
        ("nvd_api_key", "NVD_API_KEY"),
    ]:
        val = getattr(settings_data, field_name, None)
        if val is not None:
            _settings[field_name] = val
            if val:
                os.environ[env_key] = val
                env_updates[env_key] = val

    # Cost tracking
    if settings_data.cost_budget_per_scan is not None:
        _settings["cost_budget_per_scan"] = settings_data.cost_budget_per_scan
        os.environ["COST_BUDGET_PER_SCAN"] = str(settings_data.cost_budget_per_scan)
        env_updates["COST_BUDGET_PER_SCAN"] = str(settings_data.cost_budget_per_scan)

    if settings_data.cost_warn_at_pct is not None:
        _settings["cost_warn_at_pct"] = settings_data.cost_warn_at_pct
        os.environ["COST_WARN_AT_PCT"] = str(settings_data.cost_warn_at_pct)
        env_updates["COST_WARN_AT_PCT"] = str(settings_data.cost_warn_at_pct)

    if settings_data.enable_cost_tracking is not None:
        _settings["enable_cost_tracking"] = settings_data.enable_cost_tracking
        val = str(settings_data.enable_cost_tracking).lower()
        os.environ["ENABLE_COST_TRACKING"] = val
        env_updates["ENABLE_COST_TRACKING"] = val

    # Security testing
    for field_name, env_key in [
        ("enable_waf_evasion", "ENABLE_WAF_EVASION"),
    ]:
        val = getattr(settings_data, field_name, None)
        if val is not None:
            _settings[field_name] = val
            str_val = str(val).lower()
            os.environ[env_key] = str_val
            env_updates[env_key] = str_val

    for field_name, env_key in [
        ("waf_confidence_threshold", "WAF_CONFIDENCE_THRESHOLD"),
    ]:
        val = getattr(settings_data, field_name, None)
        if val is not None:
            _settings[field_name] = val
            os.environ[env_key] = str(val)
            env_updates[env_key] = str(val)

    for field_name, env_key in [
        ("confidence_pivot_threshold", "CONFIDENCE_PIVOT_THRESHOLD"),
        ("confidence_reject_threshold", "CONFIDENCE_REJECT_THRESHOLD"),
        ("default_timeout", "DEFAULT_TIMEOUT"),
        ("max_requests_per_second", "MAX_REQUESTS_PER_SECOND"),
    ]:
        val = getattr(settings_data, field_name, None)
        if val is not None:
            _settings[field_name] = val
            os.environ[env_key] = str(val)
            env_updates[env_key] = str(val)

    # Persist to .env file on disk
    if env_updates:
        _update_env_file(env_updates)

    return await get_settings()


# Provider name mapping: settings UI name -> LLMManager provider name
_PROVIDER_MAP = {
    "claude": "claude",
    "anthropic": "claude",
    "openai": "gpt",
    "openrouter": "openrouter",
    "ollama": "ollama",
    "bedrock": "bedrock",
    "gemini": "gemini",
    "lmstudio": "lmstudio",
}

# Default models per provider (used when no model is configured)
_DEFAULT_MODELS = {
    "claude": "claude-sonnet-4-6",
    "gpt": "gpt-4o",
    "openrouter": "anthropic/claude-sonnet-4-6",
    "ollama": "llama3.2",
    "bedrock": "us.anthropic.claude-sonnet-4-6-v1:0",
    "gemini": "gemini-2.0-flash",
    "lmstudio": "default",
}

# Which env var holds the API key for each settings provider
_API_KEY_ENV = {
    "claude": "ANTHROPIC_API_KEY",
    "anthropic": "ANTHROPIC_API_KEY",
    "openai": "OPENAI_API_KEY",
    "openrouter": "OPENROUTER_API_KEY",
    "gemini": "GEMINI_API_KEY",
}


async def _save_and_return(db: AsyncSession, result_data: dict) -> dict:
    """Persist an LLM test result and return {current, previous}."""
    # Fetch the most recent previous result before inserting the new one
    prev_row = (
        await db.execute(
            select(LlmTestResult)
            .order_by(LlmTestResult.created_at.desc())
            .limit(1)
        )
    ).scalar_one_or_none()

    new_row = LlmTestResult(**result_data)
    db.add(new_row)
    await db.flush()          # populate defaults (id, created_at)

    current = new_row.to_dict()
    previous = prev_row.to_dict() if prev_row else None

    return {"current": current, "previous": previous}


@router.post("/test-llm")
async def test_llm_connection(
    request: Request,
    db: AsyncSession = Depends(get_db),
):
    """Test LLM provider connectivity.

    Accepts optional JSON body ``{"provider": "...", "model": "..."}`` so the
    frontend can test the *currently-selected* provider/model even before saving.
    Falls back to saved settings when no body is provided.
    """
    # Parse optional body overrides
    body_provider: str | None = None
    body_model: str | None = None
    try:
        body = await request.json()
        body_provider = body.get("provider")
        body_model = body.get("model")
    except Exception:
        pass  # No body or invalid JSON — use saved settings

    provider_ui = body_provider or _settings.get("llm_provider", "claude")
    llm_provider = _PROVIDER_MAP.get(provider_ui, provider_ui)
    default_model = _DEFAULT_MODELS.get(llm_provider, "")

    # Resolve API key from in-memory settings or env
    api_key = ""
    if provider_ui in _API_KEY_ENV:
        env_var = _API_KEY_ENV[provider_ui]
        key_map = {
            "claude": "anthropic_api_key",
            "anthropic": "anthropic_api_key",
            "openai": "openai_api_key",
            "openrouter": "openrouter_api_key",
            "gemini": "gemini_api_key",
        }
        api_key = _settings.get(key_map.get(provider_ui, ""), "") or os.getenv(env_var, "")
        if not api_key:
            return await _save_and_return(db, {
                "success": False,
                "provider": provider_ui,
                "model": "",
                "response_time_ms": 0,
                "response_preview": "",
                "error": f"No API key configured. Set {env_var} or enter it in settings.",
            })

    # For bedrock, check AWS credentials
    if provider_ui == "bedrock":
        has_creds = (
            _settings.get("aws_access_key_id") or os.getenv("AWS_ACCESS_KEY_ID")
            or os.getenv("AWS_PROFILE")
        )
        if not has_creds:
            return await _save_and_return(db, {
                "success": False,
                "provider": provider_ui,
                "model": "",
                "response_time_ms": 0,
                "response_preview": "",
                "error": "No AWS credentials configured. Set AWS_ACCESS_KEY_ID or AWS_PROFILE.",
            })

    # Build model name: body override > llm_model setting > provider default
    model = body_model or _settings.get("llm_model") or ""
    if not model:
        if provider_ui == "bedrock":
            model = _settings.get("aws_bedrock_model") or os.getenv("AWS_BEDROCK_MODEL", "") or default_model
        else:
            model = default_model

    # Resolve max_output_tokens
    max_output_tokens = _settings.get("max_output_tokens") or None

    # Build LLMManager config
    profile_config = {
        "provider": llm_provider,
        "model": model,
        "api_key": api_key,
        "temperature": 0.1,
        "max_tokens": 256,
        "input_token_limit": 1024,
        "output_token_limit": max_output_tokens or 256,
    }
    if provider_ui == "bedrock":
        profile_config["region"] = _settings.get("aws_bedrock_region") or os.getenv("AWS_BEDROCK_REGION", "us-east-1")

    config = {
        "llm": {
            "default_profile": "connection_test",
            "profiles": {
                "connection_test": profile_config,
            },
        }
    }

    # --- Bedrock: verify credentials via STS first, then discover valid model ---
    if provider_ui == "bedrock":
        region = profile_config.get("region", "us-east-1")

        def _bedrock_test():
            import boto3
            from botocore.exceptions import ClientError, NoCredentialsError, BotoCoreError

            start = time.monotonic()

            # Step 1: Verify AWS credentials
            try:
                sts = boto3.client("sts", region_name=region)
                identity = sts.get_caller_identity()
                account = identity.get("Account", "unknown")
            except NoCredentialsError:
                return None, 0, "No AWS credentials found. Configure AWS_ACCESS_KEY_ID/AWS_SECRET_ACCESS_KEY, AWS_PROFILE, or IAM role."
            except (ClientError, BotoCoreError) as e:
                return None, 0, f"AWS credential check failed: {e}"

            # Step 2: Try the configured model
            test_model = model
            try:
                client = boto3.client("bedrock-runtime", region_name=region)
                resp = client.converse(
                    modelId=test_model,
                    messages=[{"role": "user", "content": [{"text": "Respond with exactly: CONNECTION_OK"}]}],
                    inferenceConfig={"maxTokens": 64, "temperature": 0.1},
                )
                text = resp["output"]["message"]["content"][0]["text"]
                elapsed = round((time.monotonic() - start) * 1000)
                return text, elapsed, None
            except ClientError as e:
                code = e.response["Error"]["Code"]
                msg = e.response["Error"]["Message"]
                elapsed = round((time.monotonic() - start) * 1000)

                if code == "ValidationException" and "model identifier" in msg.lower():
                    # Model ID is invalid — discover available models
                    available = []
                    try:
                        bedrock_mgmt = boto3.client("bedrock", region_name=region)
                        fm_resp = bedrock_mgmt.list_foundation_models(byOutputModality="TEXT")
                        for m in fm_resp.get("modelSummaries", []):
                            mid = m.get("modelId", "")
                            if m.get("modelLifecycleStatus") == "ACTIVE" and "claude" in mid.lower():
                                available.append(mid)
                    except Exception:
                        pass

                    hint = ""
                    if available:
                        hint = " Available Claude models: " + ", ".join(available[:5])
                    return None, elapsed, (
                        f"AWS credentials valid (account {account}), but model '{test_model}' "
                        f"is not available in {region}.{hint} "
                        f"Select a valid model ID in Settings or use the model dropdown."
                    )
                elif code == "AccessDeniedException":
                    return None, elapsed, (
                        f"AWS credentials valid (account {account}), but access denied for model '{test_model}'. "
                        f"Enable the model in the AWS Bedrock console for region {region}."
                    )
                else:
                    return None, elapsed, f"Bedrock error ({code}): {msg}"
            except Exception as e:
                elapsed = round((time.monotonic() - start) * 1000)
                return None, elapsed, f"Bedrock test failed: {e}"

        try:
            response, elapsed_ms, error = await asyncio.to_thread(_bedrock_test)
            if error:
                return await _save_and_return(db, {
                    "success": False,
                    "provider": provider_ui,
                    "model": model,
                    "response_time_ms": elapsed_ms,
                    "response_preview": "",
                    "error": error,
                })
            return await _save_and_return(db, {
                "success": True,
                "provider": provider_ui,
                "model": model,
                "response_time_ms": elapsed_ms,
                "response_preview": response[:500] if response else "",
                "error": None,
            })
        except Exception as e:
            return await _save_and_return(db, {
                "success": False,
                "provider": provider_ui,
                "model": model,
                "response_time_ms": 0,
                "response_preview": "",
                "error": str(e),
            })

    # --- Non-Bedrock providers: use LLMManager ---
    def _run_test():
        from core.llm_manager import LLMManager
        mgr = LLMManager(config)
        start = time.monotonic()
        response = mgr.generate("Respond with exactly: CONNECTION_OK")
        elapsed_ms = round((time.monotonic() - start) * 1000)
        return response, elapsed_ms

    try:
        response, elapsed_ms = await asyncio.to_thread(_run_test)

        # LLMManager sometimes returns error strings instead of raising
        if response and response.strip().lower().startswith("error:"):
            return await _save_and_return(db, {
                "success": False,
                "provider": provider_ui,
                "model": model,
                "response_time_ms": elapsed_ms,
                "response_preview": "",
                "error": response.strip(),
            })

        return await _save_and_return(db, {
            "success": True,
            "provider": provider_ui,
            "model": model,
            "response_time_ms": elapsed_ms,
            "response_preview": response[:500] if response else "",
            "error": None,
        })
    except Exception as e:
        error_msg = str(e)
        # Provide friendlier messages for common errors
        lower_err = error_msg.lower()
        if "401" in error_msg or "unauthorized" in lower_err or "authentication" in lower_err:
            error_msg = f"Authentication failed. Check your API key. ({error_msg})"
        elif "403" in error_msg or "forbidden" in lower_err:
            error_msg = f"Access denied. Check your credentials and permissions. ({error_msg})"
        elif "timeout" in lower_err or "timed out" in lower_err:
            error_msg = f"Connection timed out. Check network connectivity and provider status. ({error_msg})"
        elif "connection" in lower_err and ("refused" in lower_err or "error" in lower_err):
            error_msg = f"Connection refused. Is the provider endpoint reachable? ({error_msg})"
        return await _save_and_return(db, {
            "success": False,
            "provider": provider_ui,
            "model": model,
            "response_time_ms": 0,
            "response_preview": "",
            "error": error_msg,
        })


@router.post("/clear-database")
async def clear_database(db: AsyncSession = Depends(get_db)):
    """Clear all data from the database (reset to fresh state)"""
    try:
        # Delete in correct order to respect foreign key constraints
        await db.execute(delete(LlmTestResult))
        await db.execute(delete(VulnerabilityTest))
        await db.execute(delete(Vulnerability))
        await db.execute(delete(Endpoint))
        await db.execute(delete(Report))
        await db.execute(delete(Target))
        await db.execute(delete(Scan))
        await db.commit()

        return {
            "message": "Database cleared successfully",
            "status": "success"
        }
    except Exception as e:
        await db.rollback()
        raise HTTPException(status_code=500, detail=f"Failed to clear database: {str(e)}")


@router.get("/stats")
async def get_database_stats(db: AsyncSession = Depends(get_db)):
    """Get database statistics"""
    from sqlalchemy import func

    scans_count = (await db.execute(select(func.count()).select_from(Scan))).scalar() or 0
    vulns_count = (await db.execute(select(func.count()).select_from(Vulnerability))).scalar() or 0
    endpoints_count = (await db.execute(select(func.count()).select_from(Endpoint))).scalar() or 0
    reports_count = (await db.execute(select(func.count()).select_from(Report))).scalar() or 0

    return {
        "scans": scans_count,
        "vulnerabilities": vulns_count,
        "endpoints": endpoints_count,
        "reports": reports_count
    }


@router.get("/tools")
async def get_installed_tools():
    """Check which security tools are installed"""
    import asyncio
    import shutil

    # Complete list of 40+ tools
    tools = {
        "recon": [
            "subfinder", "amass", "assetfinder", "chaos", "uncover",
            "dnsx", "massdns", "puredns", "cero", "tlsx", "cdncheck"
        ],
        "web_discovery": [
            "httpx", "httprobe", "katana", "gospider", "hakrawler",
            "gau", "waybackurls", "cariddi", "getJS", "gowitness"
        ],
        "fuzzing": [
            "ffuf", "gobuster", "dirb", "dirsearch", "wfuzz", "arjun", "paramspider"
        ],
        "vulnerability_scanning": [
            "nuclei", "nikto", "sqlmap", "xsstrike", "dalfox", "crlfuzz"
        ],
        "port_scanning": [
            "nmap", "naabu", "rustscan"
        ],
        "utilities": [
            "gf", "qsreplace", "unfurl", "anew", "uro", "jq"
        ],
        "tech_detection": [
            "whatweb", "wafw00f"
        ],
        "exploitation": [
            "hydra", "medusa", "john", "hashcat"
        ],
        "network": [
            "curl", "wget", "dig", "whois"
        ]
    }

    results = {}
    total_installed = 0
    total_tools = 0

    for category, tool_list in tools.items():
        results[category] = {}
        for tool in tool_list:
            total_tools += 1
            # Check if tool exists in PATH
            is_installed = shutil.which(tool) is not None
            results[category][tool] = is_installed
            if is_installed:
                total_installed += 1

    return {
        "tools": results,
        "summary": {
            "total": total_tools,
            "installed": total_installed,
            "missing": total_tools - total_installed,
            "percentage": round((total_installed / total_tools) * 100, 1)
        }
    }


@router.get("/available-models")
async def get_available_models(provider: str = ""):
    """List available models for a given LLM provider.

    Query params:
        provider: Provider name (claude/anthropic, openai, ollama, bedrock, gemini, lmstudio).
                  Defaults to the active provider.
    """
    from backend.core.llm import UnifiedLLMClient

    # Normalize provider name
    provider_alias = {"claude": "anthropic", "": None}
    provider_name = provider_alias.get(provider.lower().strip(), provider.lower().strip())

    try:
        client = UnifiedLLMClient()
        prov = client._get_provider(provider_name)
        models = await prov.list_models()
        return {"provider": prov.name, "models": models}
    except Exception as e:
        return {"provider": provider_name or "unknown", "models": [], "error": str(e)}
