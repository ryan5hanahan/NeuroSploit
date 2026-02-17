"""
NeuroSploit v3 - Settings API Endpoints
"""
import asyncio
import os
import re
import time
from pathlib import Path
from typing import Optional, Dict
from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select, delete, text
from pydantic import BaseModel

from backend.db.database import get_db, engine
from backend.models import Scan, Target, Endpoint, Vulnerability, VulnerabilityTest, Report
from backend.models.llm_test_result import LlmTestResult

router = APIRouter()

# Path to .env file (project root)
ENV_FILE_PATH = Path(__file__).parent.parent.parent.parent / ".env"


def _update_env_file(updates: Dict[str, str]) -> bool:
    """
    Update key=value pairs in the .env file without breaking formatting.
    - If the key exists (even commented out), update its value
    - If the key doesn't exist, append it
    - Preserves comments and blank lines
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
                    # Replace with uncommented key=value
                    new_lines.append(f"{key}={value}")
                    updated_keys.add(key)
                    matched = True
                    break

            if not matched:
                new_lines.append(line)

        # Append any keys that weren't found in existing file
        for key, value in updates.items():
            if key not in updated_keys:
                new_lines.append(f"{key}={value}")

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
    # Tracing & memory
    enable_tracing: Optional[bool] = None
    enable_persistent_memory: Optional[bool] = None
    # Bug bounty
    enable_bugbounty_integration: Optional[bool] = None
    hackerone_api_token: Optional[str] = None
    hackerone_username: Optional[str] = None


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

    # Tracing, memory, bug bounty toggles
    for field_name, env_key in [
        ("enable_tracing", "ENABLE_TRACING"),
        ("enable_persistent_memory", "ENABLE_PERSISTENT_MEMORY"),
        ("enable_bugbounty_integration", "ENABLE_BUGBOUNTY_INTEGRATION"),
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
    ]:
        val = getattr(settings_data, field_name, None)
        if val is not None:
            _settings[field_name] = val
            if val:
                os.environ[env_key] = val
                env_updates[env_key] = val

    # Persist to .env file on disk
    if env_updates:
        _update_env_file(env_updates)

    return await get_settings()


# Provider name mapping: settings UI name -> LLMManager provider name
_PROVIDER_MAP = {
    "claude": "claude",
    "openai": "gpt",
    "openrouter": "openrouter",
    "ollama": "ollama",
    "bedrock": "bedrock",
}

# Default models per provider (used when no model is configured)
_DEFAULT_MODELS = {
    "claude": "claude-sonnet-4-5-20250929",
    "gpt": "gpt-4o",
    "openrouter": "anthropic/claude-sonnet-4-5-20250929",
    "ollama": "llama3.2",
    "bedrock": "us.anthropic.claude-sonnet-4-5-20250929-v1:0",
}

# Which env var holds the API key for each settings provider
_API_KEY_ENV = {
    "claude": "ANTHROPIC_API_KEY",
    "openai": "OPENAI_API_KEY",
    "openrouter": "OPENROUTER_API_KEY",
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
async def test_llm_connection(db: AsyncSession = Depends(get_db)):
    """Test the current LLM configuration by sending a simple prompt."""
    provider_ui = _settings.get("llm_provider", "claude")
    llm_provider = _PROVIDER_MAP.get(provider_ui, provider_ui)
    default_model = _DEFAULT_MODELS.get(llm_provider, "")

    # Resolve API key from in-memory settings or env
    api_key = ""
    if provider_ui in _API_KEY_ENV:
        env_var = _API_KEY_ENV[provider_ui]
        key_map = {
            "claude": "anthropic_api_key",
            "openai": "openai_api_key",
            "openrouter": "openrouter_api_key",
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

    # Build model name: llm_model takes precedence, then provider-specific fallbacks
    model = _settings.get("llm_model") or ""
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
