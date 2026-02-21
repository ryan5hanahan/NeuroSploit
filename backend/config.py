"""
sploit.ai - Configuration
"""
import os
from pathlib import Path
from typing import Optional
from pydantic_settings import BaseSettings


class Settings(BaseSettings):
    """Application settings"""

    # Application
    APP_NAME: str = "sploit.ai v3"
    APP_VERSION: str = "3.0.0"
    DEBUG: bool = True

    # Server
    HOST: str = "0.0.0.0"
    PORT: int = 8000

    # Database
    DATABASE_URL: str = "sqlite+aiosqlite:///./data/sploitai.db"

    # Paths
    BASE_DIR: Path = Path(__file__).parent.parent
    DATA_DIR: Path = BASE_DIR / "data"
    REPORTS_DIR: Path = DATA_DIR / "reports"
    SCANS_DIR: Path = DATA_DIR / "scans"
    PROMPTS_DIR: Path = BASE_DIR / "prompts"

    # LLM Settings
    ANTHROPIC_API_KEY: Optional[str] = os.getenv("ANTHROPIC_API_KEY")
    OPENAI_API_KEY: Optional[str] = os.getenv("OPENAI_API_KEY")
    GEMINI_API_KEY: Optional[str] = os.getenv("GEMINI_API_KEY")
    OPENROUTER_API_KEY: Optional[str] = os.getenv("OPENROUTER_API_KEY")

    # AWS Settings
    AWS_PROFILE: Optional[str] = os.getenv("AWS_PROFILE")
    AWS_ACCESS_KEY_ID: Optional[str] = os.getenv("AWS_ACCESS_KEY_ID")
    AWS_SECRET_ACCESS_KEY: Optional[str] = os.getenv("AWS_SECRET_ACCESS_KEY")
    AWS_SESSION_TOKEN: Optional[str] = os.getenv("AWS_SESSION_TOKEN")
    AWS_BEDROCK_REGION: Optional[str] = os.getenv("AWS_BEDROCK_REGION", "us-east-1")
    AWS_BEDROCK_MODEL: Optional[str] = os.getenv("AWS_BEDROCK_MODEL")
    DEFAULT_LLM_PROVIDER: str = "claude"
    DEFAULT_LLM_MODEL: str = "claude-sonnet-4-6"
    MAX_OUTPUT_TOKENS: Optional[int] = None
    ENABLE_MODEL_ROUTING: bool = False
    LLM_MODEL_FAST: Optional[str] = None
    LLM_MODEL_BALANCED: Optional[str] = None
    LLM_MODEL_DEEP: Optional[str] = None

    # Feature Flags
    ENABLE_KNOWLEDGE_AUGMENTATION: bool = False
    ENABLE_BROWSER_VALIDATION: bool = False
    ENABLE_EXTENDED_THINKING: bool = False
    ENABLE_PERSISTENT_MEMORY: bool = True
    ENABLE_TRACING: bool = False
    ENABLE_BUGBOUNTY_INTEGRATION: bool = False
    ENABLE_AUTONOMOUS_MODE: bool = False
    ENABLE_BROWSER_STEALTH: bool = True
    ENABLE_TECHNIQUE_LIBRARY: bool = True
    ENABLE_BUGBOUNTY_SUBMISSION: bool = False
    BUGBOUNTY_AUTO_SUBMIT: bool = False

    # Bug Bounty API
    HACKERONE_API_TOKEN: Optional[str] = os.getenv("HACKERONE_API_TOKEN")
    HACKERONE_USERNAME: Optional[str] = os.getenv("HACKERONE_USERNAME")

    # OSINT API Keys
    SHODAN_API_KEY: Optional[str] = os.getenv("SHODAN_API_KEY")
    CENSYS_API_ID: Optional[str] = os.getenv("CENSYS_API_ID")
    CENSYS_API_SECRET: Optional[str] = os.getenv("CENSYS_API_SECRET")
    VIRUSTOTAL_API_KEY: Optional[str] = os.getenv("VIRUSTOTAL_API_KEY")
    BUILTWITH_API_KEY: Optional[str] = os.getenv("BUILTWITH_API_KEY")
    VULNERS_API_KEY: Optional[str] = os.getenv("VULNERS_API_KEY")
    GOOGLE_CSE_API_KEY: Optional[str] = os.getenv("GOOGLE_CSE_API_KEY")
    GOOGLE_CSE_CX: Optional[str] = os.getenv("GOOGLE_CSE_CX")

    # Benchmark
    BENCHMARK_RESULTS_DIR: str = "data/benchmark_results"

    # Techniques Library
    TECHNIQUE_CUSTOM_DIR: Optional[str] = None

    # Cost Tracking
    COST_BUDGET_PER_SCAN: float = 5.00
    COST_WARN_AT_PCT: float = 80.0
    ENABLE_COST_TRACKING: bool = True

    # Benchmark
    BENCHMARK_RESULTS_DIR: str = "data/benchmark_results"

    # Autonomous Mode (Phase 2)
    ENABLE_AUTONOMOUS_MODE: bool = False

    # Browser Stealth (Phase 2)
    ENABLE_BROWSER_STEALTH: bool = True

    # Vulners API (Phase 2)
    VULNERS_API_KEY: Optional[str] = os.getenv("VULNERS_API_KEY")

    # Google Dorking (Phase 2)
    GOOGLE_CSE_API_KEY: Optional[str] = os.getenv("GOOGLE_CSE_API_KEY")
    GOOGLE_CSE_CX: Optional[str] = os.getenv("GOOGLE_CSE_CX")

    # Bug Bounty Submission (Phase 3)
    ENABLE_BUGBOUNTY_SUBMISSION: bool = False
    BUGBOUNTY_AUTO_SUBMIT: bool = False

    # Techniques Library (Phase 5)
    ENABLE_TECHNIQUE_LIBRARY: bool = True
    TECHNIQUE_CUSTOM_DIR: Optional[str] = None

    # Security Testing
    ENABLE_WAF_EVASION: bool = True
    WAF_CONFIDENCE_THRESHOLD: float = 0.7
    CONFIDENCE_PIVOT_THRESHOLD: int = 30
    CONFIDENCE_REJECT_THRESHOLD: int = 40

    # Scan Settings
    MAX_CONCURRENT_SCANS: int = 3
    DEFAULT_SCAN_TYPE: str = "full"
    RECON_ENABLED_BY_DEFAULT: bool = True
    AGGRESSIVE_MODE: bool = False
    DEFAULT_TIMEOUT: int = 30
    MAX_REQUESTS_PER_SECOND: int = 10

    # CORS
    CORS_ORIGINS: list = ["http://localhost:3000", "http://127.0.0.1:3000"]

    class Config:
        env_file = ".env"
        case_sensitive = True


settings = Settings()

# Ensure directories exist
settings.DATA_DIR.mkdir(parents=True, exist_ok=True)
settings.REPORTS_DIR.mkdir(parents=True, exist_ok=True)
settings.SCANS_DIR.mkdir(parents=True, exist_ok=True)
