"""
NeuroSploit v3 - Configuration
"""
import os
from pathlib import Path
from typing import Optional
from pydantic_settings import BaseSettings


class Settings(BaseSettings):
    """Application settings"""

    # Application
    APP_NAME: str = "NeuroSploit v3"
    APP_VERSION: str = "3.0.0"
    DEBUG: bool = True

    # Server
    HOST: str = "0.0.0.0"
    PORT: int = 8000

    # Database
    DATABASE_URL: str = "sqlite+aiosqlite:///./data/neurosploit.db"

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
    DEFAULT_LLM_MODEL: str = "claude-sonnet-4-5-20250929"
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

    # Bug Bounty API
    HACKERONE_API_TOKEN: Optional[str] = os.getenv("HACKERONE_API_TOKEN")
    HACKERONE_USERNAME: Optional[str] = os.getenv("HACKERONE_USERNAME")

    # OSINT API Keys
    SHODAN_API_KEY: Optional[str] = os.getenv("SHODAN_API_KEY")
    CENSYS_API_ID: Optional[str] = os.getenv("CENSYS_API_ID")
    CENSYS_API_SECRET: Optional[str] = os.getenv("CENSYS_API_SECRET")
    VIRUSTOTAL_API_KEY: Optional[str] = os.getenv("VIRUSTOTAL_API_KEY")
    BUILTWITH_API_KEY: Optional[str] = os.getenv("BUILTWITH_API_KEY")

    # Scan Settings
    MAX_CONCURRENT_SCANS: int = 3
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
