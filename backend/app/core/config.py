"""
Centralized application configuration.

Purpose:
    Single source of truth for all environment-driven settings. Every other
    module imports `settings` from here instead of calling os.getenv directly,
    so configuration stays typed, validated, and discoverable in one place.
"""

from functools import lru_cache
from typing import List, Literal

from pydantic import Field, field_validator
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    model_config = SettingsConfigDict(
        env_file=".env",
        env_file_encoding="utf-8",
        case_sensitive=True,
        extra="ignore",
    )

    # --- App ---
    APP_NAME: str = "AI SOC Assistant"
    ENVIRONMENT: Literal["development", "staging", "production"] = "development"
    LOG_LEVEL: str = "INFO"
    API_V1_PREFIX: str = "/api/v1"

    # --- CORS ---
    CORS_ORIGINS: str = "http://localhost:5173"

    @field_validator("CORS_ORIGINS")
    @classmethod
    def split_origins(cls, v: str) -> str:
        return v

    @property
    def cors_origins_list(self) -> List[str]:
        return [origin.strip() for origin in self.CORS_ORIGINS.split(",") if origin.strip()]

    # --- Database ---
    DATABASE_URL: str = Field(
        default="postgresql+asyncpg://soc_admin:changeme@localhost:5432/soc_assistant"
    )
    # Sync URL used only by Alembic (which does not support asyncpg directly).
    DATABASE_URL_SYNC: str = Field(
        default="postgresql+psycopg2://soc_admin:changeme@localhost:5432/soc_assistant"
    )

    # --- Redis / Celery ---
    REDIS_URL: str = "redis://localhost:6379/0"
    CELERY_BROKER_URL: str = "redis://localhost:6379/1"
    CELERY_RESULT_BACKEND: str = "redis://localhost:6379/2"

    # --- Auth ---
    JWT_SECRET_KEY: str = "insecure-dev-secret-change-me"
    JWT_ALGORITHM: str = "HS256"
    ACCESS_TOKEN_EXPIRE_MINUTES: int = 30
    REFRESH_TOKEN_EXPIRE_DAYS: int = 7

    # --- Wazuh ---
    WAZUH_API_URL: str = "https://localhost:55000"
    WAZUH_API_USER: str = "wazuh-wui"
    WAZUH_API_PASSWORD: str = "changeme"
    WAZUH_VERIFY_SSL: bool = False
    WAZUH_INDEXER_URL: str = "https://localhost:9200"
    WAZUH_INDEXER_USER: str = "admin"
    WAZUH_INDEXER_PASSWORD: str = "changeme"
    WAZUH_SYNC_INTERVAL_SECONDS: int = 60
    WAZUH_SYNC_LOOKBACK_MINUTES: int = 5

    # --- Threat Intelligence ---
    VIRUSTOTAL_API_KEY: str = ""
    ABUSEIPDB_API_KEY: str = ""
    ALIENVAULT_OTX_API_KEY: str = ""

    # --- AI Provider ---
    AI_PROVIDER: Literal["anthropic", "openai"] = "anthropic"
    ANTHROPIC_API_KEY: str = ""
    OPENAI_API_KEY: str = ""
    AI_MODEL: str = "claude-sonnet-4-6"

    @property
    def is_production(self) -> bool:
        return self.ENVIRONMENT == "production"


@lru_cache
def get_settings() -> Settings:
    """Cached settings instance — avoids re-parsing env on every import."""
    return Settings()


settings = get_settings()
