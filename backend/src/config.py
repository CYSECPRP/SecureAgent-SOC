from typing import List, Optional
from pydantic import AnyHttpUrl, Field, field_validator, model_validator
from pydantic_settings import BaseSettings, SettingsConfigDict

DEV_SECRET_KEY = "secureagent_soc_super_secret_jwt_hmac_key_2026_dsu"
DEV_POSTGRES_PASSWORD = "secureagent_secret_2026"


class Settings(BaseSettings):
    model_config = SettingsConfigDict(
        env_file=".env",
        env_file_encoding="utf-8",
        case_sensitive=False,
        extra="ignore",
    )

    # Project metadata
    PROJECT_NAME: str = "SecureAgent-SOC"
    VERSION: str = "1.0.0"
    ENVIRONMENT: str = "development"
    DEBUG: bool = True
    API_V1_PREFIX: str = "/api/v1"

    # Security & Tokens
    SECRET_KEY: str = DEV_SECRET_KEY
    ACCESS_TOKEN_EXPIRE_MINUTES: int = 60 * 24  # 1 day
    ALLOWED_ORIGINS: List[str] = [
        "http://localhost:5173",
        "http://localhost:3000",
        "http://127.0.0.1:5173",
    ]

    # API access: comma-separated keys for sensors and tools; empty leaves the API open (development only)
    API_KEYS: str = ""
    RATE_LIMIT_PER_MINUTE: int = 0  # /ingest requests per key per minute; 0 turns the limit off
    AUTO_CREATE_TABLES: bool = True  # production runs Alembic migrations instead

    # PostgreSQL Database
    POSTGRES_USER: str = "secureagent"
    POSTGRES_PASSWORD: str = DEV_POSTGRES_PASSWORD
    POSTGRES_SERVER: str = "localhost"
    POSTGRES_PORT: int = 5432
    POSTGRES_DB: str = "secureagent_soc"
    DATABASE_URL: Optional[str] = None
    SYNC_DATABASE_URL: Optional[str] = None

    @field_validator("DATABASE_URL", mode="before")
    def assemble_async_db_connection(cls, v: Optional[str], info) -> str:
        if isinstance(v, str) and v:
            return v
        data = info.data
        user = data.get("POSTGRES_USER", "secureagent")
        password = data.get("POSTGRES_PASSWORD", "secureagent_secret_2026")
        server = data.get("POSTGRES_SERVER", "localhost")
        port = data.get("POSTGRES_PORT", 5432)
        db = data.get("POSTGRES_DB", "secureagent_soc")
        return f"postgresql+asyncpg://{user}:{password}@{server}:{port}/{db}"

    @field_validator("SYNC_DATABASE_URL", mode="before")
    def assemble_sync_db_connection(cls, v: Optional[str], info) -> str:
        if isinstance(v, str) and v:
            return v
        data = info.data
        user = data.get("POSTGRES_USER", "secureagent")
        password = data.get("POSTGRES_PASSWORD", "secureagent_secret_2026")
        server = data.get("POSTGRES_SERVER", "localhost")
        port = data.get("POSTGRES_PORT", 5432)
        db = data.get("POSTGRES_DB", "secureagent_soc")
        return f"postgresql://{user}:{password}@{server}:{port}/{db}"

    # Redis Cache & Broker
    REDIS_HOST: str = "localhost"
    REDIS_PORT: int = 6379
    REDIS_DB: int = 0
    REDIS_URL: str = "redis://localhost:6379/0"

    # Qdrant Vector Search
    QDRANT_HOST: str = "localhost"
    QDRANT_PORT: int = 6333
    QDRANT_GRPC_PORT: int = 6334
    QDRANT_COLLECTION_ALERTS: str = "soc_alerts"
    QDRANT_COLLECTION_RULES: str = "soc_rules"

    # Open Policy Agent (OPA)
    OPA_URL: str = "http://localhost:8181"

    # LLM Settings
    LLM_PROVIDER: str = "mock"  # mock | ollama | vllm
    LLM_MODEL: str = "qwen3-8b-instruct"
    OLLAMA_BASE_URL: str = "http://localhost:11434"
    VLLM_BASE_URL: str = "http://localhost:8000/v1"
    LLM_TEMPERATURE: float = 0.1
    LLM_MAX_TOKENS: int = 2048

    # Autonomy & Verification Bounds (N1–N5 + AEI)
    AEI_AUTOCLOSE_THRESHOLD: float = 0.85
    AEI_ESCALATE_THRESHOLD: float = 0.60
    EMA_ALPHA_REWARD: float = 0.02
    EMA_ALPHA_DECAY: float = 0.20
    TAINT_CONTAINMENT_THRESHOLD: float = 0.40
    MAX_CRITIQUE_ROUNDS: int = 2

    @property
    def api_keys(self) -> List[str]:
        return [key.strip() for key in self.API_KEYS.split(",") if key.strip()]

    @model_validator(mode="after")
    def refuse_unsafe_production_settings(self) -> "Settings":
        if self.ENVIRONMENT.lower() != "production":
            return self
        problems = []
        if self.SECRET_KEY == DEV_SECRET_KEY or len(self.SECRET_KEY) < 32:
            problems.append("SECRET_KEY must be a random value of at least 32 characters")
        if self.POSTGRES_PASSWORD == DEV_POSTGRES_PASSWORD:
            problems.append("POSTGRES_PASSWORD must not be the development default")
        if not self.api_keys:
            problems.append("API_KEYS must contain at least one key")
        elif any(len(key) < 24 for key in self.api_keys):
            problems.append("every API key must be at least 24 characters")
        if self.DEBUG:
            problems.append("DEBUG must be false")
        if problems:
            raise ValueError("Unsafe production settings: " + "; ".join(problems))
        return self


settings = Settings()

