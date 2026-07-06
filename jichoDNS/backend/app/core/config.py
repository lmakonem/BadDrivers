"""
Application configuration using Pydantic Settings.
"""

from functools import lru_cache
from typing import List

from pydantic import Field, PostgresDsn, RedisDsn, model_validator
from pydantic_settings import BaseSettings, SettingsConfigDict

# Well-known dev placeholder — allowed ONLY when ENVIRONMENT != "production".
_DEV_SECRET_PLACEHOLDER = "dev-secret-key-change-in-production"


class Settings(BaseSettings):
    """Application settings loaded from environment variables."""

    model_config = SettingsConfigDict(
        env_file=".env",
        env_file_encoding="utf-8",
        case_sensitive=True,
    )

    # Environment
    ENVIRONMENT: str = Field(default="development")
    LOG_LEVEL: str = Field(default="INFO")
    # SECRET_KEY has NO production default. In dev/test the model_validator below
    # backfills the placeholder so the app still boots without a .env.
    SECRET_KEY: str = Field(default="")
    # Signing key for the sqladmin / Starlette session cookie. Kept separate from
    # SECRET_KEY (JWT signing) for defense in depth; falls back to SECRET_KEY if unset.
    SESSION_SECRET_KEY: str = Field(default="")

    # Demo mode. MUST stay False in production. When False, any ASM/AI data
    # source that has no real API key is SKIPPED and returns EMPTY results
    # instead of fabricating synthetic assets, findings, or report text
    # (this output feeds real client-facing PDFs). Set True ONLY for local
    # demos / screenshots.
    ALLOW_MOCK_DATA: bool = Field(default=False)

    # Database
    DATABASE_URL: PostgresDsn = Field(
        default="postgresql://jichodns:jichodns_dev@localhost:5432/jichodns"
    )
    CLICKHOUSE_URL: str = Field(
        default="clickhouse://jichodns:jichodns_dev@localhost:9000/jichodns"
    )

    # Database connection pool (API process only; Celery workers use NullPool)
    DB_POOL_SIZE: int = Field(default=10)
    DB_MAX_OVERFLOW: int = Field(default=20)
    DB_POOL_RECYCLE: int = Field(default=1800)  # seconds; recycle conns older than this

    # Redis
    REDIS_URL: str = Field(default="redis://localhost:6379/0")

    # Elasticsearch
    ELASTICSEARCH_URL: str = Field(
        default="http://localhost:9200"
    )

    # CORS
    CORS_ORIGINS: List[str] = Field(
        default=[
            "http://localhost:3000",
            "http://127.0.0.1:3000",
            "https://jichosec.defendanddetect.com",
            "http://jichosec.defendanddetect.com",
        ]
    )

    # JWT
    JWT_ALGORITHM: str = "HS256"
    JWT_ACCESS_TOKEN_EXPIRE_MINUTES: int = 30
    JWT_REFRESH_TOKEN_EXPIRE_DAYS: int = 7
    # Optional JWT audience. Empty string = disabled (no aud claim set or verified).
    JWT_AUDIENCE: str = Field(default="")

    # External APIs
    SHODAN_API_KEY: str = Field(default="")
    SECURITYTRAILS_API_KEY: str = Field(default="")  # SecurityTrails subdomain/DNS history
    RIPE_ATLAS_API_KEY: str = Field(default="")
    VIRUSTOTAL_API_KEY: str = Field(default="")
    OTX_API_KEY: str = Field(default="")
    ABUSEIPDB_API_KEY: str = Field(default="")
    NVD_API_KEY: str = Field(default="")          # optional — higher NVD rate limit
    HIBP_API_KEY: str = Field(default="")         # Have I Been Pwned
    INTELX_API_KEY: str = Field(default="")       # Intelligence X
    WHOISXML_API_KEY: str = Field(default="")     # WhoisXML
    DEHASHED_API_KEY: str = Field(default="")     # Dehashed
    TELEGRAM_BOT_TOKEN: str = Field(default="")   # Telegram monitoring
    CENSYS_API_ID: str = Field(default="")        # Censys
    CENSYS_API_SECRET: str = Field(default="")    # Censys
    MALWAREBAZAAR_API_KEY: str = Field(default="")  # MalwareBazaar (abuse.ch)
    WEBHOOK_SIGNING_SECRET: str = Field(default="") # Outbound webhooks HMAC

    # Google Cloud / Vertex AI
    GOOGLE_CLOUD_PROJECT: str = Field(default="")
    GOOGLE_APPLICATION_CREDENTIALS: str = Field(default="")

    # MISP
    MISP_URL: str = Field(default="https://misp.afisac.africa")
    MISP_API_KEY: str = Field(default="")
    MISP_VERIFY_SSL: bool = Field(default=False)
    MISP_TIMEOUT: int = Field(default=120)  # seconds — MISP can be very slow
    MISP_PULL_LIMIT: int = Field(default=100)
    MISP_ENABLED: bool = Field(default=True)

    # Stripe
    STRIPE_SECRET_KEY: str = Field(default="")
    STRIPE_WEBHOOK_SECRET: str = Field(default="")
    STRIPE_PRICE_PROFESSIONAL: str = Field(default="price_professional_monthly")

    # Paystack
    PAYSTACK_SECRET_KEY: str = Field(default="")
    PAYSTACK_WEBHOOK_SECRET: str = Field(default="")

    # Rate Limits (per tier)
    RATE_LIMIT_FREE: int = 100  # per day
    RATE_LIMIT_PROFESSIONAL: int = 10000  # per day
    RATE_LIMIT_ENTERPRISE: int = 1000000  # effectively unlimited

    # On-demand ASM scan/check rate cap (per user, rolling window).
    # enterprise/admin get 5x the base cap. Backstop against using the
    # platform as an SSRF/port-scan proxy.
    ASM_SCAN_RATE_MAX: int = 20
    ASM_SCAN_RATE_WINDOW_SECONDS: int = 60

    # Feed Update Intervals (seconds)
    FEED_UPDATE_INTERVAL_URLHAUS: int = 300  # 5 minutes
    FEED_UPDATE_INTERVAL_PHISHTANK: int = 3600  # 1 hour
    FEED_UPDATE_INTERVAL_OTX: int = 900  # 15 minutes
    FEED_UPDATE_INTERVAL_THREATFOX: int = 600  # 10 minutes

    # Analysis Thresholds
    ENTROPY_THRESHOLD_HIGH: float = 3.5
    DGA_SCORE_THRESHOLD: float = 0.7
    SUBDOMAIN_LENGTH_ANOMALY: int = 50
    NEW_DOMAIN_HOURS: int = 24

    @model_validator(mode="after")
    def _validate_secrets(self) -> "Settings":
        """Fail-fast on weak/missing secrets in production; keep dev ergonomics otherwise."""
        if self.ENVIRONMENT == "production":
            if not self.SECRET_KEY or self.SECRET_KEY == _DEV_SECRET_PLACEHOLDER:
                raise ValueError(
                    "SECRET_KEY must be set to a strong, unique value in production "
                    "(the development placeholder is not allowed). Generate one with: "
                    'python -c "import secrets; print(secrets.token_urlsafe(64))"'
                )
            # Billing is only active when a Stripe secret key is present; when it is,
            # the webhook MUST be signature-verified (fail-closed).
            if self.STRIPE_SECRET_KEY and not self.STRIPE_WEBHOOK_SECRET:
                raise ValueError(
                    "STRIPE_WEBHOOK_SECRET is required in production when STRIPE_SECRET_KEY "
                    "is configured; without it webhook signatures cannot be verified."
                )
        else:
            # Dev/test only: backfill the placeholder so the app boots with no .env.
            if not self.SECRET_KEY:
                self.SECRET_KEY = _DEV_SECRET_PLACEHOLDER
        return self

    @property
    def is_production(self) -> bool:
        """Check if running in production environment."""
        return self.ENVIRONMENT == "production"


@lru_cache
def get_settings() -> Settings:
    """Get cached settings instance."""
    return Settings()


settings = get_settings()
