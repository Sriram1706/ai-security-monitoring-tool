import secrets
from pydantic_settings import BaseSettings, SettingsConfigDict

ALGORITHM = "HS256"


class Settings(BaseSettings):
    app_name: str = "AI Security Monitoring Tool"
    environment: str = "dev"
    database_url: str = "sqlite:///./security.db"
    jwt_secret: str = secrets.token_hex(32)
    jwt_algorithm: str = ALGORITHM
    access_token_minutes: int = 60
    bootstrap_admin_email: str = "admin@ai-sec.local"
    bootstrap_admin_password: str = "AdminPass123!"
    openai_api_key: str = ""
    openai_model: str = "gpt-4o-mini"
    openai_base_url: str = "https://api.openai.com/v1"
    threat_intel_enabled: bool = True
    threat_intel_feeds: str = ""
    threat_intel_poll_seconds: int = 1800
    supply_chain_scan_enabled: bool = True
    supply_chain_scan_osv_url: str = "https://api.osv.dev/v1/query"
    supply_chain_scan_timeout_sec: int = 3
    supply_chain_scan_cache_seconds: int = 3600
    supply_chain_scan_max_packages: int = 60
    mirror_ingest_enabled: bool = True
    mirror_ingest_require_key: bool = False
    mirror_ingest_api_key: str = ""
    url_fetch_allowlist: str = "localhost,127.0.0.1,example.com"
    url_fetch_timeout_sec: int = 5
    url_fetch_max_bytes: int = 300000
    policy_prompt_injection_block_score: int = 50
    policy_indirect_injection_block_score: int = 50
    policy_global_block_score: int = 80
    policy_warning_score: int = 40
    policy_allowed_phrases: str = ""
    policy_allowed_domains: str = ""
    policy_version: str = "v1"
    policy_hard_block_risk_types: str = (
        "prompt_injection,indirect_prompt_injection,data_exfiltration,"
        "sensitive_data_exposure,illegal_activity"
    )

    model_config = SettingsConfigDict(env_file=".env", env_file_encoding="utf-8")


settings = Settings()
