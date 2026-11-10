from functools import lru_cache
from pydantic import Field
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    model_config = SettingsConfigDict(env_file=".env", extra="ignore")
    mode: str = "DEMO"
    database_url: str = "postgresql+psycopg://soc:soc@db:5432/soc"
    redis_url: str = "redis://redis:6379/0"
    jwt_secret: str = "change-this-before-exposure-1234567890"
    webhook_secret: str = "change-webhook-secret"
    demo_admin_password: str = "admin-demo"
    demo_analyst_password: str = "analyst-demo"
    connected_admin_password: str = ""
    connected_analyst_password: str = ""
    automation_level: str = "auto_close"
    auto_close_enabled: bool = False
    connected_writes_enabled: bool = False
    connected_allowed_actions: str = ""
    timezone: str = "Asia/Qyzylorda"
    investigation_timeout_seconds: int = 90
    max_evidence_items: int = 50
    splunk_base_url: str = ""
    splunk_token: str = ""
    splunk_search_template: str = "search index=main earliest={earliest} latest={latest} | head 200"
    splunk_poll_seconds: int = 60
    splunk_overlap_seconds: int = 120
    thehive_base_url: str = ""
    thehive_api_key: str = ""
    thehive_api_version: str = ""
    misp_base_url: str = ""
    misp_api_key: str = ""
    ollama_base_url: str = ""
    ollama_model: str = ""
    ollama_timeout_seconds: int = Field(default=15, ge=2, le=120)
    ollama_max_input_chars: int = Field(default=12000, ge=1000, le=50000)
    ollama_max_output_bytes: int = Field(default=100000, ge=1000, le=1000000)
    ollama_num_ctx: int = Field(default=4096, ge=512, le=32768)
    ollama_max_concurrent: int = Field(default=2, ge=1, le=8)


@lru_cache
def settings() -> Settings:
    return Settings()
