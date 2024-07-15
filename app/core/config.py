"""
SPDX-License-Identifier: MIT
Author: Igor Kha
"""

from functools import lru_cache
from pathlib import Path
from typing import Literal

from pydantic import model_validator
from pydantic_settings import BaseSettings, SettingsConfigDict

BasePath: Path = Path(__file__).resolve().parent.parent


class Settings(BaseSettings):
    """Global application settings"""

    model_config = SettingsConfigDict(
        env_file=f"{BasePath}/.env", env_file_encoding="utf-8", extra="ignore"
    )

    # Environment configuration
    ENVIRONMENT: Literal["development", "production"] = "development"

    # FastAPI settings
    APP_NAME: str = "fastapi API"
    APP_VERSION: str = "0.0.1"
    APP_DESCRIPTION: str = ""
    APP_LICENSE_NAME: str = "MIT License"
    APP_LICENSE_IDENTIFIER: str = "MIT"
    APP_CONTACT_NAME: str = ""
    APP_CONTACT_URL: str = ""
    APP_REDIRECT_SLASHES: bool = True
    APP_ROOT_PATH: str = "/api"
    API_V1_PREFIX: str = "/v1"
    DOCS_URL: str | None = f"{API_V1_PREFIX}/docs"
    REDOCS_URL: str | None = f"{API_V1_PREFIX}/redocs"
    OPENAPI_URL: str | None = f"{API_V1_PREFIX}/openapi"

    @model_validator(mode="before")
    @classmethod
    def validate_openapi_url(cls, values: dict[str, str | None]) -> dict:
        """Validate the openapi_url based on the environment"""
        if values["ENVIRONMENT"] == "production":
            values["OPENAPI_URL"] = None
        return values

    # CORS
    CORS_ALLOW_ORIGINS: list[str] = ["*"]
    CORS_ALLOW_CREDENTIALS: bool = True
    CORS_ALLOW_METHODS: list[str] = ["*"]
    CORS_ALLOW_HEADERS: list[str] = ["*"]


@lru_cache
def get_settings() -> Settings:
    """Get global settings"""
    return Settings()


settings: Settings = get_settings()
