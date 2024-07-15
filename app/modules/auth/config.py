"""
SPDX-FileCopyrightText: 2024 Igor Kha.
SPDX-License-Identifier: MIT.
"""

import secrets
from functools import lru_cache
from pathlib import Path

from pydantic_settings import BaseSettings, SettingsConfigDict

BasePath: Path = Path(__file__).resolve().parent.parent


class AuthSettings(BaseSettings):
    """Settings for authentication."""

    model_config = SettingsConfigDict(
        env_file=f"{BasePath}/.env", env_file_encoding="utf-8", extra="ignore"
    )

    # API Key configuration
    KEY_API_SECRET: str = ""
    KEY_API_ALGORITHM: str = "HS256"
    KEY_API_NAME: str = "X-API-Key"

    # JWT Token configuration
    JWT_SECRET: str = secrets.token_urlsafe(32)
    JWT_ALGORITHM: str = "HS256"
    JWT_ACCESS_EXPIRE_MINUTES: int = 30
    JWT_REFRESH_EXPIRE_DAYS: int = 7


@lru_cache
def get_auth_settings() -> AuthSettings:
    """Get auth settings"""
    return AuthSettings()


auth_settings: AuthSettings = get_auth_settings()
