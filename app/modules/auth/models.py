"""
SPDX-FileCopyrightText: 2024 Igor Kha.
SPDX-License-Identifier: MIT.
"""

from pydantic import BaseModel


class Token(BaseModel):
    """Data model for tokens."""

    access_token: str
    refresh_token: str
    token_type: str


class TokenData(BaseModel):
    """Data model for token data."""

    username: str


class TokenRefreshRequest(BaseModel):
    """Data model for token refresh request."""

    refresh_token: str


class User(BaseModel):
    """Data model for user."""

    username: str
    email: str
    full_name: str | None = None
    disabled: bool = False


class UserInDB(User):
    """Data model for user in the database."""

    hashed_password: str
