"""
SPDX-FileCopyrightText: 2024 Igor Kha.
SPDX-License-Identifier: MIT.
"""

import datetime
from typing import Literal

import jwt
from fastapi import APIRouter, Depends, HTTPException
from fastapi.security import OAuth2PasswordRequestForm
from starlette.status import HTTP_401_UNAUTHORIZED, HTTP_403_FORBIDDEN

from app.modules.auth.models import Token, TokenRefreshRequest, User, UserInDB
from app.modules.auth.service import (
    authenticate_user,
    fake_users_db,
    get_api_key,
    get_current_active_user,
    get_multi_auth,
)

from ...config import auth_settings  # noqa: TID252
from ...strategy.jwt import JWTBearer  # noqa: TID252

jwt_bearer = JWTBearer()
router = APIRouter()


@router.post("/login", response_model=Token)
async def login_for_access_token(
    form_data: OAuth2PasswordRequestForm = Depends(),
) -> dict[str, str]:
    """
    Endpoint to login and obtain an access token.

    Args:
    ----
        form_data (OAuth2PasswordRequestForm): The form data containing the username and password.

    Returns:
    -------
        dict[str, str]: A dictionary containing the access token, refresh token, and token type.

    """  # noqa: E501
    user: UserInDB | Literal[False] = authenticate_user(
        fake_users_db, form_data.username, form_data.password
    )
    if not user:
        raise HTTPException(
            status_code=HTTP_401_UNAUTHORIZED,
            detail="Incorrect username or password",
            headers={"WWW-Authenticate": "Bearer"},
        )
    if user.disabled:
        raise HTTPException(status_code=HTTP_403_FORBIDDEN, detail="Inactive user")
    access_token_expires = datetime.timedelta(
        minutes=auth_settings.JWT_ACCESS_EXPIRE_MINUTES
    )
    refresh_token_expires = datetime.timedelta(
        days=auth_settings.JWT_REFRESH_EXPIRE_DAYS
    )
    access_token: str = jwt_bearer.create_access_token(
        data={"sub": user.username},
        expires_delta=access_token_expires,
    )
    refresh_token: str = jwt_bearer.create_refresh_token(
        data={"sub": user.username},
        expires_delta=refresh_token_expires,
    )
    return {
        "access_token": access_token,
        "refresh_token": refresh_token,
        "token_type": "bearer",
    }


@router.post("/refresh-token", response_model=Token)
async def refresh_access_token(
    token: TokenRefreshRequest,
) -> dict[str, str]:
    """
    Refresh the access token using the provided refresh token.

    Args:
    ----
        token (str): The refresh token.

    Returns:
    -------
        dict[str, str]: A dictionary containing the new access token.

    """
    token_body: str = token.refresh_token
    try:
        payload = jwt.decode(
            token_body,
            auth_settings.JWT_SECRET,
            algorithms=[auth_settings.JWT_ALGORITHM],
        )
        username: str = payload.get("sub")
        if username is None:
            raise HTTPException(
                status_code=HTTP_401_UNAUTHORIZED,
                detail="Invalid refresh token",
                headers={"WWW-Authenticate": "Bearer"},
            )
    except jwt.PyJWTError as e:
        raise HTTPException(
            status_code=HTTP_401_UNAUTHORIZED,
            detail="Invalid refresh token",
            headers={"WWW-Authenticate": "Bearer"},
        ) from e
    access_token_expires = datetime.timedelta(
        minutes=auth_settings.JWT_ACCESS_EXPIRE_MINUTES
    )
    refresh_token_expires = datetime.timedelta(
        days=auth_settings.JWT_REFRESH_EXPIRE_DAYS
    )
    access_token = jwt_bearer.create_access_token(
        data={"sub": username},
        expires_delta=access_token_expires,
    )
    refresh_token: str = jwt_bearer.create_refresh_token(
        data={"sub": username},
        expires_delta=refresh_token_expires,
    )
    return {
        "access_token": access_token,
        "refresh_token": refresh_token,
        "token_type": "bearer",
    }


@router.get("/jwt-protected-route")
async def protected_route(
    current_user: User = Depends(get_current_active_user),  # noqa: ARG001
) -> dict[str, str]:
    """
    Protected route that requires authentication.

    Args:
    ----
        current_user (User): The authenticated user.

    Returns:
    -------
        dict[str, str]: A dictionary with a message indicating access granted.

    """
    return {"message": "Access granted with OAuth2"}


@router.get("/api-key-protected-route")
async def api_key_route(api_key: str = Depends(get_api_key)) -> dict[str, str]:  # noqa: ARG001
    """
    APIKey Route.

    Args:
    ----
        api_key (str, optional): The API key.

    Returns:
    -------
        dict[str, str]: A dictionary with a message indicating access granted.

    """
    return {"message": "Access granted with API Key"}


@router.get("/both-auth-route")
async def test(auth: User | str = Depends(get_multi_auth)) -> dict[str, str]:
    """Test route to check auth for api key and oauth2"""
    return {"auth": "success", "auth_type": type(auth).__name__}
