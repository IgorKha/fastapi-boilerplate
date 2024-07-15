"""
SPDX-FileCopyrightText: 2024 Igor Kha.
SPDX-License-Identifier: MIT.
"""

from typing import Literal

import jwt
from fastapi import Depends, HTTPException, Security
from fastapi.security import APIKeyHeader, OAuth2PasswordBearer
from starlette.status import HTTP_401_UNAUTHORIZED, HTTP_403_FORBIDDEN

from .models import TokenData, User, UserInDB
from .strategy.jwt import JWTBearer

jwt_bearer = JWTBearer()
oauth2_scheme = OAuth2PasswordBearer(tokenUrl="login", auto_error=False)
api_key_header = APIKeyHeader(name="X-API-Key", auto_error=False)

# Admin password: "secret"
fake_users_db = {
    "admin": {
        "username": "admin",
        "full_name": "John Doe",
        "email": "user@example.com",
        "hashed_password": "$2b$12$EixZaYVK1fsbw1ZfbX3OXePaWxn96p36WQoeG6Lruj3vjPGga31lW",  # noqa: E501
        "disabled": False,
    },
}


def _get_user(db, username: str) -> UserInDB | None:  # noqa: ANN001
    """
    Retrieve a user from the database based on the username.

    Args:
    ----
        db (dict): The database containing user information.
        username (str): The username of the user to retrieve.

    Returns:
    -------
        UserInDB | None: The user object if found, None otherwise.

    """
    if username in db:
        user_dict = db[username]
        return UserInDB(**user_dict)
    return None


def authenticate_user(
    fake_db: object, username: str, password: str
) -> UserInDB | Literal[False]:
    """
    Authenticate a user based on the provided username and password.
    Use for login endpoint.

    Args:
    ----
        fake_db (object): The database object.
        username (str): The username of the user.
        password (str): The password of the user.

    Returns:
    -------
        UserInDB | Literal[False]:
        The authenticated user object if successful, False otherwise.

    """
    user: UserInDB | None = _get_user(fake_db, username)
    if not user:
        return False
    if not jwt_bearer.verify_password(password, user.hashed_password):
        return False
    return user


async def _get_current_user(token: str = Depends(oauth2_scheme)) -> None | UserInDB:
    """
    Retrieves the current user based on the provided token.

    Args:
    ----
        token (str): The authentication token.

    Returns:
    -------
        User: The current user if the token is valid, otherwise None.

    """  # noqa: D401
    credentials_exception = HTTPException(
        status_code=HTTP_401_UNAUTHORIZED,
        detail="Could not validate credentials",
        headers={"WWW-Authenticate": "Bearer"},
    )
    try:
        payload: dict = jwt_bearer.decode_token(token)
        username: str | None = payload.get("sub")
        if username is None:
            raise credentials_exception
        token_data = TokenData(username=username)
    except jwt.PyJWTError as e:
        raise credentials_exception from e
    user: UserInDB | None = _get_user(fake_users_db, username=token_data.username)

    if user is None:
        raise credentials_exception
    return user


async def _get_current_user_multi_auth(
    token: str = Depends(oauth2_scheme),
) -> None | UserInDB:
    """
    DO NOT USE DIRECTLY THIS FUNCTION IN ROUTE AS Security() OR Depends().

    Retrieves the current user based on the provided token.

    Args:
    ----
        token (str): The authentication token.

    Returns:
    -------
        None: If the token is invalid or the user cannot be found.
        UserInDB: The user object if found.

    """
    try:
        payload: dict = jwt_bearer.decode_token(token)
        username: str | None = payload.get("sub")
        if username is None:
            return None
    except jwt.PyJWTError:
        return None
    user: UserInDB | None = _get_user(fake_users_db, username=username)
    if user is None:
        return None
    return user


# USE THIS FUNCTION IN ROUTE AS Security() OR Depends() for single-auth (user) JWT
async def get_current_active_user(
    current_user: User = Depends(_get_current_user),
) -> User:
    """
    Get the current active user.

    Args:
    ----
    current_user (User): The current user object.

    Returns:
    -------
    User: The current active user.

    Raises:
    ------
    HTTPException: If the current user is disabled.

    """
    if current_user.disabled:
        raise HTTPException(status_code=HTTP_403_FORBIDDEN, detail="Inactive user")
    return current_user


# USE THIS FUNCTION IN ROUTE AS Security()
#   OR Depends() for single-auth (external services) API key
async def get_api_key(api_key: str = Security(api_key_header)) -> str | None:
    """
    Get the API key from the request header.

    Args:
    ----
        api_key (str, optional): The API key provided in the request header.
            Defaults to None.

    Returns:
    -------
        str: The API key.

    Raises:
    ------
        HTTPException: If the API key is invalid.

    """
    if api_key != "expected_api_key":
        raise HTTPException(status_code=HTTP_401_UNAUTHORIZED, detail="Invalid API Key")
    return api_key


# USE THIS FUNCTION IN ROUTE AS Security() OR Depends() for multi-auth
async def get_multi_auth(
    api_key: str | None = Security(api_key_header),
    current_user: User | None = Security(_get_current_user_multi_auth),
) -> User | str:
    """
    Authenticates the user based on the provided API key or current user credentials.

    Args:
    ----
        api_key (str, optional): The API key provided in the request header.
        Defaults to None.
        current_user (User, optional): The current user object. Defaults to None.

    Returns:
    -------
        Union[User, str]: The authenticated user object or the API key.

    Raises:
    ------
        HTTPException: If the API key is invalid or the credentials are invalid or the user is inactive.

    """  # noqa: D401, E501
    if api_key:
        if api_key != "expected_api_key":
            raise HTTPException(
                status_code=HTTP_401_UNAUTHORIZED, detail="Invalid API Key"
            )
        return api_key
    if current_user:
        # Check if current_user is of expected User type before accessing attributes
        if current_user.disabled:
            raise HTTPException(status_code=HTTP_403_FORBIDDEN, detail="Inactive user")
        return current_user
    raise HTTPException(status_code=HTTP_401_UNAUTHORIZED, detail="Invalid credentials")
