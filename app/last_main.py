"""
SPDX-FileCopyrightText: 2024 Igor Kha.
SPDX-License-Identifier: MIT.
"""

import datetime
from typing import Literal

import jwt
from fastapi import Depends, FastAPI, HTTPException, Security
from fastapi.security import (
    APIKeyHeader,
    OAuth2PasswordBearer,
    OAuth2PasswordRequestForm,
)
from jwt.exceptions import PyJWTError
from passlib.context import CryptContext
from pydantic import BaseModel
from starlette.status import HTTP_401_UNAUTHORIZED

SECRET_KEY = "secret"  # noqa: S105
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 30
REFRESH_TOKEN_EXPIRE_DAYS = 7

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
    disabled: bool | None = None


class UserInDB(User):
    """Data model for user in the database."""

    hashed_password: str


pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")
oauth2_scheme = OAuth2PasswordBearer(tokenUrl="token", auto_error=False)
api_key_header = APIKeyHeader(name="X-API-Key", auto_error=False)


def verify_password(plain_password: str, hashed_password: str) -> bool:
    """Verify the provided plain password against the hashed password."""
    return pwd_context.verify(plain_password, hashed_password)


def get_password_hash(password: str) -> str:
    """Generate a password hash for the provided password."""
    return pwd_context.hash(password)


def get_user(db, username: str) -> UserInDB | None:  # noqa: ANN001
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
    user = get_user(fake_db, username)
    if not user:
        return False
    if not verify_password(password, user.hashed_password):
        return False
    return user


def create_access_token(
    data: dict, expires_delta: datetime.timedelta | None = None
) -> str:
    """
    Create an access token using the provided data and expiration delta.

    Args:
    ----
        data (dict): The data to be encoded in the access token.
        expires_delta (datetime.timedelta | None, optional):
            The expiration delta for the access token.
            If not provided, a default expiration of 15 minutes will be used.

    Returns:
    -------
        str: The encoded access token.

    """
    to_encode = data.copy()
    if expires_delta:
        expire: datetime.datetime = datetime.datetime.now(datetime.UTC) + expires_delta
    else:
        expire: datetime.datetime = datetime.datetime.now(
            datetime.UTC
        ) + datetime.timedelta(minutes=15)
    to_encode.update({"exp": expire})
    return jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)


def create_refresh_token(
    data: dict, expires_delta: datetime.timedelta | None = None
) -> str:
    """
    Create a refresh token.

    Args:
    ----
        data (dict): The data to be encoded in the token.
        expires_delta (datetime.timedelta | None, optional):
            The expiration time delta for the token.
            If not provided, a default expiration time of 7 days will be used. Defaults to None.

    Returns:
    -------
        str: The encoded refresh token.

    """  # noqa: E501
    to_encode = data.copy()
    if expires_delta:
        expire = datetime.datetime.now(datetime.UTC) + expires_delta
    else:
        expire: datetime.datetime = datetime.datetime.now(
            datetime.UTC
        ) + datetime.timedelta(days=7)
    to_encode.update({"exp": expire})
    return jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)


async def get_current_user(token: str = Depends(oauth2_scheme)) -> None | UserInDB:
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
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        username: str = payload.get("sub")
        if username is None:
            raise credentials_exception
        token_data = TokenData(username=username)
    except PyJWTError:
        return None
    user = get_user(fake_users_db, username=token_data.username)

    if user is None:
        return None
    return user


async def get_current_active_user(
    current_user: User = Depends(get_current_user),
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
        raise HTTPException(status_code=400, detail="Inactive user")
    return current_user


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
    if not api_key:
        return None
    if api_key != "expected_api_key":
        raise HTTPException(status_code=HTTP_401_UNAUTHORIZED, detail="Invalid API Key")
    return api_key


async def get_auth(
    api_key: str | None = Security(get_api_key),
    current_user: User | None = Security(get_current_active_user),
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
            raise HTTPException(status_code=400, detail="Inactive user")
        return current_user
    raise HTTPException(status_code=HTTP_401_UNAUTHORIZED, detail="Invalid credentials")


app = FastAPI(
    redoc_url=None,
)


@app.post("/token", response_model=Token)
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
    access_token_expires = datetime.timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
    refresh_token_expires = datetime.timedelta(days=REFRESH_TOKEN_EXPIRE_DAYS)
    access_token: str = create_access_token(
        data={"sub": user.username},
        expires_delta=access_token_expires,
    )
    refresh_token: str = create_refresh_token(
        data={"sub": user.username},
        expires_delta=refresh_token_expires,
    )
    return {
        "access_token": access_token,
        "refresh_token": refresh_token,
        "token_type": "bearer",
    }


@app.post("/refresh-token", response_model=Token)
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
        payload = jwt.decode(token_body, SECRET_KEY, algorithms=[ALGORITHM])
        username: str = payload.get("sub")
        if username is None:
            raise HTTPException(
                status_code=HTTP_401_UNAUTHORIZED,
                detail="Invalid refresh token",
                headers={"WWW-Authenticate": "Bearer"},
            )
    except PyJWTError as e:
        raise HTTPException(
            status_code=HTTP_401_UNAUTHORIZED,
            detail="Invalid refresh token",
            headers={"WWW-Authenticate": "Bearer"},
        ) from e
    access_token_expires = datetime.timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
    refresh_token_expires = datetime.timedelta(days=REFRESH_TOKEN_EXPIRE_DAYS)
    access_token = create_access_token(
        data={"sub": username},
        expires_delta=access_token_expires,
    )
    refresh_token: str = create_refresh_token(
        data={"sub": username},
        expires_delta=refresh_token_expires,
    )
    return {
        "access_token": access_token,
        "refresh_token": refresh_token,
        "token_type": "bearer",
    }


@app.get("/protected-route")
async def protected_route(
    current_user: User = Depends(get_current_active_user),
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
    print(current_user)  # noqa: T201
    return {"message": "Access granted with OAuth2"}


@app.get("/api-key-route")
async def api_key_route(api_key: str = Depends(get_api_key)) -> dict[str, str]:
    """
    APIKey Route.

    Args:
    ----
        api_key (str, optional): The API key.

    Returns:
    -------
        dict[str, str]: A dictionary with a message indicating access granted.

    """
    print(api_key)  # noqa: T201
    return {"message": "Access granted with API Key"}


@app.get("/common-route")
async def common_route(
    api_key: str | None = Security(api_key_header),
    current_user: User | None = Depends(get_current_active_user),
) -> dict[str, str]:
    """Asd"""
    if api_key == "expected_api_key":
        return {"message": "Access granted with API Key"}
    if current_user:
        return {"message": "Access granted with OAuth2"}
    raise HTTPException(status_code=HTTP_401_UNAUTHORIZED, detail="Invalid credentials")


@app.get("/test")
async def test(auth: User | str = Depends(get_auth)) -> dict[str, str]:
    """Test route to check auth for api key and oauth2"""
    return {"auth": "success", "auth_type": type(auth).__name__}
