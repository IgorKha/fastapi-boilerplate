"""
SPDX-FileCopyrightText: 2024 Igor Kha.
SPDX-License-Identifier: MIT.
"""

import datetime

import jwt
from passlib.context import CryptContext

from ..config import auth_settings  # noqa: TID252


class JWTBearer:
    """JWTBearer class for handling JWT encoding and decoding for User authentication"""

    def __init__(
        self,
        secret_key: str = auth_settings.JWT_SECRET,
        algorithm: str = auth_settings.JWT_ALGORITHM,
        context: CryptContext = CryptContext(schemes=["bcrypt"], deprecated="auto"),
    ) -> None:
        """
        Initialize the JWTBearer class.

        Args:
        ----
            secret_key (str): The secret key for JWT encoding and decoding.
            algorithm (str): The algorithm used for JWT encoding and decoding.
            context (CryptContext): The CryptContext object for password hashing.

        """
        self.secret_key: str = secret_key
        self.algorithm: str = algorithm
        self.context: CryptContext = context

    def verify_password(self, plain_password: str, hashed_password: str) -> bool:
        """
        Verify the password.

        Args:
        ----
            plain_password (str): The plain password.
            hashed_password (str): The hashed password.

        Returns:
        -------
            bool: True if the password is verified, False otherwise.

        """
        return self.context.verify(plain_password, hashed_password)

    def get_password_hash(self, password: str) -> str:
        """
        Get the password hash.

        Args:
        ----
            password (str): The password to hash.

        Returns:
        -------
            str: The hashed password.

        """
        return self.context.hash(password)

    def create_access_token(
        self, data: dict, expires_delta: datetime.timedelta | None = None
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
            expire: datetime.datetime = (
                datetime.datetime.now(datetime.UTC) + expires_delta
            )
        else:
            expire: datetime.datetime = datetime.datetime.now(
                datetime.UTC
            ) + datetime.timedelta(minutes=15)
        to_encode.update({"exp": expire})
        return jwt.encode(
            payload=to_encode, key=self.secret_key, algorithm=self.algorithm
        )

    def create_refresh_token(
        self, data: dict, expires_delta: datetime.timedelta | None = None
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
        return jwt.encode(
            payload=to_encode, key=self.secret_key, algorithm=self.algorithm
        )

    def decode_token(self, token: str) -> dict:
        """
        Decode a token.

        Args:
        ----
            token (str): The token to decode.

        Returns:
        -------
            dict: The decoded token.

        """
        return jwt.decode(token, self.secret_key, algorithms=[self.algorithm])
