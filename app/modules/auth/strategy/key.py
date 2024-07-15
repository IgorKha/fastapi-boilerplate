"""
SPDX-FileCopyrightText: 2024 Igor Kha.
SPDX-License-Identifier: MIT.
"""

import datetime

import jwt
from fastapi.security import APIKeyHeader

from ..config import auth_settings as settings  # noqa: TID252


class KeyBearer:
    """KeyBearer class for handling key encoding and decoding."""

    def __init__(
        self,
        secret_key: str = settings.KEY_API_SECRET,
        algorithm: str = settings.KEY_API_ALGORITHM,
        key_header: APIKeyHeader = APIKeyHeader(
            name=settings.KEY_API_NAME, auto_error=False
        ),
    ) -> None:
        """
        Initialize the KeyBearer class.

        Args:
        ----
            secret_key (str): The secret key for encoding and decoding.
            algorithm (str): The algorithm used for encoding and decoding.
            key_header (APIKeyHeader): The APIKeyHeader object.

        """
        self.secret_key: str = secret_key
        self.algorithm: str = algorithm
        self.key_header: APIKeyHeader = key_header

    # TODO(igor): Changing logic based on api key (change payload)
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

    # TODO(igor): Changing logic based on api key (change payload)
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
