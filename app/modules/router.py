"""
SPDX-FileCopyrightText: 2024 Igor Kha.
SPDX-License-Identifier: MIT.
"""

from fastapi import APIRouter

from app.core.config import settings

from .auth.api.router import v1 as auth_v1

route_v1 = APIRouter(prefix=settings.API_V1_PREFIX)

route_v1.include_router(auth_v1)
