"""
SPDX-FileCopyrightText: 2024 Igor Kha.
SPDX-License-Identifier: MIT.
"""

from fastapi import APIRouter

from .v1.router import router as v1_auth_router

v1 = APIRouter(tags=["auth"])

v1.include_router(v1_auth_router)
