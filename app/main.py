"""
SPDX-FileCopyrightText: 2024 Igor Kha.
SPDX-License-Identifier: MIT.
"""

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from .core.config import settings
from .modules.router import route_v1


def get_application() -> FastAPI:
    """Configure, start and return the application"""
    application = FastAPI(
        title=settings.APP_NAME,
        description=settings.APP_DESCRIPTION,
        version=settings.APP_VERSION,
        license_info={
            "name": settings.APP_LICENSE_NAME,
            "identifier": settings.APP_LICENSE_IDENTIFIER,
        },
        contact={
            "name": settings.APP_CONTACT_NAME,
            "url": settings.APP_CONTACT_URL,
        },
        root_path=settings.APP_ROOT_PATH,
        redirect_slashes=settings.APP_REDIRECT_SLASHES,
        openapi_url=settings.OPENAPI_URL,
        docs_url=settings.DOCS_URL,
        redoc_url=settings.REDOCS_URL,
    )

    # Allow cors
    application.add_middleware(
        CORSMiddleware,
        allow_origins=["*"],
        allow_credentials=True,
        allow_methods=["*"],
        allow_headers=["*"],
    )

    application.include_router(route_v1)

    return application


app: FastAPI = get_application()
