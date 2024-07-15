"""
SPDX-License-Identifier: MIT
Author: Igor Kha
"""

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from app.core.config import settings
from app.src.config import API_PREFIX
from app.src.routers.api import router as router_api

###
# Main application file
###


def get_application() -> FastAPI:
    """Configure, start and return the application"""
    # Start FastApi App
    application = FastAPI(
        title=settings.APP_NAME,
        description=settings.APP_DESCRIPTION,
        version="0.0.1",
        license_info={
            "name": "MIT License",
            "identifier": "MIT",
        },
        contact={
            "name": "lab240",
            "url": "https://github.com/lab240",
        },
        root_path=API_PREFIX,
        redirect_slashes=True,
        openapi_tags=[
            {
                "name": "test",
                "description": "Test operations",
            },
        ],
        redoc_url=None,
    )

    # Generate database tables
    # Base.metadata.create_all(bind=engine)

    # Mapping api routes
    application.include_router(router_api)

    # Add exception handlers
    # application.add_exception_handler(HTTPException, http_error_handler)

    # Allow cors
    application.add_middleware(
        CORSMiddleware,
        # allow_origins=ALLOWED_HOSTS or ["*"],
        allow_origins=["*"],
        allow_credentials=True,
        allow_methods=["*"],
        allow_headers=["*"],
    )

    # Example of admin route
    # application.include_router(
    #     admin.router,
    #     prefix="/admin",
    #     tags=["admin"],
    #     dependencies=[Depends(get_token_header)],
    #     responses={418: {"description": "I'm a teapot"}},
    # )

    return application


app: FastAPI = get_application()
