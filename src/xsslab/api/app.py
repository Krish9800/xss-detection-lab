"""FastAPI application factory for xsslab microservice."""

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from xsslab.api.routes import router
from xsslab.config.settings import get_settings


def create_app() -> FastAPI:
    """Build and configure the FastAPI application instance."""
    settings = get_settings()

    app = FastAPI(
        title=settings.app_name,
        version=settings.version,
        description=(
            "Enterprise-Grade Cross-Site Scripting (XSS) Detection Engine and Dual-Mode Defensive Lab."
        ),
        docs_url="/docs",
        redoc_url="/redoc",
    )

    app.add_middleware(
        CORSMiddleware,
        allow_origins=["*"],
        allow_credentials=True,
        allow_methods=["*"],
        allow_headers=["*"],
    )

    app.include_router(router)
    return app


app = create_app()
