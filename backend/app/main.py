"""
FastAPI application entrypoint.

Purpose:
    Wires together middleware, routers, startup/shutdown events, and
    exception handling into a single ASGI app.

Running (local, without Docker):
    uvicorn app.main:app --reload --port 8000

Running (Docker):
    docker compose up backend

API docs:
    http://localhost:8000/docs        (Swagger UI)
    http://localhost:8000/redoc       (ReDoc)
"""

from contextlib import asynccontextmanager

from fastapi import FastAPI, Request, status
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse

from app.api.routers import alerts, auth, dashboard, health, websocket
from app.core.config import settings
from app.core.database import init_db
from app.core.logging_config import configure_logging
from app.services.redis_listener import start_listener, stop_listener

configure_logging()


@asynccontextmanager
async def lifespan(app: FastAPI):
    # Startup
    await init_db()
    start_listener()
    yield
    # Shutdown
    await stop_listener()


app = FastAPI(
    title=settings.APP_NAME,
    version="0.2.0",
    description=(
        "AI-powered SOC Assistant — alert investigation, MITRE ATT&CK mapping, "
        "IOC enrichment, risk scoring, and AI-generated incident reports."
    ),
    docs_url="/docs",
    redoc_url="/redoc",
    openapi_url="/openapi.json",
    lifespan=lifespan,
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=settings.cors_origins_list,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


@app.exception_handler(Exception)
async def unhandled_exception_handler(request: Request, exc: Exception) -> JSONResponse:
    """
    Catch-all so unexpected errors return a clean JSON body instead of a
    raw traceback — important for a tool analysts may script against.
    """
    return JSONResponse(
        status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
        content={"detail": "Internal server error", "type": exc.__class__.__name__},
    )


app.include_router(health.router, prefix=settings.API_V1_PREFIX)
app.include_router(auth.router, prefix=settings.API_V1_PREFIX)
app.include_router(alerts.router, prefix=settings.API_V1_PREFIX)
app.include_router(dashboard.router, prefix=settings.API_V1_PREFIX)
app.include_router(websocket.router, prefix=settings.API_V1_PREFIX)

# Phase 3+ will register: ioc, ai_assistant, reports, mitre routers


@app.get("/")
async def root() -> dict:
    return {
        "name": settings.APP_NAME,
        "status": "running",
        "environment": settings.ENVIRONMENT,
        "docs": "/docs",
    }
