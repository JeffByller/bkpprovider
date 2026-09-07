import asyncio
from contextlib import asynccontextmanager

from fastapi import FastAPI
from fastapi.staticfiles import StaticFiles
from starlette.middleware.base import BaseHTTPMiddleware

from app.db import init_db
from app.mikrotik import mikrotik_worker
from app.monitor import icmp_worker
from app.routes import auth_routes, devices_api, pages, settings_api, summary_api, targets_api


@asynccontextmanager
async def lifespan(app: FastAPI):
    init_db()
    asyncio.create_task(icmp_worker())
    asyncio.create_task(mikrotik_worker())
    yield


app = FastAPI(title="MeuProvedor Monitor & Backup", lifespan=lifespan, docs_url=None, redoc_url=None, openapi_url=None)


class SecurityHeadersMiddleware(BaseHTTPMiddleware):
    async def dispatch(self, request, call_next):
        response = await call_next(request)
        response.headers["X-Content-Type-Options"] = "nosniff"
        response.headers["X-Frame-Options"] = "DENY"
        response.headers["X-XSS-Protection"] = "1; mode=block"
        response.headers["Referrer-Policy"] = "strict-origin-when-cross-origin"
        response.headers["Cache-Control"] = "no-store, no-cache, must-revalidate"
        return response


app.add_middleware(SecurityHeadersMiddleware)

app.mount("/static", StaticFiles(directory="static"), name="static")

app.include_router(auth_routes.router)
app.include_router(pages.router)
app.include_router(targets_api.router)
app.include_router(devices_api.router)
app.include_router(devices_api.download_router)
app.include_router(settings_api.router)
app.include_router(summary_api.router)
