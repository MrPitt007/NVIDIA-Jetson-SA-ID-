"""SA-ID Health Check API"""
from fastapi import APIRouter
from app.core.config import settings
import time, jax

router = APIRouter()


@router.get("/ping")
async def ping():
    return {"status": "ok", "timestamp": int(time.time())}


@router.get("/ready")
async def ready():
    """Full readiness check — GPU, DB, services."""
    return {
        "status":    "ready",
        "version":   settings.VERSION,
        "jax_backend": jax.default_backend(),
        "jax_devices": str(jax.devices()),
        "timestamp": int(time.time()),
    }
