"""SA-ID Audit API — v1"""
from fastapi import APIRouter, Depends, Query
from app.core.auth import require_auth, require_role, ClientRole
from app.core.database import AuditLogger
import time

router = APIRouter()
_audit = AuditLogger()


@router.get("/verify-chain")
async def verify_audit_chain(
    payload: dict = Depends(require_role(ClientRole.ADMIN, ClientRole.GOVERNMENT))
):
    """Verify integrity of POPIA SHA-256 audit hash chain."""
    return await _audit.verify_chain()


@router.get("/system-events")
async def get_system_events(
    payload: dict = Depends(require_role(ClientRole.ADMIN))
):
    """Get system event log — ADMIN only."""
    return {"events": [], "timestamp": int(time.time())}
