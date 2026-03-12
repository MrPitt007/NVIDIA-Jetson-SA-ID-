"""
SA-ID Identity Verification API — v1
POST /api/v1/identity/verify
POST /api/v1/identity/batch
GET  /api/v1/identity/status/{tx_hash}
"""
from fastapi import APIRouter, Depends, HTTPException, status, BackgroundTasks
from pydantic import BaseModel, Field, field_validator
import re, time, logging
from typing import Optional

from app.core.auth import require_auth
from app.services.identity_service import IdentityService, verify_sa_id_checksum

log    = logging.getLogger("said.api.identity")
router = APIRouter()
_svc   = IdentityService()


# ── Request / Response Models ─────────────────────────────────────────────────
class VerifyRequest(BaseModel):
    id_number:      str   = Field(..., min_length=13, max_length=13,
                                  description="SA-ID number — 13 digits")
    surname:        str   = Field(..., min_length=1, max_length=100)
    given_names:    str   = Field(..., min_length=1, max_length=200)
    dob:            str   = Field(..., description="Date of birth YYYYMMDD")
    terminal_id:    str   = Field(..., min_length=4, max_length=64)
    live_frame_b64: Optional[str] = Field(None, description="Base64 IR camera frame")
    doc_frame_b64:  Optional[str] = Field(None, description="Base64 document camera frame")

    @field_validator("id_number")
    @classmethod
    def id_must_be_digits(cls, v):
        if not v.isdigit():
            raise ValueError("SA-ID number must be 13 digits only")
        return v

    @field_validator("dob")
    @classmethod
    def dob_format(cls, v):
        if not re.match(r"^\d{8}$", v):
            raise ValueError("DOB must be YYYYMMDD format")
        return v

    @field_validator("surname", "given_names")
    @classmethod
    def names_alpha(cls, v):
        if not re.match(r"^[a-zA-Z\s\-'\.]+$", v):
            raise ValueError("Names must contain letters, spaces, hyphens, apostrophes only")
        return v.strip().upper()


class VerifyResponse(BaseModel):
    verified:      bool
    result:        str
    reject_reason: Optional[str]
    id_hash:       str       # first 16 hex chars of SHA-256 — never raw ID
    client_type:   str
    terminal_id:   str
    bio_score:     Optional[float]
    liveness:      Optional[str]
    liveness_conf: Optional[float]
    dha_verified:  Optional[bool]
    total_ms:      float
    timestamp:     int
    tx_hash:       str
    version:       str


# ── Endpoints ─────────────────────────────────────────────────────────────────
@router.post(
    "/verify",
    response_model=VerifyResponse,
    summary="Full 7-stage biometric identity verification",
    description=(
        "Runs complete SA-ID verification pipeline: "
        "Camera → Liveness (NVDLA v2.0) → MRZ/OCR → DHA API → "
        "ArcFace biometric match (Ampere GPU) → POPIA audit → HMAC signed result. "
        "Authorised enterprise clients only."
    ),
)
async def verify_identity(
    req:      VerifyRequest,
    bg:       BackgroundTasks,
    payload:  dict = Depends(require_auth),
):
    """Verify a single SA-ID document + biometric in real time."""
    client_type = payload["client_type"]
    terminal_id = req.terminal_id

    try:
        result = await _svc.verify(
            id_number      = req.id_number,
            surname        = req.surname,
            given_names    = req.given_names,
            dob            = req.dob,
            client_type    = client_type,
            terminal_id    = terminal_id,
            live_frame_b64 = req.live_frame_b64,
            doc_frame_b64  = req.doc_frame_b64,
        )
        return result

    except Exception as e:
        log.exception("[VERIFY] Unhandled error for terminal=%s: %s", terminal_id, e)
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail={"error": "Verification pipeline error", "code": "SAID_500_VERIFY"},
        )


@router.post(
    "/checksum",
    summary="Fast SA-ID checksum validation only (no biometric)",
    include_in_schema=True,
)
async def checksum_only(
    id_number: str,
    payload:   dict = Depends(require_auth),
):
    """
    Fast Luhn-style checksum check.
    Does NOT call DHA or run biometric — for pre-validation only.
    """
    valid = verify_sa_id_checksum(id_number)
    return {
        "id_number_valid": valid,
        "id_length_ok":    len(id_number) == 13,
        "timestamp":       int(time.time()),
    }
