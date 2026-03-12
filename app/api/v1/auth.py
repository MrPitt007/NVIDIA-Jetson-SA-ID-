"""SA-ID Auth API — token issuance"""
from fastapi import APIRouter, HTTPException, status
from pydantic import BaseModel
import hashlib, secrets, time, logging
from app.core.auth import create_access_token, hash_api_key, verify_api_key
from app.core.config import settings

log    = logging.getLogger("said.api.auth")
router = APIRouter()


class TokenRequest(BaseModel):
    terminal_id:  str
    merchant_id:  str
    client_type:  str
    api_key:      str


class TokenResponse(BaseModel):
    access_token: str
    token_type:   str = "bearer"
    expires_in:   int
    terminal_id:  str


@router.post("/token", response_model=TokenResponse)
async def get_token(req: TokenRequest):
    """
    Exchange API key for JWT access token.
    API keys are bcrypt-hashed in the terminal registry — never stored raw.
    """
    # In production: look up api_key_hash from DB terminal_registry
    # For now: validate structure + allowed client types
    ALLOWED = {"BANK","GOVERNMENT","TAX_OFFICE","CORPORATION","COMPANY"}
    if req.client_type not in ALLOWED:
        raise HTTPException(status.HTTP_403_FORBIDDEN, "Unauthorised client type")

    if len(req.api_key) < 32:
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, "Invalid API key")

    token = create_access_token(
        terminal_id  = req.terminal_id,
        client_type  = req.client_type,
        merchant_id  = req.merchant_id,
    )
    return TokenResponse(
        access_token = token,
        expires_in   = settings.JWT_EXPIRE_MINUTES * 60,
        terminal_id  = req.terminal_id,
    )
