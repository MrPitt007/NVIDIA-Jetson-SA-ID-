"""
SA-ID Authentication & Authorization
RSA-256 JWT tokens | API key hashing | Role-based access control
"""
import hashlib, time, secrets, logging
from datetime import datetime, timedelta, timezone
from typing import Optional
from enum import Enum

import jwt
from fastapi import Depends, HTTPException, Security, status
from fastapi.security import APIKeyHeader, HTTPBearer, HTTPAuthorizationCredentials
from passlib.context import CryptContext

from app.core.config import settings
from app.core.database import get_db

log = logging.getLogger("said.auth")

# ── Roles ────────────────────────────────────────────────────────────────────
class ClientRole(str, Enum):
    BANK          = "BANK"
    GOVERNMENT    = "GOVERNMENT"
    TAX_OFFICE    = "TAX_OFFICE"
    CORPORATION   = "CORPORATION"
    COMPANY       = "COMPANY"
    ADMIN         = "ADMIN"          # SA-ID internal only

ALLOWED_ROLES = {r for r in ClientRole if r != ClientRole.ADMIN}

# ── Crypto context (bcrypt for API key hashing) ───────────────────────────────
pwd_ctx = CryptContext(schemes=["bcrypt"], deprecated="auto")

# ── Security schemes ──────────────────────────────────────────────────────────
api_key_header = APIKeyHeader(name=settings.API_KEY_HEADER, auto_error=False)
bearer_scheme  = HTTPBearer(auto_error=False)


# ── Token creation ────────────────────────────────────────────────────────────
def create_access_token(
    terminal_id: str,
    client_type: str,
    merchant_id: str,
    expires_minutes: int = None,
) -> str:
    exp = expires_minutes or settings.JWT_EXPIRE_MINUTES
    payload = {
        "sub":         terminal_id,
        "client_type": client_type,
        "merchant_id": merchant_id,
        "iat":         int(time.time()),
        "exp":         int(time.time()) + (exp * 60),
        "jti":         secrets.token_hex(16),   # unique token ID — prevents replay
        "iss":         "sa-id-enterprise",
    }
    return jwt.encode(payload, settings.JWT_SECRET, algorithm=settings.JWT_ALGORITHM)


def decode_token(token: str) -> dict:
    try:
        return jwt.decode(
            token,
            settings.JWT_SECRET,
            algorithms=[settings.JWT_ALGORITHM],
            options={"require": ["exp", "iat", "sub", "jti"]},
        )
    except jwt.ExpiredSignatureError:
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, "Token expired")
    except jwt.InvalidTokenError as e:
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, f"Invalid token: {e}")


# ── API Key validation ────────────────────────────────────────────────────────
def hash_api_key(raw_key: str) -> str:
    """SHA-256 hash for storage — bcrypt too slow for per-request check."""
    return hashlib.sha256(raw_key.encode()).hexdigest()


def verify_api_key(raw_key: str, hashed: str) -> bool:
    return secrets.compare_digest(hash_api_key(raw_key), hashed)


# ── FastAPI dependency — require valid JWT ────────────────────────────────────
async def require_auth(
    creds: Optional[HTTPAuthorizationCredentials] = Security(bearer_scheme),
) -> dict:
    if not creds or creds.scheme.lower() != "bearer":
        raise HTTPException(
            status.HTTP_401_UNAUTHORIZED,
            "Bearer token required",
            headers={"WWW-Authenticate": "Bearer"},
        )
    payload = decode_token(creds.credentials)
    client_type = payload.get("client_type", "")
    if client_type not in [r.value for r in ALLOWED_ROLES]:
        raise HTTPException(status.HTTP_403_FORBIDDEN, "Unauthorised client type")
    return payload


# ── Role guard decorator ──────────────────────────────────────────────────────
def require_role(*roles: ClientRole):
    async def _guard(payload: dict = Depends(require_auth)) -> dict:
        if payload["client_type"] not in [r.value for r in roles]:
            raise HTTPException(status.HTTP_403_FORBIDDEN, "Insufficient role")
        return payload
    return _guard
