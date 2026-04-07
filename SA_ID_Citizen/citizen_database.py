# citizen_database.py
# SA-ID Platform — PostgreSQL Database Layer
# Replaces the mock database with real PostgreSQL

import os
import asyncpg
import hashlib
import json
from datetime import datetime, timedelta
from typing import Optional, Dict, Any, List
from dotenv import load_dotenv

load_dotenv()

# ── Database Configuration ──────────────────────────────────
DB_CONFIG = {
    "host":     os.getenv("DB_HOST", "localhost"),
    "port":     int(os.getenv("DB_PORT", 5432)),
    "database": os.getenv("DB_NAME", "sa_id_db"),
    "user":     os.getenv("DB_USER", "sa_id_user"),
    "password": os.getenv("DB_PASSWORD", "sa_id_secure_2026"),
}

# Global connection pool
_pool: Optional[asyncpg.Pool] = None


# ── Pool Management ─────────────────────────────────────────
async def get_pool() -> asyncpg.Pool:
    """Get or create the database connection pool."""
    global _pool
    if _pool is None:
        _pool = await asyncpg.create_pool(
            **DB_CONFIG,
            min_size=2,
            max_size=10,
            command_timeout=30,
        )
        print("✅ PostgreSQL pool connected")
    return _pool


async def close_pool():
    """Close the connection pool on shutdown."""
    global _pool
    if _pool:
        await _pool.close()
        _pool = None
        print("🔌 PostgreSQL pool closed")


# ── Audit Helper ────────────────────────────────────────────
async def audit(
    action: str,
    citizen_id: str = None,
    id_number: str = None,
    table_affected: str = None,
    record_id: str = None,
    old_values: dict = None,
    new_values: dict = None,
    ip_address: str = None,
):
    """Write an audit log entry — raw SQL, no ORM."""
    pool = await get_pool()
    async with pool.acquire() as conn:
        await conn.execute("""
            INSERT INTO audit_log
                (citizen_id, id_number, action, table_affected, record_id,
                 old_values, new_values, ip_address)
            VALUES ($1, $2, $3, $4, $5, $6, $7, $8)
        """,
            citizen_id,
            id_number,
            action,
            table_affected,
            record_id,
            json.dumps(old_values) if old_values else None,
            json.dumps(new_values) if new_values else None,
            ip_address,
        )


# ── Citizen Operations ──────────────────────────────────────
async def get_citizen(id_number: str) -> Optional[Dict]:
    """Fetch citizen by ID number."""
    pool = await get_pool()
    async with pool.acquire() as conn:
        row = await conn.fetchrow("""
            SELECT id, id_number, first_name, last_name, date_of_birth,
                   gender, province, phone_number, email,
                   biometric_enrolled, dha_verified, popia_consent,
                   is_active, created_at
            FROM citizens
            WHERE id_number = $1 AND is_active = TRUE
        """, id_number)
        return dict(row) if row else None


async def create_citizen(data: Dict) -> Optional[str]:
    """Create a new citizen record. Returns citizen UUID."""
    pool = await get_pool()
    async with pool.acquire() as conn:
        row = await conn.fetchrow("""
            INSERT INTO citizens
                (id_number, first_name, last_name, date_of_birth,
                 gender, province, phone_number, email, popia_consent, popia_consent_date)
            VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,NOW())
            ON CONFLICT (id_number) DO NOTHING
            RETURNING id
        """,
            data.get("id_number"),
            data.get("first_name"),
            data.get("last_name"),
            data.get("date_of_birth"),
            data.get("gender"),
            data.get("province"),
            data.get("phone_number"),
            data.get("email"),
            data.get("popia_consent", False),
        )
        return str(row["id"]) if row else None


async def update_citizen(id_number: str, updates: Dict) -> bool:
    """Update citizen profile fields."""
    pool = await get_pool()
    async with pool.acquire() as conn:
        result = await conn.execute("""
            UPDATE citizens
            SET first_name   = COALESCE($2, first_name),
                last_name    = COALESCE($3, last_name),
                phone_number = COALESCE($4, phone_number),
                email        = COALESCE($5, email),
                province     = COALESCE($6, province),
                updated_at   = NOW()
            WHERE id_number = $1
        """,
            id_number,
            updates.get("first_name"),
            updates.get("last_name"),
            updates.get("phone_number"),
            updates.get("email"),
            updates.get("province"),
        )
        return result == "UPDATE 1"


# ── Authentication Operations ───────────────────────────────
async def verify_pin(id_number: str, pin: str) -> bool:
    """Verify a citizen's PIN (bcrypt)."""
    pool = await get_pool()
    async with pool.acquire() as conn:
        row = await conn.fetchrow("""
            SELECT pin_hash FROM citizens
            WHERE id_number = $1 AND is_active = TRUE
        """, id_number)
        if not row or not row["pin_hash"]:
            return False
        # Simple SHA256 check (use bcrypt in production)
        pin_hash = hashlib.sha256(pin.encode()).hexdigest()
        return pin_hash == row["pin_hash"]


async def set_pin(id_number: str, pin: str) -> bool:
    """Set or update a citizen's PIN."""
    pin_hash = hashlib.sha256(pin.encode()).hexdigest()
    pool = await get_pool()
    async with pool.acquire() as conn:
        result = await conn.execute("""
            UPDATE citizens SET pin_hash = $2, updated_at = NOW()
            WHERE id_number = $1
        """, id_number, pin_hash)
        return result == "UPDATE 1"


async def log_auth_session(
    id_number: str,
    auth_method: str,
    success: bool,
    ip_address: str = None,
    failure_reason: str = None,
):
    """Log every authentication attempt."""
    pool = await get_pool()
    async with pool.acquire() as conn:
        citizen = await get_citizen(id_number)
        citizen_id = citizen["id"] if citizen else None
        await conn.execute("""
            INSERT INTO auth_sessions
                (citizen_id, id_number, auth_method, ip_address, success, failure_reason)
            VALUES ($1,$2,$3,$4,$5,$6)
        """,
            citizen_id, id_number, auth_method,
            ip_address, success, failure_reason,
        )


# ── QR Token Operations ─────────────────────────────────────
async def create_qr_token(id_number: str) -> str:
    """Generate and store a QR auth token (expires in 5 minutes)."""
    import secrets
    token = secrets.token_urlsafe(32)
    expires_at = datetime.now() + timedelta(minutes=5)
    pool = await get_pool()
    async with pool.acquire() as conn:
        citizen = await get_citizen(id_number)
        if not citizen:
            return None
        await conn.execute("""
            INSERT INTO qr_tokens (citizen_id, id_number, token, expires_at)
            VALUES ($1,$2,$3,$4)
        """, citizen["id"], id_number, token, expires_at)
    return token


async def verify_qr_token(token: str) -> Optional[str]:
    """Verify a QR token and return the ID number if valid."""
    pool = await get_pool()
    async with pool.acquire() as conn:
        row = await conn.fetchrow("""
            SELECT id_number FROM qr_tokens
            WHERE token = $1 AND used = FALSE AND expires_at > NOW()
        """, token)
        if not row:
            return None
        # Mark as used
        await conn.execute("""
            UPDATE qr_tokens SET used = TRUE WHERE token = $1
        """, token)
        return row["id_number"]


# ── Document Operations ─────────────────────────────────────
async def save_signed_document(
    id_number: str,
    document_name: str,
    document_hash: str,
    sign_method: str,
    signature_data: str = None,
) -> Optional[str]:
    """Save a signed document record."""
    pool = await get_pool()
    async with pool.acquire() as conn:
        citizen = await get_citizen(id_number)
        if not citizen:
            return None
        row = await conn.fetchrow("""
            INSERT INTO signed_documents
                (citizen_id, id_number, document_name, document_hash,
                 sign_method, signature_data)
            VALUES ($1,$2,$3,$4,$5,$6)
            RETURNING id
        """,
            citizen["id"], id_number, document_name,
            document_hash, sign_method, signature_data,
        )
        doc_id = str(row["id"])
        await audit("DOCUMENT_SIGNED", citizen["id"], id_number,
                    "signed_documents", doc_id,
                    new_values={"document_name": document_name, "method": sign_method})
        return doc_id


async def get_signed_documents(id_number: str) -> List[Dict]:
    """Get all signed documents for a citizen."""
    pool = await get_pool()
    async with pool.acquire() as conn:
        rows = await conn.fetch("""
            SELECT id, document_name, sign_method, signed_at, is_valid
            FROM signed_documents
            WHERE id_number = $1
            ORDER BY signed_at DESC
        """, id_number)
        return [dict(r) for r in rows]


# ── Grant Operations ─────────────────────────────────────────
async def get_grants(id_number: str) -> List[Dict]:
    """Get all grants for a citizen."""
    pool = await get_pool()
    async with pool.acquire() as conn:
        rows = await conn.fetch("""
            SELECT id, grant_type, amount, status, next_payment, start_date
            FROM grants
            WHERE id_number = $1
            ORDER BY created_at DESC
        """, id_number)
        return [dict(r) for r in rows]


async def get_payment_history(id_number: str) -> List[Dict]:
    """Get payment history for a citizen."""
    pool = await get_pool()
    async with pool.acquire() as conn:
        rows = await conn.fetch("""
            SELECT p.id, p.amount, p.status, p.payment_method,
                   p.reference, p.processed_at, p.created_at,
                   g.grant_type
            FROM payments p
            LEFT JOIN grants g ON p.grant_id = g.id
            WHERE p.id_number = $1
            ORDER BY p.created_at DESC
            LIMIT 50
        """, id_number)
        return [dict(r) for r in rows]


# ── Notification Operations ──────────────────────────────────
async def get_notifications(id_number: str, unread_only: bool = False) -> List[Dict]:
    """Get notifications for a citizen."""
    pool = await get_pool()
    async with pool.acquire() as conn:
        query = """
            SELECT id, title, message, notif_type, is_read, created_at
            FROM notifications
            WHERE id_number = $1
        """
        if unread_only:
            query += " AND is_read = FALSE"
        query += " ORDER BY created_at DESC LIMIT 20"
        rows = await conn.fetch(query, id_number)
        return [dict(r) for r in rows]


async def send_notification(
    id_number: str,
    title: str,
    message: str,
    notif_type: str = "GENERAL",
) -> bool:
    """Create a notification for a citizen."""
    pool = await get_pool()
    async with pool.acquire() as conn:
        citizen = await get_citizen(id_number)
        await conn.execute("""
            INSERT INTO notifications (citizen_id, id_number, title, message, notif_type)
            VALUES ($1,$2,$3,$4,$5)
        """,
            citizen["id"] if citizen else None,
            id_number, title, message, notif_type,
        )
        return True


# ── Health Check ─────────────────────────────────────────────
async def db_health_check() -> Dict:
    """Check database connectivity and return stats."""
    try:
        pool = await get_pool()
        async with pool.acquire() as conn:
            result = await conn.fetchrow("""
                SELECT
                    (SELECT COUNT(*) FROM citizens) as citizens,
                    (SELECT COUNT(*) FROM auth_sessions) as sessions,
                    (SELECT COUNT(*) FROM signed_documents) as documents,
                    (SELECT COUNT(*) FROM grants) as grants,
                    (SELECT COUNT(*) FROM audit_log) as audit_entries,
                    NOW() as db_time
            """)
            return {
                "status": "connected",
                "citizens": result["citizens"],
                "sessions": result["sessions"],
                "documents": result["documents"],
                "grants": result["grants"],
                "audit_entries": result["audit_entries"],
                "db_time": str(result["db_time"]),
            }
    except Exception as e:
        return {"status": "error", "message": str(e)}
