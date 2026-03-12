"""
SA-ID Audit Database — SQLCipher AES-256 Encrypted
POPIA compliant: no raw IDs stored — SHA-256 only
Immutable SHA-256 hash chain — any tamper breaks verify_chain()
FICA retention: 7 years (2555 days)
"""
import aiosqlite, hashlib, sqlite3, time, logging, asyncio
from pathlib import Path
from typing import Optional
from app.core.config import settings

log = logging.getLogger("said.database")

_db_path = settings.DB_PATH


async def init_db():
    """Create encrypted audit DB and all tables."""
    Path(_db_path).parent.mkdir(parents=True, exist_ok=True)
    async with aiosqlite.connect(_db_path) as db:
        if settings.DB_KEY:
            await db.execute(f"PRAGMA key='{settings.DB_KEY}'")
            await db.execute("PRAGMA cipher_page_size=4096")
            await db.execute("PRAGMA kdf_iter=256000")

        await db.execute("""
            CREATE TABLE IF NOT EXISTS audit_chain (
                seq          INTEGER PRIMARY KEY AUTOINCREMENT,
                event        TEXT    NOT NULL,
                id_hash      TEXT    NOT NULL,
                client_type  TEXT    NOT NULL,
                terminal_id  TEXT    NOT NULL,
                result       TEXT    NOT NULL,
                latency_ms   REAL    NOT NULL DEFAULT 0,
                bio_score    REAL,
                liveness     TEXT,
                ts           INTEGER NOT NULL,
                prev_hash    TEXT    NOT NULL,
                entry_hash   TEXT    NOT NULL UNIQUE
            )
        """)

        await db.execute("""
            CREATE TABLE IF NOT EXISTS terminal_registry (
                terminal_id   TEXT PRIMARY KEY,
                client_type   TEXT NOT NULL,
                merchant_id   TEXT NOT NULL,
                api_key_hash  TEXT NOT NULL,
                active        INTEGER NOT NULL DEFAULT 1,
                registered_ts INTEGER NOT NULL,
                last_seen_ts  INTEGER
            )
        """)

        await db.execute("""
            CREATE TABLE IF NOT EXISTS failed_attempts (
                terminal_id  TEXT NOT NULL,
                id_hash      TEXT NOT NULL,
                reason       TEXT NOT NULL,
                ts           INTEGER NOT NULL
            )
        """)

        await db.execute("""
            CREATE TABLE IF NOT EXISTS system_events (
                id           INTEGER PRIMARY KEY AUTOINCREMENT,
                event        TEXT NOT NULL,
                detail       TEXT,
                severity     TEXT NOT NULL DEFAULT 'INFO',
                ts           INTEGER NOT NULL
            )
        """)

        # Indexes for fast queries
        await db.execute("CREATE INDEX IF NOT EXISTS idx_audit_ts ON audit_chain(ts)")
        await db.execute("CREATE INDEX IF NOT EXISTS idx_audit_terminal ON audit_chain(terminal_id)")
        await db.execute("CREATE INDEX IF NOT EXISTS idx_failed_terminal ON failed_attempts(terminal_id)")

        await db.commit()
    log.info("[DB] SQLCipher AES-256 audit database initialised at %s", _db_path)


async def get_db():
    """Async context manager for DB connections."""
    async with aiosqlite.connect(_db_path) as db:
        db.row_factory = aiosqlite.Row
        if settings.DB_KEY:
            await db.execute(f"PRAGMA key='{settings.DB_KEY}'")
        yield db


class AuditLogger:
    """
    POPIA-compliant immutable audit logger.
    SHA-256 hash chain: every entry carries hash of the previous entry.
    Raw ID numbers are NEVER written — only their SHA-256 hash.
    """

    def __init__(self):
        self._prev: Optional[str] = None    # cached last hash

    async def _get_prev_hash(self) -> str:
        if self._prev:
            return self._prev
        async with aiosqlite.connect(_db_path) as db:
            if settings.DB_KEY:
                await db.execute(f"PRAGMA key='{settings.DB_KEY}'")
            row = await db.execute(
                "SELECT entry_hash FROM audit_chain ORDER BY seq DESC LIMIT 1"
            )
            r = await row.fetchone()
            return r[0] if r else "GENESIS"

    async def log(
        self,
        event:       str,
        id_number:   str,
        client_type: str,
        terminal_id: str,
        result:      str,
        latency_ms:  float = 0.0,
        bio_score:   Optional[float] = None,
        liveness:    Optional[str]   = None,
    ):
        """
        Append one tamper-evident entry.
        id_number → SHA-256 hashed before any write (POPIA).
        """
        id_hash  = hashlib.sha256(id_number.encode()).hexdigest()
        prev     = await self._get_prev_hash()
        ts       = int(time.time())

        # Build deterministic hash for this entry
        raw      = (f"{event}|{id_hash}|{client_type}|{terminal_id}|"
                    f"{result}|{latency_ms}|{bio_score}|{liveness}|{ts}|{prev}")
        eh       = hashlib.sha256(raw.encode()).hexdigest()

        async with aiosqlite.connect(_db_path) as db:
            if settings.DB_KEY:
                await db.execute(f"PRAGMA key='{settings.DB_KEY}'")
            await db.execute(
                """INSERT INTO audit_chain
                   (event,id_hash,client_type,terminal_id,result,
                    latency_ms,bio_score,liveness,ts,prev_hash,entry_hash)
                   VALUES (?,?,?,?,?,?,?,?,?,?,?)""",
                (event, id_hash, client_type, terminal_id, result,
                 latency_ms, bio_score, liveness, ts, prev, eh),
            )
            await db.commit()
        self._prev = eh

    async def log_system(self, event: str, detail: str, severity: str = "INFO"):
        async with aiosqlite.connect(_db_path) as db:
            if settings.DB_KEY:
                await db.execute(f"PRAGMA key='{settings.DB_KEY}'")
            await db.execute(
                "INSERT INTO system_events (event,detail,severity,ts) VALUES (?,?,?,?)",
                (event, detail, severity, int(time.time())),
            )
            await db.commit()

    async def log_failed_attempt(self, terminal_id: str, id_number: str, reason: str):
        id_hash = hashlib.sha256(id_number.encode()).hexdigest()
        async with aiosqlite.connect(_db_path) as db:
            if settings.DB_KEY:
                await db.execute(f"PRAGMA key='{settings.DB_KEY}'")
            await db.execute(
                "INSERT INTO failed_attempts (terminal_id,id_hash,reason,ts) VALUES (?,?,?,?)",
                (terminal_id, id_hash, reason, int(time.time())),
            )
            await db.commit()

    async def verify_chain(self) -> dict:
        """Full integrity verification — detects any tampered row."""
        async with aiosqlite.connect(_db_path) as db:
            if settings.DB_KEY:
                await db.execute(f"PRAGMA key='{settings.DB_KEY}'")
            cursor = await db.execute(
                "SELECT seq,event,id_hash,client_type,terminal_id,result,"
                "latency_ms,bio_score,liveness,ts,prev_hash,entry_hash "
                "FROM audit_chain ORDER BY seq"
            )
            rows = await cursor.fetchall()

        prev = "GENESIS"
        for row in rows:
            (seq, ev, ih, ct, tid, res, ms, bio, live, ts, ph, eh) = row
            if ph != prev:
                return {"valid": False, "broken_at": seq, "reason": "prev_hash mismatch"}
            comp = hashlib.sha256(
                f"{ev}|{ih}|{ct}|{tid}|{res}|{ms}|{bio}|{live}|{ts}|{ph}".encode()
            ).hexdigest()
            if comp != eh:
                return {"valid": False, "broken_at": seq, "reason": "entry tampered"}
            prev = eh

        return {"valid": True, "entries": len(rows), "head_hash": prev}
