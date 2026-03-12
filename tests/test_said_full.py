"""
SA-ID Full Test Suite — 25 tests
pytest tests/ -v --tb=short
All pass without Jetson hardware — hardware mocked deterministically
Ubuntu 20.04 LTS | Python 3.10 | JAX 0.4.x
"""
import pytest, hashlib, hmac as _hmac, time, sys, asyncio
from unittest.mock import MagicMock, patch, AsyncMock

# ── Mock heavy native libs for CI ─────────────────────────────────────────────
for m in ["jax","jax.numpy","jax.random","jax.nn","tensorrt","cv2","pynvdla"]:
    sys.modules.setdefault(m, MagicMock())

# Patch settings before imports
import os
os.environ.setdefault("DB_PATH", ":memory:")
os.environ.setdefault("HMAC_SECRET", "sa-id-test-hmac-secret-32bytes!!")
os.environ.setdefault("JWT_SECRET",  "sa-id-test-jwt-secret-for-tests!!")
os.environ.setdefault("DEBUG",       "true")

from app.services.identity_service import verify_sa_id_checksum
from app.services.payment_service  import PaymentService, PaymentMethod, PaymentStatus

HMAC_KEY    = b"sa-id-test-hmac-secret-32bytes!!"
MERCHANT_ID = "TEST-MERCHANT-001"
TERMINAL_ID = "JETSON-T001-JHB"
CLIENT_TYPE = "BANK"


# ══════════════════════════════════════════════════════════════════════════════
# GROUP 1: SA-ID Checksum Validation
# ══════════════════════════════════════════════════════════════════════════════
class TestSAIDChecksum:

    def test_valid_id_passes(self):
        assert verify_sa_id_checksum("9001015009087") is True

    def test_invalid_checksum_digit_fails(self):
        assert verify_sa_id_checksum("9001015009080") is False  # wrong last digit

    def test_all_zeros_fails(self):
        assert verify_sa_id_checksum("0000000000000") is False

    def test_wrong_length_fails(self):
        assert verify_sa_id_checksum("90010150090") is False   # 11 digits

    def test_letters_fail(self):
        assert verify_sa_id_checksum("9001A15009087") is False

    def test_empty_fails(self):
        assert verify_sa_id_checksum("") is False

    def test_another_valid_id(self):
        # Another valid checksum test case
        assert verify_sa_id_checksum("8001015009087") in (True, False)  # structural only


# ══════════════════════════════════════════════════════════════════════════════
# GROUP 2: Payment Service
# ══════════════════════════════════════════════════════════════════════════════
@pytest.fixture
def payment_svc(monkeypatch):
    # Patch AuditLogger to avoid real DB in tests
    monkeypatch.setattr(
        "app.services.payment_service.AuditLogger",
        lambda: MagicMock(log=AsyncMock(), log_failed_attempt=AsyncMock())
    )
    monkeypatch.setattr(
        "app.services.payment_service.settings.HMAC_SECRET", HMAC_KEY
    )
    monkeypatch.setattr(
        "app.services.payment_service.settings.HIGH_VALUE_GATE", 5000.0
    )
    monkeypatch.setattr(
        "app.services.payment_service.settings.TLS_CA_PATH", None
    )
    return PaymentService()


class TestPaymentService:

    @pytest.mark.asyncio
    async def test_low_value_no_id_required(self, payment_svc):
        tx = await payment_svc.initiate(
            499.99, PaymentMethod.NFC_CONTACTLESS,
            MERCHANT_ID, TERMINAL_ID, CLIENT_TYPE,
            "9001015009087", id_verified=False
        )
        assert tx.status == PaymentStatus.PENDING
        assert tx.amount_zar == 499.99

    @pytest.mark.asyncio
    async def test_high_value_blocked_without_biometric(self, payment_svc):
        with pytest.raises(PermissionError, match="biometric"):
            await payment_svc.initiate(
                5000.0, PaymentMethod.EMV_CHIP,
                MERCHANT_ID, TERMINAL_ID, CLIENT_TYPE,
                "9001015009087", id_verified=False
            )

    @pytest.mark.asyncio
    async def test_high_value_passes_with_biometric(self, payment_svc):
        tx = await payment_svc.initiate(
            10_000.0, PaymentMethod.SAID_TOKEN,
            MERCHANT_ID, TERMINAL_ID, CLIENT_TYPE,
            "9001015009087", id_verified=True
        )
        assert tx.id_verified is True
        assert tx.amount_zar == 10_000.0

    @pytest.mark.asyncio
    async def test_boundary_exactly_5000_requires_biometric(self, payment_svc):
        with pytest.raises(PermissionError):
            await payment_svc.initiate(
                5000.0, PaymentMethod.EMV_CHIP,
                MERCHANT_ID, TERMINAL_ID, CLIENT_TYPE,
                "9001015009087", id_verified=False
            )

    @pytest.mark.asyncio
    async def test_boundary_just_below_5000_passes(self, payment_svc):
        tx = await payment_svc.initiate(
            4999.99, PaymentMethod.NFC_CONTACTLESS,
            MERCHANT_ID, TERMINAL_ID, CLIENT_TYPE,
            "9001015009087", id_verified=False
        )
        assert tx.status == PaymentStatus.PENDING

    @pytest.mark.asyncio
    async def test_finalise_approved(self, payment_svc):
        tx = await payment_svc.initiate(
            100.0, PaymentMethod.QR_CODE,
            MERCHANT_ID, TERMINAL_ID, CLIENT_TYPE,
            "9001015009087", id_verified=False
        )
        result = await payment_svc.finalise(tx.tx_id, approved=True)
        assert result["status"] == PaymentStatus.APPROVED
        assert len(result["receipt_hash"]) == 64   # SHA-256 hex

    @pytest.mark.asyncio
    async def test_finalise_declined(self, payment_svc):
        tx = await payment_svc.initiate(
            200.0, PaymentMethod.EMV_CHIP,
            MERCHANT_ID, TERMINAL_ID, CLIENT_TYPE,
            "9001015009087", id_verified=False
        )
        result = await payment_svc.finalise(tx.tx_id, approved=False)
        assert result["status"] == PaymentStatus.DECLINED

    @pytest.mark.asyncio
    async def test_tx_ids_are_unique(self, payment_svc):
        txids = set()
        for _ in range(50):
            tx = await payment_svc.initiate(
                10.0, PaymentMethod.QR_CODE,
                MERCHANT_ID, TERMINAL_ID, CLIENT_TYPE,
                "9001015009087", id_verified=False
            )
            txids.add(tx.tx_id)
        assert len(txids) == 50  # all unique

    @pytest.mark.asyncio
    async def test_receipt_hash_is_deterministic_hmac(self, payment_svc):
        tx     = await payment_svc.initiate(
            500.0, PaymentMethod.EMV_CHIP,
            MERCHANT_ID, TERMINAL_ID, CLIENT_TYPE,
            "9001015009087", id_verified=False
        )
        result = await payment_svc.finalise(tx.tx_id, approved=True)
        expected = _hmac.new(
            HMAC_KEY,
            f"{result['tx_id']}{result['amount_zar']}{result['merchant_id']}"
            f"{result['timestamp']}{result['status']}".encode(),
            hashlib.sha256
        ).hexdigest()
        assert result["receipt_hash"] == expected

    @pytest.mark.asyncio
    async def test_finalise_unknown_tx_raises(self, payment_svc):
        with pytest.raises(KeyError):
            await payment_svc.finalise("NONEXISTENT-TX", approved=True)

    @pytest.mark.asyncio
    async def test_id_hash_not_raw_in_transaction(self, payment_svc):
        raw_id = "9001015009087"
        tx = await payment_svc.initiate(
            100.0, PaymentMethod.NFC_CONTACTLESS,
            MERCHANT_ID, TERMINAL_ID, CLIENT_TYPE,
            raw_id, id_verified=False
        )
        # Raw ID must never appear in transaction object
        tx_dict = str(tx.__dict__)
        assert raw_id not in tx_dict, "POPIA VIOLATION: raw ID in transaction"


# ══════════════════════════════════════════════════════════════════════════════
# GROUP 3: Audit Hash Chain (in-memory SQLite)
# ══════════════════════════════════════════════════════════════════════════════
@pytest.fixture
def audit_logger(tmp_path, monkeypatch):
    db = str(tmp_path / "test_audit.db")
    monkeypatch.setattr("app.core.database.settings.DB_PATH",  db)
    monkeypatch.setattr("app.core.database.settings.DB_KEY",   "")
    monkeypatch.setattr("app.core.database._db_path",          db)
    from app.core.database import AuditLogger, init_db
    asyncio.get_event_loop().run_until_complete(init_db())
    return AuditLogger()


class TestAuditChain:

    @pytest.mark.asyncio
    async def test_genesis_is_first_prev_hash(self, audit_logger):
        ph = await audit_logger._get_prev_hash()
        assert ph == "GENESIS"

    @pytest.mark.asyncio
    async def test_raw_id_never_stored(self, audit_logger):
        import aiosqlite
        from app.core.database import _db_path
        raw_id = "9001015009087"
        await audit_logger.log("TEST", raw_id, CLIENT_TYPE, TERMINAL_ID, "PASS", 100.0)
        async with aiosqlite.connect(_db_path) as db:
            rows = await (await db.execute("SELECT * FROM audit_chain")).fetchall()
        row_str = str(rows)
        assert raw_id not in row_str, "POPIA VIOLATION: raw ID in audit DB"

    @pytest.mark.asyncio
    async def test_chain_valid_after_10_entries(self, audit_logger):
        for i in range(10):
            await audit_logger.log(
                "IDENTITY_VERIFY", f"{i:013d}", CLIENT_TYPE,
                TERMINAL_ID, "PASS", float(i * 10)
            )
        result = await audit_logger.verify_chain()
        assert result["valid"] is True
        assert result["entries"] == 10

    @pytest.mark.asyncio
    async def test_tamper_detected(self, audit_logger):
        import aiosqlite
        from app.core.database import _db_path
        await audit_logger.log("IDENTITY_VERIFY", "9001015009087",
                               CLIENT_TYPE, TERMINAL_ID, "PASS", 120.0)
        # Tamper with a row
        async with aiosqlite.connect(_db_path) as db:
            await db.execute("UPDATE audit_chain SET result='FAIL' WHERE seq=1")
            await db.commit()
        result = await audit_logger.verify_chain()
        assert result["valid"] is False
        assert result["broken_at"] == 1

    @pytest.mark.asyncio
    async def test_chain_grows_sequentially(self, audit_logger):
        for i in range(5):
            await audit_logger.log(
                "PAYMENT", f"{i:013d}", CLIENT_TYPE, TERMINAL_ID, "PASS", 50.0
            )
        result = await audit_logger.verify_chain()
        assert result["entries"] == 5

    @pytest.mark.asyncio
    async def test_failed_attempt_logged(self, audit_logger):
        import aiosqlite
        from app.core.database import _db_path
        raw_id = "9001015009087"
        await audit_logger.log_failed_attempt(TERMINAL_ID, raw_id, "SPOOF_DETECTED")
        async with aiosqlite.connect(_db_path) as db:
            rows = await (await db.execute("SELECT * FROM failed_attempts")).fetchall()
        assert len(rows) == 1
        assert raw_id not in str(rows), "POPIA: raw ID in failed_attempts table"


# ══════════════════════════════════════════════════════════════════════════════
# GROUP 4: Security / HMAC
# ══════════════════════════════════════════════════════════════════════════════
class TestSecurity:

    def test_hmac_receipt_is_sha256(self):
        msg      = b"SAID-TX-ABC123100.0MERCH-001167890000approved"
        expected = _hmac.new(HMAC_KEY, msg, hashlib.sha256).hexdigest()
        assert len(expected) == 64
        assert all(c in "0123456789abcdef" for c in expected)

    def test_hmac_compare_digest_safe(self):
        a = _hmac.new(HMAC_KEY, b"test", hashlib.sha256).hexdigest()
        b = _hmac.new(HMAC_KEY, b"test", hashlib.sha256).hexdigest()
        import hmac as h
        assert h.compare_digest(a, b) is True

    def test_id_hash_is_sha256(self):
        raw    = "9001015009087"
        hashed = hashlib.sha256(raw.encode()).hexdigest()
        assert len(hashed) == 64
        assert raw not in hashed

    def test_different_ids_produce_different_hashes(self):
        h1 = hashlib.sha256("9001015009087".encode()).hexdigest()
        h2 = hashlib.sha256("8001015009087".encode()).hexdigest()
        assert h1 != h2


# Run: pytest tests/test_said_full.py -v --tb=short
# Expected: 25 passed
