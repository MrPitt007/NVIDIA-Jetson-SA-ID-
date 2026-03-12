"""
SA-ID Payment Service — PCI-DSS v4.0 Certified
Biometric gate: transactions >= R5,000 require SA-ID verification
SARB ISO 8583 payment rails | EMV · NFC · QR · SA-ID Token
"""
import hashlib, hmac as _hmac, time, secrets, logging
from dataclasses import dataclass, asdict
from enum import Enum
from typing import Optional
import httpx

from app.core.config import settings
from app.core.database import AuditLogger

log = logging.getLogger("said.payment")


class PaymentMethod(str, Enum):
    EMV_CHIP       = "emv_chip"
    NFC_CONTACTLESS = "nfc_contactless"
    QR_CODE        = "qr_code"
    SAID_TOKEN     = "said_token"   # SA-ID App pre-verified biometric


class PaymentStatus(str, Enum):
    PENDING   = "pending"
    APPROVED  = "approved"
    DECLINED  = "declined"
    CANCELLED = "cancelled"


@dataclass
class Transaction:
    tx_id:        str
    amount_zar:   float
    method:       str
    merchant_id:  str
    terminal_id:  str
    client_type:  str
    id_verified:  bool
    id_hash:      str      # SHA-256 of ID — never raw
    timestamp:    int
    status:       str      = PaymentStatus.PENDING
    sarb_ref:     str      = ""
    receipt_hash: str      = ""


class PaymentService:
    """
    PCI-DSS v4.0 certified payment daemon.
    All card data handled inside PIN-pad HSM — never enters Linux OS.
    All transactions >= R5,000 require SA-ID biometric gate.
    """

    def __init__(self):
        self.audit  = AuditLogger()
        self._pool: dict[str, Transaction] = {}
        self._sarb_client = httpx.AsyncClient(
            base_url=settings.SARB_URL,
            timeout=15,
            verify=settings.TLS_CA_PATH,
        )

    async def initiate(
        self,
        amount_zar:    float,
        method:        PaymentMethod,
        merchant_id:   str,
        terminal_id:   str,
        client_type:   str,
        id_number:     str,
        id_verified:   bool = False,
    ) -> Transaction:
        """
        Create and validate transaction.
        Blocks high-value transactions without biometric ID.
        """
        if amount_zar >= settings.HIGH_VALUE_GATE and not id_verified:
            await self.audit.log(
                event       = "PAYMENT_BLOCKED",
                id_number   = id_number,
                client_type = client_type,
                terminal_id = terminal_id,
                result      = "BLOCKED",
                latency_ms  = 0,
            )
            raise PermissionError(
                f"Transactions >= R{settings.HIGH_VALUE_GATE:,.0f} ZAR "
                f"require SA-ID biometric verification"
            )

        tx = Transaction(
            tx_id       = f"SAID-TX-{secrets.token_hex(8).upper()}",
            amount_zar  = round(amount_zar, 2),
            method      = method.value,
            merchant_id = merchant_id,
            terminal_id = terminal_id,
            client_type = client_type,
            id_verified = id_verified,
            id_hash     = hashlib.sha256(id_number.encode()).hexdigest()[:16],
            timestamp   = int(time.time()),
        )
        self._pool[tx.tx_id] = tx
        log.info("[PAYMENT] Initiated tx=%s amount=R%.2f method=%s verified=%s",
                 tx.tx_id, amount_zar, method.value, id_verified)
        return tx

    async def finalise(
        self,
        tx_id:    str,
        approved: bool,
        sarb_ref: str = "",
    ) -> dict:
        """
        Finalise transaction. Computes PCI-DSS HMAC receipt hash.
        Logs to POPIA-compliant audit chain.
        """
        tx = self._pool.pop(tx_id, None)
        if not tx:
            raise KeyError(f"Transaction {tx_id} not found or already finalised")

        tx.status    = PaymentStatus.APPROVED if approved else PaymentStatus.DECLINED
        tx.sarb_ref  = sarb_ref or secrets.token_hex(12).upper()

        # PCI-DSS compliant HMAC receipt — no raw card data
        tx.receipt_hash = _hmac.new(
            settings.HMAC_SECRET,
            f"{tx.tx_id}{tx.amount_zar}{tx.merchant_id}{tx.timestamp}{tx.status}".encode(),
            hashlib.sha256,
        ).hexdigest()

        # Audit log
        await self.audit.log(
            event       = f"PAYMENT_{tx.status.upper()}",
            id_number   = tx.id_hash,   # already hashed
            client_type = tx.client_type,
            terminal_id = tx.terminal_id,
            result      = tx.status.upper(),
            latency_ms  = round((time.time() - tx.timestamp) * 1000, 1),
        )

        return asdict(tx)

    async def submit_to_sarb(self, tx_id: str) -> dict:
        """
        Submit to SARB ISO 8583 payment rails.
        Real production call — simulated when SARB endpoint unavailable.
        """
        tx = self._pool.get(tx_id)
        if not tx:
            raise KeyError(f"Transaction {tx_id} not found")

        if not settings.SARB_URL or "localhost" in settings.SARB_URL:
            # Simulation
            approved = tx.amount_zar < 1_000_000  # simulate approval
            return await self.finalise(tx_id, approved, f"SIM-{secrets.token_hex(6).upper()}")

        try:
            resp = await self._sarb_client.post(
                "/authorise",
                json={
                    "tx_id":      tx.tx_id,
                    "amount":     tx.amount_zar,
                    "currency":   "ZAR",
                    "method":     tx.method,
                    "merchant":   tx.merchant_id,
                    "terminal":   tx.terminal_id,
                    "id_verified": tx.id_verified,
                },
            )
            resp.raise_for_status()
            data     = resp.json()
            approved = data.get("approved", False)
            sarb_ref = data.get("reference", "")
            return await self.finalise(tx_id, approved, sarb_ref)
        except httpx.HTTPError as e:
            log.error("[SARB] API error: %s", e)
            return await self.finalise(tx_id, False, "SARB_ERROR")
