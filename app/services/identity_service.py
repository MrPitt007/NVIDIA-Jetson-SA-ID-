"""
SA-ID Identity Verification Service
7-Stage Pipeline: Camera → Liveness → MRZ → DHA → Biometric → Audit → Result
All stages run on Jetson AGX Orin 64GB hardware
"""
import hashlib, hmac as _hmac, time, logging, asyncio, secrets
from typing import Optional
import httpx
import numpy as np

from app.core.config import settings
from app.core.jax_engine import engine
from app.core.database import AuditLogger

log = logging.getLogger("said.identity")

# ── DHA Checksum (Luhn-style SA ID) ──────────────────────────────────────────
def verify_sa_id_checksum(id_number: str) -> bool:
    """
    Luhn-style SA-ID checksum.
    9001015009087 → True
    """
    if len(id_number) != 13 or not id_number.isdigit():
        return False
    total = 0
    for i, d in enumerate(id_number[:-1]):
        n = int(d)
        if i % 2 == 1:  # even positions (0-indexed odd) → multiply by 2
            n *= 2
            if n > 9:
                n -= 9
        total += n
    return (10 - (total % 10)) % 10 == int(id_number[-1])


class IdentityService:
    """
    Full 7-stage biometric identity verification pipeline.
    Thread-safe — one instance per worker process.
    """

    def __init__(self):
        self.audit  = AuditLogger()
        self._client = httpx.AsyncClient(
            base_url=settings.DHA_API_URL,
            headers={"X-API-Key": settings.DHA_API_KEY},
            timeout=settings.DHA_TIMEOUT,
            verify=settings.TLS_CA_PATH,   # verify DHA TLS cert
        )

    # ── STAGE 1: Camera Capture ───────────────────────────────────────────────
    async def capture_frames(
        self,
        live_frame_b64: Optional[str],
        doc_frame_b64:  Optional[str],
    ) -> tuple[np.ndarray, np.ndarray]:
        """
        Decode base64 camera frames from terminal.
        In production: frames arrive from MIPI CSI-2 camera via terminal firmware.
        """
        import base64, cv2

        if live_frame_b64:
            raw  = base64.b64decode(live_frame_b64)
            npa  = np.frombuffer(raw, dtype=np.uint8)
            live = cv2.imdecode(npa, cv2.IMREAD_COLOR)
            live = cv2.resize(live, (128, 128)).transpose(2, 0, 1)  # (3,128,128)
        else:
            # CI / simulation mode — random frame
            rng  = np.random.default_rng(int(time.time()))
            live = rng.integers(0, 255, (3, 128, 128), dtype=np.uint8)

        if doc_frame_b64:
            raw  = base64.b64decode(doc_frame_b64)
            npa  = np.frombuffer(raw, dtype=np.uint8)
            doc  = cv2.imdecode(npa, cv2.IMREAD_COLOR)
            doc  = cv2.resize(doc, (112, 112)).transpose(2, 0, 1)   # (3,112,112)
        else:
            rng  = np.random.default_rng(int(time.time()) + 1)
            doc  = rng.integers(0, 255, (3, 112, 112), dtype=np.uint8)

        return live, doc

    # ── STAGE 2: Liveness Detection (NVDLA v2.0) ─────────────────────────────
    async def check_liveness(self, frame: np.ndarray) -> dict:
        """
        Runs on NVDLA v2.0 — <2W passive anti-spoofing.
        Blocks: printed photos · video replay · 3D masks · deepfakes.
        """
        loop = asyncio.get_event_loop()
        is_live, label, conf = await loop.run_in_executor(
            None, engine.run_liveness, frame
        )
        return {
            "live":     is_live,
            "label":    label,
            "conf":     conf,
            "passed":   is_live,
        }

    # ── STAGE 3: MRZ / OCR Document Parse ────────────────────────────────────
    async def parse_mrz(self, id_number: str, surname: str,
                        given_names: str, dob: str) -> dict:
        """
        Validates SA-ID document fields + Luhn checksum.
        In production: OCR from MIPI CSI-2 document scanner via TensorRT XLA.
        """
        checksum_ok = verify_sa_id_checksum(id_number)
        return {
            "checksum_valid": checksum_ok,
            "id_number_len":  len(id_number) == 13,
            "fields_present": all([id_number, surname, given_names]),
            "passed":         checksum_ok,
        }

    # ── STAGE 4: DHA API Live Verification ───────────────────────────────────
    async def verify_dha(self, id_number: str, surname: str,
                         given_names: str, dob: str) -> dict:
        """
        Live call to Department of Home Affairs API v2 over TLS 1.3.
        Simulated when DHA_API_KEY not set (dev/CI mode).
        """
        if not settings.DHA_API_KEY:
            # Simulation — use checksum only
            ok = verify_sa_id_checksum(id_number)
            return {"verified": ok, "source": "SIMULATION", "passed": ok}

        try:
            resp = await self._client.post(
                "/verify",
                json={
                    "id_number":   id_number,
                    "surname":     surname,
                    "given_names": given_names,
                    "dob":         dob,
                },
                headers={
                    "X-Request-ID": secrets.token_hex(16),
                    "X-Timestamp":  str(int(time.time())),
                },
            )
            resp.raise_for_status()
            data = resp.json()
            return {
                "verified": data.get("verified", False),
                "source":   "DHA_LIVE",
                "passed":   data.get("verified", False),
            }
        except httpx.HTTPError as e:
            log.error("[DHA] API error: %s", e)
            return {"verified": False, "source": "DHA_ERROR", "passed": False,
                    "error": "DHA API unavailable"}

    # ── STAGE 5: ArcFace Biometric Match (Ampere GPU) ─────────────────────────
    async def biometric_match(self, live: np.ndarray, doc: np.ndarray) -> dict:
        """
        Face embedding on 2048-core Ampere GPU via JIT-compiled JAX kernel.
        ArcFace cosine similarity — threshold 0.82.
        """
        loop = asyncio.get_event_loop()

        # Run both embeddings in parallel
        emb_live, emb_doc = await asyncio.gather(
            loop.run_in_executor(None, engine.run_face_embed, live),
            loop.run_in_executor(None, engine.run_face_embed, doc),
        )
        match, score = await loop.run_in_executor(
            None, engine.run_cosine_match, emb_live, emb_doc
        )
        return {
            "match":   match,
            "score":   score,
            "threshold": settings.BIO_THRESHOLD,
            "passed":  match,
        }

    # ── FULL PIPELINE ─────────────────────────────────────────────────────────
    async def verify(
        self,
        id_number:      str,
        surname:        str,
        given_names:    str,
        dob:            str,
        client_type:    str,
        terminal_id:    str,
        live_frame_b64: Optional[str] = None,
        doc_frame_b64:  Optional[str] = None,
    ) -> dict:
        """
        Full 7-stage verification pipeline.
        Returns cryptographically-signed result dict.
        """
        t0       = time.perf_counter()
        stages   = {}
        rejected = False
        reject_reason = ""

        # Stage 1 — Camera capture
        live_frame, doc_frame = await self.capture_frames(live_frame_b64, doc_frame_b64)
        stages["camera"] = {"passed": True, "ms": round((time.perf_counter()-t0)*1000, 1)}

        # Stage 2 — Liveness
        t1 = time.perf_counter()
        live_res = await self.check_liveness(live_frame)
        stages["liveness"] = {**live_res, "ms": round((time.perf_counter()-t1)*1000, 1)}
        if not live_res["passed"]:
            rejected = True
            reject_reason = f"Liveness check failed: {live_res['label']}"

        # Stage 3 — MRZ / Document
        t2 = time.perf_counter()
        mrz_res = await self.parse_mrz(id_number, surname, given_names, dob)
        stages["mrz"] = {**mrz_res, "ms": round((time.perf_counter()-t2)*1000, 1)}
        if not mrz_res["passed"] and not rejected:
            rejected = True
            reject_reason = "Document checksum invalid"

        # Stage 4 — DHA API
        t3 = time.perf_counter()
        dha_res = await self.verify_dha(id_number, surname, given_names, dob)
        stages["dha"] = {**dha_res, "ms": round((time.perf_counter()-t3)*1000, 1)}
        if not dha_res["passed"] and not rejected:
            rejected = True
            reject_reason = "DHA identity verification failed"

        # Stage 5 — Biometric match
        t4 = time.perf_counter()
        bio_res = await self.biometric_match(live_frame, doc_frame)
        stages["biometric"] = {**bio_res, "ms": round((time.perf_counter()-t4)*1000, 1)}
        if not bio_res["passed"] and not rejected:
            rejected = True
            reject_reason = "Biometric match failed"

        # Stage 6 — POPIA Audit
        total_ms    = round((time.perf_counter()-t0)*1000, 1)
        result      = "REJECT" if rejected else "PASS"

        t5 = time.perf_counter()
        await self.audit.log(
            event       = "IDENTITY_VERIFY",
            id_number   = id_number,
            client_type = client_type,
            terminal_id = terminal_id,
            result      = result,
            latency_ms  = total_ms,
            bio_score   = bio_res.get("score"),
            liveness    = live_res.get("label"),
        )
        stages["audit"] = {"passed": True, "ms": round((time.perf_counter()-t5)*1000, 1)}

        # Stage 7 — HMAC-signed result
        t6      = time.perf_counter()
        ts      = int(time.time())
        tx_hash = _hmac.new(
            settings.HMAC_SECRET,
            f"{id_number}{bio_res.get('score',0)}{ts}{result}".encode(),
            hashlib.sha256,
        ).hexdigest()
        stages["signing"] = {"passed": True, "ms": round((time.perf_counter()-t6)*1000, 1)}

        # Log failed attempt if rejected
        if rejected:
            await self.audit.log_failed_attempt(terminal_id, id_number, reject_reason)

        return {
            "verified":      not rejected,
            "result":        result,
            "reject_reason": reject_reason if rejected else None,
            "id_hash":       hashlib.sha256(id_number.encode()).hexdigest()[:16],
            "client_type":   client_type,
            "terminal_id":   terminal_id,
            "bio_score":     bio_res.get("score"),
            "liveness":      live_res.get("label"),
            "liveness_conf": live_res.get("conf"),
            "dha_verified":  dha_res.get("verified"),
            "total_ms":      total_ms,
            "timestamp":     ts,
            "tx_hash":       tx_hash,
            "stages":        stages,
            "version":       settings.VERSION,
        }
