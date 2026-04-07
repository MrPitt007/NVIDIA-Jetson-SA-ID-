"""
SASSA Gateway Pipeline
======================
Phase 1 - Windows Build (API integration, no Jetson needed)

What it does:
- Accepts verified SA ID number from MRZ pipeline
- Connects to SASSA API to check grant eligibility
- Returns grant status, type, and payment details
- Ready to feed into SA-ID Cloud sync pipeline

Author: MrPitt007
Project: NVIDIA-Jetson-SA-ID-
"""

import requests
import json
import logging
from datetime import datetime, timezone
from dataclasses import dataclass, asdict
from typing import Optional
import hashlib
import hmac
import base64
import os

# ── Logging ──────────────────────────────────────────────────────────────────
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s"
)
logger = logging.getLogger("sassa_pipeline")


# ── Data Models ──────────────────────────────────────────────────────────────
@dataclass
class SASSARequest:
    id_number: str                  # SA ID number from MRZ pipeline
    surname: str                    # From MRZ pipeline
    first_names: str                # From MRZ pipeline
    date_of_birth: str              # YYYY-MM-DD
    gender: str                     # M or F
    request_timestamp: str = ""

    def __post_init__(self):
        self.request_timestamp = datetime.now(timezone.utc).isoformat()


@dataclass
class GrantInfo:
    grant_type: str                 # e.g. OLD_AGE, DISABILITY, CHILD_SUPPORT
    grant_status: str               # ACTIVE, SUSPENDED, PENDING, NOT_ELIGIBLE
    monthly_amount: float           # ZAR amount
    payment_date: str               # Next payment date
    payment_method: str             # CASH_SEND, BANK, POST_OFFICE
    bank_account: Optional[str]     # Masked account number if applicable


@dataclass
class SASSAResponse:
    id_number: str
    eligible: bool
    grants: list                    # List of GrantInfo
    verification_status: str        # VERIFIED, FAILED, ERROR
    message: str
    reference_number: str
    timestamp: str = ""

    def __post_init__(self):
        self.timestamp = datetime.now(timezone.utc).isoformat()


# ── SASSA Gateway Client ──────────────────────────────────────────────────────
class SASSAGatewayClient:
    """
    SASSA Gateway API Client
    Connects to SASSA's grant verification and eligibility API.

    Endpoints used:
    - POST /api/v1/grants/eligibility   — check if person is eligible
    - GET  /api/v1/grants/status        — get current grant status
    - GET  /api/v1/grants/payment       — get next payment details
    """

    # ── Sandbox/Production URLs ───────────────────────────────────────────────
    SANDBOX_URL  = "https://sandbox.sassa.gov.za/api/v1"
    PROD_URL     = "https://gateway.sassa.gov.za/api/v1"

    GRANT_TYPES = {
        "OLD_AGE":           "Old Age Grant",
        "DISABILITY":        "Disability Grant",
        "CHILD_SUPPORT":     "Child Support Grant",
        "FOSTER_CARE":       "Foster Care Grant",
        "CARE_DEPENDENCY":   "Care Dependency Grant",
        "WAR_VETERANS":      "War Veterans Grant",
        "GRANT_IN_AID":      "Grant in Aid",
        "SOCIAL_RELIEF":     "Social Relief of Distress",
    }

    def __init__(self, api_key: str, api_secret: str, sandbox: bool = True):
        self.api_key    = api_key
        self.api_secret = api_secret
        self.base_url   = self.SANDBOX_URL if sandbox else self.PROD_URL
        self.sandbox    = sandbox
        self.session    = requests.Session()
        self.session.headers.update({
            "Content-Type":  "application/json",
            "Accept":        "application/json",
            "X-API-Key":     self.api_key,
            "X-Client-ID":   "JETSON-SA-ID-SYSTEM",
        })
        logger.info(f"SASSA Gateway Client initialized ({'SANDBOX' if sandbox else 'PRODUCTION'})")

    # ── HMAC Signature ────────────────────────────────────────────────────────
    def _generate_signature(self, payload: str, timestamp: str) -> str:
        """Generate HMAC-SHA256 signature for request authentication."""
        message = f"{timestamp}:{payload}"
        signature = hmac.new(
            self.api_secret.encode("utf-8"),
            message.encode("utf-8"),
            hashlib.sha256
        ).digest()
        return base64.b64encode(signature).decode("utf-8")

    def _get_auth_headers(self, payload: str) -> dict:
        timestamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
        signature = self._generate_signature(payload, timestamp)
        return {
            "X-Timestamp":  timestamp,
            "X-Signature":  signature,
        }

    # ── Core API Calls ────────────────────────────────────────────────────────
    def check_eligibility(self, request: SASSARequest) -> SASSAResponse:
        """
        Check if a person is eligible for any SASSA grants.
        Calls: POST /api/v1/grants/eligibility
        """
        endpoint = f"{self.base_url}/grants/eligibility"
        payload  = json.dumps(asdict(request))
        headers  = self._get_auth_headers(payload)

        logger.info(f"Checking SASSA eligibility for ID: {request.id_number[:6]}******")

        try:
            response = self.session.post(
                endpoint,
                data=payload,
                headers=headers,
                timeout=30
            )
            response.raise_for_status()
            return self._parse_eligibility_response(request.id_number, response.json())

        except requests.exceptions.ConnectionError:
            logger.warning("SASSA API unreachable — running in simulation mode")
            return self._simulate_response(request)

        except requests.exceptions.Timeout:
            logger.error("SASSA API timeout")
            return SASSAResponse(
                id_number=request.id_number,
                eligible=False,
                grants=[],
                verification_status="ERROR",
                message="SASSA API timeout. Please retry.",
                reference_number="TIMEOUT"
            )

        except requests.exceptions.HTTPError as e:
            logger.error(f"SASSA API HTTP error: {e}")
            return SASSAResponse(
                id_number=request.id_number,
                eligible=False,
                grants=[],
                verification_status="ERROR",
                message=f"API error: {str(e)}",
                reference_number="HTTP_ERROR"
            )

    def get_payment_details(self, id_number: str) -> dict:
        """
        Get next payment date and method for a grant holder.
        Calls: GET /api/v1/grants/payment?id={id_number}
        """
        endpoint = f"{self.base_url}/grants/payment"
        payload  = ""
        headers  = self._get_auth_headers(payload)

        try:
            response = self.session.get(
                endpoint,
                params={"id": id_number},
                headers=headers,
                timeout=30
            )
            response.raise_for_status()
            return response.json()

        except Exception as e:
            logger.warning(f"Payment details unavailable: {e}")
            return {"payment_date": "N/A", "payment_method": "N/A", "amount": 0}

    # ── Response Parser ───────────────────────────────────────────────────────
    def _parse_eligibility_response(self, id_number: str, data: dict) -> SASSAResponse:
        grants = []
        for g in data.get("grants", []):
            grants.append(GrantInfo(
                grant_type     = g.get("type", "UNKNOWN"),
                grant_status   = g.get("status", "UNKNOWN"),
                monthly_amount = float(g.get("amount", 0)),
                payment_date   = g.get("next_payment_date", "N/A"),
                payment_method = g.get("payment_method", "N/A"),
                bank_account   = g.get("masked_account", None),
            ))

        return SASSAResponse(
            id_number           = id_number,
            eligible            = data.get("eligible", False),
            grants              = grants,
            verification_status = data.get("verification_status", "VERIFIED"),
            message             = data.get("message", "OK"),
            reference_number    = data.get("reference_number", "N/A"),
        )

    # ── Simulation Mode (for testing without live API) ────────────────────────
    def _simulate_response(self, request: SASSARequest) -> SASSAResponse:
        """
        Simulates a realistic SASSA response for development/testing.
        Uses ID number to derive age and determine likely grant type.
        """
        logger.info("Running SASSA simulation response")

        # Extract birth year from SA ID (first 6 digits = YYMMDD)
        try:
            yy  = int(request.id_number[0:2])
            birth_year = (1900 + yy) if yy >= 24 else (2000 + yy)
            age = datetime.now().year - birth_year
        except Exception:
            age = 30

        grants = []

        if age >= 60:
            grants.append(GrantInfo(
                grant_type     = "OLD_AGE",
                grant_status   = "ACTIVE",
                monthly_amount = 2090.00,
                payment_date   = "2026-04-01",
                payment_method = "BANK",
                bank_account   = "****5432",
            ))
        elif age >= 18:
            grants.append(GrantInfo(
                grant_type     = "SOCIAL_RELIEF",
                grant_status   = "PENDING",
                monthly_amount = 370.00,
                payment_date   = "2026-04-05",
                payment_method = "CASH_SEND",
                bank_account   = None,
            ))
        else:
            grants.append(GrantInfo(
                grant_type     = "CHILD_SUPPORT",
                grant_status   = "ACTIVE",
                monthly_amount = 530.00,
                payment_date   = "2026-04-03",
                payment_method = "POST_OFFICE",
                bank_account   = None,
            ))

        return SASSAResponse(
            id_number           = request.id_number,
            eligible            = True,
            grants              = grants,
            verification_status = "SIMULATED",
            message             = "Simulation mode — connect live SASSA API for real data",
            reference_number    = f"SIM-{request.id_number[:6]}-{datetime.now().strftime('%H%M%S')}",
        )


# ── Main Pipeline Function ────────────────────────────────────────────────────
def run_sassa_pipeline(mrz_data: dict) -> dict:
    """
    Main entry point — accepts output from MRZ pipeline.

    Args:
        mrz_data: dict from mrz_pipeline.py containing:
                  id_number, surname, first_names, date_of_birth, gender

    Returns:
        dict with full SASSA grant information
    """
    logger.info("=" * 55)
    logger.info("SASSA GATEWAY PIPELINE STARTED")
    logger.info("=" * 55)

    # ── Load credentials from environment ────────────────────────────────────
    api_key    = os.getenv("SASSA_API_KEY",    "sandbox_test_key_001")
    api_secret = os.getenv("SASSA_API_SECRET", "sandbox_test_secret_001")
    sandbox    = os.getenv("SASSA_SANDBOX",    "true").lower() == "true"

    # ── Build request from MRZ data ───────────────────────────────────────────
    request = SASSARequest(
        id_number   = mrz_data.get("id_number", ""),
        surname     = mrz_data.get("surname", ""),
        first_names = mrz_data.get("first_names", ""),
        date_of_birth = mrz_data.get("date_of_birth", ""),
        gender      = mrz_data.get("gender", ""),
    )

    # ── Run eligibility check ─────────────────────────────────────────────────
    client   = SASSAGatewayClient(api_key, api_secret, sandbox=sandbox)
    response = client.check_eligibility(request)

    # ── Format result ─────────────────────────────────────────────────────────
    result = {
        "id_number":           response.id_number,
        "eligible":            response.eligible,
        "verification_status": response.verification_status,
        "reference_number":    response.reference_number,
        "message":             response.message,
        "timestamp":           response.timestamp,
        "grants": [asdict(g) for g in response.grants],
    }

    # ── Log summary ───────────────────────────────────────────────────────────
    logger.info(f"ID:        {response.id_number[:6]}******")
    logger.info(f"Eligible:  {response.eligible}")
    logger.info(f"Status:    {response.verification_status}")
    logger.info(f"Grants:    {len(response.grants)} found")
    for g in response.grants:
        logger.info(f"  → {g.grant_type}: R{g.monthly_amount:.2f}/month ({g.grant_status})")
    logger.info(f"Reference: {response.reference_number}")
    logger.info("SASSA GATEWAY PIPELINE COMPLETE ✅")

    return result


# ── Test / Demo ───────────────────────────────────────────────────────────────
if __name__ == "__main__":
    # Simulate MRZ pipeline output
    mock_mrz_data = {
        "id_number":    "6501015800084",   # Born 1965 → age 61 → Old Age Grant
        "surname":      "DLAMINI",
        "first_names":  "SIPHO WILLIAM",
        "date_of_birth": "1965-01-01",
        "gender":       "M",
    }

    result = run_sassa_pipeline(mock_mrz_data)

    print("\n" + "=" * 55)
    print("SASSA GATEWAY RESULT")
    print("=" * 55)
    print(json.dumps(result, indent=2))
