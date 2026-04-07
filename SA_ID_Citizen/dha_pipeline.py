# SA-ID DHA API Pipeline
# Department of Home Affairs - Live Identity Verification
# Works on Windows PC - no Jetson needed
# Connects to real DHA API when credentials are available
# Falls back to simulation mode for testing

import requests
import hashlib
import hmac
import time
import json
import re
from datetime import datetime

# ─── CONFIG ───────────────────────────────────────────────────────────────────

# Replace these with real credentials when you get DHA API access
# Apply at: https://www.dha.gov.za/index.php/civic-services
DHA_CONFIG = {
    "api_key":     "YOUR_DHA_API_KEY_HERE",
    "api_secret":  "YOUR_DHA_API_SECRET_HERE",
    "base_url":    "https://eservices.dha.gov.za/api/v2",
    "timeout":     10,
    "simulation":  True,   # Set False when you have real DHA credentials
}

# ─── LUHN CHECKSUM ────────────────────────────────────────────────────────────

def verify_luhn(id_number: str) -> bool:
    if len(id_number) != 13 or not id_number.isdigit():
        return False
    total = 0
    for i, d in enumerate(id_number[:-1]):
        n = int(d)
        if i % 2 == 1:
            n *= 2
            if n > 9:
                n -= 9
        total += n
    return (10 - (total % 10)) % 10 == int(id_number[-1])

# ─── ID PARSER ────────────────────────────────────────────────────────────────

def parse_id_number(id_number: str) -> dict:
    if not verify_luhn(id_number):
        return {"valid": False, "error": "Luhn checksum failed"}
    yy = id_number[0:2]
    mm = id_number[2:4]
    dd = id_number[4:6]
    gender_digit = int(id_number[6:10])
    citizenship  = id_number[10]
    current_yy   = datetime.now().year % 100
    century      = "19" if int(yy) > current_yy else "20"
    full_year    = century + yy
    try:
        dob = datetime.strptime(f"{full_year}{mm}{dd}", "%Y%m%d")
        age = (datetime.now() - dob).days // 365
    except:
        return {"valid": False, "error": "Invalid date in ID"}
    return {
        "valid":       True,
        "id_number":   id_number,
        "dob":         dob.strftime("%Y-%m-%d"),
        "age":         age,
        "gender":      "MALE" if gender_digit >= 5000 else "FEMALE",
        "citizenship": "SA CITIZEN" if citizenship == "0" else "PERMANENT RESIDENT",
        "id_hash":     hashlib.sha256(id_number.encode()).hexdigest()[:16],
    }

# ─── DHA API CLIENT ───────────────────────────────────────────────────────────

class DHAClient:
    def __init__(self, config: dict):
        self.config = config
        self.session = requests.Session()
        self.session.headers.update({
            "Content-Type":  "application/json",
            "X-API-Key":     config["api_key"],
            "X-Client-ID":   "SA-ID-ENTERPRISE-v2",
        })

    def _sign_request(self, payload: dict) -> str:
        """HMAC-SHA256 request signing for DHA API."""
        body = json.dumps(payload, separators=(',', ':'))
        signature = hmac.new(
            self.config["api_secret"].encode(),
            body.encode(),
            hashlib.sha256
        ).hexdigest()
        return signature

    def verify_identity(self, id_number: str, surname: str,
                        given_names: str, dob: str) -> dict:
        """
        Verify identity against DHA database.
        Returns full verification result.
        """
        t0 = time.perf_counter()

        # First validate locally
        id_info = parse_id_number(id_number)
        if not id_info["valid"]:
            return {
                "verified":     False,
                "result":       "REJECT",
                "reject_reason": id_info["error"],
                "source":       "local_validation",
                "total_ms":     0,
            }

        # Simulation mode (no real DHA credentials yet)
        if self.config["simulation"]:
            return self._simulate_dha_response(id_number, surname,
                                               given_names, dob, id_info, t0)

        # Real DHA API call
        return self._call_dha_api(id_number, surname, given_names, dob, id_info, t0)

    def _call_dha_api(self, id_number, surname, given_names, dob, id_info, t0) -> dict:
        """Real DHA API call."""
        payload = {
            "id_number":   id_number,
            "surname":     surname.upper(),
            "given_names": given_names.upper(),
            "dob":         dob,
            "timestamp":   int(time.time()),
            "request_id":  hashlib.sha256(
                f"{id_number}{time.time()}".encode()
            ).hexdigest()[:16],
        }

        try:
            signature = self._sign_request(payload)
            self.session.headers["X-Signature"] = signature

            response = self.session.post(
                f"{self.config['base_url']}/verify",
                json=payload,
                timeout=self.config["timeout"]
            )
            response.raise_for_status()
            data = response.json()

            total_ms = round((time.perf_counter() - t0) * 1000, 1)

            return {
                "verified":      data.get("verified", False),
                "result":        "PASS" if data.get("verified") else "REJECT",
                "reject_reason": data.get("reason", None),
                "dha_ref":       data.get("reference_number", ""),
                "name_match":    data.get("name_match", False),
                "dob_match":     data.get("dob_match", False),
                "alive":         data.get("alive", True),
                "id_info":       id_info,
                "source":        "dha_live",
                "total_ms":      total_ms,
            }

        except requests.exceptions.Timeout:
            return {"verified": False, "result": "ERROR",
                    "reject_reason": "DHA API timeout", "source": "dha_live"}
        except requests.exceptions.ConnectionError:
            return {"verified": False, "result": "ERROR",
                    "reject_reason": "DHA API unreachable", "source": "dha_live"}
        except Exception as e:
            return {"verified": False, "result": "ERROR",
                    "reject_reason": str(e), "source": "dha_live"}

    def _simulate_dha_response(self, id_number, surname,
                                given_names, dob, id_info, t0) -> dict:
        """
        Simulation mode - mimics real DHA API response.
        Used for development and testing.
        """
        import random
        time.sleep(0.05)  # Simulate network latency

        total_ms = round((time.perf_counter() - t0) * 1000, 1)

        # Simulate realistic DHA checks
        name_match    = len(surname) > 2 and len(given_names) > 2
        dob_match     = id_info["dob"] is not None
        alive_status  = True
        verified      = name_match and dob_match and id_info["valid"]

        return {
            "verified":      verified,
            "result":        "PASS" if verified else "REJECT",
            "reject_reason": None if verified else "Name/DOB mismatch",
            "dha_ref":       f"DHA-SIM-{id_number[:6]}-{int(time.time())}",
            "name_match":    name_match,
            "dob_match":     dob_match,
            "alive":         alive_status,
            "id_info":       id_info,
            "source":        "simulation",
            "total_ms":      total_ms,
            "note":          "SIMULATION MODE - Set simulation=False for live DHA"
        }

    def check_alive_status(self, id_number: str) -> dict:
        """Check if person is registered as alive in DHA."""
        if self.config["simulation"]:
            return {
                "alive":   True,
                "source":  "simulation",
                "dha_ref": f"DHA-ALIVE-{id_number[:6]}"
            }
        try:
            response = self.session.get(
                f"{self.config['base_url']}/alive/{id_number}",
                timeout=self.config["timeout"]
            )
            data = response.json()
            return {"alive": data.get("alive", False), "source": "dha_live"}
        except Exception as e:
            return {"alive": None, "error": str(e), "source": "dha_live"}

    def get_photo(self, id_number: str) -> dict:
        """Retrieve DHA photo for biometric matching."""
        if self.config["simulation"]:
            return {
                "photo_available": True,
                "photo_b64":       None,
                "source":          "simulation",
                "note":            "Real photo returned in production"
            }
        try:
            response = self.session.get(
                f"{self.config['base_url']}/photo/{id_number}",
                timeout=self.config["timeout"]
            )
            data = response.json()
            return {
                "photo_available": data.get("available", False),
                "photo_b64":       data.get("photo", None),
                "source":          "dha_live"
            }
        except Exception as e:
            return {"photo_available": False, "error": str(e)}


# ─── FULL PIPELINE ────────────────────────────────────────────────────────────

def run_dha_verification(id_number: str, surname: str,
                         given_names: str, dob: str = None) -> dict:
    """
    Full DHA verification pipeline.
    Call this from main.py or any other module.
    """
    client = DHAClient(DHA_CONFIG)

    # Auto-extract DOB from ID if not provided
    if not dob:
        id_info = parse_id_number(id_number)
        dob = id_info.get("dob", "")

    result = client.verify_identity(id_number, surname, given_names, dob)
    result["alive"]         = client.check_alive_status(id_number).get("alive")
    result["photo"]         = client.get_photo(id_number)
    result["pipeline"]      = "dha_v2"
    result["timestamp"]     = int(time.time())

    return result


# ─── SELF TEST ────────────────────────────────────────────────────────────────

if __name__ == "__main__":
    print("\n" + "="*55)
    print("  SA-ID DHA PIPELINE - SELF TEST")
    print("="*55)

    # Test 1: Valid citizen
    print("\n[TEST 1] Valid SA citizen")
    r = run_dha_verification(
        id_number="8001015009087",
        surname="DLAMINI",
        given_names="SIPHO BONGANI"
    )
    print(f"  Verified:     {r['verified']}")
    print(f"  Result:       {r['result']}")
    print(f"  Name match:   {r['name_match']}")
    print(f"  DOB match:    {r['dob_match']}")
    print(f"  Alive:        {r['alive']}")
    print(f"  DHA ref:      {r['dha_ref']}")
    print(f"  Source:       {r['source']}")
    print(f"  Total ms:     {r['total_ms']}ms")
    if r.get('note'):
        print(f"  Note:         {r['note']}")

    # Test 2: Invalid ID
    print("\n[TEST 2] Invalid ID number")
    r = run_dha_verification(
        id_number="1234567890123",
        surname="TEST",
        given_names="TEST"
    )
    print(f"  Verified:      {r['verified']}")
    print(f"  Result:        {r['result']}")
    print(f"  Reject reason: {r['reject_reason']}")

    # Test 3: Missing names
    print("\n[TEST 3] Empty names (should fail)")
    r = run_dha_verification(
        id_number="8001015009087",
        surname="",
        given_names=""
    )
    print(f"  Verified:      {r['verified']}")
    print(f"  Result:        {r['result']}")

    print("\n" + "="*55)
    print("  DHA PIPELINE READY")
    print("  Mode: SIMULATION (set simulation=False for live)")
    print("  Next: Connect to SARB ISO 8583 payment rails")
    print("="*55)
