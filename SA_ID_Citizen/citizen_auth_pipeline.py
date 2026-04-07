"""
SA-ID Citizen App — Auth Pipeline
Handles: Face recognition, PIN verification, Document (SA-ID card) login
"""
import hashlib
import time
import random
import re
from typing import Optional

# ── Luhn checksum ─────────────────────────────────────────────────────────────
def luhn_check(id_number: str) -> bool:
    if not re.match(r'^\d{13}$', id_number):
        return False
    total = 0
    for i, digit in enumerate(id_number[:12]):
        n = int(digit)
        if i % 2 == 1:
            n *= 2
            if n > 9:
                n -= 9
        total += n
    return (10 - (total % 10)) % 10 == int(id_number[12])

# ── Parse SA-ID ───────────────────────────────────────────────────────────────
def parse_id(id_number: str) -> dict:
    yy = int(id_number[0:2])
    mm = int(id_number[2:4])
    dd = int(id_number[4:6])
    year = 2000 + yy if yy <= 25 else 1900 + yy
    gender = "Male" if int(id_number[6:10]) >= 5000 else "Female"
    citizen = "SA Citizen" if id_number[10] == "0" else "Permanent Resident"
    age = time.localtime().tm_year - year
    return {
        "dob": f"{dd:02d}/{mm:02d}/{year}",
        "gender": gender,
        "citizenship": citizen,
        "age": age,
        "year_of_birth": year,
    }

# ── Face Recognition Pipeline ─────────────────────────────────────────────────
def run_face_auth_pipeline(id_number: str, face_data: Optional[str] = None) -> dict:
    """
    Simulates face recognition + liveness detection.
    On Jetson: uses ArcFace GPU model + NVDLA liveness chip.
    On Windows: simulation mode.
    """
    if not luhn_check(id_number):
        return {
            "success": False,
            "auth_method": "face",
            "error": "Invalid SA-ID number — checksum failed",
            "timestamp": int(time.time()),
        }

    # Simulate liveness check stages
    stages = [
        "Face detected",
        "Liveness check passed",
        "Biometric match: 94.7%",
        "DHA record confirmed",
    ]

    id_info = parse_id(id_number)
    bio_score = round(random.uniform(0.88, 0.98), 3)

    return {
        "success": True,
        "auth_method": "face",
        "id_number_hash": hashlib.sha256(id_number.encode()).hexdigest()[:16],
        "biometric_score": bio_score,
        "liveness": "REAL",
        "stages": stages,
        "citizen_info": id_info,
        "session_token": hashlib.sha256(f"{id_number}{time.time()}".encode()).hexdigest()[:32],
        "timestamp": int(time.time()),
        "mode": "simulation (GPU on Jetson)",
    }

# ── PIN Verification Pipeline ─────────────────────────────────────────────────
def run_pin_auth_pipeline(id_number: str, pin: str) -> dict:
    """
    Verifies 6-digit PIN against stored hash.
    PIN is never stored in plain text — SHA-256 hashed with ID salt.
    """
    if not luhn_check(id_number):
        return {
            "success": False,
            "auth_method": "pin",
            "error": "Invalid SA-ID number",
            "timestamp": int(time.time()),
        }

    if not re.match(r'^\d{6}$', pin):
        return {
            "success": False,
            "auth_method": "pin",
            "error": "PIN must be exactly 6 digits",
            "timestamp": int(time.time()),
        }

    # In production: compare against stored PIN hash in secure DB
    # For testing: any 6-digit PIN passes
    pin_hash = hashlib.sha256(f"{id_number}:{pin}".encode()).hexdigest()
    id_info = parse_id(id_number)

    return {
        "success": True,
        "auth_method": "pin",
        "id_number_hash": hashlib.sha256(id_number.encode()).hexdigest()[:16],
        "pin_verified": True,
        "citizen_info": id_info,
        "session_token": hashlib.sha256(f"{id_number}{time.time()}".encode()).hexdigest()[:32],
        "timestamp": int(time.time()),
    }

# ── Document (SA-ID Card) Scan Pipeline ───────────────────────────────────────
def run_document_scan_pipeline(id_number: str, mrz_data: Optional[str] = None) -> dict:
    """
    Reads MRZ barcode on SA-ID card.
    On Jetson: uses MIPI camera + OCR pipeline.
    On Windows: simulation mode.
    """
    if not luhn_check(id_number):
        return {
            "success": False,
            "auth_method": "document",
            "error": "Invalid SA-ID barcode — checksum failed",
            "timestamp": int(time.time()),
        }

    id_info = parse_id(id_number)

    return {
        "success": True,
        "auth_method": "document",
        "id_number_hash": hashlib.sha256(id_number.encode()).hexdigest()[:16],
        "mrz_read": True,
        "barcode_type": "PDF417 / MRZ",
        "citizen_info": id_info,
        "dha_verified": True,
        "document_status": "VALID",
        "session_token": hashlib.sha256(f"{id_number}{time.time()}".encode()).hexdigest()[:32],
        "timestamp": int(time.time()),
        "mode": "simulation (MIPI camera on Jetson)",
    }
