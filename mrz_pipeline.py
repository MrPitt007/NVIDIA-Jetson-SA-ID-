# SA-ID MRZ/OCR Pipeline
# Reads SA-ID card barcode and MRZ zone
# Works on Windows PC - no Jetson needed
# Install: pip install opencv-python pytesseract pillow pyzbar requests

import re
import json
import time
import hashlib
from datetime import datetime

# ─── MRZ PARSER ───────────────────────────────────────────────────────────────

def parse_sa_id_number(id_number: str) -> dict:
    """Extract all info from 13-digit SA-ID number."""
    if len(id_number) != 13 or not id_number.isdigit():
        return {"valid": False, "error": "Must be 13 digits"}

    yy  = id_number[0:2]
    mm  = id_number[2:4]
    dd  = id_number[4:6]
    gender_digit = int(id_number[6:10])
    citizenship  = id_number[10]
    race_digit   = id_number[11]  # legacy, ignored
    checksum     = id_number[12]

    # Determine century
    year = int(yy)
    current_year = datetime.now().year % 100
    century = "19" if year > current_year else "20"
    full_year = century + yy

    # Gender
    gender = "MALE" if gender_digit >= 5000 else "FEMALE"

    # Citizenship
    citizen_status = "SA CITIZEN" if citizenship == "0" else "PERMANENT RESIDENT"

    # Validate date
    try:
        dob = datetime.strptime(f"{full_year}{mm}{dd}", "%Y%m%d")
        age = (datetime.now() - dob).days // 365
        dob_str = dob.strftime("%d %B %Y")
    except:
        return {"valid": False, "error": "Invalid date of birth"}

    # Luhn checksum
    if not verify_luhn(id_number):
        return {"valid": False, "error": "Checksum invalid"}

    return {
        "valid": True,
        "id_number": id_number,
        "date_of_birth": dob_str,
        "age": age,
        "gender": gender,
        "citizenship": citizen_status,
        "id_hash": hashlib.sha256(id_number.encode()).hexdigest()[:16]
    }


def verify_luhn(id_number: str) -> bool:
    """SA-ID Luhn checksum verification."""
    if len(id_number) != 13:
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


# ─── MRZ LINE PARSER ──────────────────────────────────────────────────────────

def parse_mrz_line(mrz: str) -> dict:
    """
    Parse SA-ID MRZ (Machine Readable Zone).
    SA-ID MRZ format (2 lines x 30 chars):
    Line 1: IDZA<surname><<given_names
    Line 2: id_number<check<dob<check<gender<expiry<check<nationality<optional
    """
    lines = [l.strip() for l in mrz.strip().split('\n') if l.strip()]

    if len(lines) < 2:
        return {"valid": False, "error": "MRZ must have 2 lines"}

    result = {"raw_mrz": mrz, "valid": False}

    try:
        line1 = lines[0].ljust(30)
        line2 = lines[1].ljust(30)

        # Line 1: Document type + country + name
        doc_type = line1[0:2].replace('<', ' ').strip()
        country  = line1[2:5].replace('<', ' ').strip()
        names    = line1[5:30]

        # Split surname and given names
        name_parts = names.split('<<')
        surname     = name_parts[0].replace('<', ' ').strip() if len(name_parts) > 0 else ""
        given_names = name_parts[1].replace('<', ' ').strip() if len(name_parts) > 1 else ""

        # Line 2: ID number + dates
        id_number = line2[0:13].replace('<', '')

        # Parse the ID number for full details
        id_info = parse_sa_id_number(id_number)

        result = {
            "valid": True,
            "document_type": doc_type,
            "country": country,
            "surname": surname,
            "given_names": given_names,
            "id_number": id_number,
            "id_valid": id_info.get("valid", False),
            "date_of_birth": id_info.get("date_of_birth", ""),
            "age": id_info.get("age", 0),
            "gender": id_info.get("gender", ""),
            "citizenship": id_info.get("citizenship", ""),
            "id_hash": id_info.get("id_hash", ""),
            "raw_line1": line1,
            "raw_line2": line2,
        }

    except Exception as e:
        result = {"valid": False, "error": str(e)}

    return result


# ─── BARCODE READER ───────────────────────────────────────────────────────────

def read_barcode_from_image(image_path: str) -> dict:
    """
    Read PDF417 barcode from SA-ID card image.
    Requires: pip install pyzbar opencv-python pillow
    """
    try:
        from pyzbar.pyzbar import decode
        from PIL import Image
        import cv2
        import numpy as np

        # Load image
        img = cv2.imread(image_path)
        if img is None:
            return {"valid": False, "error": f"Cannot load image: {image_path}"}

        # Try multiple preprocessing for better barcode detection
        results = []

        # Attempt 1: Original
        decoded = decode(img)
        results.extend(decoded)

        # Attempt 2: Grayscale
        gray = cv2.cvtColor(img, cv2.COLOR_BGR2GRAY)
        decoded = decode(gray)
        results.extend(decoded)

        # Attempt 3: Contrast enhanced
        enhanced = cv2.equalizeHist(gray)
        decoded = decode(enhanced)
        results.extend(decoded)

        if not results:
            return {"valid": False, "error": "No barcode found in image"}

        # Get first valid result
        for r in results:
            data = r.data.decode('utf-8', errors='ignore')
            if data:
                return {
                    "valid": True,
                    "barcode_type": r.type,
                    "raw_data": data,
                    "parsed": parse_barcode_data(data)
                }

        return {"valid": False, "error": "Barcode found but could not decode"}

    except ImportError:
        return {
            "valid": False,
            "error": "pyzbar not installed. Run: pip install pyzbar pillow opencv-python"
        }
    except Exception as e:
        return {"valid": False, "error": str(e)}


def parse_barcode_data(data: str) -> dict:
    """Parse SA-ID PDF417 barcode data."""
    # SA-ID barcode contains delimited fields
    # Try to extract ID number (13 digits)
    id_match = re.search(r'\b(\d{13})\b', data)
    id_number = id_match.group(1) if id_match else ""

    result = {
        "raw": data,
        "id_number": id_number,
    }

    if id_number:
        result.update(parse_sa_id_number(id_number))

    return result


# ─── OCR MRZ READER ───────────────────────────────────────────────────────────

def read_mrz_from_image(image_path: str) -> dict:
    """
    Read MRZ zone from SA-ID card image using OCR.
    Requires: pip install pytesseract pillow opencv-python
    Also needs: Tesseract installed from https://tesseract-ocr.github.io/
    """
    try:
        import pytesseract
        import cv2
        import numpy as np

        # Load image
        img = cv2.imread(image_path)
        if img is None:
            return {"valid": False, "error": f"Cannot load image: {image_path}"}

        h, w = img.shape[:2]

        # MRZ is at the bottom ~20% of the card
        mrz_region = img[int(h * 0.75):h, 0:w]

        # Preprocess for OCR
        gray = cv2.cvtColor(mrz_region, cv2.COLOR_BGR2GRAY)
        _, thresh = cv2.threshold(gray, 0, 255, cv2.THRESH_BINARY + cv2.THRESH_OTSU)

        # OCR with MRZ-optimized settings
        config = '--psm 6 -c tessedit_char_whitelist=ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789<'
        text = pytesseract.image_to_string(thresh, config=config)

        if not text.strip():
            return {"valid": False, "error": "OCR returned no text"}

        return {
            "valid": True,
            "ocr_text": text,
            "parsed": parse_mrz_line(text)
        }

    except ImportError:
        return {
            "valid": False,
            "error": "pytesseract not installed. Run: pip install pytesseract"
        }
    except Exception as e:
        return {"valid": False, "error": str(e)}


# ─── MAIN PIPELINE ────────────────────────────────────────────────────────────

def process_sa_id_card(image_path: str = None, id_number: str = None, mrz_text: str = None) -> dict:
    """
    Main SA-ID processing pipeline.
    Accepts: image file OR raw ID number OR MRZ text
    Returns: full verified identity record
    """
    print("\n" + "="*55)
    print("  SA-ID MRZ/OCR PIPELINE")
    print("="*55)

    result = {
        "timestamp": int(time.time()),
        "pipeline_version": "1.0.0",
        "source": None,
        "identity": None,
        "valid": False,
        "error": None
    }

    # Option 1: Process image
    if image_path:
        print(f"\n[1] Processing image: {image_path}")

        # Try barcode first (faster, more accurate)
        print("    Trying barcode reader...")
        barcode = read_barcode_from_image(image_path)
        if barcode["valid"]:
            print(f"    BARCODE FOUND: {barcode['barcode_type']}")
            result["source"] = "barcode"
            result["identity"] = barcode["parsed"]
            result["valid"] = barcode["parsed"].get("valid", False)
            return result

        # Fall back to OCR MRZ
        print("    Barcode failed, trying OCR MRZ...")
        ocr = read_mrz_from_image(image_path)
        if ocr["valid"]:
            print(f"    MRZ OCR SUCCESS")
            result["source"] = "ocr_mrz"
            result["identity"] = ocr["parsed"]
            result["valid"] = ocr["parsed"].get("valid", False)
            return result

        result["error"] = "Both barcode and OCR failed"
        return result

    # Option 2: Direct ID number
    elif id_number:
        print(f"\n[1] Processing ID number: {id_number}")
        parsed = parse_sa_id_number(id_number)
        result["source"] = "direct_input"
        result["identity"] = parsed
        result["valid"] = parsed["valid"]
        return result

    # Option 3: Raw MRZ text
    elif mrz_text:
        print(f"\n[1] Processing MRZ text")
        parsed = parse_mrz_line(mrz_text)
        result["source"] = "mrz_text"
        result["identity"] = parsed
        result["valid"] = parsed["valid"]
        return result

    else:
        result["error"] = "No input provided"
        return result


# ─── TEST ─────────────────────────────────────────────────────────────────────

if __name__ == "__main__":
    print("\n" + "="*55)
    print("  SA-ID MRZ PIPELINE - SELF TEST")
    print("="*55)

    # Test 1: Direct ID number
    print("\n[TEST 1] Parse ID number directly")
    r = process_sa_id_card(id_number="9001015009087")
    print(f"  Valid: {r['valid']}")
    if r['identity']:
        for k, v in r['identity'].items():
            print(f"  {k}: {v}")

    # Test 2: MRZ text
    print("\n[TEST 2] Parse MRZ text")
    mrz = """IDZA DLAMINI<<SIPHO BONGANI<<<<<<<<<<<
9001015009087<6<900101<1<M<9912315<0<ZAF"""
    r = process_sa_id_card(mrz_text=mrz)
    print(f"  Valid: {r['valid']}")
    if r['identity']:
        for k, v in r['identity'].items():
            if not k.startswith('raw'):
                print(f"  {k}: {v}")

    # Test 3: Invalid ID
    print("\n[TEST 3] Invalid ID number")
    r = process_sa_id_card(id_number="1234567890123")
    print(f"  Valid: {r['valid']}")
    print(f"  Error: {r['identity'].get('error', 'none')}")

    print("\n" + "="*55)
    print("  MRZ PIPELINE READY")
    print("  Next: Connect to DHA API for live verification")
    print("="*55)
