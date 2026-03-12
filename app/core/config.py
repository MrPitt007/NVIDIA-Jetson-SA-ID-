"""
SA-ID Enterprise Platform — Core Configuration
NVIDIA Jetson AGX Orin 64GB | Ubuntu 20.04 LTS
All secrets loaded from environment — never hardcoded
"""
import os, secrets
from pathlib import Path
from typing import List
from pydantic_settings import BaseSettings


class Settings(BaseSettings):
    # ── Identity ─────────────────────────────────────────────────────────────
    VERSION:            str  = "2.1.0"
    APP_NAME:           str  = "SA-ID Enterprise Platform"
    DEBUG:              bool = False

    # ── Server ───────────────────────────────────────────────────────────────
    HOST:               str  = "0.0.0.0"
    PORT:               int  = 8443
    WORKERS:            int  = 4          # 4 workers across 12-core ARM CPU
    ALLOWED_HOSTS:      List[str] = ["*"]
    CORS_ORIGINS:       List[str] = []    # Set to enterprise client domains only

    # ── TLS / mTLS ───────────────────────────────────────────────────────────
    TLS_CERT_PATH:      str  = "/opt/said/certs/server.crt"
    TLS_KEY_PATH:       str  = "/opt/said/certs/server.key"
    TLS_CA_PATH:        str  = "/opt/said/certs/ca.crt"
    MTLS_ENABLED:       bool = True       # Require client certificates

    # ── Database ─────────────────────────────────────────────────────────────
    DB_PATH:            str  = "/opt/said/audit/audit.db"
    DB_KEY:             str  = ""         # SQLCipher AES-256 key (from env/HSM)

    # ── JWT / Auth ────────────────────────────────────────────────────────────
    JWT_SECRET:         str  = ""         # Loaded from HSM
    JWT_ALGORITHM:      str  = "RS256"    # RSA-256 — not HS256
    JWT_EXPIRE_MINUTES: int  = 30
    API_KEY_HEADER:     str  = "X-SA-ID-API-Key"

    # ── HMAC Request Signing ─────────────────────────────────────────────────
    HMAC_SECRET:        bytes = b""       # Loaded from ARM TrustZone TEE
    HMAC_ALGORITHM:     str  = "sha256"
    TIMESTAMP_TOLERANCE: int = 30         # Reject requests older than 30 seconds

    # ── Biometric Thresholds ─────────────────────────────────────────────────
    BIO_THRESHOLD:      float = 0.82      # ArcFace cosine similarity pass
    LIVENESS_THRESH:    float = 0.91      # NVDLA liveness confidence pass
    MAX_ATTEMPTS:       int   = 3         # Max failed attempts before lockout

    # ── Rate Limiting ────────────────────────────────────────────────────────
    RATE_LIMIT_PER_MINUTE: int = 60       # Per terminal per minute
    LOCKOUT_DURATION:      int = 900      # 15 min lockout after max attempts

    # ── DHA API ──────────────────────────────────────────────────────────────
    DHA_API_URL:        str  = "https://api.dha.gov.za/v2"
    DHA_API_KEY:        str  = ""         # Enterprise credential from DHA
    DHA_TIMEOUT:        int  = 10         # seconds

    # ── SARB Payment ─────────────────────────────────────────────────────────
    SARB_URL:           str  = "https://payments.sarb.gov.za/iso8583"
    HIGH_VALUE_GATE:    float = 5000.0    # ZAR — biometric gate threshold
    PCI_HSM_DEVICE:     str  = "/dev/ttyUSB0"

    # ── Hardware ─────────────────────────────────────────────────────────────
    NVDLA_DEVICE_0:     str  = "/dev/nvdla0"
    NVDLA_DEVICE_1:     str  = "/dev/nvdla1"
    CAMERA_CSI_DOC:     str  = "/dev/video0"  # MIPI CSI-2 document camera
    CAMERA_CSI_IR:      str  = "/dev/video1"  # IR liveness camera
    NFC_DEVICE:         str  = "/dev/ttyACM0"

    # ── Audit / POPIA ────────────────────────────────────────────────────────
    AUDIT_RETENTION_DAYS: int = 2555      # 7 years (FICA requirement)
    POPIA_HASH_ALGO:    str  = "sha256"
    LOG_DIR:            str  = "/var/log/said"

    class Config:
        env_file = "/opt/said/config/.env"
        env_file_encoding = "utf-8"
        case_sensitive = True


settings = Settings()
