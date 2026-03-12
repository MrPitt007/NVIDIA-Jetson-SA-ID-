#!/bin/bash
# =============================================================================
# SA-ID Enterprise Backend — Full Jetson AGX Orin Deployment Script
# Ubuntu 20.04 LTS | JetPack 5.1.3 | CUDA 11.4
# Run as root on Jetson: sudo bash deploy_jetson.sh
# =============================================================================
set -euo pipefail
SAID_HOME="/opt/said"
LOG="/var/log/said/deploy_$(date +%Y%m%d_%H%M%S).log"
mkdir -p /var/log/said

echo_step() { echo -e "\n\033[1;36m[SA-ID] $1\033[0m" | tee -a "$LOG"; }
echo_ok()   { echo -e "\033[1;32m  ✓ $1\033[0m"       | tee -a "$LOG"; }
echo_warn() { echo -e "\033[1;33m  ⚠ $1\033[0m"       | tee -a "$LOG"; }
echo_fail() { echo -e "\033[1;31m  ✗ $1\033[0m"       | tee -a "$LOG"; exit 1; }

# ── 0. Pre-flight checks ─────────────────────────────────────────────────────
echo_step "0/9  Pre-flight hardware verification"

[[ $(uname -m) == "aarch64" ]] || echo_fail "Must run on Jetson ARM64"
[[ $(id -u) -eq 0 ]]           || echo_fail "Must run as root"

# Verify Jetson model
JETSON_MODEL=$(cat /proc/device-tree/model 2>/dev/null || echo "UNKNOWN")
echo_ok "Hardware: $JETSON_MODEL"

# Verify CUDA
nvcc --version | grep "release 11.4" >/dev/null 2>&1 \
  && echo_ok "CUDA 11.4 confirmed" \
  || echo_warn "CUDA 11.4 not found — check JetPack version"

# Verify NVDLA
ls /dev/nvdla0 /dev/nvdla1 >/dev/null 2>&1 \
  && echo_ok "NVDLA v2.0 devices present (/dev/nvdla0, /dev/nvdla1)" \
  || echo_warn "NVDLA devices not found — check Jetson drivers"

# ── 1. System packages ───────────────────────────────────────────────────────
echo_step "1/9  Installing system packages"
apt-get update -qq
apt-get install -y --no-install-recommends \
  python3.10 python3.10-dev python3.10-venv \
  build-essential libssl-dev libffi-dev \
  libsqlcipher-dev \
  docker-ce docker-compose-plugin \
  nginx openssl \
  ufw fail2ban auditd \
  curl wget git | tee -a "$LOG"
echo_ok "System packages installed"

# ── 2. Python 3.10 venv ──────────────────────────────────────────────────────
echo_step "2/9  Setting up Python 3.10 virtual environment"
python3.10 -m venv "$SAID_HOME/venv"
source "$SAID_HOME/venv/bin/activate"
pip install --upgrade pip wheel | tee -a "$LOG"
echo_ok "Python 3.10 venv ready at $SAID_HOME/venv"

# ── 3. JAX + CUDA 11 ────────────────────────────────────────────────────────
echo_step "3/9  Installing JAX with CUDA 11 (Ampere GPU acceleration)"
pip install jax[cuda11_pip] \
  -f https://storage.googleapis.com/jax-releases/jax_cuda_releases.html \
  | tee -a "$LOG"

python3 -c "
import jax
print(f'  JAX version:  {jax.__version__}')
print(f'  JAX backend:  {jax.default_backend()}')
print(f'  JAX devices:  {jax.devices()}')
" || echo_warn "JAX GPU check failed — may need reboot"
echo_ok "JAX installed"

# ── 4. SA-ID Python dependencies ────────────────────────────────────────────
echo_step "4/9  Installing SA-ID Python dependencies"
pip install -r "$SAID_HOME/app/requirements.txt" | tee -a "$LOG"
echo_ok "Python dependencies installed"

# ── 5. TLS certificates ──────────────────────────────────────────────────────
echo_step "5/9  Generating TLS certificates (replace with CA-signed in production)"
mkdir -p "$SAID_HOME/certs"

# Self-signed for initial setup — replace with proper CA in production
openssl req -x509 -newkey rsa:4096 -keyout "$SAID_HOME/certs/server.key" \
  -out "$SAID_HOME/certs/server.crt" -days 365 -nodes \
  -subj "/C=ZA/ST=Gauteng/L=Johannesburg/O=SA-ID Proprietary/CN=said.local" \
  2>/dev/null

# CA cert (copy server cert for self-signed — replace with real CA)
cp "$SAID_HOME/certs/server.crt" "$SAID_HOME/certs/ca.crt"
chmod 600 "$SAID_HOME/certs/server.key"
chmod 644 "$SAID_HOME/certs/server.crt" "$SAID_HOME/certs/ca.crt"
echo_ok "TLS certificates generated at $SAID_HOME/certs/"
echo_warn "Replace with CA-signed certificates before production use!"

# ── 6. Environment config ────────────────────────────────────────────────────
echo_step "6/9  Creating environment configuration"
mkdir -p "$SAID_HOME/config"

# Generate secrets if not already set
HMAC_SECRET=$(python3 -c "import secrets; print(secrets.token_hex(32))")
DB_KEY=$(python3 -c "import secrets; print(secrets.token_hex(32))")
JWT_SECRET=$(python3 -c "import secrets; print(secrets.token_hex(64))")

cat > "$SAID_HOME/config/.env" << EOF
# SA-ID Enterprise Configuration — CONFIDENTIAL
# Generated: $(date -u +%Y-%m-%dT%H:%M:%SZ)

VERSION=2.1.0
DEBUG=false

# Server
PORT=8443
WORKERS=4

# TLS
TLS_CERT_PATH=$SAID_HOME/certs/server.crt
TLS_KEY_PATH=$SAID_HOME/certs/server.key
TLS_CA_PATH=$SAID_HOME/certs/ca.crt

# Database (SQLCipher AES-256)
DB_PATH=$SAID_HOME/audit/audit.db
DB_KEY=$DB_KEY

# Secrets (load from HSM in production)
HMAC_SECRET=$HMAC_SECRET
JWT_SECRET=$JWT_SECRET

# DHA API (set real credentials)
DHA_API_URL=https://api.dha.gov.za/v2
DHA_API_KEY=YOUR_DHA_API_KEY_HERE

# SARB Payment
SARB_URL=https://payments.sarb.gov.za/iso8583
HIGH_VALUE_GATE=5000.0

# Hardware
NVDLA_DEVICE_0=/dev/nvdla0
NVDLA_DEVICE_1=/dev/nvdla1
CAMERA_CSI_DOC=/dev/video0
CAMERA_CSI_IR=/dev/video1
NFC_DEVICE=/dev/ttyACM0
PCI_HSM_DEVICE=/dev/ttyUSB0

# Biometrics
BIO_THRESHOLD=0.82
LIVENESS_THRESH=0.91

# Rate limiting
RATE_LIMIT_PER_MINUTE=60
LOCKOUT_DURATION=900

# Redis
REDIS_PASSWORD=$(python3 -c "import secrets; print(secrets.token_hex(24))")
EOF

chmod 600 "$SAID_HOME/config/.env"
echo_ok "Environment config created at $SAID_HOME/config/.env"
echo_warn "Set DHA_API_KEY and load HMAC_SECRET/JWT_SECRET from HSM before go-live!"

# ── 7. NVIDIA Container Runtime ──────────────────────────────────────────────
echo_step "7/9  Configuring Docker + NVIDIA Container Runtime"
cat > /etc/docker/daemon.json << 'DOCKER_EOF'
{
  "default-runtime": "nvidia",
  "runtimes": {
    "nvidia": {
      "path": "nvidia-container-runtime",
      "runtimeArgs": []
    }
  },
  "log-driver": "json-file",
  "log-opts": { "max-size": "100m", "max-file": "5" }
}
DOCKER_EOF
systemctl restart docker
echo_ok "Docker NVIDIA runtime configured"

# ── 8. Run tests ─────────────────────────────────────────────────────────────
echo_step "8/9  Running SA-ID test suite"
source "$SAID_HOME/venv/bin/activate"
cd "$SAID_HOME/app"
pytest tests/test_said_full.py -v --tb=short 2>&1 | tee -a "$LOG"
TEST_EXIT=${PIPESTATUS[0]}
if [ $TEST_EXIT -eq 0 ]; then
  echo_ok "All tests passed"
else
  echo_fail "Tests FAILED — do not deploy. See $LOG"
fi

# ── 9. Start services ─────────────────────────────────────────────────────────
echo_step "9/9  Starting SA-ID services"
cd "$SAID_HOME/app/docker"
docker compose up -d 2>&1 | tee -a "$LOG"

# Wait for health check
sleep 10
HEALTH=$(curl -k -s -o /dev/null -w "%{http_code}" https://localhost:8443/api/v1/health/ping)
if [ "$HEALTH" == "200" ]; then
  echo_ok "Health check passed (HTTP $HEALTH)"
else
  echo_warn "Health check returned HTTP $HEALTH — check logs"
fi

# ── Done ─────────────────────────────────────────────────────────────────────
echo ""
echo "============================================================"
echo "  SA-ID Enterprise Backend DEPLOYED"
echo "  API:     https://$(hostname -I | awk '{print $1}'):8443"
echo "  Logs:    $LOG"
echo "  Config:  $SAID_HOME/config/.env"
echo "  Docs:    Set DEBUG=true then visit /api/docs"
echo "============================================================"
