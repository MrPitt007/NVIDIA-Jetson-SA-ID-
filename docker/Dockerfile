# SA-ID Enterprise Backend — Jetson AGX Orin ARM64
# Base: NVIDIA L4T JetPack 5.1.3 (Ubuntu 20.04 LTS + CUDA 11.4)
FROM nvcr.io/nvidia/l4t-ml:r35.3.1-py3

LABEL maintainer="SA-ID Proprietary Limited"
LABEL version="2.1.0"
LABEL description="SA-ID Biometric Identity Backend — Jetson AGX Orin 64GB"

# ── System dependencies ────────────────────────────────────────────────────
RUN apt-get update && apt-get install -y --no-install-recommends \
    python3.10 python3.10-dev python3.10-venv \
    libssl-dev libffi-dev \
    libsqlcipher-dev \
    build-essential git curl \
    libusb-1.0-0 libnfc-dev \
    && rm -rf /var/lib/apt/lists/*

# ── Python 3.10 as default ─────────────────────────────────────────────────
RUN update-alternatives --install /usr/bin/python3 python3 /usr/bin/python3.10 1
RUN curl -sS https://bootstrap.pypa.io/get-pip.py | python3.10

# ── Non-root user for security ─────────────────────────────────────────────
RUN groupadd -r said && useradd -r -g said -s /bin/bash said
RUN mkdir -p /opt/said /var/log/said && chown -R said:said /opt/said /var/log/said

# ── Python dependencies ────────────────────────────────────────────────────
WORKDIR /opt/said/app
COPY requirements.txt .

RUN pip install --no-cache-dir \
    jax[cuda11_pip] \
    -f https://storage.googleapis.com/jax-releases/jax_cuda_releases.html

RUN pip install --no-cache-dir -r requirements.txt

# ── App source ─────────────────────────────────────────────────────────────
COPY --chown=said:said . .

# ── Security: read-only filesystem where possible ─────────────────────────
RUN chmod -R 550 /opt/said/app

USER said

# ── Health check ───────────────────────────────────────────────────────────
HEALTHCHECK --interval=30s --timeout=10s --start-period=60s --retries=3 \
    CMD curl -kf https://localhost:8443/api/v1/health/ping || exit 1

EXPOSE 8443

CMD ["python3", "-m", "uvicorn", "main:app", \
     "--host", "0.0.0.0", \
     "--port", "8443", \
     "--ssl-keyfile", "/opt/said/certs/server.key", \
     "--ssl-certfile", "/opt/said/certs/server.crt", \
     "--workers", "4", \
     "--log-level", "info"]
