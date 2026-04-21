# syntax=docker/dockerfile:1.7
#
# Build liboqs + liboqs-python from source, pinned by commit SHA.
#
# Rationale for building from source instead of using openquantumsafe/python:
#   * Upstream image has not been republished since 2023-06-08 and does not
#     ship an arm64 manifest (breaks Apple-Silicon dev).
#   * Building lets us track the live upstream liboqs / liboqs-python
#     security releases by bumping the pinned SHA.
#
# To update the pins:
#   gh api repos/open-quantum-safe/liboqs/releases/latest          --jq .tag_name
#   gh api repos/open-quantum-safe/liboqs-python/releases/latest   --jq .tag_name
#   gh api repos/open-quantum-safe/liboqs/commits/<tag>            --jq .sha
#   gh api repos/open-quantum-safe/liboqs-python/commits/<tag>     --jq .sha
#
# Both projects ship multi-arch support; build works on linux/amd64 and
# linux/arm64 runners (Apple Silicon included).

# ── Stage 1: Builder — compile liboqs + install Python deps ────────────
FROM python:3.12-slim AS builder

# liboqs 0.15.0 (released 2025-11-14). OQS_DIST_BUILD=ON disables
# CPU-specific optimizations for a portable binary.
ARG LIBOQS_COMMIT=97f6b86b1b6d109cfd43cf276ae39c2e776aed80
# liboqs-python 0.12.0 (released 2025-01-16). Pure-Python ctypes wrapper.
ARG LIBOQS_PYTHON_COMMIT=7906e7879a099fa34217035957d977314f99757d

ENV DEBIAN_FRONTEND=noninteractive \
    PIP_NO_CACHE_DIR=1 \
    PIP_DISABLE_PIP_VERSION_CHECK=1

RUN apt-get update \
 && apt-get install --no-install-recommends -y \
        build-essential \
        cmake \
        ninja-build \
        git \
        libssl-dev \
        ca-certificates \
 && rm -rf /var/lib/apt/lists/*

# Build liboqs shared library.
WORKDIR /src
RUN git clone --filter=tree:0 https://github.com/open-quantum-safe/liboqs.git \
 && cd liboqs \
 && git checkout "${LIBOQS_COMMIT}" \
 && cmake -S . -B build -GNinja \
        -DCMAKE_BUILD_TYPE=Release \
        -DCMAKE_INSTALL_PREFIX=/usr/local \
        -DBUILD_SHARED_LIBS=ON \
        -DOQS_BUILD_ONLY_LIB=ON \
        -DOQS_DIST_BUILD=ON \
 && cmake --build build --parallel \
 && cmake --install build \
 && ldconfig

# Install Python dependencies into a relocatable prefix we can copy
# wholesale into the runtime stage.
WORKDIR /app
COPY requirements.txt .
RUN pip install --prefix=/install -r requirements.txt \
 && pip install --prefix=/install \
        "git+https://github.com/open-quantum-safe/liboqs-python@${LIBOQS_PYTHON_COMMIT}"

# ── Stage 2: Runtime base ──────────────────────────────────────────────
FROM python:3.12-slim AS base

ENV DEBIAN_FRONTEND=noninteractive \
    PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    LD_LIBRARY_PATH=/usr/local/lib \
    OQS_INSTALL_PATH=/usr/local

# Runtime dependencies: libssl3 for liboqs's OpenSSL-backed paths.
RUN apt-get update \
 && apt-get install --no-install-recommends -y \
        libssl3 \
        ca-certificates \
 && rm -rf /var/lib/apt/lists/* \
 && groupadd -r oqs \
 && useradd -r -g oqs -d /app -s /sbin/nologin oqs

# Copy liboqs shared library + headers, then Python site-packages.
COPY --from=builder /usr/local/lib/liboqs.so*    /usr/local/lib/
COPY --from=builder /usr/local/include/oqs       /usr/local/include/oqs
COPY --from=builder /install                     /usr/local
RUN ldconfig

WORKDIR /app
COPY --chown=oqs:oqs . .

# Sanity-check: liboqs loads and ML-KEM-768 is enabled. Fails the build
# early if the shared library is missing or the commit pin is incompatible
# with liboqs-python.
RUN python -c "import oqs; assert 'ML-KEM-768' in oqs.get_enabled_kem_mechanisms(), 'ML-KEM-768 missing'; print('liboqs', oqs.oqs_version()); print('liboqs-python', oqs.oqs_python_version())"

USER oqs

# ── Test target ──────────────────────────────────────────────
FROM base AS test
CMD ["python", "-m", "pytest", "tests/", "-v"]

# ── Production target ────────────────────────────────────────
FROM base AS production
EXPOSE 5001

HEALTHCHECK --interval=30s --timeout=5s --retries=3 \
    CMD python -c "import urllib.request; urllib.request.urlopen('http://localhost:5001/pqc/status')" || exit 1

CMD ["python", "server.py"]
