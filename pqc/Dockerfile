# OQS official image — liboqs + Python 3 pre-built by the Open Quantum Safe project
FROM openquantumsafe/python:latest AS base

WORKDIR /app

COPY requirements.txt .
RUN pip3 install --no-cache-dir -r requirements.txt

COPY --chown=oqs:oqs . .
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
