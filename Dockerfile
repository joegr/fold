# ── Stage 1: Build React frontend (Vite) ─────────────────────────
# Vite 7 requires Node >= 20.19 / >= 22.12. We use Node 22 LTS.
FROM node:22-slim AS frontend
WORKDIR /build
COPY package.json package-lock.json ./
RUN npm ci
COPY public/ public/
COPY src/ src/
COPY index.html tsconfig.json tsconfig.node.json vite.config.ts ./
RUN npm run build

# ── Stage 2: Python base ────────────────────────────────────────
FROM python:3.11-slim AS base

# Create non-root user
RUN groupadd -r appuser && useradd -r -g appuser -d /app -s /sbin/nologin appuser

WORKDIR /app

# Install Python dependencies first (layer caching)
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copy application code
COPY app.py tests.py ./

# Copy frontend build from stage 1
COPY --from=frontend /build/build ./build/

# Switch to non-root user
RUN chown -R appuser:appuser /app
USER appuser

EXPOSE 5000

HEALTHCHECK --interval=30s --timeout=5s --retries=3 \
    CMD python -c "import urllib.request; urllib.request.urlopen('http://localhost:5000/api/status')" || exit 1

# ── Test target (used by: docker compose run test) ──────────────
FROM base AS test
CMD ["python", "-m", "unittest", "tests", "-v"]

# ── Production target (default) ─────────────────────────────────
FROM base AS production
# SECURITY FIX Issue #17: Add graceful timeout and tune worker settings
CMD ["sh", "-c", "gunicorn --bind 0.0.0.0:5000 --workers ${GUNICORN_WORKERS:-4} --timeout ${GUNICORN_TIMEOUT:-30} --graceful-timeout ${GUNICORN_GRACEFUL_TIMEOUT:-30} --max-requests 1000 --max-requests-jitter 50 app:app"]
