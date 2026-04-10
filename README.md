# Circuit Card Simulator with Encryption Generator

A web-based simulation system for visualizing stackable circuit cards with matrix
logic and predefined mesh layer interactions. Each unique circuit layout produces a
custom encryption algorithm that wraps AES-256-CBC.

> **WARNING — Educational Use Only**
> The generated encryption algorithms are intended for visualization and conceptual
> exploration. They combine custom circuit-derived transforms with AES-256-CBC, but
> the custom layer has **not** been subjected to formal cryptanalysis. Do **not** use
> the generated algorithms for production encryption.

---

## Table of Contents

1. [Features](#features)
2. [Architecture](#architecture)
3. [Prerequisites](#prerequisites)
4. [Quick Start](#quick-start)
5. [Docker](#docker)
6. [Running Tests](#running-tests)
7. [Using the UI](#using-the-ui)
8. [API Reference](#api-reference)
9. [Configuration](#configuration)
10. [Project Structure](#project-structure)
11. [CI / CD](#ci--cd)
12. [Security](#security)
13. [License](#license)

---

## Features

- **Interactive 3D canvas** — drag-and-drop stackable circuit cards rendered with
  Three.js and orbit controls.
- **Card generator** — build custom cards with configurable node counts, connection
  matrices, mesh interaction points, and logic gates (AND, OR, XOR, NOT, NAND, NOR,
  BUFFER).
- **Card library** — pre-built cards (AND gate, matrix, hybrid, mesh connector) plus
  any cards you create.
- **Encryption algorithm export** — click **FINALIZE** to generate a self-contained
  Python encryption class derived from your circuit layout.
- **Encrypt / decrypt round-trip** — every generated algorithm supports
  `encrypt(plaintext, key)` → `decrypt(ciphertext, key)` backed by AES-256-CBC.

---

## Architecture

```
┌──────────────────────────────────────────────────────┐
│  React + TypeScript + Three.js  (src/)               │
│  └─ CardGenerator, CardLibrary, CircuitCanvas        │
├──────────────────────────────────────────────────────┤
│  Flask REST API  (app.py)                            │
│  ├─ Input validation & sanitization                  │
│  ├─ Circuit analysis (analyze_circuit)               │
│  ├─ Code generation (generate_encryption_algorithm)  │
│  ├─ Safe factory  (create_encryption_from_analysis)  │
│  └─ CircuitEncryption class (encrypt / decrypt)      │
├──────────────────────────────────────────────────────┤
│  Cryptography layer                                  │
│  ├─ SHA-256 key derivation with circuit matrix       │
│  ├─ Reversible substitution + XOR diffusion + perm.  │
│  └─ AES-256-CBC (via pyca/cryptography)              │
└──────────────────────────────────────────────────────┘
```

---

## Prerequisites

| Tool       | Minimum version | Purpose           |
| ---------- | --------------- | ----------------- |
| Node.js    | 18+             | React frontend    |
| npm        | 9+              | JS dependencies   |
| Python     | 3.9+            | Flask backend     |
| pip        | 23+             | Python deps       |
| Docker     | 24+ *(optional)*| Containerized run |

---

## Quick Start

```bash
# 1. Clone
git clone <repo-url> && cd fold

# 2. Environment
cp .env.example .env          # edit as needed

# 3. Install & build
./build.sh                    # installs npm + pip deps, builds React

# 4. Run
python app.py                 # serves UI + API on http://localhost:5000
```

For split dev servers (hot-reload):

```bash
./start_dev.sh                # React on :3000, Flask on :5000
./start_dev.sh frontend       # React only
./start_dev.sh backend        # Flask only
```

---

## Docker

Docker is the **canonical deployment method**. The multi-stage `Dockerfile` provides
three targets (`base`, `test`, `production`), and `docker-compose.yml` wires them up
so the entire team uses the same environment.

### Using Make (recommended)

```bash
make build          # build all images (no cache)
make test           # run unit tests in Docker
make up             # start production server (gunicorn, detached)
make dev            # start Flask dev server with FLASK_DEBUG=1
make logs           # tail production logs
make down           # stop everything
make clean          # remove containers, images, volumes
```

`make` auto-creates `.env` from `.env.example` if it doesn't exist.

### Using Docker Compose directly

```bash
docker compose up app --build -d       # production (gunicorn)
docker compose run --rm test           # tests
docker compose up dev --build          # dev server
docker compose down                    # stop
```

### Using raw Docker

```bash
# Production image
docker build --target production -t fold .
docker run -p 5000:5000 --env-file .env fold

# Test image
docker build --target test -t fold-test .
docker run --rm fold-test
```

### Image details

- **Base** — `python:3.11-slim`, non-root `appuser`, `HEALTHCHECK` on `/api/status`
- **Production** — gunicorn with configurable worker count (`GUNICORN_WORKERS`)
- **Test** — runs `python -m unittest tests -v` and exits
- **Security** — `read_only: true`, `no-new-privileges`, tmpfs for `/tmp`

---

## Running Tests

The test suite (`tests.py`) contains 8 unit tests covering:

- Base class encrypt/decrypt round-trip (text + binary)
- Custom parameter initialization
- Simple and complex circuit algorithm generation
- Key derivation determinism and uniqueness
- Circuit transformation reversibility
- Multi-configuration encrypt/decrypt
- Algorithm isolation (different circuits → different ciphertexts)

```bash
# Via Make + Docker (recommended)
make test

# Via Docker Compose
docker compose run --rm test

# Via virtualenv (local)
python -m venv venv && source venv/bin/activate
pip install -r requirements.txt
python -m unittest tests -v

# Via helper scripts (local)
./setup_test_env.sh && ./run_tests.sh -v
```

---

## Using the UI

1. Open `http://localhost:5000` in your browser.
2. Expand **Create Custom Card** to build a card, or click a pre-built card in the
   **Card Library** to add it to the stack.
3. The 3D canvas updates in real-time as cards are stacked.
4. Click **FINALIZE** to send the stack to `/api/generate_encryption`.
5. The returned Python code appears below the canvas — copy or save it.
6. Use **Clear Stack** to reset.

---

## API Reference

All `/api/` endpoints support optional API-key authentication. Set `API_KEY` in your
environment and pass the key via the `X-API-Key` request header.

| Method | Endpoint                   | Auth     | Rate Limit   | Description                        |
| ------ | -------------------------- | -------- | ------------ | ---------------------------------- |
| POST   | `/api/generate_encryption` | optional | 10 req / min | Generate encryption from cards     |
| GET    | `/api/history`             | optional | 60 req / min | Retrieve generation history        |
| GET    | `/api/status`              | none     | 60 req / min | Health-check / version info        |

### POST `/api/generate_encryption`

**Request body** (JSON):

```json
{
  "cards": [
    {
      "id": "card-1",
      "type": "processor",
      "color": "blue",
      "nodes": [
        { "id": "n1", "x": 0.1, "y": 0.2, "type": "input", "connections": [] }
      ],
      "matrixConnections": [
        { "id": "c1", "active": true, "fromX": 0.1, "fromY": 0.2, "toX": 0.9, "toY": 0.8 }
      ],
      "meshInteractionPoints": [
        { "id": "m1", "x": 0.5, "y": 0.5, "upConnections": [], "downConnections": [] }
      ],
      "logicGates": [
        { "id": "g1", "type": "XOR", "x": 0.5, "y": 0.5 }
      ]
    }
  ]
}
```

**Allowed values**:

- `cards[].type` — `processor`, `memory`, `io`, `custom`, `network`, `logic`,
  `matrix`, `hybrid`, `basic`
- `logicGates[].type` — `AND`, `OR`, `XOR`, `NOT`, `NAND`, `NOR`, `BUFFER`

**Response** (200):

```json
{
  "algorithm": "import base64\nimport hashlib\n...",
  "analysis": {
    "num_cards": 1,
    "num_nodes": 1,
    "num_connections": 1,
    "complexity_score": 11,
    "..."
  }
}
```

**Error responses**: `400` (validation), `401` (auth), `429` (rate limit), `500`
(server error — no internals exposed).

### GET `/api/history`

Returns the most recent generation records (capped at `MAX_HISTORY_RECORDS`).

```json
{
  "records": [
    { "timestamp": 1712345678.9, "cards_count": 2, "complexity": 30, "algorithm_size": 4521 }
  ]
}
```

### GET `/api/status`

```json
{ "status": "online", "version": "1.1.0", "endpoints": ["/api/generate_encryption", "/api/history", "/api/status"] }
```

---

## Configuration

All settings are managed via environment variables. Copy `.env.example` → `.env`.

| Variable             | Default                                      | Description                              |
| -------------------- | -------------------------------------------- | ---------------------------------------- |
| `PORT`               | `5000`                                       | Server listen port                       |
| `FLASK_DEBUG`        | `0`                                          | Enable debug mode (`1` / `0`)            |
| `SECRET_KEY`         | *(auto-generated)*                           | Flask secret key for sessions            |
| `ALLOWED_ORIGINS`    | `http://localhost:3000,http://localhost:5000` | CORS allowed origins (comma-separated)   |
| `API_KEY`            | *(empty — auth disabled)*                    | API key for protected endpoints          |
| `MAX_CARDS`          | `20`                                         | Max cards per request                    |
| `MAX_NODES_PER_CARD` | `16`                                         | Max nodes per card                       |
| `MAX_REQUEST_SIZE`   | `1048576`                                    | Max request body in bytes (1 MB)         |
| `MAX_HISTORY_RECORDS`| `200`                                        | Max generation history entries in memory  |
| `GUNICORN_WORKERS`   | `4`                                          | Gunicorn worker processes (prod only)    |
| `REACT_APP_API_KEY`  | *(empty)*                                    | Frontend sends this as `X-API-Key`       |

For production behind a reverse proxy, also configure the rate-limiter storage
backend (see [Flask-Limiter docs](https://flask-limiter.readthedocs.io)).

---

## Project Structure

```
fold/
├── app.py                  # Flask backend — API, crypto engine, code generation
├── tests.py                # 8 unit tests for encryption round-trips
├── requirements.txt        # Python dependencies (pinned)
├── package.json            # Node.js dependencies (React, Three.js, TypeScript)
├── tsconfig.json           # TypeScript compiler config
│
├── Dockerfile              # Multi-stage: base → test / production (gunicorn)
├── docker-compose.yml      # Services: app (prod), test, dev
├── Makefile                # Docker-first task runner (make test, make up, etc.)
├── .dockerignore           # Keeps Docker context lean
├── .github/
│   └── workflows/
│       └── ci.yml          # GitHub Actions: build + test + smoke-test
│
├── .env.example            # Environment variable template
├── .gitignore              # Git exclusions (venv, node_modules, .env, build)
├── build.sh                # Full build: npm install + build + pip install
├── setup.sh                # Dependency install only
├── start_dev.sh            # Split dev servers (frontend + backend)
├── setup_test_env.sh       # Create virtualenv and install test deps
├── run_tests.sh            # Run tests inside virtualenv
├── test_circuit.sh         # Run tests with Python 3.11 specifically
│
├── public/
│   └── index.html          # HTML shell for React app
└── src/
    ├── App.tsx             # Root component — stack management, API calls
    ├── index.tsx           # React DOM entry point
    ├── index.css           # Global styles (dark theme)
    ├── types/
    │   └── CircuitTypes.ts # TypeScript interfaces (CircuitCard, LogicGate, etc.)
    ├── data/
    │   └── defaultCards.ts # Pre-built card library (AND, matrix, hybrid, mesh)
    └── components/
        ├── CircuitCanvas.tsx   # Three.js 3D scene with OrbitControls
        ├── CardLibrary.tsx     # Clickable card grid
        └── CardGenerator.tsx   # Form for building custom cards
```

---

## CI / CD

GitHub Actions (`.github/workflows/ci.yml`) runs automatically on every push and PR
to `main`.

### Pipeline

```
PR / push → test job ─────────────────────────→ ✅ / ❌
                │
          (main only)
                ↓
         build-and-push job
                ├─ Build production image
                ├─ Smoke-test (API + frontend)
                └─ Push to ghcr.io
```

| Job              | Trigger            | What it does                                          |
| ---------------- | ------------------ | ----------------------------------------------------- |
| `test`           | Every push & PR    | Builds test image, runs 8 unit tests                  |
| `build-and-push` | Push to `main` only| Builds prod image, smoke-tests, pushes to GHCR        |

### Pulling the image

```bash
# Latest from main
docker pull ghcr.io/joegr/fold:latest

# Specific commit
docker pull ghcr.io/joegr/fold:sha-<commit>

# Run it
docker run -p 5000:5000 --env-file .env ghcr.io/joegr/fold:latest
```

### Required setup

No additional secrets needed — `GITHUB_TOKEN` is provided automatically by Actions
and has `packages:write` permission set in the workflow. The image is published to
the repo's GitHub Packages.

---

## Security

### Hardening measures

- **Input validation** — all incoming circuit data is deep-validated: types are
  checked, strings are length-capped, floats reject `Infinity`/`NaN`, and gate types
  are restricted to a 7-value allowlist.
- **No dynamic code execution** — server-side encryption instances use
  `create_encryption_from_analysis()` (safe factory). No `exec()` or `eval()`.
- **Constructor safety** — `CircuitEncryption.__init__` restricts `setattr` to a
  frozen key set and clamps numeric constants to safe upper bounds.
- **Timing-safe auth** — API key comparison uses `hmac.compare_digest()`.
- **CORS** — restricted to explicitly configured origins.
- **Rate limiting** — per-IP via Flask-Limiter (10/min for generation, 60/min
  default). Backed by in-memory store; use Redis for production.
- **Security headers** — `X-Content-Type-Options`, `X-Frame-Options`,
  `X-XSS-Protection`, `Referrer-Policy`, `Content-Security-Policy` on every
  response.
- **Request size limits** — enforced via Flask `MAX_CONTENT_LENGTH`.
- **Bounded history** — `encryption_records` is capped at `MAX_HISTORY_RECORDS` to
  prevent memory exhaustion.
- **Safe error handling** — internal exceptions are logged server-side; clients
  receive only generic messages.
- **Non-root container** — Docker image runs as `appuser` with health check.
- **Strict shell scripts** — all `.sh` files use `set -euo pipefail`.
- **Ciphertext validation** — `decrypt()` rejects inputs shorter than IV + one
  AES block.

### Encryption internals

The `CircuitEncryption` class implements a layered scheme:

1. **Key derivation** — SHA-256 hash of the user key, then multiple rounds of
   circuit-matrix-driven mixing and logic-gate-based byte operations.
2. **Pre-encryption transform** — reversible substitution (add mod 256), XOR
   diffusion, and deterministic byte permutation derived from the connection matrix.
3. **AES-256-CBC** — standard encryption using `pyca/cryptography` with a random
   16-byte IV prepended to the ciphertext.
4. **PKCS7 padding** — ensures block alignment.

Decryption runs the inverse: base64-decode → extract IV → AES-CBC decrypt → reverse
transform → unpad.

---

## License

See repository for license details.
