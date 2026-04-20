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
- **Post-quantum mode** — toggle PQ mode to generate ML-KEM-768 keypairs
  (NIST FIPS 203) bound to the circuit topology, with AES-256-GCM symmetric
  encryption and SHAKE-256 circuit binding.
- **PQC sidecar** — a dedicated Docker service running on the
  [Open Quantum Safe](https://openquantumsafe.org/) stack (liboqs) provides
  key encapsulation, encrypt, and decrypt endpoints.

---

## Architecture

```
┌──────────────────────────────────────────────────────┐
│  React + TypeScript + Three.js  (src/)               │
│  ├─ CardGenerator, CardLibrary, CircuitCanvas        │
│  └─ PQ mode toggle → /api/pqc/* proxy               │
├──────────────────────────────────────────────────────┤
│  Flask REST API  (app.py)   :5000                    │
│  ├─ Input validation & sanitization                  │
│  ├─ Circuit analysis (analyze_circuit)               │
│  ├─ Circuit parameter derivation                     │
│  ├─ Safe factory  (create_encryption_from_analysis)  │
│  ├─ CircuitEncryption (AES-256-GCM + scrypt + HKDF) │
│  └─ /api/pqc/* proxy → PQC sidecar                  │
├──────────────────────────────────────────────────────┤
│  PQC Sidecar  (pqc/server.py)   :5001                │
│  ├─ ML-KEM-768 keypair generation (NIST FIPS 203)   │
│  ├─ Key encapsulation / decapsulation (liboqs)       │
│  ├─ Circuit-topology binding via SHAKE-256           │
│  └─ AES-256-GCM authenticated encryption             │
├──────────────────────────────────────────────────────┤
│  Classical cryptography layer                        │
│  ├─ SHA-256 key derivation with circuit matrix       │
│  ├─ Reversible substitution + XOR diffusion + perm.  │
│  └─ AES-256-CBC (via pyca/cryptography)              │
├──────────────────────────────────────────────────────┤
│  Post-quantum cryptography layer                     │
│  ├─ ML-KEM-768 (CRYSTALS-Kyber) key encapsulation   │
│  ├─ SHAKE-256 circuit binding (topology → AES key)   │
│  └─ AES-256-GCM with circuit AAD                     │
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
make test           # run classical unit tests in Docker
make up             # start production server + PQC sidecar (detached)
make dev            # start Flask dev + PQC with hot-reload
make logs           # tail production + PQC logs
make down           # stop everything
make clean          # remove containers, images, volumes

# Post-quantum targets
make pqc-build      # build PQC image only (liboqs, ~3 min first time)
make pqc-up         # start PQC sidecar only on :5001
make pqc-test       # run PQC pytest suite in Docker
make pqc-logs       # tail PQC server logs
make test-all       # run classical + PQC tests
```

`make` auto-creates `.env` from `.env.example` if it doesn't exist.

### Using Docker Compose directly

```bash
docker compose up app pqc --build -d   # production + PQC (gunicorn)
docker compose run --rm test           # classical tests
docker compose run --rm pqc-test       # PQC tests
docker compose up dev --build          # dev server + PQC
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
5. The returned JSON **parameters** (plus HMAC signature) appear below the
   canvas. Feed them into `CircuitEncryption(parameters)` locally; the server
   no longer emits runnable Python source.
6. Use **Clear Stack** to reset.

---

## API Reference

All `/api/` endpoints support optional API-key authentication. Set `API_KEY` in your
environment and pass the key via the `X-API-Key` request header.

Auth model: every mutating endpoint requires EITHER a valid `X-API-Key`
header (server-to-server) OR a Flask session cookie (browser). Browsers call
`POST /api/session` once on page load to obtain the cookie; the API key is
never shipped in the frontend bundle.

| Method | Endpoint                   | Auth     | Rate Limit   | Description                        |
| ------ | -------------------------- | -------- | ------------ | ---------------------------------- |
| POST   | `/api/session`             | none     | 30 req / min | Mint an anonymous browser session  |
| POST   | `/api/generate_encryption` | required | 10 req / min | Generate encryption parameters     |
| GET    | `/api/history`             | required | 60 req / min | Retrieve generation history        |
| GET    | `/api/status`              | none     | 60 req / min | Health-check / version info        |
| POST   | `/api/pqc/keypair`         | required | 10 req / min | Generate ML-KEM-768 keypair        |
| POST   | `/api/pqc/encrypt`         | optional | 10 req / min | PQ encrypt (KEM + AES-256-GCM)     |
| POST   | `/api/pqc/decrypt`         | required | 10 req / min | PQ decrypt (KEM + AES-256-GCM)     |
| GET    | `/api/pqc/status`          | none     | 60 req / min | PQC sidecar health-check           |

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
| `REDIS_URL`          | *(empty)*                                    | Shared Flask-Limiter storage (recommended in prod) |
| `TRUSTED_PROXY_HOPS` | `0`                                          | Number of trusted reverse-proxy hops for ProxyFix  |
| `SCRYPT_N`           | `32768`                                      | scrypt N parameter (CircuitEncryption KDF)         |
| `SESSION_COOKIE_SECURE` | `1`                                       | Set to `0` only for localhost HTTP development     |
| `PQC_ALLOWED_HOSTNAMES` | `pqc,localhost`                           | Explicit SSRF allowlist for the PQC proxy         |

For production behind a reverse proxy, also configure the rate-limiter storage
backend (see [Flask-Limiter docs](https://flask-limiter.readthedocs.io)).

---

## Project Structure

```
fold/
├── app.py                  # Flask backend — API, crypto engine, PQC proxy
├── tests.py                # 8 unit tests for encryption round-trips
├── requirements.txt        # Python dependencies (pinned)
├── package.json            # Node.js dependencies (React, Three.js, TypeScript)
├── tsconfig.json           # TypeScript compiler config
│
├── Dockerfile              # Multi-stage: base → test / production (gunicorn)
├── docker-compose.yml      # Services: app, pqc, test, pqc-test, dev
├── Makefile                # Docker-first task runner (make test, make pqc-test, etc.)
├── .dockerignore           # Keeps Docker context lean
├── .github/
│   └── workflows/
│       └── ci.yml          # GitHub Actions: build + test + smoke-test
│
├── .env.example            # Environment variable template (incl. PQC vars)
├── .gitignore              # Git exclusions (venv, node_modules, .env, build)
├── build.sh                # Full build: npm install + build + pip install
├── setup.sh                # Dependency install only
├── start_dev.sh            # Split dev servers (frontend + backend)
├── setup_test_env.sh       # Create virtualenv and install test deps
├── run_tests.sh            # Run tests inside virtualenv
├── test_circuit.sh         # Run tests with Python 3.11 specifically
│
├── pqc/                    # Post-quantum cryptography sidecar
│   ├── Dockerfile          # OQS base image (liboqs + Python)
│   ├── docker-compose.yml  # Standalone compose (also wired into root)
│   ├── Makefile            # PQC-specific make targets
│   ├── requirements.txt    # PQC Python deps
│   ├── lattice.py          # ML-KEM-768 + SHAKE-256 circuit binding
│   ├── server.py           # Flask REST API for PQ encrypt/decrypt
│   └── tests/
│       └── test_lattice.py # 12 pytest tests for PQ crypto pipeline
│
├── public/
│   └── index.html          # HTML shell for React app
└── src/
    ├── App.tsx             # Root component — stack management, PQ toggle
    ├── index.tsx           # React DOM entry point
    ├── index.css           # Global styles (dark theme)
    ├── types/
    │   └── CircuitTypes.ts # TypeScript interfaces (incl. PQ card types)
    ├── data/
    │   └── defaultCards.ts # Pre-built card library (incl. lattice, hash PQ cards)
    └── components/
        ├── CircuitCanvas.tsx   # Three.js 3D scene with OrbitControls
        ├── CardLibrary.tsx     # Clickable card grid
        └── CardGenerator.tsx   # Form for building custom cards (incl. PQ types)
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
- **No dynamic code execution** — the server does not emit runnable Python
  source; it returns a structured `parameters` object. No `exec()` or `eval()`.
- **Authenticated encryption** — `CircuitEncryption` is AES-256-GCM with a
  per-message random salt (scrypt KDF) and random 96-bit nonce. Circuit
  parameters are bound to each ciphertext via HKDF info AND AES-GCM AAD.
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

### Classical encryption internals

The `CircuitEncryption` class is intentionally a thin wrapper:

1. **Key derivation** — `scrypt(password, salt)` → base key, then
   `HKDF-SHA256(base, info=circuit_params)` → 32-byte AES key. Salt is 16
   random bytes per message.

   *(Previously this class implemented homegrown AES-CBC + hand-rolled
   byte permutations with `SHA-256(password)` as the key; that design was
   removed because it provided no authentication and was vulnerable to
   padding-oracle and offline brute-force attacks.)*
2. **AES-256-GCM** — authenticated encryption using `pyca/cryptography` with a
   random 12-byte nonce per message. Circuit parameters are passed as
   Additional Authenticated Data (AAD), so ciphertexts are cryptographically
   tied to the circuit topology that produced them.
3. **Wire format** — base64 of `FOLD2 || salt(16) || nonce(12) || AES-GCM output`.

Decryption validates the magic prefix, re-derives the key with scrypt+HKDF,
and verifies the GCM tag before returning plaintext. Any tampering anywhere
in the blob (salt, nonce, ciphertext, or AAD) causes decryption to fail.

### Post-quantum encryption internals

The `PostQuantumCircuitEncryption` class (`pqc/lattice.py`) implements a
quantum-resistant pipeline using NIST-standardized algorithms:

1. **Circuit → lattice parameter derivation** — SHAKE-256 hashes the circuit
   topology (card types, colors, gates, connections) to produce a deterministic
   seed, noise vector, and binding vector.
2. **ML-KEM-768 key encapsulation** (NIST FIPS 203 / CRYSTALS-Kyber) —
   generates a public/secret keypair. The sender encapsulates a shared secret
   using the public key; the recipient decapsulates with the secret key.
3. **Circuit binding** — the ML-KEM shared secret is mixed with the
   circuit-specific binding vector and gate modifier via SHAKE-256, producing
   a 32-byte AES key unique to that (circuit, keypair) pair.
4. **AES-256-GCM** — authenticated encryption with the circuit binding vector
   as Additional Authenticated Data (AAD). A random 12-byte nonce is prepended.

Different circuit topologies produce different AES keys even from the same ML-KEM
keypair, and tampering with the topology causes GCM authentication to fail.

---

## License

See repository for license details.
