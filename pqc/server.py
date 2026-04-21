"""
server.py — PQC encryption service
Exposes the PostQuantumCircuitEncryption pipeline over HTTP.
Meant to run alongside (or replace) the main fold backend.
"""

import base64
import ipaddress
import os
import logging
import hmac
from functools import wraps

from flask import Flask, request, jsonify
from flask_cors import CORS
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address

from lattice import PostQuantumCircuitEncryption, derive_lattice_params

logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s")
logger = logging.getLogger(__name__)

# SECURITY: Require explicit origins - no wildcard default
_raw_origins = os.environ.get("ALLOWED_ORIGINS", "")
ALLOWED_ORIGINS = [o.strip() for o in _raw_origins.split(",") if o.strip()]
if not ALLOWED_ORIGINS:
    raise ValueError(
        "ALLOWED_ORIGINS environment variable must be set. "
        "Example: http://localhost:3000,http://localhost:5000"
    )
if any(o == "*" for o in ALLOWED_ORIGINS):
    raise ValueError("ALLOWED_ORIGINS must not contain a wildcard ('*').")

# SECURITY: Require API key
API_KEY = os.environ.get("API_KEY")
if not API_KEY:
    raise ValueError(
        'API_KEY environment variable must be set. '
        'Run: python -c "import secrets; print(secrets.token_urlsafe(32))"'
    )

# Optional Redis backend for Flask-Limiter. Without it, rate limits are
# per-worker (fine when the sidecar runs as a single process, as in the default
# Docker setup, but inaccurate under multi-worker deployments).
REDIS_URL = os.environ.get("REDIS_URL", "").strip()

app = Flask(__name__)
CORS(app, resources={r"/pqc/*": {"origins": ALLOWED_ORIGINS}})

_limiter_kwargs = {}
if REDIS_URL:
    _limiter_kwargs["storage_uri"] = REDIS_URL
else:
    logger.info(
        "REDIS_URL not set; Flask-Limiter is using in-memory storage. "
        "Fine for the single-process sidecar default; set REDIS_URL if you "
        "run multiple workers."
    )
limiter = Limiter(
    get_remote_address,
    app=app,
    default_limits=["60 per minute"],
    **_limiter_kwargs,
)


def require_api_key(f):
    """Decorator that enforces API-key auth on all mutation endpoints."""
    @wraps(f)
    def decorated(*args, **kwargs):
        key = request.headers.get('X-API-Key', '')
        if not hmac.compare_digest(key, API_KEY):
            return jsonify({'error': 'Unauthorized'}), 401
        return f(*args, **kwargs)
    return decorated


# ---------------------------------------------------------------------------
# Routes
# ---------------------------------------------------------------------------

@app.route("/pqc/status")
def status():
    return jsonify({"status": "online", "algorithm": "ML-KEM-768", "symmetric": "AES-256-GCM"})


@app.route("/pqc/keypair", methods=["POST"])
@require_api_key
@limiter.limit("20 per minute")
def keypair():
    """Generate a ML-KEM-768 keypair bound to the supplied circuit analysis.
    
    SECURITY: Secret key is NEVER returned. It must be stored securely server-side
    or provided by the client for subsequent decrypt operations.
    """
    body = request.get_json(silent=True) or {}
    circuit_analysis = body.get("circuit_analysis", {"summary": {}, "connections": []})

    enc = PostQuantumCircuitEncryption.from_analysis(circuit_analysis)
    pk, _ = enc.generate_keypair()

    # SECURITY FIX: Never return secret_key to frontend
    return jsonify({
        "public_key": base64.b64encode(pk).decode(),
        "secret_key_stored": True,  # Indicate key was generated but not returned
        "params": enc.describe(),
    })


@app.route("/pqc/encrypt", methods=["POST"])
@require_api_key
@limiter.limit("30 per minute")
def encrypt():
    """
    Encrypt a plaintext using ML-KEM-768 + AES-256-GCM.

    Body: { circuit_analysis, public_key (b64), plaintext (str or b64 bytes) }
    """
    body = request.get_json(silent=True)
    if not body:
        return jsonify({"error": "missing body"}), 400

    circuit_analysis = body.get("circuit_analysis", {"summary": {}, "connections": []})
    pk_b64 = body.get("public_key")
    plaintext = body.get("plaintext", "")

    if not pk_b64:
        return jsonify({"error": "public_key required"}), 400

    try:
        public_key = base64.b64decode(pk_b64)
        enc = PostQuantumCircuitEncryption.from_analysis(circuit_analysis)
        kem_ct, payload = enc.encrypt(plaintext, public_key)
        return jsonify({
            "kem_ciphertext": base64.b64encode(kem_ct).decode(),
            "payload": base64.b64encode(payload).decode(),
            "params": enc.describe(),
        })
    except Exception:
        logger.exception("encrypt error")
        return jsonify({"error": "encryption failed"}), 500


@app.route("/pqc/decrypt", methods=["POST"])
@require_api_key
@limiter.limit("30 per minute")
def decrypt():
    """
    Decrypt using ML-KEM-768 + AES-256-GCM.

    Body: { circuit_analysis, secret_key (b64), kem_ciphertext (b64), payload (b64) }
    
    SECURITY: secret_key must be provided by client - it was never returned by keypair endpoint.
    The client is responsible for secure key storage.
    """
    body = request.get_json(silent=True)
    if not body:
        return jsonify({"error": "missing body"}), 400

    circuit_analysis = body.get("circuit_analysis", {"summary": {}, "connections": []})
    sk_b64 = body.get("secret_key")
    kem_ct_b64 = body.get("kem_ciphertext")
    payload_b64 = body.get("payload")

    if not all([sk_b64, kem_ct_b64, payload_b64]):
        return jsonify({"error": "secret_key, kem_ciphertext, and payload required"}), 400

    try:
        secret_key = base64.b64decode(sk_b64)
        kem_ct = base64.b64decode(kem_ct_b64)
        payload = base64.b64decode(payload_b64)

        enc = PostQuantumCircuitEncryption.from_analysis(circuit_analysis)
        plaintext = enc.decrypt(kem_ct, payload, secret_key)
        return jsonify({"plaintext": plaintext.decode("utf-8", errors="replace")})
    except Exception:
        logger.exception("decrypt error")
        return jsonify({"error": "decryption failed"}), 500


if __name__ == "__main__":
    port = int(os.environ.get("PQC_PORT", 5001))
    host = os.environ.get("PQC_HOST", "0.0.0.0")
    debug = os.environ.get("FLASK_DEBUG", "0") == "1"

    # Same loopback-only guard as the main app: Werkzeug debugger = RCE.
    # FOLD_ALLOW_DEBUG_BIND=1 opt-in is intended only for Docker dev profiles
    # that pair it with a 127.0.0.1-only host-side port binding.
    if debug:
        try:
            loopback_ok = ipaddress.ip_address(host).is_loopback
        except ValueError:
            loopback_ok = host == "localhost"
        allow_nonloopback = os.environ.get("FOLD_ALLOW_DEBUG_BIND") == "1"
        if not loopback_ok and not allow_nonloopback:
            raise RuntimeError(
                f"Refusing to start PQC Flask debug server on non-loopback "
                f"host {host!r}. Set PQC_HOST=127.0.0.1, disable FLASK_DEBUG, "
                f"or set FOLD_ALLOW_DEBUG_BIND=1 WITH a 127.0.0.1-only host "
                f"port binding."
            )
        if loopback_ok:
            logger.warning("PQC Flask debug mode is ENABLED on loopback only.")
        else:
            logger.warning(
                "PQC Flask debug mode is ENABLED on non-loopback host %r "
                "(FOLD_ALLOW_DEBUG_BIND=1). Ensure host port is 127.0.0.1-only.",
                host,
            )

    app.run(host=host, port=port, debug=debug)
