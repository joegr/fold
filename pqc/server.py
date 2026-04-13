"""
server.py — PQC encryption service
Exposes the PostQuantumCircuitEncryption pipeline over HTTP.
Meant to run alongside (or replace) the main fold backend.
"""

import base64
import os
import logging

from flask import Flask, request, jsonify
from flask_cors import CORS
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address

from lattice import PostQuantumCircuitEncryption, derive_lattice_params

logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s")
logger = logging.getLogger(__name__)

app = Flask(__name__)
CORS(app, resources={r"/pqc/*": {"origins": os.environ.get("ALLOWED_ORIGINS", "*").split(",")}})
limiter = Limiter(get_remote_address, app=app, default_limits=["60 per minute"])


# ---------------------------------------------------------------------------
# Routes
# ---------------------------------------------------------------------------

@app.route("/pqc/status")
def status():
    return jsonify({"status": "online", "algorithm": "ML-KEM-768", "symmetric": "AES-256-GCM"})


@app.route("/pqc/keypair", methods=["POST"])
@limiter.limit("20 per minute")
def keypair():
    """Generate a ML-KEM-768 keypair bound to the supplied circuit analysis."""
    body = request.get_json(silent=True) or {}
    circuit_analysis = body.get("circuit_analysis", {"summary": {}, "connections": []})

    enc = PostQuantumCircuitEncryption.from_analysis(circuit_analysis)
    pk, sk = enc.generate_keypair()

    return jsonify({
        "public_key": base64.b64encode(pk).decode(),
        "secret_key": base64.b64encode(sk).decode(),
        "params": enc.describe(),
    })


@app.route("/pqc/encrypt", methods=["POST"])
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
@limiter.limit("30 per minute")
def decrypt():
    """
    Decrypt using ML-KEM-768 + AES-256-GCM.

    Body: { circuit_analysis, secret_key (b64), kem_ciphertext (b64), payload (b64) }
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
    app.run(host="0.0.0.0", port=port, debug=os.environ.get("FLASK_DEBUG", "0") == "1")
