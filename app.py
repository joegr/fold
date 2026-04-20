"""
app.py — fold backend.

Security rewrite:
  * CircuitEncryption is now a thin AES-256-GCM wrapper with a proper KDF
    (scrypt) and circuit parameters used only as authenticated-associated-data
    (AAD) / HKDF domain separator. No homegrown ciphers.
  * /api/generate_encryption returns structured parameters, never Python source.
  * Auth: session-cookie OR X-API-Key. Frontend no longer needs the API key.
  * ProxyFix + optional Redis storage for Flask-Limiter (multi-worker correct).
  * SSRF allowlist uses ipaddress.is_private / is_loopback + explicit names.
  * FLASK_DEBUG=1 is refused unless bound to 127.0.0.1.
"""

from flask import Flask, request, jsonify, send_from_directory, session
from flask_cors import CORS
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
from werkzeug.middleware.proxy_fix import ProxyFix
from functools import wraps
import ipaddress
import json
import math
import os
import logging
import base64
import hashlib
import hmac
import secrets as py_secrets
import time
import urllib.request
import urllib.error
from urllib.parse import urlparse

from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.scrypt import Scrypt
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives import hashes


# ---------------------------------------------------------------------------
# Configuration
# ---------------------------------------------------------------------------
ALLOWED_ORIGINS = [
    o.strip() for o in os.environ.get(
        'ALLOWED_ORIGINS', 'http://localhost:3000,http://localhost:5000'
    ).split(',') if o.strip()
]
if any(o == '*' for o in ALLOWED_ORIGINS):
    raise ValueError("ALLOWED_ORIGINS must not contain a wildcard ('*').")

# API_KEY is still required for server-to-server clients; frontend no longer uses it.
API_KEY = os.environ.get('API_KEY')
if not API_KEY:
    raise ValueError(
        'API_KEY environment variable must be set. '
        'Run: python -c "import secrets; print(secrets.token_urlsafe(32))"'
    )

SECRET_KEY = os.environ.get('SECRET_KEY')
if not SECRET_KEY:
    raise ValueError(
        'SECRET_KEY environment variable must be set. '
        'Run: python -c "import os; print(os.urandom(32).hex())"'
    )

MAX_CARDS = int(os.environ.get('MAX_CARDS', '20'))
MAX_NODES_PER_CARD = int(os.environ.get('MAX_NODES_PER_CARD', '16'))
MAX_REQUEST_SIZE = int(os.environ.get('MAX_REQUEST_SIZE', str(1 * 1024 * 1024)))  # 1 MB
MAX_HISTORY_RECORDS = int(os.environ.get('MAX_HISTORY_RECORDS', '200'))
MAX_HISTORY_USERS = int(os.environ.get('MAX_HISTORY_USERS', '1000'))
PQC_SERVICE_URL = os.environ.get('PQC_SERVICE_URL', 'http://localhost:5001')

# Reverse-proxy / limiter configuration
TRUSTED_PROXY_HOPS = int(os.environ.get('TRUSTED_PROXY_HOPS', '0'))
REDIS_URL = os.environ.get('REDIS_URL', '').strip()

# Explicit internal service-name allowlist for SSRF protection.
_INTERNAL_SERVICE_NAMES = frozenset(
    n.strip() for n in os.environ.get(
        'PQC_ALLOWED_HOSTNAMES', 'pqc,localhost'
    ).split(',') if n.strip()
)


def _validate_pqc_url(url: str) -> str:
    """Validate PQC service URL to prevent SSRF.

    Accepts:
      * Explicit allowlisted service names (PQC_ALLOWED_HOSTNAMES env).
      * IP addresses in RFC1918 / loopback / link-local ranges (IPv4+IPv6).
      * *.local DNS names (mDNS).
    Rejects everything else, including bareword hostnames not on the allowlist
    and public IPs in unusual encodings (decimal/octal/hex int-as-host).
    """
    parsed = urlparse(url)
    if parsed.scheme not in ('http', 'https'):
        raise ValueError(f'Invalid PQC_SERVICE_URL scheme: {parsed.scheme!r}')
    hostname = parsed.hostname
    if not hostname:
        raise ValueError('Invalid PQC_SERVICE_URL: no hostname')

    # Explicit allowlist of internal service names.
    if hostname in _INTERNAL_SERVICE_NAMES:
        return url
    if hostname.endswith('.local'):
        return url

    # IP literal? Parse strictly via `ipaddress`.
    try:
        ip = ipaddress.ip_address(hostname)
    except ValueError:
        raise ValueError(
            f'PQC_SERVICE_URL hostname {hostname!r} is not in the allowlist '
            f'({sorted(_INTERNAL_SERVICE_NAMES)}) and is not an IP address.'
        )

    if not (ip.is_loopback or ip.is_private or ip.is_link_local):
        raise ValueError(
            f'PQC_SERVICE_URL IP {ip} is not loopback/private/link-local.'
        )
    return url


# Validate PQC URL on startup
PQC_SERVICE_URL = _validate_pqc_url(PQC_SERVICE_URL)


logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s [%(levelname)s] %(name)s: %(message)s',
)
logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# App init
# ---------------------------------------------------------------------------
app = Flask(__name__, static_folder='build')
app.config['MAX_CONTENT_LENGTH'] = MAX_REQUEST_SIZE
app.config['SECRET_KEY'] = SECRET_KEY
# Cookie hardening. SESSION_COOKIE_SECURE defaults to True; set to "0" to
# disable explicitly when developing over plain HTTP on localhost.
app.config['SESSION_COOKIE_HTTPONLY'] = True
app.config['SESSION_COOKIE_SAMESITE'] = 'Strict'
app.config['SESSION_COOKIE_SECURE'] = os.environ.get('SESSION_COOKIE_SECURE', '1') == '1'

# ProxyFix: only trust TRUSTED_PROXY_HOPS hops. 0 means "not behind a proxy".
if TRUSTED_PROXY_HOPS > 0:
    app.wsgi_app = ProxyFix(
        app.wsgi_app,
        x_for=TRUSTED_PROXY_HOPS,
        x_proto=TRUSTED_PROXY_HOPS,
        x_host=TRUSTED_PROXY_HOPS,
    )

CORS(
    app,
    resources={r"/api/*": {"origins": ALLOWED_ORIGINS}},
    supports_credentials=True,  # needed for session cookie
)

# Limiter backend. Redis is strongly recommended in multi-worker deployments;
# without it, each worker keeps its own in-memory counter.
_limiter_kwargs = {}
if REDIS_URL:
    _limiter_kwargs['storage_uri'] = REDIS_URL
else:
    logger.warning(
        'REDIS_URL not set; Flask-Limiter is using in-memory storage. '
        'Rate limits are per-worker and will be inaccurate under gunicorn '
        'with multiple workers.'
    )

limiter = Limiter(
    get_remote_address,
    app=app,
    default_limits=["60 per minute"],
    **_limiter_kwargs,
)

# Per-user history storage. Keyed by a server-minted session id when available,
# falling back to a per-IP hash. The previous "per-user" claim that was really
# per-IP is now enforced by the session cookie path.
encryption_records_by_user: "dict[str, list[dict]]" = {}

ALLOWED_GATE_TYPES = frozenset({'AND', 'OR', 'XOR', 'NOT', 'NAND', 'NOR', 'BUFFER'})
ALLOWED_CARD_TYPES = frozenset({
    'processor', 'memory', 'io', 'custom', 'network',
    'logic', 'matrix', 'hybrid', 'basic',
    'lattice', 'code_based', 'hash_based',
})


# ---------------------------------------------------------------------------
# Signing key — derived via HKDF from SECRET_KEY, never the API_KEY.
# ---------------------------------------------------------------------------
def _derive_signing_key() -> bytes:
    return HKDF(
        algorithm=hashes.SHA256(),
        length=32,
        salt=b'fold-signing-v1',
        info=b'algorithm-integrity-signature',
    ).derive(SECRET_KEY.encode() if isinstance(SECRET_KEY, str) else SECRET_KEY)


_SIGNING_KEY = _derive_signing_key()


def _sign(payload: bytes) -> str:
    return hmac.new(_SIGNING_KEY, payload, hashlib.sha256).hexdigest()


# ---------------------------------------------------------------------------
# Security helpers — auth
# ---------------------------------------------------------------------------
def _has_valid_api_key() -> bool:
    key = request.headers.get('X-API-Key', '')
    if not key:
        return False
    return hmac.compare_digest(key, API_KEY)


def _has_valid_session() -> bool:
    return bool(session.get('sid'))


def require_auth(f):
    """Accept either a signed Flask session cookie or a valid X-API-Key header."""
    @wraps(f)
    def decorated(*args, **kwargs):
        if _has_valid_session() or _has_valid_api_key():
            return f(*args, **kwargs)
        return jsonify({'error': 'Unauthorized'}), 401
    return decorated


def require_api_key(f):
    """Stricter auth for server-to-server endpoints only."""
    @wraps(f)
    def decorated(*args, **kwargs):
        if _has_valid_api_key():
            return f(*args, **kwargs)
        return jsonify({'error': 'Unauthorized'}), 401
    return decorated


def _get_user_id() -> str:
    """Stable per-caller identifier.

    Preference order:
      1. Session id (set by /api/session; unique per browser).
      2. API-key callers collapse to a single namespace 'apikey'.
      3. Anonymous callers fall back to a hashed remote address.
    """
    sid = session.get('sid')
    if sid:
        return f'sess:{sid}'
    if _has_valid_api_key():
        return 'apikey'
    ip = get_remote_address() or '0.0.0.0'
    return 'ip:' + hashlib.sha256(ip.encode()).hexdigest()[:24]


# ---------------------------------------------------------------------------
# Input validation
# ---------------------------------------------------------------------------
def _safe_float(val, default=0.0):
    """Convert to float, rejecting inf/nan and non-numeric values."""
    try:
        f = float(val)
    except (TypeError, ValueError):
        return default
    if not math.isfinite(f):
        return default
    return f


def validate_circuit_data(data):
    """Validate and sanitize incoming circuit data. Returns (cleaned, error)."""
    if not isinstance(data, dict):
        return None, 'Request body must be a JSON object'
    cards = data.get('cards')
    if not isinstance(cards, list) or len(cards) == 0:
        return None, 'Missing or empty cards array'
    if len(cards) > MAX_CARDS:
        return None, f'Too many cards (max {MAX_CARDS})'

    cleaned_cards = []
    for idx, card in enumerate(cards):
        if not isinstance(card, dict):
            return None, f'Card at index {idx} is not an object'

        card_type = str(card.get('type', 'basic'))
        if card_type not in ALLOWED_CARD_TYPES:
            card_type = 'basic'

        color = str(card.get('color', 'gray'))[:20]

        raw_nodes = card.get('nodes', [])
        if not isinstance(raw_nodes, list):
            raw_nodes = []
        nodes = []
        for node in raw_nodes[:MAX_NODES_PER_CARD]:
            if isinstance(node, dict):
                nodes.append({
                    'id': str(node.get('id', ''))[:64],
                    'x': _safe_float(node.get('x', 0)),
                    'y': _safe_float(node.get('y', 0)),
                    'type': str(node.get('type', 'input'))[:20],
                    'connections': [str(c)[:64] for c in node.get('connections', [])[:16] if isinstance(c, str)],
                })

        raw_conns = card.get('matrixConnections', [])
        if not isinstance(raw_conns, list):
            raw_conns = []
        connections = []
        for conn in raw_conns[:64]:
            if isinstance(conn, dict) and conn.get('active'):
                connections.append({
                    'id': str(conn.get('id', ''))[:64],
                    'active': True,
                    'fromX': _safe_float(conn.get('fromX', 0)),
                    'fromY': _safe_float(conn.get('fromY', 0)),
                    'toX': _safe_float(conn.get('toX', 0)),
                    'toY': _safe_float(conn.get('toY', 0)),
                })

        raw_mesh = card.get('meshInteractionPoints', [])
        if not isinstance(raw_mesh, list):
            raw_mesh = []
        mesh_points = []
        for pt in raw_mesh[:32]:
            if isinstance(pt, dict):
                mesh_points.append({
                    'id': str(pt.get('id', ''))[:64],
                    'x': _safe_float(pt.get('x', 0)),
                    'y': _safe_float(pt.get('y', 0)),
                    'upConnections': [str(c)[:64] for c in pt.get('upConnections', [])[:16] if isinstance(c, str)],
                    'downConnections': [str(c)[:64] for c in pt.get('downConnections', [])[:16] if isinstance(c, str)],
                })

        raw_gates = card.get('logicGates', [])
        if not isinstance(raw_gates, list):
            raw_gates = []
        logic_gates = []
        for gate in raw_gates[:16]:
            if isinstance(gate, dict):
                gate_type = str(gate.get('type', 'BUFFER'))
                if gate_type not in ALLOWED_GATE_TYPES:
                    gate_type = 'BUFFER'
                logic_gates.append({
                    'id': str(gate.get('id', ''))[:64],
                    'type': gate_type,
                    'x': _safe_float(gate.get('x', 0)),
                    'y': _safe_float(gate.get('y', 0)),
                })

        cleaned_cards.append({
            'id': str(card.get('id', f'card-{idx}'))[:64],
            'type': card_type,
            'color': color,
            'nodes': nodes,
            'matrixConnections': connections,
            'meshInteractionPoints': mesh_points,
            'logicGates': logic_gates,
        })

    return {'cards': cleaned_cards}, None


# ---------------------------------------------------------------------------
# Security headers
# ---------------------------------------------------------------------------
@app.after_request
def add_security_headers(response):
    response.headers['X-Content-Type-Options'] = 'nosniff'
    response.headers['X-Frame-Options'] = 'DENY'
    response.headers['Referrer-Policy'] = 'strict-origin-when-cross-origin'
    # HSTS only over HTTPS.
    if request.is_secure:
        response.headers['Strict-Transport-Security'] = (
            'max-age=31536000; includeSubDomains; preload'
        )
    response.headers['Permissions-Policy'] = (
        'camera=(), microphone=(), geolocation=(), accelerometer=(), '
        'gyroscope=(), magnetometer=(), payment=(), usb=(), midi=()'
    )
    response.headers['Content-Security-Policy'] = (
        "default-src 'self'; script-src 'self'; style-src 'self' 'unsafe-inline'"
    )
    return response


# ---------------------------------------------------------------------------
# CircuitEncryption — rewritten.
# AES-256-GCM + scrypt KDF. Circuit parameters are mixed into both:
#   * the HKDF info (key separation)  and
#   * the AES-GCM AAD (per-message binding to the circuit topology)
# so that ciphertexts produced under one circuit cannot be decrypted under
# another even with the same password.
# ---------------------------------------------------------------------------
_CIPHER_MAGIC = b'FOLD2'  # version prefix for wire format
_SCRYPT_N = int(os.environ.get('SCRYPT_N', str(2 ** 15)))
_SCRYPT_R = 8
_SCRYPT_P = 1


def _canonical_info(circuit_params: dict) -> bytes:
    """Stable byte encoding of circuit parameters for use as HKDF info/AAD."""
    return json.dumps(circuit_params, sort_keys=True, separators=(',', ':')).encode()


class CircuitEncryption:
    """Authenticated encryption keyed from a user password and circuit params.

    API (stable):
        CircuitEncryption(circuit_params: dict | None = None)
        .encrypt(plaintext: str | bytes, password: str | bytes) -> bytes (base64)
        .decrypt(ciphertext: str | bytes, password: str | bytes) -> str | bytes

    Wire format (after base64 decode):
        magic(5) || salt(16) || nonce(12) || aesgcm_ciphertext_and_tag(rest)
    The circuit parameters are used as HKDF info AND AES-GCM AAD.
    """

    def __init__(self, circuit_params: "dict | None" = None):
        self.circuit_params = dict(circuit_params or {})
        self._info = _canonical_info(self.circuit_params)

    # -- key derivation -----------------------------------------------------
    def _derive_key(self, password, salt: bytes) -> bytes:
        if isinstance(password, str):
            password = password.encode('utf-8')
        base = Scrypt(
            salt=salt,
            length=32,
            n=_SCRYPT_N,
            r=_SCRYPT_R,
            p=_SCRYPT_P,
        ).derive(password)
        # Mix circuit params into the key via HKDF so that changing the
        # circuit changes the effective key (domain separation).
        return HKDF(
            algorithm=hashes.SHA256(),
            length=32,
            salt=salt,
            info=b'fold-circuit-v2|' + self._info,
        ).derive(base)

    # -- encryption ---------------------------------------------------------
    def encrypt(self, plaintext, password) -> bytes:
        if isinstance(plaintext, str):
            plaintext = plaintext.encode('utf-8')
        salt = os.urandom(16)
        nonce = os.urandom(12)
        key = self._derive_key(password, salt)
        ct = AESGCM(key).encrypt(nonce, plaintext, self._info)
        return base64.b64encode(_CIPHER_MAGIC + salt + nonce + ct)

    # -- decryption ---------------------------------------------------------
    def decrypt(self, ciphertext, password):
        if isinstance(ciphertext, str):
            ciphertext = ciphertext.encode('ascii')
        blob = base64.b64decode(ciphertext)
        if len(blob) < len(_CIPHER_MAGIC) + 16 + 12 + 16:
            raise ValueError('Ciphertext too short')
        if not blob.startswith(_CIPHER_MAGIC):
            raise ValueError('Unsupported ciphertext format')
        off = len(_CIPHER_MAGIC)
        salt = blob[off:off + 16]
        nonce = blob[off + 16:off + 28]
        ct = blob[off + 28:]
        key = self._derive_key(password, salt)
        pt = AESGCM(key).decrypt(nonce, ct, self._info)
        try:
            return pt.decode('utf-8')
        except UnicodeDecodeError:
            return pt


# ---------------------------------------------------------------------------
# Circuit analysis (unchanged semantics)
# ---------------------------------------------------------------------------
def analyze_circuit(circuit_data):
    cards = circuit_data.get('cards', [])
    all_nodes, all_connections, all_mesh_points, all_logic_gates = [], [], [], []

    for idx, card in enumerate(cards):
        card_id = card.get('id', f'unknown-{idx}')
        all_nodes.extend([{**node, 'card_id': card_id, 'card_index': idx}
                          for node in card.get('nodes', [])])
        if 'matrixConnections' in card:
            all_connections.extend([{**conn, 'card_id': card_id, 'card_index': idx}
                                    for conn in card['matrixConnections'] if conn.get('active', False)])
        all_mesh_points.extend([{**point, 'card_id': card_id, 'card_index': idx}
                                for point in card.get('meshInteractionPoints', [])])
        if 'logicGates' in card:
            all_logic_gates.extend([{**gate, 'card_id': card_id, 'card_index': idx}
                                    for gate in card.get('logicGates', [])])

    mesh_connections = []
    for point in all_mesh_points:
        card_idx = point.get('card_index')
        for up_id in point.get('upConnections', []):
            for target_point in all_mesh_points:
                if target_point.get('id') == up_id and target_point.get('card_index') > card_idx:
                    mesh_connections.append({'from_point': point, 'to_point': target_point, 'direction': 'up'})
        for down_id in point.get('downConnections', []):
            for target_point in all_mesh_points:
                if target_point.get('id') == down_id and target_point.get('card_index') < card_idx:
                    mesh_connections.append({'from_point': point, 'to_point': target_point, 'direction': 'down'})

    circuit_summary = {
        'num_cards': len(cards),
        'card_types': [card.get('type') for card in cards],
        'card_colors': [card.get('color') for card in cards],
        'num_nodes': len(all_nodes),
        'num_connections': len(all_connections),
        'num_mesh_points': len(all_mesh_points),
        'num_mesh_connections': len(mesh_connections),
        'num_logic_gates': len(all_logic_gates),
        'logic_gate_types': [gate.get('type') for gate in all_logic_gates],
        'complexity_score': (
            len(cards) * 5
            + len(all_connections) * 2
            + len(mesh_connections) * 3
            + len(all_logic_gates) * 4
        ),
    }

    return {
        'nodes': all_nodes,
        'connections': all_connections,
        'mesh_points': all_mesh_points,
        'mesh_connections': mesh_connections,
        'logic_gates': all_logic_gates,
        'summary': circuit_summary,
    }


def derive_circuit_parameters(circuit_analysis: dict) -> dict:
    """Compute a small, structured parameter object describing the circuit's
    contribution to the cipher. These values are *public* — the secret is the
    user's password. The parameters bind ciphertexts to a given circuit
    topology via HKDF info / AES-GCM AAD.
    """
    summary = circuit_analysis['summary']
    circuit_seed_material = ''.join(
        (summary['card_types'] or [])
        + (summary['card_colors'] or [])
        + (summary['logic_gate_types'] or [])
    )
    circuit_seed = hashlib.sha256(circuit_seed_material.encode()).hexdigest()[:32]
    return {
        'version': 2,
        'algorithm': 'AES-256-GCM',
        'kdf': 'scrypt(N=%d,r=%d,p=%d)+HKDF-SHA256' % (_SCRYPT_N, _SCRYPT_R, _SCRYPT_P),
        'circuit_seed': circuit_seed,
        'summary': {
            'num_cards': summary['num_cards'],
            'num_nodes': summary['num_nodes'],
            'num_connections': summary['num_connections'],
            'num_logic_gates': summary['num_logic_gates'],
            'complexity_score': summary['complexity_score'],
            'card_types': list(summary['card_types']),
            'logic_gate_types': list(summary['logic_gate_types']),
        },
    }


def create_encryption_from_analysis(circuit_analysis: dict) -> "CircuitEncryption":
    """Factory used by tests and server code to build a configured cipher."""
    return CircuitEncryption(derive_circuit_parameters(circuit_analysis))


# ---------------------------------------------------------------------------
# Session bootstrap endpoint
# ---------------------------------------------------------------------------
@app.route('/api/session', methods=['POST'])
@limiter.limit("30 per minute")
def api_session():
    """Mint a browser session. Frontend calls this once on page load.
    No credentials required — this only provides an anonymous opaque id."""
    if not session.get('sid'):
        session['sid'] = py_secrets.token_urlsafe(24)
        session.permanent = False
    return jsonify({'session': 'ok'})


# ---------------------------------------------------------------------------
# API Routes
# ---------------------------------------------------------------------------
@app.route('/api/generate_encryption', methods=['POST'])
@require_auth
@limiter.limit("10 per minute")
def api_generate_encryption():
    """Analyze a circuit and return structured encryption parameters.

    We do NOT return Python source. Clients who want to encrypt locally can
    use the documented CircuitEncryption class (see tests.py) and pass the
    `parameters` field returned here.
    """
    try:
        circuit_data = request.get_json(silent=True)
        if circuit_data is None:
            return jsonify({'error': 'Invalid or missing JSON body'}), 400

        cleaned, err = validate_circuit_data(circuit_data)
        if err:
            return jsonify({'error': err}), 400

        analysis = analyze_circuit(cleaned)
        parameters = derive_circuit_parameters(analysis)

        record = {
            'timestamp': time.time(),
            'cards_count': len(cleaned.get('cards', [])),
            'complexity': analysis['summary']['complexity_score'],
            'circuit_seed': parameters['circuit_seed'],
        }
        user_id = _get_user_id()
        bucket = encryption_records_by_user.setdefault(user_id, [])
        bucket.append(record)
        while len(bucket) > MAX_HISTORY_RECORDS:
            bucket.pop(0)
        # Global cap on distinct users to prevent unbounded memory growth.
        while len(encryption_records_by_user) > MAX_HISTORY_USERS:
            # Drop an arbitrary oldest key (dict insertion order).
            victim = next(iter(encryption_records_by_user))
            if victim == user_id:
                break
            encryption_records_by_user.pop(victim, None)

        # Sign the parameters with a key derived from SECRET_KEY (not API_KEY).
        param_bytes = _canonical_info(parameters)
        signature = _sign(param_bytes)

        return jsonify({
            'parameters': parameters,
            'parameters_signature': signature,
            'analysis': analysis['summary'],
        })

    except Exception:
        logger.exception('Error generating encryption parameters')
        return jsonify({'error': 'Internal server error'}), 500


@app.route('/api/history', methods=['GET'])
@require_auth
@limiter.limit("60 per minute")
def api_history():
    user_id = _get_user_id()
    return jsonify({
        'records': encryption_records_by_user.get(user_id, []),
        'user_isolated': True,
    })


@app.route('/', defaults={'path': ''})
@app.route('/<path:path>')
def serve(path):
    if app.static_folder is None or not os.path.isdir(app.static_folder):
        return jsonify({
            'error': 'Frontend not built. Run: npm install && npm run build',
            'api': '/api/status',
        }), 503
    if path != "" and os.path.exists(os.path.join(app.static_folder, path)):
        return send_from_directory(app.static_folder, path)
    return send_from_directory(app.static_folder, 'index.html')


@app.route('/api/status')
def api_status():
    pqc_status = 'unavailable'
    try:
        req = urllib.request.Request(f'{PQC_SERVICE_URL}/pqc/status', method='GET')
        with urllib.request.urlopen(req, timeout=2) as resp:
            if resp.status == 200:
                pqc_status = 'online'
    except Exception:
        pass
    return jsonify({
        'status': 'online',
        'version': '2.1.0',
        'pqc_status': pqc_status,
        'pqc_algorithm': 'ML-KEM-768',
        'endpoints': [
            '/api/session',
            '/api/generate_encryption',
            '/api/history',
            '/api/status',
            '/api/pqc/keypair',
            '/api/pqc/encrypt',
            '/api/pqc/decrypt',
            '/api/pqc/status',
        ],
    })


# ---------------------------------------------------------------------------
# PQC proxy
# ---------------------------------------------------------------------------
_PQC_MAX_PROXY_BODY = int(os.environ.get('PQC_MAX_PROXY_BODY', str(256 * 1024)))  # 256 KB


def _proxy_to_pqc(path: str):
    target_url = f'{PQC_SERVICE_URL}/pqc/{path}'
    try:
        body = request.get_data(cache=False)
        if len(body) > _PQC_MAX_PROXY_BODY:
            return jsonify({'error': 'Request too large for PQC proxy'}), 413
        headers = {'Content-Type': 'application/json'}
        # The sidecar authenticates with the shared API_KEY. The frontend never
        # sees this key; the proxy injects it here.
        headers['X-API-Key'] = API_KEY
        req = urllib.request.Request(
            target_url,
            data=body if request.method == 'POST' else None,
            headers=headers,
            method=request.method,
        )
        with urllib.request.urlopen(req, timeout=15) as resp:
            return app.response_class(
                response=resp.read(),
                status=resp.status,
                mimetype='application/json',
            )
    except urllib.error.HTTPError as e:
        return app.response_class(
            response=e.read(),
            status=e.code,
            mimetype='application/json',
        )
    except Exception:
        logger.exception('PQC proxy error for %s', path)
        return jsonify({'error': 'PQC service unavailable'}), 503


@app.route('/api/pqc/status')
def api_pqc_status():
    return _proxy_to_pqc('status')


@app.route('/api/pqc/keypair', methods=['POST'])
@require_auth
@limiter.limit("10 per minute")
def api_pqc_keypair():
    return _proxy_to_pqc('keypair')


@app.route('/api/pqc/encrypt', methods=['POST'])
@require_auth
@limiter.limit("10 per minute")
def api_pqc_encrypt():
    return _proxy_to_pqc('encrypt')


@app.route('/api/pqc/decrypt', methods=['POST'])
@require_auth
@limiter.limit("10 per minute")
def api_pqc_decrypt():
    return _proxy_to_pqc('decrypt')


if __name__ == '__main__':
    port = int(os.environ.get('PORT', 5000))
    host = os.environ.get('HOST', '0.0.0.0')
    debug = os.environ.get('FLASK_DEBUG', '0') == '1'

    # M1: Refuse to start with FLASK_DEBUG=1 unless bound to loopback.
    # The Werkzeug debugger is effectively an RCE on any client that can
    # reach the port. The explicit FOLD_ALLOW_DEBUG_BIND=1 escape hatch is
    # used by the Docker `dev` profile, which pairs it with a host-side
    # port binding of 127.0.0.1 only — see docker-compose.yml.
    if debug:
        try:
            host_ip = ipaddress.ip_address(host)
            loopback_ok = host_ip.is_loopback
        except ValueError:
            loopback_ok = host in ('localhost',)
        allow_nonloopback = os.environ.get('FOLD_ALLOW_DEBUG_BIND') == '1'
        if not loopback_ok and not allow_nonloopback:
            raise RuntimeError(
                f'Refusing to start Flask debug server on non-loopback host '
                f'{host!r}. The Werkzeug debugger permits arbitrary code '
                f'execution. Set HOST=127.0.0.1 (or run under gunicorn). '
                f'For containerized dev with a loopback-only host port, set '
                f'FOLD_ALLOW_DEBUG_BIND=1 AND ensure the host port is bound '
                f'to 127.0.0.1 only.'
            )
        if loopback_ok:
            logger.warning('Flask debug mode is ENABLED on loopback only.')
        else:
            logger.warning(
                'Flask debug mode is ENABLED on non-loopback host %r because '
                'FOLD_ALLOW_DEBUG_BIND=1. Ensure the host-side port binding '
                'is restricted to 127.0.0.1.', host,
            )

    app.run(host=host, port=port, debug=debug)
