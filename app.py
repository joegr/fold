from flask import Flask, request, jsonify, send_from_directory
from flask_cors import CORS
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
from functools import wraps
import math
import os
import json
import logging
import numpy as np
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import padding
from cryptography.hazmat.backends import default_backend
import base64
import hashlib
import hmac
import time
import inspect

# ---------------------------------------------------------------------------
# Configuration
# ---------------------------------------------------------------------------
ALLOWED_ORIGINS = os.environ.get(
    'ALLOWED_ORIGINS', 'http://localhost:3000,http://localhost:5000'
).split(',')
API_KEY = os.environ.get('API_KEY', None)
MAX_CARDS = int(os.environ.get('MAX_CARDS', '20'))
MAX_NODES_PER_CARD = int(os.environ.get('MAX_NODES_PER_CARD', '16'))
MAX_REQUEST_SIZE = int(os.environ.get('MAX_REQUEST_SIZE', str(1 * 1024 * 1024)))  # 1 MB
MAX_HISTORY_RECORDS = int(os.environ.get('MAX_HISTORY_RECORDS', '200'))

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
app.config['SECRET_KEY'] = os.environ.get('SECRET_KEY', os.urandom(32).hex())
CORS(app, resources={r"/api/*": {"origins": ALLOWED_ORIGINS}})
limiter = Limiter(get_remote_address, app=app, default_limits=["60 per minute"])
encryption_records = []

ALLOWED_GATE_TYPES = frozenset({'AND', 'OR', 'XOR', 'NOT', 'NAND', 'NOR', 'BUFFER'})
ALLOWED_CARD_TYPES = frozenset({
    'processor', 'memory', 'io', 'custom', 'network',
    'logic', 'matrix', 'hybrid', 'basic',
})


# ---------------------------------------------------------------------------
# Security helpers
# ---------------------------------------------------------------------------
def require_api_key(f):
    """Decorator that enforces API-key auth when API_KEY is configured."""
    @wraps(f)
    def decorated(*args, **kwargs):
        if API_KEY is None:
            return f(*args, **kwargs)
        key = request.headers.get('X-API-Key', '')
        if not hmac.compare_digest(key, API_KEY):
            return jsonify({'error': 'Unauthorized'}), 401
        return f(*args, **kwargs)
    return decorated


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

        # Sanitize nodes — deep validate each node
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

        # Sanitize matrix connections
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

        # Sanitize mesh interaction points
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

        # Sanitize logic gates — only allow known types
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


@app.after_request
def add_security_headers(response):
    response.headers['X-Content-Type-Options'] = 'nosniff'
    response.headers['X-Frame-Options'] = 'DENY'
    response.headers['X-XSS-Protection'] = '1; mode=block'
    response.headers['Referrer-Policy'] = 'strict-origin-when-cross-origin'
    response.headers['Content-Security-Policy'] = (
        "default-src 'self'; script-src 'self'; style-src 'self' 'unsafe-inline'"
    )
    return response

# Define the CircuitEncryption class template that will be used to generate custom encryption algorithms
class CircuitEncryption:
    """Base class for circuit-based encryption algorithms."""
    
    def __init__(self, key_derivation_constants=None, connection_matrix=None, logic_operations=None):
        """Initialize with circuit-derived parameters."""
        # Default values that will be overridden in generated classes
        self.KEY_ROUNDS = 4
        self.MATRIX_SIZE = 8
        self.PERMUTATION_ROUNDS = 2
        self.CIRCUIT_SEED = "0000000000000000"
        
        # Default connection matrix
        self.connection_matrix = [[0 for _ in range(8)] for _ in range(8)]
        
        # Default logic operations
        self.logic_operations = [
            lambda byte1, byte2: byte1 ^ byte2
        ]
        
        # Override with provided values if any
        _ALLOWED_CONSTANT_KEYS = frozenset({
            'KEY_ROUNDS', 'MATRIX_SIZE', 'PERMUTATION_ROUNDS', 'CIRCUIT_SEED',
        })
        if key_derivation_constants:
            for key, value in key_derivation_constants.items():
                if key in _ALLOWED_CONSTANT_KEYS:
                    setattr(self, key, value)
                
        if connection_matrix is not None:
            self.connection_matrix = connection_matrix
            
        if logic_operations is not None:
            self.logic_operations = logic_operations
    
    def derive_key(self, input_key):
        """Derive encryption key based on circuit layout."""
        # Hash the input key
        key_hash = hashlib.sha256(input_key.encode() if isinstance(input_key, str) else input_key).digest()
        
        # Apply circuit-specific transformations
        derived_key = bytearray(key_hash)
        
        # Apply multiple rounds of transformation
        for round in range(self.KEY_ROUNDS):
            # Apply the connection matrix
            for i in range(min(16, len(derived_key))):
                row = i % len(self.connection_matrix)
                for j in range(len(self.connection_matrix[row])):
                    matrix_val = self.connection_matrix[row][j]
                    if matrix_val > 0:
                        idx = (j + round) % len(derived_key)
                        derived_key[i] = (derived_key[i] + (derived_key[idx] ^ matrix_val)) % 256
            
            # Apply logic operations
            for i in range(len(derived_key) - 1):
                op_idx = i % len(self.logic_operations)
                derived_key[i] = self.logic_operations[op_idx](derived_key[i], derived_key[i+1])
        
        # Ensure the key is the right length for AES (32 bytes for AES-256)
        if len(derived_key) < 32:
            derived_key.extend(derived_key[:32-len(derived_key)])
        return bytes(derived_key[:32])
    
    def apply_circuit_transformation(self, data, key):
        """Apply the circuit logic to transform data (fully reversible)."""
        data_array = bytearray(data)

        for round_num in range(self.PERMUTATION_ROUNDS):
            # Step 1 – key + matrix substitution (reverse: subtract mod 256)
            for i in range(len(data_array)):
                row = i % len(self.connection_matrix)
                col = (i + round_num) % len(self.connection_matrix[0])
                matrix_val = self.connection_matrix[row][col]
                key_byte = key[i % len(key)]
                if isinstance(key_byte, str):
                    key_byte = ord(key_byte)
                data_array[i] = (data_array[i] + (key_byte ^ matrix_val)) % 256

            # Step 2 – XOR diffusion (forward pass; reverse via backward pass)
            for i in range(len(data_array) - 1):
                key_byte = key[(i + round_num) % len(key)]
                if isinstance(key_byte, str):
                    key_byte = ord(key_byte)
                data_array[i] ^= ((data_array[i + 1] + key_byte) % 256)

            # Step 3 – byte permutation (reverse: inverse permutation)
            if len(data_array) > 1:
                perm_val = self.connection_matrix[
                    round_num % len(self.connection_matrix)
                ][round_num % len(self.connection_matrix[0])]
                temp = bytearray(data_array)
                for i in range(len(data_array)):
                    dest = (i + perm_val) % len(data_array)
                    data_array[dest] = temp[i]

        return bytes(data_array)

    def reverse_circuit_transformation(self, data, key):
        """Reverse the circuit transformation (exact inverse)."""
        data_array = bytearray(data)

        for round_num in range(self.PERMUTATION_ROUNDS - 1, -1, -1):
            # Step 3 reverse – undo permutation
            if len(data_array) > 1:
                perm_val = self.connection_matrix[
                    round_num % len(self.connection_matrix)
                ][round_num % len(self.connection_matrix[0])]
                temp = bytearray(data_array)
                for i in range(len(data_array)):
                    src = (i + perm_val) % len(data_array)
                    data_array[i] = temp[src]

            # Step 2 reverse – undo XOR diffusion (backward pass)
            for i in range(len(data_array) - 2, -1, -1):
                key_byte = key[(i + round_num) % len(key)]
                if isinstance(key_byte, str):
                    key_byte = ord(key_byte)
                data_array[i] ^= ((data_array[i + 1] + key_byte) % 256)

            # Step 1 reverse – undo substitution
            for i in range(len(data_array)):
                row = i % len(self.connection_matrix)
                col = (i + round_num) % len(self.connection_matrix[0])
                matrix_val = self.connection_matrix[row][col]
                key_byte = key[i % len(key)]
                if isinstance(key_byte, str):
                    key_byte = ord(key_byte)
                data_array[i] = (data_array[i] - (key_byte ^ matrix_val)) % 256

        return bytes(data_array)
    
    def encrypt(self, plaintext, key):
        """Encrypt data using the circuit-based algorithm."""
        # Derive the encryption key
        circuit_key = self.derive_key(key)
        
        # Prepare data
        if isinstance(plaintext, str):
            plaintext = plaintext.encode('utf-8')
            
        # Apply padding
        padder = padding.PKCS7(128).padder()
        padded_data = padder.update(plaintext) + padder.finalize()
        
        # Apply circuit transformation
        transformed = self.apply_circuit_transformation(padded_data, circuit_key)
        
        # Encrypt with AES
        iv = os.urandom(16)
        cipher = Cipher(algorithms.AES(circuit_key), modes.CBC(iv), backend=default_backend())
        encryptor = cipher.encryptor()
        ciphertext = encryptor.update(transformed) + encryptor.finalize()
        
        # Combine IV and ciphertext
        encrypted = base64.b64encode(iv + ciphertext)
        return encrypted
    
    def decrypt(self, ciphertext, key):
        """Decrypt data using the circuit-based algorithm."""
        circuit_key = self.derive_key(key)

        encrypted_data = base64.b64decode(ciphertext)
        iv = encrypted_data[:16]
        actual_ciphertext = encrypted_data[16:]

        cipher = Cipher(algorithms.AES(circuit_key), modes.CBC(iv), backend=default_backend())
        decryptor = cipher.decryptor()
        transformed = decryptor.update(actual_ciphertext) + decryptor.finalize()

        reversed_transform = self.reverse_circuit_transformation(transformed, circuit_key)

        unpadder = padding.PKCS7(128).unpadder()
        plaintext = unpadder.update(reversed_transform) + unpadder.finalize()

        try:
            return plaintext.decode('utf-8')
        except UnicodeDecodeError:
            return plaintext


def analyze_circuit(circuit_data):
    """Analyze circuit stack to extract logical operations and connections"""
    cards = circuit_data.get('cards', [])
    
    # Extract data from cards
    all_nodes = []
    all_connections = []
    all_mesh_points = []
    all_logic_gates = []
    
    # Process cards bottom to top
    for idx, card in enumerate(cards):
        card_id = card.get('id', f'unknown-{idx}')
        
        # Extract nodes
        all_nodes.extend([{**node, 'card_id': card_id, 'card_index': idx} 
                         for node in card.get('nodes', [])])
        
        # Extract connections
        if 'matrixConnections' in card:
            all_connections.extend([{**conn, 'card_id': card_id, 'card_index': idx} 
                                  for conn in card['matrixConnections'] if conn.get('active', False)])
        
        # Extract mesh points
        all_mesh_points.extend([{**point, 'card_id': card_id, 'card_index': idx} 
                               for point in card.get('meshInteractionPoints', [])])
        
        # Extract logic gates
        if 'logicGates' in card:
            all_logic_gates.extend([{**gate, 'card_id': card_id, 'card_index': idx} 
                                   for gate in card.get('logicGates', [])])
    
    # Analyze mesh interactions between cards
    mesh_connections = []
    for point in all_mesh_points:
        card_idx = point.get('card_index')
        
        # Check upward connections
        for up_id in point.get('upConnections', []):
            for target_point in all_mesh_points:
                if (target_point.get('id') == up_id and 
                    target_point.get('card_index') > card_idx):
                    mesh_connections.append({
                        'from_point': point,
                        'to_point': target_point,
                        'direction': 'up'
                    })
        
        # Check downward connections
        for down_id in point.get('downConnections', []):
            for target_point in all_mesh_points:
                if (target_point.get('id') == down_id and 
                    target_point.get('card_index') < card_idx):
                    mesh_connections.append({
                        'from_point': point,
                        'to_point': target_point,
                        'direction': 'down'
                    })
    
    # Generate circuit summary
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
            len(cards) * 5 +
            len(all_connections) * 2 +
            len(mesh_connections) * 3 +
            len(all_logic_gates) * 4
        )
    }
    
    return {
        'nodes': all_nodes,
        'connections': all_connections,
        'mesh_points': all_mesh_points,
        'mesh_connections': mesh_connections,
        'logic_gates': all_logic_gates,
        'summary': circuit_summary
    }

def create_encryption_from_analysis(circuit_analysis):
    """Create a configured CircuitEncryption instance directly from analysis.

    This avoids the need for exec() when consuming generated algorithms
    programmatically (e.g. in tests).
    """
    summary = circuit_analysis['summary']

    constants = {
        'KEY_ROUNDS': max(2, min(16, summary['num_cards'] + 2)),
        'MATRIX_SIZE': max(4, min(32, summary['num_nodes'] // 2)),
        'PERMUTATION_ROUNDS': max(1, min(8, summary['num_connections'] // 2)),
    }

    circuit_seed = ''.join(
        summary['card_types'] + summary['card_colors'] + summary['logic_gate_types']
    )
    constants['CIRCUIT_SEED'] = hashlib.sha256(circuit_seed.encode()).hexdigest()[:16]

    size = constants['MATRIX_SIZE']
    conn_matrix = [[0] * size for _ in range(size)]

    connections = circuit_analysis['connections']
    for conn in connections:
        row = int(conn.get('fromX', 0) * 100) % size
        col = int(conn.get('fromY', 0) * 100) % size
        val = int(conn.get('toX', 0.5) * 100 + conn.get('toY', 0.5) * 100) % 256
        conn_matrix[row][col] = val

    if len(connections) < size:
        seed_array = [int(constants['CIRCUIT_SEED'][i:i+2], 16) for i in range(0, 16, 2)]
        for i in range(size):
            if sum(conn_matrix[i]) == 0:
                for j in range(size):
                    if conn_matrix[i][j] == 0:
                        conn_matrix[i][j] = seed_array[(i + j) % len(seed_array)]

    _gate_to_lambda = {
        'AND':    lambda b1, b2: (b1 & b2),
        'OR':     lambda b1, b2: (b1 | b2),
        'XOR':    lambda b1, b2: (b1 ^ b2),
        'NOT':    lambda b1, b2: (~b1 & 0xFF),
        'NAND':   lambda b1, b2: (~(b1 & b2) & 0xFF),
        'NOR':    lambda b1, b2: (~(b1 | b2) & 0xFF),
        'BUFFER': lambda b1, b2: b1,
    }

    logic_gates = circuit_analysis['logic_gates']
    logic_ops = [
        _gate_to_lambda.get(gate.get('type', 'BUFFER'), _gate_to_lambda['BUFFER'])
        for gate in logic_gates
    ]
    if not logic_ops:
        logic_ops = [lambda b1, b2: (b1 ^ b2)]

    return CircuitEncryption(
        key_derivation_constants=constants,
        connection_matrix=conn_matrix,
        logic_operations=logic_ops,
    )


def generate_encryption_algorithm(circuit_analysis):
    """Generate encryption algorithm based on circuit analysis"""
    summary = circuit_analysis['summary']
    
    # Derive constants from circuit properties
    constants = {
        'KEY_ROUNDS': max(2, min(16, summary['num_cards'] + 2)),
        'MATRIX_SIZE': max(4, min(32, summary['num_nodes'] // 2)),
        'PERMUTATION_ROUNDS': max(1, min(8, summary['num_connections'] // 2))
    }
    
    # Generate unique seed
    circuit_seed = ''.join(summary['card_types'] + summary['card_colors'] + summary['logic_gate_types'])
    constants['CIRCUIT_SEED'] = hashlib.sha256(circuit_seed.encode()).hexdigest()[:16]
    
    # Create connection matrix
    size = constants['MATRIX_SIZE']
    conn_matrix = np.zeros((size, size), dtype=int)
    
    # Fill matrix using circuit connections
    connections = circuit_analysis['connections']
    for conn in connections:
        row = int(conn.get('fromX', 0) * 100) % size
        col = int(conn.get('fromY', 0) * 100) % size
        val = int(conn.get('toX', 0.5) * 100 + conn.get('toY', 0.5) * 100) % 256
        conn_matrix[row, col] = val
    
    # Add defaults if needed
    if len(connections) < size:
        seed_array = [int(constants['CIRCUIT_SEED'][i:i+2], 16) for i in range(0, 16, 2)]
        for i in range(size):
            if sum(conn_matrix[i]) == 0:
                for j in range(size):
                    if conn_matrix[i, j] == 0:
                        conn_matrix[i, j] = seed_array[(i+j) % len(seed_array)]
    
    # Map logic gates to valid lambda expressions (no assignments)
    logic_gate_map = {
        'AND': '(byte1 & byte2)',
        'OR': '(byte1 | byte2)',
        'XOR': '(byte1 ^ byte2)',
        'NOT': '(~byte1 & 0xFF)',
        'NAND': '(~(byte1 & byte2) & 0xFF)',
        'NOR': '(~(byte1 | byte2) & 0xFF)',
        'BUFFER': 'byte1',
    }
    
    # Construct logic operations — only allow known gate types
    logic_gates = circuit_analysis['logic_gates']
    logic_ops = []
    for gate in logic_gates:
        gate_type = gate.get('type', 'BUFFER')
        if gate_type not in logic_gate_map:
            gate_type = 'BUFFER'
        logic_ops.append(logic_gate_map[gate_type])
    
    # Add default if no logic gates
    if not logic_ops:
        logic_ops = ['(byte1 ^ byte2)',
                     '(((byte1 << 1) | (byte1 >> 7)) & 0xFF)']
    
    # Build lambda source strings
    logic_lambdas = [f"lambda byte1, byte2: {op}" for op in logic_ops]
    
    # Generate Python code for the custom encryption class
    code = [
        "import base64",
        "import hashlib",
        "import os",
        "from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes",
        "from cryptography.hazmat.primitives import padding",
        "from cryptography.hazmat.backends import default_backend",
        "",
        "class CircuitEncryption:",
        "    def __init__(self):",
        "        # Circuit-derived constants"
    ]
    
    # Add constants with proper representation
    for key, value in constants.items():
        if key == 'CIRCUIT_SEED':
            # Properly quote the hexadecimal string
            code.append(f"        self.{key} = '{value}'")
        else:
            code.append(f"        self.{key} = {value}")
    
    # Add connection matrix
    code.append("")
    code.append("        # Node connection matrix (derived from circuit layout)")
    code.append("        self.connection_matrix = [")
    for row in conn_matrix:
        code.append(f"            {row.tolist()},")
    code.append("        ]")
    
    # Add logic operations
    code.append("")
    code.append("        # Logic gate operations (derived from circuit cards)")
    code.append("        self.logic_operations = [")
    for logic_lambda in logic_lambdas:
        code.append(f"            {logic_lambda},")
    code.append("        ]")
    
    # Add the rest of the class methods by inspecting the CircuitEncryption class
    methods = [name for name, func in inspect.getmembers(CircuitEncryption, predicate=inspect.isfunction)
              if name not in ('__init__')]
    
    for method_name in methods:
        method = getattr(CircuitEncryption, method_name)
        lines = inspect.getsource(method).split('\n')
        
        # Skip the first line (method definition with self)
        method_def = lines[0]
        indent = len(method_def) - len(method_def.lstrip())
        
        # Add method with proper indentation (4 spaces for class methods)
        code.append("")
        code.append(f"    {method_def.strip()}")
        
        # Add remaining lines with proper indentation
        for line in lines[1:]:
            if line.strip():
                # Keep the correct indentation relative to the method
                if len(line) > indent:
                    code.append(f"    {line[indent:]}")
                else:
                    code.append(f"    {line}")
    
    # Join all lines to create the full algorithm code
    algorithm_code = "\n".join(code)
    return algorithm_code

# ---------------------------------------------------------------------------
# API Routes
# ---------------------------------------------------------------------------
@app.route('/api/generate_encryption', methods=['POST'])
@require_api_key
@limiter.limit("10 per minute")
def api_generate_encryption():
    """Generate encryption algorithm from circuit data"""
    try:
        circuit_data = request.get_json(silent=True)
        if circuit_data is None:
            return jsonify({'error': 'Invalid or missing JSON body'}), 400

        cleaned, err = validate_circuit_data(circuit_data)
        if err:
            return jsonify({'error': err}), 400

        analysis = analyze_circuit(cleaned)
        algorithm = generate_encryption_algorithm(analysis)

        record = {
            'timestamp': time.time(),
            'cards_count': len(cleaned.get('cards', [])),
            'complexity': analysis['summary']['complexity_score'],
            'algorithm_size': len(algorithm),
        }
        encryption_records.append(record)
        # Prevent unbounded memory growth
        while len(encryption_records) > MAX_HISTORY_RECORDS:
            encryption_records.pop(0)

        return jsonify({
            'algorithm': algorithm,
            'analysis': analysis['summary'],
        })

    except Exception:
        logger.exception('Error generating encryption algorithm')
        return jsonify({'error': 'Internal server error'}), 500


@app.route('/api/history', methods=['GET'])
@require_api_key
def api_history():
    """Get history of encryption algorithms generated"""
    return jsonify({'records': encryption_records})


@app.route('/', defaults={'path': ''})
@app.route('/<path:path>')
def serve(path):
    """Serve the React frontend"""
    if path != "" and os.path.exists(os.path.join(app.static_folder, path)):
        return send_from_directory(app.static_folder, path)
    return send_from_directory(app.static_folder, 'index.html')


@app.route('/api/status')
def api_status():
    """API status check endpoint"""
    return jsonify({
        'status': 'online',
        'version': '1.1.0',
        'endpoints': ['/api/generate_encryption', '/api/history', '/api/status'],
    })


if __name__ == '__main__':
    port = int(os.environ.get('PORT', 5000))
    debug = os.environ.get('FLASK_DEBUG', '0') == '1'
    app.run(host='0.0.0.0', port=port, debug=debug)