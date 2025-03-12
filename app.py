from flask import Flask, request, jsonify, send_from_directory
from flask_cors import CORS
import os
import json
import numpy as np
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import padding
from cryptography.hazmat.backends import default_backend
import base64
import hashlib
import time
import inspect

app = Flask(__name__, static_folder='build')
CORS(app)
encryption_records = []

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
        if key_derivation_constants:
            for key, value in key_derivation_constants.items():
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
        """Apply the circuit logic to transform data."""
        # Convert data to bytearray for manipulation
        data_array = bytearray(data)
        
        # Apply circuit transformations based on connection matrix
        for round in range(self.PERMUTATION_ROUNDS):
            # Apply substitution using key and connection matrix
            for i in range(len(data_array)):
                row = i % len(self.connection_matrix)
                col = (i + round) % len(self.connection_matrix[0])
                matrix_val = self.connection_matrix[row][col]
                key_byte = key[i % len(key)]
                # Ensure key_byte is an integer
                if isinstance(key_byte, str):
                    key_byte = ord(key_byte)
                data_array[i] = (data_array[i] + (key_byte ^ matrix_val)) % 256
            
            # Apply logic gate operations
            for i in range(len(data_array) - 1):
                op_idx = (i + round) % len(self.logic_operations)
                data_array[i] = self.logic_operations[op_idx](data_array[i], data_array[i+1])
            
            # Permute bytes based on the circuit layout
            if len(data_array) > 1:
                temp = bytearray(data_array)
                for i in range(len(data_array)):
                    dest = (i + matrix_val) % len(data_array)
                    data_array[dest] = temp[i]
        
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
        # Derive the key
        circuit_key = self.derive_key(key)
        
        # Decode
        encrypted_data = base64.b64decode(ciphertext)
        iv = encrypted_data[:16]
        actual_ciphertext = encrypted_data[16:]
        
        # Decrypt with AES
        cipher = Cipher(algorithms.AES(circuit_key), modes.CBC(iv), backend=default_backend())
        decryptor = cipher.decryptor()
        transformed = decryptor.update(actual_ciphertext) + decryptor.finalize()
        
        # Reverse circuit transformation
        data_array = bytearray(transformed)
        
        # Apply inverse transformations in reverse order
        for round in range(self.PERMUTATION_ROUNDS - 1, -1, -1):
            # Undo permutation
            if len(data_array) > 1:
                temp = bytearray(data_array)
                for i in range(len(data_array)):
                    dest = (i + self.connection_matrix[i % len(self.connection_matrix)][
                        (i + round) % len(self.connection_matrix[0])]) % len(data_array)
                    data_array[i] = temp[dest]
            
            # Logic operations are harder to inverse, so we apply a reversing transformation
            for i in range(len(data_array) - 1, 0, -1):
                op_idx = (i - 1 + round) % len(self.logic_operations)
                # XOR itself is reversible
                data_array[i-1] = data_array[i-1] ^ (data_array[i] & 0x55)
            
            # Undo substitution
            for i in range(len(data_array) - 1, -1, -1):
                row = i % len(self.connection_matrix)
                col = (i + round) % len(self.connection_matrix[0])
                matrix_val = self.connection_matrix[row][col]
                key_byte = circuit_key[i % len(circuit_key)]
                # Ensure key_byte is an integer
                if isinstance(key_byte, str):
                    key_byte = ord(key_byte)
                data_array[i] = (data_array[i] - (key_byte ^ matrix_val)) % 256
        
        reversed_transform = bytes(data_array)
        
        # Remove padding
        unpadder = padding.PKCS7(128).unpadder()
        plaintext = unpadder.update(reversed_transform) + unpadder.finalize()
        
        return plaintext.decode('utf-8')


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
    
    # Map logic gates to operations
    logic_gate_map = {
        'AND': 'result = (byte1 & byte2)',
        'OR': 'result = (byte1 | byte2)',
        'XOR': 'result = (byte1 ^ byte2)',
        'NOT': 'result = (~byte1 & 0xFF)',
        'NAND': 'result = (~(byte1 & byte2) & 0xFF)',
        'NOR': 'result = (~(byte1 | byte2) & 0xFF)',
        'BUFFER': 'result = byte1'
    }
    
    # Construct logic operations
    logic_gates = circuit_analysis['logic_gates']
    logic_ops = [logic_gate_map.get(gate.get('type', 'BUFFER'), 'result = byte1') 
                for gate in logic_gates]
    
    # Add default if no logic gates
    if not logic_ops:
        logic_ops = ['result = (byte1 ^ byte2)', 
                    'result = ((result << 1) | (result >> 7)) & 0xFF']
    
    # Convert logic operations to lambda functions
    logic_lambdas = []
    for op in logic_ops:
        # Create a function from the operation string
        logic_lambdas.append(f"lambda byte1, byte2: {op}")
    
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

# API Routes
@app.route('/api/generate_encryption', methods=['POST'])
def api_generate_encryption():
    """Generate encryption algorithm from circuit data"""
    try:
        circuit_data = request.get_json()
        
        if not circuit_data or 'cards' not in circuit_data:
            return jsonify({'error': 'Missing required circuit data'}), 400
        
        analysis = analyze_circuit(circuit_data)
        algorithm = generate_encryption_algorithm(analysis)
        
        encryption_records.append({
            'timestamp': time.time(),
            'cards_count': len(circuit_data.get('cards', [])),
            'complexity': analysis['summary']['complexity_score'],
            'algorithm_size': len(algorithm)
        })
        
        return jsonify({
            'algorithm': algorithm,
            'analysis': analysis['summary']
        })
    
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/api/history', methods=['GET'])
def api_history():
    """Get history of encryption algorithms generated"""
    return jsonify({'records': encryption_records})

@app.route('/', defaults={'path': ''})
@app.route('/<path:path>')
def serve(path):
    """Serve the React frontend"""
    if path != "" and os.path.exists(app.static_folder + '/' + path):
        return send_from_directory(app.static_folder, path)
    return send_from_directory(app.static_folder, 'index.html')

@app.route('/api/status')
def api_status():
    """API status check endpoint"""
    return jsonify({
        'status': 'online',
        'version': '1.0.0',
        'endpoints': ['/api/generate_encryption', '/api/history', '/api/status']
    })

if __name__ == '__main__':
    port = int(os.environ.get('PORT', 5000))
    app.run(host='0.0.0.0', port=port) 