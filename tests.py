#!/usr/bin/env python3
import unittest
import sys
import os
import json
import random
import string
import numpy as np
import inspect
import tempfile
from io import StringIO

# Import the CircuitEncryption class and other functions from app.py
from app import CircuitEncryption, analyze_circuit, generate_encryption_algorithm

class TestCipherAlgorithms(unittest.TestCase):
    """Test suite for cipher algorithms generated from circuit configurations."""
    
    def setUp(self):
        """Set up test environment before each test."""
        # Create default test data
        self.test_data = "Hello, this is a test message for encryption and decryption!"
        self.test_key = "SecretKey123"
        
        # Create a simple circuit configuration for testing
        self.simple_circuit = {
            'cards': [
                {
                    'id': 'card1',
                    'type': 'processor',
                    'color': 'blue',
                    'nodes': [{'id': 'node1', 'x': 0.1, 'y': 0.2}, {'id': 'node2', 'x': 0.8, 'y': 0.3}],
                    'matrixConnections': [
                        {'id': 'conn1', 'active': True, 'fromX': 0.1, 'fromY': 0.2, 'toX': 0.8, 'toY': 0.3}
                    ],
                    'meshInteractionPoints': [{'id': 'mesh1', 'x': 0.5, 'y': 0.5, 'upConnections': [], 'downConnections': []}],
                    'logicGates': [{'id': 'gate1', 'type': 'XOR', 'x': 0.4, 'y': 0.4}]
                },
                {
                    'id': 'card2',
                    'type': 'memory',
                    'color': 'green',
                    'nodes': [{'id': 'node3', 'x': 0.2, 'y': 0.6}, {'id': 'node4', 'x': 0.7, 'y': 0.9}],
                    'matrixConnections': [
                        {'id': 'conn2', 'active': True, 'fromX': 0.2, 'fromY': 0.6, 'toX': 0.7, 'toY': 0.9}
                    ],
                    'meshInteractionPoints': [{'id': 'mesh2', 'x': 0.5, 'y': 0.5, 'upConnections': [], 'downConnections': ['mesh1']}],
                    'logicGates': [{'id': 'gate2', 'type': 'AND', 'x': 0.6, 'y': 0.3}]
                }
            ]
        }
        
        # Create a complex circuit with more cards and different logic gates
        self.complex_circuit = {
            'cards': [
                # Similar structure as simple_circuit but with more cards and varied logic gates
                {
                    'id': 'card1',
                    'type': 'processor',
                    'color': 'blue',
                    'nodes': [{'id': 'node1', 'x': 0.1, 'y': 0.2}, {'id': 'node2', 'x': 0.8, 'y': 0.3}],
                    'matrixConnections': [
                        {'id': 'conn1', 'active': True, 'fromX': 0.1, 'fromY': 0.2, 'toX': 0.8, 'toY': 0.3}
                    ],
                    'meshInteractionPoints': [{'id': 'mesh1', 'x': 0.5, 'y': 0.5, 'upConnections': ['mesh2'], 'downConnections': []}],
                    'logicGates': [{'id': 'gate1', 'type': 'XOR', 'x': 0.4, 'y': 0.4}]
                },
                {
                    'id': 'card2',
                    'type': 'memory',
                    'color': 'green',
                    'nodes': [{'id': 'node3', 'x': 0.2, 'y': 0.6}, {'id': 'node4', 'x': 0.7, 'y': 0.9}],
                    'matrixConnections': [
                        {'id': 'conn2', 'active': True, 'fromX': 0.2, 'fromY': 0.6, 'toX': 0.7, 'toY': 0.9}
                    ],
                    'meshInteractionPoints': [{'id': 'mesh2', 'x': 0.5, 'y': 0.5, 'upConnections': ['mesh3'], 'downConnections': ['mesh1']}],
                    'logicGates': [{'id': 'gate2', 'type': 'AND', 'x': 0.6, 'y': 0.3}]
                },
                {
                    'id': 'card3',
                    'type': 'io',
                    'color': 'red',
                    'nodes': [{'id': 'node5', 'x': 0.3, 'y': 0.3}, {'id': 'node6', 'x': 0.9, 'y': 0.8}],
                    'matrixConnections': [
                        {'id': 'conn3', 'active': True, 'fromX': 0.3, 'fromY': 0.3, 'toX': 0.9, 'toY': 0.8}
                    ],
                    'meshInteractionPoints': [{'id': 'mesh3', 'x': 0.5, 'y': 0.5, 'upConnections': [], 'downConnections': ['mesh2']}],
                    'logicGates': [{'id': 'gate3', 'type': 'OR', 'x': 0.2, 'y': 0.7}]
                },
                {
                    'id': 'card4',
                    'type': 'custom',
                    'color': 'yellow',
                    'nodes': [{'id': 'node7', 'x': 0.4, 'y': 0.1}, {'id': 'node8', 'x': 0.6, 'y': 0.5}],
                    'matrixConnections': [
                        {'id': 'conn4', 'active': True, 'fromX': 0.4, 'fromY': 0.1, 'toX': 0.6, 'toY': 0.5}
                    ],
                    'meshInteractionPoints': [{'id': 'mesh4', 'x': 0.5, 'y': 0.5, 'upConnections': [], 'downConnections': []}],
                    'logicGates': [{'id': 'gate4', 'type': 'NAND', 'x': 0.3, 'y': 0.8}]
                },
                {
                    'id': 'card5',
                    'type': 'network',
                    'color': 'purple',
                    'nodes': [{'id': 'node9', 'x': 0.1, 'y': 0.9}, {'id': 'node10', 'x': 0.5, 'y': 0.7}],
                    'matrixConnections': [
                        {'id': 'conn5', 'active': True, 'fromX': 0.1, 'fromY': 0.9, 'toX': 0.5, 'toY': 0.7}
                    ],
                    'meshInteractionPoints': [{'id': 'mesh5', 'x': 0.5, 'y': 0.5, 'upConnections': [], 'downConnections': []}],
                    'logicGates': [{'id': 'gate5', 'type': 'NOR', 'x': 0.7, 'y': 0.2}]
                }
            ]
        }
    
    def test_base_class(self):
        """Test the base CircuitEncryption class with default parameters."""
        # Create instance with default parameters
        cipher = CircuitEncryption()
        
        # Test encryption and decryption
        encrypted = cipher.encrypt(self.test_data, self.test_key)
        decrypted = cipher.decrypt(encrypted, self.test_key)
        
        # Verify that decryption produces the original text
        self.assertEqual(self.test_data, decrypted)
        
        # Test with binary data
        binary_data = os.urandom(100)  # 100 random bytes
        encrypted = cipher.encrypt(binary_data, self.test_key)
        decrypted = cipher.decrypt(encrypted, self.test_key)
        
        # Convert the decrypted data back to bytes for comparison
        if isinstance(decrypted, str):
            decrypted = decrypted.encode('utf-8')
            
        self.assertEqual(binary_data, decrypted)

    def test_custom_parameters(self):
        """Test the CircuitEncryption class with custom parameters."""
        # Create custom parameters
        custom_constants = {
            'KEY_ROUNDS': 10,
            'MATRIX_SIZE': 16,
            'PERMUTATION_ROUNDS': 5,
            'CIRCUIT_SEED': '1234567890abcdef'
        }
        
        custom_matrix = [[random.randint(0, 255) for _ in range(16)] for _ in range(16)]
        
        custom_operations = [
            lambda byte1, byte2: (byte1 & byte2),
            lambda byte1, byte2: (byte1 | byte2),
            lambda byte1, byte2: (byte1 ^ byte2)
        ]
        
        # Create instance with custom parameters
        cipher = CircuitEncryption(
            key_derivation_constants=custom_constants,
            connection_matrix=custom_matrix,
            logic_operations=custom_operations
        )
        
        # Test key derivation
        key = cipher.derive_key(self.test_key)
        self.assertEqual(len(key), 32)  # Should be 32 bytes for AES-256
        
        # Test encryption and decryption with custom parameters
        encrypted = cipher.encrypt(self.test_data, self.test_key)
        decrypted = cipher.decrypt(encrypted, self.test_key)
        
        self.assertEqual(self.test_data, decrypted)

    def test_simple_circuit_algorithm(self):
        """Test encryption algorithm generated from a simple circuit."""
        # Analyze the circuit
        analysis = analyze_circuit(self.simple_circuit)
        
        # Generate the algorithm code
        algorithm_code = generate_encryption_algorithm(analysis)
        
        # Save the algorithm to a temporary file and import it
        with tempfile.NamedTemporaryFile(suffix='.py', delete=False, mode='w') as f:
            f.write(algorithm_code)
            temp_module_path = f.name
        
        # Dynamically import the generated module
        temp_module_name = os.path.basename(temp_module_path).replace('.py', '')
        temp_module_dir = os.path.dirname(temp_module_path)
        
        # Add the directory to the Python path
        sys.path.insert(0, temp_module_dir)
        
        try:
            # Import the module
            temp_module = __import__(temp_module_name)
            
            # Create an instance of the encryption class
            cipher = temp_module.CircuitEncryption()
            
            # Test encryption and decryption
            encrypted = cipher.encrypt(self.test_data, self.test_key)
            decrypted = cipher.decrypt(encrypted, self.test_key)
            
            self.assertEqual(self.test_data, decrypted)
        finally:
            # Clean up
            if temp_module_name in sys.modules:
                del sys.modules[temp_module_name]
            sys.path.remove(temp_module_dir)
            os.unlink(temp_module_path)

    def test_complex_circuit_algorithm(self):
        """Test encryption algorithm generated from a complex circuit."""
        # Analyze the circuit
        analysis = analyze_circuit(self.complex_circuit)
        
        # Generate the algorithm code
        algorithm_code = generate_encryption_algorithm(analysis)
        
        # Save the algorithm to a temporary file and import it
        with tempfile.NamedTemporaryFile(suffix='.py', delete=False, mode='w') as f:
            f.write(algorithm_code)
            temp_module_path = f.name
        
        # Dynamically import the generated module
        temp_module_name = os.path.basename(temp_module_path).replace('.py', '')
        temp_module_dir = os.path.dirname(temp_module_path)
        
        # Add the directory to the Python path
        sys.path.insert(0, temp_module_dir)
        
        try:
            # Import the module
            temp_module = __import__(temp_module_name)
            
            # Create an instance of the encryption class
            cipher = temp_module.CircuitEncryption()
            
            # Test encryption and decryption with different data types
            
            # Test with string
            encrypted = cipher.encrypt(self.test_data, self.test_key)
            decrypted = cipher.decrypt(encrypted, self.test_key)
            self.assertEqual(self.test_data, decrypted)
            
            # Test with binary data
            binary_data = os.urandom(100)
            encrypted = cipher.encrypt(binary_data, self.test_key)
            decrypted = cipher.decrypt(encrypted, self.test_key)
            if isinstance(decrypted, str):
                decrypted = decrypted.encode('utf-8')
            self.assertEqual(binary_data, decrypted)
            
            # Test with empty string
            encrypted = cipher.encrypt("", self.test_key)
            decrypted = cipher.decrypt(encrypted, self.test_key)
            self.assertEqual("", decrypted)
            
            # Test with very long string
            long_string = ''.join(random.choice(string.ascii_letters) for _ in range(10000))
            encrypted = cipher.encrypt(long_string, self.test_key)
            decrypted = cipher.decrypt(encrypted, self.test_key)
            self.assertEqual(long_string, decrypted)
        finally:
            # Clean up
            if temp_module_name in sys.modules:
                del sys.modules[temp_module_name]
            sys.path.remove(temp_module_dir)
            os.unlink(temp_module_path)

    def test_key_derivation(self):
        """Test the key derivation function with different inputs."""
        cipher = CircuitEncryption()
        
        # Test with string key
        key1 = cipher.derive_key("test_key")
        self.assertEqual(len(key1), 32)
        
        # Test with bytes key - use a different input to ensure a different key
        key2 = cipher.derive_key(b"different_test_key")
        self.assertEqual(len(key2), 32)
        
        # Test with empty key
        key3 = cipher.derive_key("")
        self.assertEqual(len(key3), 32)
        
        # Test with long key
        long_key = "A" * 1000
        key4 = cipher.derive_key(long_key)
        self.assertEqual(len(key4), 32)
        
        # Keys derived from different inputs should be different
        self.assertNotEqual(key1, key2)
        self.assertNotEqual(key1, key3)
        self.assertNotEqual(key1, key4)

    def test_circuit_transformation(self):
        """Test the circuit transformation function."""
        cipher = CircuitEncryption()
        
        # Test with sample data
        data = b"Sample data for transformation"
        key = cipher.derive_key(self.test_key)
        
        # Apply transformation
        transformed = cipher.apply_circuit_transformation(data, key)
        
        # Verify the transformation produces output of the same length
        self.assertEqual(len(transformed), len(data))
        
        # Transformation should change the data
        self.assertNotEqual(transformed, data)

    def test_different_circuit_configurations(self):
        """Test encryption/decryption with different circuit configurations."""
        # Define a list of circuit configurations to test
        circuit_configs = [
            self.simple_circuit,
            self.complex_circuit,
            # Create a circuit with only one card
            {
                'cards': [self.simple_circuit['cards'][0]]
            },
            # Create a circuit with no logic gates
            {
                'cards': [{
                    'id': 'card1',
                    'type': 'basic',
                    'color': 'gray',
                    'nodes': [{'id': 'node1', 'x': 0.1, 'y': 0.2}],
                    'matrixConnections': [],
                    'meshInteractionPoints': [],
                    'logicGates': []
                }]
            }
        ]
        
        for idx, circuit_config in enumerate(circuit_configs):
            # Analyze the circuit
            analysis = analyze_circuit(circuit_config)
            
            # Generate the algorithm code
            algorithm_code = generate_encryption_algorithm(analysis)
            
            # Execute the algorithm code in a new namespace
            namespace = {}
            exec(algorithm_code, namespace)
            
            # Create an instance of the encryption class
            cipher = namespace['CircuitEncryption']()
            
            # Test encryption and decryption
            test_data = f"Test data for circuit configuration {idx}"
            encrypted = cipher.encrypt(test_data, self.test_key)
            decrypted = cipher.decrypt(encrypted, self.test_key)
            
            self.assertEqual(test_data, decrypted)

    def test_algorithm_isolation(self):
        """Test that algorithms generated from different circuits produce different results."""
        # Analyze the circuits
        simple_analysis = analyze_circuit(self.simple_circuit)
        complex_analysis = analyze_circuit(self.complex_circuit)
        
        # Generate the algorithm codes
        simple_algorithm_code = generate_encryption_algorithm(simple_analysis)
        complex_algorithm_code = generate_encryption_algorithm(complex_analysis)
        
        # Execute the algorithm codes in separate namespaces
        simple_namespace = {}
        complex_namespace = {}
        
        exec(simple_algorithm_code, simple_namespace)
        exec(complex_algorithm_code, complex_namespace)
        
        # Create instances of the encryption classes
        simple_cipher = simple_namespace['CircuitEncryption']()
        complex_cipher = complex_namespace['CircuitEncryption']()
        
        # Encrypt the same data with both ciphers
        encrypted_simple = simple_cipher.encrypt(self.test_data, self.test_key)
        encrypted_complex = complex_cipher.encrypt(self.test_data, self.test_key)
        
        # The encrypted results should be different
        self.assertNotEqual(encrypted_simple, encrypted_complex)
        
        # But each should decrypt correctly with its own algorithm
        decrypted_simple = simple_cipher.decrypt(encrypted_simple, self.test_key)
        decrypted_complex = complex_cipher.decrypt(encrypted_complex, self.test_key)
        
        self.assertEqual(self.test_data, decrypted_simple)
        self.assertEqual(self.test_data, decrypted_complex)
        
        # Test that they cannot decrypt each other's output
        with self.assertRaises(Exception):
            simple_cipher.decrypt(encrypted_complex, self.test_key)
        
        with self.assertRaises(Exception):
            complex_cipher.decrypt(encrypted_simple, self.test_key)

if __name__ == '__main__':
    unittest.main() 