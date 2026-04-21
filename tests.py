#!/usr/bin/env python3
"""Tests for the rewritten CircuitEncryption (AES-256-GCM + scrypt + HKDF).

The previous test suite exercised a homegrown AES-CBC + ad-hoc transformation
pipeline with methods like `derive_key` and `apply_circuit_transformation`.
Those methods are gone on purpose — homegrown crypto is no longer part of the
public API. The tests below validate the new contract:

  CircuitEncryption(circuit_params=None)
    .encrypt(plaintext, password) -> bytes (base64)
    .decrypt(ciphertext, password) -> str | bytes

  create_encryption_from_analysis(analysis) -> CircuitEncryption
  derive_circuit_parameters(analysis) -> dict

Before running, set dummy env vars so app.py can import:

    API_KEY=test-key SECRET_KEY=$(python -c 'import os;print(os.urandom(32).hex())') \\
        python -m unittest tests -v
"""
import os
import random
import string
import unittest

# Ensure required env vars exist before importing app.py.
os.environ.setdefault('API_KEY', 'test-api-key')
os.environ.setdefault('SECRET_KEY', 'test-secret-key-' + 'a' * 32)
# Use a low scrypt cost for test speed.
os.environ.setdefault('SCRYPT_N', '1024')

from app import (  # noqa: E402
    CircuitEncryption,
    analyze_circuit,
    create_encryption_from_analysis,
    derive_circuit_parameters,
    validate_circuit_data,
)


class TestCircuitEncryption(unittest.TestCase):
    def setUp(self):
        self.test_data = "Hello, this is a test message for encryption and decryption!"
        self.test_key = "SecretKey123"

        self.simple_circuit = {
            'cards': [
                {
                    'id': 'card1',
                    'type': 'processor',
                    'color': 'blue',
                    'nodes': [{'id': 'n1', 'x': 0.1, 'y': 0.2}, {'id': 'n2', 'x': 0.8, 'y': 0.3}],
                    'matrixConnections': [
                        {'id': 'c1', 'active': True, 'fromX': 0.1, 'fromY': 0.2, 'toX': 0.8, 'toY': 0.3}
                    ],
                    'meshInteractionPoints': [{'id': 'm1', 'x': 0.5, 'y': 0.5, 'upConnections': [], 'downConnections': []}],
                    'logicGates': [{'id': 'g1', 'type': 'XOR', 'x': 0.4, 'y': 0.4}],
                },
                {
                    'id': 'card2',
                    'type': 'memory',
                    'color': 'green',
                    'nodes': [{'id': 'n3', 'x': 0.2, 'y': 0.6}, {'id': 'n4', 'x': 0.7, 'y': 0.9}],
                    'matrixConnections': [
                        {'id': 'c2', 'active': True, 'fromX': 0.2, 'fromY': 0.6, 'toX': 0.7, 'toY': 0.9}
                    ],
                    'meshInteractionPoints': [{'id': 'm2', 'x': 0.5, 'y': 0.5, 'upConnections': [], 'downConnections': ['m1']}],
                    'logicGates': [{'id': 'g2', 'type': 'AND', 'x': 0.6, 'y': 0.3}],
                },
            ],
        }

        self.complex_circuit = {
            'cards': self.simple_circuit['cards'] + [
                {
                    'id': f'card{i}',
                    'type': t,
                    'color': 'red',
                    'nodes': [{'id': f'n{i}a', 'x': 0.3, 'y': 0.3}],
                    'matrixConnections': [
                        {'id': f'c{i}', 'active': True, 'fromX': 0.3, 'fromY': 0.3, 'toX': 0.9, 'toY': 0.8}
                    ],
                    'meshInteractionPoints': [],
                    'logicGates': [{'id': f'g{i}', 'type': g, 'x': 0.2, 'y': 0.7}],
                }
                for i, (t, g) in enumerate(
                    [('io', 'OR'), ('custom', 'NAND'), ('network', 'NOR')], start=3
                )
            ],
        }

    # -- basic roundtrip ---------------------------------------------------
    def test_default_roundtrip_string(self):
        cipher = CircuitEncryption()
        enc = cipher.encrypt(self.test_data, self.test_key)
        self.assertEqual(cipher.decrypt(enc, self.test_key), self.test_data)

    def test_default_roundtrip_binary(self):
        cipher = CircuitEncryption()
        blob = os.urandom(256)
        enc = cipher.encrypt(blob, self.test_key)
        dec = cipher.decrypt(enc, self.test_key)
        if isinstance(dec, str):
            dec = dec.encode('utf-8')
        self.assertEqual(dec, blob)

    def test_empty_plaintext(self):
        cipher = CircuitEncryption()
        enc = cipher.encrypt('', self.test_key)
        self.assertEqual(cipher.decrypt(enc, self.test_key), '')

    def test_long_plaintext(self):
        cipher = CircuitEncryption()
        long_s = ''.join(random.choice(string.ascii_letters) for _ in range(10_000))
        enc = cipher.encrypt(long_s, self.test_key)
        self.assertEqual(cipher.decrypt(enc, self.test_key), long_s)

    # -- integrity / auth --------------------------------------------------
    def test_wrong_password_fails(self):
        cipher = CircuitEncryption()
        enc = cipher.encrypt(self.test_data, self.test_key)
        with self.assertRaises(Exception):
            cipher.decrypt(enc, 'WrongPassword')

    def test_tampered_ciphertext_fails(self):
        import base64
        cipher = CircuitEncryption()
        enc = cipher.encrypt(self.test_data, self.test_key)
        raw = bytearray(base64.b64decode(enc))
        # flip a byte deep in the ciphertext/tag
        raw[-5] ^= 0x01
        tampered = base64.b64encode(bytes(raw))
        with self.assertRaises(Exception):
            cipher.decrypt(tampered, self.test_key)

    def test_different_ciphertexts_each_call(self):
        """Encryption is randomized via per-message salt+nonce."""
        cipher = CircuitEncryption()
        a = cipher.encrypt(self.test_data, self.test_key)
        b = cipher.encrypt(self.test_data, self.test_key)
        self.assertNotEqual(a, b)

    def test_format_version_prefix(self):
        import base64
        cipher = CircuitEncryption()
        enc = cipher.encrypt('hello', self.test_key)
        self.assertTrue(base64.b64decode(enc).startswith(b'FOLD2'))

    # -- circuit-binding semantics ----------------------------------------
    def test_different_circuits_produce_different_ciphertexts(self):
        simple = create_encryption_from_analysis(analyze_circuit(self.simple_circuit))
        complex_ = create_encryption_from_analysis(analyze_circuit(self.complex_circuit))
        a = simple.encrypt(self.test_data, self.test_key)
        b = complex_.encrypt(self.test_data, self.test_key)
        self.assertNotEqual(a, b)

    def test_cross_circuit_decrypt_rejected(self):
        simple = create_encryption_from_analysis(analyze_circuit(self.simple_circuit))
        complex_ = create_encryption_from_analysis(analyze_circuit(self.complex_circuit))
        enc = simple.encrypt(self.test_data, self.test_key)
        with self.assertRaises(Exception):
            complex_.decrypt(enc, self.test_key)

    def test_each_circuit_roundtrips_itself(self):
        for circuit in (self.simple_circuit, self.complex_circuit):
            cipher = create_encryption_from_analysis(analyze_circuit(circuit))
            enc = cipher.encrypt(self.test_data, self.test_key)
            self.assertEqual(cipher.decrypt(enc, self.test_key), self.test_data)

    # -- parameter object --------------------------------------------------
    def test_derive_parameters_shape(self):
        params = derive_circuit_parameters(analyze_circuit(self.simple_circuit))
        self.assertEqual(params['version'], 2)
        self.assertEqual(params['algorithm'], 'AES-256-GCM')
        self.assertIn('scrypt', params['kdf'])
        self.assertIn('HKDF', params['kdf'])
        self.assertEqual(len(params['circuit_seed']), 32)
        self.assertIn('summary', params)

    # -- input validation still works -------------------------------------
    def test_validate_circuit_data_rejects_non_object(self):
        cleaned, err = validate_circuit_data("not a dict")
        self.assertIsNone(cleaned)
        self.assertIsNotNone(err)

    def test_validate_circuit_data_rejects_empty(self):
        cleaned, err = validate_circuit_data({'cards': []})
        self.assertIsNone(cleaned)
        self.assertIsNotNone(err)

    def test_validate_circuit_data_clamps_unknown_types(self):
        cleaned, err = validate_circuit_data({
            'cards': [{
                'id': 'x', 'type': 'NOT_A_REAL_TYPE', 'color': 'gray',
                'nodes': [], 'matrixConnections': [],
                'meshInteractionPoints': [],
                'logicGates': [{'id': 'g', 'type': 'BOGUS', 'x': 0, 'y': 0}],
            }],
        })
        self.assertIsNone(err)
        self.assertEqual(cleaned['cards'][0]['type'], 'basic')
        self.assertEqual(cleaned['cards'][0]['logicGates'][0]['type'], 'BUFFER')


if __name__ == '__main__':
    unittest.main()
