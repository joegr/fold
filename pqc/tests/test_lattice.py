"""Tests for post-quantum circuit lattice encryption."""

import pytest
from lattice import (
    derive_lattice_params,
    CircuitLatticeKEM,
    CircuitCipher,
    PostQuantumCircuitEncryption,
)


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------

SIMPLE_ANALYSIS = {
    "summary": {
        "num_cards": 1,
        "card_types": ["logic"],
        "card_colors": ["#4a6fa5"],
        "num_nodes": 3,
        "num_connections": 0,
        "num_mesh_points": 3,
        "num_logic_gates": 1,
        "logic_gate_types": ["AND"],
        "complexity_score": 9,
    },
    "connections": [],
    "logic_gates": [{"id": "g1", "type": "AND", "x": 0.5, "y": 0.5}],
    "mesh_points": [],
    "mesh_connections": [],
    "nodes": [],
}

COMPLEX_ANALYSIS = {
    "summary": {
        "num_cards": 3,
        "card_types": ["logic", "matrix", "hybrid"],
        "card_colors": ["#4a6fa5", "#a56b4a", "#6aa54a"],
        "num_nodes": 12,
        "num_connections": 4,
        "num_mesh_points": 8,
        "num_logic_gates": 3,
        "logic_gate_types": ["AND", "XOR", "OR"],
        "complexity_score": 45,
    },
    "connections": [
        {"fromX": 0.1, "fromY": 0.2, "toX": 0.9, "toY": 0.8},
        {"fromX": 0.1, "fromY": 0.4, "toX": 0.9, "toY": 0.6},
        {"fromX": 0.5, "fromY": 0.5, "toX": 0.9, "toY": 0.3},
        {"fromX": 0.5, "fromY": 0.5, "toX": 0.9, "toY": 0.7},
    ],
    "logic_gates": [
        {"id": "g1", "type": "AND", "x": 0.3, "y": 0.5},
        {"id": "g2", "type": "XOR", "x": 0.5, "y": 0.5},
        {"id": "g3", "type": "OR",  "x": 0.7, "y": 0.5},
    ],
    "mesh_points": [],
    "mesh_connections": [],
    "nodes": [],
}


# ---------------------------------------------------------------------------
# Lattice param derivation
# ---------------------------------------------------------------------------

class TestDeriveParams:
    def test_returns_required_keys(self):
        p = derive_lattice_params(SIMPLE_ANALYSIS)
        for key in ("kem_algorithm", "seed", "binding_vector", "noise_vector", "gate_mod"):
            assert key in p

    def test_deterministic(self):
        p1 = derive_lattice_params(SIMPLE_ANALYSIS)
        p2 = derive_lattice_params(SIMPLE_ANALYSIS)
        assert p1["binding_vector"] == p2["binding_vector"]
        assert p1["seed"] == p2["seed"]

    def test_different_circuits_differ(self):
        p1 = derive_lattice_params(SIMPLE_ANALYSIS)
        p2 = derive_lattice_params(COMPLEX_ANALYSIS)
        assert p1["binding_vector"] != p2["binding_vector"]
        assert p1["circuit_seed_hex"] != p2["circuit_seed_hex"]

    def test_kem_algorithm_is_ml_kem_768(self):
        p = derive_lattice_params(SIMPLE_ANALYSIS)
        assert p["kem_algorithm"] == "ML-KEM-768"

    def test_gate_mod_is_positive(self):
        p = derive_lattice_params(COMPLEX_ANALYSIS)
        assert 0 < p["gate_mod"] < 257


# ---------------------------------------------------------------------------
# KEM round-trip
# ---------------------------------------------------------------------------

class TestKEM:
    def test_encap_decap_round_trip(self):
        params = derive_lattice_params(SIMPLE_ANALYSIS)
        kem = CircuitLatticeKEM(params)
        pk, sk = kem.generate_keypair()
        kem_ct, aes_key_sender = kem.encapsulate(pk)
        aes_key_recipient = kem.decapsulate(sk, kem_ct)
        assert aes_key_sender == aes_key_recipient
        assert len(aes_key_sender) == 32

    def test_different_topologies_produce_different_keys(self):
        p1 = derive_lattice_params(SIMPLE_ANALYSIS)
        p2 = derive_lattice_params(COMPLEX_ANALYSIS)
        kem1 = CircuitLatticeKEM(p1)
        kem2 = CircuitLatticeKEM(p2)
        pk, sk = kem1.generate_keypair()
        ct, key1 = kem1.encapsulate(pk)
        key2 = kem2.decapsulate(sk, ct)
        # Different binding vectors → different AES keys even from same ML-KEM shared secret
        assert key1 != key2

    def test_keypair_size_ml_kem_768(self):
        params = derive_lattice_params(SIMPLE_ANALYSIS)
        kem = CircuitLatticeKEM(params)
        pk, sk = kem.generate_keypair()
        assert len(pk) == 1184   # ML-KEM-768 public key
        assert len(sk) == 2400   # ML-KEM-768 secret key


# ---------------------------------------------------------------------------
# Symmetric cipher
# ---------------------------------------------------------------------------

class TestCircuitCipher:
    def _make_key(self):
        import os
        return os.urandom(32)

    def test_encrypt_decrypt_str(self):
        params = derive_lattice_params(SIMPLE_ANALYSIS)
        cipher = CircuitCipher(params)
        key = self._make_key()
        ct = cipher.encrypt("hello post-quantum world", key)
        pt = cipher.decrypt(ct, key)
        assert pt == b"hello post-quantum world"

    def test_encrypt_decrypt_bytes(self):
        params = derive_lattice_params(SIMPLE_ANALYSIS)
        cipher = CircuitCipher(params)
        key = self._make_key()
        data = bytes(range(256))
        ct = cipher.encrypt(data, key)
        assert cipher.decrypt(ct, key) == data

    def test_wrong_key_fails(self):
        params = derive_lattice_params(SIMPLE_ANALYSIS)
        cipher = CircuitCipher(params)
        key = self._make_key()
        ct = cipher.encrypt("secret", key)
        with pytest.raises(Exception):
            cipher.decrypt(ct, self._make_key())

    def test_aad_mismatch_fails(self):
        """Different circuit topology → different AAD → decryption failure."""
        p1 = derive_lattice_params(SIMPLE_ANALYSIS)
        p2 = derive_lattice_params(COMPLEX_ANALYSIS)
        c1 = CircuitCipher(p1)
        c2 = CircuitCipher(p2)
        key = self._make_key()
        ct = c1.encrypt("secret", key)
        with pytest.raises(Exception):
            c2.decrypt(ct, key)


# ---------------------------------------------------------------------------
# Full pipeline
# ---------------------------------------------------------------------------

class TestPostQuantumCircuitEncryption:
    def test_simple_round_trip(self):
        enc = PostQuantumCircuitEncryption.from_analysis(SIMPLE_ANALYSIS)
        pk, sk = enc.generate_keypair()
        kem_ct, payload = enc.encrypt("hello", pk)
        result = enc.decrypt(kem_ct, payload, sk)
        assert result == b"hello"

    def test_complex_round_trip(self):
        enc = PostQuantumCircuitEncryption.from_analysis(COMPLEX_ANALYSIS)
        pk, sk = enc.generate_keypair()
        msg = b"\x00\xFF" * 512
        kem_ct, payload = enc.encrypt(msg, pk)
        assert enc.decrypt(kem_ct, payload, sk) == msg

    def test_describe_reports_pq_secure(self):
        enc = PostQuantumCircuitEncryption.from_analysis(SIMPLE_ANALYSIS)
        d = enc.describe()
        assert d["pq_secure"] is True
        assert d["kem_algorithm"] == "ML-KEM-768"
        assert d["symmetric"] == "AES-256-GCM"

    def test_cross_topology_isolation(self):
        enc1 = PostQuantumCircuitEncryption.from_analysis(SIMPLE_ANALYSIS)
        enc2 = PostQuantumCircuitEncryption.from_analysis(COMPLEX_ANALYSIS)
        pk1, sk1 = enc1.generate_keypair()
        kem_ct, payload = enc1.encrypt("isolated", pk1)
        with pytest.raises(Exception):
            enc2.decrypt(kem_ct, payload, sk1)
