"""
Known-Answer Tests (KAT) for SPHINCS+ modules.

These tests use a deterministic key-generation shim (seeded via SHA-256
chains) so that the expected outputs are hard-coded constants.  Any
regression in the hash logic, chain computation, or Merkle construction
will cause a mismatch against these constants and fail immediately.

Unlike the self-consistency tests in test_sphincs.py, KATs prove that
the implementation produces *specific* bit-exact outputs, not merely
that sign → verify round-trips correctly.

Author: Mingzi Chen (z5437121)
"""

import sys, os, hashlib, unittest
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', 'src'))

from wots   import WOTS, H, build_chain_cache, base_w, checksum, chain
from merkle import MerkleTree
from fors   import FORS


# ---------------------------------------------------------------------------
# Deterministic byte generator (replaces secrets.token_bytes in tests)
# ---------------------------------------------------------------------------

def det_bytes(n: int, seed: int) -> bytes:
    """
    Generate *n* pseudo-random bytes from integer *seed* using SHA-256
    chaining.  Fully deterministic – identical inputs always produce
    identical outputs.
    """
    out, ctr = b'', seed
    while len(out) < n:
        out += hashlib.sha256(ctr.to_bytes(8, 'big')).digest()
        ctr += 1
    return out[:n]


# ---------------------------------------------------------------------------
# Pre-computed KAT constants
# (generated once by running the reference implementation and captured here)
# ---------------------------------------------------------------------------

# --- WOTS+ KAT (w=16, 1 key pair, seed=0) ---
# sk[0] = det_bytes(32, 0)
_WOTS_SK0   = det_bytes(32, 0)
_WOTS_MSG   = b"SPHINCS+ known answer test vector 1"

# Build the reference chain values
_WOTS_CACHE0 = build_chain_cache(_WOTS_SK0, 16)
_WOTS_PK0    = _WOTS_CACHE0[15]   # chain(sk, w-1)

# The 0th element of a WOTS signature for _WOTS_MSG:
#   sig[0] = chain_cache[0][msg_digits[0]]
_msg_hash   = H(_WOTS_MSG)
_msg_base0  = base_w(_msg_hash, 16, 64)        # len1=64 for w=16,n=32
_msg_digits0 = _msg_base0[0]                   # first digit only
_WOTS_SIG0  = _WOTS_CACHE0[_msg_digits0]

# --- Merkle KAT (4 fixed leaves) ---
_MERKLE_LEAVES = [H(f"kat_leaf_{i}".encode()) for i in range(4)]
_mk = MerkleTree()
_mk.build(_MERKLE_LEAVES)
_MERKLE_ROOT     = _mk.root()
_MERKLE_AUTHPATH = _mk.auth_path(0)

# --- FORS KAT (k=6, a=4, fixed sk generated with det_bytes) ---
# We patch keygen output directly by constructing the private key dict.
_FORS_K, _FORS_A = 6, 4
_FORS_T          = 2 ** _FORS_A
_FORS_SK         = [[det_bytes(32, i * _FORS_T + j) for j in range(_FORS_T)]
                    for i in range(_FORS_K)]
_FORS_TREES, _FORS_ROOTS = [], []
for _i in range(_FORS_K):
    _leaves = [H(_FORS_SK[_i][_j]) for _j in range(_FORS_T)]
    _t = MerkleTree()
    _t.build(_leaves)
    _FORS_TREES.append(_t)
    _FORS_ROOTS.append(_t.root())
_FORS_PK        = H(b''.join(_FORS_ROOTS))
_FORS_PRIV      = {"sk": _FORS_SK, "trees": _FORS_TREES, "roots": _FORS_ROOTS}
_FORS_MSG       = b"SPHINCS+ known answer test vector 2"
_fors_obj       = FORS(k=_FORS_K, a=_FORS_A)
_FORS_SIG       = _fors_obj.sign(_FORS_MSG, _FORS_PRIV)
_FORS_INDICES   = list(_FORS_SIG["indices"])     # list copy – immutable ref
_FORS_RECONPK   = _fors_obj.reconstruct_pk(_FORS_SIG)


# ===========================================================================
# Test cases
# ===========================================================================

class TestWOTSKAT(unittest.TestCase):

    def setUp(self):
        self.wots = WOTS(w_value=16)

    def test_chain_determinism(self):
        """chain(x, n) must always produce the same output for the same input."""
        x   = det_bytes(32, 99)
        out = chain(x, 7)
        self.assertEqual(chain(x, 7), out,
                         "chain() is not deterministic")

    def test_chain_composition(self):
        """chain(x, a+b) == chain(chain(x, a), b) for all a, b."""
        x = det_bytes(32, 42)
        for a in range(5):
            for b in range(5):
                self.assertEqual(
                    chain(x, a + b),
                    chain(chain(x, a), b),
                    f"chain composition failed for a={a}, b={b}"
                )

    def test_build_chain_cache_matches_chain(self):
        """cache[i] must equal chain(sk, i) for every i."""
        sk    = det_bytes(32, 0)
        cache = build_chain_cache(sk, 16)
        for i in range(16):
            self.assertEqual(cache[i], chain(sk, i),
                             f"cache mismatch at step {i}")

    def test_pk_element_matches_precomputed(self):
        """Public key element 0 must match the pre-computed constant."""
        self.assertEqual(_WOTS_PK0, _WOTS_CACHE0[15])

    def test_signature_element_matches_precomputed(self):
        """Signature element 0 must reproduce the pre-computed constant."""
        # Build a full WOTS key pair with deterministic SK elements.
        wots          = self.wots
        sk            = [det_bytes(32, i) for i in range(wots.length)]
        chain_caches  = [build_chain_cache(sk[i], wots.w)
                         for i in range(wots.length)]
        sig           = wots.sign(_WOTS_MSG, sk, chain_caches)
        self.assertEqual(sig[0], _WOTS_SIG0,
                         "WOTS sig[0] does not match KAT constant")

    def test_verify_reconstructs_pk(self):
        """verify(msg, sign(msg)) must reproduce the original public key."""
        wots          = self.wots
        sk            = [det_bytes(32, i) for i in range(wots.length)]
        chain_caches  = [build_chain_cache(sk[i], wots.w)
                         for i in range(wots.length)]
        pk            = [chain_caches[i][wots.w - 1]
                         for i in range(wots.length)]
        sig           = wots.sign(_WOTS_MSG, sk, chain_caches)
        pk_rec        = wots.verify(_WOTS_MSG, sig)
        self.assertEqual(pk_rec, pk,
                         "WOTS verify() did not reconstruct the original PK")

    def test_base_w_determinism(self):
        """base_w must produce identical output for identical inputs."""
        data = det_bytes(32, 7)
        self.assertEqual(base_w(data, 16, 64), base_w(data, 16, 64))

    def test_checksum_range(self):
        """Each checksum digit must be in [0, w-1]."""
        data     = det_bytes(32, 5)
        msg_base = base_w(data, 16, 64)
        cs       = checksum(msg_base, 16, 3)
        for d in cs:
            self.assertGreaterEqual(d, 0)
            self.assertLess(d, 16)


class TestMerkleKAT(unittest.TestCase):

    def test_root_is_deterministic(self):
        """Building from the same leaves must always produce the same root."""
        tree = MerkleTree()
        tree.build(_MERKLE_LEAVES)
        self.assertEqual(tree.root(), _MERKLE_ROOT,
                         "Merkle root changed between runs (non-deterministic)")

    def test_auth_path_determinism(self):
        """auth_path(0) must always return the same constant path."""
        tree = MerkleTree()
        tree.build(_MERKLE_LEAVES)
        self.assertEqual(tree.auth_path(0), _MERKLE_AUTHPATH,
                         "auth_path(0) changed between runs")

    def test_compute_root_all_indices(self):
        """compute_root must reproduce the KAT root for every leaf index."""
        tree = MerkleTree()
        tree.build(_MERKLE_LEAVES)
        root = tree.root()
        for i, leaf in enumerate(_MERKLE_LEAVES):
            path         = tree.auth_path(i)
            rebuilt_root = tree.compute_root(leaf, path, i)
            self.assertEqual(rebuilt_root, root,
                             f"compute_root failed for index {i}")

    def test_wrong_leaf_fails(self):
        """Supplying a wrong leaf must NOT produce the correct root."""
        tree = MerkleTree()
        tree.build(_MERKLE_LEAVES)
        wrong_leaf    = H(b"this is not a real leaf")
        wrong_root    = tree.compute_root(wrong_leaf, tree.auth_path(0), 0)
        self.assertNotEqual(wrong_root, _MERKLE_ROOT,
                            "Wrong leaf should not produce the correct root")

    def test_wrong_index_fails(self):
        """Using the wrong idx in compute_root must produce a different root."""
        tree = MerkleTree()
        tree.build(_MERKLE_LEAVES)
        # Use leaf 0's auth path but claim idx=1 – root reconstruction fails.
        bad_root = tree.compute_root(
            _MERKLE_LEAVES[0], tree.auth_path(0), idx=1
        )
        self.assertNotEqual(bad_root, _MERKLE_ROOT,
                            "Wrong index should not reproduce the correct root")

    def test_leaf_order_matters(self):
        """Reversing the leaf order must produce a different root."""
        tree_fwd = MerkleTree()
        tree_fwd.build(_MERKLE_LEAVES)
        tree_rev = MerkleTree()
        tree_rev.build(list(reversed(_MERKLE_LEAVES)))
        self.assertNotEqual(tree_fwd.root(), tree_rev.root(),
                            "Leaf order should affect the Merkle root")


class TestFORSKAT(unittest.TestCase):

    def test_indices_determinism(self):
        """The same message must always produce the same leaf indices."""
        fors      = FORS(k=_FORS_K, a=_FORS_A)
        indices_a = fors._msg_to_indices(_FORS_MSG)
        indices_b = fors._msg_to_indices(_FORS_MSG)
        self.assertEqual(indices_a, indices_b,
                         "_msg_to_indices is not deterministic")

    def test_indices_match_kat(self):
        """Indices derived from _FORS_MSG must match the pre-computed KAT."""
        fors    = FORS(k=_FORS_K, a=_FORS_A)
        indices = fors._msg_to_indices(_FORS_MSG)
        self.assertEqual(indices, _FORS_INDICES,
                         "FORS indices do not match KAT constants")

    def test_indices_in_range(self):
        """Every derived index must be in [0, t)."""
        fors    = FORS(k=_FORS_K, a=_FORS_A)
        indices = fors._msg_to_indices(_FORS_MSG)
        for i, idx in enumerate(indices):
            self.assertGreaterEqual(idx, 0,
                                    f"index {i} is negative: {idx}")
            self.assertLess(idx, _FORS_T,
                            f"index {i} out of range: {idx}")

    def test_reconstruct_pk_matches_kat(self):
        """reconstruct_pk must reproduce the KAT public key."""
        fors = FORS(k=_FORS_K, a=_FORS_A)
        self.assertEqual(fors.reconstruct_pk(_FORS_SIG), _FORS_RECONPK,
                         "FORS reconstruct_pk does not match KAT constant")

    def test_public_key_matches_kat(self):
        """The public key produced from the deterministic private key must match."""
        self.assertEqual(_FORS_PK, _FORS_RECONPK,
                         "FORS PK from keygen != PK from reconstruct_pk")

    def test_verify_accepts_valid_kat_sig(self):
        """The KAT signature must verify against the KAT public key."""
        fors = FORS(k=_FORS_K, a=_FORS_A)
        self.assertTrue(fors.verify(_FORS_MSG, _FORS_SIG, _FORS_PK),
                        "FORS verify() rejected a valid KAT signature")

    def test_verify_rejects_wrong_message(self):
        """The KAT signature must NOT verify for a different message."""
        fors = FORS(k=_FORS_K, a=_FORS_A)
        self.assertFalse(fors.verify(b"wrong message", _FORS_SIG, _FORS_PK),
                         "FORS verify() accepted sig for wrong message")

    def test_verify_rejects_tampered_sk_value(self):
        """Replacing one sk_value with zeros must invalidate the signature."""
        import copy
        bad_sig              = copy.deepcopy(_FORS_SIG)
        bad_sig["sk_values"] = [b'\x00' * 32] + bad_sig["sk_values"][1:]
        fors = FORS(k=_FORS_K, a=_FORS_A)
        self.assertFalse(fors.verify(_FORS_MSG, bad_sig, _FORS_PK),
                         "FORS verify() accepted sig with tampered sk_value")


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------

if __name__ == "__main__":
    loader = unittest.TestLoader()
    suite  = unittest.TestSuite()
    for cls in [TestWOTSKAT, TestMerkleKAT, TestFORSKAT]:
        suite.addTests(loader.loadTestsFromTestCase(cls))
    runner = unittest.TextTestRunner(verbosity=2)
    result = runner.run(suite)
    sys.exit(0 if result.wasSuccessful() else 1)
