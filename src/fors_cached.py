"""
FORSCached – optimised FORS with precomputed authentication path cache.

During key generation every authentication path for every leaf in every
tree is computed and stored.  Signing then becomes a direct cache lookup
(O(k) dictionary reads) instead of a tree traversal.

Trade-off: higher memory usage and slower keygen; faster signing.

Author: Kaiqi Shi (z5622283)
"""

import hashlib
import secrets
from merkle import MerkleTree


def H(data: bytes) -> bytes:
    """SHA-256 hash function shared across all SPHINCS+ modules."""
    return hashlib.sha256(data).digest()


class FORSCached:
    """
    FORS with precomputed authentication path cache.

    Parameters
    ----------
    k : int   – number of trees (default: 10)
    a : int   – tree height; each tree has t = 2^a leaves (default: 6)
    """

    def __init__(self, k: int = 10, a: int = 6):
        self.k = k
        self.a = a
        self.t = 2 ** a

    # ------------------------------------------------------------------
    # Key generation
    # ------------------------------------------------------------------

    def keygen(self) -> tuple:
        """
        Generate a FORS key pair with a full authentication path cache.

        In addition to the standard keygen output this method precomputes
        auth_path_cache[i][j] for every tree i and leaf j.

        Returns
        -------
        private_key : dict  – keys: 'sk', 'trees', 'roots', 'auth_path_cache'
        pk          : bytes – 32-byte compressed public key
        """
        sk = [
            [secrets.token_bytes(32) for _ in range(self.t)]
            for _ in range(self.k)
        ]

        trees, roots, auth_path_cache = [], [], []
        for i in range(self.k):
            leaves = [H(sk[i][j]) for j in range(self.t)]
            tree   = MerkleTree()
            tree.build(leaves)
            trees.append(tree)
            roots.append(tree.root())
            auth_path_cache.append([tree.auth_path(j) for j in range(self.t)])

        pk = H(b''.join(roots))
        private_key = {
            "sk": sk,
            "trees": trees,
            "roots": roots,
            "auth_path_cache": auth_path_cache,
        }
        return private_key, pk

    # ------------------------------------------------------------------
    # Index derivation  (identical logic to FORS baseline)
    # ------------------------------------------------------------------

    def _msg_to_indices(self, msg: bytes) -> list:
        """
        Derive k leaf indices (each in [0, t)) from *msg*.

        Uses the same algorithm as the baseline FORS so that signatures
        produced by either class can be verified by either class.
        """
        needed_bits = self.k * self.a
        hash_bytes  = H(msg)
        while len(hash_bytes) * 8 < needed_bits:
            hash_bytes += H(hash_bytes)

        bit_int    = int.from_bytes(hash_bytes, 'big')
        total_bits = len(hash_bytes) * 8
        mask       = (1 << self.a) - 1

        indices, pos = [], total_bits
        for _ in range(self.k):
            pos -= self.a
            indices.append((bit_int >> pos) & mask)
        return indices

    # ------------------------------------------------------------------
    # Sign  (cache lookup – no tree traversal)
    # ------------------------------------------------------------------

    def sign(self, msg: bytes, private_key: dict) -> dict:
        """
        Sign *msg* using precomputed authentication paths.

        Returns
        -------
        dict with keys:
          'indices'    – list[int]
          'sk_values'  – list[bytes]
          'auth_paths' – list[list[bytes]]  (retrieved from cache)
        """
        sk              = private_key["sk"]
        auth_path_cache = private_key["auth_path_cache"]
        indices         = self._msg_to_indices(msg)

        sk_values, auth_paths = [], []
        for i in range(self.k):
            idx = indices[i]
            sk_values.append(sk[i][idx])
            auth_paths.append(auth_path_cache[i][idx])   # O(1) lookup

        return {"indices": indices, "sk_values": sk_values, "auth_paths": auth_paths}

    # ------------------------------------------------------------------
    # Verify  (same as baseline – cache not needed for verification)
    # ------------------------------------------------------------------

    def verify(self, msg: bytes, signature: dict, pk: bytes) -> bool:
        """Verify a FORSCached signature against *pk*."""
        expected = self._msg_to_indices(msg)
        if signature["indices"] != expected:
            return False

        helper = MerkleTree()
        roots  = []
        for i in range(self.k):
            idx  = signature["indices"][i]
            leaf = H(signature["sk_values"][i])
            root = helper.compute_root(leaf, signature["auth_paths"][i], idx)
            roots.append(root)

        return H(b''.join(roots)) == pk
