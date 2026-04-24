"""
Merkle Tree module for SPHINCS+.

Provides tree construction, root extraction, authentication path generation,
and root reconstruction from a leaf + auth path (used during verification).

Author: Peiliang Zhao (z5539814)
"""

import hashlib
from typing import List


def H(data: bytes) -> bytes:
    """SHA-256 hash function shared across all SPHINCS+ modules."""
    return hashlib.sha256(data).digest()


class MerkleTree:
    """
    A simple Merkle Tree implementation for SPHINCS+.

    The tree is stored level-by-level:
    - ``self.tree[0]``    — leaf nodes
    - ``self.tree[-1][0]`` — Merkle root
    """

    def __init__(self):
        self.tree:   list = []
        self.leaves: list = []

    # ------------------------------------------------------------------
    # Construction
    # ------------------------------------------------------------------

    def build(self, leaves: List[bytes]) -> None:
        """
        Build the full Merkle tree from a list of leaf hashes.

        If the number of nodes at any level is odd the last node is
        duplicated so that every node has a sibling.

        Parameters
        ----------
        leaves : List[bytes]   – leaf nodes (non-empty)

        Raises
        ------
        ValueError  – if *leaves* is empty
        """
        if not leaves:
            raise ValueError("Leaves list cannot be empty.")

        self.leaves = leaves[:]
        self.tree   = [leaves[:]]

        current_level = leaves[:]

        while len(current_level) > 1:
            if len(current_level) % 2 == 1:
                current_level.append(current_level[-1])

            next_level = [
                H(current_level[i] + current_level[i + 1])
                for i in range(0, len(current_level), 2)
            ]

            self.tree.append(next_level)
            current_level = next_level

    # ------------------------------------------------------------------
    # Root
    # ------------------------------------------------------------------

    def root(self) -> bytes:
        """
        Return the Merkle root.

        Raises
        ------
        ValueError  – if the tree has not been built yet
        """
        if not self.tree:
            raise ValueError("Tree has not been built yet.")
        return self.tree[-1][0]

    # ------------------------------------------------------------------
    # Authentication path
    # ------------------------------------------------------------------

    def auth_path(self, idx: int) -> List[bytes]:
        """
        Return the authentication path for the leaf at *idx*.

        The path is the list of sibling nodes from the leaf level up to
        (but not including) the root, ordered bottom-up.

        Parameters
        ----------
        idx : int   – leaf index (0-based)

        Returns
        -------
        List[bytes]

        Raises
        ------
        ValueError   – if the tree has not been built yet
        IndexError   – if *idx* is out of range
        """
        if not self.tree:
            raise ValueError("Tree has not been built yet.")
        if idx < 0 or idx >= len(self.leaves):
            raise IndexError("Leaf index out of range.")

        path = []
        current_idx = idx

        for level in range(len(self.tree) - 1):
            nodes = self.tree[level][:]
            if len(nodes) % 2 == 1:
                nodes.append(nodes[-1])

            sibling_idx = current_idx ^ 1          # flip the last bit
            path.append(nodes[sibling_idx])
            current_idx >>= 1

        return path

    # ------------------------------------------------------------------
    # Root reconstruction (used in verify)
    # ------------------------------------------------------------------

    def compute_root(self, leaf: bytes, auth_path: List[bytes], idx: int) -> bytes:
        """
        Recompute the Merkle root from a leaf, its authentication path,
        and the original leaf index.

        Parameters
        ----------
        leaf      : bytes         – the leaf hash
        auth_path : List[bytes]   – authentication path returned by ``auth_path``
        idx       : int           – original leaf index

        Returns
        -------
        bytes  – reconstructed root
        """
        current     = leaf
        current_idx = idx

        for sibling in auth_path:
            if current_idx % 2 == 0:
                current = H(current + sibling)
            else:
                current = H(sibling + current)
            current_idx >>= 1

        return current
