"""
Test suite for the Merkle Tree module.

Author: Peiliang Zhao (z5539814)
"""
import sys, os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', 'src'))

from merkle import MerkleTree, H


def test_basic():
    leaves = [H(f"leaf{i}".encode()) for i in range(4)]
    tree   = MerkleTree()
    tree.build(leaves)
    root   = tree.root()

    for i, leaf in enumerate(leaves):
        path         = tree.auth_path(i)
        rebuilt_root = tree.compute_root(leaf, path, i)
        assert rebuilt_root == root, f"Root mismatch at index {i}"

    print("[1] Basic 4-leaf tree: PASS")


def test_odd_leaves():
    leaves = [H(f"leaf{i}".encode()) for i in range(3)]
    tree   = MerkleTree()
    tree.build(leaves)
    root   = tree.root()

    for i, leaf in enumerate(leaves):
        path         = tree.auth_path(i)
        rebuilt_root = tree.compute_root(leaf, path, i)
        assert rebuilt_root == root, f"Root mismatch at index {i}"

    print("[2] Odd-leaf (3 leaves) tree: PASS")


def test_single_leaf():
    leaves = [H(b"only_leaf")]
    tree   = MerkleTree()
    tree.build(leaves)
    assert tree.root() == leaves[0]
    print("[3] Single-leaf tree: PASS")


def test_exceptions():
    tree = MerkleTree()

    try:
        tree.root()
        print("[4a] Empty-tree root: FAIL")
    except ValueError:
        print("[4a] Empty-tree root raises ValueError: PASS")

    try:
        tree.build([])
        print("[4b] Empty-leaves build: FAIL")
    except ValueError:
        print("[4b] Empty-leaves build raises ValueError: PASS")

    tree.build([H(b"a"), H(b"b")])

    try:
        tree.auth_path(-1)
        print("[4c] Negative index: FAIL")
    except IndexError:
        print("[4c] Negative index raises IndexError: PASS")

    try:
        tree.auth_path(99)
        print("[4d] Out-of-range index: FAIL")
    except IndexError:
        print("[4d] Out-of-range index raises IndexError: PASS")


if __name__ == "__main__":
    print("=== Merkle Tree Test Suite ===\n")
    test_basic()
    test_odd_leaves()
    test_single_leaf()
    test_exceptions()
    print("\n=== All Merkle Tests Passed ===")
