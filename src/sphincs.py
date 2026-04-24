"""
SPHINCS+ simplified implementation – main signing workflow.

Architecture
------------
                 Message
                    │
              ┌─────▼──────┐
              │    FORS     │  (few-time signature on message)
              └─────┬──────┘
                    │ fors_pk  (reconstructed from FORS sig)
              ┌─────▼──────┐
              │  H(fors_pk) │  (digest used as WOTS+ message)
              └─────┬──────┘
                    │
              ┌─────▼──────┐
              │   WOTS+     │  (one-time signature on digest)
              └─────┬──────┘
                    │ pk_rec
              ┌─────▼──────┐
              │ Merkle Tree │  (hyper-tree root authenticates WOTS+ pk)
              └────────────┘

Public key  = (merkle_root, fors_pk)
Signature   = (fors_sig, wots_sig, auth_path, idx)

Author: Yixuan Wang (z5607523)
Integration fixes: Kaiqi Shi (z5622283) Shize Gao(z5603339) – see handover_notes.txt
"""

import hashlib

from wots import WOTS
from merkle import MerkleTree
from fors import FORS


def H(data: bytes) -> bytes:
    """SHA-256 hash function shared across all SPHINCS+ modules."""
    return hashlib.sha256(data).digest()


# ---------------------------------------------------------------------------
# Key generation
# ---------------------------------------------------------------------------

def keygen(num_leaves: int = 4, k: int = 10, a: int = 6) -> tuple:
    """
    Generate a SPHINCS+ key pair.

    Parameters
    ----------
    num_leaves : int   – number of WOTS+ key pairs (= Merkle tree leaves)
    k          : int   – FORS number of trees
    a          : int   – FORS tree height

    Returns
    -------
    private_key : dict
        'all_sk'     – list of WOTS+ secret keys
        'all_caches' – list of WOTS+ chain caches
        'all_pk'     – list of WOTS+ public keys
        'tree'       – MerkleTree built over WOTS+ public key hashes
        'num_leaves' – num_leaves
        'fors_sk'    – FORS private key
        'k', 'a'     – FORS parameters (stored for use in sign/verify)

    public_key : dict
        'merkle_root' – bytes  Merkle root of all WOTS+ public keys
        'fors_pk'     – bytes  FORS public key
    """
    wots = WOTS()
    fors = FORS(k=k, a=a)

    all_sk, all_pk, all_caches = [], [], []
    for _ in range(num_leaves):
        sk, pk, caches = wots.keygen()
        all_sk.append(sk)
        all_pk.append(pk)
        all_caches.append(caches)

    # Each Merkle leaf is H(concatenated WOTS+ public key elements).
    leaves = [H(b''.join(pk)) for pk in all_pk]
    tree   = MerkleTree()
    tree.build(leaves)

    fors_sk, fors_pk = fors.keygen()

    private_key = {
        "all_sk":     all_sk,
        "all_caches": all_caches,
        "all_pk":     all_pk,
        "tree":       tree,
        "num_leaves": num_leaves,
        "fors_sk":    fors_sk,
        "k": k,
        "a": a,
    }

    public_key = {
        "merkle_root": tree.root(),
        "fors_pk":     fors_pk,
    }

    return private_key, public_key


# ---------------------------------------------------------------------------
# Signing
# ---------------------------------------------------------------------------

def sign(msg: bytes, private_key: dict, idx: int = 0) -> dict:
    """
    Sign *msg* using the SPHINCS+ private key.

    Parameters
    ----------
    msg         : bytes  – message to sign
    private_key : dict   – returned by ``keygen``
    idx         : int    – index of the WOTS+ key pair to use (0 ≤ idx < num_leaves)

    Returns
    -------
    dict with keys:
      'fors_sig'  – FORS signature
      'wots_sig'  – WOTS+ signature
      'auth_path' – Merkle authentication path for leaf *idx*
      'idx'       – leaf index used
    """
    if idx < 0 or idx >= private_key["num_leaves"]:
        raise ValueError(f"idx must be in [0, {private_key['num_leaves']})")

    wots = WOTS()
    fors = FORS(k=private_key["k"], a=private_key["a"])

    # Step 1 – FORS signs the raw message.
    fors_sig = fors.sign(msg, private_key["fors_sk"])

    # Step 2 – reconstruct the FORS public key from the signature, then
    #           hash it to produce the digest that WOTS+ will sign.
    fors_pk_rec = fors.reconstruct_pk(fors_sig)
    digest      = H(fors_pk_rec)

    # Step 3 – WOTS+ signs the digest using the selected key pair.
    wots_sig  = wots.sign(digest, private_key["all_sk"][idx], private_key["all_caches"][idx])
    auth_path = private_key["tree"].auth_path(idx)

    return {
        "fors_sig":  fors_sig,
        "wots_sig":  wots_sig,
        "auth_path": auth_path,
        "idx":       idx,
    }


# ---------------------------------------------------------------------------
# Verification
# ---------------------------------------------------------------------------

def verify(msg: bytes, signature: dict, public_key: dict) -> bool:
    """
    Verify a SPHINCS+ signature.

    Parameters
    ----------
    msg        : bytes  – the message that was signed
    signature  : dict   – returned by ``sign``
    public_key : dict   – returned by ``keygen``

    Returns
    -------
    bool  – True iff the signature is valid
    """
    fors_sig  = signature["fors_sig"]
    wots_sig  = signature["wots_sig"]
    auth_path = signature["auth_path"]
    idx       = signature["idx"]

    # Recover FORS parameters from the signature structure.
    k = len(fors_sig["indices"])
    a = len(fors_sig["auth_paths"][0])

    wots = WOTS()
    fors = FORS(k=k, a=a)

    # Step 1 – verify FORS signature against the stored FORS public key.
    if not fors.verify(msg, fors_sig, public_key["fors_pk"]):
        return False

    # Step 2 – reconstruct the digest (must match what was signed in step 3).
    fors_pk_rec = fors.reconstruct_pk(fors_sig)
    digest      = H(fors_pk_rec)

    # Step 3 – reconstruct WOTS+ public key from the signature.
    pk_rec = wots.verify(digest, wots_sig)
    leaf   = H(b''.join(pk_rec))

    # Step 4 – recompute Merkle root and compare with stored root.
    tree           = MerkleTree()
    computed_root  = tree.compute_root(leaf, auth_path, idx)

    return computed_root == public_key["merkle_root"]
