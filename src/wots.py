"""
WOTS+ (Winternitz One-Time Signature Plus) module for SPHINCS+.

Optimisation: chain_cache is precomputed during keygen so that signing
is a direct cache lookup (O(1) chain calls) rather than recomputing
from the secret key each time.

Author: Shize Gao (z5603339)
"""

import hashlib
import secrets
import math


# ---------------------------------------------------------------------------
# Primitives
# ---------------------------------------------------------------------------

def H(data: bytes) -> bytes:
    """SHA-256 hash function used throughout the module."""
    return hashlib.sha256(data).digest()


def chain(x: bytes, steps: int) -> bytes:
    """Apply the hash chain for *steps* iterations starting from *x*."""
    result = x
    for _ in range(steps):
        result = H(result)
    return result


def build_chain_cache(x: bytes, w: int) -> list:
    """
    Precompute all w chain values for a single secret key element.

    Returns a list of length w where cache[i] = chain(x, i).
    """
    cache = [x]
    for _ in range(w - 1):
        cache.append(H(cache[-1]))
    return cache


def base_w(X: bytes, w: int, out_len: int) -> list:
    """
    Convert byte string *X* into a list of base-w digits of length *out_len*.
    """
    log_w = int(math.log2(w))
    bits = 0
    bits_left = 0
    in_idx = 0
    output = []

    for _ in range(out_len):
        if bits_left < log_w:
            if in_idx < len(X):
                bits = (bits << 8) | X[in_idx]
                in_idx += 1
                bits_left += 8
            else:
                bits <<= (log_w - bits_left)
                bits_left = log_w

        bits_left -= log_w
        output.append((bits >> bits_left) & (w - 1))

    return output


def checksum(base_w_digits: list, w: int, len2: int) -> list:
    """Compute and return the base-w encoded checksum digits."""
    csum = sum((w - 1 - x) for x in base_w_digits)
    csum_bytes = csum.to_bytes((csum.bit_length() + 7) // 8 or 1, 'big')
    return base_w(csum_bytes, w, len2)


# ---------------------------------------------------------------------------
# WOTS+ class
# ---------------------------------------------------------------------------

class WOTS:
    """
    WOTS+ one-time signature scheme.

    Parameters
    ----------
    w_value : int
        Winternitz parameter.  Must be a power of 2.  Default: 16.
    """

    def __init__(self, w_value: int = 16):
        self.n = 32            # hash output length in bytes
        self.w = w_value

        self.log_w = int(math.log2(self.w))
        self.len1  = math.ceil((8 * self.n) / self.log_w)
        self.len2  = math.floor(
            math.log2(self.len1 * (self.w - 1)) / self.log_w
        ) + 1
        self.length = self.len1 + self.len2

    # ------------------------------------------------------------------
    # Key generation
    # ------------------------------------------------------------------

    def keygen(self) -> tuple:
        """
        Generate a WOTS+ key pair.

        Returns
        -------
        sk : list[bytes]
            Private key (length ``self.length`` random 32-byte values).
        pk : list[bytes]
            Public key (each element is ``chain(sk[i], w-1)``).
        chain_caches : list[list[bytes]]
            Precomputed chain caches; ``chain_caches[i][j] = chain(sk[i], j)``.
        """
        sk = [secrets.token_bytes(self.n) for _ in range(self.length)]

        chain_caches = [
            build_chain_cache(sk[i], self.w)
            for i in range(self.length)
        ]

        pk = [chain_caches[i][self.w - 1] for i in range(self.length)]

        return sk, pk, chain_caches

    # ------------------------------------------------------------------
    # Signing
    # ------------------------------------------------------------------

    def sign(self, msg: bytes, sk: list, chain_caches: list) -> list:
        """
        Sign *msg* using the private key and precomputed chain caches.

        Parameters
        ----------
        msg          : bytes   – message to sign (will be hashed internally)
        sk           : list    – private key returned by ``keygen``
        chain_caches : list    – chain caches returned by ``keygen``

        Returns
        -------
        list[bytes] – signature of length ``self.length``
        """
        if not isinstance(msg, bytes):
            raise TypeError("msg must be bytes")
        if not isinstance(sk, list) or len(sk) != self.length:
            raise ValueError(f"sk must be a list of length {self.length}")
        if not isinstance(chain_caches, list) or len(chain_caches) != self.length:
            raise ValueError("chain_caches must match sk length")

        msg_hash   = H(msg)
        msg_base   = base_w(msg_hash, self.w, self.len1)
        msg_digits = msg_base + checksum(msg_base, self.w, self.len2)

        sig = [
            chain_caches[i][msg_digits[i]]
            for i in range(self.length)
        ]

        return sig

    # ------------------------------------------------------------------
    # Verification
    # ------------------------------------------------------------------

    def verify(self, msg: bytes, sig: list, pk: list = None) -> list:
        """
        Reconstruct the public key from *msg* and *sig*.

        Parameters
        ----------
        msg : bytes      – the message that was signed
        sig : list[bytes] – signature returned by ``sign``
        pk  : list[bytes] – (optional) public key for equality check;
                            if supplied, raises ValueError on mismatch.

        Returns
        -------
        list[bytes]
            Reconstructed public key elements (``pk_rec``).
            The caller uses these as leaves in the Merkle tree.

        Notes
        -----
        A WOTS+ signature is valid when
        ``H(b"".join(pk_rec)) == H(b"".join(real_pk))``.
        """
        if not isinstance(msg, bytes):
            raise TypeError("msg must be bytes")
        if not isinstance(sig, list) or len(sig) != self.length:
            raise ValueError("invalid signature length")

        msg_hash   = H(msg)
        msg_base   = base_w(msg_hash, self.w, self.len1)
        msg_digits = msg_base + checksum(msg_base, self.w, self.len2)

        pk_rec = [
            chain(sig[i], self.w - 1 - msg_digits[i])
            for i in range(self.length)
        ]

        return pk_rec
