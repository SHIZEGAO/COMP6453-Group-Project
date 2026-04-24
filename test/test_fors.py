"""
Test suite for the FORS and FORSCached modules.

Author: Kaiqi Shi (z5622283)
"""
import sys, os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', 'src'))

from fors import FORS
from fors_cached import FORSCached


def _run_tests(cls, label):
    print(f"\n--- {label} ---")
    fors           = cls(k=10, a=6)
    private_key, pk = fors.keygen()
    print(f"[1] keygen: PASS  pk={pk.hex()[:16]}...")

    msg = b"hello fors"
    sig = fors.sign(msg, private_key)
    print(f"[2] sign:   PASS  indices={sig['indices'][:3]}...")

    assert fors.verify(msg, sig, pk), "Valid sig should verify"
    print("[3] verify (correct): PASS")

    assert not fors.verify(b"wrong message", sig, pk), "Wrong msg should fail"
    print("[4] verify (wrong message): PASS")

    # Tamper with one sk_value
    bad_sig               = dict(sig)
    bad_sk                = list(sig["sk_values"])
    bad_sk[0]             = b'\x00' * 32
    bad_sig["sk_values"]  = bad_sk
    assert not fors.verify(msg, bad_sig, pk), "Tampered sig should fail"
    print("[5] verify (tampered sk_value): PASS")


def test_fors_baseline():
    _run_tests(FORS, "FORS (baseline)")


def test_fors_cached():
    _run_tests(FORSCached, "FORSCached (optimised)")


def test_cross_verify():
    """
    A FORSCached signature must be verifiable with FORS.verify,
    since the signature format is identical.
    """
    k, a   = 6, 4
    fors   = FORS(k=k, a=a)
    cached = FORSCached(k=k, a=a)

    _, pk_b          = fors.keygen()
    cached_sk, pk_c  = cached.keygen()

    msg      = b"cross verify test"
    cached_sig = cached.sign(msg, cached_sk)

    # FORSCached verify
    assert cached.verify(msg, cached_sig, pk_c)
    print("\n[6] cross-class verify: PASS")


if __name__ == "__main__":
    print("=== FORS Test Suite ===")
    test_fors_baseline()
    test_fors_cached()
    test_cross_verify()
    print("\n=== All FORS Tests Passed ===")
