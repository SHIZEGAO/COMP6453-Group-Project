"""
Test suite for the WOTS+ module.

Author: Shize Gao (z5603339)
"""
import sys, os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', 'src'))

from wots import WOTS


def test_wots():
    print("=== WOTS+ Test Suite ===\n")

    wots = WOTS(16)
    sk, pk, caches = wots.keygen()
    print("[1] KeyGen: PASS")

    msg = b"Hello WOTS+"
    sig = wots.sign(msg, sk, caches)

    # verify returns the reconstructed pk_rec; check it matches pk
    pk_rec = wots.verify(msg, sig)
    assert pk_rec == pk, "Reconstructed PK should match original PK"
    print("[2] Valid signature verification: PASS")

    # Wrong message → pk_rec will not match pk
    pk_rec_fake = wots.verify(b"Fake message", sig)
    assert pk_rec_fake != pk, "Wrong message should produce different PK"
    print("[3] Message tampering detection: PASS")

    # Tampered signature
    fake_sig    = sig[:]
    fake_sig[0] = b'\x00' * len(fake_sig[0])
    pk_rec_bad  = wots.verify(msg, fake_sig)
    assert pk_rec_bad != pk, "Tampered signature should produce different PK"
    print("[4] Signature tampering detection: PASS")

    # Invalid input types
    try:
        wots.sign("not bytes", sk, caches)
        print("[5] TypeError on non-bytes msg: FAIL")
    except TypeError:
        print("[5] TypeError on non-bytes msg: PASS")

    try:
        wots.sign(msg, sk[:10], caches)
        print("[6] ValueError on short sk: FAIL")
    except ValueError:
        print("[6] ValueError on short sk: PASS")

    print("\n=== All WOTS+ Tests Passed ===")


if __name__ == "__main__":
    test_wots()
