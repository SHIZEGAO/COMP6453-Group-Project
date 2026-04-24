"""
Integration test suite for the full SPHINCS+ workflow.

Author: Yixuan Wang (z5607523)
"""
import sys, os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', 'src'))

from sphincs import keygen, sign, verify


def test_basic():
    print("[1] Basic sign-verify cycle...")
    private_key, public_key = keygen(num_leaves=4)
    msg = b"hello sphincs"
    sig = sign(msg, private_key, idx=0)

    assert verify(msg, sig, public_key), "Valid signature should verify"
    print("    PASS: valid signature accepted")

    assert not verify(b"wrong message", sig, public_key), "Wrong message should fail"
    print("    PASS: wrong message rejected")


def test_multiple_indices():
    print("[2] Sign with different WOTS+ leaf indices...")
    private_key, public_key = keygen(num_leaves=4)
    msg = b"test message"

    for idx in range(4):
        sig = sign(msg, private_key, idx=idx)
        assert verify(msg, sig, public_key), f"idx={idx} should verify"
    print("    PASS: all indices verify correctly")


def test_different_messages():
    print("[3] Different messages produce different signatures...")
    private_key, public_key = keygen(num_leaves=4)
    msgs = [b"msg_alpha", b"msg_beta", b"msg_gamma"]

    for msg in msgs:
        sig = sign(msg, private_key, idx=0)
        assert verify(msg, sig, public_key)
        assert not verify(b"not the original message", sig, public_key)
    print("    PASS")


def test_tampered_signature():
    print("[4] Tampered WOTS+ signature detection...")
    private_key, public_key = keygen(num_leaves=4)
    msg = b"tamper test"
    sig = sign(msg, private_key, idx=0)

    bad_sig              = dict(sig)
    bad_wots             = list(sig["wots_sig"])
    bad_wots[0]          = b'\x00' * 32
    bad_sig["wots_sig"]  = bad_wots

    assert not verify(msg, bad_sig, public_key), "Tampered wots_sig should fail"
    print("    PASS")


def test_wrong_public_key():
    print("[5] Wrong public key detection...")
    private_key1, public_key1 = keygen(num_leaves=4)
    private_key2, public_key2 = keygen(num_leaves=4)

    msg = b"pk mismatch test"
    sig = sign(msg, private_key1, idx=0)

    assert verify(msg, sig, public_key1)
    assert not verify(msg, sig, public_key2), "Signature should not verify under different PK"
    print("    PASS")


def test_parameter_sets():
    print("[6] Multiple parameter sets...")
    for num_leaves, k, a in [(4, 6, 4), (8, 10, 6)]:
        private_key, public_key = keygen(num_leaves=num_leaves, k=k, a=a)
        msg = b"param set test"
        sig = sign(msg, private_key, idx=0)
        assert verify(msg, sig, public_key), f"Failed for num_leaves={num_leaves}, k={k}, a={a}"
    print("    PASS")


if __name__ == "__main__":
    print("=== SPHINCS+ Integration Test Suite ===\n")
    test_basic()
    test_multiple_indices()
    test_different_messages()
    test_tampered_signature()
    test_wrong_public_key()
    test_parameter_sets()
    print("\n=== All Integration Tests Passed ===")
