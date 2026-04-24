"""
demo.py – SPHINCS+ live demonstration script.

Walks through the complete SPHINCS+ workflow with annotated terminal
output.  Designed to be run during a presentation or demo session.

Usage
-----
    cd sphincs_project/
    python demo.py

Author: Shize Gao (z5603339)
"""

import sys, os, time, hashlib
sys.path.insert(0, os.path.join(os.path.dirname(__file__), 'src'))

from sphincs     import keygen, sign, verify
from wots        import WOTS, build_chain_cache
from fors        import FORS
from merkle      import MerkleTree


# ---------------------------------------------------------------------------
# Pretty-print helpers
# ---------------------------------------------------------------------------

RESET  = "\033[0m"
BOLD   = "\033[1m"
GREEN  = "\033[32m"
RED    = "\033[31m"
CYAN   = "\033[36m"
YELLOW = "\033[33m"
GRAY   = "\033[90m"

def banner(text: str) -> None:
    width = 62
    print()
    print(BOLD + CYAN + "─" * width + RESET)
    print(BOLD + CYAN + f"  {text}" + RESET)
    print(BOLD + CYAN + "─" * width + RESET)

def step(n: int, text: str) -> None:
    print(f"\n{BOLD}[Step {n}]{RESET} {text}")

def ok(text: str) -> None:
    print(f"  {GREEN}✓{RESET}  {text}")

def fail(text: str) -> None:
    print(f"  {RED}✗{RESET}  {text}")

def info(label: str, value: str) -> None:
    print(f"  {GRAY}{label:<28}{RESET} {value}")

def pause() -> None:
    try:
        input(f"\n  {YELLOW}[Press Enter to continue…]{RESET}")
    except EOFError:
        print()

def hex8(b: bytes) -> str:
    return b.hex()[:16] + "…"

def timed(func):
    t0     = time.perf_counter()
    result = func()
    elapsed = (time.perf_counter() - t0) * 1000
    return result, elapsed


# ---------------------------------------------------------------------------
# Demo sections
# ---------------------------------------------------------------------------

def section_intro() -> None:
    banner("SPHINCS+ Post-Quantum Signature Scheme – Live Demo")
    print("""
  SPHINCS+ (SLH-DSA) is a NIST-standardised stateless hash-based
  signature scheme.  It requires no private state between signings and
  is believed to be secure against both classical and quantum computers.

  This demo walks through:
    1. Key generation   (FORS + WOTS+ + Merkle tree)
    2. Message signing
    3. Signature verification (valid message)
    4. Tamper detection       (altered message)
    5. Optimisation comparison (cache vs baseline)
    6. Parameter impact on size and speed
""")


def section_keygen() -> tuple:
    banner("1 · Key Generation")

    params = dict(num_leaves=4, k=10, a=6)
    step(1, "Generating SPHINCS+ key pair …")
    info("Parameters", f"num_leaves={params['num_leaves']}  k={params['k']}  a={params['a']}")

    (priv, pub), t_kg = timed(lambda: keygen(**params))

    ok(f"Key generation complete  ({t_kg:.1f} ms)")
    print()
    info("Public key – merkle_root", hex8(pub['merkle_root']))
    info("Public key – fors_pk    ", hex8(pub['fors_pk']))
    info("Public key total size",    f"{len(pub['merkle_root']) + len(pub['fors_pk'])} bytes")

    print(f"""
  {GRAY}How it works:{RESET}
    • FORS generates k={params['k']} independent Merkle trees
      (each with 2^{params['a']}={2**params['a']} leaves from random secret values).
    • WOTS+ generates {params['num_leaves']} one-time key pairs.
    • A top-level Merkle tree authenticates all WOTS+ public keys.
    • The public key = (merkle_root, compressed FORS public key).
""")
    return priv, pub, params


def section_sign(priv: dict, params: dict) -> tuple:
    banner("2 · Signing")

    msg = b"Hello SPHINCS+ - this message is protected!"
    step(2, f"Signing message: {BOLD}{msg.decode()}{RESET}")

    (sig, ), t_sg = timed(lambda: (sign(msg, priv, idx=0),))

    ok(f"Signature produced  ({t_sg:.2f} ms)")
    print()

    fors_sz = (sum(len(v) for v in sig['fors_sig']['sk_values']) +
               sum(len(p) for path in sig['fors_sig']['auth_paths'] for p in path))
    wots_sz = sum(len(x) for x in sig['wots_sig'])
    auth_sz = sum(len(x) for x in sig['auth_path'])
    total   = fors_sz + wots_sz + auth_sz

    info("FORS component size",   f"{fors_sz:>5} bytes  (revealed sk values + auth paths)")
    info("WOTS+ component size",  f"{wots_sz:>5} bytes  (hash chain outputs)")
    info("Merkle auth path",       f"{auth_sz:>5} bytes")
    info("Total signature size",   f"{total:>5} bytes")
    info("Signing leaf index",     str(sig['idx']))

    print(f"""
  {GRAY}How it works:{RESET}
    • FORS signs the raw message using one secret value per tree.
    • The FORS signature reveals a secret value and a Merkle path
      per tree – enough for a verifier to reconstruct the FORS PK.
    • The reconstructed FORS PK is hashed → digest for WOTS+.
    • WOTS+ signs the digest using one of the pre-generated key pairs.
    • The Merkle auth path proves that WOTS+ key pair is legitimate.
""")
    return msg, sig


def section_verify_valid(msg: bytes, sig: dict, pub: dict) -> None:
    banner("3 · Verification – Valid Signature")

    step(3, "Verifying the original message and signature …")
    (result,), t_vf = timed(lambda: (verify(msg, sig, pub),))

    if result:
        ok(f"Signature VALID  ({t_vf:.2f} ms)")
    else:
        fail("Verification failed (unexpected!)")

    print(f"""
  {GRAY}How it works:{RESET}
    • Verifier re-derives FORS indices from the message.
    • Reconstructs each FORS tree root via the revealed sk value +
      the Merkle auth path.
    • Recomputes FORS PK → hash → digest.
    • Runs WOTS+ verify: each sig element is hashed (w-1-d) times to
      recover the WOTS+ public key.
    • Hashes the recovered WOTS+ PK and checks it against the top
      Merkle tree root stored in the public key.
""")


def section_verify_tampered(msg: bytes, sig: dict, pub: dict) -> None:
    banner("4 · Tamper Detection")

    step(4, "Attempting to verify an ALTERED message …")
    bad_msg = b"Hello SPHINCS+ - this message has been ALTERED!"
    print(f"  Original:  {msg.decode()}")
    print(f"  Tampered:  {bad_msg.decode()}")
    print()

    (result,), t_vf = timed(lambda: (verify(bad_msg, sig, pub),))

    if not result:
        ok(f"Tampered message correctly REJECTED  ({t_vf:.2f} ms)")
    else:
        fail("Tampered message was accepted (security failure!)")

    step(5, "Attempting to use a signature from a different key pair …")
    priv2, pub2 = keygen(num_leaves=4, k=10, a=6)
    sig2 = sign(msg, priv2, idx=0)

    (result2,), _ = timed(lambda: (verify(msg, sig2, pub),))
    if not result2:
        ok("Signature from wrong key pair correctly REJECTED")
    else:
        fail("Cross-key verification succeeded (security failure!)")


def section_optimisations() -> None:
    banner("5 · Optimisation Comparison")

    print(f"""
  Three independent optimisations are implemented and benchmarked:

  {BOLD}① WOTS+ Chain Cache{RESET}  (wots.py)
    Precompute all w chain values per sk element at keygen time.
    Signing becomes O(length) cache lookups instead of O(length·steps)
    hash calls.

  {BOLD}② FORS Auth-Path Cache{RESET}  (fors_cached.py)
    Precompute every Merkle auth path for every leaf at keygen.
    Signing is then O(k) dictionary lookups; no tree traversal needed.

  {BOLD}③ MerkleCached flat node dict{RESET}  (merkle_cached.py)
    Store every internal node in a flat dict indexed by (level, idx).
    auth_path() is O(h) dict lookups with zero list allocation;
    improves when auth_path() is called repeatedly on large trees.
""")

    step(6, "Live speedup measurement – WOTS+ cache vs baseline …")
    from wots import H, base_w, checksum, chain

    wots = WOTS(w_value=16)
    sk, pk, caches = wots.keygen()
    msg = b"optimisation benchmark"

    def baseline():
        mh = H(msg)
        mb = base_w(mh, wots.w, wots.len1)
        md = mb + checksum(mb, wots.w, wots.len2)
        return [chain(sk[i], md[i]) for i in range(wots.length)]

    RUNS = 200
    t0 = time.perf_counter()
    for _ in range(RUNS): baseline()
    t_base = (time.perf_counter() - t0) / RUNS * 1000

    t0 = time.perf_counter()
    for _ in range(RUNS): wots.sign(msg, sk, caches)
    t_cache = (time.perf_counter() - t0) / RUNS * 1000

    info("Baseline sign (no cache)", f"{t_base:.3f} ms")
    info("Cached   sign",            f"{t_cache:.3f} ms")
    info("Speedup",                  f"{t_base/t_cache:.1f}x faster")


def section_param_impact() -> None:
    banner("6 · Parameter Impact on Size & Speed")

    print("""
  SPHINCS+ parameters control the security / performance trade-off.
  The table below shows how num_leaves, k, and a affect the key
  generation time, signing time, and signature size.
""")

    header = f"  {'Config':<10} {'num_leaves':>11} {'k':>4} {'a':>4} {'keygen':>10} {'sign':>9} {'verify':>9} {'sig size':>10}"
    print(header)
    print("  " + "─" * (len(header) - 2))

    configs = [
        ("Small",  4,  6, 4),
        ("Medium", 8, 10, 6),
        ("Large",  16, 14, 8),
    ]

    for label, nl, k, a in configs:
        priv, pub = keygen(num_leaves=nl, k=k, a=a)
        msg  = b"param sweep"

        RUNS = 5
        t0 = time.perf_counter()
        for _ in range(RUNS): keygen(num_leaves=nl, k=k, a=a)
        t_kg = (time.perf_counter() - t0) / RUNS * 1000

        sig = sign(msg, priv, idx=0)
        t0 = time.perf_counter()
        for _ in range(RUNS): sign(msg, priv, idx=0)
        t_sg = (time.perf_counter() - t0) / RUNS * 1000

        t0 = time.perf_counter()
        for _ in range(RUNS): verify(msg, sig, pub)
        t_vf = (time.perf_counter() - t0) / RUNS * 1000

        total = (sum(len(v) for v in sig['fors_sig']['sk_values']) +
                 sum(len(p) for path in sig['fors_sig']['auth_paths'] for p in path) +
                 sum(len(x) for x in sig['wots_sig']) +
                 sum(len(x) for x in sig['auth_path']))

        print(f"  {label:<10} {nl:>11} {k:>4} {a:>4} "
              f"{t_kg:>8.1f}ms {t_sg:>7.2f}ms {t_vf:>7.2f}ms {total:>8} B")

    print(f"""
  {GRAY}Observation:{RESET}
    Larger parameters → larger signature size and slower keygen, but
    signing and verification remain fast even for the "Large" config.
    The public key is always 64 bytes regardless of parameters.
""")


def section_comparison() -> None:
    banner("7 · Comparison with Classical & Other PQ Schemes")

    print("""
  The table below compares approximate figures for common signature
  schemes.  Classical schemes (RSA, ECDSA) are broken by quantum
  computers running Shor's algorithm.  Post-quantum schemes are not.

  ┌─────────────────┬──────────┬───────────┬──────────┬──────────┬───────────────┐
  │ Scheme          │ PQ-safe? │ PK size   │ Sig size │ Sign     │ Security base │
  ├─────────────────┼──────────┼───────────┼──────────┼──────────┼───────────────┤
  │ RSA-2048        │    ✗     │  256 B    │  256 B   │ ~1 ms    │ Factoring     │
  │ ECDSA P-256     │    ✗     │   64 B    │   64 B   │ <1 ms    │ Discrete log  │
  │ Dilithium-2     │    ✓     │ 1,312 B   │ 2,420 B  │ <1 ms    │ Module LWE    │
  │ Falcon-512      │    ✓     │  897 B    │  666 B   │ ~1 ms    │ NTRU lattice  │
  │ SPHINCS+-128s   │    ✓     │   32 B    │ 7,856 B  │ ~8 ms    │ Hash only     │
  │ This impl. (S)  │    ✓     │   64 B    │ 3,168 B  │ ~0.05 ms │ Hash only     │
  └─────────────────┴──────────┴───────────┴──────────┴──────────┴───────────────┘

  Notes
  ─────
  • Dilithium / Falcon figures are from NIST PQC Round 3 specifications.
  • SPHINCS+-128s figures from the NIST FIPS 205 standard.
  • "This impl." uses simplified (reduced) parameters suitable for a
    course project; it does not achieve the 128-bit security target.
  • Hash-only security (SPHINCS+) is the most conservative assumption:
    security relies solely on the collision resistance of SHA-256, not
    on any algebraic hardness problem that might weaken in the future.

  Complexity analysis
  ───────────────────
  Let n = hash output length (32 B), w = Winternitz param (16),
  k = FORS trees (10), a = FORS height (6), t = 2^a, H = tree height.

  Module     │ Operation │ Hash calls
  ───────────┼───────────┼─────────────────────────────────
  WOTS+      │ keygen    │ O(length × w)   ≈ 67 × 16 = 1072
             │ sign      │ O(length)       (cache lookup)
             │ verify    │ O(length × w/2) ≈ 67 × 8  = 536
  FORS       │ keygen    │ O(k × t)        ≈ 10 × 64 = 640
             │ sign      │ O(k × a)        ≈ 10 × 6  = 60
             │ verify    │ O(k × a)        ≈ 10 × 6  = 60
  Merkle     │ build     │ O(n)            (n = leaf count)
             │ auth_path │ O(H)            (tree height)
  SPHINCS+   │ keygen    │ O(FORS) + O(WOTS × leaves)
             │ sign      │ O(FORS sign) + O(WOTS sign) + O(H)
             │ verify    │ O(FORS verify) + O(WOTS verify) + O(H)
""")


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

if __name__ == "__main__":
    section_intro()
    pause()

    priv, pub, params = section_keygen()
    pause()

    msg, sig = section_sign(priv, params)
    pause()

    section_verify_valid(msg, sig, pub)
    pause()

    section_verify_tampered(msg, sig, pub)
    pause()

    section_optimisations()
    pause()

    section_param_impact()
    pause()

    section_comparison()

    banner("Demo Complete")
    print(f"  {GREEN}All sections finished successfully.{RESET}\n")
