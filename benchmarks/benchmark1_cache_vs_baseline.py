"""
Benchmark 1: WOTS+ cache vs baseline signing speed.

Compares the precomputed-chain-cache optimisation against recomputing
chains from the secret key on every sign call.

Author: Shize Gao (z5603339)
"""
import sys, os, time
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', 'src'))

from wots import WOTS, H, base_w, checksum, chain


def benchmark(func, *args, repeat: int = 5) -> float:
    times = []
    for _ in range(repeat):
        t0 = time.perf_counter()
        func(*args)
        times.append(time.perf_counter() - t0)
    return sum(times) / len(times)


def sign_baseline(wots: WOTS, msg: bytes, sk: list) -> list:
    """Re-compute chains from scratch each time (no cache)."""
    msg_hash   = H(msg)
    msg_base   = base_w(msg_hash, wots.w, wots.len1)
    msg_digits = msg_base + checksum(msg_base, wots.w, wots.len2)
    return [chain(sk[i], msg_digits[i]) for i in range(wots.length)]


if __name__ == "__main__":
    print("=== Benchmark 1: Cache vs Baseline ===\n")
    wots = WOTS(16)
    msg  = b"benchmark message"
    sk, pk, caches = wots.keygen()

    ROUNDS = 5
    base_times, cache_times = [], []

    for _ in range(ROUNDS):
        base_times.append(benchmark(sign_baseline, wots, msg, sk))
        cache_times.append(benchmark(wots.sign, msg, sk, caches))

    avg_base  = sum(base_times)  / ROUNDS
    avg_cache = sum(cache_times) / ROUNDS

    print(f"  Baseline sign (no cache):  {avg_base  * 1000:.3f} ms")
    print(f"  Cached   sign (w/ cache):  {avg_cache * 1000:.3f} ms")
    print(f"  Speedup:                   {avg_base / avg_cache:.2f}x")
    print("\n=== Done ===")
