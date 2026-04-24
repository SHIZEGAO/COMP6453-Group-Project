"""
Benchmark 2: WOTS+ Winternitz parameter w analysis.

Sweeps w ∈ {4, 16, 256} and measures signing time and signature length,
then computes a combined score to aid parameter selection.

Author: Shize Gao (z5603339)
"""
import sys, os, time
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', 'src'))

from wots import WOTS


def benchmark(func, *args, repeat: int = 5) -> float:
    times = []
    for _ in range(repeat):
        t0 = time.perf_counter()
        func(*args)
        times.append(time.perf_counter() - t0)
    return sum(times) / len(times)


if __name__ == "__main__":
    print("=== Benchmark 2: WOTS+ w-parameter Analysis ===\n")

    msg      = b"benchmark message"
    w_values = [4, 16, 256]
    results  = []

    for w in w_values:
        wots           = WOTS(w)
        sk, pk, caches = wots.keygen()
        t              = benchmark(wots.sign, msg, sk, caches)
        results.append({"w": w, "time": t, "length": wots.length})

    max_time = max(r["time"]   for r in results)
    max_len  = max(r["length"] for r in results)

    for r in results:
        r["time_norm"] = r["time"]   / max_time
        r["len_norm"]  = r["length"] / max_len
        r["score"]     = r["time_norm"] + r["len_norm"]

    print(f"  {'w':<6}{'Time (ms)':<14}{'Sig length':<14}{'T_norm':<10}{'L_norm':<10}{'Score'}")
    print("  " + "-" * 58)
    for r in results:
        print(f"  {r['w']:<6}{r['time']*1000:<14.3f}{r['length']:<14}"
              f"{r['time_norm']:<10.3f}{r['len_norm']:<10.3f}{r['score']:.3f}")

    best = min(results, key=lambda r: r["score"])
    print(f"\n  Best combined score: w={best['w']}")
    print("\n=== Done ===")
