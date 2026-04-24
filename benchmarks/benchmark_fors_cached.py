"""
Benchmark: FORS baseline vs FORSCached.

Measures average keygen, sign, and verify times across three parameter sets.
The cached variant precomputes all authentication paths at keygen time, so
signing becomes a direct lookup at the cost of higher keygen time and memory.

Author: Kaiqi Shi (z5622283)
"""
import sys, os, time
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', 'src'))

from fors import FORS
from fors_cached import FORSCached


def benchmark(label: str, func, runs: int = 20) -> float:
    times = []
    for _ in range(runs):
        t0 = time.perf_counter()
        func()
        times.append(time.perf_counter() - t0)
    avg = sum(times) / len(times)
    print(f"    {label:<18} avg {avg*1000:8.3f} ms  "
          f"min {min(times)*1000:7.3f} ms  "
          f"max {max(times)*1000:7.3f} ms")
    return avg


def _speedup(t_base: float, t_cache: float) -> None:
    if t_cache > 0:
        ratio     = t_base / t_cache
        direction = f"{ratio:.2f}x faster" if ratio >= 1 else f"{1/ratio:.2f}x slower"
        print(f"    speedup: cached is {direction} than baseline")


def run_comparison(k: int, a: int, runs: int = 20) -> None:
    print(f"\n  [k={k}, a={a}]")

    baseline = FORS(k=k, a=a)
    cached   = FORSCached(k=k, a=a)

    baseline_sk, baseline_pk = baseline.keygen()
    cached_sk,   cached_pk   = cached.keygen()

    msg          = b"benchmark message"
    baseline_sig = baseline.sign(msg, baseline_sk)
    cached_sig   = cached.sign(msg,   cached_sk)

    print("    --- keygen ---")
    t_bkg = benchmark("baseline", lambda: baseline.keygen(), runs)
    t_ckg = benchmark("cached  ", lambda: cached.keygen(),   runs)
    _speedup(t_bkg, t_ckg)

    print("    --- sign ---")
    t_bsg = benchmark("baseline", lambda: baseline.sign(msg, baseline_sk), runs)
    t_csg = benchmark("cached  ", lambda: cached.sign(msg, cached_sk),     runs)
    _speedup(t_bsg, t_csg)

    print("    --- verify ---")
    t_bvf = benchmark("baseline", lambda: baseline.verify(msg, baseline_sig, baseline_pk), runs)
    t_cvf = benchmark("cached  ", lambda: cached.verify(msg, cached_sig, cached_pk),       runs)
    _speedup(t_bvf, t_cvf)


if __name__ == "__main__":
    print("=== FORS: Baseline vs Auth Path Cache ===")
    run_comparison(k=6,  a=4)
    run_comparison(k=10, a=6)
    run_comparison(k=14, a=8)
    print("\n=== Done ===")
