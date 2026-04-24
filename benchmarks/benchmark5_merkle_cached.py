"""
Benchmark 5: MerkleTree baseline vs MerkleCached.

MerkleCached stores every internal node in a flat dict, eliminating
list-slice allocation in auth_path().  This benchmark measures the
improvement across tree sizes used in SPHINCS+ (8, 64, 512, 1024 leaves).

Author: Peiliang Zhao (z5539814) – extended by Mingzi Chen (z5437121)
"""
import sys, os, time
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', 'src'))

from merkle        import MerkleTree,   H
from merkle_cached import MerkleCached


def bench(label: str, func, runs: int = 200) -> float:
    times = []
    for _ in range(runs):
        t0 = time.perf_counter()
        func()
        times.append(time.perf_counter() - t0)
    avg = sum(times) / len(times)
    print(f"    {label:<28} avg {avg*1e6:8.2f} µs  "
          f"min {min(times)*1e6:7.2f} µs  "
          f"max {max(times)*1e6:7.2f} µs")
    return avg


def run_for_size(n: int, runs: int = 200) -> None:
    print(f"\n  [n_leaves={n}]")
    leaves = [H(f"leaf{i}".encode()) for i in range(n)]

    base = MerkleTree()
    base.build(leaves)

    cached = MerkleCached()
    cached.build(leaves)

    # build
    print("    --- build ---")
    tb = bench("baseline", lambda: (MerkleTree().build(leaves)), runs)
    tc = bench("cached  ", lambda: (MerkleCached().build(leaves)), runs)
    _speedup(tb, tc)

    # auth_path (query leaf 0 and mid-leaf)
    for qi, ql in [(0, "auth_path(0)"), (n // 2, f"auth_path({n//2})")]:
        print(f"    --- {ql} ---")
        tb = bench("baseline", lambda idx=qi: base.auth_path(idx),   runs)
        tc = bench("cached  ", lambda idx=qi: cached.auth_path(idx), runs)
        _speedup(tb, tc)


def _speedup(t_base: float, t_opt: float) -> None:
    ratio = t_base / t_opt if t_opt > 0 else float('inf')
    tag   = f"{ratio:.2f}x faster" if ratio >= 1 else f"{1/ratio:.2f}x slower"
    print(f"    speedup: cached is {tag} than baseline")


if __name__ == "__main__":
    print("=== Benchmark 5: MerkleTree baseline vs MerkleCached ===")
    for sz in [8, 64, 512, 1024]:
        run_for_size(sz)
    print("\n=== Done ===")
