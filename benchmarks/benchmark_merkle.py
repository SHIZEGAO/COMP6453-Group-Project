"""
Benchmark: Merkle Tree build, auth_path, and compute_root performance.

Tests across tree sizes (8, 64, 512 leaves) to show how operations scale.

Author: Peiliang Zhao (z5539814)
"""
import sys, os, time
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', 'src'))

from merkle import MerkleTree, H


def benchmark(label: str, func, runs: int = 50) -> float:
    times = []
    for _ in range(runs):
        t0 = time.perf_counter()
        func()
        times.append(time.perf_counter() - t0)
    avg = sum(times) / len(times)
    print(f"    {label:<30} avg {avg*1000:8.4f} ms  "
          f"min {min(times)*1000:7.4f} ms  "
          f"max {max(times)*1000:7.4f} ms")
    return avg


def run_for_size(n_leaves: int, runs: int = 50) -> None:
    print(f"\n  [n_leaves={n_leaves}]")
    leaves = [H(f"leaf{i}".encode()) for i in range(n_leaves)]

    tree = MerkleTree()
    tree.build(leaves)

    benchmark("build",       lambda: (MerkleTree().build(leaves)), runs)
    benchmark("auth_path(0)", lambda: tree.auth_path(0),           runs)
    benchmark("auth_path(mid)", lambda: tree.auth_path(n_leaves//2), runs)
    benchmark("compute_root",
              lambda: tree.compute_root(leaves[0], tree.auth_path(0), 0), runs)


if __name__ == "__main__":
    print("=== Benchmark: Merkle Tree Operations ===")
    for size in [8, 64, 512]:
        run_for_size(size)
    print("\n=== Done ===")
