"""
Benchmark: Full SPHINCS+ keygen / sign / verify.

Tests three parameter sets (small, medium, large) to show the performance
trade-off between security parameters and runtime.

Author: Mingzi Chen (z5437121)
"""
import sys, os, time
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', 'src'))

from sphincs import keygen, sign, verify


def benchmark(label: str, func, runs: int = 10) -> object:
    times, result = [], None
    for _ in range(runs):
        t0     = time.perf_counter()
        result = func()
        times.append(time.perf_counter() - t0)
    avg = sum(times) / len(times)
    print(f"  {label:<10} avg {avg*1000:8.2f} ms  "
          f"min {min(times)*1000:7.2f} ms  "
          f"max {max(times)*1000:7.2f} ms")
    return result


def run_param_set(label: str, num_leaves: int, k: int, a: int, runs: int = 10) -> None:
    print(f"\n[{label}]  num_leaves={num_leaves}  k={k}  a={a}")

    private_key, public_key = keygen(num_leaves=num_leaves, k=k, a=a)
    msg = b"benchmark message"
    sig = sign(msg, private_key, idx=0)

    benchmark("keygen", lambda: keygen(num_leaves=num_leaves, k=k, a=a), runs)
    benchmark("sign   ", lambda: sign(msg, private_key, idx=0), runs)
    benchmark("verify ", lambda: verify(msg, sig, public_key), runs)

    # Signature size (approximate – bytes in the dict fields)
    fors_size = (
        sum(len(v) for v in sig["fors_sig"]["sk_values"]) +
        sum(len(p) for path in sig["fors_sig"]["auth_paths"] for p in path)
    )
    wots_size  = sum(len(x) for x in sig["wots_sig"])
    auth_size  = sum(len(x) for x in sig["auth_path"])
    total_size = fors_size + wots_size + auth_size
    print(f"  Approx signature size: {total_size} bytes "
          f"(FORS={fors_size}  WOTS={wots_size}  auth={auth_size})")


if __name__ == "__main__":
    print("=== SPHINCS+ Full Benchmark ===")
    run_param_set("Small ",  num_leaves=4,  k=6,  a=4)
    run_param_set("Medium",  num_leaves=8,  k=10, a=6)
    run_param_set("Large ",  num_leaves=16, k=14, a=8)
    print("\n=== Done ===")
