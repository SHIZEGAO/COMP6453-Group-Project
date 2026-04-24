"""
Benchmark 3: WOTS+ Serial vs Parallel chain computation.

Uses Python multiprocessing to parallelise the independent hash chains
in sign() and verify().  On CPython the GIL is released during
hashlib operations, so process-level parallelism is used instead.

Note: due to process-spawn overhead, parallel mode is only beneficial
when the chain length (w-1) is large enough to amortise the overhead.

Author: Shize Gao (z5603339)
"""
import sys, os, time, math, hashlib, secrets
from multiprocessing import Pool, cpu_count
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', 'src'))

from wots import H, base_w, checksum, chain, WOTS


# ---------------------------------------------------------------------------
# Parallel helpers (must be top-level for pickling)
# ---------------------------------------------------------------------------

def chain_task(args):
    x, steps = args
    return chain(x, steps)


# ---------------------------------------------------------------------------
# Parallel WOTS+ (standalone, no caches – used only for benchmarking)
# ---------------------------------------------------------------------------

class WOTSParallel(WOTS):
    """WOTS+ variant that parallelises chain computation."""

    def sign_parallel(self, msg: bytes, sk: list) -> list:
        msg_hash   = H(msg)
        msg_base   = base_w(msg_hash, self.w, self.len1)
        msg_digits = msg_base + checksum(msg_base, self.w, self.len2)
        with Pool(cpu_count()) as p:
            return p.map(chain_task, [(sk[i], msg_digits[i]) for i in range(self.length)])

    def verify_parallel(self, msg: bytes, sig: list, pk: list) -> bool:
        msg_hash   = H(msg)
        msg_base   = base_w(msg_hash, self.w, self.len1)
        msg_digits = msg_base + checksum(msg_base, self.w, self.len2)
        with Pool(cpu_count()) as p:
            pk_rec = p.map(chain_task,
                           [(sig[i], self.w - 1 - msg_digits[i]) for i in range(self.length)])
        return pk_rec == pk


def benchmark(func, *args, repeat: int = 5) -> float:
    times = []
    for _ in range(repeat):
        t0 = time.perf_counter()
        func(*args)
        times.append(time.perf_counter() - t0)
    return sum(times) / len(times)


if __name__ == "__main__":
    print("=== Benchmark 3: Serial vs Parallel WOTS+ ===\n")
    print(f"  CPU count: {cpu_count()}\n")

    wots = WOTSParallel(w_value=16)
    msg  = b"benchmark message"
    sk, pk, caches = wots.keygen()
    sig = wots.sign(msg, sk, caches)

    REPEAT = 5

    t_serial_sign    = benchmark(wots.sign,          msg, sk, caches, repeat=REPEAT)
    t_parallel_sign  = benchmark(wots.sign_parallel, msg, sk,         repeat=REPEAT)
    t_serial_verify  = benchmark(wots.verify,        msg, sig,        repeat=REPEAT)
    t_parallel_verify= benchmark(wots.verify_parallel, msg, sig, pk,  repeat=REPEAT)

    print(f"  {'Operation':<22} {'Serial (ms)':<16} {'Parallel (ms)':<16} Speedup")
    print("  " + "-" * 62)
    for op, ts, tp in [("sign",   t_serial_sign,   t_parallel_sign),
                       ("verify", t_serial_verify, t_parallel_verify)]:
        speedup = ts / tp if tp > 0 else float('inf')
        print(f"  {op:<22} {ts*1000:<16.3f} {tp*1000:<16.3f} {speedup:.2f}x")

    print("\n=== Done ===")
