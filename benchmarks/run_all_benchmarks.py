"""
run_all_benchmarks.py – single entry point for all benchmarks.

Runs every benchmark module, collects timing data, writes a CSV
report and a human-readable text summary to results/.

Usage
-----
    cd sphincs_project/
    python run_all_benchmarks.py

Output
------
    results/benchmark_report.txt   – human-readable summary
    results/benchmark_data.csv     – machine-readable timings

Author: Shize Gao (z5603339)
"""

import sys, os, time, csv, io, contextlib
sys.path.insert(0, os.path.join(os.path.dirname(__file__), 'src'))

from wots        import WOTS, H, base_w, checksum, chain, build_chain_cache
from merkle      import MerkleTree
from merkle_cached import MerkleCached
from fors        import FORS
from fors_cached import FORSCached
from sphincs     import keygen, sign, verify

RESULTS_DIR = os.path.join(os.path.dirname(__file__), 'results')
os.makedirs(RESULTS_DIR, exist_ok=True)


# ---------------------------------------------------------------------------
# Micro-benchmark helper
# ---------------------------------------------------------------------------

def _bench(func, runs: int = 20) -> dict:
    times = []
    for _ in range(runs):
        t0 = time.perf_counter()
        func()
        times.append(time.perf_counter() - t0)
    return {
        "avg_ms": sum(times) / len(times) * 1000,
        "min_ms": min(times) * 1000,
        "max_ms": max(times) * 1000,
    }


def _row(label, d):
    return f"  {label:<40} avg {d['avg_ms']:8.3f} ms  min {d['min_ms']:7.3f} ms  max {d['max_ms']:7.3f} ms"


# ---------------------------------------------------------------------------
# Section 1 – WOTS+
# ---------------------------------------------------------------------------

def bench_wots(rows: list) -> str:
    lines = ["=" * 60, "WOTS+ Benchmarks", "=" * 60]

    for w in [4, 16, 256]:
        wots = WOTS(w_value=w)
        sk, pk, caches = wots.keygen()
        msg = b"benchmark message"

        d_kg  = _bench(lambda w=w: WOTS(w_value=w).keygen())
        d_sg  = _bench(lambda: wots.sign(msg, sk, caches))
        d_vf  = _bench(lambda: wots.verify(msg, wots.sign(msg, sk, caches)))

        lines.append(f"\n  [WOTS+ w={w}  length={wots.length}]")
        lines.append(_row("keygen", d_kg))
        lines.append(_row("sign (cached)", d_sg))
        lines.append(_row("verify", d_vf))

        # Baseline (no cache) for comparison
        def sign_baseline(wots=wots, msg=msg, sk=sk):
            mh = H(msg)
            mb = base_w(mh, wots.w, wots.len1)
            md = mb + checksum(mb, wots.w, wots.len2)
            return [chain(sk[i], md[i]) for i in range(wots.length)]

        d_bl = _bench(sign_baseline)
        lines.append(_row("sign (baseline, no cache)", d_bl))
        speedup = d_bl['avg_ms'] / d_sg['avg_ms']
        lines.append(f"  {'cache speedup':<40} {speedup:.2f}x")

        for op, d in [("keygen", d_kg), ("sign_cached", d_sg),
                      ("sign_baseline", d_bl), ("verify", d_vf)]:
            rows.append({"module": "WOTS+", "variant": f"w={w}",
                         "operation": op, **d})

    return "\n".join(lines)


# ---------------------------------------------------------------------------
# Section 2 – FORS
# ---------------------------------------------------------------------------

def bench_fors(rows: list) -> str:
    lines = ["=" * 60, "FORS Benchmarks", "=" * 60]
    msg   = b"benchmark message"

    for k, a in [(6, 4), (10, 6), (14, 8)]:
        baseline = FORS(k=k, a=a)
        cached   = FORSCached(k=k, a=a)
        bsk, bpk = baseline.keygen()
        csk, cpk = cached.keygen()
        bsig = baseline.sign(msg, bsk)
        csig = cached.sign(msg, csk)

        lines.append(f"\n  [FORS k={k}, a={a}, t={2**a}]")

        for label, obj, sk, pk, sig, tag in [
            ("baseline", baseline, bsk, bpk, bsig, "base"),
            ("cached  ", cached,   csk, cpk, csig, "cache"),
        ]:
            d_kg = _bench(lambda o=obj: o.keygen())
            d_sg = _bench(lambda o=obj, s=sk: o.sign(msg, s))
            d_vf = _bench(lambda o=obj, s=sig, p=pk: o.verify(msg, s, p))
            lines.append(f"    {label}")
            lines.append(_row("  keygen", d_kg))
            lines.append(_row("  sign",   d_sg))
            lines.append(_row("  verify", d_vf))
            for op, d in [("keygen", d_kg), ("sign", d_sg), ("verify", d_vf)]:
                rows.append({"module": "FORS", "variant": f"k={k},a={a},{tag}",
                             "operation": op, **d})

        sg_speedup = _bench(lambda o=baseline, s=bsk: o.sign(msg, s))['avg_ms'] / \
                     _bench(lambda o=cached, s=csk:  o.sign(msg, s))['avg_ms']
        lines.append(f"    sign speedup (cached vs baseline): {sg_speedup:.2f}x")

    return "\n".join(lines)


# ---------------------------------------------------------------------------
# Section 3 – Merkle
# ---------------------------------------------------------------------------

def bench_merkle(rows: list) -> str:
    lines = ["=" * 60, "Merkle Tree Benchmarks", "=" * 60]

    for n in [8, 64, 512, 1024]:
        leaves = [H(f"leaf{i}".encode()) for i in range(n)]
        bt = MerkleTree();  bt.build(leaves)
        ct = MerkleCached(); ct.build(leaves)

        lines.append(f"\n  [n_leaves={n}]")

        for label, obj, tag in [("baseline", bt, "base"), ("cached", ct, "cache")]:
            d_b  = _bench(lambda ls=leaves, o=type(obj): o().build(ls))
            d_ap = _bench(lambda o=obj: o.auth_path(0))
            lines.append(f"    {label}")
            lines.append(_row("  build", d_b))
            lines.append(_row("  auth_path(0)", d_ap))
            for op, d in [("build", d_b), ("auth_path", d_ap)]:
                rows.append({"module": "Merkle", "variant": f"n={n},{tag}",
                             "operation": op, **d})

        ap_speedup = _bench(lambda o=bt: o.auth_path(0))['avg_ms'] / \
                     _bench(lambda o=ct: o.auth_path(0))['avg_ms']
        lines.append(f"    auth_path speedup (cached vs baseline, n={n}): {ap_speedup:.2f}x")

    return "\n".join(lines)


# ---------------------------------------------------------------------------
# Section 4 – Full SPHINCS+
# ---------------------------------------------------------------------------

def bench_sphincs(rows: list) -> str:
    lines = ["=" * 60, "Full SPHINCS+ End-to-End Benchmarks", "=" * 60]
    msg   = b"benchmark message"

    param_sets = [
        ("Small ",  4,  6, 4),
        ("Medium",  8, 10, 6),
        ("Large ", 16, 14, 8),
    ]

    for label, nl, k, a in param_sets:
        priv, pub = keygen(num_leaves=nl, k=k, a=a)
        sig = sign(msg, priv, idx=0)

        d_kg = _bench(lambda nl=nl,k=k,a=a: keygen(num_leaves=nl, k=k, a=a), runs=5)
        d_sg = _bench(lambda: sign(msg, priv, idx=0))
        d_vf = _bench(lambda: verify(msg, sig, pub))

        # Approximate signature size
        fors_bytes = (sum(len(v) for v in sig['fors_sig']['sk_values']) +
                      sum(len(p) for path in sig['fors_sig']['auth_paths'] for p in path))
        wots_bytes = sum(len(x) for x in sig['wots_sig'])
        auth_bytes = sum(len(x) for x in sig['auth_path'])
        total_bytes = fors_bytes + wots_bytes + auth_bytes
        pk_bytes = len(pub['merkle_root']) + len(pub['fors_pk'])

        lines.append(f"\n  [{label}  num_leaves={nl}  k={k}  a={a}]")
        lines.append(_row("keygen", d_kg))
        lines.append(_row("sign",   d_sg))
        lines.append(_row("verify", d_vf))
        lines.append(f"  {'Public key size':<40} {pk_bytes} bytes")
        lines.append(f"  {'Signature size':<40} {total_bytes} bytes  "
                     f"(FORS={fors_bytes}  WOTS={wots_bytes}  auth={auth_bytes})")

        for op, d in [("keygen", d_kg), ("sign", d_sg), ("verify", d_vf)]:
            rows.append({"module": "SPHINCS+", "variant": label.strip(),
                         "operation": op, "sig_bytes": total_bytes,
                         "pk_bytes": pk_bytes, **d})

    return "\n".join(lines)


# ---------------------------------------------------------------------------
# Write outputs
# ---------------------------------------------------------------------------

def write_csv(rows: list) -> None:
    path = os.path.join(RESULTS_DIR, 'benchmark_data.csv')
    fieldnames = ["module", "variant", "operation",
                  "avg_ms", "min_ms", "max_ms", "sig_bytes", "pk_bytes"]
    with open(path, 'w', newline='') as f:
        w = csv.DictWriter(f, fieldnames=fieldnames, extrasaction='ignore')
        w.writeheader()
        w.writerows(rows)
    print(f"\n  CSV saved → {path}")


def write_report(sections: list) -> None:
    path = os.path.join(RESULTS_DIR, 'benchmark_report.txt')
    with open(path, 'w') as f:
        f.write("SPHINCS+ Benchmark Report\n")
        f.write(f"Generated: {time.strftime('%Y-%m-%d %H:%M:%S')}\n\n")
        for s in sections:
            f.write(s + "\n\n")
    print(f"  Report saved → {path}")


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

if __name__ == "__main__":
    print("Running all benchmarks – this may take ~60 seconds …\n")
    rows     = []
    sections = []

    for name, fn in [
        ("WOTS+",     bench_wots),
        ("FORS",      bench_fors),
        ("Merkle",    bench_merkle),
        ("SPHINCS+",  bench_sphincs),
    ]:
        print(f"  Benchmarking {name} …", flush=True)
        s = fn(rows)
        sections.append(s)
        print(s)
        print()

    write_csv(rows)
    write_report(sections)
    print("\nAll benchmarks complete.")
