# SPHINCS+ Simplified Implementation

A Python implementation of a simplified SPHINCS+ (SLH-DSA) post-quantum
signature scheme, built from modular components by a team of five.

## Team

| Member | zID | Responsibility |
|---|---|---|
| Yixuan Wang | z5607523 | Project coordination, SPHINCS+ main workflow (`sphincs.py`) |
| Shize Gao | z5603339 | WOTS+ module (`wots.py`), benchmarks 1–3 Final document integration (`demo.py`)|
| Peiliang Zhao | z5539814 | Merkle Tree module (`merkle.py`, `merkle_cached.py`) |
| Kaiqi Shi | z5622283 | FORS modules (`fors.py`, `fors_cached.py`) |
| Mingzi Chen | z5437121 | Integration, benchmarking, KAT tests, demo, charts |

---

## Quick Start

No third-party packages required for core modules (only `hashlib`, `secrets`).
`matplotlib` is needed only for chart generation.

```bash
# 1. Run the live demo
python demo.py

# 2. Run all tests (including KATs)
cd tests/
python test_wots.py && python test_merkle.py && python test_fors.py \
  && python test_sphincs.py && python test_kat.py
cd ..

# 3. Run all benchmarks (generates results/benchmark_data.csv)
python run_all_benchmarks.py

# 4. Generate charts (requires matplotlib)
python generate_charts.py
```

---

## Project Structure

```
sphincs_project/
├── demo.py                    ← live demonstration (run this for a presentation)
├── run_all_benchmarks.py      ← automated benchmark runner → CSV + report
├── generate_charts.py         ← produces 7 PNG charts from benchmark CSV
│
├── src/
│   ├── wots.py                ← WOTS+ (chain-cache optimisation)
│   ├── merkle.py              ← Merkle Tree (baseline)
│   ├── merkle_cached.py       ← Merkle Tree (flat-dict node cache, optimisation ③)
│   ├── fors.py                ← FORS baseline
│   ├── fors_cached.py         ← FORS with precomputed auth-path cache (optimisation ②)
│   └── sphincs.py             ← top-level keygen / sign / verify
│
├── tests/
│   ├── test_wots.py
│   ├── test_merkle.py
│   ├── test_fors.py
│   ├── test_sphincs.py        ← integration tests
│   └── test_kat.py            ← Known-Answer Tests (deterministic, bit-exact)
│
├── benchmarks/
│   ├── benchmark1_cache_vs_baseline.py   ← WOTS+ cache speedup
│   ├── benchmark2_w_analysis.py          ← WOTS+ w-parameter sweep
│   ├── benchmark3_serial_vs_parallel.py  ← WOTS+ parallel chain computation
│   ├── benchmark_fors_cached.py          ← FORS baseline vs cached
│   ├── benchmark_merkle.py               ← Merkle baseline operation scaling
│   ├── benchmark5_merkle_cached.py       ← MerkleCached vs baseline
│   └── benchmark_sphincs.py              ← full end-to-end (3 param sets)
│
└── results/                   ← created automatically
    ├── benchmark_report.txt
    ├── benchmark_data.csv
    └── charts/
        ├── chart1_wots_cache.png
        ├── chart2_wots_ops.png
        ├── chart3_fors_sign.png
        ├── chart4_fors_keygen.png
        ├── chart5_sphincs_e2e.png
        ├── chart6_sizes.png
        └── chart7_scheme_comparison.png
```

---

## Architecture

```
         Message
            │
      ┌─────▼──────┐
      │    FORS     │  few-time signature on raw message
      └─────┬──────┘
            │ fors_pk (reconstructed via Merkle auth paths)
      ┌─────▼──────┐
      │  H(fors_pk) │  digest used as WOTS+ input
      └─────┬──────┘
            │
      ┌─────▼──────┐
      │   WOTS+     │  one-time signature on digest
      └─────┬──────┘
            │ pk_rec
      ┌─────▼──────┐
      │ Merkle Tree │  root authenticates WOTS+ public key
      └────────────┘

Public key  = (merkle_root, fors_pk)          — always 64 bytes
Signature   = (fors_sig, wots_sig, auth_path, idx)
```

---

## Optimisations

Three distinct optimisations are implemented, each targeting a different
performance parameter:

### ① WOTS+ chain cache  (`wots.py`)
During `keygen`, all `w` intermediate chain values for every secret key
element are precomputed and stored. Signing reads directly from the cache
instead of recomputing chains, reducing sign from O(length × avg_steps)
hash calls to O(length) table lookups.

| w  | Baseline sign | Cached sign | Speedup |
|----|--------------|-------------|---------|
| 4  | ~0.133 ms    | ~0.027 ms   | ~5×     |
| 16 | ~0.216 ms    | ~0.016 ms   | ~14×    |
| 256| ~1.830 ms    | ~0.012 ms   | ~153×   |

### ② FORS auth-path cache  (`fors_cached.py`)
`FORSCached` precomputes the Merkle authentication path for **every leaf
in every tree** at keygen time. Signing is then O(k) dictionary reads
with no tree traversal.

| k, a    | Baseline sign | Cached sign | Speedup |
|---------|--------------|-------------|---------|
| 6,  4   | ~0.007 ms    | ~0.002 ms   | ~3.5×   |
| 10, 6   | ~0.016 ms    | ~0.003 ms   | ~5×     |
| 14, 8   | ~0.049 ms    | ~0.004 ms   | ~13×    |

Trade-off: keygen is ~1.2–1.5× slower; signing is significantly faster.

### ③ MerkleCached flat node dict  (`merkle_cached.py`)
Every internal node is stored in a flat `dict[(level, index) → bytes]`
with a pre-stored level-size array. `auth_path()` is O(h) dict lookups
with zero list allocation, versus the baseline which slices level lists
and checks odd-node duplication each call.

| n leaves | Baseline auth_path | Cached auth_path | Speedup |
|----------|--------------------|------------------|---------|
| 8        | ~0.7 µs            | ~0.7 µs          | ~1×     |
| 512      | ~4.9 µs            | ~1.4 µs          | ~3.3×   |
| 1024     | ~8.2 µs            | ~1.5 µs          | ~5.4×   |

Benefit grows with tree size; negligible overhead for small trees.

---

## Complexity Analysis

```
Module     │ Operation │ Complexity         │ Concrete (default params)
───────────┼───────────┼────────────────────┼────────────────────────────
WOTS+      │ keygen    │ O(length × w)      │ 67 × 16 = 1,072 hash calls
           │ sign      │ O(length)          │ 67 cache lookups
           │ verify    │ O(length × w/2)    │ 67 × 8 ≈ 536 hash calls avg
───────────┼───────────┼────────────────────┼────────────────────────────
FORS       │ keygen    │ O(k × t)           │ 10 × 64 = 640 hash calls
           │ sign      │ O(k × a)           │ 10 × 6 = 60 ops
           │ verify    │ O(k × a)           │ 10 × 6 = 60 hash calls
───────────┼───────────┼────────────────────┼────────────────────────────
Merkle     │ build     │ O(2n)              │ 2n – 1 hash calls
           │ auth_path │ O(h) = O(log n)    │ h dict/list lookups
           │ verify    │ O(h) = O(log n)    │ h hash calls
───────────┼───────────┼────────────────────┼────────────────────────────
SPHINCS+   │ keygen    │ O(k·t + L·len·w)  │ L = num_leaves
           │ sign      │ O(k·a + len + h)  │ dominated by WOTS+ verify
           │ verify    │ O(k·a + len·w/2)  │ + O(h) Merkle path
```

---

## Scheme Comparison

| Scheme        | PQ-safe | PK size  | Sig size  | Security basis      |
|---------------|---------|----------|-----------|---------------------|
| RSA-2048      | ✗       | 256 B    | 256 B     | Integer factoring   |
| ECDSA P-256   | ✗       | 64 B     | 64 B      | Discrete logarithm  |
| Dilithium-2   | ✓       | 1,312 B  | 2,420 B   | Module LWE          |
| Falcon-512    | ✓       | 897 B    | 666 B     | NTRU lattice        |
| SPHINCS+-128s | ✓       | 32 B     | 7,856 B   | Hash only (SHA-256) |
| **This impl.**| **✓**   | **64 B** | **3,168 B** | **Hash only (SHA-256)** |

SPHINCS+ / SLH-DSA is the **most conservative** post-quantum choice:
security rests solely on the collision resistance of SHA-256, with no
dependence on algebraic problems that may weaken as research advances.

---

## Parameters

| Parameter   | Meaning                               | Default |
|-------------|---------------------------------------|---------|
| `n`         | Hash output length (bytes)            | 32      |
| `w`         | WOTS+ Winternitz parameter            | 16      |
| `num_leaves`| WOTS+ key pairs in the hypertree      | 4       |
| `k`         | FORS number of trees                  | 10      |
| `a`         | FORS tree height (2^a leaves/tree)    | 6       |

---

## Known Simplifications vs Full SPHINCS+ (FIPS 205)

- Single hypertree layer (full SLH-DSA uses d layers).
- No ADRS (address) tweaks or domain separation.
- `secrets.token_bytes` used for key material (no SPHINCS+ PRF).
- SHA-256 only; standard also supports SHAKE-256.
- No serialisation / byte-array encoding of keys or signatures.
- Reduced parameters → does not achieve 128-bit post-quantum security.
