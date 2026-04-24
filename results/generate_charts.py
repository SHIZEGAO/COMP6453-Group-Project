"""
generate_charts.py – produce all benchmark charts as PNG files.

Reads results/benchmark_data.csv (written by run_all_benchmarks.py)
and generates six publication-quality charts saved to results/charts/.

Usage
-----
    python run_all_benchmarks.py      # generate CSV first
    python generate_charts.py         # then produce charts

Author: Shize Gao (z5603339)
"""

import sys, os, csv, math
sys.path.insert(0, os.path.join(os.path.dirname(__file__), 'src'))

import matplotlib
matplotlib.use('Agg')
import matplotlib.pyplot as plt
import matplotlib.patches as mpatches
import numpy as np

RESULTS_DIR = os.path.join(os.path.dirname(__file__), 'results')
CHARTS_DIR  = os.path.join(RESULTS_DIR, 'charts')
CSV_PATH    = os.path.join(RESULTS_DIR, 'benchmark_data.csv')
os.makedirs(CHARTS_DIR, exist_ok=True)

# --- style -----------------------------------------------------------------
plt.rcParams.update({
    'figure.facecolor':  'white',
    'axes.facecolor':    '#F9F9F9',
    'axes.grid':          True,
    'grid.color':        '#DDDDDD',
    'grid.linewidth':     0.6,
    'font.family':       'DejaVu Sans',
    'font.size':          11,
    'axes.titlesize':     13,
    'axes.titleweight':  'bold',
    'axes.labelsize':     11,
    'legend.fontsize':    10,
    'xtick.labelsize':    10,
    'ytick.labelsize':    10,
})

BLUE   = '#1A6BAD'
ORANGE = '#D46B0F'
GREEN  = '#2E8B57'
RED    = '#B22222'
PURPLE = '#6A3B9C'
GRAY   = '#888888'

# ---------------------------------------------------------------------------
# Load CSV
# ---------------------------------------------------------------------------

def load_csv():
    rows = []
    with open(CSV_PATH) as f:
        for r in csv.DictReader(f):
            r['avg_ms'] = float(r['avg_ms'])
            r['min_ms'] = float(r['min_ms'])
            r['max_ms'] = float(r['max_ms'])
            rows.append(r)
    return rows


def select(rows, module=None, variant_contains=None, operation=None):
    out = rows
    if module:             out = [r for r in out if r['module'] == module]
    if variant_contains:   out = [r for r in out if variant_contains in r['variant']]
    if operation:          out = [r for r in out if r['operation'] == operation]
    return out


# ---------------------------------------------------------------------------
# Chart 1: WOTS+ cache vs baseline across w values
# ---------------------------------------------------------------------------

def chart_wots_cache(rows):
    w_vals   = [4, 16, 256]
    baselines = [select(rows, 'WOTS+', f'w={w}', 'sign_baseline')[0]['avg_ms'] for w in w_vals]
    cached    = [select(rows, 'WOTS+', f'w={w}', 'sign_cached')[0]['avg_ms']   for w in w_vals]

    x = np.arange(len(w_vals))
    w = 0.35

    fig, ax = plt.subplots(figsize=(7, 4.5))
    b1 = ax.bar(x - w/2, baselines, w, label='Baseline (no cache)', color=ORANGE, alpha=0.85)
    b2 = ax.bar(x + w/2, cached,    w, label='Cached',              color=BLUE,   alpha=0.85)

    for bars in [b1, b2]:
        for bar in bars:
            h = bar.get_height()
            ax.text(bar.get_x() + bar.get_width()/2, h + 0.002,
                    f'{h:.3f}', ha='center', va='bottom', fontsize=9)

    ax.set_xticks(x)
    ax.set_xticklabels([f'w = {v}' for v in w_vals])
    ax.set_ylabel('Sign time (ms)')
    ax.set_title('Chart 1: WOTS+ Sign – Cache vs Baseline')
    ax.legend()
    speedups = [b/c for b, c in zip(baselines, cached)]
    ax.set_xlabel(f'Winternitz parameter w  '
                  f'(speedup: {speedups[0]:.1f}x / {speedups[1]:.1f}x / {speedups[2]:.0f}x)')
    fig.tight_layout()
    path = os.path.join(CHARTS_DIR, 'chart1_wots_cache.png')
    fig.savefig(path, dpi=150)
    plt.close(fig)
    print(f'  Saved {path}')


# ---------------------------------------------------------------------------
# Chart 2: WOTS+ keygen / sign / verify across w
# ---------------------------------------------------------------------------

def chart_wots_ops(rows):
    w_vals = [4, 16, 256]
    ops    = ['keygen', 'sign_cached', 'verify']
    labels = ['Keygen', 'Sign (cached)', 'Verify']
    colors = [BLUE, GREEN, ORANGE]

    data = {op: [select(rows, 'WOTS+', f'w={w}', op)[0]['avg_ms'] for w in w_vals]
            for op in ops}

    x = np.arange(len(w_vals))
    width = 0.25

    fig, ax = plt.subplots(figsize=(7, 4.5))
    for i, (op, label, color) in enumerate(zip(ops, labels, colors)):
        bars = ax.bar(x + (i - 1) * width, data[op], width,
                      label=label, color=color, alpha=0.85)

    ax.set_xticks(x)
    ax.set_xticklabels([f'w = {v}' for v in w_vals])
    ax.set_ylabel('Time (ms)')
    ax.set_title('Chart 2: WOTS+ Operation Times vs w Parameter')
    ax.legend()
    ax.set_xlabel('Winternitz parameter w')
    fig.tight_layout()
    path = os.path.join(CHARTS_DIR, 'chart2_wots_ops.png')
    fig.savefig(path, dpi=150)
    plt.close(fig)
    print(f'  Saved {path}')


# ---------------------------------------------------------------------------
# Chart 3: FORS cached vs baseline sign time
# ---------------------------------------------------------------------------

def chart_fors_sign(rows):
    configs = [('k=6,a=4', 'k=6, a=4'), ('k=10,a=6', 'k=10, a=6'), ('k=14,a=8', 'k=14, a=8')]

    base_times  = [select(rows, 'FORS', cfg+',base',  'sign')[0]['avg_ms'] for cfg, _ in configs]
    cache_times = [select(rows, 'FORS', cfg+',cache', 'sign')[0]['avg_ms'] for cfg, _ in configs]
    xlabels     = [lbl for _, lbl in configs]

    x = np.arange(len(configs))
    w = 0.35

    fig, ax = plt.subplots(figsize=(7, 4.5))
    b1 = ax.bar(x - w/2, base_times,  w, label='FORS baseline', color=ORANGE, alpha=0.85)
    b2 = ax.bar(x + w/2, cache_times, w, label='FORSCached',    color=BLUE,   alpha=0.85)

    for bars in [b1, b2]:
        for bar in bars:
            h = bar.get_height()
            ax.text(bar.get_x() + bar.get_width()/2, h + 0.0003,
                    f'{h:.4f}', ha='center', va='bottom', fontsize=8)

    ax.set_xticks(x)
    ax.set_xticklabels(xlabels)
    ax.set_ylabel('Sign time (ms)')
    ax.set_title('Chart 3: FORS Sign Time – Cached vs Baseline')
    speedups = [b/c for b, c in zip(base_times, cache_times)]
    ax.set_xlabel(f'Parameter set  '
                  f'(speedup: {speedups[0]:.1f}x / {speedups[1]:.1f}x / {speedups[2]:.1f}x)')
    ax.legend()
    fig.tight_layout()
    path = os.path.join(CHARTS_DIR, 'chart3_fors_sign.png')
    fig.savefig(path, dpi=150)
    plt.close(fig)
    print(f'  Saved {path}')


# ---------------------------------------------------------------------------
# Chart 4: FORS keygen comparison (shows cache cost)
# ---------------------------------------------------------------------------

def chart_fors_keygen(rows):
    configs = [('k=6,a=4', 'k=6, a=4'), ('k=10,a=6', 'k=10, a=6'), ('k=14,a=8', 'k=14, a=8')]
    base  = [select(rows, 'FORS', c+',base',  'keygen')[0]['avg_ms'] for c, _ in configs]
    cache = [select(rows, 'FORS', c+',cache', 'keygen')[0]['avg_ms'] for c, _ in configs]
    xlabels = [l for _, l in configs]

    x = np.arange(len(configs))
    w = 0.35

    fig, ax = plt.subplots(figsize=(7, 4.5))
    ax.bar(x - w/2, base,  w, label='FORS baseline', color=ORANGE, alpha=0.85)
    ax.bar(x + w/2, cache, w, label='FORSCached',    color=BLUE,   alpha=0.85)
    ax.set_xticks(x); ax.set_xticklabels(xlabels)
    ax.set_ylabel('Keygen time (ms)')
    ax.set_title('Chart 4: FORS Keygen – Cached has higher upfront cost')
    ax.set_xlabel('Parameter set  (cache trades keygen time for sign speed)')
    ax.legend()
    fig.tight_layout()
    path = os.path.join(CHARTS_DIR, 'chart4_fors_keygen.png')
    fig.savefig(path, dpi=150)
    plt.close(fig)
    print(f'  Saved {path}')


# ---------------------------------------------------------------------------
# Chart 5: Full SPHINCS+ end-to-end
# ---------------------------------------------------------------------------

def chart_sphincs_e2e(rows):
    configs   = ['Small', 'Medium', 'Large']
    ops       = ['keygen', 'sign', 'verify']
    op_labels = ['Keygen', 'Sign', 'Verify']
    colors    = [BLUE, GREEN, ORANGE]

    data = {}
    for cfg in configs:
        for op in ops:
            hits = select(rows, 'SPHINCS+', cfg, op)
            data[(cfg, op)] = hits[0]['avg_ms'] if hits else 0

    x     = np.arange(len(configs))
    width = 0.25

    fig, ax = plt.subplots(figsize=(7, 4.5))
    for i, (op, label, color) in enumerate(zip(ops, op_labels, colors)):
        vals = [data[(cfg, op)] for cfg in configs]
        ax.bar(x + (i-1)*width, vals, width, label=label, color=color, alpha=0.85)

    ax.set_xticks(x)
    ax.set_xticklabels(['Small\n(nl=4,k=6,a=4)', 'Medium\n(nl=8,k=10,a=6)', 'Large\n(nl=16,k=14,a=8)'])
    ax.set_ylabel('Time (ms)')
    ax.set_title('Chart 5: SPHINCS+ End-to-End Performance')
    ax.legend()
    fig.tight_layout()
    path = os.path.join(CHARTS_DIR, 'chart5_sphincs_e2e.png')
    fig.savefig(path, dpi=150)
    plt.close(fig)
    print(f'  Saved {path}')


# ---------------------------------------------------------------------------
# Chart 6: Signature & key size across parameter sets
# ---------------------------------------------------------------------------

def chart_sizes(rows):
    configs   = ['Small', 'Medium', 'Large']
    sig_sizes = []
    pk_sizes  = []
    for cfg in configs:
        hits = [r for r in rows if r['module'] == 'SPHINCS+' and
                r['variant'].strip() == cfg and r['operation'] == 'sign']
        if hits and hits[0].get('sig_bytes'):
            sig_sizes.append(int(float(hits[0]['sig_bytes'])))
            pk_sizes.append(int(float(hits[0]['pk_bytes'])))
        else:
            sig_sizes.append(0); pk_sizes.append(0)

    x = np.arange(len(configs))
    w = 0.35

    fig, ax1 = plt.subplots(figsize=(7, 4.5))
    ax1.bar(x - w/2, sig_sizes, w, label='Signature size (B)', color=BLUE, alpha=0.85)
    ax1.bar(x + w/2, pk_sizes,  w, label='Public key size (B)', color=GREEN, alpha=0.85)
    ax1.set_xticks(x)
    ax1.set_xticklabels(['Small\n(nl=4,k=6,a=4)', 'Medium\n(nl=8,k=10,a=6)', 'Large\n(nl=16,k=14,a=8)'])
    ax1.set_ylabel('Size (bytes)')
    ax1.set_title('Chart 6: Signature & Public Key Size vs Parameter Set')
    ax1.legend()

    for i, (s, p) in enumerate(zip(sig_sizes, pk_sizes)):
        ax1.text(i - w/2, s + 20, f'{s}B', ha='center', fontsize=9)
        ax1.text(i + w/2, p + 20, f'{p}B', ha='center', fontsize=9)

    fig.tight_layout()
    path = os.path.join(CHARTS_DIR, 'chart6_sizes.png')
    fig.savefig(path, dpi=150)
    plt.close(fig)
    print(f'  Saved {path}')


# ---------------------------------------------------------------------------
# Chart 7: Scheme comparison (classical vs PQ)
# ---------------------------------------------------------------------------

def chart_scheme_comparison():
    schemes   = ['RSA-2048', 'ECDSA\nP-256', 'Dilithium-2', 'Falcon-512', 'SPHINCS+\n-128s', 'This impl.\n(Small)']
    pk_bytes  = [256,  64, 1312,  897,  32, 64]
    sig_bytes = [256,  64, 2420,  666, 7856, 3168]
    pq_safe   = [False, False, True, True, True, True]

    colors_pk  = [RED if not p else BLUE   for p in pq_safe]
    colors_sig = [RED if not p else ORANGE for p in pq_safe]

    x = np.arange(len(schemes))
    w = 0.35

    fig, ax = plt.subplots(figsize=(9, 5))
    b1 = ax.bar(x - w/2, pk_bytes,  w, label='Public key (B)',  color=colors_pk,  alpha=0.85)
    b2 = ax.bar(x + w/2, sig_bytes, w, label='Signature (B)',   color=colors_sig, alpha=0.85)

    ax.set_xticks(x)
    ax.set_xticklabels(schemes, fontsize=9)
    ax.set_ylabel('Size (bytes)')
    ax.set_title('Chart 7: Key & Signature Size – Classical vs Post-Quantum Schemes')

    pq_patch = mpatches.Patch(color=BLUE,   label='Post-quantum safe')
    cl_patch = mpatches.Patch(color=RED,    label='Classical (quantum-vulnerable)')
    pk_patch = mpatches.Patch(color=GRAY,   label='Public key size')
    sg_patch = mpatches.Patch(facecolor='none', edgecolor='black',
                               linestyle='--', label='Signature size (hatched)')
    ax.legend(handles=[pq_patch, cl_patch], loc='upper right')

    fig.tight_layout()
    path = os.path.join(CHARTS_DIR, 'chart7_scheme_comparison.png')
    fig.savefig(path, dpi=150)
    plt.close(fig)
    print(f'  Saved {path}')


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

if __name__ == "__main__":
    if not os.path.exists(CSV_PATH):
        print(f"ERROR: {CSV_PATH} not found.")
        print("Run   python run_all_benchmarks.py   first.")
        sys.exit(1)

    rows = load_csv()
    print("Generating charts …\n")

    chart_wots_cache(rows)
    chart_wots_ops(rows)
    chart_fors_sign(rows)
    chart_fors_keygen(rows)
    chart_sphincs_e2e(rows)
    chart_sizes(rows)
    chart_scheme_comparison()

    print(f"\nAll charts saved to {CHARTS_DIR}/")
