"""
parse_scalability.py — Parse Cooja scalability log and generate graph.

Usage:
    python3 scripts/parse_scalability.py <cooja_log_file>

Or run in demo mode (no log file) to generate a graph from
analytical estimates — useful for paper draft before real measurements.
"""

import sys
import os
import re

# ── Try to parse real Cooja log ───────────────────────────────────────────────
results = {}  # {n_motes: duration_ms}

if len(sys.argv) > 1 and os.path.exists(sys.argv[1]):
    with open(sys.argv[1]) as f:
        for line in f:
            m = re.search(r'RESULT: motes=(\d+) duration_ms=(\d+)', line)
            if m:
                results[int(m.group(1))] = int(m.group(2))
    print(f"Parsed {len(results)} results from {sys.argv[1]}")
else:
    # Demo mode: analytical estimates
    # Base: 864ms per device (our measured latency)
    # Concurrent auth: devices authenticate independently
    # Gateway overhead: linear in number of devices
    # (Each auth takes 864ms device-side; gateway adds ~50ms per device)
    print("Demo mode: using analytical estimates (no log file provided)")
    base = 864
    gateway_overhead_per_device = 50
    for n in [1, 10, 25, 50, 100]:
        # All devices start simultaneously, gateway serializes responses
        # Total time = device_auth_time + gateway_serialization
        results[n] = base + (gateway_overhead_per_device * n)

# ── Print table ───────────────────────────────────────────────────────────────
print("\n── Scalability Results ─────────────────────────────────────")
print(f"  {'Devices':>8}  {'Total (ms)':>12}  {'Per-device (ms)':>16}  {'Source'}")
print(f"  {'-'*8}  {'-'*12}  {'-'*16}  {'-'*12}")
for n in sorted(results.keys()):
    total = results[n]
    per = total / n
    src = "measured" if len(sys.argv) > 1 else "analytical"
    print(f"  {n:>8}  {total:>12}  {per:>16.1f}  {src}")

# ── Generate graph ────────────────────────────────────────────────────────────
try:
    import matplotlib
    matplotlib.use('Agg')
    import matplotlib.pyplot as plt
    import numpy as np

    ns = sorted(results.keys())
    totals = [results[n] for n in ns]
    per_device = [results[n]/n for n in ns]

    fig, (ax1, ax2) = plt.subplots(1, 2, figsize=(10, 4))

    # Total time vs number of devices
    ax1.plot(ns, totals, 'b-o', linewidth=2, markersize=6)
    ax1.set_xlabel('Number of Devices')
    ax1.set_ylabel('Total Authentication Time (ms)')
    ax1.set_title('Scalability: Total Auth Time')
    ax1.grid(True, alpha=0.3)
    ax1.set_xticks(ns)

    # Per-device time vs number of devices
    ax2.plot(ns, per_device, 'r-s', linewidth=2, markersize=6)
    ax2.set_xlabel('Number of Devices')
    ax2.set_ylabel('Per-Device Auth Time (ms)')
    ax2.set_title('Scalability: Per-Device Cost')
    ax2.grid(True, alpha=0.3)
    ax2.set_xticks(ns)
    ax2.axhline(y=864, color='gray', linestyle='--',
                label='Single-device baseline (864ms)')
    ax2.legend()

    plt.tight_layout()
    out = os.path.join(os.path.dirname(__file__),
                       '../paper/figures/scalability.png')
    os.makedirs(os.path.dirname(out), exist_ok=True)
    plt.savefig(out, dpi=150, bbox_inches='tight')
    print(f"\nGraph saved to: {out}")
    plt.close()

except ImportError:
    print("\nmatplotlib not installed. Install with:")
    print("  pip install matplotlib --break-system-packages")

print("─" * 60)
