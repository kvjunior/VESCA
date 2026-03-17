#!/usr/bin/env python3
"""
VESCA Visualization Module
============================
Generates all figures and tables for the paper, following IEEE TDSC
formatting guidelines. Publication-quality plots with consistent styling.

Figures generated:
  Fig. 4:  Computational cost at edge server vs vehicle count
  Fig. 5:  Blockchain delay/throughput heatmaps
  Fig. 6:  Average verification & aggregation delay
  Fig. 7:  Average message loss rate
  Fig. 8:  SignCrypt computation cost comparison
  Fig. 9:  UnSignCrypt computation cost comparison
  NEW Fig: Security level comparison (80-bit vs 128-bit)
  NEW Fig: Blockchain storage overhead scaling
  NEW Fig: Communication overhead bar chart

Tables generated (LaTeX):
  Table V:   Cryptographic operation execution times
  Table VII: Computational time comparison
  Table VIII:Communication overhead comparison
  Table IX:  Blockchain transaction performance
  NEW Table: Blockchain storage overhead
"""

import os
import json
import numpy as np
import matplotlib
matplotlib.use('Agg')  # Non-interactive backend
import matplotlib.pyplot as plt
import matplotlib.ticker as ticker
from matplotlib.colors import Normalize
from matplotlib.cm import ScalarMappable

from config import (
    SecurityLevel, SECURITY_CURVES, BENCHMARK_CONFIG,
    BLOCKCHAIN_CONFIG, NETWORK_SIM_CONFIG,
    FIGURES_DIR, TABLES_DIR, DATA_DIR,
)
from baselines import EXTENDED_BASELINES

# ============================================================================
# Global Plot Style (IEEE-compatible)
# ============================================================================

plt.rcParams.update({
    'font.family': 'serif',
    'font.size': 10,
    'axes.labelsize': 11,
    'axes.titlesize': 11,
    'legend.fontsize': 8,
    'xtick.labelsize': 9,
    'ytick.labelsize': 9,
    'figure.dpi': 300,
    'savefig.dpi': 300,
    'savefig.bbox': 'tight',
    'lines.linewidth': 1.5,
    'lines.markersize': 5,
})

# Color scheme: distinguishable, colorblind-friendly
SCHEME_COLORS = {
    "Yu2021":       "#1f77b4",
    "Dohare2022":   "#ff7f0e",
    "Yang2022a":    "#2ca02c",
    "Yang2022b":    "#d62728",
    "Rajkumar2023": "#9467bd",
    "Dai2022":      "#8c564b",
    "Cobblah2024":  "#e377c2",
    "Wang2025":     "#bcbd22",
    "Liu2025":      "#17becf",
    "VESCA":        "#000000",
}

SCHEME_MARKERS = {
    "Yu2021":       "o",
    "Dohare2022":   "s",
    "Yang2022a":    "^",
    "Yang2022b":    "v",
    "Rajkumar2023": "D",
    "Dai2022":      "<",
    "Cobblah2024":  ">",
    "Wang2025":     "h",
    "Liu2025":      "*",
    "VESCA":        "X",
}


# ============================================================================
# Helper Functions
# ============================================================================

def _get_label(key: str) -> str:
    """Get display label for a scheme."""
    if key == "VESCA":
        return "VESCA (Ours)"
    if key in EXTENDED_BASELINES:
        return EXTENDED_BASELINES[key].label
    return key


def _save_fig(fig, filename: str):
    """Save figure to both PNG and PDF."""
    png_path = os.path.join(FIGURES_DIR, f"{filename}.png")
    pdf_path = os.path.join(FIGURES_DIR, f"{filename}.pdf")
    fig.savefig(png_path)
    fig.savefig(pdf_path)
    plt.close(fig)
    return png_path


# ============================================================================
# Figure 4: Edge Server Computational Cost
# ============================================================================

def plot_edge_server_cost(scaling_results: dict, level: SecurityLevel):
    """
    Plot computational cost at edge server vs number of vehicles.
    """
    fig, ax = plt.subplots(figsize=(7, 4.5))

    for key, data_list in scaling_results.items():
        if not data_list:
            continue
        ns = [d.n_vehicles for d in data_list]
        costs = [d.edge_cost_ms for d in data_list]
        ax.plot(ns, costs, color=SCHEME_COLORS.get(key, "#333"),
                marker=SCHEME_MARKERS.get(key, "o"),
                label=_get_label(key), markevery=2)

    ax.set_xlabel("Number of Vehicles")
    ax.set_ylabel("Computational Cost at Edge Server (ms)")
    ax.legend(loc="upper left", ncol=2, framealpha=0.9)
    ax.grid(True, alpha=0.3)
    sec = SECURITY_CURVES[level].bit_security
    ax.set_title(f"Edge Server Cost ({sec}-bit Security)")

    return _save_fig(fig, f"fig4_edge_cost_{sec}bit")


# ============================================================================
# Figure 5: Blockchain Performance Heatmaps
# ============================================================================

def plot_blockchain_heatmaps(bc_perf: dict):
    """
    Plot combined delay and throughput heatmaps.
    """
    fig, (ax1, ax2) = plt.subplots(1, 2, figsize=(12, 4.5))

    send_rates = bc_perf["send_rates"]
    tx_counts = bc_perf["tx_counts"]
    delay = np.array(bc_perf["delay_heatmap"])
    throughput = np.array(bc_perf["throughput_heatmap"])

    # Delay heatmap
    im1 = ax1.imshow(delay, cmap='YlOrRd', aspect='auto')
    ax1.set_xticks(range(len(send_rates)))
    ax1.set_xticklabels(send_rates)
    ax1.set_yticks(range(len(tx_counts)))
    ax1.set_yticklabels(tx_counts)
    ax1.set_xlabel("Transaction Send Rate (TPS)")
    ax1.set_ylabel("Number of Transactions")
    ax1.set_title("(a) Average Delay (ms)")

    # Annotate cells
    for i in range(len(tx_counts)):
        for j in range(len(send_rates)):
            ax1.text(j, i, f"{int(delay[i,j])}",
                    ha="center", va="center", fontsize=7,
                    color="white" if delay[i,j] > 300 else "black")
    fig.colorbar(im1, ax=ax1, label="Delay (ms)")

    # Throughput heatmap
    im2 = ax2.imshow(throughput, cmap='YlGn', aspect='auto')
    ax2.set_xticks(range(len(send_rates)))
    ax2.set_xticklabels(send_rates)
    ax2.set_yticks(range(len(tx_counts)))
    ax2.set_yticklabels(tx_counts)
    ax2.set_xlabel("Transaction Send Rate (TPS)")
    ax2.set_ylabel("Number of Transactions")
    ax2.set_title("(b) Achieved Throughput (TPS)")

    for i in range(len(tx_counts)):
        for j in range(len(send_rates)):
            ax2.text(j, i, f"{int(throughput[i,j])}",
                    ha="center", va="center", fontsize=7,
                    color="white" if throughput[i,j] < 300 else "black")
    fig.colorbar(im2, ax=ax2, label="Throughput (TPS)")

    fig.tight_layout()
    return _save_fig(fig, "fig5_blockchain_heatmaps")


# ============================================================================
# Figures 6 & 7: Network Simulation (Delay & Loss)
# ============================================================================

def plot_network_delay(net_results: list):
    """Plot average verification & aggregation delay vs vehicle density."""
    fig, ax = plt.subplots(figsize=(7, 4.5))

    periods = sorted(set(r.batch_period_ms for r in net_results))
    markers = ['o', 's', '^', 'v', 'D']

    for idx, P in enumerate(periods):
        subset = [r for r in net_results if r.batch_period_ms == P]
        subset.sort(key=lambda r: r.vehicle_density)
        densities = [r.vehicle_density for r in subset]
        delays = [r.avg_delay_ms for r in subset]
        ax.plot(densities, delays, marker=markers[idx % len(markers)],
                label=f"P = {P} ms")

    ax.set_xlabel("Vehicle Density")
    ax.set_ylabel("Average Verification & Aggregation Delay (ms)")
    ax.axhline(y=100, color='red', linestyle='--', alpha=0.5, label="100 ms threshold")
    ax.legend(loc="upper left")
    ax.grid(True, alpha=0.3)

    return _save_fig(fig, "fig6_network_delay")


def plot_network_loss(net_results: list):
    """Plot average message loss rate vs vehicle density."""
    fig, ax = plt.subplots(figsize=(7, 4.5))

    periods = sorted(set(r.batch_period_ms for r in net_results))
    markers = ['o', 's', '^', 'v', 'D']

    for idx, P in enumerate(periods):
        subset = [r for r in net_results if r.batch_period_ms == P]
        subset.sort(key=lambda r: r.vehicle_density)
        densities = [r.vehicle_density for r in subset]
        losses = [r.loss_rate for r in subset]
        ax.plot(densities, losses, marker=markers[idx % len(markers)],
                label=f"P = {P} ms")

    ax.set_xlabel("Vehicle Density")
    ax.set_ylabel("Average Loss Rate")
    ax.legend(loc="upper left")
    ax.grid(True, alpha=0.3)
    ax.set_ylim(-0.05, 1.05)

    return _save_fig(fig, "fig7_network_loss")


# ============================================================================
# Figures 8 & 9: SignCrypt and UnSignCrypt Cost Comparison
# ============================================================================

def plot_signcrypt_cost(scaling_results: dict, level: SecurityLevel):
    """Plot signcryption computation cost comparison."""
    fig, ax = plt.subplots(figsize=(7, 4.5))

    for key, data_list in scaling_results.items():
        if not data_list:
            continue
        ns = [d.n_vehicles for d in data_list]
        costs = [d.signcrypt_ms * d.n_vehicles for d in data_list]
        ax.plot(ns, costs, color=SCHEME_COLORS.get(key, "#333"),
                marker=SCHEME_MARKERS.get(key, "o"),
                label=_get_label(key), markevery=2)

    ax.set_xlabel("Number of Vehicles")
    ax.set_ylabel("Execution Time (ms)")
    ax.legend(loc="upper left", ncol=2, framealpha=0.9)
    ax.grid(True, alpha=0.3)
    sec = SECURITY_CURVES[level].bit_security
    ax.set_title(f"Signcryption Cost ({sec}-bit Security)")

    return _save_fig(fig, f"fig8_signcrypt_cost_{sec}bit")


def plot_unsigncrypt_cost(scaling_results: dict, level: SecurityLevel):
    """Plot unsigncryption computation cost comparison."""
    fig, ax = plt.subplots(figsize=(7, 4.5))

    for key, data_list in scaling_results.items():
        if not data_list:
            continue
        ns = [d.n_vehicles for d in data_list]
        costs = [d.unsigncrypt_ms for d in data_list]
        ax.plot(ns, costs, color=SCHEME_COLORS.get(key, "#333"),
                marker=SCHEME_MARKERS.get(key, "o"),
                label=_get_label(key), markevery=2)

    ax.set_xlabel("Number of Vehicles")
    ax.set_ylabel("Execution Time (ms)")
    ax.legend(loc="upper left", ncol=2, framealpha=0.9)
    ax.grid(True, alpha=0.3)
    sec = SECURITY_CURVES[level].bit_security
    ax.set_title(f"Unsigncryption Cost ({sec}-bit Security)")

    return _save_fig(fig, f"fig9_unsigncrypt_cost_{sec}bit")


# ============================================================================
# NEW: Security Level Comparison Figure
# ============================================================================

def plot_security_level_comparison(sec_comp: list):
    """Bar chart comparing 80-bit vs 128-bit VESCA costs."""
    fig, ax = plt.subplots(figsize=(8, 4))

    ops = [c.operation for c in sec_comp]
    costs_80 = [c.cost_80bit_ms for c in sec_comp]
    costs_128 = [c.cost_128bit_ms for c in sec_comp]

    x = np.arange(len(ops))
    width = 0.35

    bars1 = ax.bar(x - width/2, costs_80, width, label='80-bit (BACAS)',
                   color='#1f77b4', alpha=0.8)
    bars2 = ax.bar(x + width/2, costs_128, width, label='128-bit (VESCA)',
                   color='#ff7f0e', alpha=0.8)

    ax.set_xlabel("Operation")
    ax.set_ylabel("Execution Time (ms)")
    ax.set_title("Security Level Impact on VESCA Performance")
    ax.set_xticks(x)
    ax.set_xticklabels(ops, rotation=20, ha='right', fontsize=8)
    ax.legend()
    ax.grid(True, axis='y', alpha=0.3)

    # Add overhead percentages
    for i, c in enumerate(sec_comp):
        ax.annotate(f"+{c.overhead_pct:.0f}%",
                   xy=(x[i] + width/2, costs_128[i]),
                   ha='center', va='bottom', fontsize=7, color='#d62728')

    fig.tight_layout()
    return _save_fig(fig, "fig_security_level_comparison")


# ============================================================================
# NEW: Blockchain Storage Overhead
# ============================================================================

def plot_blockchain_storage(storage_results: list):
    """Plot blockchain storage scaling with number of vehicles."""
    fig, (ax1, ax2) = plt.subplots(1, 2, figsize=(10, 4))

    nvs = [s.num_vehicles for s in storage_results]
    totals_mb = [s.total_ledger_bytes / (1024*1024) for s in storage_results]
    per_vehicle = [s.per_vehicle_bytes for s in storage_results]
    reg_mb = [s.registration_bytes / (1024*1024) for s in storage_results]
    upd_mb = [s.update_bytes / (1024*1024) for s in storage_results]

    # Total storage
    ax1.bar(range(len(nvs)), reg_mb, label='Registration', color='#1f77b4')
    ax1.bar(range(len(nvs)), upd_mb, bottom=reg_mb,
            label='Pseudonym Updates', color='#ff7f0e')
    ax1.set_xticks(range(len(nvs)))
    ax1.set_xticklabels([str(n) for n in nvs])
    ax1.set_xlabel("Number of Vehicles")
    ax1.set_ylabel("Storage (MB)")
    ax1.set_title("(a) Total Ledger Size")
    ax1.legend()
    ax1.grid(True, axis='y', alpha=0.3)

    # Per-vehicle cost
    ax2.plot(nvs, per_vehicle, 'o-', color='#2ca02c', linewidth=2)
    ax2.set_xlabel("Number of Vehicles")
    ax2.set_ylabel("Storage per Vehicle (bytes)")
    ax2.set_title("(b) Per-Vehicle Storage Overhead")
    ax2.grid(True, alpha=0.3)
    ax2.set_xscale('log')

    fig.tight_layout()
    return _save_fig(fig, "fig_blockchain_storage")


# ============================================================================
# NEW: Communication Overhead Bar Chart
# ============================================================================

def plot_comm_overhead(level: SecurityLevel = SecurityLevel.LEVEL_128):
    """Bar chart of communication overhead comparison."""
    from config import VESCA_COMM_OVERHEAD_BYTES_128, VESCA_COMM_OVERHEAD_BYTES_80

    fig, ax = plt.subplots(figsize=(8, 4))

    schemes = list(EXTENDED_BASELINES.values())
    labels = [s.label for s in schemes] + ["VESCA (Ours)"]
    vesca_bytes = (VESCA_COMM_OVERHEAD_BYTES_128 if level == SecurityLevel.LEVEL_128
                   else VESCA_COMM_OVERHEAD_BYTES_80)
    values = [s.comm_overhead_bytes for s in schemes] + [vesca_bytes]

    colors = ['#1f77b4'] * len(schemes) + ['#d62728']
    bars = ax.barh(range(len(labels)), values, color=colors, alpha=0.8)

    ax.set_yticks(range(len(labels)))
    ax.set_yticklabels(labels, fontsize=8)
    ax.set_xlabel("Communication Overhead (bytes)")
    ax.set_title(f"Per-Message Communication Cost ({SECURITY_CURVES[level].bit_security}-bit)")
    ax.grid(True, axis='x', alpha=0.3)

    # Annotate values
    for i, (bar, val) in enumerate(zip(bars, values)):
        ax.text(val + 20, bar.get_y() + bar.get_height()/2,
                f"{val}", va='center', fontsize=8)

    fig.tight_layout()
    return _save_fig(fig, f"fig_comm_overhead_{SECURITY_CURVES[level].bit_security}bit")


# ============================================================================
# Master Plot Generator
# ============================================================================

def generate_all_figures(eval_results, verbose: bool = True):
    """Generate all paper figures from evaluation results."""
    generated = []

    if verbose:
        print("\n  Generating figures...")

    # Figures for each security level
    for level in BENCHMARK_CONFIG.security_levels:
        if level in eval_results.scaling_results:
            scaling = eval_results.scaling_results[level]

            p = plot_edge_server_cost(scaling, level)
            generated.append(p)
            if verbose: print(f"    {os.path.basename(p)}")

            p = plot_signcrypt_cost(scaling, level)
            generated.append(p)
            if verbose: print(f"    {os.path.basename(p)}")

            p = plot_unsigncrypt_cost(scaling, level)
            generated.append(p)
            if verbose: print(f"    {os.path.basename(p)}")

    # Blockchain heatmaps
    p = plot_blockchain_heatmaps(eval_results.blockchain_perf)
    generated.append(p)
    if verbose: print(f"    {os.path.basename(p)}")

    # Network simulation
    p = plot_network_delay(eval_results.network_sim)
    generated.append(p)
    if verbose: print(f"    {os.path.basename(p)}")

    p = plot_network_loss(eval_results.network_sim)
    generated.append(p)
    if verbose: print(f"    {os.path.basename(p)}")

    # Security level comparison
    p = plot_security_level_comparison(eval_results.security_comparison)
    generated.append(p)
    if verbose: print(f"    {os.path.basename(p)}")

    # Blockchain storage
    p = plot_blockchain_storage(eval_results.blockchain_storage)
    generated.append(p)
    if verbose: print(f"    {os.path.basename(p)}")

    # Communication overhead
    for level in [SecurityLevel.LEVEL_128]:
        p = plot_comm_overhead(level)
        generated.append(p)
        if verbose: print(f"    {os.path.basename(p)}")

    if verbose:
        print(f"\n  Total figures generated: {len(generated)}")
        print(f"  Output directory: {FIGURES_DIR}/")

    return generated


if __name__ == "__main__":
    # Quick test with minimal iterations
    from evaluation import run_full_evaluation
    results = run_full_evaluation(iterations=200, verbose=True)
    figs = generate_all_figures(results, verbose=True)
