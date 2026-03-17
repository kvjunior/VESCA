#!/usr/bin/env python3
"""
VESCA Baseline Comparison Module
==================================
Implements cost estimation for all baseline certificateless aggregate
signcryption schemes, enabling fair comparison with VESCA.

Baseline schemes included:
  Original BACAS baselines:
    - Yu et al. (2021) IEEE Syst. J.
    - Dohare et al. (2022) IEEE Trans. Ind. Inform.
    - Yang et al. (2022) IEEE TIFS
    - Yang et al. (2022) IEEE TGCN
    - Rajkumar et al. (2023) Wireless Networks
    - Dai et al. (2022) IEEE IoT J.

  NEW baselines (Reviewer 3 suggested references):
    - Cobblah et al. (2024) IEEE IoT J.
    - Cobblah et al. (2025) IEEE/ACM TON
    - Wang et al. (2025) IEEE IoT J.
    - Liu et al. (2025) IEEE IoT J.

Methodology:
  Baseline costs are computed using the PairingSimulator calibrated
  to actual ETsm measurements on the same hardware, ensuring fair
  apples-to-apples comparison.
"""

import json
import os
from typing import Dict, List, Tuple, Optional
from dataclasses import dataclass

from config import (
    SecurityLevel, DEFAULT_SECURITY_LEVEL, SECURITY_CURVES,
    BASELINE_SCHEMES, BaselineScheme,
    VESCA_SIGNCRYPT_FORMULA, VESCA_UNSIGNCRYPT_FORMULA,
    VESCA_BATCH_VERIFY_FORMULA,
    VESCA_COMM_OVERHEAD_BYTES_80, VESCA_COMM_OVERHEAD_BYTES_128,
    DATA_DIR,
)
from primitives import PairingSimulator, BenchmarkResult


# ============================================================================
# SECTION 1: Comprehensive Baseline Registry
# ============================================================================

# Extended with Reviewer 3 references
# NOTE: Cobblah et al. (2025) IEEE/ACM TON is a blockchain-based reputation
# and trust management framework using PBFT consensus, NOT a signcryption
# scheme. It is cited in Related Work but excluded from cost comparison.
EXTENDED_BASELINES = dict(BASELINE_SCHEMES)


# ============================================================================
# SECTION 2: Cost Computation Engine
# ============================================================================

@dataclass
class SchemeCostProfile:
    """Complete cost profile for a single scheme at a given vehicle count."""
    label: str
    signcrypt_ms: float
    unsigncrypt_ms: float
    total_ms: float
    comm_bytes: int
    uses_pairing: bool
    year: int
    venue: str


def compute_scheme_costs(
    simulator: PairingSimulator,
    scheme: BaselineScheme,
    n: int = 1,
) -> SchemeCostProfile:
    """
    Compute signcryption and unsigncryption costs for a baseline scheme
    at a given vehicle count n.
    """
    sc_cost = simulator.evaluate_formula(scheme.signcrypt_formula, n)
    usc_cost = simulator.evaluate_formula(scheme.unsigncrypt_formula, n)

    return SchemeCostProfile(
        label=scheme.label,
        signcrypt_ms=sc_cost,
        unsigncrypt_ms=usc_cost,
        total_ms=sc_cost + usc_cost,
        comm_bytes=scheme.comm_overhead_bytes,
        uses_pairing=scheme.uses_pairing,
        year=scheme.year,
        venue=scheme.venue,
    )


def compute_vesca_costs(
    simulator: PairingSimulator,
    n: int = 1,
    level: SecurityLevel = DEFAULT_SECURITY_LEVEL,
) -> SchemeCostProfile:
    """Compute VESCA costs at a given vehicle count n."""
    sc_cost = simulator.evaluate_formula(VESCA_SIGNCRYPT_FORMULA, n)
    usc_cost = simulator.evaluate_formula(VESCA_UNSIGNCRYPT_FORMULA, n)

    if level == SecurityLevel.LEVEL_128:
        comm = VESCA_COMM_OVERHEAD_BYTES_128
    else:
        comm = VESCA_COMM_OVERHEAD_BYTES_80

    return SchemeCostProfile(
        label="VESCA (Ours)",
        signcrypt_ms=sc_cost,
        unsigncrypt_ms=usc_cost,
        total_ms=sc_cost + usc_cost,
        comm_bytes=comm,
        uses_pairing=False,
        year=2026,
        venue="(This work)",
    )


# ============================================================================
# SECTION 3: Full Comparison Tables
# ============================================================================

def generate_comparison_table(
    simulator: PairingSimulator,
    vehicle_counts: List[int] = None,
    level: SecurityLevel = DEFAULT_SECURITY_LEVEL,
    include_vesca: bool = True,
) -> Dict[str, List[SchemeCostProfile]]:
    """
    Generate full comparison data for all schemes across vehicle counts.

    Returns:
        Dict mapping scheme_key -> list of SchemeCostProfile (one per vehicle count)
    """
    if vehicle_counts is None:
        vehicle_counts = [1]

    results = {}

    for key, scheme in EXTENDED_BASELINES.items():
        results[key] = []
        for n in vehicle_counts:
            cost = compute_scheme_costs(simulator, scheme, n)
            results[key].append(cost)

    if include_vesca:
        results["VESCA"] = []
        for n in vehicle_counts:
            cost = compute_vesca_costs(simulator, n, level)
            results["VESCA"].append(cost)

    return results


def generate_crypto_ops_table(
    simulator: PairingSimulator,
    level: SecurityLevel = DEFAULT_SECURITY_LEVEL,
) -> str:
    """
    Generate Table VII equivalent: symbolic + numerical cost comparison.
    Returns LaTeX-formatted table string.
    """
    lines = []
    lines.append(r"\begin{table*}[t]")
    lines.append(r"\centering")
    lines.append(r"\caption{Comparison of Computational Times for Cryptographic Operations}")
    lines.append(r"\label{tab:crypto_comparison}")
    lines.append(r"\begin{tabular}{lccc}")
    lines.append(r"\hline")
    lines.append(r"\textbf{Scheme} & \textbf{Signcryption (ms)} & "
                 r"\textbf{Unsigncryption (ms)} & \textbf{Total (ms)} \\")
    lines.append(r"\hline")

    all_schemes = list(EXTENDED_BASELINES.items())
    for key, scheme in all_schemes:
        cost = compute_scheme_costs(simulator, scheme, n=1)
        sc_sym = scheme.signcrypt_formula
        usc_sym = scheme.unsigncrypt_formula
        lines.append(
            f"  {scheme.label} & {sc_sym} = {cost.signcrypt_ms:.4f} & "
            f"{usc_sym} = {cost.unsigncrypt_ms:.4f} & {cost.total_ms:.4f} \\\\"
        )

    # VESCA
    vesca = compute_vesca_costs(simulator, n=1, level=level)
    lines.append(
        f"  \\textbf{{VESCA (Ours)}} & {VESCA_SIGNCRYPT_FORMULA} = "
        f"\\textbf{{{vesca.signcrypt_ms:.4f}}} & "
        f"{VESCA_UNSIGNCRYPT_FORMULA} = "
        f"\\textbf{{{vesca.unsigncrypt_ms:.4f}}} & "
        f"\\textbf{{{vesca.total_ms:.4f}}} \\\\"
    )
    lines.append(r"\hline")
    lines.append(r"\end{tabular}")
    lines.append(r"\end{table*}")

    return "\n".join(lines)


def generate_comm_overhead_table(
    level: SecurityLevel = DEFAULT_SECURITY_LEVEL,
) -> str:
    """
    Generate Table VIII equivalent: communication overhead comparison.
    Returns LaTeX-formatted table.
    """
    lines = []
    lines.append(r"\begin{table}[t]")
    lines.append(r"\centering")
    lines.append(r"\caption{Communication Overhead Comparison (Bytes)}")
    lines.append(r"\label{tab:comm_overhead}")
    lines.append(r"\begin{tabular}{lc}")
    lines.append(r"\hline")
    lines.append(r"\textbf{Scheme} & \textbf{Overhead (bytes)} \\")
    lines.append(r"\hline")

    for key, scheme in sorted(EXTENDED_BASELINES.items(),
                               key=lambda x: x[1].comm_overhead_bytes,
                               reverse=True):
        lines.append(f"  {scheme.label} & {scheme.comm_overhead_bytes} \\\\")

    vesca_bytes = (VESCA_COMM_OVERHEAD_BYTES_128 if level == SecurityLevel.LEVEL_128
                   else VESCA_COMM_OVERHEAD_BYTES_80)
    lines.append(
        f"  \\textbf{{VESCA (Ours)}} & \\textbf{{{vesca_bytes}}} \\\\"
    )
    lines.append(r"\hline")
    lines.append(r"\end{tabular}")
    lines.append(r"\end{table}")

    return "\n".join(lines)


def generate_security_features_table() -> str:
    """
    Generate Table III equivalent: security feature comparison.
    Returns LaTeX-formatted table.
    """
    features = [
        "Data Confidentiality & Integrity",
        "Traceability",
        "Authentication",
        "Key Escrow Resistance",
        "Anonymized Identity",
        "Data Immutability",
        "Replay Attack Protection",
        "Modification Attack Protection",
        "Blockchain Authentication",
        "Decentralized Storage",
        "Aggregate Signcryption",
        "NDN Mechanism",
        "128-bit Security",     # NEW feature column
        "Batch Verification",   # NEW feature column
    ]

    # Feature matrix: True/False for each scheme
    # Keys correspond to scheme labels; values are lists matching features
    # Features: [Confid, Trace, Auth, KeyEscrow, AnonID, Immut, Replay,
    #            Modif, BCAuth, DecentStorage, AggSigncrypt, NDN, 128bit, Batch]
    matrix = {
        "Yu2021":      [1,1,1,1,0,0,0,0,0,0,1,0,0,0],
        "Dohare2022":  [1,1,1,1,0,0,1,1,0,0,1,0,0,0],
        "Yang2022a":   [1,0,1,1,0,1,1,1,0,0,1,0,0,0],
        "Yang2022b":   [1,1,1,0,1,0,1,1,0,0,1,0,0,0],
        "Rajkumar2023":[1,1,1,1,0,0,0,1,0,0,1,0,0,0],
        "Dai2022":     [1,1,1,1,1,0,1,1,0,0,1,0,0,0],
        # Cobblah2024: standalone signcryption (NOT aggregate), NDN-based
        "Cobblah2024": [1,1,1,1,1,0,1,1,0,0,0,1,0,0],
        # Wang2025: blockchain-assisted aggregate, VANETs (not NDN)
        "Wang2025":    [1,1,1,1,1,0,1,1,1,1,1,0,1,0],
        # Liu2025: aggregate, vehicular sensor networks (not NDN)
        "Liu2025":     [1,1,1,1,1,0,1,1,0,1,1,0,1,0],
        "VESCA":       [1,1,1,1,1,1,1,1,1,1,1,1,1,1],
    }

    lines = []
    lines.append(r"\begin{table*}[t]")
    lines.append(r"\centering")
    lines.append(r"\caption{Security Feature Comparison}")
    lines.append(r"\label{tab:security_features}")

    scheme_keys = list(matrix.keys())
    ncols = len(scheme_keys)
    col_spec = "l" + "c" * ncols
    lines.append(f"\\begin{{tabular}}{{{col_spec}}}")
    lines.append(r"\hline")

    # Header row
    header = r"\textbf{Feature}"
    for key in scheme_keys:
        if key == "VESCA":
            header += r" & \textbf{Ours}"
        elif key in EXTENDED_BASELINES:
            # Shortened label
            short = EXTENDED_BASELINES[key].label.split("(")[0].strip()
            header += f" & {short}"
        else:
            header += f" & {key}"
    header += r" \\"
    lines.append(header)
    lines.append(r"\hline")

    # Feature rows
    for fi, feat in enumerate(features):
        row = feat
        for key in scheme_keys:
            val = matrix[key][fi]
            sym = r"\checkmark" if val else r"$\times$"
            if key == "VESCA" and val:
                row += f" & \\textbf{{{sym}}}"
            else:
                row += f" & {sym}"
        row += r" \\"
        lines.append(row)

    lines.append(r"\hline")
    lines.append(r"\end{tabular}")
    lines.append(r"\end{table*}")

    return "\n".join(lines)


# ============================================================================
# SECTION 4: Export Utilities
# ============================================================================

def export_comparison_data(
    simulator: PairingSimulator,
    vehicle_counts: List[int],
    level: SecurityLevel = DEFAULT_SECURITY_LEVEL,
    filepath: str = None,
) -> str:
    """Export comparison data as JSON for reproducibility."""
    if filepath is None:
        filepath = os.path.join(DATA_DIR, "comparison_data.json")

    results = generate_comparison_table(simulator, vehicle_counts, level)

    export = {}
    for key, costs in results.items():
        export[key] = [{
            "n": vehicle_counts[i],
            "signcrypt_ms": c.signcrypt_ms,
            "unsigncrypt_ms": c.unsigncrypt_ms,
            "total_ms": c.total_ms,
            "comm_bytes": c.comm_bytes,
        } for i, c in enumerate(costs)]

    with open(filepath, "w") as f:
        json.dump(export, f, indent=2)
    return filepath


if __name__ == "__main__":
    from primitives import benchmark_all_primitives, create_pairing_simulator

    print("=" * 70)
    print("VESCA Baseline Comparison")
    print("=" * 70)

    for level in [SecurityLevel.LEVEL_80, SecurityLevel.LEVEL_128]:
        sec = SECURITY_CURVES[level].bit_security
        print(f"\n{'─'*50}")
        print(f"Security Level: {sec}-bit")
        print(f"{'─'*50}")

        prims = benchmark_all_primitives(level, iterations=200)
        sim = create_pairing_simulator(level, prims)

        print(f"\n  Cryptographic operation costs (Table VII):")
        print(f"  {'Scheme':<25s} {'Signcrypt':>10s} {'Unsigncrypt':>12s} {'Total':>10s}")
        print(f"  {'─'*57}")

        for key, scheme in EXTENDED_BASELINES.items():
            cost = compute_scheme_costs(sim, scheme, n=1)
            print(f"  {scheme.label:<25s} {cost.signcrypt_ms:>10.4f} "
                  f"{cost.unsigncrypt_ms:>12.4f} {cost.total_ms:>10.4f}")

        vesca = compute_vesca_costs(sim, n=1, level=level)
        print(f"  {'VESCA (Ours)':<25s} {vesca.signcrypt_ms:>10.4f} "
              f"{vesca.unsigncrypt_ms:>12.4f} {vesca.total_ms:>10.4f}")

        print(f"\n  Communication overhead (Table VIII):")
        for key, scheme in sorted(EXTENDED_BASELINES.items(),
                                   key=lambda x: x[1].comm_overhead_bytes):
            print(f"  {scheme.label:<25s} {scheme.comm_overhead_bytes:>6d} bytes")
        print(f"  {'VESCA (Ours)':<25s} {vesca.comm_bytes:>6d} bytes")
