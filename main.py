#!/usr/bin/env python3
"""
VESCA Main Entry Point
========================
Vehicular Edge-assisted Secure Certificateless Aggregate Signcryption

Orchestrates the complete experimental pipeline:
  1. Correctness verification at both security levels
  2. Cryptographic primitive benchmarking
  3. Scheme comparison (baselines + VESCA)
  4. Blockchain performance & storage analysis
  5. Network simulation
  6. Figure and table generation
  7. LaTeX table export

Usage:
  python main.py                    # Full pipeline (default iterations)
  python main.py --iterations 1000  # Full pipeline with 1000 iterations
  python main.py --quick            # Quick mode (200 iterations)
  python main.py --correctness-only # Only run correctness tests
  python main.py --figures-only     # Only generate figures from cached data

Environment:
  - Python 3.8+
  - Dependencies: ecdsa, pycryptodome, matplotlib, numpy, scipy, tabulate
  - Hardware: see Table X in paper for benchmark environment specs

Output:
  results/
    data/       - Raw JSON data for all experiments
    figures/    - PNG and PDF figures for the paper
    tables/     - LaTeX table source files
"""

import os
import sys
import time
import argparse
import json
from datetime import datetime

from config import (
    SecurityLevel, SECURITY_CURVES, BENCHMARK_CONFIG,
    OUTPUT_DIR, FIGURES_DIR, TABLES_DIR, DATA_DIR,
    export_config,
)


def parse_args():
    """Parse command-line arguments."""
    parser = argparse.ArgumentParser(
        description="VESCA: Complete Experimental Pipeline",
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    parser.add_argument(
        "--iterations", type=int, default=None,
        help="Number of benchmark iterations (default: from config)",
    )
    parser.add_argument(
        "--quick", action="store_true",
        help="Quick mode with reduced iterations (200)",
    )
    parser.add_argument(
        "--correctness-only", action="store_true",
        help="Only run correctness verification tests",
    )
    parser.add_argument(
        "--figures-only", action="store_true",
        help="Only generate figures from cached data",
    )
    parser.add_argument(
        "--no-figures", action="store_true",
        help="Skip figure generation",
    )
    parser.add_argument(
        "--security-level", type=int, choices=[80, 128], default=None,
        help="Run only at specified security level",
    )
    return parser.parse_args()


def print_header():
    """Print program header."""
    print("\n" + "=" * 70)
    print("  VESCA — Vehicular Edge-assisted Secure Certificateless")
    print("          Aggregate Signcryption Scheme")
    print("=" * 70)
    print(f"  Date: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    print(f"  Output: {OUTPUT_DIR}")
    print("=" * 70)


def run_correctness_tests():
    """Phase 1: Verify scheme correctness at all security levels."""
    from scheme import run_correctness_test

    print("\n" + "─" * 50)
    print("  PHASE 1: Correctness Verification")
    print("─" * 50)

    all_pass = True
    for level in [SecurityLevel.LEVEL_80, SecurityLevel.LEVEL_128]:
        for n in [1, 3, 10]:
            success = run_correctness_test(level, num_vehicles=n, verbose=True)
            all_pass = all_pass and success

    if all_pass:
        print("\n  All correctness tests PASSED.")
    else:
        print("\n  WARNING: Some correctness tests FAILED!")
        sys.exit(1)

    return all_pass


def run_evaluation(iterations: int = None):
    """Phase 2: Run complete evaluation pipeline."""
    from evaluation import run_full_evaluation, export_all_results

    print("\n" + "─" * 50)
    print("  PHASE 2: Experimental Evaluation")
    print("─" * 50)

    start = time.time()
    results = run_full_evaluation(iterations=iterations, verbose=True)
    export_all_results(results, verbose=True)
    elapsed = time.time() - start

    print(f"\n  Evaluation completed in {elapsed:.1f} seconds.")
    return results


def generate_figures(eval_results):
    """Phase 3: Generate all paper figures."""
    from plots import generate_all_figures

    print("\n" + "─" * 50)
    print("  PHASE 3: Figure Generation")
    print("─" * 50)

    figs = generate_all_figures(eval_results, verbose=True)
    return figs


def generate_latex_tables(eval_results):
    """Phase 4: Generate LaTeX tables for the paper."""
    from baselines import (
        generate_crypto_ops_table,
        generate_comm_overhead_table,
        generate_security_features_table,
    )

    print("\n" + "─" * 50)
    print("  PHASE 4: LaTeX Table Generation")
    print("─" * 50)

    sim = eval_results.primitive_suites[SecurityLevel.LEVEL_128].simulator

    # Table VII: Crypto operations comparison
    table7 = generate_crypto_ops_table(sim, SecurityLevel.LEVEL_128)
    path7 = os.path.join(TABLES_DIR, "table_vii_crypto_comparison.tex")
    with open(path7, "w") as f:
        f.write(table7)
    print(f"  Table VII: {path7}")

    # Table VIII: Communication overhead
    table8 = generate_comm_overhead_table(SecurityLevel.LEVEL_128)
    path8 = os.path.join(TABLES_DIR, "table_viii_comm_overhead.tex")
    with open(path8, "w") as f:
        f.write(table8)
    print(f"  Table VIII: {path8}")

    # Table III: Security features
    table3 = generate_security_features_table()
    path3 = os.path.join(TABLES_DIR, "table_iii_security_features.tex")
    with open(path3, "w") as f:
        f.write(table3)
    print(f"  Table III: {path3}")

    # Table V: Primitive execution times
    table5_lines = []
    table5_lines.append(r"\begin{table}[t]")
    table5_lines.append(r"\centering")
    table5_lines.append(r"\caption{Cryptographic Operation Execution Times (ms)}")
    table5_lines.append(r"\label{tab:crypto_times}")
    table5_lines.append(r"\begin{tabular}{lcc}")
    table5_lines.append(r"\hline")
    table5_lines.append(r"\textbf{Operation} & \textbf{80-bit} & \textbf{128-bit} \\")
    table5_lines.append(r"\hline")

    ops_80 = eval_results.primitive_suites[SecurityLevel.LEVEL_80].results
    ops_128 = eval_results.primitive_suites[SecurityLevel.LEVEL_128].results

    for op in ["ETsm", "ETpa", "ETh"]:
        if op in ops_80 and op in ops_128:
            table5_lines.append(
                f"  {op} & {ops_80[op].mean_ms:.4f} & {ops_128[op].mean_ms:.4f} \\\\"
            )

    # Add estimated pairing costs
    sim80 = eval_results.primitive_suites[SecurityLevel.LEVEL_80].simulator
    sim128 = eval_results.primitive_suites[SecurityLevel.LEVEL_128].simulator
    for op in ["ETbp", "ETbpsm", "ETmp", "ETe"]:
        table5_lines.append(
            f"  {op} (est.) & {sim80.get_time(op):.4f} & {sim128.get_time(op):.4f} \\\\"
        )

    table5_lines.append(r"\hline")
    table5_lines.append(r"\end{tabular}")
    table5_lines.append(r"\end{table}")

    path5 = os.path.join(TABLES_DIR, "table_v_primitive_times.tex")
    with open(path5, "w") as f:
        f.write("\n".join(table5_lines))
    print(f"  Table V: {path5}")

    # NEW: Blockchain storage table
    storage_lines = []
    storage_lines.append(r"\begin{table}[t]")
    storage_lines.append(r"\centering")
    storage_lines.append(r"\caption{Blockchain Storage Overhead Analysis}")
    storage_lines.append(r"\label{tab:blockchain_storage}")
    storage_lines.append(r"\begin{tabular}{rrrr}")
    storage_lines.append(r"\hline")
    storage_lines.append(r"\textbf{Vehicles} & \textbf{Total (MB)} & "
                        r"\textbf{Per-Vehicle (B)} & \textbf{Updates/24h} \\")
    storage_lines.append(r"\hline")

    for s in eval_results.blockchain_storage:
        total_mb = s.total_ledger_bytes / (1024 * 1024)
        storage_lines.append(
            f"  {s.num_vehicles:,} & {total_mb:.2f} & "
            f"{s.per_vehicle_bytes:.0f} & {s.pseudonym_updates:,} \\\\"
        )

    storage_lines.append(r"\hline")
    storage_lines.append(r"\end{tabular}")
    storage_lines.append(r"\end{table}")

    path_st = os.path.join(TABLES_DIR, "table_blockchain_storage.tex")
    with open(path_st, "w") as f:
        f.write("\n".join(storage_lines))
    print(f"  Storage: {path_st}")

    print(f"\n  All tables saved to: {TABLES_DIR}/")


def print_summary(eval_results):
    """Print executive summary of results."""
    print("\n" + "=" * 70)
    print("  RESULTS SUMMARY")
    print("=" * 70)

    # Primitive costs
    for level in [SecurityLevel.LEVEL_80, SecurityLevel.LEVEL_128]:
        sec = SECURITY_CURVES[level].bit_security
        suite = eval_results.primitive_suites[level]
        sim = suite.simulator
        sc = sim.evaluate_formula("2*ETsm + 3*ETh + ETpa", 1)
        usc = sim.evaluate_formula("2*ETsm + ETh", 1)
        print(f"\n  VESCA at {sec}-bit security:")
        print(f"    ETsm: {suite.results['ETsm'].mean_ms:.4f} ms")
        print(f"    Signcryption:   {sc:.4f} ms")
        print(f"    Unsigncryption: {usc:.4f} ms (per message)")
        print(f"    Total:          {sc + usc:.4f} ms")

    # Security level overhead
    print(f"\n  128-bit vs 80-bit overhead:")
    for c in eval_results.security_comparison:
        print(f"    {c.operation}: +{c.overhead_pct:.1f}%")

    # Capacity
    for level, cap in eval_results.capacity_analysis.items():
        sec = SECURITY_CURVES[level].bit_security
        print(f"\n  Capacity at {sec}-bit:")
        print(f"    Verification: {cap.verification_throughput_msg_s:.0f} msg/s")
        print(f"    Max vehicles (edge): ~{cap.max_vehicles_edge_limited}")

    print(f"\n  Output files: {OUTPUT_DIR}/")
    for subdir in ["data", "figures", "tables"]:
        path = os.path.join(OUTPUT_DIR, subdir)
        count = len(os.listdir(path)) if os.path.exists(path) else 0
        print(f"    {subdir}/: {count} files")

    print("\n" + "=" * 70)


def main():
    """Main entry point."""
    args = parse_args()
    print_header()

    # Export configuration for reproducibility
    config_path = export_config()
    print(f"\n  Config exported: {config_path}")

    # Determine iterations
    iterations = args.iterations
    if args.quick:
        iterations = 200
    elif iterations is None:
        iterations = min(BENCHMARK_CONFIG.total_iterations, 500)

    print(f"  Benchmark iterations: {iterations}")

    # Phase 1: Correctness
    if not args.figures_only:
        run_correctness_tests()

    # Phase 2: Evaluation
    if not args.correctness_only and not args.figures_only:
        eval_results = run_evaluation(iterations)

        # Phase 3: Figures
        if not args.no_figures:
            generate_figures(eval_results)

        # Phase 4: Tables
        generate_latex_tables(eval_results)

        # Summary
        print_summary(eval_results)

    elif args.correctness_only:
        print("\n  Correctness-only mode. Skipping evaluation.")

    print("\n  Pipeline complete.\n")


if __name__ == "__main__":
    main()
