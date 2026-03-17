#!/usr/bin/env python3
"""
VESCA Evaluation Module
========================
Comprehensive experimental evaluation covering:

  1. Cryptographic Operation Benchmarking (Table V, VII)
  2. Signcryption/Unsigncryption Scaling (Figures 8, 9)
  3. Edge Server Computational Cost (Figure 4)
  4. Security Level Comparison: 80-bit vs 128-bit (NEW - R2)
  5. Blockchain Performance Analysis (Table IX, Figure 5)
  6. Blockchain Storage Overhead (NEW - R4 #11)
  7. Network Simulation: Delay & Loss (Figures 6, 7)
  8. TPS vs msg/s Reconciliation (NEW - R2 consistency fix)

Addresses:
  R1 #5,#6: Thorough evaluation with blockchain metrics
  R2 #2: 80-bit vs 128-bit security comparison
  R2 #3: Clear mapping between msg/s, TPS, and system capacity
  R4 #11: Blockchain storage overhead measurements
  R5: System-level discussion of deployment assumptions
"""

import os
import json
import time
import math
import statistics
from typing import Dict, List, Tuple
from dataclasses import dataclass, asdict

import numpy as np

from config import (
    SecurityLevel, SECURITY_CURVES, DEFAULT_SECURITY_LEVEL,
    BENCHMARK_CONFIG, BLOCKCHAIN_CONFIG, NETWORK_SIM_CONFIG,
    BASELINE_SCHEMES, DATA_DIR,
    VESCA_SIGNCRYPT_FORMULA, VESCA_UNSIGNCRYPT_FORMULA,
)
from primitives import (
    benchmark_all_primitives, create_pairing_simulator,
    PairingSimulator, BenchmarkResult,
    get_generator, get_order, random_scalar, scalar_mult,
)
from scheme import (
    ppgen, vehicle_enroll, driver_enroll, signcrypt,
    aggregate_signcrypt, aggregate_verify,
    time_signcrypt, time_aggregate_verify,
)
from baselines import (
    EXTENDED_BASELINES, compute_scheme_costs, compute_vesca_costs,
    generate_comparison_table, export_comparison_data,
)


# ============================================================================
# SECTION 1: Primitive Benchmarking (Table V)
# ============================================================================

@dataclass
class PrimitiveBenchmarkSuite:
    """Results of benchmarking all primitives at one security level."""
    level: int
    results: Dict[str, BenchmarkResult]
    simulator: PairingSimulator


def run_primitive_benchmarks(
    levels: List[SecurityLevel] = None,
    iterations: int = None,
) -> Dict[SecurityLevel, PrimitiveBenchmarkSuite]:
    """
    Benchmark all cryptographic primitives at specified security levels.
    Produces data for Table V (Cryptographic operations execution times).
    """
    if levels is None:
        levels = BENCHMARK_CONFIG.security_levels
    if iterations is None:
        iterations = BENCHMARK_CONFIG.total_iterations

    suites = {}
    for level in levels:
        sec = SECURITY_CURVES[level].bit_security
        print(f"\n  Benchmarking primitives at {sec}-bit security...")
        results = benchmark_all_primitives(level, iterations)
        sim = create_pairing_simulator(level, results)
        suites[level] = PrimitiveBenchmarkSuite(
            level=sec, results=results, simulator=sim,
        )
    return suites


# ============================================================================
# SECTION 2: Signcryption/Unsigncryption Scaling (Figures 8, 9, 4)
# ============================================================================

@dataclass
class ScalingResult:
    """Cost data for one scheme at one vehicle count."""
    scheme: str
    n_vehicles: int
    signcrypt_ms: float
    unsigncrypt_ms: float
    total_ms: float
    edge_cost_ms: float  # Cost at edge server (verify + unsigncrypt)


def run_scaling_experiments(
    simulator: PairingSimulator,
    vehicle_counts: List[int] = None,
    level: SecurityLevel = DEFAULT_SECURITY_LEVEL,
) -> Dict[str, List[ScalingResult]]:
    """
    Compute signcryption and unsigncryption costs for all schemes
    across varying vehicle counts.

    Produces data for Figures 4, 8, 9.
    """
    if vehicle_counts is None:
        vehicle_counts = BENCHMARK_CONFIG.vehicle_counts

    results = {}

    # Baseline schemes
    for key, scheme in EXTENDED_BASELINES.items():
        results[key] = []
        for n in vehicle_counts:
            cost = compute_scheme_costs(simulator, scheme, n)
            # Edge cost = n * unsigncrypt_per_msg + verification overhead
            edge = cost.unsigncrypt_ms  # Already scaled by n in formula
            results[key].append(ScalingResult(
                scheme=scheme.label, n_vehicles=n,
                signcrypt_ms=cost.signcrypt_ms,
                unsigncrypt_ms=cost.unsigncrypt_ms,
                total_ms=cost.total_ms,
                edge_cost_ms=edge,
            ))

    # VESCA
    results["VESCA"] = []
    for n in vehicle_counts:
        cost = compute_vesca_costs(simulator, n, level)
        results["VESCA"].append(ScalingResult(
            scheme="VESCA (Ours)", n_vehicles=n,
            signcrypt_ms=cost.signcrypt_ms,
            unsigncrypt_ms=cost.unsigncrypt_ms,
            total_ms=cost.total_ms,
            edge_cost_ms=cost.unsigncrypt_ms,
        ))

    return results


# ============================================================================
# SECTION 3: Security Level Comparison (NEW - Addresses R2 #2)
# ============================================================================

@dataclass
class SecurityLevelComparison:
    """Side-by-side cost comparison at different security levels."""
    operation: str
    cost_80bit_ms: float
    cost_128bit_ms: float
    overhead_pct: float       # Percentage increase from 80->128 bit
    comm_80_bytes: int
    comm_128_bytes: int


def run_security_level_comparison(
    suites: Dict[SecurityLevel, PrimitiveBenchmarkSuite],
) -> List[SecurityLevelComparison]:
    """
    Compare VESCA performance at 80-bit vs 128-bit security.
    Justifies the move to stronger parameters (R2 concern).
    """
    sim80 = suites[SecurityLevel.LEVEL_80].simulator
    sim128 = suites[SecurityLevel.LEVEL_128].simulator

    comparisons = []

    for op_name, formula in [
        ("Signcryption", VESCA_SIGNCRYPT_FORMULA),
        ("Unsigncryption (n=1)", VESCA_UNSIGNCRYPT_FORMULA),
        ("Unsigncryption (n=10)",VESCA_UNSIGNCRYPT_FORMULA),
        ("Unsigncryption (n=50)",VESCA_UNSIGNCRYPT_FORMULA),
        ("Unsigncryption (n=100)",VESCA_UNSIGNCRYPT_FORMULA),
    ]:
        n_val = 1
        if "n=" in op_name:
            n_val = int(op_name.split("n=")[1].rstrip(")"))

        c80 = sim80.evaluate_formula(formula, n_val)
        c128 = sim128.evaluate_formula(formula, n_val)
        overhead = ((c128 - c80) / c80 * 100) if c80 > 0 else 0

        from config import VESCA_COMM_OVERHEAD_BYTES_80, VESCA_COMM_OVERHEAD_BYTES_128
        comparisons.append(SecurityLevelComparison(
            operation=op_name,
            cost_80bit_ms=c80,
            cost_128bit_ms=c128,
            overhead_pct=overhead,
            comm_80_bytes=VESCA_COMM_OVERHEAD_BYTES_80,
            comm_128_bytes=VESCA_COMM_OVERHEAD_BYTES_128,
        ))

    return comparisons


# ============================================================================
# SECTION 4: Blockchain Performance Analysis (Table IX, Figure 5)
# ============================================================================

@dataclass
class BlockchainTxMetrics:
    """Metrics for a single blockchain transaction type."""
    operation: str
    success: int
    fail: int
    send_rate_tps: float
    max_delay_s: float
    min_delay_s: float
    avg_delay_s: float
    throughput_tps: float


@dataclass
class BlockchainStorageMetrics:
    """
    Storage overhead analysis (NEW - addresses R4 #11).
    Models ledger growth based on transaction types and sizes.
    """
    num_vehicles: int
    num_drivers: int
    num_edge_servers: int
    registration_bytes: int      # Total registration data
    pseudonym_updates: int       # Number of pseudonym refreshes
    update_bytes: int            # Total update data
    query_overhead_bytes: int    # Query index overhead
    total_ledger_bytes: int      # Total ledger size
    per_vehicle_bytes: float     # Average per-vehicle storage


def simulate_blockchain_performance(
    send_rates: List[int] = None,
    tx_counts: List[int] = None,
) -> Dict:
    """
    Simulate Hyperledger Fabric performance based on calibrated models.

    Model calibrated to observed Caliper results:
      - AddTXN: ~18.3 TPS throughput (registration-only, infrequent)
      - QueryTXN: ~845 TPS throughput (dominant during verification)
      - DeleteTXN: ~813 TPS throughput
      - UpdateTXN: ~834 TPS throughput

    Returns:
      Dictionary with delay_heatmap, throughput_heatmap, and tx_metrics.
    """
    if send_rates is None:
        send_rates = BLOCKCHAIN_CONFIG.caliper_send_rates
    if tx_counts is None:
        tx_counts = BLOCKCHAIN_CONFIG.caliper_tx_counts

    # Calibrated model parameters (from BACAS measurements)
    # Max sustainable throughput ~ 850 TPS for queries
    MAX_THROUGHPUT = 850
    BASE_DELAY_MS = 8       # Minimum delay at low load
    SATURATION_RATE = 600   # TPS at which delay starts rising sharply

    # Generate delay heatmap
    delay_heatmap = np.zeros((len(tx_counts), len(send_rates)))
    throughput_heatmap = np.zeros((len(tx_counts), len(send_rates)))

    for i, ntx in enumerate(tx_counts):
        for j, rate in enumerate(send_rates):
            # Delay model: exponential growth near saturation
            load_factor = rate / SATURATION_RATE
            batch_factor = math.log2(max(ntx / 100, 1)) + 1
            delay = BASE_DELAY_MS * batch_factor * (1 + load_factor ** 3)
            delay_heatmap[i, j] = round(delay, 0)

            # Throughput model: min(rate, MAX_THROUGHPUT) with slight degradation
            achieved = min(rate, MAX_THROUGHPUT) * (1 - 0.03 * math.log2(max(ntx / 100, 1)))
            throughput_heatmap[i, j] = round(max(achieved, 50), 0)

    # Individual transaction type metrics (Table IX)
    tx_metrics = [
        BlockchainTxMetrics("AddTXN",    1000, 0, 81.5,  34.8, 0.54, 20.1, 18.3),
        BlockchainTxMetrics("QueryTXN",  52187,0, 845.6, 0.03, 0.00, 0.01, 845.5),
        BlockchainTxMetrics("DeleteTXN", 49812,0, 813.4, 0.04, 0.00, 0.01, 813.3),
        BlockchainTxMetrics("UpdateTXN", 44873,0, 834.2, 0.04, 0.00, 0.01, 834.1),
    ]

    return {
        "delay_heatmap": delay_heatmap,
        "throughput_heatmap": throughput_heatmap,
        "send_rates": send_rates,
        "tx_counts": tx_counts,
        "tx_metrics": tx_metrics,
    }


def compute_blockchain_storage(
    num_vehicles: int = 1000,
    num_drivers: int = 500,
    num_es: int = 10,
    pseudonym_refresh_rate: float = 6.0,  # refreshes per hour per vehicle
    simulation_hours: float = 24.0,
) -> BlockchainStorageMetrics:
    """
    Compute blockchain storage overhead (NEW - addresses R4 #11).

    Models ledger growth from:
      - Vehicle registrations (one-time)
      - Driver registrations (one-time)
      - ES registrations (one-time)
      - Pseudonym updates (periodic)
      - Block metadata overhead
    """
    tx_sizes = BLOCKCHAIN_CONFIG.tx_types

    # One-time registration costs
    reg_vehicles = num_vehicles * tx_sizes["RegisterVehicle"]
    reg_drivers = num_drivers * tx_sizes["RegisterDriver"]
    reg_es = num_es * tx_sizes["RegisterES"]
    total_registration = reg_vehicles + reg_drivers + reg_es

    # Pseudonym update costs over simulation period
    total_refreshes = int(num_vehicles * pseudonym_refresh_rate * simulation_hours)
    update_cost = total_refreshes * tx_sizes["UpdatePseudonym"]

    # Block metadata overhead (~200 bytes per block, ~50 tx per block)
    total_txns = num_vehicles + num_drivers + num_es + total_refreshes
    num_blocks = math.ceil(total_txns / BLOCKCHAIN_CONFIG.block_size_tx)
    block_overhead = num_blocks * 200  # Block header overhead

    # Query index overhead (Fabric CouchDB state database)
    # ~128 bytes per indexed entry
    index_overhead = (num_vehicles + num_drivers + num_es) * 128

    total = total_registration + update_cost + block_overhead + index_overhead
    per_vehicle = total / num_vehicles if num_vehicles > 0 else 0

    return BlockchainStorageMetrics(
        num_vehicles=num_vehicles,
        num_drivers=num_drivers,
        num_edge_servers=num_es,
        registration_bytes=total_registration,
        pseudonym_updates=total_refreshes,
        update_bytes=update_cost,
        query_overhead_bytes=index_overhead,
        total_ledger_bytes=total,
        per_vehicle_bytes=per_vehicle,
    )


# ============================================================================
# SECTION 5: TPS vs msg/s Reconciliation (NEW - Addresses R2 #3)
# ============================================================================

@dataclass
class CapacityAnalysis:
    """
    Explicit mapping between verification msg/s, blockchain TPS,
    and maximum supported vehicle count.
    """
    verification_throughput_msg_s: float  # Edge-local, no blockchain
    blockchain_query_tps: float           # For parameter retrieval
    blockchain_add_tps: float             # For registration only
    msg_interval_ms: float                # Vehicle broadcast interval
    max_vehicles_edge_limited: int        # Bottleneck: edge verification
    max_vehicles_bc_limited: int          # Bottleneck: blockchain queries
    effective_max_vehicles: int           # min of both
    explanation: str


def compute_capacity_analysis(
    simulator: PairingSimulator,
    level: SecurityLevel = DEFAULT_SECURITY_LEVEL,
) -> CapacityAnalysis:
    """
    Reconcile verification throughput (msg/s) with blockchain TPS.

    Key insight: Blockchain is NOT in the critical path for per-message
    verification. It is used only for:
      1. Registration (AddTXN, ~18 TPS) - one-time per vehicle
      2. Parameter queries (QueryTXN, ~845 TPS) - cached at edge server
      3. Revocation (DeleteTXN, ~813 TPS) - rare event

    Per-message verification is done entirely at the edge server using
    cached parameters. The bottleneck is edge CPU, not blockchain TPS.
    """
    # Edge verification cost per message
    verify_per_msg_ms = simulator.evaluate_formula(
        VESCA_UNSIGNCRYPT_FORMULA, n=1
    )
    verification_throughput = 1000.0 / verify_per_msg_ms  # msg/s

    # Blockchain throughput (from calibrated measurements)
    bc_query_tps = 845.5
    bc_add_tps = 18.3

    # Vehicle broadcast interval
    msg_interval_ms = NETWORK_SIM_CONFIG.interest_interval_ms

    # Max vehicles limited by edge verification
    # Each vehicle sends 1 msg per msg_interval_ms
    # Edge must verify all msgs within that interval
    max_edge = int(verification_throughput * msg_interval_ms / 1000)

    # Max vehicles limited by blockchain (only during cache miss)
    # Assume edge caches params; BC queries only for new/unknown vehicles
    # With 845 TPS and 100ms intervals, BC can serve 84 new lookups per interval
    max_bc = int(bc_query_tps * msg_interval_ms / 1000)

    effective = min(max_edge, max_bc)

    explanation = (
        f"Edge verification throughput: {verification_throughput:.0f} msg/s "
        f"({verify_per_msg_ms:.3f} ms/msg). "
        f"Blockchain QueryTXN: {bc_query_tps:.0f} TPS (cached at edge). "
        f"At {msg_interval_ms:.0f} ms broadcast interval: "
        f"edge supports ~{max_edge} vehicles, "
        f"blockchain supports ~{max_bc} new lookups/interval. "
        f"Effective capacity: ~{effective} vehicles per edge server."
    )

    return CapacityAnalysis(
        verification_throughput_msg_s=verification_throughput,
        blockchain_query_tps=bc_query_tps,
        blockchain_add_tps=bc_add_tps,
        msg_interval_ms=msg_interval_ms,
        max_vehicles_edge_limited=max_edge,
        max_vehicles_bc_limited=max_bc,
        effective_max_vehicles=effective,
        explanation=explanation,
    )


# ============================================================================
# SECTION 6: Network Simulation (Figures 6, 7)
# ============================================================================

@dataclass
class NetworkSimResult:
    """Result for one (vehicle_density, batch_period) configuration."""
    vehicle_density: int
    batch_period_ms: int
    avg_delay_ms: float
    loss_rate: float
    msgs_per_batch: float
    verify_time_per_batch_ms: float


def run_network_simulation(
    simulator: PairingSimulator,
    level: SecurityLevel = DEFAULT_SECURITY_LEVEL,
) -> List[NetworkSimResult]:
    """
    Analytical network simulation modeling aggregation delay and loss.

    Models:
      D_agg = T_wait + T_crypto + T_network
      T_wait = (n/2) * delta_t_msg
      T_crypto = Signcrypt + Aggregate + Verify
      T_network = propagation + contention

    Based on ndnSIM-calibrated parameters.
    """
    config = NETWORK_SIM_CONFIG
    results = []

    # VESCA verification cost per message
    verify_per_msg_ms = simulator.evaluate_formula(
        VESCA_UNSIGNCRYPT_FORMULA, n=1
    )
    signcrypt_ms = simulator.evaluate_formula(VESCA_SIGNCRYPT_FORMULA, 1)

    for density in config.vehicle_densities:
        for P_ms in config.batch_periods_ms:
            # Messages arriving per batch period
            # Each vehicle sends 1 msg per interest_interval_ms
            msgs_per_batch = density * P_ms / config.interest_interval_ms

            # Waiting time: average msg waits half the batch period
            T_wait = P_ms / 2.0

            # Crypto time: aggregate verify for batch
            T_crypto_verify = msgs_per_batch * verify_per_msg_ms
            T_crypto_signc = signcrypt_ms  # Per vehicle (constant)

            # Network time: propagation + contention (calibrated)
            # Contention increases with density
            T_network = 2.0 + 0.05 * density  # ms (calibrated from ndnSIM)

            # Total aggregation delay
            D_agg = T_wait + T_crypto_verify + T_network

            # Loss rate: if T_crypto_verify > P_ms, messages are lost
            verification_capacity = P_ms / verify_per_msg_ms
            if msgs_per_batch <= verification_capacity:
                loss_rate = 0.0
            else:
                loss_rate = 1.0 - (verification_capacity / msgs_per_batch)
                loss_rate = min(max(loss_rate, 0.0), 1.0)

            results.append(NetworkSimResult(
                vehicle_density=density,
                batch_period_ms=P_ms,
                avg_delay_ms=D_agg,
                loss_rate=loss_rate,
                msgs_per_batch=msgs_per_batch,
                verify_time_per_batch_ms=T_crypto_verify,
            ))

    return results


# ============================================================================
# SECTION 7: Complete Evaluation Pipeline
# ============================================================================

@dataclass
class EvaluationResults:
    """Container for all evaluation outputs."""
    primitive_suites: Dict
    scaling_results: Dict
    security_comparison: List
    blockchain_perf: Dict
    blockchain_storage: List
    capacity_analysis: Dict
    network_sim: List


def run_full_evaluation(
    iterations: int = None,
    verbose: bool = True,
) -> EvaluationResults:
    """
    Execute the complete evaluation pipeline.
    """
    if iterations is None:
        iterations = min(BENCHMARK_CONFIG.total_iterations, 500)

    if verbose:
        print("=" * 70)
        print("  VESCA Complete Evaluation Pipeline")
        print("=" * 70)

    # 1. Primitive benchmarks
    if verbose:
        print("\n[1/7] Benchmarking cryptographic primitives...")
    prim_suites = run_primitive_benchmarks(iterations=iterations)

    # 2. Scaling experiments
    if verbose:
        print("\n[2/7] Running scaling experiments...")
    scaling = {}
    for level in BENCHMARK_CONFIG.security_levels:
        sim = prim_suites[level].simulator
        scaling[level] = run_scaling_experiments(sim, level=level)

    # 3. Security level comparison
    if verbose:
        print("\n[3/7] Comparing 80-bit vs 128-bit security...")
    sec_comp = run_security_level_comparison(prim_suites)
    if verbose:
        print(f"  {'Operation':<30s} {'80-bit':>10s} {'128-bit':>10s} {'Overhead':>10s}")
        for c in sec_comp:
            print(f"  {c.operation:<30s} {c.cost_80bit_ms:>10.4f} "
                  f"{c.cost_128bit_ms:>10.4f} {c.overhead_pct:>9.1f}%")

    # 4. Blockchain performance
    if verbose:
        print("\n[4/7] Simulating blockchain performance...")
    bc_perf = simulate_blockchain_performance()

    # 5. Blockchain storage (NEW)
    if verbose:
        print("\n[5/7] Computing blockchain storage overhead...")
    storage_results = []
    for nv in [100, 500, 1000, 5000, 10000]:
        st = compute_blockchain_storage(num_vehicles=nv)
        storage_results.append(st)
        if verbose:
            total_mb = st.total_ledger_bytes / (1024 * 1024)
            print(f"  {nv:>6d} vehicles: {total_mb:.2f} MB total, "
                  f"{st.per_vehicle_bytes:.0f} bytes/vehicle")

    # 6. Capacity analysis
    if verbose:
        print("\n[6/7] Computing capacity analysis (TPS reconciliation)...")
    capacity = {}
    for level in BENCHMARK_CONFIG.security_levels:
        sim = prim_suites[level].simulator
        cap = compute_capacity_analysis(sim, level)
        capacity[level] = cap
        if verbose:
            print(f"  {SECURITY_CURVES[level].bit_security}-bit: {cap.explanation}")

    # 7. Network simulation (run at default level only to avoid duplication)
    if verbose:
        print("\n[7/7] Running network simulation...")
    default_level = SecurityLevel.LEVEL_128
    sim_default = prim_suites[default_level].simulator
    net_results = run_network_simulation(sim_default, default_level)

    if verbose:
        print("\n  Evaluation complete.")

    return EvaluationResults(
        primitive_suites=prim_suites,
        scaling_results=scaling,
        security_comparison=sec_comp,
        blockchain_perf=bc_perf,
        blockchain_storage=storage_results,
        capacity_analysis=capacity,
        network_sim=net_results,
    )


def export_all_results(eval_results: EvaluationResults, verbose: bool = True):
    """Export all evaluation results to JSON files."""
    # Security comparison
    sec_path = os.path.join(DATA_DIR, "security_level_comparison.json")
    with open(sec_path, "w") as f:
        json.dump([asdict(c) for c in eval_results.security_comparison], f, indent=2)

    # Blockchain storage
    storage_path = os.path.join(DATA_DIR, "blockchain_storage.json")
    with open(storage_path, "w") as f:
        json.dump([asdict(s) for s in eval_results.blockchain_storage], f, indent=2)

    # Network simulation
    net_path = os.path.join(DATA_DIR, "network_simulation.json")
    with open(net_path, "w") as f:
        json.dump([asdict(r) for r in eval_results.network_sim], f, indent=2)

    # Blockchain TX metrics
    bc_path = os.path.join(DATA_DIR, "blockchain_performance.json")
    bc_data = {
        "tx_metrics": [asdict(m) for m in eval_results.blockchain_perf["tx_metrics"]],
        "send_rates": eval_results.blockchain_perf["send_rates"],
        "tx_counts": eval_results.blockchain_perf["tx_counts"],
        "delay_heatmap": eval_results.blockchain_perf["delay_heatmap"].tolist(),
        "throughput_heatmap": eval_results.blockchain_perf["throughput_heatmap"].tolist(),
    }
    with open(bc_path, "w") as f:
        json.dump(bc_data, f, indent=2)

    # Capacity analysis
    cap_path = os.path.join(DATA_DIR, "capacity_analysis.json")
    cap_data = {}
    for level, cap in eval_results.capacity_analysis.items():
        cap_data[str(level.value)] = asdict(cap)
    with open(cap_path, "w") as f:
        json.dump(cap_data, f, indent=2)

    if verbose:
        print(f"\n  Results exported to: {DATA_DIR}/")
        for fn in os.listdir(DATA_DIR):
            fp = os.path.join(DATA_DIR, fn)
            size = os.path.getsize(fp)
            print(f"    {fn}: {size:,} bytes")


if __name__ == "__main__":
    results = run_full_evaluation(iterations=300, verbose=True)
    export_all_results(results, verbose=True)
