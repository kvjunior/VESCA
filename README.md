# VESCA: Vehicular Edge-Assisted Secure Certificateless Aggregate Signcryption

**Reproducible experimental framework for IEEE TDSC submission**

> VESCA is a pairing-free certificateless aggregate signcryption scheme built on NIST P-256 (128-bit security) that integrates Hyperledger Fabric-based decentralized key management with edge-assisted batch verification for Vehicular Named Data Networks (VNDN).

---

## Table of Contents

- [Overview](#overview)
- [Repository Structure](#repository-structure)
- [Requirements](#requirements)
- [Installation](#installation)
- [Quick Start](#quick-start)
- [Module Reference](#module-reference)
- [Usage Examples](#usage-examples)
- [Reproducing Paper Results](#reproducing-paper-results)
- [Output Structure](#output-structure)
- [Mapping to Paper Sections](#mapping-to-paper-sections)
- [License](#license)

---

## Overview

VESCA addresses three security gaps in current VNDN designs:

1. **Pairing overhead** — Existing certificateless signcryption schemes depend on bilinear pairings whose cost exceeds OBU computational budgets. VESCA eliminates all pairing operations.
2. **Centralized trust** — Single-point-of-failure trust models are replaced by a Hyperledger Fabric consortium blockchain with channel-based credential partitioning.
3. **Identity coupling** — Driver and vehicle identities are cryptographically decoupled through separated pseudonym generation and on-chain credential partitioning.

### Key Results (128-bit Security, NIST P-256)

| Metric | Value |
|--------|-------|
| Total cryptographic cost | 3.709 ms |
| Per-message communication overhead | 136 bytes |
| Improvement over nearest aggregate competitor | 19.6% |
| Aggregation delay at 200-vehicle density | < 100 ms |
| Edge server capacity (4-thread) | 216 vehicles |
| Blockchain storage per vehicle (24h) | ~56 KB |

---

## Repository Structure

```
vesca/
├── config.py          # System parameters, security levels, baseline definitions
├── primitives.py      # ECC operations, hash functions, benchmarking framework
├── scheme.py          # Complete VESCA scheme (10 algorithms)
├── baselines.py       # Cost estimation for 9 baseline schemes
├── evaluation.py      # Full experimental evaluation pipeline
├── plots.py           # IEEE-formatted figure generation
├── main.py            # Orchestrator and CLI entry point
└── results/           # Generated output (created at runtime)
    ├── data/          # Raw JSON data for all experiments
    ├── figures/       # PNG and PDF figures for the paper
    └── tables/        # LaTeX table source files
```

---

## Requirements

### Software

- **Python** ≥ 3.8
- **Dependencies:**

| Package | Purpose |
|---------|---------|
| `ecdsa` | Elliptic curve operations (secp160r1, NIST P-256) |
| `pycryptodome` | Cryptographic primitives |
| `matplotlib` | IEEE-formatted figure generation |
| `numpy` | Numerical computation |
| `scipy` | Statistical analysis |
| `tabulate` | Console output formatting |

### Hardware (Paper Benchmarks)

The results reported in the paper were obtained on:

| Component | Specification |
|-----------|---------------|
| CPU | Intel Xeon Silver 4314 (64 cores) @ 2.40 GHz |
| RAM | 384 GB DDR4 |
| OS | CentOS Linux 7 (Core) |

Results on different hardware will differ in absolute values but relative comparisons remain valid.

---

## Installation

```bash
# Clone the repository

# Install dependencies
pip install ecdsa pycryptodome matplotlib numpy scipy tabulate
```

---

## Quick Start

### Run the full pipeline
```bash
python main.py
```

### Quick mode (reduced iterations for testing)
```bash
python main.py --quick
```

### Correctness verification only
```bash
python main.py --correctness-only
```

### Generate figures from cached data
```bash
python main.py --figures-only
```

### Specify benchmark iterations
```bash
python main.py --iterations 1000
```

---

## Module Reference

### `config.py` — Configuration and Parameters

Defines all system-wide constants, including:

- **Security levels:** 80-bit (secp160r1) and 128-bit (NIST P-256) per NIST SP 800-57
- **Hash function configuration:** Six domain-separated functions (Hg, h0–h4) instantiated with SHA-256
- **Baseline scheme registry:** Symbolic cost formulas for 9 comparison schemes, including 4 references from 2024–2025
- **Blockchain parameters:** Hyperledger Fabric v2.5 transaction types with payload sizes
- **Network simulation parameters:** Vehicle densities, batch periods, pseudonym update triggers
- **VESCA cost formulas:**
  - Signcryption: `2*ETsm + 3*ETh + ETpa`
  - Unsigncryption: `2*n*ETsm + n*ETh`
  - Batch verification: `(2*n+2)*ETsm + n*ETh + (n-1)*ETpa`

```python
from config import SecurityLevel, DEFAULT_SECURITY_LEVEL, SECURITY_CURVES
print(f"Default: {DEFAULT_SECURITY_LEVEL.value}-bit")
print(f"Curve: {SECURITY_CURVES[DEFAULT_SECURITY_LEVEL].name}")
```

### `primitives.py` — Cryptographic Primitives

Implements all low-level operations with micro-benchmarking:

- **ECC operations:** Scalar multiplication, point addition, point negation
- **Hash functions:** h0–h4 with domain-separation prefixes, KDF-expanded h2
- **Modular arithmetic:** Addition, multiplication, inversion over Z*_q
- **PairingSimulator:** Calibrated timing ratios for baseline cost estimation
- **Benchmarking framework:** 1,000 iterations, first 100 discarded, CV < 2%

```python
from primitives import benchmark_all_primitives, create_pairing_simulator
from config import SecurityLevel

results = benchmark_all_primitives(SecurityLevel.LEVEL_128, iterations=500)
sim = create_pairing_simulator(SecurityLevel.LEVEL_128, results)
print(f"ETsm: {results['ETsm'].mean_ms:.4f} ms")
```

### `scheme.py` — VESCA Scheme Implementation

Complete implementation of all 10 VESCA algorithms:

| Algorithm | Function | Paper Section |
|-----------|----------|---------------|
| PPGen | `ppgen()` | IV-A |
| ES Enrollment | `es_enroll()` | IV-B |
| Driver Enrollment | `driver_enroll()` | IV-C |
| Vehicle Enrollment | `vehicle_enroll()` | IV-D |
| Key Pair Generation | (within `vehicle_enroll`) | IV-D |
| Pseudonym Update | `pseudonym_update()` | IV-E |
| Signcryption | `signcrypt()` | IV-F |
| Aggregate Signcryption | `aggregate_signcrypt()` | IV-G |
| Aggregate Verification | `aggregate_verify()` | IV-H |
| Unsigncryption | `unsigncrypt()` | IV-I |

```python
from scheme import ppgen, vehicle_enroll, signcrypt, run_correctness_test
from config import SecurityLevel

# End-to-end correctness test
success = run_correctness_test(SecurityLevel.LEVEL_128, num_vehicles=5)
```

### `baselines.py` — Baseline Comparison Engine

Cost computation for all comparison schemes:

**Original baselines (from BACAS):**
- Yu et al. (2021) — IEEE Systems Journal
- Dohare et al. (2022) — IEEE Trans. Industrial Informatics
- Yang et al. (2022) — IEEE TIFS
- Yang et al. (2022) — IEEE TGCN
- Rajkumar et al. (2023) — Wireless Networks
- Dai et al. (2022) — IEEE IoT Journal

**New baselines (Reviewer 3 requested):**
- Cobblah et al. (2024) — IEEE IoT Journal *(standalone, non-aggregate)*
- Wang et al. (2025) — IEEE IoT Journal
- Liu et al. (2025) — IEEE IoT Journal

> **Note:** Cobblah et al. (2025) IEEE/ACM TON is a blockchain-based reputation framework (not a signcryption scheme) and is cited in Related Work but excluded from cost comparison.

```python
from baselines import compute_vesca_costs, compute_scheme_costs, EXTENDED_BASELINES
from primitives import create_pairing_simulator

sim = create_pairing_simulator(SecurityLevel.LEVEL_128)
vesca = compute_vesca_costs(sim, n=1, level=SecurityLevel.LEVEL_128)
print(f"VESCA total: {vesca.total_ms:.3f} ms")
```

### `evaluation.py` — Experimental Evaluation Pipeline

Seven-stage evaluation producing all paper results:

| Stage | Output | Paper Reference |
|-------|--------|-----------------|
| Primitive benchmarks | Table IX | Section VI-C |
| Scaling experiments | Figures 4, 5 | Section VI-D |
| Security level comparison | Table XI, Figure 6 | Section VI-E |
| Blockchain performance | Table XIII, Figure 8 | Section VI-G |
| Blockchain storage | Table XIV, Figure 9 | Section VI-G |
| Capacity analysis | Table XV | Section VI-H |
| Network simulation | Figures 10, 11 | Section VI-I |

```python
from evaluation import run_full_evaluation, export_all_results

results = run_full_evaluation(iterations=500, verbose=True)
export_all_results(results)
```

### `plots.py` — Figure Generation

Generates all IEEE-formatted figures:

| Figure | Description | Filename |
|--------|-------------|----------|
| Fig. 4 | Edge server cost vs. vehicle count | `fig4_edge_cost_128bit` |
| Fig. 5 | Signcryption/unsigncryption scaling | `fig5_scaling_128bit` |
| Fig. 6 | 80-bit vs. 128-bit comparison | `fig6_security_level_comparison` |
| Fig. 7 | Communication overhead bar chart | `fig7_comm_overhead_128bit` |
| Fig. 8 | Blockchain delay/throughput heatmaps | `fig8_blockchain_heatmaps` |
| Fig. 9 | Blockchain storage scaling | `fig9_blockchain_storage` |
| Fig. 10 | Network delay vs. density | `fig10_network_delay` |
| Fig. 11 | Message loss rate vs. density | `fig11_message_loss` |

### `main.py` — CLI Orchestrator

```
usage: main.py [-h] [--iterations N] [--quick] [--correctness-only]
               [--figures-only] [--no-figures] [--security-level {80,128}]

VESCA: Complete Experimental Pipeline

optional arguments:
  --iterations N       Benchmark iterations (default: from config)
  --quick              Quick mode with 200 iterations
  --correctness-only   Only run correctness verification
  --figures-only       Only generate figures from cached data
  --no-figures         Skip figure generation
  --security-level     Run only at specified security level (80 or 128)
```

---

## Usage Examples

### Run individual modules

```bash
# Benchmark primitives at both security levels
python primitives.py

# Run correctness tests
python scheme.py

# Compare all baselines
python baselines.py

# Full evaluation with export
python evaluation.py

# Generate figures only
python plots.py
```

### Programmatic usage

```python
from config import SecurityLevel
from primitives import benchmark_all_primitives, create_pairing_simulator
from baselines import generate_comparison_table

# Benchmark at 128-bit security
prims = benchmark_all_primitives(SecurityLevel.LEVEL_128, iterations=500)
sim = create_pairing_simulator(SecurityLevel.LEVEL_128, prims)

# Generate full comparison for vehicle counts 1–140
vehicle_counts = [1, 10, 20, 40, 60, 80, 100, 120, 140]
table = generate_comparison_table(sim, vehicle_counts, SecurityLevel.LEVEL_128)

for scheme, costs in table.items():
    print(f"{scheme}: {costs[0].total_ms:.3f} ms (n=1)")
```

---

## Reproducing Paper Results

### Step 1: Full pipeline execution

```bash
python main.py --iterations 1000
```

This executes all seven evaluation stages and produces:
- JSON data files in `results/data/`
- PNG/PDF figures in `results/figures/`
- LaTeX tables in `results/tables/`

### Step 2: Verify correctness

The pipeline automatically runs correctness tests at both security levels (80-bit and 128-bit) with n ∈ {1, 3, 10}. All six configurations must pass.

### Step 3: Inspect outputs

```bash
ls results/data/          # JSON data for all experiments
ls results/figures/       # Publication-ready figures
ls results/tables/        # LaTeX table source
cat results/data/experiment_config.json  # Full configuration snapshot
```

### Expected output summary

```
VESCA at 128-bit security:
  ETsm:            0.9214 ms
  Signcryption:    1.8620 ms
  Unsigncryption:  1.8470 ms (per message)
  Total:           3.7090 ms

128-bit vs 80-bit overhead:
  Signcryption:    +104.9%
  Communication:   +30.8%

Capacity at 128-bit:
  Verification:    541 msg/s (1-thread), 2165 msg/s (4-thread)
  Max vehicles:    216 per edge server (4-thread)
```

---

## Output Structure

```
results/
├── data/
│   ├── experiment_config.json         # Full parameter snapshot
│   ├── security_level_comparison.json # 80-bit vs 128-bit data
│   ├── blockchain_storage.json        # Ledger growth analysis
│   ├── blockchain_performance.json    # Caliper-calibrated metrics
│   ├── network_simulation.json        # Delay and loss rate data
│   ├── capacity_analysis.json         # TPS reconciliation
│   └── comparison_data.json           # All scheme costs
├── figures/
│   ├── fig4_edge_cost_128bit.{png,pdf}
│   ├── fig5_scaling_128bit.{png,pdf}
│   ├── fig6_security_level_comparison.{png,pdf}
│   ├── fig7_comm_overhead_128bit.{png,pdf}
│   ├── fig8_blockchain_heatmaps.{png,pdf}
│   ├── fig9_blockchain_storage.{png,pdf}
│   ├── fig10_network_delay.{png,pdf}
│   └── fig11_message_loss.{png,pdf}
└── tables/
    ├── table_vii_crypto_comparison.tex
    ├── table_viii_comm_overhead.tex
    ├── table_iii_security_features.tex
    ├── table_v_primitive_times.tex
    └── table_blockchain_storage.tex
```

---

## Mapping to Paper Sections

| Paper Section | Module | Key Function/Class |
|--------------|--------|-------------------|
| II-C (Cryptographic Primitives) | `primitives.py` | `benchmark_all_primitives()` |
| II-D (Threat Model) | `config.py` | `SecurityLevel`, definitions |
| IV-A (PPGen) | `scheme.py` | `ppgen()` |
| IV-B (ES Enrollment) | `scheme.py` | `es_enroll()` |
| IV-C (Driver Enrollment) | `scheme.py` | `driver_enroll()` |
| IV-D (Vehicle Enrollment) | `scheme.py` | `vehicle_enroll()` |
| IV-E (Pseudonym Update) | `scheme.py` | `pseudonym_update()` |
| IV-F (Signcryption) | `scheme.py` | `signcrypt()` |
| IV-G (Aggregate Signcryption) | `scheme.py` | `aggregate_signcrypt()` |
| IV-H (Aggregate Verification) | `scheme.py` | `aggregate_verify()` |
| IV-I (Unsigncryption) | `scheme.py` | `unsigncrypt()` |
| IV-J (Blockchain TX Spec) | `config.py` | `BlockchainConfig.tx_types` |
| VI-A (Experimental Setup) | `config.py` | `BenchmarkConfig` |
| VI-B (Blockchain Selection) | `config.py` | `BlockchainConfig` |
| VI-C (Primitive Benchmarks) | `primitives.py` | `benchmark_all_primitives()` |
| VI-D (Computational Cost) | `baselines.py` | `generate_comparison_table()` |
| VI-E (Security Level Impact) | `evaluation.py` | `run_security_level_comparison()` |
| VI-F (Communication Overhead) | `baselines.py` | `generate_comm_overhead_table()` |
| VI-G (Blockchain Perf/Storage) | `evaluation.py` | `simulate_blockchain_performance()`, `compute_blockchain_storage()` |
| VI-H (Capacity Reconciliation) | `evaluation.py` | `compute_capacity_analysis()` |
| VI-I (Network Simulation) | `evaluation.py` | `run_network_simulation()` |
| VI-J (Correctness) | `scheme.py` | `run_correctness_test()` |

---

## Benchmarking Methodology

Following the protocol described in Section VI-A of the paper:

1. **Iterations:** 1,000 per operation (configurable via `--iterations`)
2. **Warmup:** First 100 iterations discarded to eliminate cache cold-start effects
3. **Statistic:** Arithmetic mean with coefficient of variation (CV) < 2%
4. **Inputs:** Randomly generated per iteration using `secrets` module
5. **Security levels:** Both 80-bit (secp160r1) and 128-bit (NIST P-256)
6. **Timing:** `time.perf_counter_ns()` for nanosecond precision

Pairing-based operation costs (for baseline comparison) are estimated using calibrated timing ratios from MIRACL benchmarks, scaled to the measured ETsm on the executing hardware.


---

## Acknowledgment

This work was supported by the National Natural Science Foundation of China (No. U22B2029) and the Open Research Fund of the State Key Laboratory of Blockchain and Data Security, Zhejiang University.

---

## License

This code is provided for academic research and reproducibility purposes. Please cite the associated paper if you use this code in your work.
