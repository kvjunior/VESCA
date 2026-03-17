#!/usr/bin/env python3
"""
VESCA Configuration Module
==========================
Vehicular Edge-assisted Secure Certificateless Aggregate signcryption

This module defines all system parameters, security levels, curve
configurations, hash function mappings, and baseline scheme operation
costs used throughout the VESCA framework.

Key Improvements Over BACAS (Addressing Reviewer Concerns):
  - R2: Dual security levels (80-bit AND 128-bit) with full benchmarks
  - R4: Explicit blockchain transaction type definitions for storage analysis
  - R3: Extended baseline set including 2024-2025 references
  - R1: Clear parameter documentation and traceability

References:
  [1] NIST SP 800-57 Part 1 Rev. 5 (2020) - Security strength guidelines
  [2] SEC 2: Recommended Elliptic Curve Domain Parameters, v2.0
"""

import os
import json
import hashlib
from dataclasses import dataclass, field, asdict
from typing import Dict, List, Tuple, Optional
from enum import Enum

# ============================================================================
# SECTION 1: Security Level Definitions
# ============================================================================

class SecurityLevel(Enum):
    """
    Security levels per NIST SP 800-57.
    BACAS used only LEVEL_80; VESCA supports both for rigorous comparison.
    """
    LEVEL_80  = 80   # 160-bit ECC group order (BACAS original)
    LEVEL_128 = 128  # 256-bit ECC group order (VESCA recommended)


@dataclass(frozen=True)
class CurveParams:
    """Elliptic curve parameter set for a given security level."""
    name: str               # Human-readable name
    ecdsa_curve_name: str   # ecdsa library curve identifier
    bit_security: int       # Equivalent symmetric security bits
    scalar_bits: int        # Scalar (private key) bit length
    point_bytes: int        # Compressed point size in bytes
    hash_output_bits: int   # Hash output length
    hash_algorithm: str     # Hash function name
    p_hex: str              # Field prime (hex)
    order_hex: str          # Group order (hex)


# --- 80-bit security (BACAS original, for backward comparison) ---
CURVE_80 = CurveParams(
    name="secp160r1",
    ecdsa_curve_name="SECP160r1",
    bit_security=80,
    scalar_bits=160,
    point_bytes=21,        # 1 + 20 bytes compressed
    hash_output_bits=160,
    hash_algorithm="sha1",
    p_hex="FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF7FFFFFFF",
    order_hex="0100000000000000000001F4C8F927AED3CA752257",
)

# --- 128-bit security (VESCA recommended) ---
CURVE_128 = CurveParams(
    name="NIST P-256 (secp256r1)",
    ecdsa_curve_name="NIST256p",
    bit_security=128,
    scalar_bits=256,
    point_bytes=33,        # 1 + 32 bytes compressed
    hash_output_bits=256,
    hash_algorithm="sha256",
    p_hex="FFFFFFFF00000001000000000000000000000000FFFFFFFFFFFFFFFFFFFFFFFF",
    order_hex="FFFFFFFF00000000FFFFFFFFFFFFFFFFBCE6FAADA7179E84F3B9CAC2FC632551",
)

# Mapping for easy lookup
SECURITY_CURVES = {
    SecurityLevel.LEVEL_80: CURVE_80,
    SecurityLevel.LEVEL_128: CURVE_128,
}

# Default security level for VESCA
DEFAULT_SECURITY_LEVEL = SecurityLevel.LEVEL_128


# ============================================================================
# SECTION 2: Hash Function Configuration (Table II in paper)
# ============================================================================

@dataclass(frozen=True)
class HashFunctionConfig:
    """
    Specification for each hash function used in the scheme.
    Domain separation prefixes ensure cryptographic independence (SHA-256).
    """
    name: str
    input_description: str
    output_description: str
    purpose: str
    domain_prefix: bytes   # Unique prefix for domain separation


HASH_FUNCTIONS = {
    "Hg": HashFunctionConfig(
        name="Hg",
        input_description="{0,1}*",
        output_description="Z*_q",
        purpose="General-purpose identity hashing",
        domain_prefix=b"VESCA_Hg_v1:",
    ),
    "h0": HashFunctionConfig(
        name="h0",
        input_description="G x {0,1}*",
        output_description="Z*_q",
        purpose="Pseudo-identity generation and coefficient derivation",
        domain_prefix=b"VESCA_h0_v1:",
    ),
    "h1": HashFunctionConfig(
        name="h1",
        input_description="G x G x {0,1}*",
        output_description="Z*_q",
        purpose="Vehicle pseudo-identity with temporal binding",
        domain_prefix=b"VESCA_h1_v1:",
    ),
    "h2": HashFunctionConfig(
        name="h2",
        input_description="{0,1}* x G x G x G x {0,1}*",
        output_description="Z*_q",
        purpose="Message concealment and one-time pad generation",
        domain_prefix=b"VESCA_h2_v1:",
    ),
    "h3": HashFunctionConfig(
        name="h3",
        input_description="G x {0,1}* x G",
        output_description="Z*_q",
        purpose="Signcryption coefficient (binds message to sender)",
        domain_prefix=b"VESCA_h3_v1:",
    ),
    "h4": HashFunctionConfig(
        name="h4",
        input_description="{0,1}* x {0,1}* x G x G",
        output_description="Z*_q",
        purpose="Signature coefficient ensuring non-repudiation",
        domain_prefix=b"VESCA_h4_v1:",
    ),
}


# ============================================================================
# SECTION 3: Benchmarking Configuration
# ============================================================================

@dataclass
class BenchmarkConfig:
    """Parameters controlling the benchmarking methodology."""
    total_iterations: int = 1000      # Total repetitions per operation
    warmup_iterations: int = 100      # Discarded warmup runs (cache effects)
    vehicle_counts: List[int] = field(
        default_factory=lambda: [1, 5, 10, 20, 40, 60, 80, 100, 120, 140]
    )
    security_levels: List[SecurityLevel] = field(
        default_factory=lambda: [SecurityLevel.LEVEL_80, SecurityLevel.LEVEL_128]
    )
    confidence_level: float = 0.95    # For confidence intervals
    cv_threshold: float = 0.02        # Max coefficient of variation (2%)
    random_seed: int = 42             # Reproducibility


BENCHMARK_CONFIG = BenchmarkConfig()


# ============================================================================
# SECTION 4: Baseline Scheme Definitions (Extended per R3)
# ============================================================================

@dataclass(frozen=True)
class BaselineScheme:
    """
    Defines a baseline scheme's cryptographic operation profile.
    Operation costs are expressed symbolically in terms of primitive costs.
    """
    label: str                          # Short citation label
    authors: str                        # Author names
    year: int                           # Publication year
    venue: str                          # Journal/conference
    signcrypt_formula: str              # Symbolic expression
    unsigncrypt_formula: str            # Symbolic expression (may contain 'n')
    comm_overhead_bytes: int            # Per-message communication cost
    uses_pairing: bool                  # Whether bilinear pairings are used
    doi: str = ""                       # DOI for reference


# Cryptographic operation symbolic names (resolved at runtime from benchmarks)
# ETbp   = Bilinear pairing
# ETbpsm = Bilinear pairing scalar multiplication
# ETmp   = Map-to-point hash
# ETbppa = Bilinear pairing point addition
# ETpa   = ECC point addition
# ETsm   = ECC scalar multiplication
# ETh    = Hash function
# ETe    = Modular exponentiation

BASELINE_SCHEMES = {
    "Yu2021": BaselineScheme(
        label="Yu et al.",
        authors="H. Yu and R. Ren",
        year=2021,
        venue="IEEE Syst. J.",
        signcrypt_formula="2*ETpa + 3*ETsm",
        unsigncrypt_formula="3*ETpa + 4*ETmp",
        comm_overhead_bytes=336,
        uses_pairing=False,
        doi="10.1109/JSYST.2021.3053498",
    ),
    "Dohare2022": BaselineScheme(
        label="Dohare et al.",
        authors="I. Dohare et al.",
        year=2022,
        venue="IEEE Trans. Ind. Inform.",
        signcrypt_formula="ETe + 2*ETmp",
        unsigncrypt_formula="2*n*(ETe+ETh) + ETbp",
        comm_overhead_bytes=336,
        uses_pairing=True,
        doi="10.1109/TII.2022.3147166",
    ),
    "Yang2022a": BaselineScheme(
        label="Yang et al. (TIFS)",
        authors="Y. Yang et al.",
        year=2022,
        venue="IEEE Trans. Inf. Forensics Secur.",
        signcrypt_formula="6*ETbpsm",
        unsigncrypt_formula="5*ETbp + 3*n*ETbpsm + 3*ETmp + 2*n*ETh",
        comm_overhead_bytes=786,
        uses_pairing=True,
        doi="10.1109/TIFS.2021.3138612",
    ),
    "Yang2022b": BaselineScheme(
        label="Yang et al. (TGCN)",
        authors="Y. Yang et al.",
        year=2022,
        venue="IEEE Trans. Green Commun. Netw.",
        signcrypt_formula="2*ETsm + ETpa + 2*ETmp + 3*ETh",
        unsigncrypt_formula="3*n*ETbppa + 3*n*ETbpsm + n*ETmp + 3*n*ETh",
        comm_overhead_bytes=1472,
        uses_pairing=True,
        doi="10.1109/TGCN.2022.3155463",
    ),
    "Rajkumar2023": BaselineScheme(
        label="Rajkumar et al.",
        authors="Y. Rajkumar and S. S. Kumar",
        year=2023,
        venue="Wireless Networks",
        signcrypt_formula="3*ETsm + 5*ETpa + ETh",
        unsigncrypt_formula="3*n*ETbpsm + 5*n*ETpa + 2*n*ETh",
        comm_overhead_bytes=1984,
        uses_pairing=True,
        doi="10.1007/s11276-023-03388-6",
    ),
    "Dai2022": BaselineScheme(
        label="Dai et al.",
        authors="C. Dai and Z. Xu",
        year=2022,
        venue="IEEE IoT J.",
        signcrypt_formula="ETpa + 3*ETmp",
        unsigncrypt_formula="2*ETpa + 4*n*ETmp",
        comm_overhead_bytes=698,
        uses_pairing=False,
        doi="10.1109/JIOT.2022.3222048",
    ),
    # ---- NEW baselines from Reviewer 3 suggested references ----
    "Cobblah2024": BaselineScheme(
        label="Cobblah et al. (2024)",
        authors="C. N. A. Cobblah et al.",
        year=2024,
        venue="IEEE IoT J.",
        # Standalone (NOT aggregate) signcryption using hyperelliptic curves.
        # Paper Table V: 3 HECDM per operation. For n messages: n individual ops.
        # HECDM = hyperelliptic-curve divisor multiplication (ratio 0.4286 vs ETsm).
        signcrypt_formula="3*HECDM",
        unsigncrypt_formula="3*n*HECDM",
        comm_overhead_bytes=144,
        uses_pairing=False,
        doi="10.1109/JIOT.2024.3399031",
    ),
    "Wang2025": BaselineScheme(
        label="Wang et al. (2025)",
        authors="Y. Wang et al.",
        year=2025,
        venue="IEEE IoT J.",
        # Paper Table IV: Signcrypt = 3Tm, Agg unsigncrypt = 2nTm + (2n-1)Ta
        # Tm = ETsm, Ta = ETpa
        signcrypt_formula="3*ETsm",
        unsigncrypt_formula="2*n*ETsm + (2*n-1)*ETpa",
        comm_overhead_bytes=124,
        uses_pairing=False,
        doi="10.1109/JIOT.2025.3528067",
    ),
    "Liu2025": BaselineScheme(
        label="Liu et al. (2025)",
        authors="D. Liu et al.",
        year=2025,
        venue="IEEE IoT J.",
        # Paper Table IV: Signcrypt = 3Tm + 2Ta, Agg unsigncrypt = (3n+2)Tm + 3nTa
        # Tm = ETsm, Ta = ETpa
        signcrypt_formula="3*ETsm + 2*ETpa",
        unsigncrypt_formula="(3*n+2)*ETsm + 3*n*ETpa",
        comm_overhead_bytes=132,
        uses_pairing=False,
        doi="10.1109/JIOT.2025.3590105",
    ),
}


# ============================================================================
# SECTION 5: Blockchain Configuration (Addresses R4 #9, #10, #11)
# ============================================================================

@dataclass
class BlockchainConfig:
    """
    Hyperledger Fabric deployment parameters.
    Includes storage overhead metrics (NEW - addresses R4 comment #11).
    """
    fabric_version: str = "2.5"
    consensus: str = "Raft"
    num_orderers: int = 3              # 2f+1 for f=1 fault tolerance
    num_peers_edge: int = 4            # Edge server peers
    num_peers_cloud: int = 1           # Cloud platform peer (anchor)
    block_size_tx: int = 50            # Transactions per block
    block_timeout_s: float = 2.0       # Block creation timeout
    # Chaincode channels
    channels: List[str] = field(
        default_factory=lambda: ["edge-auth-channel", "cloud-mgmt-channel"]
    )
    # Transaction types and their estimated payload sizes (bytes)
    # (Addresses R4 #9: explicit details for all transaction types)
    tx_types: Dict[str, int] = field(default_factory=lambda: {
        "RegisterVehicle":   320,   # PSID + Pubk + partial key proof + Bi
        "RegisterDriver":    256,   # PSID_dj + Pubk_dj + metadata
        "RegisterES":        288,   # PSID_en + Pubk_en + Sn
        "QueryParams":        64,   # Query by Ai or PSID
        "UpdatePseudonym":   384,   # Old PSID + New PSID + new params
        "RevokeVehicle":     128,   # DeleteTXN with Ai reference
        "StoreAST":          512,   # Aggregate signcrypted text metadata
    })
    # Caliper benchmark parameters
    caliper_workers: int = 4
    caliper_tx_counts: List[int] = field(
        default_factory=lambda: [100, 500, 1000, 5000, 10000, 50000]
    )
    caliper_send_rates: List[int] = field(
        default_factory=lambda: [100, 200, 400, 600, 800, 1000]
    )


BLOCKCHAIN_CONFIG = BlockchainConfig()


# ============================================================================
# SECTION 6: Network Simulation Configuration
# ============================================================================

@dataclass
class NetworkSimConfig:
    """
    Parameters for vehicular network simulation (ndnSIM-equivalent).
    Models aggregation delay and message loss analytically.
    """
    area_km2: float = 1.0              # Simulation area
    avg_speed_kmh: float = 60.0        # Average vehicle speed
    comm_range_m: float = 250.0        # Communication range
    channel_rate_mbps: float = 5.0     # Channel data rate
    interest_interval_ms: float = 100.0  # Interest packet broadcast interval
    interest_pkt_bytes: int = 148
    data_pkt_bytes: int = 212
    vehicle_densities: List[int] = field(
        default_factory=lambda: [20, 40, 60, 80, 100, 120, 140, 160, 180, 200]
    )
    batch_periods_ms: List[int] = field(
        default_factory=lambda: [20, 30, 40, 50, 60]
    )
    # Pseudonym update parameters (Addresses R4 #7)
    pseudonym_validity: Dict[str, int] = field(default_factory=lambda: {
        "urban_min": 10,        # minutes
        "highway_min": 30,
        "high_risk_min": 5,
        "msg_threshold": 100,   # messages before forced refresh
    })


NETWORK_SIM_CONFIG = NetworkSimConfig()


# ============================================================================
# SECTION 7: VESCA Scheme Operation Cost (Our scheme)
# ============================================================================

# Symbolic formulas for VESCA (improved over BACAS)
VESCA_SIGNCRYPT_FORMULA = "2*ETsm + 3*ETh + ETpa"
VESCA_UNSIGNCRYPT_FORMULA = "2*n*ETsm + n*ETh"
VESCA_COMM_OVERHEAD_BYTES_80 = 104   # At 80-bit security
VESCA_COMM_OVERHEAD_BYTES_128 = 136  # At 128-bit security (larger points)

# Improvement: Batch verification optimization (NEW)
VESCA_BATCH_VERIFY_FORMULA = "(2*n+2)*ETsm + n*ETh + (n-1)*ETpa"


# ============================================================================
# SECTION 8: Output Directories
# ============================================================================

OUTPUT_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), "results")
FIGURES_DIR = os.path.join(OUTPUT_DIR, "figures")
TABLES_DIR = os.path.join(OUTPUT_DIR, "tables")
DATA_DIR = os.path.join(OUTPUT_DIR, "data")

for _dir in [OUTPUT_DIR, FIGURES_DIR, TABLES_DIR, DATA_DIR]:
    os.makedirs(_dir, exist_ok=True)


# ============================================================================
# SECTION 9: Utility Functions
# ============================================================================

def get_curve_params(level: SecurityLevel = DEFAULT_SECURITY_LEVEL) -> CurveParams:
    """Retrieve curve parameters for the specified security level."""
    return SECURITY_CURVES[level]


def export_config(filepath: str = None):
    """Export full configuration as JSON for reproducibility."""
    if filepath is None:
        filepath = os.path.join(DATA_DIR, "experiment_config.json")

    config = {
        "default_security_level": DEFAULT_SECURITY_LEVEL.value,
        "curve_80": {
            "name": CURVE_80.name,
            "bit_security": CURVE_80.bit_security,
            "scalar_bits": CURVE_80.scalar_bits,
        },
        "curve_128": {
            "name": CURVE_128.name,
            "bit_security": CURVE_128.bit_security,
            "scalar_bits": CURVE_128.scalar_bits,
        },
        "benchmark": asdict(BENCHMARK_CONFIG),
        "blockchain": {
            "fabric_version": BLOCKCHAIN_CONFIG.fabric_version,
            "consensus": BLOCKCHAIN_CONFIG.consensus,
            "tx_types": BLOCKCHAIN_CONFIG.tx_types,
        },
        "network_sim": {
            "vehicle_densities": NETWORK_SIM_CONFIG.vehicle_densities,
            "batch_periods_ms": NETWORK_SIM_CONFIG.batch_periods_ms,
        },
        "vesca_formulas": {
            "signcrypt": VESCA_SIGNCRYPT_FORMULA,
            "unsigncrypt": VESCA_UNSIGNCRYPT_FORMULA,
            "batch_verify": VESCA_BATCH_VERIFY_FORMULA,
        },
        "baselines": {s.label: s.doi for s in BASELINE_SCHEMES.values()},
    }

    with open(filepath, "w") as f:
        json.dump(config, f, indent=2, default=str)
    return filepath


if __name__ == "__main__":
    path = export_config()
    print(f"Configuration exported to: {path}")
    print(f"Default security level: {DEFAULT_SECURITY_LEVEL.value}-bit")
    print(f"Default curve: {get_curve_params().name}")
    print(f"Baseline schemes: {len(BASELINE_SCHEMES)}")
    print(f"Hash functions: {len(HASH_FUNCTIONS)}")
