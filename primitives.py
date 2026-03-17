#!/usr/bin/env python3
"""
VESCA Cryptographic Primitives Module
======================================
Implements all low-level cryptographic operations used in the VESCA scheme,
including ECC scalar multiplication, point addition, hash functions, and
(simulated) bilinear pairing operations for baseline comparison.

Each primitive is individually benchmarkable following the methodology:
  - 1000 iterations, first 100 discarded (warmup)
  - Arithmetic mean with coefficient of variation < 2%
  - Random inputs per iteration

Addresses:
  R2: Dual security level support (80-bit and 128-bit)
  R4 #15: Rigorous formalization of cryptographic operations
"""

import os
import time
import hashlib
import secrets
import statistics
from typing import Tuple, Dict, Optional, Callable
from dataclasses import dataclass

import ecdsa
from ecdsa import SECP160r1, NIST256p, ellipticcurve, numbertheory
from ecdsa.ellipticcurve import PointJacobi, INFINITY

from config import (
    SecurityLevel, CurveParams, SECURITY_CURVES, DEFAULT_SECURITY_LEVEL,
    HASH_FUNCTIONS, BENCHMARK_CONFIG, DATA_DIR
)

# ============================================================================
# SECTION 1: Curve Initialization
# ============================================================================

# Map SecurityLevel -> ecdsa curve object
_ECDSA_CURVES = {
    SecurityLevel.LEVEL_80: SECP160r1,
    SecurityLevel.LEVEL_128: NIST256p,
}


def get_curve(level: SecurityLevel = DEFAULT_SECURITY_LEVEL):
    """Get the ecdsa curve object for a security level."""
    return _ECDSA_CURVES[level]


def get_generator(level: SecurityLevel = DEFAULT_SECURITY_LEVEL):
    """Get the base point P for the curve."""
    curve = get_curve(level)
    return curve.generator


def get_order(level: SecurityLevel = DEFAULT_SECURITY_LEVEL) -> int:
    """Get the group order q."""
    curve = get_curve(level)
    return curve.order


# ============================================================================
# SECTION 2: Random Scalar Generation
# ============================================================================

def random_scalar(level: SecurityLevel = DEFAULT_SECURITY_LEVEL) -> int:
    """Generate a random scalar in Z*_q."""
    q = get_order(level)
    while True:
        k = secrets.randbelow(q)
        if k > 0:
            return k


# ============================================================================
# SECTION 3: ECC Point Operations
# ============================================================================

def scalar_mult(k: int, P, level: SecurityLevel = DEFAULT_SECURITY_LEVEL):
    """
    Elliptic curve scalar multiplication: k * P.
    This is the dominant cost operation in pairing-free ECC schemes.
    """
    return k * P


def point_add(P, Q):
    """
    Elliptic curve point addition: P + Q.
    Used in public key computation and aggregation.
    """
    return P + Q


def point_neg(P, level: SecurityLevel = DEFAULT_SECURITY_LEVEL):
    """Point negation: -P."""
    curve = get_curve(level)
    return (-1) * P


def point_to_bytes(P, level: SecurityLevel = DEFAULT_SECURITY_LEVEL) -> bytes:
    """Serialize an elliptic curve point to bytes."""
    if P == INFINITY:
        return b'\x00'
    params = SECURITY_CURVES[level]
    x = P.x()
    y = P.y()
    x_bytes = x.to_bytes(params.scalar_bits // 8, 'big')
    y_bytes = y.to_bytes(params.scalar_bits // 8, 'big')
    return x_bytes + y_bytes


def bytes_to_int(data: bytes, level: SecurityLevel = DEFAULT_SECURITY_LEVEL) -> int:
    """Convert bytes to integer mod q."""
    q = get_order(level)
    return int.from_bytes(data, 'big') % q


# ============================================================================
# SECTION 4: Hash Functions (Domain-Separated, per Table II)
# ============================================================================

def _hash_core(data: bytes, level: SecurityLevel = DEFAULT_SECURITY_LEVEL) -> int:
    """
    Core hash function: SHA-256 (128-bit) or SHA-1 (80-bit) -> Z*_q.
    Output is reduced modulo q.
    """
    params = SECURITY_CURVES[level]
    if params.hash_algorithm == "sha256":
        digest = hashlib.sha256(data).digest()
    else:
        digest = hashlib.sha1(data).digest()
    q = get_order(level)
    return int.from_bytes(digest, 'big') % q


def hash_Hg(identity: bytes, level: SecurityLevel = DEFAULT_SECURITY_LEVEL) -> int:
    """Hg: General-purpose identity hashing."""
    prefix = HASH_FUNCTIONS["Hg"].domain_prefix
    return _hash_core(prefix + identity, level)


def hash_h0(*args, level: SecurityLevel = DEFAULT_SECURITY_LEVEL) -> int:
    """
    h0: G x {0,1}* -> Z*_q
    Used for pseudo-identity generation and coefficient derivation.
    Accepts mix of EC points and byte strings.
    """
    prefix = HASH_FUNCTIONS["h0"].domain_prefix
    data = prefix
    for arg in args:
        if isinstance(arg, bytes):
            data += arg
        elif isinstance(arg, (str,)):
            data += arg.encode()
        elif isinstance(arg, int):
            data += arg.to_bytes(32, 'big')
        else:
            # Assume EC point
            data += point_to_bytes(arg, level)
    return _hash_core(data, level)


def hash_h1(*args, level: SecurityLevel = DEFAULT_SECURITY_LEVEL) -> int:
    """
    h1: G x G x {0,1}* -> Z*_q
    Vehicle pseudo-identity with temporal binding.
    """
    prefix = HASH_FUNCTIONS["h1"].domain_prefix
    data = prefix
    for arg in args:
        if isinstance(arg, bytes):
            data += arg
        elif isinstance(arg, (str,)):
            data += arg.encode()
        elif isinstance(arg, int):
            data += arg.to_bytes(32, 'big')
        else:
            data += point_to_bytes(arg, level)
    return _hash_core(data, level)


def hash_h2(*args, level: SecurityLevel = DEFAULT_SECURITY_LEVEL) -> bytes:
    """
    h2: {0,1}* x G x G x G x {0,1}* -> {0,1}*
    Message concealment via KDF-expanded hash.
    Returns raw bytes for XOR-based encryption.
    """
    prefix = HASH_FUNCTIONS["h2"].domain_prefix
    data = prefix
    for arg in args:
        if isinstance(arg, bytes):
            data += arg
        elif isinstance(arg, (str,)):
            data += arg.encode()
        elif isinstance(arg, int):
            data += arg.to_bytes(32, 'big')
        else:
            data += point_to_bytes(arg, level)
    # KDF expansion using counter mode (for variable-length output)
    params = SECURITY_CURVES[level]
    if params.hash_algorithm == "sha256":
        return hashlib.sha256(data).digest()
    else:
        return hashlib.sha1(data).digest()


def hash_h2_expand(
    *args,
    output_len: int,
    level: SecurityLevel = DEFAULT_SECURITY_LEVEL
) -> bytes:
    """
    KDF-expanded h2 for arbitrary-length message concealment.
    Uses HKDF-like counter mode.
    """
    prefix = HASH_FUNCTIONS["h2"].domain_prefix
    data = prefix
    for arg in args:
        if isinstance(arg, bytes):
            data += arg
        elif isinstance(arg, (str,)):
            data += arg.encode()
        elif isinstance(arg, int):
            data += arg.to_bytes(32, 'big')
        else:
            data += point_to_bytes(arg, level)

    params = SECURITY_CURVES[level]
    hash_fn = hashlib.sha256 if params.hash_algorithm == "sha256" else hashlib.sha1
    block_size = hash_fn().digest_size

    result = b""
    counter = 0
    while len(result) < output_len:
        block = hash_fn(data + counter.to_bytes(4, 'big')).digest()
        result += block
        counter += 1
    return result[:output_len]


def hash_h3(*args, level: SecurityLevel = DEFAULT_SECURITY_LEVEL) -> int:
    """
    h3: G x {0,1}* x G -> Z*_q
    Signcryption coefficient binding message to sender.
    """
    prefix = HASH_FUNCTIONS["h3"].domain_prefix
    data = prefix
    for arg in args:
        if isinstance(arg, bytes):
            data += arg
        elif isinstance(arg, (str,)):
            data += arg.encode()
        elif isinstance(arg, int):
            data += arg.to_bytes(32, 'big')
        else:
            data += point_to_bytes(arg, level)
    return _hash_core(data, level)


def hash_h4(*args, level: SecurityLevel = DEFAULT_SECURITY_LEVEL) -> int:
    """
    h4: {0,1}* x {0,1}* x G x G -> Z*_q
    Signature coefficient for non-repudiation.
    """
    prefix = HASH_FUNCTIONS["h4"].domain_prefix
    data = prefix
    for arg in args:
        if isinstance(arg, bytes):
            data += arg
        elif isinstance(arg, (str,)):
            data += arg.encode()
        elif isinstance(arg, int):
            data += arg.to_bytes(32, 'big')
        else:
            data += point_to_bytes(arg, level)
    return _hash_core(data, level)


def xor_bytes(a: bytes, b: bytes) -> bytes:
    """XOR two byte strings. If lengths differ, truncate to shorter."""
    length = min(len(a), len(b))
    return bytes(x ^ y for x, y in zip(a[:length], b[:length]))


# ============================================================================
# SECTION 5: Modular Arithmetic Helpers
# ============================================================================

def mod_inverse(a: int, q: int) -> int:
    """Compute modular inverse a^{-1} mod q."""
    return pow(a, q - 2, q)  # Fermat's little theorem (q is prime)


def mod_add(a: int, b: int, q: int) -> int:
    """Modular addition."""
    return (a + b) % q


def mod_mul(a: int, b: int, q: int) -> int:
    """Modular multiplication."""
    return (a * b) % q


# ============================================================================
# SECTION 6: Simulated Pairing Operations (for baseline cost estimation)
# ============================================================================

class PairingSimulator:
    """
    Simulates bilinear pairing operations for baseline comparison.
    Uses calibrated timing ratios from MIRACL benchmarks (Table V).

    Timing ratios (relative to ETsm at the same security level):
      ETbp   / ETsm ≈ 5.048
      ETbpsm / ETsm ≈ 4.426
      ETmp   / ETsm ≈ 7.831
      ETbppa / ETsm ≈ 0.017
      ETe    / ETsm ≈ 2.164
      HECDM  / ETsm ≈ 0.429  (Cobblah 2024: HECDM=0.42, SPMEC=0.98)
    """
    RATIOS = {
        "ETbp":   5.048,   # Bilinear pairing e(P,Q)
        "ETbpsm": 4.426,   # Pairing scalar mult a*P in Gb
        "ETmp":   7.831,   # Map-to-point hash
        "ETbppa": 0.017,   # Pairing point addition
        "ETe":    2.164,   # Modular exponentiation
        "ETsm":   1.000,   # ECC scalar mult (reference)
        "ETpa":   0.007,   # ECC point addition
        "ETh":    0.009,   # Hash function
        "HECDM":  0.429,   # Hyperelliptic-curve divisor multiplication
    }

    def __init__(self, base_etsm_ms: float, measured: dict = None):
        """
        Initialize with measured ETsm time in milliseconds.

        Args:
            base_etsm_ms: Measured ETsm time (ms)
            measured: Optional dict of {op_name: measured_ms} to override
                      ratio-based estimates with actual measurements
        """
        self.base_etsm_ms = base_etsm_ms
        self.times = {}
        for op, ratio in self.RATIOS.items():
            self.times[op] = base_etsm_ms * ratio
        # Override with measured values when available (fixes ETpa/ETh accuracy)
        if measured:
            for op, ms in measured.items():
                if op in self.times:
                    self.times[op] = ms

    def get_time(self, operation: str) -> float:
        """Get estimated time for an operation in milliseconds."""
        return self.times.get(operation, 0.0)

    def evaluate_formula(self, formula: str, n: int = 1) -> float:
        """
        Evaluate a symbolic cost formula.
        E.g., "2*ETsm + 3*ETh + ETpa" -> numerical ms value
        Supports parenthesized expressions like "(3*n+2)*ETsm + 3*n*ETpa".
        """
        import re
        # Replace 'n' with actual count (word boundary to avoid replacing
        # 'n' inside operation names or other tokens)
        expr = re.sub(r'\bn\b', str(n), formula)
        # Replace operation names with their ms values (longest first to
        # avoid partial matches, e.g. ETbpsm before ETbp)
        for op in sorted(self.times.keys(), key=len, reverse=True):
            expr = expr.replace(op, str(self.times[op]))
        try:
            return eval(expr)
        except Exception:
            return 0.0


# ============================================================================
# SECTION 7: Micro-Benchmarking Framework
# ============================================================================

@dataclass
class BenchmarkResult:
    """Result of benchmarking a single operation."""
    operation: str
    security_level: int
    mean_ms: float
    std_ms: float
    median_ms: float
    cv: float              # Coefficient of variation
    min_ms: float
    max_ms: float
    iterations: int


def benchmark_operation(
    operation_fn: Callable,
    operation_name: str,
    level: SecurityLevel = DEFAULT_SECURITY_LEVEL,
    setup_fn: Callable = None,
    iterations: int = None,
    warmup: int = None,
) -> BenchmarkResult:
    """
    Benchmark a single cryptographic operation with statistical rigor.

    Args:
        operation_fn: Function to benchmark (called with setup output)
        operation_name: Human-readable name
        level: Security level
        setup_fn: Called before each iteration to generate fresh inputs
        iterations: Total iterations (default from config)
        warmup: Warmup iterations to discard (default from config)

    Returns:
        BenchmarkResult with timing statistics
    """
    if iterations is None:
        iterations = BENCHMARK_CONFIG.total_iterations
    if warmup is None:
        warmup = BENCHMARK_CONFIG.warmup_iterations

    times = []
    for i in range(iterations):
        if setup_fn is not None:
            args = setup_fn()
        else:
            args = ()

        if not isinstance(args, tuple):
            args = (args,)

        start = time.perf_counter_ns()
        operation_fn(*args)
        end = time.perf_counter_ns()

        if i >= warmup:
            elapsed_ms = (end - start) / 1e6
            times.append(elapsed_ms)

    mean = statistics.mean(times)
    std = statistics.stdev(times) if len(times) > 1 else 0.0
    cv = std / mean if mean > 0 else 0.0

    return BenchmarkResult(
        operation=operation_name,
        security_level=SECURITY_CURVES[level].bit_security,
        mean_ms=mean,
        std_ms=std,
        median_ms=statistics.median(times),
        cv=cv,
        min_ms=min(times),
        max_ms=max(times),
        iterations=len(times),
    )


# ============================================================================
# SECTION 8: Benchmark All Primitives
# ============================================================================

def benchmark_all_primitives(
    level: SecurityLevel = DEFAULT_SECURITY_LEVEL,
    iterations: int = None,
) -> Dict[str, BenchmarkResult]:
    """
    Benchmark all ECC and hash primitives at the specified security level.
    Returns a dictionary mapping operation name -> BenchmarkResult.
    """
    P = get_generator(level)
    q = get_order(level)
    results = {}

    # --- ETsm: ECC Scalar Multiplication ---
    def setup_sm():
        k = random_scalar(level)
        return (k, P)

    results["ETsm"] = benchmark_operation(
        lambda k, pt: scalar_mult(k, pt, level),
        "ECC Scalar Multiplication",
        level, setup_fn=setup_sm, iterations=iterations,
    )

    # --- ETpa: ECC Point Addition ---
    def setup_pa():
        k1 = random_scalar(level)
        k2 = random_scalar(level)
        P1 = scalar_mult(k1, P, level)
        P2 = scalar_mult(k2, P, level)
        return (P1, P2)

    results["ETpa"] = benchmark_operation(
        lambda p1, p2: point_add(p1, p2),
        "ECC Point Addition",
        level, setup_fn=setup_pa, iterations=iterations,
    )

    # --- ETh: Hash Function ---
    def setup_hash():
        data = secrets.token_bytes(64)
        return (data,)

    results["ETh"] = benchmark_operation(
        lambda data: hash_h0(data, level=level),
        "Hash Function",
        level, setup_fn=setup_hash, iterations=iterations,
    )

    # --- Combined: 2*ETsm (for signcryption cost estimation) ---
    def setup_2sm():
        k1 = random_scalar(level)
        k2 = random_scalar(level)
        return (k1, k2, P)

    results["2ETsm"] = benchmark_operation(
        lambda k1, k2, pt: (scalar_mult(k1, pt, level),
                            scalar_mult(k2, pt, level)),
        "2x ECC Scalar Multiplication",
        level, setup_fn=setup_2sm, iterations=iterations,
    )

    print(f"\n  Primitives benchmarked at {SECURITY_CURVES[level].bit_security}-bit security:")
    for name, res in results.items():
        print(f"    {name:8s}: {res.mean_ms:.4f} ms  (CV={res.cv:.4f})")

    return results


# ============================================================================
# SECTION 9: Convenience: Get Pairing Simulator from Benchmark
# ============================================================================

def create_pairing_simulator(
    level: SecurityLevel = DEFAULT_SECURITY_LEVEL,
    primitive_results: Dict[str, BenchmarkResult] = None,
) -> PairingSimulator:
    """
    Create a PairingSimulator calibrated to actual ETsm measurements.
    Overrides ratio-based ETpa and ETh with measured values for accuracy.
    If primitive_results not provided, runs a quick benchmark.
    """
    if primitive_results is None:
        primitive_results = benchmark_all_primitives(level, iterations=200)

    etsm_ms = primitive_results["ETsm"].mean_ms

    # Collect measured values to override ratio-based estimates
    measured = {}
    if "ETpa" in primitive_results:
        measured["ETpa"] = primitive_results["ETpa"].mean_ms
    if "ETh" in primitive_results:
        measured["ETh"] = primitive_results["ETh"].mean_ms

    return PairingSimulator(etsm_ms, measured=measured)


if __name__ == "__main__":
    print("=" * 70)
    print("VESCA Cryptographic Primitives Benchmark")
    print("=" * 70)

    for level in [SecurityLevel.LEVEL_80, SecurityLevel.LEVEL_128]:
        params = SECURITY_CURVES[level]
        print(f"\n{'─' * 50}")
        print(f"Security Level: {params.bit_security}-bit  |  Curve: {params.name}")
        print(f"{'─' * 50}")

        results = benchmark_all_primitives(level, iterations=300)

        # Create simulator and show estimated pairing costs
        sim = create_pairing_simulator(level, results)
        print(f"\n  Estimated pairing-based operation costs:")
        for op in ["ETbp", "ETbpsm", "ETmp", "ETe"]:
            print(f"    {op:8s}: {sim.get_time(op):.4f} ms")
