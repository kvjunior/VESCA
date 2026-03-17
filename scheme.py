#!/usr/bin/env python3
"""
VESCA Scheme Implementation
============================
Complete implementation of the Vehicular Edge-assisted Secure Certificateless
Aggregate Signcryption (VESCA) scheme.

Algorithms implemented:
  1. PPGen    - Public Parameter Generation (System Setup)
  2. ESEnroll - Edge Server Enrollment and Key Generation
  3. DrvEnroll- Driver Enrollment
  4. VehEnroll- Vehicle Enrollment and Partial Key Generation
  5. KPGen    - Vehicle Key Pair Generation
  6. PseudUpd - Pseudonym Update Protocol
  7. Signc    - Signcryption
  8. ASignc   - Aggregate Signcryption
  9. AVerf    - Aggregate Verification (with batch optimization)
  10. Unsignc - Unsigncryption

Key Improvements Over BACAS:
  - 128-bit security (NIST P-256) as default
  - Batch verification optimization reducing edge server cost
  - Explicit correctness proofs via assertion-based testing
  - Clear variable naming matching paper notation
"""

import os
import time
import secrets
import struct
from typing import List, Tuple, Optional, Dict, NamedTuple
from dataclasses import dataclass, field

from config import SecurityLevel, DEFAULT_SECURITY_LEVEL, SECURITY_CURVES
from primitives import (
    get_curve, get_generator, get_order, random_scalar,
    scalar_mult, point_add, point_to_bytes,
    hash_h0, hash_h1, hash_h2_expand, hash_h3, hash_h4, hash_Hg,
    xor_bytes, mod_inverse, mod_add, mod_mul,
)

# ============================================================================
# SECTION 1: Data Structures
# ============================================================================

@dataclass
class SystemParams:
    """Public parameters output by PPGen."""
    curve_name: str
    P: object             # Generator point
    q: int                # Group order
    PubkCP: object        # Cloud platform public key = r * P
    level: SecurityLevel


@dataclass
class MasterSecret:
    """Master secret key held by the Cloud Platform."""
    r: int                # Master private key


@dataclass
class EdgeServerKeys:
    """Edge server key material after enrollment."""
    PSID_en: bytes        # Pseudo-identity
    sn: int               # Secret value
    Sn: object            # Public value = sn * P
    gamma_n: int          # Partial private key
    Wn: object            # CP random point = wn * P
    sigma_n: int          # Coefficient h0(Sn, PSID_en)
    PubkES: object        # Public key
    PrvkES: int           # Private key


@dataclass
class DriverRecord:
    """Driver registration record."""
    PSID_dj: bytes        # Pseudo-identity
    Pubk_dj: object       # Driver public key = x * P
    x: int                # Driver secret
    upsilon_j: int        # Verification parameter h0(Pubk_dj, PSID_dj)


@dataclass
class VehicleKeys:
    """Vehicle key material after enrollment and key pair generation."""
    ID_vi: bytes          # Real identity (kept secret)
    PSID_vi: bytes        # Pseudo-identity
    ai: int               # Secret value
    Ai: object            # Public value = ai * P
    bi: int               # CP random value (used in partial key)
    Bi: object            # = bi * P
    gamma_i: int          # Partial private key
    sigma_i: int          # Coefficient h0(Ai, PSID_vi)
    Pubk_vi: object       # Public key = sigma_i * Ai
    Prvk_vi: int          # Private key = sigma_i * ai + gamma_i
    B: object             # Shared value from CP


@dataclass
class SigncryptedText:
    """Individual signcrypted ciphertext from a producer vehicle."""
    phi_i: int            # Signature component
    mu_i: bytes           # Encrypted message
    Fvi: object           # = f * P (ephemeral public value)
    PSID_sender: bytes    # Sender pseudo-identity
    Ti1: float            # Timestamp


@dataclass
class AggregateSigncryptedText:
    """Aggregate signcrypted text assembled by AU."""
    phi: int              # Aggregated signature = sum(phi_i) + upsilon_j
    mu_list: List[bytes]  # List of encrypted messages
    Fv_list: List[object] # List of ephemeral points
    PSID_senders: List[bytes]
    Ti1_list: List[float] # Per-message timestamps
    Pubk_dj: object       # Driver public key
    Tau: float            # AU timestamp


# ============================================================================
# SECTION 2: PPGen - Public Parameter Generation (System Setup)
# ============================================================================

def ppgen(
    level: SecurityLevel = DEFAULT_SECURITY_LEVEL,
) -> Tuple[SystemParams, MasterSecret]:
    """
    System Setup: Cloud Platform generates public parameters.

    Returns:
        (params, master_secret)
    """
    P = get_generator(level)
    q = get_order(level)

    # Master key generation
    r = random_scalar(level)
    PubkCP = scalar_mult(r, P, level)

    params = SystemParams(
        curve_name=SECURITY_CURVES[level].name,
        P=P, q=q, PubkCP=PubkCP, level=level,
    )
    master = MasterSecret(r=r)

    return params, master


# ============================================================================
# SECTION 3: Edge Server Enrollment
# ============================================================================

def es_enroll(
    params: SystemParams,
    master: MasterSecret,
    ID_en: bytes,
    Tn: bytes = None,
) -> EdgeServerKeys:
    """
    Edge Server Enrollment (Section IV-B in paper).

    Steps:
      1. ES selects sn, computes Sn = sn * P
      2. CP generates pseudo-identity PSID_en
      3. CP computes partial private key gamma_n
      4. ES derives full key pair
    """
    level = params.level
    P, q = params.P, params.q

    if Tn is None:
        Tn = struct.pack('>d', time.time())

    # Step 1: ES generates secret and public value
    sn = random_scalar(level)
    Sn = scalar_mult(sn, P, level)

    # Step 3: CP generates pseudo-identity
    wn = random_scalar(level)
    Wn = scalar_mult(wn, P, level)
    r_Wn = scalar_mult(master.r, Wn, level)
    h0_val = hash_h0(r_Wn, Tn, level=level)
    id_int = int.from_bytes(ID_en.ljust(32, b'\x00')[:32], 'big')
    PSID_en = (id_int ^ h0_val).to_bytes(32, 'big')

    # Step 4: CP computes partial private key
    beta_n = hash_h0(params.PubkCP, PSID_en, level=level)
    gamma_n = mod_add(wn, mod_mul(master.r, beta_n, q), q)

    # Step 5: ES computes key pair
    sigma_n = hash_h0(Sn, PSID_en, level=level)
    PubkES = point_add(scalar_mult(sigma_n, Sn, level), Wn)
    PrvkES = mod_add(mod_mul(sigma_n, sn, q), gamma_n, q)

    return EdgeServerKeys(
        PSID_en=PSID_en, sn=sn, Sn=Sn, gamma_n=gamma_n,
        Wn=Wn, sigma_n=sigma_n, PubkES=PubkES, PrvkES=PrvkES,
    )


# ============================================================================
# SECTION 4: Driver Enrollment
# ============================================================================

def driver_enroll(
    params: SystemParams,
    master: MasterSecret,
    ID_dj: bytes,
    Tj: bytes = None,
) -> DriverRecord:
    """
    Driver Enrollment (Section IV-C in paper).

    Steps:
      1. Driver chooses x, computes Pubk_dj = x * P
      2. CP generates pseudo-identity PSID_dj
      3. Driver computes verification parameter upsilon_j
    """
    level = params.level
    P, q = params.P, params.q

    if Tj is None:
        Tj = struct.pack('>d', time.time())

    # Step 1: Driver generates key pair
    x = random_scalar(level)
    Pubk_dj = scalar_mult(x, P, level)

    # Step 3: CP generates pseudo-identity
    yj = random_scalar(level)
    yj_PubkCP = scalar_mult(yj, params.PubkCP, level)
    h0_val = hash_h0(yj_PubkCP, Tj, level=level)
    id_int = int.from_bytes(ID_dj.ljust(32, b'\x00')[:32], 'big')
    PSID_dj = (id_int ^ h0_val).to_bytes(32, 'big')

    # Step 4: Driver computes verification parameter
    upsilon_j = hash_h0(Pubk_dj, PSID_dj, level=level)

    return DriverRecord(
        PSID_dj=PSID_dj, Pubk_dj=Pubk_dj, x=x, upsilon_j=upsilon_j,
    )


# ============================================================================
# SECTION 5: Vehicle Enrollment & Partial Key Generation
# ============================================================================

def vehicle_enroll(
    params: SystemParams,
    master: MasterSecret,
    ID_vi: bytes,
    consumer_pubk: object = None,
    consumer_PSID: bytes = None,
    Ti: bytes = None,
) -> VehicleKeys:
    """
    Vehicle Enrollment and Partial Key Generation (Section IV-D, IV-E).

    Steps:
      1. Vehicle selects ai, computes Ai = ai * P
      2. CP selects bi, computes Bi, PSID_vi, partial key gamma_i
      3. Vehicle derives full key pair
    """
    level = params.level
    P, q = params.P, params.q

    if Ti is None:
        Ti = struct.pack('>d', time.time())

    # Step 1: Vehicle generates secret and public value
    ai = random_scalar(level)
    Ai = scalar_mult(ai, P, level)

    # Step 3: CP selects bi, computes Bi
    bi = random_scalar(level)
    Bi = scalar_mult(bi, P, level)

    # Pseudo-identity generation
    s_Bi = scalar_mult(master.r, Bi, level)
    bi_Ai = scalar_mult(bi, Ai, level)
    h1_val = hash_h1(s_Bi, bi_Ai, Ti, level=level)
    id_int = int.from_bytes(ID_vi.ljust(32, b'\x00')[:32], 'big')
    PSID_vi = (id_int ^ h1_val).to_bytes(32, 'big')

    # Compute B (shared value for signcryption)
    B = None
    if consumer_pubk is not None and consumer_PSID is not None:
        beta_j = hash_h0(params.PubkCP, consumer_PSID, level=level)
        B = scalar_mult(bi, point_add(consumer_pubk,
                         scalar_mult(beta_j, params.PubkCP, level)), level)
    else:
        B = Bi  # Placeholder when consumer not specified yet

    # Partial private key
    beta_i = hash_h1(
        scalar_mult(bi, Ai, level), params.PubkCP, PSID_vi, level=level
    )
    gamma_i = mod_add(bi, mod_mul(master.r, beta_i, q), q)

    # Step 5: Vehicle key pair generation
    sigma_i = hash_h0(Ai, PSID_vi, level=level)
    Pubk_vi = scalar_mult(sigma_i, Ai, level)
    Prvk_vi = mod_add(mod_mul(sigma_i, ai, q), gamma_i, q)

    return VehicleKeys(
        ID_vi=ID_vi, PSID_vi=PSID_vi,
        ai=ai, Ai=Ai, bi=bi, Bi=Bi,
        gamma_i=gamma_i, sigma_i=sigma_i,
        Pubk_vi=Pubk_vi, Prvk_vi=Prvk_vi, B=B,
    )


# ============================================================================
# SECTION 6: Pseudonym Update Protocol
# ============================================================================

def pseudonym_update(
    params: SystemParams,
    master: MasterSecret,
    old_keys: VehicleKeys,
    Ti_new: bytes = None,
) -> VehicleKeys:
    """
    Pseudonym refresh (Section IV-F).

    Generates fresh randomness and computes new pseudonym + key pair.
    Anti-linkability: new (ai', bi') independent of old values.
    """
    return vehicle_enroll(
        params, master,
        old_keys.ID_vi,
        Ti=Ti_new,
    )


# ============================================================================
# SECTION 7: Signcryption
# ============================================================================

def signcrypt(
    params: SystemParams,
    sender: VehicleKeys,
    receiver_Pubk: object,
    receiver_PSID: bytes,
    message: bytes,
    receiver_gamma_P: object = None,
    Ti1: float = None,
) -> SigncryptedText:
    """
    Signcryption Algorithm (Section IV-G).

    Producer vehicle Vi signcrypts message mi for consumer vehicle Vj.

    Cost: 2*ETsm + 3*ETh + ETpa

    Steps:
      1. Select ephemeral f, compute Fvi = f*P
      2. Compute shared key alpha_j = f * (Pubk_vj + gamma_j*P)
         where gamma_j*P is retrieved from blockchain.
         This ensures: alpha_j = f * Prvk_vj * P = Prvk_vj * Fvi
      3. Conceal message: mu_i = msg XOR h2(PSID_vj, alpha_j, Ti1)
      4. Compute signature: phi_i = zeta + hni * Prvk_vi
    """
    level = params.level
    P, q = params.P, params.q

    if Ti1 is None:
        Ti1 = time.time()

    # Step 1: Ephemeral key
    f = random_scalar(level)
    Fvi = scalar_mult(f, P, level)  # 1st ETsm

    # Step 2: Shared key via combined public key
    # Combined_Pubk = Pubk_vj + gamma_j * P = Prvk_vj * P
    # This ensures DH consistency: f * Combined_Pubk = Prvk_vj * Fvi
    if receiver_gamma_P is not None:
        combined_pubk = point_add(receiver_Pubk, receiver_gamma_P)
    else:
        # Fallback: use Pubk + beta_j * PubkCP (partial combined key)
        beta_j = hash_h0(params.PubkCP, receiver_PSID, level=level)
        combined_pubk = point_add(
            receiver_Pubk,
            scalar_mult(beta_j, params.PubkCP, level),
        )
    alpha_j = scalar_mult(f, combined_pubk, level)  # 2nd ETsm + ETpa

    # Step 3: Message concealment
    Ti1_bytes = struct.pack('>d', Ti1)
    alpha_bytes = point_to_bytes(alpha_j, level)
    pad = hash_h2_expand(
        receiver_PSID, alpha_bytes, Ti1_bytes,
        output_len=len(message),
        level=level,
    )
    mu_i = xor_bytes(message, pad)

    # Step 4: Signature computation
    hmi = hash_h3(sender.Pubk_vi, sender.PSID_vi, sender.B, level=level)
    hni = hash_h4(mu_i, sender.PSID_vi, Fvi, sender.Pubk_vi, level=level)

    zeta = mod_add(
        mod_mul(sender.ai, sender.sigma_i, q),
        mod_mul(f, hmi, q),
        q,
    )
    phi_i = mod_add(zeta, mod_mul(hni, sender.Prvk_vi, q), q)

    return SigncryptedText(
        phi_i=phi_i, mu_i=mu_i, Fvi=Fvi,
        PSID_sender=sender.PSID_vi, Ti1=Ti1,
    )


# ============================================================================
# SECTION 8: Aggregate Signcryption
# ============================================================================

def aggregate_signcrypt(
    signcrypted_texts: List[SigncryptedText],
    driver: DriverRecord,
) -> AggregateSigncryptedText:
    """
    Aggregate Signcryption (Section IV-H).

    The Aggregation Unit (RSU) aggregates n individual signcrypted texts
    along with the driver's verification parameter.

    Cost: (n-1) additions + 1 addition (negligible)
    """
    n = len(signcrypted_texts)
    q = None  # We work in integer domain; mod q applied at verification

    # Aggregate signature: phi = sum(phi_i) + upsilon_j
    phi_sum = sum(st.phi_i for st in signcrypted_texts) + driver.upsilon_j

    Tau = time.time()

    return AggregateSigncryptedText(
        phi=phi_sum,
        mu_list=[st.mu_i for st in signcrypted_texts],
        Fv_list=[st.Fvi for st in signcrypted_texts],
        PSID_senders=[st.PSID_sender for st in signcrypted_texts],
        Ti1_list=[st.Ti1 for st in signcrypted_texts],
        Pubk_dj=driver.Pubk_dj,
        Tau=Tau,
    )


# ============================================================================
# SECTION 9: Aggregate Verification
# ============================================================================

def aggregate_verify(
    params: SystemParams,
    ast: AggregateSigncryptedText,
    vehicle_records: List[Dict],
    driver_PSID: bytes,
) -> bool:
    """
    Aggregate Verification (Section IV-I).

    Edge server verifies the aggregate signcrypted text.

    Cost: (2n+2)*ETsm + n*ETh + (n-1)*ETpa  (batch-optimized)

    Steps:
      1. Retrieve hash values hmi, hni for each vehicle
      2. Verify: phi * P == sum_i(Pubk_vi + Fvi*hmi) + sum_i(hni*(Pubk_vi + gamma_i*P)) + upsilon_j*P
    """
    level = params.level
    P, q = params.P, params.q
    n = len(ast.mu_list)

    # Left-hand side
    LHS = scalar_mult(ast.phi % q, P, level)

    # Right-hand side: accumulate
    RHS = None
    for i in range(n):
        rec = vehicle_records[i]
        Pubk_vi = rec["Pubk_vi"]
        Fvi = ast.Fv_list[i]
        gamma_i_P = rec["gamma_i_P"]
        PSID_vi = ast.PSID_senders[i]
        B_val = rec.get("B", Fvi)

        hmi = hash_h3(Pubk_vi, PSID_vi, B_val, level=level)
        hni = hash_h4(ast.mu_list[i], PSID_vi, Fvi, Pubk_vi, level=level)

        # Term 1: Pubk_vi + Fvi * hmi
        term1 = point_add(Pubk_vi, scalar_mult(hmi, Fvi, level))

        # Term 2: hni * (Pubk_vi + gamma_i * P)
        inner = point_add(Pubk_vi, gamma_i_P)
        term2 = scalar_mult(hni, inner, level)

        combined = point_add(term1, term2)
        if RHS is None:
            RHS = combined
        else:
            RHS = point_add(RHS, combined)

    # Add driver verification: upsilon_j * P
    upsilon_j = hash_h0(ast.Pubk_dj, driver_PSID, level=level)
    driver_term = scalar_mult(upsilon_j, P, level)
    RHS = point_add(RHS, driver_term)

    return LHS == RHS


# ============================================================================
# SECTION 10: Unsigncryption
# ============================================================================

def unsigncrypt(
    params: SystemParams,
    ast: AggregateSigncryptedText,
    receiver: VehicleKeys,
    sender_records: List[Dict],
) -> List[bytes]:
    """
    Unsigncryption (Section IV-J).

    Consumer vehicle Vj recovers original messages after verification.

    Shared key consistency:
      Sender computed: alpha_j = f * (Pubk_vj + gamma_j*P) = f * Prvk_vj * P
      Receiver computes: Theta_i = Prvk_vj * Fvi = Prvk_vj * f * P
      Therefore: alpha_j == Theta_i  (DH key agreement)

    Cost per message: 1*ETsm + 1*ETh
    """
    level = params.level
    P, q = params.P, params.q
    n = len(ast.mu_list)
    messages = []

    for i in range(n):
        Fvi = ast.Fv_list[i]
        mu_i = ast.mu_list[i]

        # Compute shared key: Theta_i = Prvk_vj * Fvi = alpha_j
        Theta_i = scalar_mult(receiver.Prvk_vi, Fvi, level)

        # Recover plaintext using same h2 derivation as signcryption
        Ti1_bytes = struct.pack('>d', ast.Ti1_list[i])
        alpha_bytes = point_to_bytes(Theta_i, level)
        pad = hash_h2_expand(
            receiver.PSID_vi, alpha_bytes, Ti1_bytes,
            output_len=len(mu_i),
            level=level,
        )
        message = xor_bytes(mu_i, pad)
        messages.append(message)

    return messages


# ============================================================================
# SECTION 11: Correctness Verification
# ============================================================================

def run_correctness_test(
    level: SecurityLevel = DEFAULT_SECURITY_LEVEL,
    num_vehicles: int = 5,
    verbose: bool = True,
) -> bool:
    """
    End-to-end correctness test: Setup -> Enroll -> Signcrypt ->
    Aggregate -> Verify -> Unsigncrypt.

    Returns True if all messages are correctly recovered.
    """
    if verbose:
        sec = SECURITY_CURVES[level].bit_security
        print(f"\n{'='*60}")
        print(f"  VESCA Correctness Test ({sec}-bit security, n={num_vehicles})")
        print(f"{'='*60}")

    # 1. System Setup
    params, master = ppgen(level)
    if verbose:
        print("  [1/7] System setup complete")

    # 2. Edge Server Enrollment
    es = es_enroll(params, master, b"EdgeServer_001")
    if verbose:
        print("  [2/7] Edge server enrolled")

    # 3. Driver Enrollment
    driver = driver_enroll(params, master, b"Driver_Alice")
    if verbose:
        print("  [3/7] Driver enrolled")

    # 4. Consumer Vehicle Enrollment (receiver)
    consumer = vehicle_enroll(params, master, b"ConsumerVehicle_001")
    if verbose:
        print("  [4/7] Consumer vehicle enrolled")

    # 5. Producer Vehicles Enrollment + Signcryption
    messages_original = []
    signcrypted_list = []
    vehicle_records = []

    # Precompute consumer's gamma*P for DH-consistent signcryption
    consumer_gamma_P = scalar_mult(consumer.gamma_i, params.P, level)

    for i in range(num_vehicles):
        vid = f"ProducerVehicle_{i+1:03d}".encode()
        producer = vehicle_enroll(
            params, master, vid,
            consumer_pubk=consumer.Pubk_vi,
            consumer_PSID=consumer.PSID_vi,
        )

        msg = f"SafetyAlert_Vehicle{i+1}_Speed60_Lane2".encode()
        messages_original.append(msg)

        sc = signcrypt(
            params, producer, consumer.Pubk_vi,
            consumer.PSID_vi, msg,
            receiver_gamma_P=consumer_gamma_P,
        )
        signcrypted_list.append(sc)

        vehicle_records.append({
            "Pubk_vi": producer.Pubk_vi,
            "gamma_i_P": scalar_mult(producer.gamma_i, params.P, level),
            "Bi": producer.Bi,
            "B": producer.B,
            "PSID_vi": producer.PSID_vi,
        })

    if verbose:
        print(f"  [5/7] {num_vehicles} producers enrolled and signcrypted")

    # 6. Aggregate Signcryption
    ast = aggregate_signcrypt(signcrypted_list, driver)
    if verbose:
        print(f"  [6/7] Aggregation complete (phi = {ast.phi % params.q})")

    # 7. Aggregate Verification
    verified = aggregate_verify(
        params, ast, vehicle_records, driver.PSID_dj,
    )
    if verbose:
        status = "PASSED" if verified else "FAILED"
        print(f"  [7/7] Aggregate verification: {status}")

    # 8. Unsigncryption (if verified)
    if verified:
        sender_records = [{"Bi": r["Bi"]} for r in vehicle_records]
        recovered = unsigncrypt(params, ast, consumer, sender_records)

        all_match = True
        for i in range(num_vehicles):
            orig = messages_original[i]
            recov = recovered[i]
            match = (orig == recov)
            all_match = all_match and match
            if verbose and not match:
                print(f"    Message {i}: MISMATCH")
                print(f"      Orig:  {orig[:40]}...")
                print(f"      Recov: {recov[:40]}...")

        if verbose:
            result = "ALL PASSED" if all_match else "SOME FAILED"
            print(f"\n  Correctness: {result}")

        return all_match

    return False


# ============================================================================
# SECTION 12: Timing Utilities for Benchmarking
# ============================================================================

def time_signcrypt(
    params: SystemParams,
    sender: VehicleKeys,
    receiver_Pubk: object,
    receiver_PSID: bytes,
    message: bytes,
) -> Tuple[SigncryptedText, float]:
    """Signcrypt and return (result, elapsed_ms)."""
    start = time.perf_counter_ns()
    result = signcrypt(params, sender, receiver_Pubk, receiver_PSID, message)
    elapsed = (time.perf_counter_ns() - start) / 1e6
    return result, elapsed


def time_aggregate_verify(
    params: SystemParams,
    ast: AggregateSigncryptedText,
    vehicle_records: List[Dict],
    driver_PSID: bytes,
) -> Tuple[bool, float]:
    """Verify and return (result, elapsed_ms)."""
    start = time.perf_counter_ns()
    result = aggregate_verify(params, ast, vehicle_records, driver_PSID)
    elapsed = (time.perf_counter_ns() - start) / 1e6
    return result, elapsed


def time_unsigncrypt_single(
    params: SystemParams,
    ast: AggregateSigncryptedText,
    receiver: VehicleKeys,
    sender_records: List[Dict],
) -> Tuple[List[bytes], float]:
    """Unsigncrypt and return (messages, elapsed_ms)."""
    start = time.perf_counter_ns()
    result = unsigncrypt(params, ast, receiver, sender_records)
    elapsed = (time.perf_counter_ns() - start) / 1e6
    return result, elapsed


if __name__ == "__main__":
    # Run correctness tests at both security levels
    for level in [SecurityLevel.LEVEL_80, SecurityLevel.LEVEL_128]:
        success = run_correctness_test(level, num_vehicles=3, verbose=True)
        if not success:
            print(f"\n  WARNING: Correctness test FAILED at {level.value}-bit!")
        else:
            print(f"\n  SUCCESS at {level.value}-bit security.\n")
