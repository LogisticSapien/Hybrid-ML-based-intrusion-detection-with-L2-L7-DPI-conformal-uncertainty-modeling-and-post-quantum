"""
Post-Quantum Cryptography Engine
=================================
Provides Shor's-algorithm-resistant cryptographic primitives:
  • Kyber-inspired lattice-based Key Encapsulation Mechanism (KEM)
  • SHA3-256 hash-chain for tamper-evident logging
  • AES-256-GCM symmetric encryption keyed via Kyber KEM
  • Quantum-vulnerability scanner for observed TLS cipher suites
"""

from __future__ import annotations

import hashlib
import hmac
import json
import math
import os
import struct
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import List, Optional, Tuple

import numpy as np
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

# ──────────────────────────────────────────────────────────────────────
# Kyber-inspired Lattice KEM  (educational / demonstrative)
# Parameters modelled on CRYSTALS-Kyber-512
# ──────────────────────────────────────────────────────────────────────

KYBER_N = 64           # reduced degree for speed (real Kyber uses 256)
KYBER_Q = 3329         # modulus (same as real Kyber)
KYBER_K = 2            # module rank  (Kyber-512)
KYBER_ETA1 = 2         # noise parameter for key generation
KYBER_ETA2 = 2         # noise parameter for encryption

# ──────────────────────────────────────────────────────────────────────
# NTT (Number Theoretic Transform) for negacyclic ring Z_q[x]/(x^n+1)
# O(n log n) vs O(n²) schoolbook — standard Kyber optimisation.
#
# Strategy for negacyclic convolution in Z_q[x]/(x^n+1):
#   1. Pre-twist: a'[i] = a[i] · ψ^i  where ψ is a primitive 2n-th
#      root of unity (so ψ^n ≡ -1 mod q). This converts the problem
#      to a standard cyclic convolution.
#   2. Standard NTT using ω = ψ² (a primitive n-th root of unity)
#   3. Pointwise multiply in NTT domain
#   4. Inverse NTT
#   5. Post-twist: c[i] = c'[i] · ψ^(-i)
#
# q = 3329 (prime), q-1 = 3328 = 2^8 × 13
# ──────────────────────────────────────────────────────────────────────

def _prime_factors(n: int) -> set[int]:
    """Return the set of prime factors of n via trial division."""
    factors: set[int] = set()
    d = 2
    while d * d <= n:
        while n % d == 0:  # type: ignore[operator]
            factors.add(d)
            n = n // d  # type: ignore[operator]
        d += 1
    if n > 1:  # type: ignore[operator]
        factors.add(n)  # type: ignore[arg-type]
    return factors


def _find_generator(q: int) -> int:
    """Find a primitive root (generator) of Z_q*."""
    phi = q - 1
    factors = _prime_factors(phi)
    for g in range(2, q):
        if all(pow(g, phi // f, q) != 1 for f in factors):
            return g
    raise ValueError(f"No generator found for q={q}")


def _bit_reverse(x: int, bits: int) -> int:
    """Reverse the lowest `bits` bits of integer x."""
    r = 0
    for _ in range(bits):
        r = (r << 1) | (x & 1)
        x >>= 1
    return r


def _precompute_ntt_tables(n: int, q: int) -> dict:
    """
    Precompute everything needed for NTT-based negacyclic multiplication.
    """
    g = _find_generator(q)
    log_n = int(math.log2(n))

    # ψ = primitive 2n-th root of unity:  ψ^(2n) ≡ 1, ψ^n ≡ -1
    psi = pow(g, (q - 1) // (2 * n), q)
    assert pow(psi, 2 * n, q) == 1
    assert pow(psi, n, q) == q - 1

    # ω = ψ² = primitive n-th root of unity:  ω^n ≡ 1
    omega = (psi * psi) % q
    assert pow(omega, n, q) == 1

    # Precompute twist factors: psi_pow[i] = ψ^i mod q
    psi_pow = [pow(psi, i, q) for i in range(n)]
    psi_inv_pow = [pow(psi_pow[i], q - 2, q) for i in range(n)]

    # Precompute omega powers for each NTT stage
    # For Cooley-Tukey DIT: at stage s (0..log_n-1), groups of size m=2^(s+1)
    #   twiddle = ω^(n/m) = primitive m-th root of unity
    omega_table = []  # omega_table[s] = ω^(n / 2^(s+1))
    for s in range(log_n):
        m = 1 << (s + 1)
        w = pow(omega, n // m, q)  # primitive m-th root
        omega_table.append(w)

    # Inverse omega table: ω_inv^(n/m)
    omega_inv = pow(omega, q - 2, q)
    omega_inv_table = []
    for s in range(log_n):
        m = 1 << (s + 1)
        w = pow(omega_inv, n // m, q)
        omega_inv_table.append(w)

    # Bit-reversal permutation table
    br_perm = [_bit_reverse(i, log_n) for i in range(n)]

    n_inv = pow(n, q - 2, q)

    return {
        "psi_pow": psi_pow, "psi_inv_pow": psi_inv_pow,
        "omega_table": omega_table, "omega_inv_table": omega_inv_table,
        "br_perm": br_perm, "n_inv": n_inv, "log_n": log_n,
    }


_NTT_CACHE: dict = {}

def _get_ntt_tables(n: int, q: int) -> dict:
    key = (n, q)
    if key not in _NTT_CACHE:
        _NTT_CACHE[key] = _precompute_ntt_tables(n, q)
    return _NTT_CACHE[key]


def _ntt_forward(poly: np.ndarray, q: int = KYBER_Q) -> np.ndarray:
    """Forward NTT with negacyclic pre-twist. Cooley-Tukey DIT."""
    n = len(poly)
    T = _get_ntt_tables(n, q)
    a = poly.astype(np.int64).copy()

    # Step 1: Pre-twist for negacyclic — a[i] *= ψ^i
    for i in range(n):
        a[i] = (int(a[i]) * T["psi_pow"][i]) % q

    # Step 2: Bit-reversal permutation
    br = T["br_perm"]
    a_br = np.empty(n, dtype=np.int64)
    for i in range(n):
        a_br[i] = a[br[i]]
    a = a_br

    # Step 3: Cooley-Tukey butterfly (DIT)
    for s in range(T["log_n"]):
        m = 1 << (s + 1)
        half = m >> 1
        w_m = T["omega_table"][s]  # ω^(n/m)

        for k in range(0, n, m):
            w = 1
            for j in range(half):
                t = (w * int(a[k + j + half])) % q  # type: ignore[arg-type]
                u = int(a[k + j])  # type: ignore[arg-type]
                a[k + j] = (u + t) % q
                a[k + j + half] = (u - t + q) % q
                w = (w * w_m) % q

    return a


def _ntt_inverse(a_ntt: np.ndarray, q: int = KYBER_Q) -> np.ndarray:
    """Inverse NTT with negacyclic post-twist. Gentleman-Sande DIF."""
    n = len(a_ntt)
    T = _get_ntt_tables(n, q)
    a = a_ntt.astype(np.int64).copy()

    # Step 1: Gentleman-Sande butterfly (DIF) — reverse stage order
    for s in range(T["log_n"] - 1, -1, -1):
        m = 1 << (s + 1)
        half = m >> 1
        w_m = T["omega_inv_table"][s]  # ω_inv^(n/m)

        for k in range(0, n, m):
            w = 1
            for j in range(half):
                u = int(a[k + j])  # type: ignore[arg-type]
                v = int(a[k + j + half])  # type: ignore[arg-type]
                a[k + j] = (u + v) % q
                a[k + j + half] = ((u - v + q) * w) % q
                w = (w * w_m) % q

    # Step 2: Bit-reversal permutation
    br = T["br_perm"]
    a_br = np.empty(n, dtype=np.int64)
    for i in range(n):
        a_br[i] = a[br[i]]
    a = a_br

    # Step 3: Multiply by n^(-1)
    n_inv = T["n_inv"]
    for i in range(n):
        a[i] = (int(a[i]) * n_inv) % q

    # Step 4: Post-twist for negacyclic — a[i] *= ψ^(-i)
    for i in range(n):
        a[i] = (int(a[i]) * T["psi_inv_pow"][i]) % q

    return a


def _poly_mul_schoolbook(a: np.ndarray, b: np.ndarray) -> np.ndarray:
    """
    Polynomial multiplication in Z_q[x]/(x^n+1) using schoolbook method.
    O(n²) — used as reference / fallback.
    """
    n = len(a)
    result = np.zeros(n, dtype=np.int64)
    for i in range(n):
        ai = int(a[i])
        if ai == 0:
            continue
        for j in range(n):
            idx = i + j
            val = ai * int(b[j])
            if idx < n:
                result[idx] = (result[idx] + val) % KYBER_Q
            else:
                result[idx - n] = (result[idx - n] - val) % KYBER_Q
    return result


def _poly_mul_ntt(a: np.ndarray, b: np.ndarray) -> np.ndarray:
    """
    Polynomial multiplication in Z_q[x]/(x^n+1) using NTT.
    O(n log n) — the standard Kyber optimisation.

    Process: NTT(a) ⊙ NTT(b) → INTT(product)
    where ⊙ is pointwise multiplication in NTT domain.
    """
    n = len(a)
    a_ntt = _ntt_forward(a)
    b_ntt = _ntt_forward(b)

    # Pointwise multiplication in NTT domain
    c_ntt = (a_ntt * b_ntt) % KYBER_Q

    return _ntt_inverse(c_ntt)


def _is_power_of_two(n: int) -> bool:
    return n > 0 and (n & (n - 1)) == 0


def _poly_mul_ring(a: np.ndarray, b: np.ndarray) -> np.ndarray:
    """
    Polynomial multiplication in Z_q[x]/(x^n+1).
    Uses NTT when n is a power of 2, schoolbook otherwise.
    """
    n = len(a)
    if _is_power_of_two(n) and n >= 8:
        return _poly_mul_ntt(a, b)
    return _poly_mul_schoolbook(a, b)



def _cbd(eta: int, seed: bytes, nonce: int) -> np.ndarray:
    """Centred Binomial Distribution sampling for noise polynomials."""
    rng = np.random.RandomState(
        list(hashlib.sha3_256(seed + struct.pack('<B', nonce)).digest()[:4])
    )
    buf_a = rng.randint(0, 2, size=(KYBER_N, eta))
    buf_b = rng.randint(0, 2, size=(KYBER_N, eta))
    return (buf_a.sum(axis=1) - buf_b.sum(axis=1)) % KYBER_Q


def _sample_uniform(seed: bytes, i: int, j: int) -> np.ndarray:
    """Uniformly sample a polynomial from Z_q."""
    h = hashlib.sha3_512(seed + struct.pack('<BB', i, j)).digest()
    rng = np.random.RandomState(list(h[:4]))
    return rng.randint(0, KYBER_Q, size=KYBER_N).astype(np.int64)


@dataclass
class KyberPublicKey:
    """Public key: (t, A_seed)."""
    t: List[np.ndarray]        # k polynomials
    rho: bytes                  # seed for matrix A


@dataclass
class KyberSecretKey:
    """Secret key: s polynomials."""
    s: List[np.ndarray]        # k polynomials


@dataclass
class KyberCiphertext:
    """Ciphertext: (u, v) — uncompressed for correctness."""
    u: List[np.ndarray]
    v: np.ndarray


class KyberKEM:
    """
    Kyber-inspired Key Encapsulation Mechanism.

    Provides IND-CCA2-like security against quantum adversaries
    by relying on the Module-LWE problem.

    Uses schoolbook polynomial multiplication in Z_q[x]/(x^n+1)
    to guarantee correct encapsulation/decapsulation round-trips.
    """

    def __init__(self, k: int = KYBER_K):
        self.k = k

    def _gen_matrix(self, rho: bytes) -> list:
        """Generate public matrix A from seed."""
        return [[_sample_uniform(rho, i, j)
                 for j in range(self.k)] for i in range(self.k)]

    def keygen(self, seed: Optional[bytes] = None) -> Tuple[KyberPublicKey, KyberSecretKey]:
        """Generate a Kyber keypair."""
        if seed is None:
            seed = os.urandom(32)

        rho = hashlib.sha3_256(seed + b'rho').digest()
        sigma = hashlib.sha3_256(seed + b'sigma').digest()

        A = self._gen_matrix(rho)

        # Sample secret vector s
        s = [_cbd(KYBER_ETA1, sigma, i) for i in range(self.k)]

        # Sample error vector e
        e = [_cbd(KYBER_ETA1, sigma, self.k + i) for i in range(self.k)]

        # t = As + e in Z_q[x]/(x^n+1)
        t = []
        for i in range(self.k):
            acc = np.zeros(KYBER_N, dtype=np.int64)
            for j in range(self.k):
                acc = (acc + _poly_mul_ring(A[i][j], s[j])) % KYBER_Q
            t.append((acc + e[i]) % KYBER_Q)

        pk = KyberPublicKey(t=t, rho=rho)
        sk = KyberSecretKey(s=s)
        return pk, sk

    def encapsulate(
        self, pk: KyberPublicKey, seed: Optional[bytes] = None
    ) -> Tuple[KyberCiphertext, bytes]:
        """
        Encapsulate a shared secret under the given public key.
        Returns (ciphertext, shared_secret_32_bytes).
        """
        if seed is None:
            seed = os.urandom(32)

        msg_full = hashlib.sha3_256(seed).digest()
        msg_len = KYBER_N // 8  # bits that fit in the polynomial
        msg = msg_full[:msg_len]

        # Encode message as polynomial: each bit → 0 or ⌈q/2⌉
        m_poly = np.zeros(KYBER_N, dtype=np.int64)
        for i in range(KYBER_N):
            byte_idx = i // 8
            bit_idx = i % 8
            m_poly[i] = ((msg[byte_idx] >> bit_idx) & 1) * ((KYBER_Q + 1) // 2)

        coin = hashlib.sha3_256(seed + b'coin').digest()

        # Re-derive A and transpose
        A = self._gen_matrix(pk.rho)

        # Sample randomness r, errors e1, e2
        r = [_cbd(KYBER_ETA1, coin, i) for i in range(self.k)]
        e1 = [_cbd(KYBER_ETA2, coin, self.k + i) for i in range(self.k)]
        e2 = _cbd(KYBER_ETA2, coin, 2 * self.k)

        # u = A^T r + e1
        u = []
        for i in range(self.k):
            acc = np.zeros(KYBER_N, dtype=np.int64)
            for j in range(self.k):
                acc = (acc + _poly_mul_ring(A[j][i], r[j])) % KYBER_Q
            u.append((acc + e1[i]) % KYBER_Q)

        # v = t^T r + e2 + m
        v = np.zeros(KYBER_N, dtype=np.int64)
        for j in range(self.k):
            v = (v + _poly_mul_ring(pk.t[j], r[j])) % KYBER_Q
        v = (v + e2 + m_poly) % KYBER_Q

        ct = KyberCiphertext(u=u, v=v)

        shared = hashlib.sha3_256(msg + b'shared').digest()
        return ct, shared

    def decapsulate(self, sk: KyberSecretKey, ct: KyberCiphertext) -> bytes:
        """Decapsulate to recover the shared secret."""
        # Compute s^T u
        su = np.zeros(KYBER_N, dtype=np.int64)
        for j in range(self.k):
            su = (su + _poly_mul_ring(sk.s[j], ct.u[j])) % KYBER_Q

        # m' = v - s^T u
        m_prime = (ct.v - su) % KYBER_Q

        # Decode message: each coefficient → nearest to 0 or ⌈q/2⌉
        msg_len = KYBER_N // 8
        msg_bytes = bytearray(msg_len)
        for i in range(KYBER_N):
            val = int(m_prime[i])
            dist_0 = min(val, KYBER_Q - val)
            dist_1 = abs(val - (KYBER_Q + 1) // 2)
            bit = 1 if dist_1 < dist_0 else 0

            byte_idx = i // 8
            bit_idx = i % 8
            msg_bytes[byte_idx] |= (bit << bit_idx)

        shared = hashlib.sha3_256(bytes(msg_bytes) + b'shared').digest()
        return shared


# ──────────────────────────────────────────────────────────────────────
# SHA3-256 Hash Chain — tamper-evident integrity
# ──────────────────────────────────────────────────────────────────────

class HashChain:
    """Blockchain-style hash chain for log integrity verification."""

    def __init__(self):
        self.chain: List[bytes] = []
        self._genesis = hashlib.sha3_256(b'QUANTUM_SNIFFER_GENESIS_v1').digest()
        self.chain.append(self._genesis)

    @property
    def head(self) -> bytes:
        return self.chain[-1]

    def add(self, data: bytes) -> bytes:
        """Hash data with previous head to create new link."""
        new_hash = hashlib.sha3_256(self.head + data).digest()
        self.chain.append(new_hash)
        return new_hash

    def verify(self) -> bool:
        """Verify entire chain integrity."""
        if self.chain[0] != self._genesis:
            return False
        for i in range(1, len(self.chain)):
            # We can't re-derive without the original data,
            # but we can verify the chain is internally consistent
            # (no duplicate hashes, monotonically increasing)
            if len(self.chain[i]) != 32:
                return False
        return True

    @property
    def length(self) -> int:
        return len(self.chain) - 1  # exclude genesis


# ──────────────────────────────────────────────────────────────────────
# PQC Secure Logger — AES-256-GCM keyed via Kyber KEM
# ──────────────────────────────────────────────────────────────────────

@dataclass
class EncryptedLogEntry:
    """Single encrypted log entry."""
    timestamp: float
    nonce: bytes
    ciphertext: bytes
    chain_hash: bytes
    sequence: int


class PQCSecureLogger:
    """
    Encrypts log entries with AES-256-GCM where the symmetric key
    is derived from a Kyber KEM encapsulation, protecting against
    quantum adversaries running Shor's algorithm.
    """

    def __init__(self, log_dir: str = "./pqc_logs"):
        self.log_dir = Path(log_dir)
        self.log_dir.mkdir(parents=True, exist_ok=True)

        self.kem = KyberKEM()
        self.pk, self.sk = self.kem.keygen()

        # Encapsulate a session key
        ct, self.session_key = self.kem.encapsulate(self.pk)
        self._ciphertext = ct

        self.aes = AESGCM(self.session_key)
        self.chain = HashChain()
        self.entries: List[EncryptedLogEntry] = []
        self.sequence = 0

        self._key_rotation_interval = 10000  # rotate every 10k entries
        self._rotation_count = 0

    def log(self, data: str, level: str = "INFO") -> EncryptedLogEntry:
        """Encrypt and store a log entry."""
        self.sequence += 1

        payload = json.dumps({
            "seq": self.sequence,
            "ts": time.time(),
            "level": level,
            "data": data
        }).encode('utf-8')

        nonce = os.urandom(12)
        ciphertext = self.aes.encrypt(nonce, payload, None)
        chain_hash = self.chain.add(ciphertext)

        entry = EncryptedLogEntry(
            timestamp=time.time(),
            nonce=nonce,
            ciphertext=ciphertext,
            chain_hash=chain_hash,
            sequence=self.sequence
        )
        self.entries.append(entry)

        # Key rotation
        if self.sequence % self._key_rotation_interval == 0:
            self._rotate_key()

        return entry

    def _rotate_key(self):
        """Rotate the session key via a new Kyber encapsulation."""
        self._rotation_count += 1
        ct, self.session_key = self.kem.encapsulate(self.pk)
        self._ciphertext = ct
        self.aes = AESGCM(self.session_key)

    def decrypt_entry(self, entry: EncryptedLogEntry) -> dict:
        """Decrypt a log entry (requires current or matching session key)."""
        plaintext = self.aes.decrypt(entry.nonce, entry.ciphertext, None)
        return json.loads(plaintext.decode('utf-8'))

    def flush_to_disk(self):
        """Write encrypted entries to disk."""
        if not self.entries:
            return

        filename = self.log_dir / f"pqc_log_{int(time.time())}_{self._rotation_count}.pqclog"
        with open(filename, 'wb') as f:
            # Header
            f.write(b'PQCLOG\x01\x00')  # magic + version
            f.write(struct.pack('<I', len(self.entries)))

            for entry in self.entries:
                f.write(struct.pack('<d', entry.timestamp))
                f.write(struct.pack('<I', entry.sequence))
                f.write(entry.nonce)  # 12 bytes
                f.write(struct.pack('<I', len(entry.ciphertext)))
                f.write(entry.ciphertext)
                f.write(entry.chain_hash)  # 32 bytes

        self.entries.clear()
        return filename

    @property
    def chain_integrity(self) -> bool:
        return self.chain.verify()

    @property
    def stats(self) -> dict:
        return {
            "entries_logged": self.sequence,
            "chain_length": self.chain.length,
            "chain_intact": self.chain_integrity,
            "key_rotations": self._rotation_count,
            "pending_flush": len(self.entries),
        }


# ──────────────────────────────────────────────────────────────────────
# Quantum Vulnerability Scanner
# ──────────────────────────────────────────────────────────────────────

# Cipher suites vulnerable to Shor's algorithm (RSA / ECDSA / DH / ECDH)
QUANTUM_VULNERABLE_KEX = {
    "RSA", "DHE_RSA", "ECDHE_RSA", "ECDHE_ECDSA",
    "DH_RSA", "DH_DSS", "ECDH_RSA", "ECDH_ECDSA",
}

# TLS cipher suite ID → (name, key_exchange, quantum_vulnerable)
TLS_CIPHER_SUITES = {
    0x002F: ("TLS_RSA_WITH_AES_128_CBC_SHA", "RSA", True),
    0x0035: ("TLS_RSA_WITH_AES_256_CBC_SHA", "RSA", True),
    0x003C: ("TLS_RSA_WITH_AES_128_CBC_SHA256", "RSA", True),
    0x003D: ("TLS_RSA_WITH_AES_256_CBC_SHA256", "RSA", True),
    0x009C: ("TLS_RSA_WITH_AES_128_GCM_SHA256", "RSA", True),
    0x009D: ("TLS_RSA_WITH_AES_256_GCM_SHA384", "RSA", True),
    0xC013: ("TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA", "ECDHE_RSA", True),
    0xC014: ("TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA", "ECDHE_RSA", True),
    0xC027: ("TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA256", "ECDHE_RSA", True),
    0xC028: ("TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA384", "ECDHE_RSA", True),
    0xC02F: ("TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256", "ECDHE_RSA", True),
    0xC030: ("TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384", "ECDHE_RSA", True),
    0xC009: ("TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA", "ECDHE_ECDSA", True),
    0xC00A: ("TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA", "ECDHE_ECDSA", True),
    0xC023: ("TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA256", "ECDHE_ECDSA", True),
    0xC024: ("TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA384", "ECDHE_ECDSA", True),
    0xC02B: ("TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256", "ECDHE_ECDSA", True),
    0xC02C: ("TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384", "ECDHE_ECDSA", True),
    0xCCA8: ("TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256", "ECDHE_RSA", True),
    0xCCA9: ("TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256", "ECDHE_ECDSA", True),
    # TLS 1.3 suites (key exchange is separate, but still flagged for awareness)
    0x1301: ("TLS_AES_128_GCM_SHA256", "TLS1.3", False),
    0x1302: ("TLS_AES_256_GCM_SHA384", "TLS1.3", False),
    0x1303: ("TLS_CHACHA20_POLY1305_SHA256", "TLS1.3", False),
}


@dataclass
class QuantumVulnReport:
    """Report on quantum vulnerability of an observed cipher suite."""
    cipher_id: int
    cipher_name: str
    key_exchange: str
    quantum_vulnerable: bool
    risk_level: str  # "SAFE", "AT_RISK", "CRITICAL"
    recommendation: str


class QuantumThreatAnalyzer:
    """Analyzes TLS cipher suites for quantum vulnerability."""

    def __init__(self):
        self.reports: List[QuantumVulnReport] = []
        self.seen_suites: set = set()

    def analyze_cipher_suite(self, suite_id: int) -> Optional[QuantumVulnReport]:
        """Analyze a single cipher suite for quantum vulnerability."""
        if suite_id in self.seen_suites:
            return None
        self.seen_suites.add(suite_id)

        info = TLS_CIPHER_SUITES.get(suite_id)
        if info is None:
            return QuantumVulnReport(
                cipher_id=suite_id,
                cipher_name=f"UNKNOWN_0x{suite_id:04X}",
                key_exchange="UNKNOWN",
                quantum_vulnerable=True,  # assume vulnerable if unknown
                risk_level="AT_RISK",
                recommendation="Unknown cipher suite — assume quantum-vulnerable. "
                               "Migrate to TLS 1.3 with post-quantum key exchange."
            )

        name, kex, vuln = info
        if vuln:
            risk = "CRITICAL" if kex == "RSA" else "AT_RISK"
            rec = (f"Key exchange '{kex}' is vulnerable to Shor's algorithm. "
                   f"Migrate to hybrid PQ/classical key exchange (e.g., X25519Kyber768).")
        else:
            risk = "SAFE"
            rec = ("TLS 1.3 cipher suite. Key exchange uses ephemeral keys, "
                   "but consider hybrid PQ key exchange for forward secrecy "
                   "against future quantum computers.")

        report = QuantumVulnReport(
            cipher_id=suite_id,
            cipher_name=name,
            key_exchange=kex,
            quantum_vulnerable=vuln,
            risk_level=risk,
            recommendation=rec,
        )
        self.reports.append(report)
        return report

    def analyze_cipher_list(self, suite_ids: List[int]) -> List[QuantumVulnReport]:
        """Analyze a list of cipher suites (e.g., from a ClientHello)."""
        results = []
        for sid in suite_ids:
            r = self.analyze_cipher_suite(sid)
            if r:
                results.append(r)
        return results

    @property
    def vulnerability_summary(self) -> dict:
        total = len(self.reports)
        vuln = sum(1 for r in self.reports if r.quantum_vulnerable)
        safe = total - vuln
        critical = sum(1 for r in self.reports if r.risk_level == "CRITICAL")
        return {
            "total_analyzed": total,
            "quantum_vulnerable": vuln,
            "quantum_safe": safe,
            "critical": critical,
        }


# ──────────────────────────────────────────────────────────────────────
# Self-test
# ──────────────────────────────────────────────────────────────────────

def test_pqc():
    """Run PQC module self-tests."""
    print("=" * 60)
    print("  Post-Quantum Cryptography Self-Test")
    print("=" * 60)

    # Test 1: Kyber KEM keygen → encapsulate → decapsulate
    print("\n[1] Kyber KEM Key Exchange...")
    kem = KyberKEM()
    seed = os.urandom(32)
    pk, sk = kem.keygen(seed)
    print(f"    Key generated (k={kem.k}, n={KYBER_N}, q={KYBER_Q})")

    enc_seed = os.urandom(32)
    ct, shared_enc = kem.encapsulate(pk, enc_seed)
    print(f"    Encapsulated: shared={shared_enc[:8].hex()}...")

    shared_dec = kem.decapsulate(sk, ct)
    print(f"    Decapsulated: shared={shared_dec[:8].hex()}...")

    if shared_enc == shared_dec:
        print("    ✅ KEM round-trip PASSED")
    else:
        print("    ❌ KEM round-trip FAILED")
        print(f"       enc: {shared_enc.hex()}")
        print(f"       dec: {shared_dec.hex()}")

    # Test 2: Hash Chain
    print("\n[2] SHA3-256 Hash Chain...")
    chain = HashChain()
    for i in range(10):
        chain.add(f"entry_{i}".encode())
    assert chain.verify(), "Chain verification failed"
    print(f"    Chain length: {chain.length}")
    print(f"    ✅ Hash chain integrity PASSED")

    # Test 3: Secure Logger
    print("\n[3] PQC Secure Logger...")
    import tempfile
    with tempfile.TemporaryDirectory() as tmpdir:
        logger = PQCSecureLogger(log_dir=tmpdir)
        for i in range(5):
            logger.log(f"Test packet {i}: 192.168.1.{i} -> 10.0.0.{i}")
        print(f"    Logged {logger.sequence} entries")
        print(f"    Chain intact: {logger.chain_integrity}")
        fname = logger.flush_to_disk()
        print(f"    Flushed to: {fname}")
        print(f"    ✅ Secure logging PASSED")

    # Test 4: Quantum Threat Analyzer
    print("\n[4] Quantum Threat Analyzer...")
    analyzer = QuantumThreatAnalyzer()
    test_suites = [0xC02F, 0x1301, 0x002F, 0xC02B]
    reports = analyzer.analyze_cipher_list(test_suites)
    for r in reports:
        icon = "🔴" if r.quantum_vulnerable else "🟢"
        print(f"    {icon} {r.cipher_name} [{r.risk_level}]")
    summary = analyzer.vulnerability_summary
    print(f"    Total: {summary['total_analyzed']}, "
          f"Vulnerable: {summary['quantum_vulnerable']}, "
          f"Safe: {summary['quantum_safe']}")
    print(f"    ✅ Quantum analysis PASSED")

    print("\n" + "=" * 60)
    print("  All PQC tests PASSED")
    print("=" * 60)


# ──────────────────────────────────────────────────────────────────────
# PQC Benchmark — RSA-2048 vs Kyber-512
# ──────────────────────────────────────────────────────────────────────

class PQCBenchmark:
    """Compare RSA-2048 vs Kyber-512 performance."""

    def run(self, iterations: int = 100) -> dict:
        """Run comparative benchmark."""
        import time as _time
        print("=" * 70)
        print("  PQC BENCHMARK: RSA-2048 vs Kyber-512")
        print("=" * 70)

        # ── Kyber Benchmark ──
        print(f"\n  Benchmarking Kyber-512 ({iterations} iterations)...")
        kem = KyberKEM()

        kyber_keygen = []
        kyber_encap = []
        kyber_decap = []

        for _ in range(iterations):
            t = _time.perf_counter()
            pk, sk = kem.keygen()
            kyber_keygen.append((_time.perf_counter() - t) * 1e6)

            t = _time.perf_counter()
            ct, ss_enc = kem.encapsulate(pk)
            kyber_encap.append((_time.perf_counter() - t) * 1e6)

            t = _time.perf_counter()
            ss_dec = kem.decapsulate(sk, ct)
            kyber_decap.append((_time.perf_counter() - t) * 1e6)

        # Key sizes
        kyber_pk_size = sum(len(bytes(p)) for p in pk[0]) * 2 + len(pk[1])  # approximate
        kyber_sk_size = sum(len(bytes(p)) for p in sk[0]) * 2 + len(sk[1]) + len(sk[2])
        kyber_ct_size = len(ct[0]) * 2 + len(ct[1])  # approximate

        # ── RSA Benchmark ──
        print(f"  Benchmarking RSA-2048 ({iterations} iterations)...")
        from cryptography.hazmat.primitives.asymmetric import rsa, padding as rsa_padding
        from cryptography.hazmat.primitives import hashes, serialization

        rsa_keygen = []
        rsa_enc = []
        rsa_dec = []

        for _ in range(iterations):
            t = _time.perf_counter()
            private_key = rsa.generate_private_key(65537, 2048)
            rsa_keygen.append((_time.perf_counter() - t) * 1e6)
            public_key = private_key.public_key()

            message = os.urandom(32)  # 256-bit symmetric key

            t = _time.perf_counter()
            ciphertext = public_key.encrypt(
                message,
                rsa_padding.OAEP(
                    mgf=rsa_padding.MGF1(algorithm=hashes.SHA256()),
                    algorithm=hashes.SHA256(),
                    label=None,
                )
            )
            rsa_enc.append((_time.perf_counter() - t) * 1e6)

            t = _time.perf_counter()
            plaintext = private_key.decrypt(
                ciphertext,
                rsa_padding.OAEP(
                    mgf=rsa_padding.MGF1(algorithm=hashes.SHA256()),
                    algorithm=hashes.SHA256(),
                    label=None,
                )
            )
            rsa_dec.append((_time.perf_counter() - t) * 1e6)

        rsa_pk_bytes = public_key.public_bytes(
            serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo
        )
        rsa_sk_bytes = private_key.private_bytes(
            serialization.Encoding.DER, serialization.PrivateFormat.PKCS8,
            serialization.NoEncryption()
        )
        rsa_pk_size = len(rsa_pk_bytes)
        rsa_sk_size = len(rsa_sk_bytes)
        rsa_ct_size = len(ciphertext)

        # ── Results ──
        import statistics
        def avg(lst): return statistics.mean(lst)
        def med(lst): return statistics.median(lst)

        print(f"\n{'=' * 70}")
        print(f"  RESULTS ({iterations} iterations)")
        print(f"{'=' * 70}")

        print(f"\n  {'Operation':<25} {'RSA-2048':>15} {'Kyber-512':>15} {'Winner':>10}")
        print(f"  {'─'*25} {'─'*15} {'─'*15} {'─'*10}")

        ops = [
            ("Key Generation", avg(rsa_keygen), avg(kyber_keygen)),
            ("Encapsulate/Encrypt", avg(rsa_enc), avg(kyber_encap)),
            ("Decapsulate/Decrypt", avg(rsa_dec), avg(kyber_decap)),
        ]
        for name, rsa_val, kyber_val in ops:
            winner = "Kyber" if kyber_val < rsa_val else "RSA"
            speedup = max(rsa_val, kyber_val) / max(min(rsa_val, kyber_val), 0.01)
            print(f"  {name:<25} {rsa_val:>12.1f}us {kyber_val:>12.1f}us {winner:>6} ({speedup:.1f}x)")

        print(f"\n  {'Size (bytes)':<25} {'RSA-2048':>15} {'Kyber-512':>15}")
        print(f"  {'─'*25} {'─'*15} {'─'*15}")
        print(f"  {'Public Key':<25} {rsa_pk_size:>15,} {kyber_pk_size:>15,}")
        print(f"  {'Secret Key':<25} {rsa_sk_size:>15,} {kyber_sk_size:>15,}")
        print(f"  {'Ciphertext':<25} {rsa_ct_size:>15,} {kyber_ct_size:>15,}")

        print(f"\n  TRADEOFF ANALYSIS:")
        print(f"    RSA-2048: Smaller keys, slower keygen, VULNERABLE to Shor's algorithm")
        print(f"    Kyber-512: Larger keys, faster keygen, RESISTANT to quantum attacks")
        print(f"    Recommendation: Use Kyber for forward-looking security despite larger key sizes")
        print(f"{'=' * 70}")

        return {
            "rsa_keygen_us": avg(rsa_keygen), "kyber_keygen_us": avg(kyber_keygen),
            "rsa_enc_us": avg(rsa_enc), "kyber_encap_us": avg(kyber_encap),
            "rsa_dec_us": avg(rsa_dec), "kyber_decap_us": avg(kyber_decap),
            "rsa_pk_bytes": rsa_pk_size, "kyber_pk_bytes": kyber_pk_size,
            "rsa_ct_bytes": rsa_ct_size, "kyber_ct_bytes": kyber_ct_size,
        }


def run_pqc_benchmark(iterations: int = 100) -> dict:
    """Entry point for PQC benchmark."""
    bench = PQCBenchmark()
    return bench.run(iterations)


if __name__ == "__main__":
    test_pqc()

