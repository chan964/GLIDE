"""
ECQV Core: Two-pass Elliptic Curve Qu-Vanstone implicit certificate implementation.

Curve: secp256r1 (NIST P-256)
Hash: SHA-256 reduced mod curve order
Point encoding: SEC1 compressed (33 bytes)

Two-pass variant eliminates key escrow: the issuer never learns the device's
private contribution u, therefore cannot reconstruct the device's private key d.

Math reference (derived from scratch in project docs):
    Device picks u, sends U = u*G to issuer
    Issuer picks k, computes R = U + k*G
    Issuer computes e = H(R || cert_info) mod n
    Issuer computes s = (e*k + k_ca) mod n
    Issuer sends (R, s, cert_info) to device

    Device computes d = (e*u + s) mod n       [private key]
    Gateway computes Q_dev = e*R + Q_ca        [public key reconstruction]

Reconstruction identity (proven in docs/PROTOCOL_SPEC.md):
    d*G = e*R + Q_ca
"""

import hashlib
import secrets
from dataclasses import dataclass
from typing import Tuple

from ecdsa import NIST256p, ellipticcurve
from ecdsa.ecdsa import generator_256
from ecdsa.util import string_to_number, number_to_string
# ---------------------------------------------------------------------------
# Curve parameters (P-256)
# ---------------------------------------------------------------------------

CURVE = NIST256p
G = generator_256                  # Base point
N = G.order()                      # Curve order (prime)
FIELD_SIZE = 32                    # Coordinate size in bytes (256 bits)


# ---------------------------------------------------------------------------
# Data types
# ---------------------------------------------------------------------------

@dataclass(frozen=True)
class IssuerKeypair:
    """Issuer long-term keypair. k_ca is the private key, Q_ca is public."""
    k_ca: int                                  # Private scalar, in [1, n-1]
    Q_ca: ellipticcurve.PointJacobi            # Public point, Q_ca = k_ca * G


@dataclass(frozen=True)
class DeviceContribution:
    """Device's ephemeral contribution in the first pass of ECQV."""
    u: int                                     # Private scalar, in [1, n-1]
    U: ellipticcurve.PointJacobi               # U = u * G


@dataclass(frozen=True)
class ImplicitCertificate:
    """The credential issued by the issuer.

    R:         Reconstruction point (33 bytes compressed on the wire)
    s:         Issuer's contribution scalar (32 bytes on the wire)
    cert_info: CBOR-encoded metadata (issuer_did, issued_at, max_age)

    Wire size: 33 + 32 + len(cert_info) bytes (~80-100 bytes total)
    """
    R: ellipticcurve.PointJacobi
    s: int
    cert_info: bytes


# ---------------------------------------------------------------------------
# Encoding helpers
# ---------------------------------------------------------------------------

def point_to_compressed(P: ellipticcurve.PointJacobi) -> bytes:
    """Encode an elliptic curve point as SEC1 compressed format (33 bytes).

    Prefix byte is 0x02 if y is even, 0x03 if y is odd.
    Followed by 32-byte big-endian x-coordinate.

    Raises ValueError if P is the point at infinity (invalid for our use).
    """
    if P == ellipticcurve.INFINITY:
        raise ValueError("Cannot encode point at infinity")
    x = P.x()
    y = P.y()
    prefix = b"\x02" if y % 2 == 0 else b"\x03"
    return prefix + number_to_string(x, N)


def compressed_to_point(data: bytes) -> ellipticcurve.PointJacobi:
    """Decode SEC1 compressed point bytes back to a curve point.

    Validates that the decoded point lies on the curve; raises ValueError otherwise.
    This prevents invalid-curve attacks.
    """
    if len(data) != 33:
        raise ValueError(f"Compressed point must be 33 bytes, got {len(data)}")
    if data[0] not in (0x02, 0x03):
        raise ValueError(f"Invalid compression prefix: {data[0]:#04x}")

    x = string_to_number(data[1:])
    curve = CURVE.curve
    p = curve.p()
    a = curve.a()
    b = curve.b()

    # Recover y from x: y^2 = x^3 + a*x + b (mod p)
    y_squared = (pow(x, 3, p) + a * x + b) % p
    y = pow(y_squared, (p + 1) // 4, p)   # Works because p ≡ 3 (mod 4) for P-256

    # Verify y is actually a square root
    if (y * y) % p != y_squared:
        raise ValueError("Point is not on curve (no valid y)")

    # Select correct y based on prefix parity
    if (y % 2 == 0 and data[0] == 0x03) or (y % 2 == 1 and data[0] == 0x02):
        y = p - y

    point = ellipticcurve.Point(curve, x, y, N)
    # Convert to Jacobi for efficient arithmetic with the rest of the library
    return ellipticcurve.PointJacobi.from_affine(point)


def hash_to_scalar(R: ellipticcurve.PointJacobi, cert_info: bytes) -> int:
    """Compute e = H(R_compressed || cert_info) mod n.

    This is the 'e' value used in both cert generation (issuer side) and
    key derivation (device side) and public key reconstruction (gateway side).
    All three must compute identical e for the math to work.
    """
    R_bytes = point_to_compressed(R)
    h = hashlib.sha256(R_bytes + cert_info).digest()
    e = string_to_number(h) % N
    if e == 0:
        # Astronomically unlikely but mathematically required to reject
        raise ValueError("Hash produced e=0; regenerate cert")
    return e


# ---------------------------------------------------------------------------
# Step 1: Issuer key generation
# ---------------------------------------------------------------------------

def issuer_generate_keypair() -> IssuerKeypair:
    """Generate a fresh issuer (CA) long-term keypair.

    k_ca is drawn uniformly from [1, n-1] using cryptographic RNG.
    Q_ca = k_ca * G is the issuer's public key, published in did:web document.
    """
    k_ca = secrets.randbelow(N - 1) + 1   # Uniform in [1, n-1]
    Q_ca = k_ca * G
    return IssuerKeypair(k_ca=k_ca, Q_ca=Q_ca)


# ---------------------------------------------------------------------------
# Step 2: Device generates contribution (first pass)
# ---------------------------------------------------------------------------

def device_generate_contribution() -> DeviceContribution:
    """Device generates its secret contribution u and public U = u*G.

    u MUST remain on the device. If u leaks to the issuer, key escrow returns.
    The device sends U (not u) to the issuer along with cert_info.
    """
    u = secrets.randbelow(N - 1) + 1
    U = u * G
    return DeviceContribution(u=u, U=U)


# ---------------------------------------------------------------------------
# Step 3: Issuer generates implicit certificate (second pass)
# ---------------------------------------------------------------------------

def issuer_generate_cert(
    U: ellipticcurve.PointJacobi,
    cert_info: bytes,
    issuer: IssuerKeypair,
) -> ImplicitCertificate:
    """Issuer produces implicit certificate (R, s) binding U and cert_info.

    Process:
        1. Pick random k in [1, n-1]
        2. R = U + k*G  (reconstruction point)
        3. e = H(R || cert_info) mod n
        4. s = (e*k + k_ca) mod n

    The issuer transmits (R, s, cert_info). The issuer cannot compute the
    device's private key d because it does not know u.

    Raises ValueError if cert_info is empty (defense against degenerate input).
    """
    # if not cert_info:
    #     raise ValueError("cert_info must not be empty")
    # if not isinstance(U, ellipticcurve.PointJacobi):
    #     raise TypeError("U must be a Jacobi point")

    # # Reject U at infinity (attacker trying to degenerate the protocol)
    # if U == ellipticcurve.INFINITY:
    #     raise ValueError("U cannot be point at infinity"

    if not cert_info:
        raise ValueError("cert_info must not be empty")

    # Reject U at infinity (attacker trying to degenerate the protocol)
    # Note: we accept both Point and PointJacobi — ecdsa library uses both
    # interchangeably depending on how the point was constructed.
    if U == ellipticcurve.INFINITY:
        raise ValueError("U cannot be point at infinity")

    k = secrets.randbelow(N - 1) + 1
    R = U + k * G

    # R must not be infinity (astronomically unlikely)
    if R == ellipticcurve.INFINITY:
        raise ValueError("R is point at infinity; regenerate")

    e = hash_to_scalar(R, cert_info)
    s = (e * k + issuer.k_ca) % N

    if s == 0:
        # Would make the cert trivially invalid; regenerate
        raise ValueError("s=0; regenerate cert")

    return ImplicitCertificate(R=R, s=s, cert_info=cert_info)


# ---------------------------------------------------------------------------
# Step 4: Device derives its long-term private key
# ---------------------------------------------------------------------------

def device_derive_private_key(
    contribution: DeviceContribution,
    cert: ImplicitCertificate,
) -> int:
    """Device computes its private key d = (e*u + s) mod n.

    After computing d, the device MAY discard u (u is no longer needed).
    The device keeps: d (private), R (public, in cert), cert_info (public).

    Returns d as a scalar in [1, n-1]. Raises ValueError if d is zero
    (cert is invalid — should never happen with honest issuer).
    """
    e = hash_to_scalar(cert.R, cert.cert_info)
    d = (e * contribution.u + cert.s) % N

    if d == 0:
        raise ValueError("Derived private key is zero; cert is invalid")

    return d


# ---------------------------------------------------------------------------
# Step 5: Gateway reconstructs the device's public key
# ---------------------------------------------------------------------------

def gateway_reconstruct_public_key(
    cert: ImplicitCertificate,
    issuer_Q_ca: ellipticcurve.PointJacobi,
) -> ellipticcurve.PointJacobi:
    """Gateway reconstructs Q_dev = e*R + Q_ca from cert and pinned issuer key.

    This is the authentication step. The gateway:
        1. Has Q_ca pinned via TOFU from did:web resolution at bootstrap
        2. Receives (R, cert_info) from device during auth
        3. Computes e = H(R || cert_info)
        4. Reconstructs Q_dev = e*R + Q_ca
        5. Verifies device's signature on a challenge using Q_dev

    If the cert was not signed by the issuer that Q_ca belongs to,
    the reconstructed Q_dev will be wrong and signature verification fails.

    Returns Q_dev as a Jacobi point. Raises ValueError if reconstruction
    produces infinity (cert is malformed or tampered).
    """
    e = hash_to_scalar(cert.R, cert.cert_info)
    Q_dev = e * cert.R + issuer_Q_ca

    if Q_dev == ellipticcurve.INFINITY:
        raise ValueError("Reconstructed public key is point at infinity; cert invalid")

    return Q_dev


# ---------------------------------------------------------------------------
# Convenience: verify reconstruction identity (used by tests)
# ---------------------------------------------------------------------------

def verify_reconstruction_identity(
    d: int,
    cert: ImplicitCertificate,
    issuer_Q_ca: ellipticcurve.PointJacobi,
) -> bool:
    """Check whether d*G == e*R + Q_ca.

    This is the fundamental correctness check for ECQV. If this returns
    False for an honestly-generated cert, the implementation is broken.
    """
    Q_from_private = d * G
    Q_from_reconstruction = gateway_reconstruct_public_key(cert, issuer_Q_ca)
    return Q_from_private == Q_from_reconstruction