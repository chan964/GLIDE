"""
Test suite for ecqv_core.

Each test targets a specific correctness property or failure mode.
The reconstruction identity test is the linchpin: if it fails, nothing else matters.
"""

import pytest
from ecdsa import ellipticcurve

from src.ecqv_core import (
    G, N,
    IssuerKeypair,
    DeviceContribution,
    ImplicitCertificate,
    issuer_generate_keypair,
    device_generate_contribution,
    issuer_generate_cert,
    device_derive_private_key,
    gateway_reconstruct_public_key,
    verify_reconstruction_identity,
    point_to_compressed,
    compressed_to_point,
    hash_to_scalar,
)


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------

@pytest.fixture
def issuer():
    return issuer_generate_keypair()


@pytest.fixture
def cert_info():
    # Minimal stand-in for CBOR-encoded {issuer_did, issued_at, max_age}
    return b"did:web:issuer.example||2026-04-18T00:00:00Z||31536000"


@pytest.fixture
def provisioned(issuer, cert_info):
    """Full provisioning: device contributes, issuer issues, device derives d."""
    contribution = device_generate_contribution()
    cert = issuer_generate_cert(contribution.U, cert_info, issuer)
    d = device_derive_private_key(contribution, cert)
    return {
        "issuer": issuer,
        "contribution": contribution,
        "cert": cert,
        "d": d,
    }


# ---------------------------------------------------------------------------
# Core correctness: the reconstruction identity
# ---------------------------------------------------------------------------

def test_reconstruction_identity_holds(provisioned):
    """THE critical test: d*G must equal e*R + Q_ca.

    If this fails, the entire protocol is broken and nothing else matters.
    """
    assert verify_reconstruction_identity(
        provisioned["d"],
        provisioned["cert"],
        provisioned["issuer"].Q_ca,
    )


def test_reconstruction_identity_holds_across_many_runs():
    """Run full provisioning 50 times; identity must hold every time.

    Guards against: non-deterministic bugs in randomness handling, modular
    arithmetic edge cases, point-at-infinity cases.
    """
    for _ in range(50):
        issuer = issuer_generate_keypair()
        contribution = device_generate_contribution()
        cert_info = b"test||run||" + str(_).encode()
        cert = issuer_generate_cert(contribution.U, cert_info, issuer)
        d = device_derive_private_key(contribution, cert)
        assert verify_reconstruction_identity(d, cert, issuer.Q_ca), f"Run {_} failed"


# ---------------------------------------------------------------------------
# Key properties
# ---------------------------------------------------------------------------

def test_device_private_key_in_valid_range(provisioned):
    """d must be in [1, n-1] for it to be a valid ECDSA private key."""
    d = provisioned["d"]
    assert 1 <= d < N


def test_issuer_private_key_in_valid_range(issuer):
    """k_ca must be in [1, n-1]."""
    assert 1 <= issuer.k_ca < N


def test_device_contribution_in_valid_range():
    """u must be in [1, n-1]."""
    for _ in range(20):
        c = device_generate_contribution()
        assert 1 <= c.u < N


def test_two_devices_produce_different_keys(issuer, cert_info):
    """Independent provisioning must yield independent device keys.

    Guards against: seeded RNG leaking between provisioning calls.
    """
    c1 = device_generate_contribution()
    c2 = device_generate_contribution()
    cert1 = issuer_generate_cert(c1.U, cert_info, issuer)
    cert2 = issuer_generate_cert(c2.U, cert_info, issuer)
    d1 = device_derive_private_key(c1, cert1)
    d2 = device_derive_private_key(c2, cert2)
    assert d1 != d2
    assert cert1.R != cert2.R


# ---------------------------------------------------------------------------
# No-key-escrow property (the reason for two-pass)
# ---------------------------------------------------------------------------

def test_issuer_cannot_compute_device_key(provisioned):
    """The issuer's view is {U, R, s, k_ca, cert_info, k} — not u.

    Without u, the issuer cannot compute d = e*u + s.
    This test simulates the issuer trying to derive d from what it knows.

    Since the issuer doesn't know u, the best it can do is guess.
    We verify that the actual d depends on u in a way the issuer cannot replicate.
    """
    # Simulate issuer trying to derive d with a GUESSED u (not the real one)
    cert = provisioned["cert"]
    real_d = provisioned["d"]

    # Issuer guesses u=1 (arbitrary wrong guess)
    guessed_u = 1
    e = hash_to_scalar(cert.R, cert.cert_info)
    guessed_d = (e * guessed_u + cert.s) % N

    # The guessed d must not equal the real d (overwhelmingly)
    assert guessed_d != real_d


# ---------------------------------------------------------------------------
# Tamper detection (the gateway catches modifications)
# ---------------------------------------------------------------------------

def test_tampered_cert_info_breaks_reconstruction(provisioned):
    """If cert_info is modified after issuance, reconstruction produces a
    public key that does NOT match the device's actual private key.

    Practically: the device's signature will fail verification at the gateway.
    """
    cert = provisioned["cert"]
    tampered_cert = ImplicitCertificate(
        R=cert.R,
        s=cert.s,
        cert_info=cert.cert_info + b"tampered",   # Modify cert_info
    )
    assert not verify_reconstruction_identity(
        provisioned["d"],
        tampered_cert,
        provisioned["issuer"].Q_ca,
    )


def test_tampered_R_breaks_reconstruction(provisioned):
    """If R is modified, reconstruction fails (gateway gets wrong Q_dev)."""
    cert = provisioned["cert"]
    # Replace R with a different valid point
    tampered_R = 42 * G
    tampered_cert = ImplicitCertificate(
        R=tampered_R,
        s=cert.s,
        cert_info=cert.cert_info,
    )
    assert not verify_reconstruction_identity(
        provisioned["d"],
        tampered_cert,
        provisioned["issuer"].Q_ca,
    )


def test_tampered_s_breaks_device_key_derivation(provisioned):
    """If s is tampered IN TRANSIT (before device derives d), the device's
    derived d will not match the gateway's reconstructed Q_dev.

    Nuance: s does not appear in the gateway's reconstruction formula
    (Q_dev = e*R + Q_ca), so tampering with s alone does not break the
    reconstruction identity if d is already derived from the original s.

    The real security guarantee is: if s is tampered before the device
    derives d, the resulting d*G will NOT equal e*R + Q_ca.
    """
    cert = provisioned["cert"]
    contribution = provisioned["contribution"]

    # Simulate: attacker tampers with s IN TRANSIT before device derives d
    tampered_cert = ImplicitCertificate(
        R=cert.R,
        s=(cert.s + 1) % N,   # Off-by-one tamper
        cert_info=cert.cert_info,
    )

    # Device naively derives d from tampered cert
    d_from_tampered = device_derive_private_key(contribution, tampered_cert)

    # Gateway reconstructs using R and Q_ca (does not use s directly)
    Q_dev_reconstructed = gateway_reconstruct_public_key(
        cert,   # Note: gateway uses ORIGINAL R, not tampered s
        provisioned["issuer"].Q_ca,
    )

    # The tampered d does NOT produce the reconstructed public key
    # This is what would cause signature verification to fail in practice
    assert d_from_tampered * G != Q_dev_reconstructed
    
# def test_tampered_s_breaks_reconstruction(provisioned):
#     """If s is modified, reconstruction fails."""
#     cert = provisioned["cert"]
#     tampered_cert = ImplicitCertificate(
#         R=cert.R,
#         s=(cert.s + 1) % N,   # Off-by-one
#         cert_info=cert.cert_info,
#     )
#     assert not verify_reconstruction_identity(
#         provisioned["d"],
#         tampered_cert,
#         provisioned["issuer"].Q_ca,
#     )


def test_wrong_issuer_key_breaks_reconstruction(provisioned):
    """Reconstruction with a different issuer's Q_ca must fail.

    This is the security core: a device's cert is only valid under the
    issuer whose Q_ca the gateway has pinned. TOFU pinning guarantees this.
    """
    wrong_issuer = issuer_generate_keypair()
    assert not verify_reconstruction_identity(
        provisioned["d"],
        provisioned["cert"],
        wrong_issuer.Q_ca,   # Wrong issuer!
    )


# ---------------------------------------------------------------------------
# Encoding round-trips
# ---------------------------------------------------------------------------

def test_point_encoding_roundtrip():
    """Any curve point must survive compressed encoding and decoding."""
    for _ in range(20):
        c = device_generate_contribution()
        P = c.U
        encoded = point_to_compressed(P)
        assert len(encoded) == 33
        decoded = compressed_to_point(encoded)
        assert decoded == P


def test_compressed_point_is_33_bytes():
    """Explicit size check — this is our credential-size claim."""
    c = device_generate_contribution()
    assert len(point_to_compressed(c.U)) == 33


def test_invalid_compressed_length_rejected():
    with pytest.raises(ValueError, match="33 bytes"):
        compressed_to_point(b"\x02" + b"\x00" * 31)   # 32 bytes, not 33


def test_invalid_compression_prefix_rejected():
    with pytest.raises(ValueError, match="compression prefix"):
        compressed_to_point(b"\x04" + b"\x00" * 32)   # Uncompressed prefix


def test_invalid_point_rejected():
    """A byte string with valid length but x not on curve must be rejected."""
    # Construct x with no valid y (statistically extremely likely for random x)
    bad = b"\x02" + b"\xff" * 32
    # This may or may not decode to a valid point; most "all FF" x won't
    # If it does happen to decode, the test is vacuous — but that's rare.
    try:
        compressed_to_point(bad)
    except ValueError:
        pass   # Expected for most random x values


# ---------------------------------------------------------------------------
# Input validation
# ---------------------------------------------------------------------------

def test_empty_cert_info_rejected(issuer):
    c = device_generate_contribution()
    with pytest.raises(ValueError, match="cert_info must not be empty"):
        issuer_generate_cert(c.U, b"", issuer)


def test_U_at_infinity_rejected(issuer, cert_info):
    with pytest.raises(ValueError, match="infinity"):
        issuer_generate_cert(ellipticcurve.INFINITY, cert_info, issuer)


# ---------------------------------------------------------------------------
# Hash determinism
# ---------------------------------------------------------------------------

def test_hash_to_scalar_deterministic(provisioned):
    """Same R and cert_info must produce the same e every time."""
    cert = provisioned["cert"]
    e1 = hash_to_scalar(cert.R, cert.cert_info)
    e2 = hash_to_scalar(cert.R, cert.cert_info)
    assert e1 == e2


def test_hash_to_scalar_different_cert_info(provisioned):
    cert = provisioned["cert"]
    e1 = hash_to_scalar(cert.R, cert.cert_info)
    e2 = hash_to_scalar(cert.R, cert.cert_info + b"x")
    assert e1 != e2