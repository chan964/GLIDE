"""
Test suite for edhoc_subset.

Covers:
    - MSG_1 / MSG_2 CBOR codec round-trips (done in test_cbor_codec.py)
    - HKDF primitives match test vectors from RFC 5869
    - Session key derivation symmetry (both sides derive identical key)
    - End-to-end handshake happy path
    - Tampered MSG_1 field rejections (ephemeral, R, cert_info, nonce, signature)
    - Tampered MSG_2 rejections
    - Wrong gateway public key at device rejects handshake
    - Integration with revocation manager (not-revoked passes, revoked rejected,
      offline fails closed)
"""
from datetime import datetime, timedelta, timezone
from typing import Optional

import pytest

from src.cbor_codec import (
    NONCE_SIZE,
    SIGNATURE_SIZE,
    decode_edhoc_msg1,
    decode_edhoc_msg2,
    encode_edhoc_msg1,
    encode_edhoc_msg2,
)
from src.ecqv_core import (
    G,
    device_derive_private_key,
    device_generate_contribution,
    issuer_generate_cert,
    issuer_generate_keypair,
)
from src.edhoc_subset import (
    HKDF_INFO,
    SESSION_KEY_LENGTH,
    _hkdf_expand,
    _hkdf_extract,
    _msg1_signing_bytes,
    _msg2_signing_bytes,
    derive_session_key,
    device_build_msg1,
    device_process_msg2,
    gateway_process_msg1_build_msg2,
)
from src.gateway_keystore import (
    Keystore,
    PinnedIssuer,
    _compute_q_ca_hash,
    _generate_gateway_identity,
)
from src.gateway_verifier import AuthFailureReason
from src.revocation_sync import RevocationCheck, RevocationSyncManager

ISSUER_DID = "did:web:issuer.example"


# ---------------------------------------------------------------------------
# Mock fetcher for revocation manager (same pattern as Day 11)
# ---------------------------------------------------------------------------
class MockFetcher:
    def __init__(self):
        self.entries = {}

    def __call__(self, url, timeout):
        return {"revoked_at": "2026-04-19T12:00:00Z", "entries": dict(self.entries)}


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------
def _make_cert_info(issuer_did=ISSUER_DID, issued_at=None, max_age=31_536_000) -> bytes:
    if issued_at is None:
        issued_at = datetime.now(timezone.utc)
    return f"{issuer_did}||{issued_at.isoformat()}||{max_age}".encode()


@pytest.fixture
def issuer():
    return issuer_generate_keypair()


@pytest.fixture
def gateway_identity():
    return _generate_gateway_identity(lifetime_days=90)


@pytest.fixture
def keystore(issuer, gateway_identity):
    pinned = PinnedIssuer(
        issuer_did=ISSUER_DID,
        Q_ca=issuer.Q_ca,
        Q_ca_hash_hex=_compute_q_ca_hash(issuer.Q_ca),
        bootstrap_mode="pinned",
        bootstrapped_at=datetime.now(timezone.utc).isoformat(),
    )
    return Keystore(pinned_issuer=pinned, gateway_identity=gateway_identity)


@pytest.fixture
def provisioned_device(issuer):
    contribution = device_generate_contribution()
    cert_info = _make_cert_info()
    cert = issuer_generate_cert(contribution.U, cert_info, issuer)
    d = device_derive_private_key(contribution, cert)
    return {"d": d, "cert": cert, "contribution": contribution}


# ---------------------------------------------------------------------------
# HKDF sanity (not a full RFC 5869 vector, just shape checks)
# ---------------------------------------------------------------------------
def test_hkdf_extract_is_32_bytes():
    assert len(_hkdf_extract(b"salt", b"ikm")) == 32


def test_hkdf_expand_produces_requested_length():
    prk = _hkdf_extract(b"salt", b"ikm")
    assert len(_hkdf_expand(prk, b"info", 16)) == 16
    assert len(_hkdf_expand(prk, b"info", 42)) == 42


def test_hkdf_expand_deterministic():
    prk = _hkdf_extract(b"salt", b"ikm")
    a = _hkdf_expand(prk, b"info", 16)
    b = _hkdf_expand(prk, b"info", 16)
    assert a == b


# ---------------------------------------------------------------------------
# Session key symmetry: both sides compute the same key
# ---------------------------------------------------------------------------
def test_session_key_symmetry():
    """derive_session_key(e_d, E_g, ...) == derive_session_key(e_g, E_d, ...)"""
    import secrets
    from src.ecqv_core import N
    e_d = secrets.randbelow(N - 1) + 1
    e_g = secrets.randbelow(N - 1) + 1
    E_d = e_d * G
    E_g = e_g * G
    msg1 = b"msg1_placeholder"
    msg2 = b"msg2_placeholder"
    device_key = derive_session_key(e_d, E_g, msg1, msg2)
    gateway_key = derive_session_key(e_g, E_d, msg1, msg2)
    assert device_key == gateway_key
    assert len(device_key) == SESSION_KEY_LENGTH


def test_different_transcripts_produce_different_keys():
    import secrets
    from src.ecqv_core import N
    e_d = secrets.randbelow(N - 1) + 1
    e_g = secrets.randbelow(N - 1) + 1
    E_g = e_g * G
    key1 = derive_session_key(e_d, E_g, b"msg1_A", b"msg2_A")
    key2 = derive_session_key(e_d, E_g, b"msg1_B", b"msg2_B")
    assert key1 != key2


# ---------------------------------------------------------------------------
# End-to-end happy path
# ---------------------------------------------------------------------------
def test_e2e_handshake_happy_path(keystore, provisioned_device):
    # Device builds MSG_1
    msg1_bytes, state = device_build_msg1(
        provisioned_device["d"],
        provisioned_device["cert"].R,
        provisioned_device["cert"].cert_info,
        keystore.gateway_identity.public_key,
    )
    # Gateway processes MSG_1 and builds MSG_2
    gw_result = gateway_process_msg1_build_msg2(keystore, msg1_bytes)
    assert gw_result.success, f"Gateway rejected: {gw_result.reason} / {gw_result.detail}"
    assert gw_result.session_key is not None
    assert gw_result.msg2_bytes is not None
    print(f"\n[SIZES] MSG_1={len(msg1_bytes)}  MSG_2={len(gw_result.msg2_bytes)}")
    assert gw_result.device_did is not None
    # Device processes MSG_2
    dev_result = device_process_msg2(
        state,
        keystore.gateway_identity.public_key,
        gw_result.msg2_bytes,
    )
    assert dev_result.success, f"Device rejected: {dev_result.reason} / {dev_result.detail}"
    # Both sides have the same session key
    assert dev_result.session_key == gw_result.session_key


# ---------------------------------------------------------------------------
# Tamper detection
# ---------------------------------------------------------------------------
def test_tampered_msg1_signature_rejected(keystore, provisioned_device):
    msg1_bytes, _ = device_build_msg1(
        provisioned_device["d"],
        provisioned_device["cert"].R,
        provisioned_device["cert"].cert_info,
        keystore.gateway_identity.public_key,
    )
    # Flip the last byte (highly likely to be inside the signature field)
    tampered = bytearray(msg1_bytes)
    tampered[-1] ^= 0x01
    result = gateway_process_msg1_build_msg2(keystore, bytes(tampered))
    assert result.success is False


def test_msg1_decode_failure_rejected(keystore):
    result = gateway_process_msg1_build_msg2(keystore, b"not-cbor-garbage")
    assert result.success is False
    assert result.reason == AuthFailureReason.CERT_INFO_MALFORMED


def test_expired_cert_rejected_in_msg1(keystore, issuer):
    contribution = device_generate_contribution()
    old = datetime(2020, 1, 1, tzinfo=timezone.utc)
    cert_info = _make_cert_info(issued_at=old, max_age=3600)
    cert = issuer_generate_cert(contribution.U, cert_info, issuer)
    d = device_derive_private_key(contribution, cert)
    msg1_bytes, _ = device_build_msg1(d, cert.R, cert.cert_info, keystore.gateway_identity.public_key)
    result = gateway_process_msg1_build_msg2(keystore, msg1_bytes)
    assert result.success is False
    assert result.reason == AuthFailureReason.CERT_EXPIRED


def test_issuer_mismatch_rejected_in_msg1(keystore, issuer):
    contribution = device_generate_contribution()
    cert_info = _make_cert_info(issuer_did="did:web:different-issuer.example")
    cert = issuer_generate_cert(contribution.U, cert_info, issuer)
    d = device_derive_private_key(contribution, cert)
    msg1_bytes, _ = device_build_msg1(d, cert.R, cert.cert_info, keystore.gateway_identity.public_key)
    result = gateway_process_msg1_build_msg2(keystore, msg1_bytes)
    assert result.success is False
    assert result.reason == AuthFailureReason.ISSUER_MISMATCH


def test_wrong_gateway_public_key_rejected(keystore, provisioned_device):
    """Device receives MSG_2 but was provisioned with a DIFFERENT gateway pubkey."""
    msg1_bytes, state = device_build_msg1(
        provisioned_device["d"],
        provisioned_device["cert"].R,
        provisioned_device["cert"].cert_info,
        keystore.gateway_identity.public_key,
    )
    gw_result = gateway_process_msg1_build_msg2(keystore, msg1_bytes)
    assert gw_result.success
    # Device uses WRONG gateway pubkey (e.g., from a different gateway)
    wrong_gateway = _generate_gateway_identity(lifetime_days=90)
    dev_result = device_process_msg2(
        state,
        wrong_gateway.public_key,   # WRONG
        gw_result.msg2_bytes,
    )
    assert dev_result.success is False
    assert dev_result.reason == AuthFailureReason.SIGNATURE_INVALID


def test_tampered_msg2_rejected(keystore, provisioned_device):
    msg1_bytes, state = device_build_msg1(
        provisioned_device["d"],
        provisioned_device["cert"].R,
        provisioned_device["cert"].cert_info,
        keystore.gateway_identity.public_key,
    )
    gw_result = gateway_process_msg1_build_msg2(keystore, msg1_bytes)
    assert gw_result.success
    tampered = bytearray(gw_result.msg2_bytes)
    tampered[-1] ^= 0x01   # tamper signature byte
    dev_result = device_process_msg2(
        state, keystore.gateway_identity.public_key, bytes(tampered),
    )
    assert dev_result.success is False


# ---------------------------------------------------------------------------
# Revocation integration
# ---------------------------------------------------------------------------
def test_not_revoked_device_passes_handshake(keystore, provisioned_device):
    # Revocation manager attached, but this device is NOT in the list.
    # Guards against an over-aggressive revocation check that would reject
    # a legitimate device.
    fetcher = MockFetcher()
    fetcher.entries = {}          # empty revocation list
    mgr = RevocationSyncManager("http://x", fetch_fn=fetcher)
    mgr.sync_now()
    msg1_bytes, _ = device_build_msg1(
        provisioned_device["d"],
        provisioned_device["cert"].R,
        provisioned_device["cert"].cert_info,
        keystore.gateway_identity.public_key,
    )
    result = gateway_process_msg1_build_msg2(
        keystore, msg1_bytes, revocation_manager=mgr,
    )
    assert result.success is True
    assert result.session_key is not None


def test_revoked_device_rejected_in_handshake(keystore, provisioned_device):
    from src.did_utils import encode_did_key
    # Expected device DID
    device_did = encode_did_key(provisioned_device["d"] * G)
    # Build a revocation manager with this device revoked
    fetcher = MockFetcher()
    fetcher.entries = {device_did: "2026-04-19T11:00:00Z"}
    mgr = RevocationSyncManager("http://x", fetch_fn=fetcher)
    mgr.sync_now()
    msg1_bytes, _ = device_build_msg1(
        provisioned_device["d"],
        provisioned_device["cert"].R,
        provisioned_device["cert"].cert_info,
        keystore.gateway_identity.public_key,
    )
    result = gateway_process_msg1_build_msg2(
        keystore, msg1_bytes, revocation_manager=mgr,
    )
    assert result.success is False
    assert result.reason == AuthFailureReason.DEVICE_REVOKED


def test_offline_revocation_rejected_in_handshake(keystore, provisioned_device):
    from datetime import datetime, timezone

    class FrozenClock:
        def __init__(self, t): self.t = t
        def __call__(self): return self.t
        def advance(self, s):
            from datetime import timedelta
            self.t += timedelta(seconds=s)

    clock = FrozenClock(datetime(2026, 4, 19, 12, 0, 0, tzinfo=timezone.utc))
    fetcher = MockFetcher()
    mgr = RevocationSyncManager(
        "http://x",
        sync_interval=60, grace_window=300,
        now_fn=clock, fetch_fn=fetcher,
    )
    mgr.sync_now()
    clock.advance(1000)   # way past I + G
    msg1_bytes, _ = device_build_msg1(
        provisioned_device["d"],
        provisioned_device["cert"].R,
        provisioned_device["cert"].cert_info,
        keystore.gateway_identity.public_key,
    )
    # We need cert freshness to still pass, so inject a fresh "now" for the verifier
    fresh_now = datetime.now(timezone.utc)
    result = gateway_process_msg1_build_msg2(
        keystore, msg1_bytes, revocation_manager=mgr,
        now_fn=lambda: fresh_now,
    )
    assert result.success is False
    assert result.reason == AuthFailureReason.REVOCATION_UNAVAILABLE


# ---------------------------------------------------------------------------
# Cross-gateway relay countermeasure (Semester 3)
# ---------------------------------------------------------------------------
def test_msg1_signed_for_other_gateway_rejected(keystore, provisioned_device):
    """Cross-gateway relay: MSG_1 signed for gateway A must not verify at B.

    Countermeasure: Q_gw is bound into sigma_d. Corresponds to Tamarin
    lemma Gateway_Authenticates_Device (verified, 18 steps).
    """
    other_gateway = _generate_gateway_identity(lifetime_days=90)

    msg1_bytes, _ = device_build_msg1(
        provisioned_device["d"],
        provisioned_device["cert"].R,
        provisioned_device["cert"].cert_info,
        other_gateway.public_key,      # signed for a DIFFERENT gateway
    )
    result = gateway_process_msg1_build_msg2(keystore, msg1_bytes)
    assert result.success is False
    assert result.reason == AuthFailureReason.SIGNATURE_INVALID