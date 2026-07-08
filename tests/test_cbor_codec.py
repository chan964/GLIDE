"""
Test suite for cbor_codec.

Covers:
    - Round-trip correctness for all 4 message types
    - Strict decode validation (missing fields, wrong types, extra keys)
    - Protocol version mismatch rejection
    - Wrong message type rejection
    - Size bounds match our claims in the paper
"""

import secrets

import cbor2
import pytest

from src.cbor_codec import (
    KEY_CERT_INFO,
    KEY_NONCE,
    KEY_R,
    KEY_S,
    KEY_SIGNATURE,
    KEY_TYPE,
    KEY_U,
    KEY_VERSION,
    MSG_AUTH_CHALLENGE,
    MSG_AUTH_RESPONSE,
    MSG_PROVISIONING_REQUEST,
    MSG_PROVISIONING_RESPONSE,
    NONCE_SIZE,
    PROTOCOL_VERSION,
    SIGNATURE_SIZE,
    decode_auth_challenge,
    decode_auth_response,
    decode_provisioning_request,
    decode_provisioning_response,
    encode_auth_challenge,
    encode_auth_response,
    encode_provisioning_request,
    encode_provisioning_response,
    measure_message_sizes,
)
from src.ecqv_core import (
    device_generate_contribution,
    issuer_generate_cert,
    issuer_generate_keypair,
)


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------

@pytest.fixture
def sample_cert():
    issuer = issuer_generate_keypair()
    contribution = device_generate_contribution()
    cert_info = b"did:web:test||2026-04-19||31536000"
    return issuer_generate_cert(contribution.U, cert_info, issuer)


@pytest.fixture
def sample_contribution():
    return device_generate_contribution()


@pytest.fixture
def sample_nonce():
    return secrets.token_bytes(NONCE_SIZE)


@pytest.fixture
def sample_signature():
    return secrets.token_bytes(SIGNATURE_SIZE)


# ---------------------------------------------------------------------------
# ProvisioningRequest round-trip
# ---------------------------------------------------------------------------

def test_provisioning_request_roundtrip(sample_contribution):
    cert_info = b"test-info"
    encoded = encode_provisioning_request(sample_contribution.U, cert_info)
    decoded = decode_provisioning_request(encoded)
    assert decoded.U == sample_contribution.U
    assert decoded.cert_info == cert_info


def test_provisioning_request_rejects_empty_cert_info(sample_contribution):
    with pytest.raises(ValueError, match="cert_info must not be empty"):
        encode_provisioning_request(sample_contribution.U, b"")


def test_provisioning_request_rejects_wrong_version(sample_contribution):
    # Hand-craft a bad message
    bad = cbor2.dumps({
        KEY_VERSION: 999,
        KEY_TYPE: MSG_PROVISIONING_REQUEST,
        KEY_U: b"\x02" + b"\x00" * 32,
        KEY_CERT_INFO: b"x",
    })
    with pytest.raises(ValueError, match="version"):
        decode_provisioning_request(bad)


def test_provisioning_request_rejects_wrong_type(sample_contribution):
    encoded = encode_provisioning_request(sample_contribution.U, b"info")
    # Try to decode it as a different message type
    with pytest.raises(ValueError, match="Wrong message type"):
        decode_auth_challenge(encoded)


def test_provisioning_request_rejects_extra_keys(sample_contribution):
    """Extra keys in the CBOR map must be rejected (anti-smuggling)."""
    bad = cbor2.dumps({
        KEY_VERSION: PROTOCOL_VERSION,
        KEY_TYPE: MSG_PROVISIONING_REQUEST,
        KEY_U: b"\x02" + b"\x00" * 32,
        KEY_CERT_INFO: b"x",
        99: b"smuggled-data",   # Unexpected key
    })
    with pytest.raises(ValueError, match="Unexpected extra keys"):
        decode_provisioning_request(bad)


def test_provisioning_request_rejects_wrong_U_length():
    bad = cbor2.dumps({
        KEY_VERSION: PROTOCOL_VERSION,
        KEY_TYPE: MSG_PROVISIONING_REQUEST,
        KEY_U: b"\x02" * 10,   # Too short
        KEY_CERT_INFO: b"x",
    })
    with pytest.raises(ValueError, match="U must be 33 bytes"):
        decode_provisioning_request(bad)


def test_provisioning_request_rejects_non_cbor():
    """Raw garbage bytes that don't decode as CBOR must be rejected."""
    # Use truly invalid CBOR syntax (an incomplete indefinite-length marker)
    with pytest.raises(ValueError, match="CBOR decode failed"):
        decode_provisioning_request(b"\xbf\x01")   # indefinite map with truncated content


def test_provisioning_request_rejects_non_map_cbor():
    """Valid CBOR that decodes to something other than a map must be rejected."""
    # b"not-cbor-data..." happens to be valid CBOR (decodes as a string)
    # but our decoder requires a map
    with pytest.raises(ValueError, match="Expected CBOR map"):
        decode_provisioning_request(b"not-cbor-data\x00\x00")

# ---------------------------------------------------------------------------
# ProvisioningResponse round-trip
# ---------------------------------------------------------------------------

def test_provisioning_response_roundtrip(sample_cert):
    encoded = encode_provisioning_response(sample_cert)
    decoded = decode_provisioning_response(encoded)
    assert decoded.R == sample_cert.R
    assert decoded.s == sample_cert.s
    assert decoded.cert_info == sample_cert.cert_info


def test_provisioning_response_to_implicit_certificate(sample_cert):
    encoded = encode_provisioning_response(sample_cert)
    decoded = decode_provisioning_response(encoded)
    reconstructed = decoded.to_implicit_certificate()
    assert reconstructed.R == sample_cert.R
    assert reconstructed.s == sample_cert.s
    assert reconstructed.cert_info == sample_cert.cert_info


def test_provisioning_response_rejects_wrong_s_length():
    bad = cbor2.dumps({
        KEY_VERSION: PROTOCOL_VERSION,
        KEY_TYPE: MSG_PROVISIONING_RESPONSE,
        KEY_CERT_INFO: b"info",
        KEY_R: b"\x02" + b"\x00" * 32,
        KEY_S: b"\x00" * 10,   # Wrong length
    })
    with pytest.raises(ValueError, match="s must be 32 bytes"):
        decode_provisioning_response(bad)


# ---------------------------------------------------------------------------
# AuthChallenge round-trip
# ---------------------------------------------------------------------------

def test_auth_challenge_roundtrip(sample_nonce):
    encoded = encode_auth_challenge(sample_nonce)
    decoded = decode_auth_challenge(encoded)
    assert decoded.nonce == sample_nonce


def test_auth_challenge_rejects_wrong_nonce_size():
    with pytest.raises(ValueError, match="nonce must be"):
        encode_auth_challenge(b"\x00" * 8)   # Too short


def test_auth_challenge_decode_rejects_wrong_nonce_size():
    bad = cbor2.dumps({
        KEY_VERSION: PROTOCOL_VERSION,
        KEY_TYPE: MSG_AUTH_CHALLENGE,
        KEY_NONCE: b"\x00" * 8,
    })
    with pytest.raises(ValueError, match="nonce must be"):
        decode_auth_challenge(bad)


# ---------------------------------------------------------------------------
# AuthResponse round-trip
# ---------------------------------------------------------------------------

def test_auth_response_roundtrip(sample_cert, sample_signature):
    encoded = encode_auth_response(sample_cert.R, sample_cert.cert_info, sample_signature)
    decoded = decode_auth_response(encoded)
    assert decoded.R == sample_cert.R
    assert decoded.cert_info == sample_cert.cert_info
    assert decoded.signature == sample_signature


def test_auth_response_rejects_wrong_signature_size(sample_cert):
    with pytest.raises(ValueError, match="signature must be"):
        encode_auth_response(sample_cert.R, sample_cert.cert_info, b"\x00" * 10)


# ---------------------------------------------------------------------------
# Size claims (these back our paper's numbers)
# ---------------------------------------------------------------------------

def test_size_claims(sample_cert, sample_nonce, sample_signature):
    """Assert the wire size claims we make in the paper.

    If these fail, update the paper (or the code) — but one must match the other.
    """
    sizes = measure_message_sizes(sample_cert, sample_nonce, sample_signature)

    # ProvisioningRequest: 1 map header + 4 KV pairs + U (33) + cert_info (~35)
    assert 60 <= sizes["ProvisioningRequest"] <= 90

    # ProvisioningResponse: +s (32)
    assert 90 <= sizes["ProvisioningResponse"] <= 120

    # AuthChallenge: tiny
    assert 20 <= sizes["AuthChallenge"] <= 30

    # AuthResponse: R + signature + cert_info
    assert 140 <= sizes["AuthResponse"] <= 180


def test_auth_challenge_fits_in_single_frame(sample_nonce):
    """AuthChallenge must fit in one 802.15.4 MAC frame (127 bytes incl. headers)."""
    encoded = encode_auth_challenge(sample_nonce)
    assert len(encoded) < 100   # Comfortable margin


def test_provisioning_response_fits_in_single_frame(sample_cert):
    """ProvisioningResponse should fit without fragmentation at MAC layer."""
    encoded = encode_provisioning_response(sample_cert)
    assert len(encoded) < 120


# ---------------------------------------------------------------------------
# Cross-type rejection matrix
# ---------------------------------------------------------------------------

def test_decoders_reject_other_message_types(sample_cert, sample_nonce, sample_signature):
    """Decoder A must reject a correctly-encoded message of type B.

    This is the type-confusion defense.
    """
    pr = encode_provisioning_request(sample_cert.R, b"info")
    pp = encode_provisioning_response(sample_cert)
    ac = encode_auth_challenge(sample_nonce)
    ar = encode_auth_response(sample_cert.R, sample_cert.cert_info, sample_signature)

    # Each decoder must reject each foreign message
    decoders = [
        ("provisioning_request",  decode_provisioning_request,  pr),
        ("provisioning_response", decode_provisioning_response, pp),
        ("auth_challenge",        decode_auth_challenge,        ac),
        ("auth_response",         decode_auth_response,         ar),
    ]

    for decoder_name, decoder_fn, _ in decoders:
        for _, _, foreign_msg in decoders:
            # Skip self (round-trip is tested separately)
            if decoder_fn(foreign_msg) if False else None:
                pass
        # Check all foreign messages are rejected
        for other_name, _, other_msg in decoders:
            if other_name == decoder_name:
                continue
            with pytest.raises(ValueError):
                decoder_fn(other_msg)