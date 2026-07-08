"""
Test suite for did_utils.

Tests cover:
    - did:key round-trips (encode → decode → same point)
    - did:key validation (rejects wrong method, wrong multicodec, malformed)
    - did:web construction (valid and invalid domains)
    - did:web → URL resolution (with and without path segments)
    - Generic DID parsing
    - base58btc encode/decode round-trips
"""

import pytest
from ecdsa import ellipticcurve

from src.ecqv_core import (
    G,
    device_generate_contribution,
    issuer_generate_keypair,
)
from src.did_utils import (
    P256_MULTICODEC_PREFIX,
    base58btc_decode,
    base58btc_encode,
    construct_did_web,
    decode_did_key,
    encode_did_key,
    parse_did,
    resolve_did_web_to_url,
)


# ---------------------------------------------------------------------------
# base58btc
# ---------------------------------------------------------------------------

def test_base58btc_roundtrip_random():
    import secrets
    for _ in range(20):
        data = secrets.token_bytes(35)
        encoded = base58btc_encode(data)
        decoded = base58btc_decode(encoded)
        assert decoded == data, f"Roundtrip failed for {data.hex()}"


def test_base58btc_empty():
    assert base58btc_encode(b"") == ""
    assert base58btc_decode("") == b""


def test_base58btc_leading_zeros():
    """Leading zero bytes encode as leading '1' chars in base58btc."""
    data = b"\x00\x00\x42"
    encoded = base58btc_encode(data)
    assert encoded.startswith("11")
    assert base58btc_decode(encoded) == data


# ---------------------------------------------------------------------------
# did:key
# ---------------------------------------------------------------------------

def test_did_key_roundtrip():
    """Encode a P-256 public key, decode it, get the same point back."""
    for _ in range(10):
        contribution = device_generate_contribution()
        pubkey = contribution.U
        did = encode_did_key(pubkey)
        assert did.startswith("did:key:z")
        recovered = decode_did_key(did)
        assert recovered == pubkey


def test_did_key_contains_multicodec_prefix():
    """Decoded multibase payload must start with P-256 multicodec bytes."""
    contribution = device_generate_contribution()
    did = encode_did_key(contribution.U)
    payload = did[len("did:key:z"):]
    decoded = base58btc_decode(payload)
    assert decoded[:2] == P256_MULTICODEC_PREFIX


def test_did_key_rejects_wrong_method():
    with pytest.raises(ValueError, match="did:key"):
        decode_did_key("did:web:example.com")


def test_did_key_rejects_missing_multibase_prefix():
    with pytest.raises(ValueError, match="did:key"):
        decode_did_key("did:key:xABC")   # 'x' not 'z'


def test_did_key_rejects_wrong_multicodec():
    """A did:key with valid base58btc but wrong multicodec must be rejected."""
    # Construct a "did:key" with Ed25519 multicodec (0xED01) instead of P-256
    bad_prefix = bytes([0xED, 0x01])
    fake_key = b"\x00" * 32
    payload = base58btc_encode(bad_prefix + fake_key)
    with pytest.raises(ValueError, match="Multicodec prefix"):
        decode_did_key(f"did:key:z{payload}")


def test_did_key_rejects_empty_payload():
    with pytest.raises(ValueError):
        decode_did_key("did:key:z")


# ---------------------------------------------------------------------------
# did:web construction
# ---------------------------------------------------------------------------

def test_construct_did_web_domain_only():
    assert construct_did_web("issuer.example.com") == "did:web:issuer.example.com"


def test_construct_did_web_with_path():
    did = construct_did_web("issuer.example.com", ["users", "alice"])
    assert did == "did:web:issuer.example.com:users:alice"


def test_construct_did_web_rejects_invalid_domain():
    with pytest.raises(ValueError, match="domain"):
        construct_did_web("not a domain!")


def test_construct_did_web_rejects_invalid_path_segment():
    with pytest.raises(ValueError, match="path segment"):
        construct_did_web("example.com", ["good", "bad segment"])


# ---------------------------------------------------------------------------
# did:web → URL resolution
# ---------------------------------------------------------------------------

def test_resolve_did_web_domain_only():
    url = resolve_did_web_to_url("did:web:issuer.example.com")
    assert url == "https://issuer.example.com/.well-known/did.json"


def test_resolve_did_web_with_path():
    url = resolve_did_web_to_url("did:web:issuer.example.com:users:alice")
    assert url == "https://issuer.example.com/users/alice/did.json"


def test_resolve_did_web_rejects_non_web():
    with pytest.raises(ValueError, match="did:web"):
        resolve_did_web_to_url("did:key:zABC")


def test_resolve_did_web_rejects_empty():
    with pytest.raises(ValueError):
        resolve_did_web_to_url("did:web:")


# ---------------------------------------------------------------------------
# Generic DID parsing
# ---------------------------------------------------------------------------

def test_parse_did_key():
    method, id_ = parse_did("did:key:z6MkTest")
    assert method == "key"
    assert id_ == "z6MkTest"


def test_parse_did_web_with_path():
    method, id_ = parse_did("did:web:example.com:users:alice")
    assert method == "web"
    assert id_ == "example.com:users:alice"


def test_parse_did_rejects_non_did():
    with pytest.raises(ValueError, match="Not a DID"):
        parse_did("https://example.com")


def test_parse_did_rejects_missing_id():
    with pytest.raises(ValueError):
        parse_did("did:key")