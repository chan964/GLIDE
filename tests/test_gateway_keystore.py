"""
Test suite for gateway_keystore v2.

Now tests both pinned issuer AND gateway identity management.

Covers (pinned issuer — existing):
    - Pinned bootstrap: happy path, rejects mismatched hash, rejects malformed hash
    - Load verification: detects tampered hash, tampered Q_ca, missing fields
    - Re-fetch verification: matches, mismatches

Covers (gateway identity — new in v2):
    - Gateway keypair generation with configurable lifetime
    - Persistence across bootstrap and reload
    - Integrity check: detects private/public key mismatch
    - Expiry semantics: is_expired(), time_until_expiry()
    - Lifetime validation
"""

import json
import socket
import threading
import time
from datetime import datetime, timedelta, timezone
from pathlib import Path

import httpx
import pytest

from src.did_registry import create_registry_app
from src.ecqv_core import G, issuer_generate_keypair, point_to_compressed
from src.gateway_keystore import (
    DEFAULT_GATEWAY_KEY_LIFETIME_DAYS,
    KEYSTORE_VERSION,
    AlreadyBootstrappedError,
    GatewayIdentity,
    Keystore,
    KeystoreCorruptedError,
    KeystoreError,
    KeystoreNotFoundError,
    PinnedIssuer,
    TofuMismatchError,
    _compute_q_ca_hash,
    _generate_gateway_identity,
    bootstrap_pinned,
    load_keystore,
    verify_pin_against_remote,
)


# ---------------------------------------------------------------------------
# Server fixture (unchanged)
# ---------------------------------------------------------------------------

@pytest.fixture
def running_registry():
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        port = s.getsockname()[1]

    issuer = issuer_generate_keypair()
    issuer_did = f"did:web:127.0.0.1%3A{port}"
    app = create_registry_app(issuer_did=issuer_did, issuer=issuer, admin_token="t")

    thread = threading.Thread(
        target=lambda: app.run(host="127.0.0.1", port=port,
                               debug=False, use_reloader=False, threaded=True),
        daemon=True,
    )
    thread.start()

    base_url = f"http://127.0.0.1:{port}"
    for _ in range(50):
        try:
            r = httpx.get(f"{base_url}/.well-known/did.json", timeout=0.5)
            if r.status_code == 200:
                break
        except httpx.RequestError:
            pass
        time.sleep(0.1)
    else:
        pytest.fail("Registry failed to start")

    yield base_url, issuer, issuer_did


@pytest.fixture
def did_url(running_registry):
    base_url, _, _ = running_registry
    return f"{base_url}/.well-known/did.json"


@pytest.fixture
def valid_keystore(tmp_path, did_url, running_registry):
    _, issuer, _ = running_registry
    expected_hash = _compute_q_ca_hash(issuer.Q_ca)
    keystore_path = tmp_path / "gateway_keystore.json"
    bootstrap_pinned(keystore_path, did_url, expected_hash)
    return keystore_path


# ---------------------------------------------------------------------------
# Gateway identity generation (unit tests)
# ---------------------------------------------------------------------------

def test_generate_gateway_identity_valid_key():
    identity = _generate_gateway_identity(lifetime_days=30)
    assert 1 <= identity.private_key < 2**256
    # public_key must equal private_key * G
    assert identity.private_key * G == identity.public_key


def test_generate_gateway_identity_lifetime_reflected():
    identity = _generate_gateway_identity(lifetime_days=30)
    assert identity.lifetime_days == 30
    delta = identity.expires_at - identity.created_at
    assert delta == timedelta(days=30)


def test_generate_gateway_identity_rejects_invalid_lifetime():
    with pytest.raises(ValueError, match="lifetime_days must be positive"):
        _generate_gateway_identity(lifetime_days=0)
    with pytest.raises(ValueError, match="lifetime_days must be positive"):
        _generate_gateway_identity(lifetime_days=-10)


def test_gateway_identity_is_expired():
    past = datetime(2020, 1, 1, tzinfo=timezone.utc)
    identity = _generate_gateway_identity(lifetime_days=30, now=past)
    # now is far in the future
    assert identity.is_expired(now=datetime.now(timezone.utc))


def test_gateway_identity_not_expired_when_fresh():
    identity = _generate_gateway_identity(lifetime_days=90)
    assert not identity.is_expired()


def test_gateway_identity_time_until_expiry_positive_when_fresh():
    identity = _generate_gateway_identity(lifetime_days=90)
    remaining = identity.time_until_expiry()
    assert remaining.total_seconds() > 0
    assert remaining.total_seconds() <= 90 * 24 * 3600


# ---------------------------------------------------------------------------
# Pinned bootstrap with gateway identity co-creation
# ---------------------------------------------------------------------------

def test_bootstrap_creates_both_sections(tmp_path, did_url, running_registry):
    _, issuer, issuer_did = running_registry
    expected_hash = _compute_q_ca_hash(issuer.Q_ca)
    keystore_path = tmp_path / "gateway_keystore.json"

    keystore = bootstrap_pinned(keystore_path, did_url, expected_hash)

    # Pinned issuer populated correctly
    assert keystore.pinned_issuer.issuer_did == issuer_did
    assert keystore.pinned_issuer.Q_ca == issuer.Q_ca
    assert keystore.pinned_issuer.bootstrap_mode == "pinned"

    # Gateway identity populated with fresh keypair
    assert keystore.gateway_identity is not None
    assert keystore.gateway_identity.lifetime_days == DEFAULT_GATEWAY_KEY_LIFETIME_DAYS
    assert keystore.gateway_identity.private_key * G == keystore.gateway_identity.public_key
    assert not keystore.gateway_identity.is_expired()


def test_bootstrap_custom_lifetime(tmp_path, did_url, running_registry):
    _, issuer, _ = running_registry
    expected_hash = _compute_q_ca_hash(issuer.Q_ca)
    keystore_path = tmp_path / "gateway_keystore.json"

    keystore = bootstrap_pinned(
        keystore_path, did_url, expected_hash,
        gateway_lifetime_days=30,
    )
    assert keystore.gateway_identity.lifetime_days == 30


def test_bootstrap_pinned_rejects_wrong_hash(tmp_path, did_url):
    wrong_hash = "0" * 64
    keystore_path = tmp_path / "gateway_keystore.json"
    with pytest.raises(TofuMismatchError):
        bootstrap_pinned(keystore_path, did_url, wrong_hash)
    assert not keystore_path.exists()


def test_bootstrap_refuses_existing_keystore(tmp_path, did_url, running_registry):
    _, issuer, _ = running_registry
    expected_hash = _compute_q_ca_hash(issuer.Q_ca)
    keystore_path = tmp_path / "gateway_keystore.json"
    bootstrap_pinned(keystore_path, did_url, expected_hash)
    with pytest.raises(AlreadyBootstrappedError):
        bootstrap_pinned(keystore_path, did_url, expected_hash)


def test_bootstrap_force_regenerates_gateway_identity(tmp_path, did_url, running_registry):
    """Re-bootstrap with force should issue a NEW gateway keypair."""
    _, issuer, _ = running_registry
    expected_hash = _compute_q_ca_hash(issuer.Q_ca)
    keystore_path = tmp_path / "gateway_keystore.json"

    first = bootstrap_pinned(keystore_path, did_url, expected_hash)
    second = bootstrap_pinned(keystore_path, did_url, expected_hash, force=True)

    # Pinned issuer is the same
    assert first.pinned_issuer.Q_ca == second.pinned_issuer.Q_ca
    # But gateway keypair is different (extremely likely given random gen)
    assert first.gateway_identity.private_key != second.gateway_identity.private_key


# ---------------------------------------------------------------------------
# Load verification (both sections)
# ---------------------------------------------------------------------------

def test_load_after_bootstrap_roundtrip(valid_keystore, running_registry):
    _, issuer, _ = running_registry
    keystore = load_keystore(valid_keystore)
    assert keystore.pinned_issuer.Q_ca == issuer.Q_ca
    assert keystore.gateway_identity.private_key * G == keystore.gateway_identity.public_key


def test_load_rejects_missing_pinned_issuer(valid_keystore):
    data = json.loads(valid_keystore.read_text())
    del data["pinned_issuer"]
    valid_keystore.write_text(json.dumps(data))
    with pytest.raises(KeystoreCorruptedError, match="Missing section: pinned_issuer"):
        load_keystore(valid_keystore)


def test_load_rejects_missing_gateway_identity(valid_keystore):
    data = json.loads(valid_keystore.read_text())
    del data["gateway_identity"]
    valid_keystore.write_text(json.dumps(data))
    with pytest.raises(KeystoreCorruptedError, match="Missing section: gateway_identity"):
        load_keystore(valid_keystore)


def test_load_detects_tampered_q_ca(valid_keystore):
    different_issuer = issuer_generate_keypair()
    different_hex = point_to_compressed(different_issuer.Q_ca).hex()
    data = json.loads(valid_keystore.read_text())
    data["pinned_issuer"]["Q_ca_compressed_hex"] = different_hex
    valid_keystore.write_text(json.dumps(data))
    with pytest.raises(KeystoreCorruptedError, match="integrity check failed"):
        load_keystore(valid_keystore)


def test_load_detects_tampered_gateway_public_key(valid_keystore):
    """If attacker swaps gateway public key but keeps the private key,
    the integrity check (private_key * G == public_key) must fail."""
    different_keypair = _generate_gateway_identity(lifetime_days=90)
    different_pub_hex = point_to_compressed(different_keypair.public_key).hex()

    data = json.loads(valid_keystore.read_text())
    data["gateway_identity"]["public_key_compressed_hex"] = different_pub_hex
    valid_keystore.write_text(json.dumps(data))

    with pytest.raises(KeystoreCorruptedError, match="integrity check failed"):
        load_keystore(valid_keystore)


def test_load_detects_out_of_range_gateway_private_key(valid_keystore):
    data = json.loads(valid_keystore.read_text())
    data["gateway_identity"]["private_key_hex"] = "00" * 32   # zero = out of range
    valid_keystore.write_text(json.dumps(data))
    with pytest.raises(KeystoreCorruptedError, match="out of range"):
        load_keystore(valid_keystore)


def test_load_rejects_invalid_lifetime_days(valid_keystore):
    data = json.loads(valid_keystore.read_text())
    data["gateway_identity"]["lifetime_days"] = -5
    valid_keystore.write_text(json.dumps(data))
    with pytest.raises(KeystoreCorruptedError, match="lifetime_days"):
        load_keystore(valid_keystore)


def test_load_rejects_v1_keystore(valid_keystore):
    """A v1 keystore (no gateway_identity section) must be rejected."""
    data = json.loads(valid_keystore.read_text())
    data["version"] = 1
    valid_keystore.write_text(json.dumps(data))
    with pytest.raises(KeystoreCorruptedError, match="version"):
        load_keystore(valid_keystore)


def test_load_rejects_tofu_bootstrap_mode(valid_keystore):
    """DD-001 architectural invariant: TOFU must be rejected at load."""
    data = json.loads(valid_keystore.read_text())
    data["pinned_issuer"]["bootstrap_mode"] = "tofu"
    valid_keystore.write_text(json.dumps(data))
    with pytest.raises(KeystoreCorruptedError, match="Invalid bootstrap_mode"):
        load_keystore(valid_keystore)


# ---------------------------------------------------------------------------
# Re-fetch verification (signature adjusted to Keystore)
# ---------------------------------------------------------------------------

def test_verify_pin_against_remote_matches(valid_keystore, did_url):
    keystore = load_keystore(valid_keystore)
    assert verify_pin_against_remote(keystore, did_url) is True


def test_verify_pin_against_remote_mismatch_detected(valid_keystore, did_url):
    """Construct a keystore with a fake pinned hash; re-fetch returns False."""
    keystore = load_keystore(valid_keystore)
    tampered = Keystore(
        pinned_issuer=PinnedIssuer(
            issuer_did=keystore.pinned_issuer.issuer_did,
            Q_ca=keystore.pinned_issuer.Q_ca,
            Q_ca_hash_hex="ff" * 32,
            bootstrap_mode=keystore.pinned_issuer.bootstrap_mode,
            bootstrapped_at=keystore.pinned_issuer.bootstrapped_at,
        ),
        gateway_identity=keystore.gateway_identity,
    )
    assert verify_pin_against_remote(tampered, did_url) is False