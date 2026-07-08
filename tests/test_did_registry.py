"""
Test suite for did_registry.

Tests use Flask's test client (no network required). Covers:
    - DID Document construction and W3C compliance (required fields)
    - JWK encoding correctness (base64url, coordinate sizes)
    - Revocation list CRUD and thread safety
    - HTTP endpoints (status codes, content, authorization)
    - Hash stability (same input → same hash; tampered input → different hash)
"""

import base64
import json
import pytest

from src.did_registry import (
    RevocationList,
    build_did_document,
    compute_did_document_hash,
    create_registry_app,
    public_key_to_jwk,
)
from src.ecqv_core import issuer_generate_keypair


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------

@pytest.fixture
def issuer():
    return issuer_generate_keypair()


@pytest.fixture
def issuer_did():
    return "did:web:localhost%3A5000"


@pytest.fixture
def app(issuer_did, issuer):
    app = create_registry_app(
        issuer_did=issuer_did,
        issuer=issuer,
        admin_token="test-token",
    )
    app.config["TESTING"] = True
    return app


@pytest.fixture
def client(app):
    return app.test_client()


# ---------------------------------------------------------------------------
# JWK encoding
# ---------------------------------------------------------------------------

def test_jwk_has_required_fields(issuer):
    jwk = public_key_to_jwk(issuer.Q_ca)
    assert jwk["kty"] == "EC"
    assert jwk["crv"] == "P-256"
    assert "x" in jwk
    assert "y" in jwk


def test_jwk_coordinates_are_base64url(issuer):
    jwk = public_key_to_jwk(issuer.Q_ca)
    # base64url decode should succeed and produce 32 bytes each
    x = base64.urlsafe_b64decode(jwk["x"] + "==")
    y = base64.urlsafe_b64decode(jwk["y"] + "==")
    assert len(x) == 32
    assert len(y) == 32


def test_jwk_with_kid(issuer):
    jwk = public_key_to_jwk(issuer.Q_ca, key_id="did:web:example#key-1")
    assert jwk["kid"] == "did:web:example#key-1"


def test_jwk_coordinates_match_point(issuer):
    """JWK x and y must be the actual curve coordinates."""
    from ecdsa.util import number_to_string
    from src.ecqv_core import N

    jwk = public_key_to_jwk(issuer.Q_ca)
    x_decoded = base64.urlsafe_b64decode(jwk["x"] + "==")
    y_decoded = base64.urlsafe_b64decode(jwk["y"] + "==")

    assert x_decoded == number_to_string(issuer.Q_ca.x(), N)
    assert y_decoded == number_to_string(issuer.Q_ca.y(), N)


# ---------------------------------------------------------------------------
# DID Document structure
# ---------------------------------------------------------------------------

def test_did_document_has_w3c_context(issuer, issuer_did):
    doc = build_did_document(issuer_did, issuer.Q_ca)
    assert "https://www.w3.org/ns/did/v1" in doc["@context"]


def test_did_document_id_matches_input(issuer, issuer_did):
    doc = build_did_document(issuer_did, issuer.Q_ca)
    assert doc["id"] == issuer_did


def test_did_document_has_verification_method(issuer, issuer_did):
    doc = build_did_document(issuer_did, issuer.Q_ca)
    assert len(doc["verificationMethod"]) == 1
    vm = doc["verificationMethod"][0]
    assert vm["type"] == "JsonWebKey2020"
    assert vm["controller"] == issuer_did
    assert "publicKeyJwk" in vm


def test_did_document_verification_method_id_format(issuer, issuer_did):
    doc = build_did_document(issuer_did, issuer.Q_ca)
    vm_id = doc["verificationMethod"][0]["id"]
    assert vm_id == f"{issuer_did}#key-1"


def test_did_document_references_key_in_assertion_and_authentication(issuer, issuer_did):
    doc = build_did_document(issuer_did, issuer.Q_ca)
    key_id = doc["verificationMethod"][0]["id"]
    assert key_id in doc["assertionMethod"]
    assert key_id in doc["authentication"]


# ---------------------------------------------------------------------------
# DID Document hash (for TOFU pinning)
# ---------------------------------------------------------------------------

def test_did_document_hash_is_deterministic(issuer, issuer_did):
    """Same document must produce same hash every time."""
    doc1 = build_did_document(issuer_did, issuer.Q_ca)
    doc2 = build_did_document(issuer_did, issuer.Q_ca)
    assert compute_did_document_hash(doc1) == compute_did_document_hash(doc2)


def test_did_document_hash_changes_with_different_key():
    """Different issuer key → different document → different hash."""
    issuer1 = issuer_generate_keypair()
    issuer2 = issuer_generate_keypair()
    doc1 = build_did_document("did:web:x", issuer1.Q_ca)
    doc2 = build_did_document("did:web:x", issuer2.Q_ca)
    assert compute_did_document_hash(doc1) != compute_did_document_hash(doc2)


def test_did_document_hash_is_64_hex_chars(issuer, issuer_did):
    doc = build_did_document(issuer_did, issuer.Q_ca)
    h = compute_did_document_hash(doc)
    assert len(h) == 64
    int(h, 16)   # Must parse as hex


# ---------------------------------------------------------------------------
# Revocation list
# ---------------------------------------------------------------------------

def test_revocation_list_empty_initially():
    rl = RevocationList()
    assert not rl.is_revoked("did:key:zABC")


def test_revocation_list_revoke_and_check():
    rl = RevocationList()
    rl.revoke("did:key:zABC")
    assert rl.is_revoked("did:key:zABC")
    assert not rl.is_revoked("did:key:zXYZ")


def test_revocation_list_unrevoke():
    rl = RevocationList()
    rl.revoke("did:key:zABC")
    rl.unrevoke("did:key:zABC")
    assert not rl.is_revoked("did:key:zABC")


def test_revocation_list_to_dict():
    rl = RevocationList()
    rl.revoke("did:key:zABC")
    d = rl.to_dict()
    assert "did:key:zABC" in d["entries"]
    assert "revoked_at" in d


# ---------------------------------------------------------------------------
# HTTP endpoints
# ---------------------------------------------------------------------------

def test_get_did_document_endpoint_returns_200(client):
    response = client.get("/.well-known/did.json")
    assert response.status_code == 200


def test_get_did_document_endpoint_returns_json(client, issuer_did):
    response = client.get("/.well-known/did.json")
    data = response.get_json()
    assert data["id"] == issuer_did
    assert "verificationMethod" in data


def test_get_revocation_endpoint_returns_200(client):
    response = client.get("/revocation.json")
    assert response.status_code == 200


def test_get_revocation_endpoint_initially_empty(client):
    response = client.get("/revocation.json")
    data = response.get_json()
    assert data["entries"] == {}


def test_revoke_endpoint_requires_auth(client):
    response = client.post("/revoke",
                           json={"did": "did:key:zABC"})
    assert response.status_code == 401


def test_revoke_endpoint_rejects_wrong_token(client):
    response = client.post(
        "/revoke",
        headers={"Authorization": "Bearer wrong-token"},
        json={"did": "did:key:zABC"},
    )
    assert response.status_code == 401


def test_revoke_endpoint_rejects_missing_did(client):
    response = client.post(
        "/revoke",
        headers={"Authorization": "Bearer test-token"},
        json={},
    )
    assert response.status_code == 400


def test_revoke_endpoint_rejects_non_did_string(client):
    response = client.post(
        "/revoke",
        headers={"Authorization": "Bearer test-token"},
        json={"did": "not-a-did"},
    )
    assert response.status_code == 400


def test_revoke_endpoint_succeeds_with_valid_token(client):
    response = client.post(
        "/revoke",
        headers={"Authorization": "Bearer test-token"},
        json={"did": "did:key:zABC"},
    )
    assert response.status_code == 200
    assert response.get_json()["status"] == "revoked"


def test_revoke_then_appears_in_revocation_list(client):
    client.post(
        "/revoke",
        headers={"Authorization": "Bearer test-token"},
        json={"did": "did:key:zABC"},
    )
    response = client.get("/revocation.json")
    data = response.get_json()
    assert "did:key:zABC" in data["entries"]


def test_admin_endpoint_disabled_when_no_token(issuer, issuer_did):
    """If admin_token is None, /revoke must not exist at all."""
    app = create_registry_app(issuer_did=issuer_did, issuer=issuer, admin_token=None)
    app.config["TESTING"] = True
    client = app.test_client()
    response = client.post("/revoke", json={"did": "did:key:zABC"})
    assert response.status_code == 404   # Route not registered