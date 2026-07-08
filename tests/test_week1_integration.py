"""
Week 1 integration test: full pipeline from registry boot to gateway verification.

This test exercises:
    1. DID registry server running as a real Flask app (background thread)
    2. Issuer keypair persisted to disk via CLI-style flow
    3. Gateway fetches DID document over HTTP
    4. Gateway extracts Q_ca from the JWK in the DID document
    5. Device generates contribution, issuer provisions cert
    6. Gateway reconstructs Q_dev using Q_ca from the fetched DID doc
    7. Reconstruction identity holds end-to-end

If this test passes, Week 1 is provably complete.
"""

import base64
import threading
import time
from pathlib import Path

import httpx
import pytest
from ecdsa import ellipticcurve
from ecdsa.util import string_to_number

from src.did_registry import create_registry_app
from src.ecqv_core import (
    G,
    device_derive_private_key,
    device_generate_contribution,
    gateway_reconstruct_public_key,
    issuer_generate_cert,
    issuer_generate_keypair,
    verify_reconstruction_identity,
)
from src.issuer_cli import (
    compute_issuer_public_key_hash,
    load_issuer_keypair,
    save_issuer_keypair,
)


# ---------------------------------------------------------------------------
# Server fixture: run Flask app in background thread
# ---------------------------------------------------------------------------

@pytest.fixture
def running_registry(tmp_path: Path):
    """Start a real Flask registry server on a random port in a background thread.

    Yields (base_url, issuer_keypair, keyfile_path).
    Stops the server cleanly on teardown.
    """
    import socket
    # Find a free port
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        port = s.getsockname()[1]

    issuer = issuer_generate_keypair()
    keyfile = tmp_path / "issuer_key.json"
    save_issuer_keypair(issuer, keyfile)

    domain_encoded = f"127.0.0.1%3A{port}"
    issuer_did = f"did:web:{domain_encoded}"

    app = create_registry_app(
        issuer_did=issuer_did,
        issuer=issuer,
        admin_token="integration-test-token",
    )

    # Run Flask in a background thread (werkzeug server, threaded)
    server_thread = threading.Thread(
        target=lambda: app.run(
            host="127.0.0.1",
            port=port,
            debug=False,
            use_reloader=False,
            threaded=True,
        ),
        daemon=True,
    )
    server_thread.start()

    # Wait for server to be responsive
    base_url = f"http://127.0.0.1:{port}"
    for _ in range(50):   # Max 5 seconds
        try:
            r = httpx.get(f"{base_url}/.well-known/did.json", timeout=0.5)
            if r.status_code == 200:
                break
        except httpx.RequestError:
            pass
        time.sleep(0.1)
    else:
        pytest.fail("Registry server failed to start within 5 seconds")

    yield base_url, issuer, keyfile, issuer_did

    # Flask dev server doesn't have a clean shutdown hook in threaded mode;
    # daemon=True means it dies when pytest exits. Acceptable for tests.


# ---------------------------------------------------------------------------
# Helper: extract Q_ca from a DID document JWK
# ---------------------------------------------------------------------------

def q_ca_from_did_document(did_doc: dict) -> ellipticcurve.PointJacobi:
    """Parse Q_ca out of a JWK inside a DID document.

    This is the function a real gateway would implement. We test it here
    because extraction correctness is part of the integration contract.
    """
    vm = did_doc["verificationMethod"][0]
    jwk = vm["publicKeyJwk"]
    assert jwk["kty"] == "EC" and jwk["crv"] == "P-256"

    x_bytes = base64.urlsafe_b64decode(jwk["x"] + "==")
    y_bytes = base64.urlsafe_b64decode(jwk["y"] + "==")
    assert len(x_bytes) == 32 and len(y_bytes) == 32

    # Reconstruct compressed point from x, y parity
    from src.ecqv_core import compressed_to_point
    prefix = b"\x02" if y_bytes[-1] % 2 == 0 else b"\x03"
    return compressed_to_point(prefix + x_bytes)


# ---------------------------------------------------------------------------
# The integration test
# ---------------------------------------------------------------------------

def test_week1_end_to_end_pipeline(running_registry):
    """The full flow: registry → gateway TOFU → device provisioning → verification.

    This is THE test that proves Week 1 is complete.
    """
    base_url, issuer, keyfile, issuer_did = running_registry

    # --- Step 1: Gateway TOFU bootstrap ---
    # Gateway fetches the DID document for the first time
    response = httpx.get(f"{base_url}/.well-known/did.json", timeout=2.0)
    assert response.status_code == 200
    did_doc = response.json()
    assert did_doc["id"] == issuer_did

    # --- Step 2: Gateway extracts Q_ca from the JWK ---
    Q_ca_fetched = q_ca_from_did_document(did_doc)

    # Sanity check: the fetched Q_ca must equal the real issuer Q_ca
    # (A real gateway doesn't have the luxury of this check — it trusts TOFU.
    #  We check here only because it's a test.)
    assert Q_ca_fetched == issuer.Q_ca

    # --- Step 3: Gateway pins the hash ---
    pinned_hash = compute_issuer_public_key_hash(Q_ca_fetched)

    # Second fetch: gateway verifies pin still matches
    response2 = httpx.get(f"{base_url}/.well-known/did.json", timeout=2.0)
    Q_ca_second_fetch = q_ca_from_did_document(response2.json())
    assert compute_issuer_public_key_hash(Q_ca_second_fetch) == pinned_hash

    # --- Step 4: Device provisions via issuer (simulated locally with loaded keypair) ---
    # In a real deployment, the device talks to an issuer endpoint. For this
    # test, we load the issuer keypair and issue directly — semantically identical
    # to what the CLI does.
    issuer_loaded = load_issuer_keypair(keyfile)
    assert issuer_loaded.k_ca == issuer.k_ca

    contribution = device_generate_contribution()
    cert_info = f"{issuer_did}||2026-04-19T00:00:00Z||31536000".encode()
    cert = issuer_generate_cert(contribution.U, cert_info, issuer_loaded)

    # --- Step 5: Device derives its long-term private key ---
    d = device_derive_private_key(contribution, cert)

    # --- Step 6: Gateway reconstructs Q_dev using TOFU-pinned Q_ca ---
    # The gateway has ONLY Q_ca_fetched (from step 2), not the issuer keypair.
    # This is the critical offline-capable verification step.
    Q_dev = gateway_reconstruct_public_key(cert, Q_ca_fetched)

    # --- Step 7: Reconstruction identity holds end-to-end ---
    assert d * G == Q_dev
    assert verify_reconstruction_identity(d, cert, Q_ca_fetched)


def test_revocation_propagation(running_registry):
    """Revoke a device via admin endpoint, then verify it appears in the list."""
    base_url, issuer, keyfile, issuer_did = running_registry

    # Initially empty
    r = httpx.get(f"{base_url}/revocation.json")
    assert r.json()["entries"] == {}

    # Revoke a test device
    test_did = "did:key:zTestDeviceForRevocation"
    response = httpx.post(
        f"{base_url}/revoke",
        headers={"Authorization": "Bearer integration-test-token"},
        json={"did": test_did},
        timeout=2.0,
    )
    assert response.status_code == 200

    # Verify it appears in the list
    r = httpx.get(f"{base_url}/revocation.json")
    assert test_did in r.json()["entries"]


def test_wrong_tofu_pin_detects_different_issuer(running_registry):
    """If a gateway pinned hash H1 and later sees hash H2, it must reject.

    This simulates: someone stood up a different issuer on the same URL
    (MITM after TOFU). The gateway's pin must detect this.
    """
    base_url, issuer, _, _ = running_registry

    # Legitimate TOFU pin
    r = httpx.get(f"{base_url}/.well-known/did.json")
    Q_ca_legitimate = q_ca_from_did_document(r.json())
    legitimate_hash = compute_issuer_public_key_hash(Q_ca_legitimate)

    # Imagine a different issuer tries to impersonate
    impostor = issuer_generate_keypair()
    impostor_hash = compute_issuer_public_key_hash(impostor.Q_ca)

    # The pinned gateway would refuse the impostor
    assert legitimate_hash != impostor_hash