"""
DID Registry: HTTP server hosting the issuer's did:web document and revocation list.

Endpoints:
    GET /.well-known/did.json   — Issuer's DID Document (contains Q_ca as JWK)
    GET /revocation.json         — List of revoked device DIDs with timestamps
    POST /revoke                 — Admin endpoint to revoke a device (test/demo only)

The gateway fetches /.well-known/did.json once at bootstrap (TOFU), extracts Q_ca,
and pins the hash. Subsequent device authentications verify against the pinned Q_ca
without re-fetching the DID document.

The gateway periodically polls /revocation.json to maintain fresh revocation state.
The three states (ONLINE / GRACE / OFFLINE) are implemented in revocation_sync.py;
this module just serves the data.

Security note: In production, this server MUST serve over HTTPS (per W3C did:web spec).
For Cooja simulation and local development, HTTP on localhost is acceptable. The TOFU
pinning step binds the gateway to the specific Q_ca it sees on first contact, so
MITM on first contact is the trust assumption.
"""

import base64
import hashlib
import json
import threading
from datetime import datetime, timezone
from typing import Optional

from ecdsa import ellipticcurve
from ecdsa.util import number_to_string
from flask import Flask, jsonify, request, abort

from src.did_utils import construct_did_web, encode_did_key
from src.ecqv_core import IssuerKeypair, N


# ---------------------------------------------------------------------------
# JWK encoding for P-256
# ---------------------------------------------------------------------------

def _base64url_encode(data: bytes) -> str:
    """Base64url encoding per RFC 7515 (no padding)."""
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")


def public_key_to_jwk(public_key: ellipticcurve.PointJacobi,
                      key_id: Optional[str] = None) -> dict:
    """Encode a P-256 public key as a JWK (RFC 7517).

    Format:
        {
            "kty": "EC",
            "crv": "P-256",
            "x":  base64url(x_coordinate),
            "y":  base64url(y_coordinate),
            "kid": optional key identifier
        }

    The x and y coordinates are 32-byte big-endian integers, base64url-encoded.
    """
    x_bytes = number_to_string(public_key.x(), N)
    y_bytes = number_to_string(public_key.y(), N)

    jwk = {
        "kty": "EC",
        "crv": "P-256",
        "x": _base64url_encode(x_bytes),
        "y": _base64url_encode(y_bytes),
    }
    if key_id:
        jwk["kid"] = key_id
    return jwk


# ---------------------------------------------------------------------------
# DID Document construction
# ---------------------------------------------------------------------------

def build_did_document(issuer_did: str,
                       issuer_public_key: ellipticcurve.PointJacobi) -> dict:
    """Construct a W3C-compliant DID Document for the issuer.

    The document declares:
        - The DID itself (@context, id)
        - A verification method (the issuer's public key as JWK)
        - The assertion method (which keys can sign credentials)

    This is the minimal valid DID Document. Production systems would add
    service endpoints, key rotation history, etc.
    """
    key_id = f"{issuer_did}#key-1"

    return {
        "@context": [
            "https://www.w3.org/ns/did/v1",
            "https://w3id.org/security/suites/jws-2020/v1",
        ],
        "id": issuer_did,
        "verificationMethod": [
            {
                "id": key_id,
                "type": "JsonWebKey2020",
                "controller": issuer_did,
                "publicKeyJwk": public_key_to_jwk(issuer_public_key, key_id=key_id),
            }
        ],
        "assertionMethod": [key_id],
        "authentication": [key_id],
    }


def compute_did_document_hash(did_document: dict) -> str:
    """Compute SHA-256 hash of the canonical DID document.

    The gateway uses this hash for TOFU pinning: it stores the hash on first
    contact and verifies subsequent fetches match (detecting tampering).

    Canonicalization: sort keys alphabetically, compact JSON encoding.
    Full RFC 8785 JCS canonicalization would be more robust but overkill here.
    """
    canonical = json.dumps(did_document, sort_keys=True, separators=(",", ":"))
    return hashlib.sha256(canonical.encode("utf-8")).hexdigest()


# ---------------------------------------------------------------------------
# Revocation list
# ---------------------------------------------------------------------------

class RevocationList:
    """Thread-safe in-memory revocation list.

    Stores revoked device DIDs with revocation timestamps. In production this
    would be signed by the issuer and stored persistently. For FYP scale,
    in-memory is fine — the issuer process is single-origin.
    """

    def __init__(self):
        self._revoked: dict[str, str] = {}   # did → ISO8601 timestamp
        self._lock = threading.Lock()

    def revoke(self, device_did: str) -> None:
        with self._lock:
            self._revoked[device_did] = datetime.now(timezone.utc).isoformat()

    def unrevoke(self, device_did: str) -> None:
        with self._lock:
            self._revoked.pop(device_did, None)

    def is_revoked(self, device_did: str) -> bool:
        with self._lock:
            return device_did in self._revoked

    def to_dict(self) -> dict:
        with self._lock:
            return {
                "revoked_at": datetime.now(timezone.utc).isoformat(),
                "entries": dict(self._revoked),
            }


# ---------------------------------------------------------------------------
# Flask application factory
# ---------------------------------------------------------------------------

def create_registry_app(issuer_did: str,
                        issuer: IssuerKeypair,
                        revocation_list: Optional[RevocationList] = None,
                        admin_token: Optional[str] = None) -> Flask:
    """Build a Flask application serving the issuer's DID registry.

    Args:
        issuer_did:       The issuer's DID (e.g., "did:web:localhost%3A5000")
        issuer:           The issuer's keypair (only Q_ca is exposed)
        revocation_list:  Optional shared revocation list; created if None
        admin_token:      Token required for /revoke endpoint; if None, /revoke
                          is disabled entirely

    Returns a Flask app ready to be run. The caller is responsible for choosing
    host, port, and (in production) TLS configuration.
    """
    app = Flask(__name__)
    app.config["ISSUER_DID"] = issuer_did
    app.config["REVOCATION"] = revocation_list or RevocationList()

    did_document = build_did_document(issuer_did, issuer.Q_ca)

    @app.route("/.well-known/did.json", methods=["GET"])
    def get_did_document():
        return jsonify(did_document)

    @app.route("/revocation.json", methods=["GET"])
    def get_revocation_list():
        return jsonify(app.config["REVOCATION"].to_dict())

    if admin_token:
        @app.route("/revoke", methods=["POST"])
        def revoke_device():
            token = request.headers.get("Authorization", "").replace("Bearer ", "")
            if token != admin_token:
                abort(401, description="Invalid admin token")

            data = request.get_json(silent=True) or {}
            device_did = data.get("did")
            if not device_did or not device_did.startswith("did:"):
                abort(400, description="Missing or invalid 'did' field")

            app.config["REVOCATION"].revoke(device_did)
            return jsonify({"status": "revoked", "did": device_did}), 200

    return app


# ---------------------------------------------------------------------------
# Standalone runner (for manual testing)
# ---------------------------------------------------------------------------

def run_registry_standalone(host: str = "127.0.0.1",
                            port: int = 5000,
                            admin_token: str = "dev-admin-token",
                            keyfile: str = "./issuer_key.json") -> None:
    """Run the registry as a standalone process, loading issuer from disk.

    Loads the issuer keypair from the same file used by issuer_cli.py, so
    the CLI and the registry agree on Q_ca.
    """
    from pathlib import Path
    from src.issuer_cli import load_issuer_keypair

    keyfile_path = Path(keyfile)
    if not keyfile_path.exists():
        print(f"ERROR: issuer keyfile not found at {keyfile_path}")
        print("Run: python3 -m src.issuer_cli --keyfile ./issuer_key.json init --domain ...")
        return

    issuer = load_issuer_keypair(keyfile_path)

    host_encoded = f"{host}%3A{port}" if port != 443 else host
    issuer_did = f"did:web:{host_encoded}"

    app = create_registry_app(issuer_did, issuer, admin_token=admin_token)
    print(f"Starting DID registry at http://{host}:{port}")
    print(f"  Issuer DID: {issuer_did}")
    print(f"  Issuer keyfile: {keyfile_path}")
    print(f"  DID doc:    http://{host}:{port}/.well-known/did.json")
    print(f"  Revocation: http://{host}:{port}/revocation.json")
    print(f"  Admin token: {admin_token}")
    
    app.run(host=host, port=port, debug=False)

if __name__ == "__main__":
    run_registry_standalone()