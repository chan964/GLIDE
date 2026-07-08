"""
Gateway keystore: persistent storage for both the pinned issuer and the
gateway's own long-term identity keypair.

Two distinct responsibilities:

1. **Pinned issuer** (existing): Q_ca pinned via operator-distributed hash,
   used to reconstruct and verify device certificates. See DD-001.

2. **Gateway identity** (new in v2): long-term ECDSA keypair the gateway uses
   to authenticate itself to devices during EDHOC handshake. Persisted with
   lifetime; rotation is manual (operator re-initializes). See DD-003.

Storage format (JSON file, mode 0600) — keystore version 2:
    {
        "version": 2,
        "pinned_issuer": {
            "issuer_did": "did:web:...",
            "Q_ca_compressed_hex": "02...",
            "Q_ca_hash_sha256": "...",
            "bootstrap_mode": "pinned",
            "bootstrapped_at": "..."
        },
        "gateway_identity": {
            "private_key_hex": "<32-byte scalar>",
            "public_key_compressed_hex": "<33-byte compressed point>",
            "created_at": "...",
            "expires_at": "...",
            "lifetime_days": 90
        }
    }
"""

import base64
import hashlib
import json
import secrets
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Optional

import httpx
from ecdsa import ellipticcurve
from ecdsa.util import number_to_string, string_to_number

from src.ecqv_core import (
    G,
    N,
    compressed_to_point,
    point_to_compressed,
)


KEYSTORE_VERSION = 2
DEFAULT_GATEWAY_KEY_LIFETIME_DAYS = 90


# ---------------------------------------------------------------------------
# Exceptions
# ---------------------------------------------------------------------------

class KeystoreError(Exception):
    """Base class for keystore errors."""


class KeystoreNotFoundError(KeystoreError):
    """Keystore file does not exist."""


class KeystoreCorruptedError(KeystoreError):
    """Keystore file exists but integrity check failed."""


class TofuMismatchError(KeystoreError):
    """Pinned hash does not match expected hash during strict bootstrap."""


class AlreadyBootstrappedError(KeystoreError):
    """Attempt to re-bootstrap an already-pinned keystore."""


class GatewayKeyExpiredError(KeystoreError):
    """Gateway's long-term keypair has exceeded its lifetime."""


# ---------------------------------------------------------------------------
# Data containers
# ---------------------------------------------------------------------------

@dataclass(frozen=True)
class PinnedIssuer:
    """The pinned issuer identity (existing)."""
    issuer_did: str
    Q_ca: ellipticcurve.PointJacobi
    Q_ca_hash_hex: str
    bootstrap_mode: str   # Always "pinned" in this implementation
    bootstrapped_at: str


@dataclass(frozen=True)
class GatewayIdentity:
    """The gateway's own long-term ECDSA keypair (new in v2).

    Used to sign EDHOC MSG_2, authenticating the gateway to the device.
    Devices are pre-provisioned with the gateway's public key at factory time.

    Lifetime is advisory: expiry causes warnings but not operational failure.
    Manual rotation (re-initialization) is an operator procedure (DD-003).
    """
    private_key: int                              # scalar in [1, n-1]
    public_key: ellipticcurve.PointJacobi         # public_key = private_key * G
    created_at: datetime
    expires_at: datetime
    lifetime_days: int

    def is_expired(self, now: Optional[datetime] = None) -> bool:
        if now is None:
            now = datetime.now(timezone.utc)
        return now > self.expires_at

    def time_until_expiry(self, now: Optional[datetime] = None) -> timedelta:
        if now is None:
            now = datetime.now(timezone.utc)
        return self.expires_at - now


@dataclass(frozen=True)
class Keystore:
    """Complete keystore contents: pinned issuer + gateway identity."""
    pinned_issuer: PinnedIssuer
    gateway_identity: GatewayIdentity


# ---------------------------------------------------------------------------
# Helpers (pinned issuer — unchanged)
# ---------------------------------------------------------------------------

def _compute_q_ca_hash(Q_ca: ellipticcurve.PointJacobi) -> str:
    return hashlib.sha256(point_to_compressed(Q_ca)).hexdigest()


def _extract_q_ca_from_did_document(did_doc: dict) -> ellipticcurve.PointJacobi:
    try:
        vm_list = did_doc["verificationMethod"]
        if not vm_list:
            raise KeystoreCorruptedError("DID document has empty verificationMethod")
        jwk = vm_list[0]["publicKeyJwk"]
    except (KeyError, TypeError) as e:
        raise KeystoreCorruptedError(f"Malformed DID document: {e}") from e

    if jwk.get("kty") != "EC" or jwk.get("crv") != "P-256":
        raise KeystoreCorruptedError(
            f"JWK is not P-256: kty={jwk.get('kty')} crv={jwk.get('crv')}"
        )

    try:
        x_bytes = base64.urlsafe_b64decode(jwk["x"] + "==")
        y_bytes = base64.urlsafe_b64decode(jwk["y"] + "==")
    except Exception as e:
        raise KeystoreCorruptedError(f"JWK base64 decode failed: {e}") from e

    if len(x_bytes) != 32 or len(y_bytes) != 32:
        raise KeystoreCorruptedError(
            f"JWK coordinates wrong size: x={len(x_bytes)} y={len(y_bytes)}"
        )

    prefix = b"\x02" if y_bytes[-1] % 2 == 0 else b"\x03"
    try:
        return compressed_to_point(prefix + x_bytes)
    except ValueError as e:
        raise KeystoreCorruptedError(f"JWK does not decode to valid point: {e}") from e


def _fetch_did_document(did_url: str, timeout: float = 5.0) -> dict:
    try:
        response = httpx.get(did_url, timeout=timeout)
        response.raise_for_status()
    except httpx.RequestError as e:
        raise KeystoreError(f"Failed to fetch DID document from {did_url}: {e}") from e
    except httpx.HTTPStatusError as e:
        raise KeystoreError(
            f"DID document fetch returned {e.response.status_code}"
        ) from e

    try:
        return response.json()
    except ValueError as e:
        raise KeystoreError(f"DID document is not valid JSON: {e}") from e


# ---------------------------------------------------------------------------
# Gateway identity generation (new in v2)
# ---------------------------------------------------------------------------

def _generate_gateway_identity(
    lifetime_days: int = DEFAULT_GATEWAY_KEY_LIFETIME_DAYS,
    now: Optional[datetime] = None,
) -> GatewayIdentity:
    """Generate a fresh gateway keypair with the given lifetime."""
    if lifetime_days <= 0:
        raise ValueError(f"lifetime_days must be positive, got {lifetime_days}")

    if now is None:
        now = datetime.now(timezone.utc)

    private_key = secrets.randbelow(N - 1) + 1   # uniform in [1, n-1]
    public_key = private_key * G

    return GatewayIdentity(
        private_key=private_key,
        public_key=public_key,
        created_at=now,
        expires_at=now + timedelta(days=lifetime_days),
        lifetime_days=lifetime_days,
    )


# ---------------------------------------------------------------------------
# Keystore file I/O (v2: now serializes both pinned_issuer and gateway_identity)
# ---------------------------------------------------------------------------

def _serialize_pinned_issuer(pinned: PinnedIssuer) -> dict:
    return {
        "issuer_did": pinned.issuer_did,
        "Q_ca_compressed_hex": point_to_compressed(pinned.Q_ca).hex(),
        "Q_ca_hash_sha256": pinned.Q_ca_hash_hex,
        "bootstrap_mode": pinned.bootstrap_mode,
        "bootstrapped_at": pinned.bootstrapped_at,
    }


def _serialize_gateway_identity(identity: GatewayIdentity) -> dict:
    return {
        "private_key_hex": number_to_string(identity.private_key, N).hex(),
        "public_key_compressed_hex": point_to_compressed(identity.public_key).hex(),
        "created_at": identity.created_at.isoformat(),
        "expires_at": identity.expires_at.isoformat(),
        "lifetime_days": identity.lifetime_days,
    }


def _write_keystore(path: Path, keystore: Keystore) -> None:
    data = {
        "version": KEYSTORE_VERSION,
        "pinned_issuer": _serialize_pinned_issuer(keystore.pinned_issuer),
        "gateway_identity": _serialize_gateway_identity(keystore.gateway_identity),
    }
    path.write_text(json.dumps(data, indent=2))
    path.chmod(0o600)


def _deserialize_pinned_issuer(data: dict) -> PinnedIssuer:
    required = ["issuer_did", "Q_ca_compressed_hex", "Q_ca_hash_sha256",
                "bootstrap_mode", "bootstrapped_at"]
    for field in required:
        if field not in data:
            raise KeystoreCorruptedError(f"pinned_issuer missing field: {field}")

    try:
        Q_ca_bytes = bytes.fromhex(data["Q_ca_compressed_hex"])
        Q_ca = compressed_to_point(Q_ca_bytes)
    except ValueError as e:
        raise KeystoreCorruptedError(f"Q_ca decode failed: {e}") from e

    recomputed = _compute_q_ca_hash(Q_ca)
    if recomputed != data["Q_ca_hash_sha256"]:
        raise KeystoreCorruptedError(
            f"pinned_issuer integrity check failed: stored hash "
            f"{data['Q_ca_hash_sha256'][:16]}... does not match recomputed "
            f"{recomputed[:16]}..."
        )

    if data["bootstrap_mode"] != "pinned":
        raise KeystoreCorruptedError(
            f"Invalid bootstrap_mode: {data['bootstrap_mode']!r} (expected 'pinned')"
        )

    return PinnedIssuer(
        issuer_did=data["issuer_did"],
        Q_ca=Q_ca,
        Q_ca_hash_hex=data["Q_ca_hash_sha256"],
        bootstrap_mode=data["bootstrap_mode"],
        bootstrapped_at=data["bootstrapped_at"],
    )


def _deserialize_gateway_identity(data: dict) -> GatewayIdentity:
    required = ["private_key_hex", "public_key_compressed_hex",
                "created_at", "expires_at", "lifetime_days"]
    for field in required:
        if field not in data:
            raise KeystoreCorruptedError(f"gateway_identity missing field: {field}")

    try:
        private_key_bytes = bytes.fromhex(data["private_key_hex"])
        if len(private_key_bytes) != 32:
            raise ValueError(f"private_key must be 32 bytes, got {len(private_key_bytes)}")
        private_key = string_to_number(private_key_bytes)
    except ValueError as e:
        raise KeystoreCorruptedError(f"Gateway private_key decode failed: {e}") from e

    if not (1 <= private_key < N):
        raise KeystoreCorruptedError("Gateway private_key out of range [1, n-1]")

    try:
        public_key_bytes = bytes.fromhex(data["public_key_compressed_hex"])
        public_key = compressed_to_point(public_key_bytes)
    except ValueError as e:
        raise KeystoreCorruptedError(f"Gateway public_key decode failed: {e}") from e

    # Verify public_key == private_key * G (detects file tampering)
    if private_key * G != public_key:
        raise KeystoreCorruptedError(
            "Gateway identity integrity check failed: "
            "public_key does not match private_key * G"
        )

    try:
        created_at = datetime.fromisoformat(data["created_at"])
        expires_at = datetime.fromisoformat(data["expires_at"])
    except (ValueError, TypeError) as e:
        raise KeystoreCorruptedError(f"Gateway timestamp parse failed: {e}") from e

    lifetime_days = data["lifetime_days"]
    if not isinstance(lifetime_days, int) or lifetime_days <= 0:
        raise KeystoreCorruptedError(
            f"Invalid lifetime_days: {lifetime_days!r}"
        )

    return GatewayIdentity(
        private_key=private_key,
        public_key=public_key,
        created_at=created_at,
        expires_at=expires_at,
        lifetime_days=lifetime_days,
    )


def load_keystore(path: Path) -> Keystore:
    """Load and verify both pinned issuer and gateway identity from disk."""
    if not path.exists():
        raise KeystoreNotFoundError(f"Keystore not found at {path}")

    try:
        data = json.loads(path.read_text())
    except json.JSONDecodeError as e:
        raise KeystoreCorruptedError(f"Keystore is not valid JSON: {e}") from e

    version = data.get("version")
    if version != KEYSTORE_VERSION:
        raise KeystoreCorruptedError(
            f"Unsupported keystore version: {version} (expected {KEYSTORE_VERSION})"
        )

    if "pinned_issuer" not in data:
        raise KeystoreCorruptedError("Missing section: pinned_issuer")
    if "gateway_identity" not in data:
        raise KeystoreCorruptedError("Missing section: gateway_identity")

    pinned = _deserialize_pinned_issuer(data["pinned_issuer"])
    identity = _deserialize_gateway_identity(data["gateway_identity"])

    return Keystore(pinned_issuer=pinned, gateway_identity=identity)


# ---------------------------------------------------------------------------
# Bootstrap — now creates BOTH pinned issuer AND gateway identity
# ---------------------------------------------------------------------------

def bootstrap_pinned(
    keystore_path: Path,
    did_url: str,
    expected_hash_hex: str,
    timeout: float = 5.0,
    force: bool = False,
    gateway_lifetime_days: int = DEFAULT_GATEWAY_KEY_LIFETIME_DAYS,
) -> Keystore:
    """Bootstrap gateway with pinned issuer AND fresh gateway identity.

    Performs two operations:
    1. Fetches issuer DID doc, verifies its hash matches expected, pins Q_ca
    2. Generates a fresh gateway long-term keypair with configurable lifetime

    Both are atomically persisted to the keystore file on success.

    Args (unchanged from v1):
        keystore_path:      Path where the keystore JSON file will be written.
        did_url:            URL to the issuer's DID document.
        expected_hash_hex:  64-hex SHA-256 of expected Q_ca (out-of-band).
        timeout:            HTTP fetch timeout.
        force:              Overwrite existing keystore if True.
    Args (new in v2):
        gateway_lifetime_days: How long the gateway keypair is valid (default 90).
    """
    if keystore_path.exists() and not force:
        raise AlreadyBootstrappedError(
            f"Keystore already exists at {keystore_path}. Use force=True to re-bootstrap."
        )

    expected_hash_hex = expected_hash_hex.lower().strip()
    if len(expected_hash_hex) != 64:
        raise ValueError(
            f"expected_hash_hex must be 64 hex chars, got {len(expected_hash_hex)}"
        )
    try:
        int(expected_hash_hex, 16)
    except ValueError:
        raise ValueError(f"expected_hash_hex is not valid hex: {expected_hash_hex!r}")

    did_doc = _fetch_did_document(did_url, timeout=timeout)
    Q_ca = _extract_q_ca_from_did_document(did_doc)

    actual_hash = _compute_q_ca_hash(Q_ca)
    if actual_hash != expected_hash_hex:
        raise TofuMismatchError(
            f"Q_ca hash mismatch during pinned bootstrap.\n"
            f"  Expected: {expected_hash_hex}\n"
            f"  Actual:   {actual_hash}\n"
            f"Refusing to pin."
        )

    issuer_did = did_doc.get("id", "")
    if not issuer_did:
        raise KeystoreCorruptedError("DID document missing 'id' field")

    pinned = PinnedIssuer(
        issuer_did=issuer_did,
        Q_ca=Q_ca,
        Q_ca_hash_hex=actual_hash,
        bootstrap_mode="pinned",
        bootstrapped_at=datetime.now(timezone.utc).isoformat(),
    )

    identity = _generate_gateway_identity(lifetime_days=gateway_lifetime_days)

    keystore = Keystore(pinned_issuer=pinned, gateway_identity=identity)
    _write_keystore(keystore_path, keystore)

    return keystore


# ---------------------------------------------------------------------------
# Re-fetch check (unchanged, but signature takes Keystore now)
# ---------------------------------------------------------------------------

def verify_pin_against_remote(
    keystore: Keystore,
    did_url: str,
    timeout: float = 5.0,
) -> bool:
    """Re-fetch the DID document and verify Q_ca still matches the pinned hash."""
    did_doc = _fetch_did_document(did_url, timeout=timeout)
    remote_Q_ca = _extract_q_ca_from_did_document(did_doc)
    remote_hash = _compute_q_ca_hash(remote_Q_ca)
    return remote_hash == keystore.pinned_issuer.Q_ca_hash_hex



# """
# Gateway keystore: persistent storage of the issuer public key, pinned via
# operator-distributed hash.

# Bootstrap mode: **strict pinning only**. The gateway operator must provide
# the expected SHA-256 hash of the issuer's public key via secure out-of-band
# channel before the gateway contacts the network. The keystore verifies the
# fetched DID document produces this hash; mismatches abort without pinning.

# We deliberately do NOT implement first-use trust (TOFU) as a standalone mode.
# TOFU alone is vulnerable to MITM on first contact, and exposing it as a
# callable function creates footgun risk. Operators requiring insecure
# first-use trust (e.g., for development or experimentation) can construct
# the keystore manually from a fetched DID document; we do not make this
# path convenient.

# See docs/THREAT_MODEL.md A4 and docs/DESIGN_DECISIONS.md DD-001 for the
# full rationale including why mTLS/X.509-based alternatives are not used.

# Storage format (JSON file, mode 0600):
#     {
#         "version": 1,
#         "issuer_did": "did:web:...",
#         "Q_ca_compressed_hex": "02ab...",
#         "Q_ca_hash_sha256": "abcdef...",
#         "bootstrap_mode": "pinned",
#         "bootstrapped_at": "2026-04-19T..."
#     }
# """

# import base64
# import hashlib
# import json
# from dataclasses import dataclass
# from datetime import datetime, timezone
# from pathlib import Path
# from typing import Optional

# import httpx
# from ecdsa import ellipticcurve

# from src.ecqv_core import (
#     compressed_to_point,
#     point_to_compressed,
# )


# KEYSTORE_VERSION = 1


# # ---------------------------------------------------------------------------
# # Exceptions (specific, so callers can handle distinctly)
# # ---------------------------------------------------------------------------

# class KeystoreError(Exception):
#     """Base class for keystore errors."""


# class KeystoreNotFoundError(KeystoreError):
#     """Keystore file does not exist."""


# class KeystoreCorruptedError(KeystoreError):
#     """Keystore file exists but integrity check failed."""


# class TofuMismatchError(KeystoreError):
#     """Pinned hash does not match expected hash during strict bootstrap."""


# class AlreadyBootstrappedError(KeystoreError):
#     """Attempt to re-bootstrap an already-pinned keystore."""


# # ---------------------------------------------------------------------------
# # Pinned data container
# # ---------------------------------------------------------------------------

# @dataclass(frozen=True)
# class PinnedIssuer:
#     """The result of a successful bootstrap. Immutable."""
#     issuer_did: str
#     Q_ca: ellipticcurve.PointJacobi
#     Q_ca_hash_hex: str
#     bootstrap_mode: str   # Always "pinned" in this implementation
#     bootstrapped_at: str  # ISO 8601 timestamp


# # ---------------------------------------------------------------------------
# # Helpers
# # ---------------------------------------------------------------------------

# def _compute_q_ca_hash(Q_ca: ellipticcurve.PointJacobi) -> str:
#     """SHA-256 of compressed Q_ca, hex-encoded. Used for pinning."""
#     return hashlib.sha256(point_to_compressed(Q_ca)).hexdigest()


# def _extract_q_ca_from_did_document(did_doc: dict) -> ellipticcurve.PointJacobi:
#     """Parse Q_ca from the first verificationMethod's JWK.

#     Expects a W3C-compliant DID Document with at least one verificationMethod
#     containing a P-256 publicKeyJwk. Raises KeystoreCorruptedError on any
#     structural problem.
#     """
#     try:
#         vm_list = did_doc["verificationMethod"]
#         if not vm_list:
#             raise KeystoreCorruptedError("DID document has empty verificationMethod")
#         jwk = vm_list[0]["publicKeyJwk"]
#     except (KeyError, TypeError) as e:
#         raise KeystoreCorruptedError(f"Malformed DID document: {e}") from e

#     if jwk.get("kty") != "EC" or jwk.get("crv") != "P-256":
#         raise KeystoreCorruptedError(
#             f"JWK is not P-256: kty={jwk.get('kty')} crv={jwk.get('crv')}"
#         )

#     try:
#         x_bytes = base64.urlsafe_b64decode(jwk["x"] + "==")
#         y_bytes = base64.urlsafe_b64decode(jwk["y"] + "==")
#     except Exception as e:
#         raise KeystoreCorruptedError(f"JWK base64 decode failed: {e}") from e

#     if len(x_bytes) != 32 or len(y_bytes) != 32:
#         raise KeystoreCorruptedError(
#             f"JWK coordinates wrong size: x={len(x_bytes)} y={len(y_bytes)}"
#         )

#     # Reconstruct compressed SEC1 from x + y parity
#     prefix = b"\x02" if y_bytes[-1] % 2 == 0 else b"\x03"
#     try:
#         return compressed_to_point(prefix + x_bytes)
#     except ValueError as e:
#         raise KeystoreCorruptedError(f"JWK does not decode to valid point: {e}") from e


# def _fetch_did_document(did_url: str, timeout: float = 5.0) -> dict:
#     """GET the DID document over HTTP.

#     In production, enforce HTTPS. For simulation, HTTP is acceptable because
#     pinning is the actual trust anchor, not the transport.
#     """
#     try:
#         response = httpx.get(did_url, timeout=timeout)
#         response.raise_for_status()
#     except httpx.RequestError as e:
#         raise KeystoreError(f"Failed to fetch DID document from {did_url}: {e}") from e
#     except httpx.HTTPStatusError as e:
#         raise KeystoreError(
#             f"DID document fetch returned {e.response.status_code}"
#         ) from e

#     try:
#         return response.json()
#     except ValueError as e:
#         raise KeystoreError(f"DID document is not valid JSON: {e}") from e


# # ---------------------------------------------------------------------------
# # Keystore file I/O
# # ---------------------------------------------------------------------------

# def _write_keystore(path: Path, pinned: PinnedIssuer) -> None:
#     """Serialize PinnedIssuer to disk with mode 0600."""
#     data = {
#         "version": KEYSTORE_VERSION,
#         "issuer_did": pinned.issuer_did,
#         "Q_ca_compressed_hex": point_to_compressed(pinned.Q_ca).hex(),
#         "Q_ca_hash_sha256": pinned.Q_ca_hash_hex,
#         "bootstrap_mode": pinned.bootstrap_mode,
#         "bootstrapped_at": pinned.bootstrapped_at,
#     }
#     path.write_text(json.dumps(data, indent=2))
#     path.chmod(0o600)


# def load_keystore(path: Path) -> PinnedIssuer:
#     """Load and verify the keystore from disk.

#     Verification:
#         - File exists
#         - Valid JSON
#         - Version matches KEYSTORE_VERSION
#         - All required fields present
#         - Q_ca decodes to a valid curve point
#         - Recomputed SHA-256(compressed Q_ca) matches stored hash
#         - bootstrap_mode is exactly "pinned" (rejects TOFU and any other value)

#     Any failure raises a specific exception; the gateway must refuse to
#     operate in any of these cases.
#     """
#     if not path.exists():
#         raise KeystoreNotFoundError(f"Keystore not found at {path}")

#     try:
#         data = json.loads(path.read_text())
#     except json.JSONDecodeError as e:
#         raise KeystoreCorruptedError(f"Keystore is not valid JSON: {e}") from e

#     # Version check
#     version = data.get("version")
#     if version != KEYSTORE_VERSION:
#         raise KeystoreCorruptedError(
#             f"Unsupported keystore version: {version} (expected {KEYSTORE_VERSION})"
#         )

#     required_fields = [
#         "issuer_did", "Q_ca_compressed_hex", "Q_ca_hash_sha256",
#         "bootstrap_mode", "bootstrapped_at",
#     ]
#     for field in required_fields:
#         if field not in data:
#             raise KeystoreCorruptedError(f"Missing field: {field}")

#     # Decode Q_ca and recompute hash
#     try:
#         Q_ca_bytes = bytes.fromhex(data["Q_ca_compressed_hex"])
#         Q_ca = compressed_to_point(Q_ca_bytes)
#     except ValueError as e:
#         raise KeystoreCorruptedError(f"Q_ca decode failed: {e}") from e

#     recomputed_hash = _compute_q_ca_hash(Q_ca)
#     stored_hash = data["Q_ca_hash_sha256"]
#     if recomputed_hash != stored_hash:
#         raise KeystoreCorruptedError(
#             f"Integrity check failed: stored hash {stored_hash[:16]}... "
#             f"does not match recomputed hash {recomputed_hash[:16]}..."
#         )

#     # Architectural invariant: only "pinned" is accepted.
#     # This is enforced at load time so that even manual file tampering
#     # (e.g., someone writes bootstrap_mode="tofu") is rejected.
#     if data["bootstrap_mode"] != "pinned":
#         raise KeystoreCorruptedError(
#             f"Invalid bootstrap_mode: {data['bootstrap_mode']!r} (expected 'pinned')"
#         )

#     return PinnedIssuer(
#         issuer_did=data["issuer_did"],
#         Q_ca=Q_ca,
#         Q_ca_hash_hex=stored_hash,
#         bootstrap_mode=data["bootstrap_mode"],
#         bootstrapped_at=data["bootstrapped_at"],
#     )


# # ---------------------------------------------------------------------------
# # Bootstrap (pinned only)
# # ---------------------------------------------------------------------------

# def bootstrap_pinned(keystore_path: Path,
#                      did_url: str,
#                      expected_hash_hex: str,
#                      timeout: float = 5.0,
#                      force: bool = False) -> PinnedIssuer:
#     """**The only supported bootstrap path.** Strong security via operator-
#     distributed hash.

#     The operator obtains the expected SHA-256 hash of the issuer's public key
#     through a secure out-of-band channel (deployment config, admin portal,
#     physical flashing) before the gateway contacts the network. This function
#     fetches the DID document, extracts Q_ca, hashes it, and compares against
#     the expected value. Mismatches abort without creating any keystore file.

#     This is the mitigation described in THREAT_MODEL.md A4 and the sole
#     bootstrap mode per DESIGN_DECISIONS.md DD-001. An attacker who intercepts
#     the DID document fetch cannot produce a Q_ca that hashes to the operator's
#     expected value without inverting SHA-256 or compromising the issuer's
#     private key.

#     Args:
#         keystore_path:      Path where the keystore JSON file will be written.
#         did_url:            HTTPS/HTTP URL to the issuer's DID document.
#         expected_hash_hex:  64 hex chars (SHA-256) of the expected Q_ca.
#                             Obtained out-of-band by the operator.
#         timeout:            Seconds before HTTP fetch times out.
#         force:              If True, overwrite existing keystore. Default False
#                             to prevent accidental re-pinning.

#     Raises:
#         AlreadyBootstrappedError: keystore exists and force=False
#         ValueError:               expected_hash_hex malformed
#         KeystoreError:            network fetch failed
#         TofuMismatchError:        fetched Q_ca's hash does not match expected
#         KeystoreCorruptedError:   DID document is malformed or missing fields
#     """
#     if keystore_path.exists() and not force:
#         raise AlreadyBootstrappedError(
#             f"Keystore already exists at {keystore_path}. "
#             f"Use force=True to re-bootstrap."
#         )

#     expected_hash_hex = expected_hash_hex.lower().strip()
#     if len(expected_hash_hex) != 64:
#         raise ValueError(
#             f"expected_hash_hex must be 64 hex chars (SHA-256), "
#             f"got {len(expected_hash_hex)}"
#         )
#     # Validate it's actually hex
#     try:
#         int(expected_hash_hex, 16)
#     except ValueError:
#         raise ValueError(
#             f"expected_hash_hex is not valid hexadecimal: {expected_hash_hex!r}"
#         )

#     did_doc = _fetch_did_document(did_url, timeout=timeout)
#     Q_ca = _extract_q_ca_from_did_document(did_doc)

#     actual_hash = _compute_q_ca_hash(Q_ca)
#     if actual_hash != expected_hash_hex:
#         raise TofuMismatchError(
#             f"Q_ca hash mismatch during pinned bootstrap.\n"
#             f"  Expected: {expected_hash_hex}\n"
#             f"  Actual:   {actual_hash}\n"
#             f"Refusing to pin. Either the DID document was tampered with, "
#             f"or the expected hash was incorrectly configured."
#         )

#     issuer_did = did_doc.get("id", "")
#     if not issuer_did:
#         raise KeystoreCorruptedError("DID document missing 'id' field")

#     pinned = PinnedIssuer(
#         issuer_did=issuer_did,
#         Q_ca=Q_ca,
#         Q_ca_hash_hex=actual_hash,
#         bootstrap_mode="pinned",
#         bootstrapped_at=datetime.now(timezone.utc).isoformat(),
#     )

#     _write_keystore(keystore_path, pinned)
#     return pinned


# # ---------------------------------------------------------------------------
# # Re-fetch check (for monitoring key rotation or tampering)
# # ---------------------------------------------------------------------------

# def verify_pin_against_remote(pinned: PinnedIssuer,
#                               did_url: str,
#                               timeout: float = 5.0) -> bool:
#     """Re-fetch the DID document and verify Q_ca still matches the pin.

#     Returns True if the remote still serves the same Q_ca, False otherwise.
#     Does NOT update the pin on mismatch — that's an operator decision, since
#     a mismatch could indicate legitimate key rotation OR active compromise.

#     Useful for periodic monitoring: a mismatch should trigger an alert and
#     manual investigation, not automatic re-pinning.
#     """
#     did_doc = _fetch_did_document(did_url, timeout=timeout)
#     remote_Q_ca = _extract_q_ca_from_did_document(did_doc)
#     remote_hash = _compute_q_ca_hash(remote_Q_ca)
#     return remote_hash == pinned.Q_ca_hash_hex