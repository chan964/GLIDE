"""
Gateway verifier: the auth pipeline.

Given an incoming AuthResponse and the gateway's pinned keystore, determine
whether the device is authentic. This is the central authentication function
of the entire system.

Pipeline (each step can fail with a distinct reason code):

    1. Freshness:    cert_info's issued_at + max_age window includes now
    2. Reconstruct:  Q_dev = e*R + Q_ca using pinned Q_ca
    3. Verify:       ECDSA-verify signature over (nonce || R || cert_info)
                     using reconstructed Q_dev
    4. Revocation:   device's did:key not in revocation list (Day 11)

On any failure, returns AuthResult(success=False, reason=<enum>). On success,
returns AuthResult(success=True, device_did=did:key(Q_dev)).

Design notes:
    - Signature bytes: nonce (16) || R_compressed (33) || cert_info (variable)
    - Signature scheme: standard ECDSA over P-256 with SHA-256, deterministic
      per RFC 6979 (see DESIGN_DECISIONS.md DD-002)
    - cert_info format: "issuer_did||issued_at||max_age_seconds"
      (pipe-delimited UTF-8; opaque to signature, parsed for freshness)
    - Clock is injectable to allow deterministic testing
"""

import hashlib
import secrets
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from enum import Enum
from typing import Callable, Optional

from ecdsa import NIST256p, SigningKey, VerifyingKey, BadSignatureError
from ecdsa.ellipticcurve import PointJacobi
from ecdsa.util import number_to_string, sigencode_string, sigdecode_string

from src.cbor_codec import (
    AuthResponse,
    NONCE_SIZE,
    SIGNATURE_SIZE,
    encode_auth_challenge,
)
from src.did_utils import encode_did_key
from src.ecqv_core import (
    G,
    N,
    gateway_reconstruct_public_key,
    hash_to_scalar,
    point_to_compressed,
)
from src.gateway_keystore import PinnedIssuer


# ---------------------------------------------------------------------------
# Result types
# ---------------------------------------------------------------------------

class AuthFailureReason(Enum):
    """Distinct failure modes. Each maps to a paper-reportable category."""
    CERT_INFO_MALFORMED      = "cert_info_malformed"
    CERT_NOT_YET_VALID       = "cert_not_yet_valid"
    CERT_EXPIRED             = "cert_expired"
    ISSUER_MISMATCH          = "issuer_mismatch"
    RECONSTRUCTION_FAILED    = "reconstruction_failed"
    SIGNATURE_INVALID        = "signature_invalid"
    DEVICE_REVOKED           = "device_revoked"           # Day 11
    REVOCATION_UNAVAILABLE   = "revocation_unavailable"   # Day 11


@dataclass(frozen=True)
class AuthResult:
    success: bool
    device_did: Optional[str] = None
    reason: Optional[AuthFailureReason] = None
    detail: Optional[str] = None

    @classmethod
    def ok(cls, device_did: str) -> "AuthResult":
        return cls(success=True, device_did=device_did)

    @classmethod
    def fail(cls, reason: AuthFailureReason, detail: str = "") -> "AuthResult":
        return cls(success=False, reason=reason, detail=detail)


# ---------------------------------------------------------------------------
# Challenge generation
# ---------------------------------------------------------------------------

def generate_challenge() -> bytes:
    """Generate a fresh 16-byte random nonce for an auth challenge.

    Called by the gateway at the start of each authentication session.
    The nonce binds freshness to this specific signature but does NOT prevent
    replay of the whole MSG_1: the gateway keeps no record of seen nonces, so a
    recorded MSG_1 can be re-sent within the credential validity window. This is
    the formally characterized replay limitation (Tamarin: Gateway_Replay_Possible).
    Replay does not compromise the session key (Tamarin: Session_Key_Secrecy).
    """
    return secrets.token_bytes(NONCE_SIZE)


# ---------------------------------------------------------------------------
# Signature payload construction (shared between device and gateway)
# ---------------------------------------------------------------------------

def _authentication_signing_bytes(nonce: bytes,
                                  R: PointJacobi,
                                  cert_info: bytes) -> bytes:
    """The exact byte sequence that the device signs and the gateway verifies.

    Layout: nonce (16) || R_compressed (33) || cert_info (variable)

    Both device and gateway MUST produce identical bytes here; any
    mismatch produces signature failure. Centralized in one function to
    eliminate wire-format bugs.
    """
    if len(nonce) != NONCE_SIZE:
        raise ValueError(f"nonce must be {NONCE_SIZE} bytes, got {len(nonce)}")
    return nonce + point_to_compressed(R) + cert_info


# ---------------------------------------------------------------------------
# Device-side: produce the signature
# ---------------------------------------------------------------------------

def device_sign_authentication_challenge(d: int,
                                         nonce: bytes,
                                         R: PointJacobi,
                                         cert_info: bytes) -> bytes:
    """The device's signing step during authentication.

    Signs the bytes (nonce || R || cert_info) using the device's private key d.
    Uses deterministic ECDSA per RFC 6979 to avoid nonce-reuse attacks that
    plague randomized ECDSA implementations on constrained devices with
    weak RNGs.

    Returns 64 bytes: r (32) || s (32), big-endian, fixed width.
    """
    if not (1 <= d < N):
        raise ValueError("Private key d out of range [1, n-1]")

    signing_key = SigningKey.from_secret_exponent(d, curve=NIST256p)
    payload = _authentication_signing_bytes(nonce, R, cert_info)
    signature = signing_key.sign_deterministic(
        payload,
        hashfunc=hashlib.sha256,
        sigencode=sigencode_string,
    )
    if len(signature) != SIGNATURE_SIZE:
        raise RuntimeError(
            f"Signature size mismatch: expected {SIGNATURE_SIZE}, got {len(signature)}"
        )
    return signature


# ---------------------------------------------------------------------------
# cert_info parsing
# ---------------------------------------------------------------------------

@dataclass(frozen=True)
class ParsedCertInfo:
    issuer_did: str
    issued_at: datetime
    max_age_seconds: int

    @property
    def expires_at(self) -> datetime:
        return self.issued_at + timedelta(seconds=self.max_age_seconds)


def parse_cert_info(cert_info_bytes: bytes) -> ParsedCertInfo:
    """Parse pipe-delimited cert_info.

    Format: "issuer_did||issued_at_iso||max_age_seconds"
    Example: "did:web:issuer.example||2026-04-19T00:00:00+00:00||31536000"

    Raises ValueError on any parse failure.
    """
    try:
        text = cert_info_bytes.decode("utf-8")
    except UnicodeDecodeError as e:
        raise ValueError(f"cert_info is not valid UTF-8: {e}") from e

    parts = text.split("||")
    if len(parts) != 3:
        raise ValueError(
            f"cert_info must have 3 pipe-delimited fields, got {len(parts)}: {text!r}"
        )

    issuer_did, issued_at_str, max_age_str = parts

    if not issuer_did.startswith("did:"):
        raise ValueError(f"issuer_did is not a DID: {issuer_did!r}")

    try:
        issued_at = datetime.fromisoformat(issued_at_str)
    except ValueError as e:
        raise ValueError(f"issued_at is not valid ISO 8601: {issued_at_str!r}") from e

    # Ensure timezone-aware. If naive, assume UTC.
    if issued_at.tzinfo is None:
        issued_at = issued_at.replace(tzinfo=timezone.utc)

    try:
        max_age_seconds = int(max_age_str)
    except ValueError as e:
        raise ValueError(f"max_age is not an integer: {max_age_str!r}") from e

    if max_age_seconds <= 0:
        raise ValueError(f"max_age must be positive, got {max_age_seconds}")

    return ParsedCertInfo(
        issuer_did=issuer_did,
        issued_at=issued_at,
        max_age_seconds=max_age_seconds,
    )
# ---------------------------------------------------------------------------
# Signature verification against a reconstructed ECQV public key
#
# Extracted so both the classic auth pipeline and EDHOC handshake can reuse
# the reconstruction + verification logic. The only thing that changes between
# contexts is which bytes were signed.
# ---------------------------------------------------------------------------

def verify_signature_under_reconstructed_key(
    pinned_issuer: "PinnedIssuer",
    R: "PointJacobi",
    cert_info: bytes,
    signed_bytes: bytes,
    signature: bytes,
) -> AuthResult:
    """Reconstruct Q_dev from (R, cert_info) and pinned Q_ca, then verify
    the given signature over `signed_bytes` under that reconstructed key.

    This isolates the ECQV-reconstruction + ECDSA-verify step so it can be
    composed into different protocol contexts:
        - Classic auth: signed_bytes = nonce || R || cert_info
        - EDHOC MSG_1:  signed_bytes = E_d || R || cert_info || nonce_d

    Returns AuthResult.ok(device_did) on success, or AuthResult.fail() with
    RECONSTRUCTION_FAILED or SIGNATURE_INVALID reason.

    Note: this function does NOT perform cert_info parsing, freshness checks,
    or issuer identity matching. Those are caller responsibilities.
    """
    from src.ecqv_core import ImplicitCertificate

    # Reconstruct Q_dev
    try:
        cert_for_reconstruction = ImplicitCertificate(
            R=R,
            s=1,   # placeholder; reconstruction doesn't use s
            cert_info=cert_info,
        )
        Q_dev = gateway_reconstruct_public_key(
            cert_for_reconstruction,
            pinned_issuer.Q_ca,
        )
    except ValueError as e:
        return AuthResult.fail(AuthFailureReason.RECONSTRUCTION_FAILED, str(e))

    # Build VerifyingKey from the reconstructed point
    try:
        Q_dev_bytes = point_to_compressed(Q_dev)
        verifying_key = VerifyingKey.from_string(
            Q_dev_bytes,
            curve=NIST256p,
            hashfunc=hashlib.sha256,
        )
    except Exception as e:
        return AuthResult.fail(
            AuthFailureReason.RECONSTRUCTION_FAILED,
            f"VerifyingKey construction failed: {e}",
        )

    # Verify ECDSA signature over the caller-provided bytes
    try:
        verifying_key.verify(
            signature,
            signed_bytes,
            hashfunc=hashlib.sha256,
            sigdecode=sigdecode_string,
        )
    except BadSignatureError as e:
        return AuthResult.fail(AuthFailureReason.SIGNATURE_INVALID, str(e))

    device_did = encode_did_key(Q_dev)
    return AuthResult.ok(device_did)



# ---------------------------------------------------------------------------
# The verifier
# ---------------------------------------------------------------------------

def verify_authentication(
    pinned_issuer: PinnedIssuer,
    nonce: bytes,
    auth_response: AuthResponse,
    now_fn: Callable[[], datetime] = lambda: datetime.now(timezone.utc),
) -> AuthResult:
    """Execute the full verification pipeline for an authentication attempt.

    This is the gateway's central authentication function. It does NOT
    perform revocation checking — that's layered on in Day 11 via
    a wrapper function.

    Args:
        pinned_issuer: the gateway's pinned issuer (from keystore)
        nonce:         the challenge nonce the gateway sent
        auth_response: the device's response (decoded from CBOR)
        now_fn:        injectable clock for testability (default: real UTC time)

    Returns:
        AuthResult.ok(device_did) on success
        AuthResult.fail(reason, detail) on any failure
    """
    # --- Step 1: parse cert_info ---
    try:
        parsed = parse_cert_info(auth_response.cert_info)
    except ValueError as e:
        return AuthResult.fail(
            AuthFailureReason.CERT_INFO_MALFORMED,
            str(e),
        )

    # --- Step 2: freshness checks ---
    now = now_fn()
    if now < parsed.issued_at:
        return AuthResult.fail(
            AuthFailureReason.CERT_NOT_YET_VALID,
            f"now={now.isoformat()} < issued_at={parsed.issued_at.isoformat()}",
        )
    if now > parsed.expires_at:
        return AuthResult.fail(
            AuthFailureReason.CERT_EXPIRED,
            f"now={now.isoformat()} > expires_at={parsed.expires_at.isoformat()}",
        )

    # --- Step 3: issuer identity check ---
    # The cert_info claims a specific issuer DID; it must match the one we pinned.
    if parsed.issuer_did != pinned_issuer.issuer_did:
        return AuthResult.fail(
            AuthFailureReason.ISSUER_MISMATCH,
            f"cert issuer={parsed.issuer_did!r} != pinned issuer={pinned_issuer.issuer_did!r}",
        )

    # --- Steps 4-6: reconstruct Q_dev, verify signature, derive DID ---
    payload = _authentication_signing_bytes(
        nonce,
        auth_response.R,
        auth_response.cert_info,
    )
    return verify_signature_under_reconstructed_key(
        pinned_issuer=pinned_issuer,
        R=auth_response.R,
        cert_info=auth_response.cert_info,
        signed_bytes=payload,
        signature=auth_response.signature,
    )
# ---------------------------------------------------------------------------
# Authentication with revocation layer
# ---------------------------------------------------------------------------

def verify_authentication_with_revocation(
    pinned_issuer: "PinnedIssuer",
    nonce: bytes,
    auth_response: "AuthResponse",
    revocation_manager,   # RevocationSyncManager; typed loosely to avoid cycle
    now_fn: Callable[[], datetime] = lambda: datetime.now(timezone.utc),
) -> AuthResult:
    """Full auth + revocation pipeline.

    Calls verify_authentication first. If it succeeds, additionally checks
    whether the derived device DID is revoked. Returns:
        - the original AuthResult if auth failed
        - AuthResult.fail(DEVICE_REVOKED) if device is in revocation list
        - AuthResult.fail(REVOCATION_UNAVAILABLE) if gateway is OFFLINE
        - AuthResult.ok(...) if device is not revoked

    The revocation_manager is expected to be a RevocationSyncManager, but
    any object providing check_revocation(did) -> RevocationCheck works.
    """
    # Step 1: run the cryptographic auth pipeline
    result = verify_authentication(pinned_issuer, nonce, auth_response, now_fn=now_fn)
    if not result.success:
        return result

    # Step 2: revocation check against the derived device DID
    from src.revocation_sync import RevocationCheck   # lazy import avoids cycles

    check = revocation_manager.check_revocation(result.device_did)
    if check is RevocationCheck.REVOKED:
        return AuthResult.fail(
            AuthFailureReason.DEVICE_REVOKED,
            f"device_did={result.device_did} is in revocation list",
        )
    if check is RevocationCheck.UNAVAILABLE:
        return AuthResult.fail(
            AuthFailureReason.REVOCATION_UNAVAILABLE,
            "gateway is OFFLINE — fail-closed per G5",
        )

    # Step 3: device is authenticated and not revoked
    return result