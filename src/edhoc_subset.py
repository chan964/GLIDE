"""
EDHOC subset: two-message mutual authentication and session key establishment.

Restricted subset of RFC 9528 (see docs/DESIGN_DECISIONS.md DD-003):
    - Method: 0 (signature-based on both sides)
    - Cipher Suite: 2 (P-256 / AES-CCM-16-64-128 / SHA-256)
    - Messages: MSG_1 + MSG_2 only (no MSG_3, no explicit key confirmation)
    - Credential: ECQV implicit certificate (device), raw ECDSA pubkey (gateway)

Protocol flow:
    1. Device generates ephemeral keypair (e_d, E_d)
    2. Device signs (E_d || R || cert_info || nonce_d) with its long-term key d
    3. Device sends MSG_1 = {E_d, R, cert_info, nonce_d, signature_d}
    4. Gateway verifies device via ECQV reconstruction + signature check (reuses
       gateway_verifier.verify_signature_under_reconstructed_key).
    5. Gateway generates ephemeral keypair (e_g, E_g)
    6. Gateway signs (MSG_1_bytes || E_g || nonce_g) with its long-term key
    7. Gateway sends MSG_2 = {E_g, nonce_g, signature_g}
    8. Both sides derive session key via ECDH(e_d, E_g) + HKDF over transcript

Session key derivation:
    shared_secret  = ECDH_x_coordinate(e_d, E_g)   # 32 bytes
    transcript     = MSG_1_bytes || MSG_2_bytes
    session_key    = HKDF-SHA256(
        salt = SHA256(transcript),
        IKM  = shared_secret,
        info = b"edhoc-subset-v1-session-key",
        length = 16,
    )

Explicit non-claims (from DD-003):
    - NOT interoperable with standard EDHOC
    - NOT providing explicit key confirmation (no MSG_3)
    - NOT providing device identity privacy (cert in clear in MSG_1)
"""

import hashlib
import hmac
import secrets
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Callable, Optional

from ecdsa import NIST256p, SigningKey, VerifyingKey, BadSignatureError
from ecdsa.ellipticcurve import PointJacobi
from ecdsa.util import number_to_string, sigencode_string, sigdecode_string

from src.cbor_codec import (
    EdhocMsg1,
    EdhocMsg2,
    NONCE_SIZE,
    SIGNATURE_SIZE,
    decode_edhoc_msg1,
    decode_edhoc_msg2,
    encode_edhoc_msg1,
    encode_edhoc_msg2,
)
from src.ecqv_core import (
    G,
    N,
    ImplicitCertificate,
    point_to_compressed,
)
from src.gateway_keystore import GatewayIdentity, Keystore
from src.gateway_verifier import (
    AuthFailureReason,
    AuthResult,
    parse_cert_info,
    verify_signature_under_reconstructed_key,
)


SESSION_KEY_LENGTH = 16   # AES-128
HKDF_INFO = b"edhoc-subset-v1-session-key"


# ---------------------------------------------------------------------------
# Result types
# ---------------------------------------------------------------------------

@dataclass(frozen=True)
class EdhocInitiatorState:
    """Device-side state held between MSG_1 send and MSG_2 receive."""
    e_d: int                         # ephemeral private key (kept secret)
    E_d: PointJacobi                 # ephemeral public key (sent in MSG_1)
    nonce_d: bytes
    msg1_bytes: bytes                # for transcript hashing


@dataclass(frozen=True)
class EdhocResult:
    """Either a successful handshake with a session key, or a failure reason."""
    success: bool
    session_key: Optional[bytes] = None
    device_did: Optional[str] = None
    msg2_bytes: Optional[bytes] = None     # filled on gateway side
    reason: Optional[AuthFailureReason] = None
    detail: Optional[str] = None

    @classmethod
    def ok(cls, session_key: bytes, device_did: Optional[str] = None,
           msg2_bytes: Optional[bytes] = None) -> "EdhocResult":
        return cls(success=True, session_key=session_key,
                   device_did=device_did, msg2_bytes=msg2_bytes)

    @classmethod
    def fail(cls, reason: AuthFailureReason, detail: str = "") -> "EdhocResult":
        return cls(success=False, reason=reason, detail=detail)


# ---------------------------------------------------------------------------
# Cryptographic primitives
# ---------------------------------------------------------------------------

def _ecdh_shared_secret(private_scalar: int, public_point: PointJacobi) -> bytes:
    """ECDH: compute shared x-coordinate as 32-byte big-endian."""
    if not (1 <= private_scalar < N):
        raise ValueError("private_scalar out of range [1, n-1]")
    shared_point = private_scalar * public_point
    return number_to_string(shared_point.x(), N)


def _hkdf_extract(salt: bytes, ikm: bytes) -> bytes:
    """HKDF-Extract with SHA-256."""
    if not salt:
        salt = b"\x00" * 32
    return hmac.new(salt, ikm, hashlib.sha256).digest()


def _hkdf_expand(prk: bytes, info: bytes, length: int) -> bytes:
    """HKDF-Expand with SHA-256 to `length` bytes."""
    if length > 255 * 32:
        raise ValueError("HKDF output too long")
    output = b""
    t = b""
    counter = 1
    while len(output) < length:
        t = hmac.new(prk, t + info + bytes([counter]), hashlib.sha256).digest()
        output += t
        counter += 1
    return output[:length]


def derive_session_key(
    my_ephemeral_private: int,
    their_ephemeral_public: PointJacobi,
    msg1_bytes: bytes,
    msg2_bytes: bytes,
) -> bytes:
    """Derive the 16-byte session key.

    Both sides call this with their own ephemeral private key and the
    counterparty's ephemeral public key. By ECDH symmetry, both sides
    compute the same shared secret and therefore the same session key.

        Device: derive_session_key(e_d, E_g, msg1_bytes, msg2_bytes)
        Gateway: derive_session_key(e_g, E_d, msg1_bytes, msg2_bytes)
    """
    shared_secret = _ecdh_shared_secret(my_ephemeral_private, their_ephemeral_public)
    transcript = msg1_bytes + msg2_bytes
    salt = hashlib.sha256(transcript).digest()
    prk = _hkdf_extract(salt, shared_secret)
    return _hkdf_expand(prk, HKDF_INFO, SESSION_KEY_LENGTH)


# ---------------------------------------------------------------------------
# Signature payload construction (centralized)
# ---------------------------------------------------------------------------

def _msg1_signing_bytes(
    E_d: PointJacobi,
    R: PointJacobi,
    cert_info: bytes,
    nonce_d: bytes,
) -> bytes:
    """Bytes the device signs in MSG_1."""
    return point_to_compressed(E_d) + point_to_compressed(R) + cert_info + nonce_d


def _msg2_signing_bytes(
    msg1_bytes: bytes,
    E_g: PointJacobi,
    nonce_g: bytes,
) -> bytes:
    """Bytes the gateway signs in MSG_2. Binds to the device's MSG_1."""
    return msg1_bytes + point_to_compressed(E_g) + nonce_g


# ---------------------------------------------------------------------------
# Device side
# ---------------------------------------------------------------------------

def device_build_msg1(
    d: int,
    R: PointJacobi,
    cert_info: bytes,
) -> tuple[bytes, EdhocInitiatorState]:
    """Device builds MSG_1. Returns (msg1_bytes, state_to_retain).

    The state contains the device's ephemeral private key and is needed
    when processing MSG_2 to derive the session key. The device MUST NOT
    transmit any field of the state.
    """
    if not (1 <= d < N):
        raise ValueError("d out of range [1, n-1]")

    # Generate ephemeral keypair and nonce
    e_d = secrets.randbelow(N - 1) + 1
    E_d = e_d * G
    nonce_d = secrets.token_bytes(NONCE_SIZE)

    # Sign (E_d || R || cert_info || nonce_d) with long-term key d
    signing_bytes = _msg1_signing_bytes(E_d, R, cert_info, nonce_d)
    signing_key = SigningKey.from_secret_exponent(d, curve=NIST256p)
    signature = signing_key.sign_deterministic(
        signing_bytes,
        hashfunc=hashlib.sha256,
        sigencode=sigencode_string,
    )

    msg1_bytes = encode_edhoc_msg1(E_d, R, cert_info, nonce_d, signature)
    state = EdhocInitiatorState(e_d=e_d, E_d=E_d, nonce_d=nonce_d, msg1_bytes=msg1_bytes)
    return msg1_bytes, state


def device_process_msg2(
    state: EdhocInitiatorState,
    gateway_public_key: PointJacobi,
    msg2_bytes: bytes,
) -> EdhocResult:
    """Device processes MSG_2, verifies gateway's signature, derives session key.

    `gateway_public_key` is the pre-provisioned gateway long-term public key
    (factory-provisioned per DD-003, not looked up at runtime).
    """
    try:
        msg2 = decode_edhoc_msg2(msg2_bytes)
    except ValueError as e:
        return EdhocResult.fail(AuthFailureReason.CERT_INFO_MALFORMED,
                                f"MSG_2 decode failed: {e}")

    # Verify gateway's signature using pre-provisioned gateway public key
    gateway_Q_bytes = point_to_compressed(gateway_public_key)
    try:
        vk = VerifyingKey.from_string(
            gateway_Q_bytes, curve=NIST256p, hashfunc=hashlib.sha256,
        )
    except Exception as e:
        return EdhocResult.fail(AuthFailureReason.RECONSTRUCTION_FAILED,
                                f"Gateway VerifyingKey construction failed: {e}")

    signing_bytes = _msg2_signing_bytes(state.msg1_bytes, msg2.E_g, msg2.nonce_g)
    try:
        vk.verify(
            msg2.signature,
            signing_bytes,
            hashfunc=hashlib.sha256,
            sigdecode=sigdecode_string,
        )
    except BadSignatureError as e:
        return EdhocResult.fail(AuthFailureReason.SIGNATURE_INVALID, str(e))

    # Derive session key: my ephemeral private (e_d) + their ephemeral public (E_g)
    session_key = derive_session_key(
        state.e_d, msg2.E_g, state.msg1_bytes, msg2_bytes,
    )
    return EdhocResult.ok(session_key=session_key)


# ---------------------------------------------------------------------------
# Gateway side
# ---------------------------------------------------------------------------

def gateway_process_msg1_build_msg2(
    keystore: Keystore,
    msg1_bytes: bytes,
    revocation_manager=None,   # optional; if None, revocation not checked
    now_fn: Callable[[], datetime] = lambda: datetime.now(timezone.utc),
) -> EdhocResult:
    """Gateway verifies MSG_1, generates its own ephemeral keypair,
    builds MSG_2, and derives the session key.

    Reuses verify_signature_under_reconstructed_key() for ECQV reconstruction
    plus ECDSA signature verification — the exact composition story from DD-003.

    If revocation_manager is provided, also checks the device's did:key
    against the revocation list (returns REVOCATION_UNAVAILABLE or
    DEVICE_REVOKED per threat model G5).

    Returns EdhocResult with session_key, device_did, msg2_bytes on success.
    """
    try:
        msg1 = decode_edhoc_msg1(msg1_bytes)
    except ValueError as e:
        return EdhocResult.fail(AuthFailureReason.CERT_INFO_MALFORMED,
                                f"MSG_1 decode failed: {e}")

    # --- Parse cert_info for freshness + issuer check ---
    try:
        parsed = parse_cert_info(msg1.cert_info)
    except ValueError as e:
        return EdhocResult.fail(AuthFailureReason.CERT_INFO_MALFORMED, str(e))

    now = now_fn()
    if now < parsed.issued_at:
        return EdhocResult.fail(AuthFailureReason.CERT_NOT_YET_VALID,
                                f"now={now} < issued_at={parsed.issued_at}")
    if now > parsed.expires_at:
        return EdhocResult.fail(AuthFailureReason.CERT_EXPIRED,
                                f"now={now} > expires_at={parsed.expires_at}")
    if parsed.issuer_did != keystore.pinned_issuer.issuer_did:
        return EdhocResult.fail(
            AuthFailureReason.ISSUER_MISMATCH,
            f"cert issuer={parsed.issuer_did} != pinned={keystore.pinned_issuer.issuer_did}",
        )

    # --- Verify device signature via reconstruction (reused from verifier) ---
    signing_bytes = _msg1_signing_bytes(msg1.E_d, msg1.R, msg1.cert_info, msg1.nonce_d)
    auth_result = verify_signature_under_reconstructed_key(
        pinned_issuer=keystore.pinned_issuer,
        R=msg1.R,
        cert_info=msg1.cert_info,
        signed_bytes=signing_bytes,
        signature=msg1.signature,
    )
    if not auth_result.success:
        return EdhocResult.fail(auth_result.reason, auth_result.detail or "")

    device_did = auth_result.device_did

    # --- Optional revocation check ---
    if revocation_manager is not None:
        from src.revocation_sync import RevocationCheck
        check = revocation_manager.check_revocation(device_did)
        if check is RevocationCheck.REVOKED:
            return EdhocResult.fail(
                AuthFailureReason.DEVICE_REVOKED,
                f"device_did={device_did} is revoked",
            )
        if check is RevocationCheck.UNAVAILABLE:
            return EdhocResult.fail(
                AuthFailureReason.REVOCATION_UNAVAILABLE,
                "gateway is OFFLINE",
            )

    # --- Generate gateway ephemeral keypair, sign MSG_2, derive session key ---
    e_g = secrets.randbelow(N - 1) + 1
    E_g = e_g * G
    nonce_g = secrets.token_bytes(NONCE_SIZE)

    msg2_signing_bytes = _msg2_signing_bytes(msg1_bytes, E_g, nonce_g)
    gw_signing_key = SigningKey.from_secret_exponent(
        keystore.gateway_identity.private_key, curve=NIST256p,
    )
    signature_g = gw_signing_key.sign_deterministic(
        msg2_signing_bytes,
        hashfunc=hashlib.sha256,
        sigencode=sigencode_string,
    )

    msg2_bytes = encode_edhoc_msg2(E_g, nonce_g, signature_g)

    # Derive session key: my ephemeral private (e_g) + their ephemeral public (E_d)
    session_key = derive_session_key(e_g, msg1.E_d, msg1_bytes, msg2_bytes)

    return EdhocResult.ok(
        session_key=session_key,
        device_did=device_did,
        msg2_bytes=msg2_bytes,
    )