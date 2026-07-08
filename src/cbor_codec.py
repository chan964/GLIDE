"""
CBOR codec for L-ECQV + DID protocol messages.

Design rules:
    - Integer keys (saves bytes vs string keys)
    - Fixed field order within each message
    - Strict decode validation (reject malformed/unexpected input)
    - Each message type has dedicated encode/decode functions
    - Version tag on every message for forward compatibility

Wire size targets (for 127-byte 802.15.4 frame):
    ProvisioningRequest:  ~70 bytes
    ProvisioningResponse: ~95 bytes
    AuthChallenge:        ~20 bytes
    AuthResponse:         ~165 bytes (largest; may fragment)

References:
    RFC 8949: Concise Binary Object Representation (CBOR)
    RFC 9528: EDHOC (for later message formats)
"""

from dataclasses import dataclass
from typing import Optional

import cbor2

from ecdsa import ellipticcurve
from ecdsa.util import number_to_string, string_to_number

from src.ecqv_core import (
    N,
    ImplicitCertificate,
    compressed_to_point,
    point_to_compressed,
)


# ---------------------------------------------------------------------------
# Protocol version
# ---------------------------------------------------------------------------

PROTOCOL_VERSION = 1   # Bumped when wire format changes incompatibly


# ---------------------------------------------------------------------------
# Message type tags (top-level discriminator)
# ---------------------------------------------------------------------------

MSG_PROVISIONING_REQUEST  = 0x01
MSG_PROVISIONING_RESPONSE = 0x02
MSG_AUTH_CHALLENGE        = 0x03
MSG_AUTH_RESPONSE         = 0x04
MSG_EDHOC_1               = 0x05
MSG_EDHOC_2               = 0x06
# 0x05, 0x06 reserved for EDHOC MSG_1, MSG_2 (Day 13)


# ---------------------------------------------------------------------------
# Common field keys (integer keys for CBOR maps)
# ---------------------------------------------------------------------------

KEY_VERSION    = 0
KEY_TYPE       = 1
KEY_U          = 2      # Device contribution point (compressed bytes)
KEY_CERT_INFO  = 3      # Certificate metadata (raw bytes)
KEY_R          = 4      # Reconstruction point (compressed bytes)
KEY_S          = 5      # Issuer scalar (32 bytes)
KEY_NONCE      = 6      # Fresh challenge nonce (16 bytes)
KEY_SIGNATURE  = 7 
KEY_EPHEMERAL  = 8     # Ephemeral public key (compressed point, 33 bytes)
KEY_NONCE_D    = 9     # Device nonce in EDHOC MSG_1 (distinct from gateway nonce)     # ECDSA signature (64 bytes: r || s concatenated)
KEY_NONCE_G    = 10    # Gateway's nonce in EDHOC (16 bytes)

# ---------------------------------------------------------------------------
# Dataclasses for decoded messages
# ---------------------------------------------------------------------------

@dataclass(frozen=True)
class ProvisioningRequest:
    U: ellipticcurve.PointJacobi
    cert_info: bytes


@dataclass(frozen=True)
class ProvisioningResponse:
    R: ellipticcurve.PointJacobi
    s: int
    cert_info: bytes

    def to_implicit_certificate(self) -> ImplicitCertificate:
        """Convenience: convert decoded response to an ImplicitCertificate."""
        return ImplicitCertificate(R=self.R, s=self.s, cert_info=self.cert_info)


@dataclass(frozen=True)
class AuthChallenge:
    nonce: bytes   # 16 bytes


@dataclass(frozen=True)
class AuthResponse:
    R: ellipticcurve.PointJacobi
    cert_info: bytes
    signature: bytes   # 64 bytes ECDSA r||s


# ---------------------------------------------------------------------------
# Internal validation helpers
# ---------------------------------------------------------------------------

def _require_dict(obj) -> dict:
    if not isinstance(obj, dict):
        raise ValueError(f"Expected CBOR map, got {type(obj).__name__}")
    return obj


def _require_key(m: dict, key: int, type_: type, name: str):
    if key not in m:
        raise ValueError(f"Missing required field {name!r} (key {key})")
    value = m[key]
    if not isinstance(value, type_):
        raise ValueError(
            f"Field {name!r} has wrong type: expected {type_.__name__}, "
            f"got {type(value).__name__}"
        )
    return value


def _check_message_envelope(m: dict, expected_type: int) -> None:
    """Every message begins with {KEY_VERSION: int, KEY_TYPE: int, ...}."""
    version = _require_key(m, KEY_VERSION, int, "version")
    if version != PROTOCOL_VERSION:
        raise ValueError(
            f"Unsupported protocol version: {version} (expected {PROTOCOL_VERSION})"
        )

    msg_type = _require_key(m, KEY_TYPE, int, "type")
    if msg_type != expected_type:
        raise ValueError(
            f"Wrong message type: got {msg_type:#04x}, expected {expected_type:#04x}"
        )


def _reject_unknown_keys(m: dict, allowed: set[int]) -> None:
    """Reject messages with unexpected extra keys (defense against smuggling).

    Any key not in `allowed` causes rejection. This prevents an attacker
    from embedding extra fields that a permissive decoder might use.
    """
    extra = set(m.keys()) - allowed
    if extra:
        raise ValueError(f"Unexpected extra keys in message: {sorted(extra)}")


# ---------------------------------------------------------------------------
# ProvisioningRequest (Device → Issuer)
# ---------------------------------------------------------------------------

def encode_provisioning_request(U: ellipticcurve.PointJacobi,
                                cert_info: bytes) -> bytes:
    """Encode a provisioning request: device sends its U to issuer.

    Wire layout:
        {
            0: PROTOCOL_VERSION,
            1: MSG_PROVISIONING_REQUEST,
            2: U_compressed (33 bytes),
            3: cert_info (variable)
        }
    """
    if not cert_info:
        raise ValueError("cert_info must not be empty")
    U_bytes = point_to_compressed(U)

    m = {
        KEY_VERSION: PROTOCOL_VERSION,
        KEY_TYPE: MSG_PROVISIONING_REQUEST,
        KEY_U: U_bytes,
        KEY_CERT_INFO: cert_info,
    }
    return cbor2.dumps(m)


def decode_provisioning_request(data: bytes) -> ProvisioningRequest:
    try:
        m = _require_dict(cbor2.loads(data))
    except cbor2.CBORDecodeError as e:
        raise ValueError(f"CBOR decode failed: {e}") from e

    _check_message_envelope(m, MSG_PROVISIONING_REQUEST)
    _reject_unknown_keys(m, {KEY_VERSION, KEY_TYPE, KEY_U, KEY_CERT_INFO})

    U_bytes = _require_key(m, KEY_U, bytes, "U")
    cert_info = _require_key(m, KEY_CERT_INFO, bytes, "cert_info")

    if len(U_bytes) != 33:
        raise ValueError(f"U must be 33 bytes, got {len(U_bytes)}")
    if not cert_info:
        raise ValueError("cert_info must not be empty")

    try:
        U = compressed_to_point(U_bytes)
    except ValueError as e:
        raise ValueError(f"Invalid U point: {e}") from e

    return ProvisioningRequest(U=U, cert_info=cert_info)


# ---------------------------------------------------------------------------
# ProvisioningResponse (Issuer → Device)
# ---------------------------------------------------------------------------

def encode_provisioning_response(cert: ImplicitCertificate) -> bytes:
    """Encode a provisioning response: issuer returns (R, s, cert_info).

    Wire layout:
        {
            0: PROTOCOL_VERSION,
            1: MSG_PROVISIONING_RESPONSE,
            3: cert_info,
            4: R_compressed (33 bytes),
            5: s (32 bytes big-endian)
        }
    """
    R_bytes = point_to_compressed(cert.R)
    s_bytes = number_to_string(cert.s, N)   # Fixed 32 bytes

    m = {
        KEY_VERSION: PROTOCOL_VERSION,
        KEY_TYPE: MSG_PROVISIONING_RESPONSE,
        KEY_CERT_INFO: cert.cert_info,
        KEY_R: R_bytes,
        KEY_S: s_bytes,
    }
    return cbor2.dumps(m)


def decode_provisioning_response(data: bytes) -> ProvisioningResponse:
    try:
        m = _require_dict(cbor2.loads(data))
    except cbor2.CBORDecodeError as e:
        raise ValueError(f"CBOR decode failed: {e}") from e

    _check_message_envelope(m, MSG_PROVISIONING_RESPONSE)
    _reject_unknown_keys(m, {KEY_VERSION, KEY_TYPE, KEY_CERT_INFO, KEY_R, KEY_S})

    cert_info = _require_key(m, KEY_CERT_INFO, bytes, "cert_info")
    R_bytes = _require_key(m, KEY_R, bytes, "R")
    s_bytes = _require_key(m, KEY_S, bytes, "s")

    if len(R_bytes) != 33:
        raise ValueError(f"R must be 33 bytes, got {len(R_bytes)}")
    if len(s_bytes) != 32:
        raise ValueError(f"s must be 32 bytes, got {len(s_bytes)}")

    R = compressed_to_point(R_bytes)
    s = string_to_number(s_bytes)

    if not (1 <= s < N):
        raise ValueError("s out of range [1, n-1]")

    return ProvisioningResponse(R=R, s=s, cert_info=cert_info)


# ---------------------------------------------------------------------------
# AuthChallenge (Gateway → Device)
# ---------------------------------------------------------------------------

NONCE_SIZE = 16   # 128-bit nonce; collision-free up to 2^64 sessions per gateway


def encode_auth_challenge(nonce: bytes) -> bytes:
    """Encode an auth challenge: gateway sends fresh nonce to device.

    Wire layout:
        {
            0: PROTOCOL_VERSION,
            1: MSG_AUTH_CHALLENGE,
            6: nonce (16 bytes)
        }
    """
    if len(nonce) != NONCE_SIZE:
        raise ValueError(f"nonce must be {NONCE_SIZE} bytes, got {len(nonce)}")

    m = {
        KEY_VERSION: PROTOCOL_VERSION,
        KEY_TYPE: MSG_AUTH_CHALLENGE,
        KEY_NONCE: nonce,
    }
    return cbor2.dumps(m)


def decode_auth_challenge(data: bytes) -> AuthChallenge:
    try:
        m = _require_dict(cbor2.loads(data))
    except cbor2.CBORDecodeError as e:
        raise ValueError(f"CBOR decode failed: {e}") from e

    _check_message_envelope(m, MSG_AUTH_CHALLENGE)
    _reject_unknown_keys(m, {KEY_VERSION, KEY_TYPE, KEY_NONCE})

    nonce = _require_key(m, KEY_NONCE, bytes, "nonce")
    if len(nonce) != NONCE_SIZE:
        raise ValueError(f"nonce must be {NONCE_SIZE} bytes, got {len(nonce)}")

    return AuthChallenge(nonce=nonce)


# ---------------------------------------------------------------------------
# AuthResponse (Device → Gateway)
# ---------------------------------------------------------------------------

SIGNATURE_SIZE = 64   # ECDSA over P-256: r (32) || s (32)


def encode_auth_response(R: ellipticcurve.PointJacobi,
                         cert_info: bytes,
                         signature: bytes) -> bytes:
    """Encode an auth response: device sends its cert parts + signature.

    Wire layout:
        {
            0: PROTOCOL_VERSION,
            1: MSG_AUTH_RESPONSE,
            3: cert_info,
            4: R_compressed (33 bytes),
            7: signature (64 bytes)
        }

    Note: `s` from the certificate is NOT transmitted during authentication.
    The gateway does not use `s` (reconstruction uses only R and Q_ca).
    This is a deliberate size optimization.
    """
    if len(signature) != SIGNATURE_SIZE:
        raise ValueError(f"signature must be {SIGNATURE_SIZE} bytes, got {len(signature)}")

    R_bytes = point_to_compressed(R)

    m = {
        KEY_VERSION: PROTOCOL_VERSION,
        KEY_TYPE: MSG_AUTH_RESPONSE,
        KEY_CERT_INFO: cert_info,
        KEY_R: R_bytes,
        KEY_SIGNATURE: signature,
    }
    return cbor2.dumps(m)


def decode_auth_response(data: bytes) -> AuthResponse:
    try:
        m = _require_dict(cbor2.loads(data))
    except cbor2.CBORDecodeError as e:
        raise ValueError(f"CBOR decode failed: {e}") from e

    _check_message_envelope(m, MSG_AUTH_RESPONSE)
    _reject_unknown_keys(m, {KEY_VERSION, KEY_TYPE, KEY_CERT_INFO, KEY_R, KEY_SIGNATURE})

    cert_info = _require_key(m, KEY_CERT_INFO, bytes, "cert_info")
    R_bytes = _require_key(m, KEY_R, bytes, "R")
    signature = _require_key(m, KEY_SIGNATURE, bytes, "signature")

    if len(R_bytes) != 33:
        raise ValueError(f"R must be 33 bytes, got {len(R_bytes)}")
    if len(signature) != SIGNATURE_SIZE:
        raise ValueError(f"signature must be {SIGNATURE_SIZE} bytes, got {len(signature)}")

    R = compressed_to_point(R_bytes)

    return AuthResponse(R=R, cert_info=cert_info, signature=signature)



# ---------------------------------------------------------------------------
# EDHOC MSG_1 (Device → Gateway)
# ---------------------------------------------------------------------------

@dataclass(frozen=True)
class EdhocMsg1:
    E_d: ellipticcurve.PointJacobi       # device ephemeral public key
    R: ellipticcurve.PointJacobi         # device ECQV reconstruction point
    cert_info: bytes
    nonce_d: bytes                       # 16 bytes
    signature: bytes                     # 64 bytes ECDSA r||s


def encode_edhoc_msg1(
    E_d: ellipticcurve.PointJacobi,
    R: ellipticcurve.PointJacobi,
    cert_info: bytes,
    nonce_d: bytes,
    signature: bytes,
) -> bytes:
    """Encode EDHOC MSG_1: device's handshake initiation."""
    if len(nonce_d) != NONCE_SIZE:
        raise ValueError(f"nonce_d must be {NONCE_SIZE} bytes, got {len(nonce_d)}")
    if len(signature) != SIGNATURE_SIZE:
        raise ValueError(f"signature must be {SIGNATURE_SIZE} bytes, got {len(signature)}")

    m = {
        KEY_VERSION: PROTOCOL_VERSION,
        KEY_TYPE: MSG_EDHOC_1,
        KEY_CERT_INFO: cert_info,
        KEY_R: point_to_compressed(R),
        KEY_SIGNATURE: signature,
        KEY_EPHEMERAL: point_to_compressed(E_d),
        KEY_NONCE_D: nonce_d,
    }
    return cbor2.dumps(m)


def decode_edhoc_msg1(data: bytes) -> EdhocMsg1:
    try:
        m = _require_dict(cbor2.loads(data))
    except cbor2.CBORDecodeError as e:
        raise ValueError(f"CBOR decode failed: {e}") from e

    _check_message_envelope(m, MSG_EDHOC_1)
    _reject_unknown_keys(m, {
        KEY_VERSION, KEY_TYPE, KEY_CERT_INFO,
        KEY_R, KEY_SIGNATURE, KEY_EPHEMERAL, KEY_NONCE_D,
    })

    cert_info = _require_key(m, KEY_CERT_INFO, bytes, "cert_info")
    R_bytes = _require_key(m, KEY_R, bytes, "R")
    signature = _require_key(m, KEY_SIGNATURE, bytes, "signature")
    E_d_bytes = _require_key(m, KEY_EPHEMERAL, bytes, "E_d")
    nonce_d = _require_key(m, KEY_NONCE_D, bytes, "nonce_d")

    if len(R_bytes) != 33:
        raise ValueError(f"R must be 33 bytes, got {len(R_bytes)}")
    if len(E_d_bytes) != 33:
        raise ValueError(f"E_d must be 33 bytes, got {len(E_d_bytes)}")
    if len(signature) != SIGNATURE_SIZE:
        raise ValueError(f"signature must be {SIGNATURE_SIZE} bytes, got {len(signature)}")
    if len(nonce_d) != NONCE_SIZE:
        raise ValueError(f"nonce_d must be {NONCE_SIZE} bytes, got {len(nonce_d)}")

    return EdhocMsg1(
        E_d=compressed_to_point(E_d_bytes),
        R=compressed_to_point(R_bytes),
        cert_info=cert_info,
        nonce_d=nonce_d,
        signature=signature,
    )


# ---------------------------------------------------------------------------
# EDHOC MSG_2 (Gateway → Device)
# ---------------------------------------------------------------------------

@dataclass(frozen=True)
class EdhocMsg2:
    E_g: ellipticcurve.PointJacobi       # gateway ephemeral public key
    nonce_g: bytes                       # 16 bytes
    signature: bytes                     # 64 bytes ECDSA r||s over gateway long-term key


def encode_edhoc_msg2(
    E_g: ellipticcurve.PointJacobi,
    nonce_g: bytes,
    signature: bytes,
) -> bytes:
    """Encode EDHOC MSG_2: gateway's handshake response."""
    if len(nonce_g) != NONCE_SIZE:
        raise ValueError(f"nonce_g must be {NONCE_SIZE} bytes, got {len(nonce_g)}")
    if len(signature) != SIGNATURE_SIZE:
        raise ValueError(f"signature must be {SIGNATURE_SIZE} bytes, got {len(signature)}")

    m = {
        KEY_VERSION: PROTOCOL_VERSION,
        KEY_TYPE: MSG_EDHOC_2,
        KEY_SIGNATURE: signature,
        KEY_EPHEMERAL: point_to_compressed(E_g),
        KEY_NONCE_G: nonce_g,
    }
    return cbor2.dumps(m)


def decode_edhoc_msg2(data: bytes) -> EdhocMsg2:
    try:
        m = _require_dict(cbor2.loads(data))
    except cbor2.CBORDecodeError as e:
        raise ValueError(f"CBOR decode failed: {e}") from e

    _check_message_envelope(m, MSG_EDHOC_2)
    _reject_unknown_keys(m, {
        KEY_VERSION, KEY_TYPE, KEY_SIGNATURE, KEY_EPHEMERAL, KEY_NONCE_G,
    })

    signature = _require_key(m, KEY_SIGNATURE, bytes, "signature")
    E_g_bytes = _require_key(m, KEY_EPHEMERAL, bytes, "E_g")
    nonce_g = _require_key(m, KEY_NONCE_G, bytes, "nonce_g")

    if len(E_g_bytes) != 33:
        raise ValueError(f"E_g must be 33 bytes, got {len(E_g_bytes)}")
    if len(signature) != SIGNATURE_SIZE:
        raise ValueError(f"signature must be {SIGNATURE_SIZE} bytes, got {len(signature)}")
    if len(nonce_g) != NONCE_SIZE:
        raise ValueError(f"nonce_g must be {NONCE_SIZE} bytes, got {len(nonce_g)}")

    return EdhocMsg2(
        E_g=compressed_to_point(E_g_bytes),
        nonce_g=nonce_g,
        signature=signature,
    )


# ---------------------------------------------------------------------------
# Size introspection (for measurement/paper)
# ---------------------------------------------------------------------------

def measure_message_sizes(cert: ImplicitCertificate,
                          nonce: bytes,
                          signature: bytes) -> dict[str, int]:
    """Return wire size in bytes for each message type.

    Useful for generating the Wire Format Sizes table in the paper.
    """
    return {
        "ProvisioningRequest":  len(encode_provisioning_request(cert.R, cert.cert_info)),
        "ProvisioningResponse": len(encode_provisioning_response(cert)),
        "AuthChallenge":        len(encode_auth_challenge(nonce)),
        "AuthResponse":         len(encode_auth_response(cert.R, cert.cert_info, signature)),
    }