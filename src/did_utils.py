"""
DID utilities: did:key and did:web support for P-256 public keys.

Two DID methods, deliberate split:
    did:key  → Device identity (self-certifying, no network resolution)
    did:web  → Issuer identity (web-hosted DID document, TOFU-pinned)

This module handles:
    - Encoding P-256 public keys as did:key
    - Decoding did:key back to public keys
    - Constructing and validating did:web identifiers
    - Resolving did:web to its document URL (per W3C spec)

References:
    W3C DID Core: https://www.w3.org/TR/did-core/
    did:key spec: https://w3c-ccg.github.io/did-method-key/
    did:web spec: https://w3c-ccg.github.io/did-method-web/
    Multicodec: https://github.com/multiformats/multicodec
"""

import re
from typing import Tuple
from urllib.parse import quote, unquote

from ecdsa import ellipticcurve

from src.ecqv_core import (
    compressed_to_point,
    point_to_compressed,
)

# ---------------------------------------------------------------------------
# Multicodec constants
# ---------------------------------------------------------------------------

# Multicodec prefix for P-256 compressed public keys.
# Varint-encoded: 0x1200 unsigned varint = bytes 0x80, 0x24
# Reference: https://github.com/multiformats/multicodec/blob/master/table.csv
# The entry is "p256-pub = 0x1200", varint-encoded.
P256_MULTICODEC_PREFIX = bytes([0x80, 0x24])


# ---------------------------------------------------------------------------
# Base58btc encoding (Bitcoin alphabet, used by multibase 'z' prefix)
# ---------------------------------------------------------------------------

_BASE58_ALPHABET = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"


def base58btc_encode(data: bytes) -> str:
    """Encode bytes using Bitcoin's base58 alphabet.

    Deliberately implemented from scratch (no base58 library dependency)
    because this module's correctness is too important to rely on a
    third-party package that may change alphabets.
    """
    n = int.from_bytes(data, "big")
    result = ""
    while n > 0:
        n, r = divmod(n, 58)
        result = _BASE58_ALPHABET[r] + result
    # Preserve leading zero bytes as leading "1" chars in base58
    leading_zeros = 0
    for byte in data:
        if byte == 0:
            leading_zeros += 1
        else:
            break
    return "1" * leading_zeros + result


def base58btc_decode(s: str) -> bytes:
    """Decode a base58btc string back to bytes."""
    n = 0
    for char in s:
        n = n * 58 + _BASE58_ALPHABET.index(char)
    # Count leading "1"s (representing leading zero bytes)
    leading_ones = 0
    for char in s:
        if char == "1":
            leading_ones += 1
        else:
            break
    byte_length = (n.bit_length() + 7) // 8
    return b"\x00" * leading_ones + n.to_bytes(byte_length, "big")


# ---------------------------------------------------------------------------
# did:key encoding / decoding
# ---------------------------------------------------------------------------

def encode_did_key(public_key: ellipticcurve.PointJacobi) -> str:
    """Encode a P-256 public key as a did:key identifier.

    Format: did:key:z<base58btc(multicodec_prefix || compressed_pubkey)>

    The "z" is the multibase prefix for base58btc.
    The multicodec prefix identifies this as a P-256 public key.
    """
    compressed = point_to_compressed(public_key)
    multicodec_bytes = P256_MULTICODEC_PREFIX + compressed
    multibase_encoded = "z" + base58btc_encode(multicodec_bytes)
    return f"did:key:{multibase_encoded}"


def decode_did_key(did_key: str) -> ellipticcurve.PointJacobi:
    """Extract a P-256 public key from a did:key identifier.

    Validates:
        - String starts with "did:key:z" (method + multibase prefix)
        - Multicodec prefix matches P-256 (0x80 0x24)
        - Compressed point decodes to a valid curve point

    Raises ValueError on any mismatch.
    """
    if not did_key.startswith("did:key:z"):
        raise ValueError(f"Not a did:key P-256 identifier: {did_key!r}")

    multibase_payload = did_key[len("did:key:z"):]
    if not multibase_payload:
        raise ValueError("did:key has empty payload")

    try:
        decoded = base58btc_decode(multibase_payload)
    except (ValueError, IndexError) as e:
        raise ValueError(f"base58btc decode failed: {e}") from e

    if len(decoded) < 2:
        raise ValueError("Decoded payload too short for multicodec prefix")

    if decoded[:2] != P256_MULTICODEC_PREFIX:
        raise ValueError(
            f"Multicodec prefix is not P-256: got {decoded[:2].hex()}, "
            f"expected {P256_MULTICODEC_PREFIX.hex()}"
        )

    compressed_pubkey = decoded[2:]
    if len(compressed_pubkey) != 33:
        raise ValueError(
            f"Compressed public key must be 33 bytes, got {len(compressed_pubkey)}"
        )

    return compressed_to_point(compressed_pubkey)


# ---------------------------------------------------------------------------
# did:web construction and resolution
# ---------------------------------------------------------------------------

# did:web method allows: domain[:port][:path-segments]
# Per spec: https://w3c-ccg.github.io/did-method-web/
# - Domain is required
# - Port is colon-separated after domain (URL-encoded as %3A in the DID)
# - Path segments are colon-separated
# We keep validation strict: alphanumerics, dots, hyphens in domain; path segments must be URL-safe.

_DID_WEB_DOMAIN_RE = re.compile(r"^[a-zA-Z0-9.\-]+$")
_DID_WEB_PATH_SEGMENT_RE = re.compile(r"^[a-zA-Z0-9._\-%]+$")


def construct_did_web(domain: str, path_segments: list[str] = None) -> str:
    """Build a did:web identifier from a domain and optional path segments.

    Examples:
        construct_did_web("issuer.example.com")
            → "did:web:issuer.example.com"
        construct_did_web("issuer.example.com", ["users", "alice"])
            → "did:web:issuer.example.com:users:alice"

    Raises ValueError if domain or path segments contain invalid characters.
    """
    if not _DID_WEB_DOMAIN_RE.match(domain):
        raise ValueError(f"Invalid did:web domain: {domain!r}")

    parts = [domain]
    if path_segments:
        for seg in path_segments:
            if not _DID_WEB_PATH_SEGMENT_RE.match(seg):
                raise ValueError(f"Invalid did:web path segment: {seg!r}")
            parts.append(seg)

    return "did:web:" + ":".join(parts)


def resolve_did_web_to_url(did_web: str) -> str:
    """Convert a did:web identifier to its DID Document URL.

    Resolution rules (per W3C did:web spec):
        - did:web:example.com
            → https://example.com/.well-known/did.json
        - did:web:example.com:user:alice
            → https://example.com/user/alice/did.json

    That is: if there are path segments, they become URL path components
    and the document is served at {path}/did.json (no .well-known).
    If there are no path segments, the document is at /.well-known/did.json.

    Raises ValueError if the input is not a valid did:web identifier.
    """
    if not did_web.startswith("did:web:"):
        raise ValueError(f"Not a did:web identifier: {did_web!r}")

    identifier = did_web[len("did:web:"):]
    if not identifier:
        raise ValueError("did:web has empty identifier")

    parts = identifier.split(":")
    domain = parts[0]

    if not _DID_WEB_DOMAIN_RE.match(domain):
        raise ValueError(f"Invalid did:web domain: {domain!r}")

    if len(parts) == 1:
        return f"https://{domain}/.well-known/did.json"
    else:
        path_segments = [unquote(seg) for seg in parts[1:]]
        path = "/".join(path_segments)
        return f"https://{domain}/{path}/did.json"


def parse_did(did: str) -> Tuple[str, str]:
    """Parse a DID into (method, method_specific_id).

    Examples:
        "did:key:z123..." → ("key", "z123...")
        "did:web:example.com:users:alice" → ("web", "example.com:users:alice")

    Raises ValueError on malformed input.
    """
    if not did.startswith("did:"):
        raise ValueError(f"Not a DID: {did!r}")
    rest = did[4:]
    if ":" not in rest:
        raise ValueError(f"DID missing method-specific ID: {did!r}")
    method, method_id = rest.split(":", 1)
    if not method or not method_id:
        raise ValueError(f"Empty method or ID in DID: {did!r}")
    return method, method_id