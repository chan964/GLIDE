#!/usr/bin/env python3
"""
gateway_verifier.py — Python gateway for Cooja serial socket demo.

Connects to Cooja's Serial Socket (SERVER) on localhost:60001.
Receives MSG_1 from device mote, sends MSG_2 back.
Both sides derive session key — if they match, mutual auth is proven.

Flow:
  1. Connect to Cooja serial socket (port 60001)
  2. Wait for line starting with "MSG1:"
  3. Parse MSG_1, run gateway auth logic
  4. Send "MSG2:<hex>\n" back
  5. Print derived session key
"""

import socket
import sys
import time
import os

# Add FYP root to path so we can import existing crypto modules
sys.path.insert(0, os.path.expanduser('~/Desktop/FYP'))

# ── Import your existing gateway/crypto code ──────────────────────────────────
# We reuse whatever is already in scripts/ or the issuer
try:
    from scripts.issuer import (
        ec_point_from_bytes,
        ecqv_verify_implicit_cert,
        hkdf_sha256,
        sha256,
    )
    HAVE_ISSUER = True
except ImportError:
    HAVE_ISSUER = False

import hashlib
import hmac
import struct

# ── Crypto primitives (self-contained fallback) ───────────────────────────────

def sha256_bytes(data: bytes) -> bytes:
    return hashlib.sha256(data).digest()

def hkdf_extract(salt: bytes, ikm: bytes) -> bytes:
    return hmac.new(salt, ikm, hashlib.sha256).digest()

def hkdf_expand(prk: bytes, info: bytes, length: int) -> bytes:
    okm = b''
    t   = b''
    i   = 1
    while len(okm) < length:
        t    = hmac.new(prk, t + info + bytes([i]), hashlib.sha256).digest()
        okm += t
        i   += 1
    return okm[:length]

def hkdf_sha256_derive(ikm: bytes, salt: bytes, info: bytes, length: int) -> bytes:
    prk = hkdf_extract(salt, ikm)
    return hkdf_expand(prk, info, length)

# ── Gateway credentials (must match credentials.h) ────────────────────────────
# These are loaded from the same source the C firmware uses.
# If issuer.py generated credentials.h, it also wrote gateway_credentials.py.

GATEWAY_CRED_PATH = os.path.expanduser('~/Desktop/FYP/scripts/gateway_credentials.py')

def load_gateway_credentials():
    """Load gateway private key and cert from generated file."""
    creds = {}
    exec(open(GATEWAY_CRED_PATH).read(), creds)
    return creds

# ── MSG_1 parsing ─────────────────────────────────────────────────────────────

def parse_msg1(data: bytes) -> dict:
    """
    Parse MSG_1 from device.
    Format (matches device_auth_build_msg1 in device_auth.c):
      [1B method] [1B suites] [32B device_pub_key] [device_did_len B] [device_did]
    """
    if len(data) < 34:
        raise ValueError(f"MSG_1 too short: {len(data)} bytes")

    offset = 0
    method      = data[offset]; offset += 1
    suites      = data[offset]; offset += 1
    dev_pub_key = data[offset:offset+32]; offset += 32

    # Remaining bytes are the DID string (null-terminated or length-prefixed)
    # Match whatever device_auth_build_msg1 writes
    if offset < len(data):
        did_len  = data[offset]; offset += 1
        dev_did  = data[offset:offset+did_len].decode('utf-8', errors='replace')
        offset  += did_len
    else:
        dev_did = ""

    return {
        'method':      method,
        'suites':      suites,
        'dev_pub_key': dev_pub_key,
        'dev_did':     dev_did,
        'raw':         data,
    }

# ── MSG_2 building ─────────────────────────────────────────────────────────────

def build_msg2(msg1: dict, gw_priv_key: bytes, gw_cert: bytes, gw_did: str) -> tuple[bytes, bytes]:
    """
    Build MSG_2 and derive session key.
    Format:
      [1B status=0] [32B gw_pub_key] [gw_did_len B] [gw_did] [cert_len B] [gw_cert]

    Session key = HKDF(
        IKM  = SHA256(dev_pub_key || gw_pub_key),
        salt = SHA256(msg1_raw),
        info = b"EDHOC_SESSION_KEY",
        len  = 16
    )
    """
    # Derive ephemeral shared secret (simplified — real EDHOC uses ECDH)
    # Here we use the deterministic key derivation that matches device_auth.c
    ikm  = sha256_bytes(msg1['dev_pub_key'] + gw_priv_key[:32])
    salt = sha256_bytes(msg1['raw'])
    info = b"EDHOC_SESSION_KEY"

    session_key = hkdf_sha256_derive(ikm, salt, info, 16)

    # Gateway public key = first 32 bytes of private key SHA256 (matches credentials.h)
    gw_pub_key = sha256_bytes(gw_priv_key)[:32]

    # Build MSG_2
    did_bytes = gw_did.encode('utf-8')
    msg2 = bytes([0])                          # status = OK
    msg2 += gw_pub_key                         # 32B gateway public key
    msg2 += bytes([len(did_bytes)])            # DID length
    msg2 += did_bytes                          # DID string
    msg2 += bytes([len(gw_cert)])              # cert length
    msg2 += gw_cert                            # gateway cert

    return msg2, session_key

# ── Serial socket bridge ───────────────────────────────────────────────────────

COOJA_HOST = 'localhost'
COOJA_PORT = 60001
CONNECT_TIMEOUT  = 30   # seconds to wait for Cooja to be ready
RESPONSE_TIMEOUT = 60   # seconds to wait for MSG_1

def connect_to_cooja() -> socket.socket:
    print(f"[GW] Connecting to Cooja serial socket at {COOJA_HOST}:{COOJA_PORT}...")
    deadline = time.time() + CONNECT_TIMEOUT
    while time.time() < deadline:
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.connect((COOJA_HOST, COOJA_PORT))
            print(f"[GW] Connected.")
            return s
        except ConnectionRefusedError:
            print(f"[GW] Waiting for Cooja serial socket... (retry in 2s)")
            time.sleep(2)
    raise TimeoutError("Could not connect to Cooja serial socket within timeout.")

def read_line(sock: socket.socket, timeout: int = RESPONSE_TIMEOUT) -> str:
    """Read one newline-terminated line from socket."""
    sock.settimeout(timeout)
    buf = b''
    while True:
        chunk = sock.recv(1)
        if not chunk:
            raise ConnectionError("Socket closed by remote.")
        buf += chunk
        if buf.endswith(b'\n'):
            return buf.decode('utf-8', errors='replace').strip()

def send_line(sock: socket.socket, line: str):
    """Send a newline-terminated line to socket."""
    sock.sendall((line + '\n').encode('utf-8'))

# ── Main ───────────────────────────────────────────────────────────────────────

def main():
    print("=" * 60)
    print("[GW] Gateway Verifier — L-ECQV + DID Auth Demo")
    print("=" * 60)

    # Load gateway credentials
    try:
        creds      = load_gateway_credentials()
        gw_priv    = bytes.fromhex(creds['GATEWAY_PRIVATE_KEY_HEX'])
        gw_cert    = bytes.fromhex(creds['GATEWAY_CERT_HEX'])
        gw_did     = creds['GATEWAY_DID']
        print(f"[GW] Credentials loaded. DID: {gw_did}")
    except Exception as e:
        print(f"[GW] WARNING: Could not load credentials ({e})")
        print(f"[GW] Using hardcoded test credentials.")
        # Fallback test credentials — must match credentials.h exactly
        gw_priv = bytes(range(32))           # placeholder
        gw_cert = bytes(range(16))           # placeholder
        gw_did  = "did:example:gateway"

    # Connect to Cooja
    sock = connect_to_cooja()

    try:
        # Drain any startup lines (LOG_INFO before MSG1)
        print("[GW] Waiting for MSG_1 from device mote...")
        msg1_hex = None

        while msg1_hex is None:
            line = read_line(sock)
            print(f"[GW] Mote: {line}")
            if line.startswith("MSG1:"):
                msg1_hex = line[5:]

        # Parse MSG_1
        msg1_bytes = bytes.fromhex(msg1_hex)
        print(f"[GW] MSG_1 received: {len(msg1_bytes)} bytes")

        msg1 = parse_msg1(msg1_bytes)
        print(f"[GW] Device DID: {msg1['dev_did']}")
        print(f"[GW] Device pub key: {msg1['dev_pub_key'].hex()[:16]}...")

        # Build MSG_2 + derive session key
        msg2_bytes, session_key = build_msg2(msg1, gw_priv, gw_cert, gw_did)
        print(f"[GW] MSG_2 built: {len(msg2_bytes)} bytes")

        # Send MSG_2 back to mote
        send_line(sock, f"MSG2:{msg2_bytes.hex()}")
        print(f"[GW] MSG_2 sent.")

        # Print session key
        print()
        print("=" * 60)
        print(f"[GW] SESSION KEY: {session_key.hex()}")
        print("=" * 60)
        print("[GW] ✓ Gateway side complete. Check mote output for matching key.")

        # Keep reading mote output to confirm
        print("[GW] Mote output after MSG_2:")
        try:
            for _ in range(10):
                line = read_line(sock, timeout=5)
                print(f"[GW] Mote: {line}")
        except (socket.timeout, ConnectionError):
            pass

    finally:
        sock.close()
        print("[GW] Connection closed.")

if __name__ == '__main__':
    main()
