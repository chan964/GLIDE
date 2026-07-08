#!/usr/bin/env python3
"""
cooja_serial_bridge.py — Wires Cooja's Serial Socket to the EDHOC gateway.

Run BEFORE starting the Cooja simulation. This script:
  1. Listens on TCP port 60001 (Cooja Serial Socket CLIENT mode connects here)
  2. Reads MSG1:<hex> line from the mote
  3. Passes raw bytes to gateway_process_msg1_build_msg2()
  4. Sends MSG2:<hex> back to the mote
  5. Prints the derived session key

Usage:
  cd ~/Desktop/FYP
  python -m scripts.cooja_serial_bridge
"""

import socket
import sys
from pathlib import Path

# Make src/ importable
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from src.edhoc_subset import gateway_process_msg1_build_msg2
from src.gateway_keystore import load_keystore

KEYSTORE_PATH = Path(__file__).resolve().parent.parent / "gateway_keystore.json"
HOST = "localhost"
PORT = 60001


def read_line(conn: socket.socket) -> str:
    buf = b""
    while True:
        ch = conn.recv(1)
        if not ch:
            raise ConnectionError("Socket closed before newline.")
        buf += ch
        if buf.endswith(b"\n"):
            return buf.decode("utf-8", errors="replace").strip()


def send_line(conn: socket.socket, line: str):
    conn.sendall((line + "\n").encode("utf-8"))


def main():
    print("=" * 60)
    print("[BRIDGE] Cooja Serial Bridge — L-ECQV + DID EDHOC Demo")
    print("=" * 60)

    # Load keystore
    try:
        keystore = load_keystore(KEYSTORE_PATH)
        print(f"[BRIDGE] Keystore loaded. Issuer: {keystore.pinned_issuer.issuer_did}")
    except Exception as e:
        print(f"[BRIDGE] ERROR loading keystore: {e}")
        sys.exit(1)

    # Listen for Cooja to connect
    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    server.bind((HOST, PORT))
    server.listen(1)
    print(f"[BRIDGE] Listening on {HOST}:{PORT} — now start the Cooja simulation.")

    conn, addr = server.accept()
    print(f"[BRIDGE] Cooja connected from {addr}")

    try:
        # Drain log lines until we see MSG1:
        msg1_hex = None
        while msg1_hex is None:
            line = read_line(conn)
            print(f"[MOTE]   {line}")
            if line.startswith("MSG1:"):
                msg1_hex = line[5:]

        msg1_bytes = bytes.fromhex(msg1_hex)
        print(f"[BRIDGE] MSG_1 received: {len(msg1_bytes)} bytes")

        # Hand off to the real gateway logic
        result = gateway_process_msg1_build_msg2(keystore, msg1_bytes)

        if not result.success:
            print(f"[BRIDGE] AUTH FAILED: {result.reason} — {result.detail}")
            sys.exit(1)

        print(f"[BRIDGE] Device authenticated. DID: {result.device_did}")
        print(f"[BRIDGE] MSG_2 built: {len(result.msg2_bytes)} bytes")

        # Send MSG2 back to mote
        send_line(conn, f"MSG2:{result.msg2_bytes.hex()}")
        print(f"[BRIDGE] MSG_2 sent.")

        # Print session key
        print()
        print("=" * 60)
        print(f"[BRIDGE] SESSION KEY: {result.session_key.hex()}")
        print("=" * 60)

        # Read remaining mote output (session key print + done)
        print("[BRIDGE] Mote output:")
        try:
            conn.settimeout(10)
            for _ in range(20):
                line = read_line(conn)
                print(f"[MOTE]   {line}")
                if "Done" in line or "=== Done ===" in line:
                    break
        except (socket.timeout, ConnectionError):
            pass

        print()
        print("[BRIDGE] ✓ Handshake complete. Compare session keys above.")

    finally:
        conn.close()
        server.close()


if __name__ == "__main__":
    main()
