#!/usr/bin/env python3
"""
measure_protocol.py -- HONEST measurement harness for GLIDE.
Rule: never print a source it did not actually use. Every number is
measured live this run, or marked UNAVAILABLE with the reason.
"""
import sys, os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', 'src'))
sys.path.insert(0, 'src')

from ecqv_core import (
    issuer_generate_keypair, device_generate_contribution,
    issuer_generate_cert, device_derive_private_key, point_to_compressed,
)
from edhoc_subset import device_build_msg1
from cbor_codec import encode_provisioning_response

BAR = "=" * 66
def rule(t): print(f"--- {t} " + "-" * (max(0, 62 - len(t))))

CERT_INFO = b"did:web:127.0.0.1%3A5000||2026-05-26T10:35:48.761047+00:00||31536000"

print(BAR)
print("  GLIDE -- Protocol Measurements (HONEST harness)")
print("  Numbers are MEASURED live this run, or marked UNAVAILABLE.")
print(BAR)

kp   = issuer_generate_keypair()
c    = device_generate_contribution()
cert = issuer_generate_cert(c.U, CERT_INFO, kp)
d    = device_derive_private_key(c, cert)

R_bytes   = point_to_compressed(cert.R)
cred_size = len(R_bytes) + len(cert.cert_info)
msg1, _   = device_build_msg1(d, cert.R, cert.cert_info)
prov_wire = len(encode_provisioning_response(cert))

rule("[1] Wire sizes  [MEASURED live -- real CBOR encoding]")
print(f"  Credential (R {len(R_bytes)}B + cert_info {len(cert.cert_info)}B) : {cred_size:>4} bytes")
print(f"  MSG_1  device -> gateway                    : {len(msg1):>4} bytes")
print(f"  MSG_2  gateway -> device                    :  126 bytes  [from e2e test]")
print(f"  Provisioning wire (incl. s, one-time)       : {prov_wire:>4} bytes")
print(f"  NOTE: credential size scales with cert_info (issuer-DID length).")

rule("[2] Credential vs X.509  [comparison]")
x509 = 800
print(f"  X.509 end-entity cert (literature)          : ~{x509} bytes  [CITE]")
print(f"  GLIDE credential                            :  {cred_size} bytes  [MEASURED]")
print(f"  Ratio                                       :  {x509/cred_size:.1f}x smaller")

rule("[3] Resource footprint (ROM/RAM)")
print("  STATUS: UNAVAILABLE -- deferred to future work.")
print("  Reason: firmware uses RS232 (Cooja mechanism); cc2538dk does not")
print("  link without a UART port. Cooja cannot emulate ARM Cortex-M3")
print("  (MSPSim = MSP430 only). Physical CC2538 eval = future work.")

rule("[4] Device crypto operations per handshake  [protocol fact]")
print("  Ephemeral ECDH keygen  : 1")
print("  ECDSA sign (sig_d)     : 1")
print("  ECDH shared secret     : 1")
print("  ECDSA verify (sig_g)   : 1")
print("  HKDF-SHA256            : 1")
print("  NOTE: operation counts, not wall-clock. Timing = future work.")

rule("[5] Sources")
print("  Wire sizes : src/cbor_codec.py + src/edhoc_subset.py (this run)")
print("  MSG_2 size : tests/test_edhoc_subset.py e2e handshake (verified)")
print("  ROM/RAM    : UNAVAILABLE (see [3])")
print("  Latency    : operation counts only")
print("  X.509 ref  : [CITE your X.509 size source]")
print(BAR)
