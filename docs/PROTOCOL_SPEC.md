# Protocol Specification

## ECQV Two-Pass Variant

### Parameters
- Curve: secp256r1 (NIST P-256), also known as NIST256p
- Hash function: SHA-256, output reduced mod curve order n
- Point encoding: SEC1 compressed (33 bytes per point)
- Scalar encoding: 32-byte big-endian

### Protocol Flow

**Provisioning (two-pass):**
1. Device picks random `u ∈ [1, n-1]`, computes `U = u*G`, sends `U` and `cert_info` to issuer
2. Issuer picks random `k ∈ [1, n-1]`, computes `R = U + k*G`
3. Issuer computes `e = H(R_compressed || cert_info) mod n`
4. Issuer computes `s = (e*k + k_ca) mod n`
5. Issuer returns `(R, s, cert_info)` to device
6. Device computes `d = (e*u + s) mod n` as its long-term private key
7. Device may discard `u`; retains `d`, `R`, `cert_info`

**Verification (gateway-side):**
1. Gateway has `Q_ca` pinned via TOFU from did:web bootstrap
2. Receives `(R, cert_info)` from device during authentication
3. Computes `e = H(R_compressed || cert_info) mod n`
4. Reconstructs `Q_dev = e*R + Q_ca`
5. Verifies device signature on authentication challenge using `Q_dev`

### Reconstruction Identity
The correctness of ECQV relies on: 
dG = (eu + s)G 
= euG + sG
= eU + (ek + k_ca)G
= eU + ekG + k_caG
= e(U + kG) + Q_ca
= eR + Q_ca

### Security Notes

**No key escrow (two-pass property):** The issuer's view during provisioning
is `{U, R, s, k_ca, k, cert_info}`. The issuer does not know `u`. Without `u`,
the issuer cannot compute `d = e*u + s`. This distinguishes our construction
from one-pass ECQV variants where the issuer computes the device's private key.

**Integrity of `s` (transitive guarantee):** The gateway's reconstruction
formula `Q_dev = e*R + Q_ca` does not include `s`. Therefore, `s` has no
standalone integrity check at verification time. The integrity of `s` is
guaranteed transitively: if `s` is tampered in transit before the device
derives `d`, the device's resulting `d` will be incorrect, and any signature
produced with that `d` will fail verification against the gateway's
correctly-reconstructed `Q_dev`. An attacker cannot forge a valid
`(R, s, cert_info)` tuple without knowing `k_ca`, because `s` binds `k`
(which determined `R`) to `k_ca`.

**Integrity of `R` and `cert_info` (direct guarantee):** Any modification to
`R` or `cert_info` changes `e`, which changes the reconstructed `Q_dev`.
The device's signature, produced with the `d` derived from the original
values, will fail verification against the tampered reconstruction.

**TOFU pinning assumption:** The gateway pins `Q_ca` on first contact with
the issuer's did:web document. Subsequent verifications use the pinned `Q_ca`.
Compromise of the issuer after pinning does not retroactively invalidate
authentications of devices provisioned before compromise, provided the
issuer's private key `k_ca` has not been leaked.

### Wire Format Sizes
| Field        | Size (bytes) |
|--------------|--------------|
| R (point)    | 33           |
| s (scalar)   | 32           |
| cert_info    | ~30 (CBOR)   |
| **Total**    | **~95**      |

Compare: X.509 certificate (ASN.1 DER) is typically 1000+ bytes.
Reduction factor: ~10x.