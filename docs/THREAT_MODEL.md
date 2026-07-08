**Architectural note:** The implementation exposes only `bootstrap_pinned()`
as a public API; TOFU is not a callable function. This is a deliberate
design decision (see `docs/DESIGN_DECISIONS.md` DD-001) to eliminate the
possibility of accidentally downgrading to insecure first-use trust.

**Why not mutual TLS with X.509?** An obvious alternative for the bootstrap
layer is mTLS with a pre-installed root CA cert. We reject this because it
reintroduces exactly what our device-layer architecture eliminates: X.509
certificate chains, CA-based trust hierarchies, and a single-point-of-failure
root CA. A reviewer tracing our architecture should see: constrained devices
use implicit certificates (no CA runtime trust), gateways verify via
reconstructed public keys (no signature chain), issuers publish via DID
documents (no CA issuance chain). Inserting X.509 at the gateway's bootstrap
layer would collapse this narrative at the most critical trust point. We
document this as future work for deployments that have existing X.509
infrastructure they wish to leverage, but our architectural commitment is
to not require it.


# Threat Model and Security Analysis

## 1. System Overview

The system authenticates resource-constrained IoT devices to gateways using
two-pass L-ECQV implicit certificates anchored in a dual-DID trust model.
Four actors participate:

- **Device**: constrained IoT node holding an L-ECQV credential and its derived
  private key `d`. Identified by a `did:key` derived from its public key.
- **Issuer (CA)**: trusted authority that issues implicit certificates.
  Identified by a `did:web` DID whose document contains the issuer's public
  key `Q_ca` in JWK format.
- **Gateway**: semi-trusted verifier. Bootstraps by fetching the issuer's DID
  document once (TOFU), pins the public key hash, and thereafter verifies
  devices offline.
- **DID Registry**: HTTPS server hosting the issuer's DID document and a
  revocation list.

Trust anchors:
- The gateway trusts the first `Q_ca` it sees from the issuer's did:web endpoint
  (TOFU pinning assumption).
- Devices trust the `d` they derive during provisioning, assuming the issuer
  honestly produced `(R, s)` and the channel during provisioning was secure.

## 2. Adversary Model

We adopt a **computational Dolev-Yao adversary** with the following capabilities:

- **Network control**: the adversary can read, modify, drop, inject, reorder,
  and replay any message on any link between Device, Issuer, Gateway, and
  Registry.
- **Cryptographic limits**: the adversary is computationally bounded. It cannot
  break SHA-256 collision resistance, the elliptic curve discrete log problem
  over P-256, or ECDSA signature unforgeability.
- **Corruption**: the adversary may statically corrupt at most one of:
  - Any number of Devices (other than the one under attack)
  - The Gateway (but not the Issuer concurrently)
  - The Issuer (but not the Gateway concurrently)

Static corruption means: the adversary fixes who is corrupted before the
protocol starts. Adaptive corruption is out of scope for this analysis.

### Explicit non-goals

- **Post-quantum security**: P-256 is broken by a sufficiently large quantum
  computer. This work assumes classical adversaries only.
- **Side-channel resistance**: timing attacks, power analysis, and fault
  injection on the device are out of scope. We assume the device environment
  resists physical attack.
- **Denial of service**: the adversary may drop messages, but protecting
  availability is not a goal of this work.
- **Privacy / unlinkability**: devices reveal a stable `did:key` across sessions.
  Unlinkable authentication is future work.

## 3. Security Goals

The protocol aims to achieve the following properties against the adversary
defined above:

### G1: Device Authentication
Only a device holding a valid `(d, R, cert_info)` tuple issued by the honest
issuer can successfully authenticate to the gateway.

### G2: Credential Integrity
An adversary that modifies `R` or `cert_info` in transit cannot cause the
gateway to accept authentication from the affected device.

### G3: No Key Escrow
The issuer, given its view `{U, R, s, k_ca, k, cert_info}` during provisioning,
cannot compute the device's private key `d`. This requires that `u` never
leaves the device.

### G4: Replay Resistance — NOT ACHIEVED
Goal: a recorded authentication transcript cannot be replayed. The two-message
design does not meet this goal — it has no gateway-issued challenge, so a
recorded MSG_1 replays within the credential validity window. Formally
confirmed (Tamarin: Gateway_Replay_Possible). Replay does not compromise the
session key (Tamarin: Session_Key_Secrecy). See §V and A3.

### G5: Revocation Completeness
A device revoked at time `T` is rejected by the gateway for all authentication
attempts at times `T' > T + Δ`, where `Δ` is the bounded revocation sync
window determined by the sync interval `I` and grace window `G`.

**Default parameters:** `I = 60s`, `G = 300s`, yielding a worst-case
exposure window of `I + G = 360s` (6 minutes) before the gateway fails closed.
Under active adversarial conditions — specifically, a network-position adversary 
selectively blocking G↔Registry traffic — the gateway is forced into GRACE state 
deliberately, extending the exposure window to the full I + G = 360s ceiling before 
fail-closed OFFLINE behavior activates. This represents the adversarially-achievable 
worst case; the nominal (non-adversarial) bound is I = 60s.
The 60-second sync interval balances registry load (approximately 17 req/s
for a population of 1000 gateways) against revocation freshness. The
5-minute grace window tolerates transient network partitions typical of
LPWAN deployments without prematurely denying service. Both values are
configurable in `revocation_sync.py`. Section [measurements] evaluates
the sensitivity of exposure window to these parameters, demonstrating
the security-vs-availability trade-off operators face when tuning them
for specific deployment profiles.

### G6: Offline-Capable Verification
After a single TOFU bootstrap, the gateway can verify device authentications
without contacting the issuer or registry, subject to the revocation freshness
window.

## 4. Informal Security Arguments

### G1 (Authentication) — Sketch
The authentication exchange binds a fresh gateway nonce `n` into the device's
signature over `(n || R || cert_info)`. Given the reconstruction identity
`d*G = e*R + Q_ca`, a valid signature verifies under the gateway's reconstructed
`Q_dev` only if the signer possesses `d`. Under ECDSA's EUF-CMA assumption on
P-256, no polynomial-time adversary can forge such a signature without `d`.

Forging `d` for a new `(R, s, cert_info)` requires either: (i) knowing `k_ca`
to compute a valid `s`, which contradicts the issuer honesty assumption and
ECDL hardness, or (ii) finding `(u', R', s')` such that the device's signature
under `d' = e'*u' + s'` verifies under the same pinned `Q_ca`, which reduces
to forging ECDSA signatures.

### G2 (Integrity of `R` and `cert_info`) — Sketch
Both values are inputs to the hash `e = H(R || cert_info)`. Any modification
changes `e`, which changes the reconstructed `Q_dev = e*R + Q_ca`. The device's
signature, produced with `d` derived from the original values, will not verify
under the tampered reconstruction. By collision resistance of SHA-256, an
adversary cannot find alternative `(R', cert_info')` yielding the same `e`.

### G2' (Integrity of `s`) — Transitive
`s` does not appear in the gateway's reconstruction formula. Its integrity is
guaranteed **transitively**: if `s` is tampered in transit, the device derives
an incorrect `d`, and its subsequent signatures fail to verify against the
correctly-reconstructed `Q_dev`. An adversary cannot produce a tampered
`s'` that yields a signing-capable `d'` without knowing `k_ca`.

### G3 (No Key Escrow) — Argument
Issuer's view: `{U, R, s, k_ca, k, cert_info}`. Device's `d = e*u + s`. The
issuer knows `s` and `cert_info`, so can compute `e`. It does not know `u`.
Deriving `u` from `U = u*G` requires solving ECDL on P-256, which is
computationally infeasible. Therefore the issuer cannot compute `d`.

### G4 (Replay Resistance) — Not Met
An earlier challenge-response design (gateway issues nonce `n`, device signs it)
would have resisted replay. The implemented two-message protocol has no gateway
challenge: the device generates its own nonce and the gateway stores no seen
nonces, so a captured MSG_1 replays successfully. Impact is bounded to
gateway-side resource use; session-key secrecy holds (Tamarin verified).

### G5 (Revocation Completeness) — Conditional
Under the ONLINE state (last sync within interval `I`), the gateway has a
revocation list at most `I` seconds stale. A device revoked at time `T` is
rejected by `T + I`.

Under GRACE state (sync failed but within grace window `G`), the gateway
continues to operate with stale revocation data, which may accept a device
revoked during the gap. This is a documented trade-off for availability;
operators choosing smaller `G` get tighter bounds at cost of higher rejection
rates under transient network failures.

Under OFFLINE state (grace exceeded), the gateway fails closed — all
authentication is rejected until sync is restored.

### G6 (Offline Verification) — Argument
After TOFU bootstrap, the gateway holds `Q_ca` locally. Reconstruction
`Q_dev = e*R + Q_ca` and signature verification are purely local computations.
The only external dependency is revocation freshness (G5).

## 5. Attack Scenarios and Mitigations

### A1: Network eavesdropping during provisioning
**Threat**: Adversary observes `(U, R, s, cert_info)` in transit.
**Impact**: None. `U` and `R` are public; `s` is integrity-bound transitively
via signature verification. Without `u` (never transmitted) or `k_ca`, the
adversary cannot derive or forge `d`.

### A2: Active MITM during provisioning
**Threat**: Adversary modifies `U`, `R`, `s`, or `cert_info` in transit
during provisioning.

**Impact and mitigations**:
- **Modifying `U`** → device derives unrelated `d`; binding to the intended
  `cert_info` holder is broken.
- **Modifying `R` or `cert_info`** → G2 applies; the device's signatures,
  produced using `d` derived from the original values, fail verification
  against the tampered reconstruction at the gateway.
- **Modifying `s`** → G2' (transitive integrity) applies; the device derives
  an incorrect `d` and its signatures fail verification.

**Deployment assumption (provisioning channel)**: The protocol assumes
provisioning occurs over an authenticated out-of-band channel — specifically
**factory provisioning over a wired connection during device manufacturing**.
In our Cooja simulation, this is modeled by pre-loading the device's
credentials `(d, R, cert_info)` into the mote firmware at compile time,
equivalent to post-manufacturing flashing over a physically-controlled
production line network. This matches real-world constrained-IoT deployment
practice (e.g., Zigbee, Matter, Philips Hue), where cryptographic material
is installed before a device ships and never re-provisioned over an
untrusted network. Network-layer enrollment protocols with mutual
authentication (e.g., EAP-based enrollment, pre-shared-key handshakes)
are architecturally compatible with our design but out of scope for this work.

### A3: Replay of captured authentication transcript
**Threat**: Adversary records a valid authentication and replays it.
**Status**: NOT MITIGATED. Replay succeeds within the credential validity
window (see G4, §V). Bounded to resource consumption; session key stays secret.

### A4: Rogue DID document on first contact (TOFU attack)
**Threat**: An adversary controls the network on the gateway's first fetch
of the issuer's DID document and serves an impostor `Q_ca`.

**Impact**: Without mitigation, the gateway would pin the impostor key and
accept devices provisioned by the impostor.

**Mitigation — Out-of-band hash distribution**: We document TOFU as a known
limitation and recommend operational mitigation via pre-configured trust
anchors: the gateway operator pre-loads the expected SHA-256 hash of the
issuer's public key `Q_ca` into the gateway's configuration before the
gateway's first contact with the registry. On bootstrap, the gateway
fetches the DID document, computes the hash of the embedded public key,
and compares against the pre-configured expected hash. A mismatch causes
bootstrap to abort; no pinning occurs.

This moves the trust anchor from network-based first-contact to an
operational provisioning step, consistent with standard IoT deployment
practice (e.g., Zigbee network keys distributed via physical touchlink or
manufacturer installation codes, enterprise gateways provisioned by
administrators with pre-shared trust roots).

Our implementation supports this via the `--trusted-issuer-hash` flag in
`gateway_keystore.py`, which, when provided, bypasses TOFU and enforces
strict hash verification on bootstrap.

**Architectural alternatives** (out of scope but compatible):
- Certificate Transparency logs for public auditability of issuer keys
- DNSSEC-signed did:web URLs leveraging existing internet infrastructure
- Blockchain-anchored DID documents for decentralized verification

### A5: Compromised gateway
**Threat**: Gateway is corrupted; attacker reads all gateway state including
the pinned `Q_ca`.
**Impact**: Attacker can verify any device authentication (it's already
public information). Attacker cannot *forge* new devices without `k_ca`.
Attacker can deny service by rejecting valid auths, but this is D-o-S, which
is explicitly out of scope.

### A6: Revocation bypass during GRACE window
**Threat**: A device is revoked at `T`, network partition begins at `T - ε`,
gateway remains in GRACE state until `T + G - ε`.
**Impact**: During the interval `(T, T + G - ε)`, the gateway accepts the
revoked device.
**Mitigation**: `G` is configurable; operators set it based on acceptable
exposure window. The paper measures this window quantitatively.



## 6. Limitations and Future Work

- **Adaptive corruption** is out of scope.
- **Formal verification** of the mutual authentication and session key agreement 
  properties has been completed using the Tamarin prover (v1.12.0) under a 
  Dolev-Yao symbolic adversary model. Three all-traces lemmas are verified: 
  gateway authentication of device (G1), device authentication of gateway (G2), 
  and session key agreement. Protocol executability (exists-trace) is falsified 
  under automatic heuristics — diagnosed to a setup-instance correlation 
  constraint in the proof search rather than a protocol logic error — and is 
  documented as a known limitation for future proof-script refinement. Secrecy, 
  forward secrecy, and revocation enforcement are not covered by the formal model 
  and remain future work.
- **Privacy** (device unlinkability across sessions) is not addressed.
- **Post-quantum migration** path is discussed but not implemented.
- **Hardware protection of `k_ca`** is not implemented; production deployments
  require HSM or PKCS#11.

  ## 6. Limitations and Future Work

### Explicit scope limitations
- **Adaptive corruption** is out of scope; only static corruption is considered.
- **Formal model scope**: The Tamarin model covers the D↔G communication channel 
  only. The adversary controls all messages between Device and Gateway. The 
  provisioning phase (Issuer_Setup, Issuer_Provision_Device) and gateway bootstrap 
  (!GatewayPinnedIssuer, !IssuerKey) are modeled as trusted setup outside adversary 
  reach — consistent with the factory-provisioning and TOFU-pinning assumptions 
  stated in A2 and A4. The G↔Registry channel (revocation sync) is not covered by 
  the Tamarin model; its security properties are analyzed separately in G5 and A6.
- **Formal verification** of the protocol (using ProVerif, Tamarin, or
  similar) is left as future work. Security arguments in this document
  are informal but constructively verifiable.
- **Privacy (unlinkability)** is not addressed. Devices present a stable
  public key across all authentication sessions, permitting correlation
  by a passive observer. Unlinkable variants (e.g., via verifiable
  credentials with selective disclosure) are future work.
- **Post-quantum migration** is discussed architecturally but not
  implemented. P-256 is broken by Shor's algorithm on a sufficiently
  large quantum computer. Migration to post-quantum signatures (e.g.,
  CRYSTALS-Dilithium) is compatible with the ECQV structure.

### Implementation-specific limitations
- **Issuer key rotation** is not implemented. Rotating `k_ca` requires
  the gateway to re-execute TOFU bootstrap against the new `Q_ca`.
  Concurrent old-and-new key validity during rotation (to support graceful
  cutover) is future work.
- **Multi-issuer federation** is out of scope. Each gateway pins exactly
  one issuer. Deployments requiring multiple trusted issuers per gateway
  require architectural extension.
- **Persistent revocation storage** is not implemented. The registry holds
  revocation entries in volatile memory; entries are lost on server
  restart. Production deployments require durable storage (e.g., SQLite,
  PostgreSQL) with periodic signed snapshots for integrity.
- **HSM protection of `k_ca`** is not implemented. The issuer's private
  key is stored in a plaintext JSON file (`issuer_key.json`) with POSIX
  0600 permissions. Production deployments require PKCS#11, TPM, or
  equivalent hardware-backed key protection.
- **Clock synchronization** between devices and gateways is assumed. The
  `cert_info.issued_at + max_age` field is evaluated against the gateway's
  local clock. Devices and gateways with drifted clocks may reject valid
  credentials or accept expired ones. NTP or equivalent time synchronization
  is a deployment assumption.
- **Side-channel resistance** of the device-side ECQV implementation is
  not evaluated. Timing attacks, power analysis, and fault injection on
  the constrained device are out of scope; we assume the device enclosure
  provides physical protection.
- **Denial of service resistance** is not addressed. The adversary may
  drop authentication messages or flood the gateway with invalid
  provisioning requests; availability under active attack is future work.