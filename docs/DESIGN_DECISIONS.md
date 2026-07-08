# Design Decisions Log

Each entry documents an architectural choice: what was decided, what
alternatives were considered, and why the chosen option was selected.

Entries are append-only. Do not rewrite past decisions; add a new entry
if reasoning changes.

---

## DD-001: Trust anchor for gateway bootstrap

**Date:** 2026-04-19
**Status:** Decided
**Module:** `src/gateway_keystore.py`

### Decision
Gateway trust anchor is established via **operator-distributed hash pinning**.
The keystore implements `bootstrap_pinned()` only; first-use-trust (TOFU)
is not exposed as a callable API. `bootstrap_mode` is restricted to
`"pinned"` at load time.

### Alternatives considered

**A. Pure TOFU (trust first contact).**
Rejected: vulnerable to first-contact MITM. The attacker sitting between
gateway and registry on bootstrap wins forever. No cryptographic mechanism
to recover from a mis-pinned anchor.

**B. TOFU + pinned (both modes available).**
Rejected: exposing TOFU as a callable function creates footgun risk. An
operator or maintainer could default to TOFU for "simplicity" and ship
production with an insecure bootstrap. Removing TOFU from the API makes
the insecure path architecturally impossible.

**C. Mutual TLS with X.509 chain.**
Rejected: contradicts the thesis. Our architecture's motivation is that
X.509 + CA chains are too heavy for constrained IoT and reintroduce
single-point-of-failure centralized trust. Using mTLS at the gateway
bootstrap layer would reintroduce X.509 and a root CA at a critical
trust-anchor point, inheriting exactly what the device-layer architecture
eliminates. A reviewer would correctly point out the contradiction.

**D. DNSSEC-signed did:web URLs.**
Rejected for scope: DNSSEC deployment is <10% globally, adds DNS dependency
that constrained networks may not have, and adds validation complexity
without clear win over operator-distributed hashes. Compatible architectural
alternative; documented as future work.

**E. Certificate Transparency logs.**
Rejected for scope: requires trusted log infrastructure (which reintroduces
centralization concerns), needs log inclusion proofs (adds bandwidth),
overkill for simulation scale. Strong for production with public-issuer
scale; out of scope for workshop paper.

**F. Blockchain-anchored DIDs.**
Rejected: directly contradicts the proposal's motivation. Ramírez-Gordillo
et al. (2025), cited in our proposal, identifies blockchain DID resolution
as impractical for constrained IoT. Using it for gateway bootstrap (where
the gateway has more resources than devices) is architecturally possible
but undermines the narrative.

**G. Pre-shared symmetric key.**
Rejected: same operational burden as hash distribution but worse security
properties (symmetric key compromise breaks both ends; hash compromise
only breaks on issuer-side key disclosure). Hash pinning is strictly
better for the same cost.

### Rationale summary
Pinned bootstrap + operator-distributed hash delegation moves the trust
anchor from the network to the operator, consistent with real-world IoT
deployment practice (Zigbee network keys, Matter commissioning codes,
Bluetooth Mesh provisioning). This preserves the architecture's "no
heavyweight PKI, no centralized CA" thesis while providing cryptographically
strong bootstrap security.

### Implementation consequence
- `bootstrap_pinned()` is the only public bootstrap API
- `load_keystore()` rejects any `bootstrap_mode != "pinned"`
- Test `test_load_rejects_tofu_bootstrap_mode` proves by construction
  that TOFU cannot be silently introduced via file tampering

---

---

## DD-003: EDHOC subset — scope and authentication method

**Date:** 2026-04-19
**Status:** Decided
**Module:** `src/edhoc_subset.py` (new), `src/gateway_keystore.py` (extended)

### Decision

We implement a **restricted subset of RFC 9528 (EDHOC)** for establishing
a session key between device and gateway after authentication. Explicitly
non-interoperable with standard EDHOC implementations.

Four concrete sub-decisions:

1. **Method 0 (signature-based on both sides).**
2. **Two-message handshake (MSG_1 + MSG_2); no MSG_3.**
3. **Device pre-provisioned with gateway's public key (factory provisioning).**
4. **Gateway keypair persisted to disk with 90-day lifetime; rotation deferred.**

### Alternatives considered

**1a. Method 3 (static-DH both sides).** Elegant — reuses ECQV `d` directly,
no new crypto on device. Rejected for scope: requires the gateway to have
its own ECQV cert, which requires a new provisioning flow for gateways.
Adds ~2 days to implementation; schedule does not allow.

**2a. Full three-message RFC 9528.** Adds explicit key confirmation (the
device gets cryptographic proof the gateway derived the same session key).
Rejected for scope: adds a full round-trip, a third wire format, and
~1 day of work. Documented limitation: our subset provides implicit key
confirmation through first successful encrypted message; a reviewer will
accept this with the documented limitation.

**3a. Gateway publishes `did:web`; device resolves at runtime.** Matches the
issuer pattern. Rejected: requires devices to make HTTP calls over an
untrusted network, contradicting PC-004 (offline-capable verification).
The architectural value of offline verification is greater than the
architectural consistency of uniform DID resolution.

**3b. Gateway keypair signed by issuer (hierarchical trust).** Elegant —
removes need for pre-provisioning gateway key on device. Rejected:
reintroduces a signing hierarchy that our architecture deliberately avoids
(see DD-001 argument against mTLS/X.509 chains). Also adds an issuer
signing step for every gateway keypair change.

**4a. Ephemeral gateway keypair (fresh on every startup).** Simplest code.
Rejected: device's pre-provisioned gateway key becomes stale on every
gateway restart, breaking authentication at real operational frequencies.

**4b. Persistent gateway keypair forever, no rotation awareness.** Simpler
than our compromise. Rejected: does not reflect real-world operational
security practice. A long-running gateway compromised at year N exposes
all historical and future sessions.

**4c. Full rotation protocol with overlap window.** Matches real-world
certificate rotation. Rejected for scope: requires a rotation message
flow, device-side dual-key acceptance, and operator tooling. Adds
~1-2 days; schedule does not allow. Documented as future work.

### Rationale summary

Method 0 maximizes reuse of existing ECDSA-over-ECQV signing code and
minimizes protocol surface area. Two messages is the minimum for mutual
authentication and shared-key establishment; the third message's key
confirmation is documented as a known limitation.

Factory provisioning of the gateway's public key is consistent with our
broader commitment to pre-provisioned trust anchors (DD-001 for issuer,
A2 in threat model for device credentials) and preserves offline-capable
verification (PC-004).

Gateway keypair persistence with documented lifetime captures the real
operational property without implementing full rotation. The 90-day
default matches enterprise TLS renewal cycles and is configurable.
Importantly, this choice does not affect the device-side cost of
authentication: the device performs one ECDSA verification per handshake
regardless of how often the gateway's keypair has rotated.

### Explicit non-claims

- **We do NOT claim RFC 9528 interoperability.** The module name is
  `edhoc_subset` to make this explicit.
- **We do NOT claim full key confirmation.** Two-message handshake provides
  implicit confirmation; full three-message confirmation is future work.
- **We do NOT claim device identity privacy.** Device's DID and cert appear
  in MSG_1 in the clear; cross-session linkability is preserved.
- **We do NOT claim automatic gateway key rotation.** Expiry is logged;
  operator action is required to rotate.

### Paper implications

Section "Design" will frame the EDHOC subset as scaffolding for the ECQV
integration, not as our novel contribution. Section "Limitations" will
include the three non-claims above. Section "Future work" will include
full RFC 9528 compliance, device identity privacy via MSG_3-style
encrypted identities, and gateway key rotation protocols.

---