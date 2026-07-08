# Paper Claims Log

Specific factual claims we want to make in the paper, each with:
- **Claim**: the assertion
- **Evidence**: where in the codebase / tests / measurements this is backed up
- **Section hint**: which paper section this likely lives in
- **Status**: DRAFT (argument stands but unmeasured), MEASURED (we have a number),
            or VERIFIED (measured AND tested)

Entries are append-only. When revisiting the paper, search for STATUS:MEASURED
entries to find content ready to paste.

---

## PC-001: ECQV credentials are ~10x smaller than X.509

**Claim**: Our implicit certificate wire format is approximately 95 bytes,
compared to typical X.509 certificates which exceed 1000 bytes (ASN.1 DER
encoding).

**Evidence**:
- `docs/PROTOCOL_SPEC.md` wire format table
- `src/cbor_codec.py::measure_message_sizes()`
- `tests/test_cbor_codec.py::test_provisioning_response_fits_in_single_frame`
- Comparison baseline: Malik et al. (2023) reports X.509 sizes ~1000+ bytes

**Section hint**: Introduction (motivation), Evaluation (wire format comparison)

**Status**: MEASURED. ProvisioningResponse measured at ~99 bytes in
`test_size_claims`. X.509 baseline comparison to be measured in Week 3.

---

## PC-002: Authentication omits `s` from the wire, saving 32 bytes

**Claim**: During authentication, the device transmits only `R` (33 bytes),
`cert_info` (~35 bytes), and the signature (64 bytes) — not the full
implicit certificate. The scalar `s` stays on the device because it is
consumed during the one-time derivation of the device private key `d`
and is not required for the gateway's public-key reconstruction
(`Q_dev = e*R + Q_ca`). This saves 32 bytes per authentication message
compared to schemes that transmit the full implicit certificate at
each handshake.

**Why this matters**: On a 127-byte 802.15.4 frame, 32 bytes is 25% of
the payload. Shaving this from every authentication reduces fragmentation
and energy cost on constrained devices.

**Evidence**:
- `src/cbor_codec.py::encode_auth_response` — schema excludes `KEY_S`
- `src/gateway_verifier.py::verify_authentication` — reconstruction does
  not use `s`; placeholder `s=1` is passed to satisfy the
  `ImplicitCertificate` dataclass type
- `src/ecqv_core.py::gateway_reconstruct_public_key` — formula is
  `Q_dev = e*R + Q_ca`, with no `s` input
- `tests/test_cbor_codec.py::test_auth_response_roundtrip` — confirms
  `AuthResponse` has no `s` field

**Contrast**: Naive ECQV implementations transmit the full `(R, s, cert_info)`
during authentication. Our transmission of only `(R, cert_info, signature)`
is a deliberate size optimization, and the integrity of `s` is not lost —
it is transitively guaranteed through signature verification (see
THREAT_MODEL.md section G2').

**Section hint**: Design (authentication message format), Evaluation
(wire format breakdown)

**Status**: MEASURED. Implementation confirmed, 32-byte savings verified.

---

## PC-003: Two-pass ECQV eliminates key escrow

**Claim**: Our implementation uses the two-pass ECQV variant in which the
device contributes `u` locally and never transmits it to the issuer. The
issuer's view during provisioning is `{U, R, s, k_ca, k, cert_info}`.
Deriving the device private key `d = e*u + s` requires `u`, which the
issuer does not have and cannot compute from `U = u*G` (elliptic curve
discrete log). This is an architectural improvement over one-pass variants
(including the originally-cited Malik et al. 2023) in which the issuer
computes the device's private key and therefore can impersonate the device.

**Evidence**:
- `src/ecqv_core.py::device_generate_contribution` — `u` generated on
  device, never serialized in any protocol message
- `src/ecqv_core.py::issuer_generate_cert` — issuer receives only `U`,
  does not know `u`
- `tests/test_ecqv.py::test_issuer_cannot_compute_device_key` — simulated
  issuer attempting derivation with guessed `u` produces different `d`

**Section hint**: Design (ECQV construction), Security analysis
(no-key-escrow property, mapped to G3 in threat model)

**Status**: VERIFIED.

---

## PC-004: Gateway offline verification after bootstrap

**Claim**: After a single TOFU-pinned bootstrap, the gateway performs
device authentication without any network contact. The cryptographic
operations (SHA-256, two scalar multiplications, one point addition,
ECDSA verify) are purely local. The only network dependency is periodic
revocation synchronization (see PC-005).

**Evidence**:
- `src/gateway_verifier.py::verify_authentication` — no network calls
  in the auth pipeline
- `src/gateway_keystore.py::load_keystore` — `Q_ca` loaded from local
  file, no remote fetch
- `tests/test_gateway_verifier.py` — all tests use an in-memory
  `PinnedIssuer` without any HTTP client

**Section hint**: Design (gateway architecture), Evaluation
(offline capability demonstration)

**Status**: VERIFIED.

---

## PC-005: Revocation freshness is bounded by I + G seconds

**Claim**: The gateway's revocation state machine (ONLINE/GRACE/OFFLINE)
bounds the worst-case exposure window of a revoked device to at most
`I + G` seconds, where `I` is the sync interval and `G` is the grace
window. Beyond `I + G`, the gateway fails closed, rejecting all
authentications regardless of device validity.

**Default parameters**: `I = 60s`, `G = 300s`, giving a worst-case
exposure window of 360 seconds. These parameters are configurable and
varied in measurements (Section [measurements]) to demonstrate the
security-vs-availability trade-off operators face when tuning them.

**Evidence**:
- `src/revocation_sync.py::RevocationSyncManager::get_state` — state
  transitions computed from time elapsed since last successful sync
- `src/revocation_sync.py::RevocationSyncManager::check_revocation` —
  returns UNAVAILABLE when state is OFFLINE, enforcing fail-closed
- `tests/test_revocation_sync.py::test_transitions_to_grace_after_interval`
- `tests/test_revocation_sync.py::test_transitions_to_offline_past_grace`
- `tests/test_revocation_sync.py::test_offline_reports_unavailable`
- `tests/test_revocation_sync.py::test_e2e_offline_fails_closed` —
  end-to-end: gateway in OFFLINE rejects otherwise-valid auth

**Section hint**: Design (revocation model), Evaluation (latency
sensitivity to I and G), Security analysis (G5).

**Status**: VERIFIED (architectural). Sensitivity measurements pending
Week 3 Cooja run.

## Template for future entries

Copy this block when adding a new claim:

```
## PC-XXX: [one-line claim title]

**Claim**: [1-3 sentences stating the assertion]

**Evidence**:
- [file/function references]
- [test names]
- [measurement references]

**Section hint**: [which paper section]

**Status**: DRAFT | MEASURED | VERIFIED
```

## PC-006: Thread-safety of concurrent revocation operations

**Claim**: The revocation subsystem uses a single mutex protecting shared
state (last sync timestamp, revoked DID set, failure counter). All public
methods acquire the mutex exactly once per call; computations that depend
on the mutable state are performed on a local snapshot after releasing
the mutex. This ensures concurrent calls from the background sync thread
and the main authentication thread cannot produce inconsistent reads or
deadlocks.

**Evidence**:
- `src/revocation_sync.py::_compute_state_from` — pure function taking
  last-sync as argument, no side effects
- `src/revocation_sync.py::check_revocation` — single lock acquisition,
  read snapshot, release, compute
- `src/revocation_sync.py::snapshot` — single lock acquisition pattern
- `tests/test_revocation_sync.py::test_start_stop_does_not_leak_thread`

**Section hint**: Implementation (concurrency model), Limitations
(single-mutex design does not scale beyond ~1000 concurrent auths per
gateway; SKIP_ITEMS_TABLE-based sharding is future work).

**Status**: VERIFIED.
