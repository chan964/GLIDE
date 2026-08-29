# GLIDE

**Gateway-Assisted Lightweight Implicit-Certificate Authentication with
Ledger-Free Decentralised Identifiers for Constrained IoT Devices**

Chanumi Pelawatte · CB016451 · BSc (Hons) Computer Science (Cyber Security)
APIIT Sri Lanka, in collaboration with the University of Staffordshire

A two-message device-authentication protocol for RFC 7228 Class-1
constrained IoT devices, combining L-ECQV implicit certificates with
ledger-free W3C DIDs. Implemented on a CC2538dk (ARM Cortex-M3, Contiki-NG),
with a Python reference implementation and formal verification in Tamarin
Prover.

Full write-up, evidence, and figures: `CB016451_FYP_FINAL_REPORT.docx`.
Demonstration video: **[add YouTube link]**

---

## Repository layout

```
src/            Python reference implementation
  edhoc_subset.py       the two-message protocol exchange
  cbor_codec.py          wire encoding
  gateway_keystore.py     gateway-side pinned issuer key store
  did_registry.py         identifier registry (Flask)
  issuer_cli.py            credential issuance tool
contiki/        Device firmware (Contiki-NG, targets cc2538dk)
  device_auth.c            protocol implementation on-device
  device_auth_main*.c       build entry points (protocol-isolated / full image)
tests/          166 automated tests across 10 modules
paper/sections/ Tamarin models (.spthy) and paper source
scripts/        cooja_serial_bridge.py, cap_evidence.sh
evidence/       Captured measurement snapshots (regenerable — see below)
```

## Setup

```bash
python3 -m venv venv
source venv/bin/activate
pip install -r requirements.txt
```

Firmware build requires [Contiki-NG](https://github.com/contiki-ng/contiki-ng)
checked out separately, and `arm-none-eabi-gcc` (13.2.1 used in development).

## Running it

**Issuer and identifier registry**
```bash
python -m src.issuer_cli init --domain 127.0.0.1:5000 --force
python -m src.did_registry
```

**Serial bridge** (pairs with a Cooja simulation of the device firmware)
```bash
python -m scripts.cooja_serial_bridge
```

**Test suite**
```bash
python -m pytest -q
```

**Firmware, protocol-isolated build**
```bash
cd contiki
make TARGET=cc2538dk CONTIKI_PROJECT=device_auth_main_footprint \
     MAKE_NET=MAKE_NET_NULLNET MAKE_ROUTING=MAKE_ROUTING_NULLROUTING
arm-none-eabi-size build/cc2538dk/device_auth_main_footprint.cc2538dk
```

**Formal verification** (Tamarin Prover, ~65s)
```bash
tamarin-prover --prove --derivcheck-timeout=600 \
  paper/sections/tamarin_model_pfs.spthy
```

**Regenerate all measurements**
```bash
bash cap_evidence.sh
```
Writes a timestamped folder under `evidence/` with a `SUMMARY.txt` comparing
every captured figure against its expected value.

## Branches

- `relay-fix` — current work. Semester 3: cross-gateway relay correction,
  forward-secrecy extension, evidence capture. **This is the branch to
  review.**
- `main` — historical, frozen at the ICATC conference submission.
- Tag `icatc-submission` — exact state submitted to ICATC 2026.

## Dataset

None. This project uses no dataset — the experimental setup is a compiled
device image, a Python gateway and issuer, and a symbolic security model.
All measurements above are regenerated from source, not learned from data.

## License

[Add if applicable]
