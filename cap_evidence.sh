#!/usr/bin/env bash
#
# GLIDE — evidence capture
# Regenerates every locked measurement into a timestamped folder.
# Run from ~/Desktop/FYP with the venv active.
#
#   cd ~/Desktop/FYP && source venv/bin/activate
#   bash capture_evidence.sh
#
# Produces ~/Desktop/FYP/evidence/<timestamp>/ containing one file per
# measurement plus SUMMARY.txt. Safe to re-run live during the viva.
#
# Does NOT run scripts/baseline_comparison.py (fabricated output) or the
# ROM/RAM/latency sections of scripts/measure_protocol.py (dead numbers).

set -u
FYP="$HOME/Desktop/FYP"
STAMP=$(date +%Y%m%d_%H%M%S)
OUT="$FYP/evidence/$STAMP"
mkdir -p "$OUT"

MAUDE351="$HOME/Downloads/Maude-3.5.1-linux-x86_64/maude"
MAUDE32="$HOME/Downloads/Maude-3.2-linux-x86_64/maude"   # adjust if your path differs

banner () { echo; echo "=============================================="; echo "  $1"; echo "=============================================="; }

cd "$FYP" || { echo "FYP directory not found"; exit 1; }

# ---------------------------------------------------------------- 0. provenance
banner "0. Provenance"
{
  echo "Captured:        $(date -Iseconds)"
  echo "Host:            $(uname -a)"
  echo "Git branch:      $(git rev-parse --abbrev-ref HEAD)"
  echo "Git commit:      $(git rev-parse HEAD)"
  echo "Git status:      $(git status --porcelain | wc -l) uncommitted file(s)"
  echo "Python:          $(python3 --version 2>&1)"
  echo "arm-none-eabi:   $(arm-none-eabi-gcc --version 2>&1 | head -1)"
  echo "Tamarin:         $(tamarin-prover --version 2>&1 | head -1)"
} | tee "$OUT/00_provenance.txt"

# ---------------------------------------------------------------- 1. credential
# Expected: cert_info = 66 B, credential = 99 B
# Uses the BENCHMARK config (did:web:issuer.example), NOT contiki/credentials.h
# which uses did:web:127.0.0.1%3A5000 and gives 68 B.
banner "1. Credential size (benchmark config)"
python3 -c "
import sys; sys.path.insert(0, '.')
from tests.test_edhoc_subset import _make_cert_info
ci = _make_cert_info()
print(f'cert_info length in the actual e2e test: {len(ci)}B')
print(f'credential = R(33) + cert_info({len(ci)}) = {33+len(ci)}B')
" 2>&1 | tee "$OUT/01_credential_size.txt"

# ---------------------------------------------------------------- 2. wire sizes
# Expected: MSG_1=231  MSG_2=126  (total 357)
banner "2. Handshake wire sizes"
python -m pytest tests/test_edhoc_subset.py::test_e2e_handshake_happy_path -s 2>&1 \
  | grep -E "SIZES|passed|failed" | tee "$OUT/02_wire_sizes.txt"

# ---------------------------------------------------------------- 3. test suite
# Expected: 166 passed
banner "3. Full test suite"
python -m pytest -q 2>&1 | tail -20 | tee "$OUT/03_test_suite.txt"

banner "3b. Rejection-case count"
# Expected: 72
python -m pytest -q --collect-only 2>&1 | grep -ciE "reject|invalid|expired|revoked|mismatch|malformed" \
  | tee "$OUT/03b_rejection_cases.txt"

# ---------------------------------------------------------------- 4. ROM / RAM
# ROM = text.  RAM = data + bss.
# Expected full image:      text 79,952   data+bss 16,117
# Expected protocol-only:   text 64,387   data+bss  9,963
# NOTE: target is device_auth_main_footprint, NOT device_auth_main.
banner "4a. Footprint — full image (IPv6 + RPL)"
cd "$FYP/contiki" || exit 1
make TARGET=cc2538dk CONTIKI_PROJECT=device_auth_main_footprint clean >/dev/null 2>&1
make TARGET=cc2538dk CONTIKI_PROJECT=device_auth_main_footprint > "$OUT/04a_build_full.log" 2>&1
arm-none-eabi-size build/cc2538dk/device_auth_main_footprint.cc2538dk \
  | tee "$OUT/04a_footprint_full.txt"

banner "4b. Footprint — protocol isolated (NullNet, no RPL)"
make TARGET=cc2538dk CONTIKI_PROJECT=device_auth_main_footprint \
     MAKE_NET=MAKE_NET_NULLNET MAKE_ROUTING=MAKE_ROUTING_NULLROUTING clean >/dev/null 2>&1
make TARGET=cc2538dk CONTIKI_PROJECT=device_auth_main_footprint \
     MAKE_NET=MAKE_NET_NULLNET MAKE_ROUTING=MAKE_ROUTING_NULLROUTING \
     > "$OUT/04b_build_isolated.log" 2>&1
arm-none-eabi-size build/cc2538dk/device_auth_main_footprint.cc2538dk \
  | tee "$OUT/04b_footprint_isolated.txt"

cd "$FYP" || exit 1

# ---------------------------------------------------------------- 5. Tamarin
# Expected: 10 lemmas, all verified, identical step counts under both engines.
banner "5a. Tamarin under Maude 3.5.1"
{ time tamarin-prover --prove --derivcheck-timeout=600 \
    --with-maude="$MAUDE351" \
    paper/sections/tamarin_model_pfs.spthy ; } > "$OUT/05a_tamarin_maude351.txt" 2>&1
grep -E "verified|falsified|steps|^ *analyzed" "$OUT/05a_tamarin_maude351.txt" | tail -25

if [ -x "$MAUDE32" ]; then
  banner "5b. Tamarin under Maude 3.2 (cross-engine check)"
  { time tamarin-prover --prove --derivcheck-timeout=600 \
      --with-maude="$MAUDE32" \
      paper/sections/tamarin_model_pfs.spthy ; } > "$OUT/05b_tamarin_maude32.txt" 2>&1
  grep -E "verified|falsified|steps|^ *analyzed" "$OUT/05b_tamarin_maude32.txt" | tail -25

  banner "5c. Engine agreement"
  diff <(grep -oE "^ *[A-Za-z_]+ \(.*\): (verified|falsified) \([0-9]+ steps\)" "$OUT/05a_tamarin_maude351.txt") \
       <(grep -oE "^ *[A-Za-z_]+ \(.*\): (verified|falsified) \([0-9]+ steps\)" "$OUT/05b_tamarin_maude32.txt") \
       > "$OUT/05c_engine_diff.txt" 2>&1 \
    && echo "IDENTICAL verdicts and step counts under both engines" | tee -a "$OUT/05c_engine_diff.txt" \
    || echo "DIFFERENCES FOUND — see 05c_engine_diff.txt"
else
  echo "Maude 3.2 not found at $MAUDE32 — skipping cross-engine check." | tee "$OUT/05b_SKIPPED.txt"
fi

# ---------------------------------------------------------------- 6. summary
banner "6. Summary vs locked values"
{
  echo "GLIDE evidence capture — $(date -Iseconds)"
  echo "Commit: $(git rev-parse --short HEAD)  Branch: $(git rev-parse --abbrev-ref HEAD)"
  echo
  printf "%-34s %-14s %s\n" "METRIC" "EXPECTED" "CAPTURED"
  printf "%-34s %-14s %s\n" "------" "--------" "--------"
  printf "%-34s %-14s %s\n" "cert_info" "66 B" "$(grep -oE '[0-9]+B' "$OUT/01_credential_size.txt" | head -1)"
  printf "%-34s %-14s %s\n" "credential" "99 B" "$(grep -oE '= [0-9]+B' "$OUT/01_credential_size.txt" | tail -1 | tr -d '= ')"
  printf "%-34s %-14s %s\n" "MSG_1 / MSG_2" "231 / 126 B" "$(grep -oE 'MSG_1=[0-9]+ +MSG_2=[0-9]+' "$OUT/02_wire_sizes.txt" | head -1)"
  printf "%-34s %-14s %s\n" "tests passing" "166" "$(grep -oE '[0-9]+ passed' "$OUT/03_test_suite.txt" | head -1)"
  echo
  echo "ROM = text column.  RAM = data + bss."
  echo "-- full image (expected ROM 79,952 / RAM 16,117) --"
  cat "$OUT/04a_footprint_full.txt"
  echo "-- protocol isolated (expected ROM 64,387 / RAM 9,963) --"
  cat "$OUT/04b_footprint_isolated.txt"
  echo
  echo "-- Tamarin (expected 10/10 verified) --"
  grep -cE ": verified" "$OUT/05a_tamarin_maude351.txt" | sed 's/^/lemmas verified: /'
  grep -cE ": falsified" "$OUT/05a_tamarin_maude351.txt" | sed 's/^/lemmas falsified: /'
} | tee "$OUT/SUMMARY.txt"

echo
echo "Evidence written to: $OUT"
echo "Screenshot SUMMARY.txt plus the individual files for Chapters 5 and 6."
