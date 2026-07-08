"""
energy_analysis.py — Energy consumption analysis for L-ECQV+DID protocol.

Method:
    Energest tracks CPU active time in rtimer ticks during simulation.
    CC2538dk datasheet gives current draw per mode.
    Energy = Power × Time = (V × I) × (ticks / tick_rate)

Platform: CC2538dk (ARM Cortex-M3 @ 32MHz)
Sources:
    [CC2538] Texas Instruments CC2538 Datasheet, SWRS096, Table 5
    [K21]    Krentz et al., EDHOC for Contiki-NG, IEEE MASS 2021
    [M23]    Malik et al., IEEE Access 2023
"""

import sys, os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..'))

# ── CC2538dk Hardware Constants [CC2538 Datasheet] ───────────────────────────
VCC           = 3.3          # Supply voltage (V)
RTIMER_HZ     = 32768        # CC2538 rtimer frequency (ticks/second)

# Current draw per mode (mA) [CC2538 Datasheet Table 5]
I_CPU_ACTIVE  = 10.0         # CPU active, radio off (mA)
I_RADIO_TX    = 24.0         # Radio transmitting at 0dBm (mA)
I_RADIO_RX    = 20.0         # Radio receiving (mA)
I_SLEEP       = 0.0015       # Deep sleep (mA)

# Power per mode (mW)
P_CPU_ACTIVE  = VCC * I_CPU_ACTIVE   # 33.0 mW
P_RADIO_TX    = VCC * I_RADIO_TX     # 79.2 mW
P_RADIO_RX    = VCC * I_RADIO_RX     # 66.0 mW

# ── Energest Results from Cooja Simulation ───────────────────────────────────
# From Cooja Mote output (single device run, 00:00.382 completion time)
# Cooja native mote uses simulated time — we use the protocol latency
# from our analytical estimate (864ms) as the CPU active window.
#
# In a real deployment, these values come from:
#     energest_type_time(ENERGEST_TYPE_CPU)
#     energest_type_time(ENERGEST_TYPE_TRANSMIT)
#     energest_type_time(ENERGEST_TYPE_LISTEN)
# reported by the firmware after each authentication.

# MSG_1 build: ECDSA sign + hash + CBOR encode
# Device-side only (gateway cost excluded — paper claim is device burden)
MSG1_CPU_MS   = 283.0        # ms (from analytical latency, Hutter&Schwabe)
MSG1_TX_BYTES = 224          # bytes (measured wire size)

# MSG_2 process: ECDSA verify + ECDH + HKDF
MSG2_CPU_MS   = 581.0        # ms
MSG2_RX_BYTES = 126          # bytes (measured wire size)

# Radio time for 250kbps IEEE 802.15.4 (CC2538 radio)
RADIO_RATE_KBPS = 250        # kbps
tx_time_ms = (MSG1_TX_BYTES * 8) / (RADIO_RATE_KBPS * 1000) * 1000  # ms
rx_time_ms = (MSG2_RX_BYTES * 8) / (RADIO_RATE_KBPS * 1000) * 1000  # ms

# ── Energy Calculations ───────────────────────────────────────────────────────
def mj(power_mw, time_ms):
    """Energy in millijoules = power (mW) × time (s)"""
    return power_mw * (time_ms / 1000)

# Our protocol: L-ECQV+DID
our_cpu_energy  = mj(P_CPU_ACTIVE, MSG1_CPU_MS + MSG2_CPU_MS)
our_tx_energy   = mj(P_RADIO_TX,   tx_time_ms)
our_rx_energy   = mj(P_RADIO_RX,   rx_time_ms)
our_total       = our_cpu_energy + our_tx_energy + our_rx_energy

# Baseline: X.509 + DTLS 1.3
# DTLS handshake: 6 messages, ~1250ms CPU, larger certs
# [K21] reports ~45mJ for full DTLS handshake on CC2538
dtls_cpu_ms     = 1250.0
dtls_tx_bytes   = 120 + 890   # MSG_1 + MSG_2 sizes
dtls_rx_bytes   = 890 + 120
dtls_tx_ms      = (dtls_tx_bytes * 8) / (RADIO_RATE_KBPS * 1000) * 1000
dtls_rx_ms      = (dtls_rx_bytes * 8) / (RADIO_RATE_KBPS * 1000) * 1000
dtls_cpu_energy = mj(P_CPU_ACTIVE, dtls_cpu_ms)
dtls_tx_energy  = mj(P_RADIO_TX,   dtls_tx_ms)
dtls_rx_energy  = mj(P_RADIO_RX,   dtls_rx_ms)
dtls_total      = dtls_cpu_energy + dtls_tx_energy + dtls_rx_energy

# Baseline: EDHOC standard [K21]
edhoc_cpu_ms    = 950.0
edhoc_tx_bytes  = 37 + 113
edhoc_rx_bytes  = 113 + 37
edhoc_tx_ms     = (edhoc_tx_bytes * 8) / (RADIO_RATE_KBPS * 1000) * 1000
edhoc_rx_ms     = (edhoc_rx_bytes * 8) / (RADIO_RATE_KBPS * 1000) * 1000
edhoc_cpu_energy= mj(P_CPU_ACTIVE, edhoc_cpu_ms)
edhoc_tx_energy = mj(P_RADIO_TX,   edhoc_tx_ms)
edhoc_rx_energy = mj(P_RADIO_RX,   edhoc_rx_ms)
edhoc_total     = edhoc_cpu_energy + edhoc_tx_energy + edhoc_rx_energy

# ── Output ───────────────────────────────────────────────────────────────────
W = 65
print("=" * W)
print("  Energy Consumption Analysis — L-ECQV+DID Protocol")
print("  Platform: CC2538dk (ARM Cortex-M3, VCC=3.3V)")
print("=" * W)

print(f"\n── Hardware Parameters [CC2538 Datasheet] ─────────────────")
print(f"  CPU active current:  {I_CPU_ACTIVE} mA  → {P_CPU_ACTIVE:.1f} mW")
print(f"  Radio TX current:    {I_RADIO_TX} mA  → {P_RADIO_TX:.1f} mW")
print(f"  Radio RX current:    {I_RADIO_RX} mA  → {P_RADIO_RX:.1f} mW")
print(f"  Radio data rate:     {RADIO_RATE_KBPS} kbps (IEEE 802.15.4)")

print(f"\n── Energy Breakdown: L-ECQV+DID (Our Protocol) ────────────")
print(f"  CPU active ({MSG1_CPU_MS+MSG2_CPU_MS:.0f}ms):   {our_cpu_energy:.4f} mJ")
print(f"  Radio TX  ({tx_time_ms:.2f}ms, {MSG1_TX_BYTES}B): {our_tx_energy:.4f} mJ")
print(f"  Radio RX  ({rx_time_ms:.2f}ms, {MSG2_RX_BYTES}B): {our_rx_energy:.4f} mJ")
print(f"  ─────────────────────────────────────────")
print(f"  TOTAL:                {our_total:.4f} mJ  per authentication")

print(f"\n── Comparison ──────────────────────────────────────────────")
print(f"  {'Protocol':<20} {'CPU (mJ)':>10} {'Radio (mJ)':>12} {'Total (mJ)':>12}")
print(f"  {'-'*20} {'-'*10} {'-'*12} {'-'*12}")
print(f"  {'L-ECQV+DID (ours)':<20} {our_cpu_energy:>10.4f} "
      f"{our_tx_energy+our_rx_energy:>12.4f} {our_total:>12.4f}")
print(f"  {'EDHOC standard':<20} {edhoc_cpu_energy:>10.4f} "
      f"{edhoc_tx_energy+edhoc_rx_energy:>12.4f} {edhoc_total:>12.4f}")
print(f"  {'X.509+DTLS 1.3':<20} {dtls_cpu_energy:>10.4f} "
      f"{dtls_tx_energy+dtls_rx_energy:>12.4f} {dtls_total:>12.4f}")

print(f"\n── Improvement vs X.509+DTLS 1.3 ──────────────────────────")
print(f"  Energy reduction: {(dtls_total-our_total)/dtls_total*100:.1f}%")
print(f"  ({our_total:.4f} mJ vs {dtls_total:.4f} mJ)")
print(f"  CPU dominates: {our_cpu_energy/our_total*100:.1f}% of total energy")
print(f"  Radio cost minimal: {(our_tx_energy+our_rx_energy)/our_total*100:.1f}%")

print(f"\n── Battery Life Estimate ───────────────────────────────────")
# Typical IoT battery: 2 AA cells = 3V, 2500mAh = 2500 * 3600 * 3 mJ = 27,000,000 mJ
battery_mj = 2500 * 3.6 * VCC * 1000   # mJ (2500mAh at 3.3V)
auths_possible = battery_mj / our_total
print(f"  Typical AA battery: {battery_mj/1e6:.1f} kJ ({battery_mj:.0f} mJ)")
print(f"  Authentications possible: {auths_possible:,.0f}")
print(f"  At 1 auth/hour: {auths_possible/24/365:.0f} years of operation")
print(f"  At 1 auth/min:  {auths_possible/60/24/365:.1f} years of operation")

print(f"\n── Sources ─────────────────────────────────────────────────")
print(f"  [CC2538] TI CC2538 Datasheet SWRS096, Table 5")
print(f"  [K21]    Krentz et al., IEEE MASS 2021")
print(f"  [H14]    Hutter & Schwabe, CHES 2014 (CPU latency)")
print(f"  Note: CPU latency from analytical estimates [H14].")
print(f"        Radio timing from measured wire sizes + 802.15.4 rate.")
print("=" * W)
