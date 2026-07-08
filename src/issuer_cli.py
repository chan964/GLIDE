"""
Issuer CLI: command-line interface for the issuer/CA role.

Commands:
    init          Generate issuer keypair, persist to disk, print DID
    provision     Issue an implicit certificate for a device contribution
    export        Show issuer DID + public key hash (for gateway TOFU)
    list-revoked  Query the registry and show currently revoked DIDs

Key storage:
    Issuer keys are stored as JSON at the path given by --keyfile (default:
    ./issuer_key.json). The file contains k_ca (private scalar, hex-encoded)
    and Q_ca (compressed public point, hex-encoded). Never commit this file
    to git.

Design note (FYP scope limitation):
    Production deployments should use an HSM or PKCS#11 module to protect
    k_ca. We use a plain JSON file for transparency and reproducibility.
    This is a deliberate, documented trade-off appropriate for simulation.
"""

import hashlib
import json
import sys
from pathlib import Path
from typing import Optional
from urllib.parse import quote

import click
import httpx
from ecdsa import ellipticcurve
from ecdsa.util import number_to_string, string_to_number

from src.did_utils import construct_did_web, encode_did_key
from src.ecqv_core import (
    G,
    N,
    ImplicitCertificate,
    IssuerKeypair,
    compressed_to_point,
    device_generate_contribution,
    device_derive_private_key,
    gateway_reconstruct_public_key,
    issuer_generate_cert,
    issuer_generate_keypair,
    point_to_compressed,
    verify_reconstruction_identity,
)


# ---------------------------------------------------------------------------
# Keyfile persistence
# ---------------------------------------------------------------------------

def save_issuer_keypair(keypair: IssuerKeypair, path: Path) -> None:
    """Write issuer keypair to disk as JSON.

    Format:
        {
            "k_ca_hex": "...",          # Private scalar, 64 hex chars
            "Q_ca_compressed_hex": "..."  # Compressed public point, 66 hex chars
        }

    File permissions are set to 0600 (owner read/write only).
    """
    k_ca_bytes = number_to_string(keypair.k_ca, N)
    Q_ca_bytes = point_to_compressed(keypair.Q_ca)

    data = {
        "k_ca_hex": k_ca_bytes.hex(),
        "Q_ca_compressed_hex": Q_ca_bytes.hex(),
    }

    path.write_text(json.dumps(data, indent=2))
    path.chmod(0o600)   # Owner read/write only


def load_issuer_keypair(path: Path) -> IssuerKeypair:
    """Load issuer keypair from disk.

    Validates that Q_ca == k_ca * G (detects file corruption or tampering).
    Raises ValueError on mismatch.
    """
    if not path.exists():
        raise FileNotFoundError(f"Issuer keyfile not found: {path}")

    data = json.loads(path.read_text())

    k_ca_bytes = bytes.fromhex(data["k_ca_hex"])
    if len(k_ca_bytes) != 32:
        raise ValueError(f"k_ca must be 32 bytes, got {len(k_ca_bytes)}")
    k_ca = string_to_number(k_ca_bytes)

    if not (1 <= k_ca < N):
        raise ValueError("k_ca out of range [1, n-1]")

    Q_ca_bytes = bytes.fromhex(data["Q_ca_compressed_hex"])
    Q_ca = compressed_to_point(Q_ca_bytes)

    # Sanity check: Q_ca must equal k_ca * G
    if k_ca * G != Q_ca:
        raise ValueError(
            "Keyfile integrity check failed: Q_ca does not match k_ca*G. "
            "File may be corrupted or tampered."
        )

    return IssuerKeypair(k_ca=k_ca, Q_ca=Q_ca)


def compute_issuer_public_key_hash(Q_ca: ellipticcurve.PointJacobi) -> str:
    """Compute SHA-256 hash of the compressed issuer public key.

    This is what the gateway pins via TOFU. Any future fetch of the issuer's
    DID document must produce a document whose public key hashes to this value.
    """
    compressed = point_to_compressed(Q_ca)
    return hashlib.sha256(compressed).hexdigest()


# ---------------------------------------------------------------------------
# CLI group
# ---------------------------------------------------------------------------

@click.group()
@click.option(
    "--keyfile",
    type=click.Path(path_type=Path),
    default=Path("./issuer_key.json"),
    show_default=True,
    help="Path to issuer keypair JSON file.",
)
@click.pass_context
def cli(ctx: click.Context, keyfile: Path) -> None:
    """Issuer CLI for the L-ECQV + DID authentication system."""
    ctx.ensure_object(dict)
    ctx.obj["keyfile"] = keyfile


# ---------------------------------------------------------------------------
# init
# ---------------------------------------------------------------------------

@cli.command()
@click.option(
    "--domain",
    required=True,
    help="Domain for the issuer's did:web (e.g., 'issuer.example.com' or "
         "'127.0.0.1%%3A5000' for localhost:5000).",
)
@click.option(
    "--force",
    is_flag=True,
    help="Overwrite existing keyfile if present.",
)
@click.pass_context
def init(ctx: click.Context, domain: str, force: bool) -> None:
    """Generate a new issuer keypair and persist it.

    Also prints the issuer DID, public key hash (for TOFU pinning), and
    the path where the keyfile was saved.
    """
    keyfile: Path = ctx.obj["keyfile"]

    if keyfile.exists() and not force:
        click.echo(f"Keyfile already exists at {keyfile}. Use --force to overwrite.",
                   err=True)
        sys.exit(1)

    keypair = issuer_generate_keypair()
    save_issuer_keypair(keypair, keyfile)

    issuer_did = f"did:web:{domain}"
    pubkey_hash = compute_issuer_public_key_hash(keypair.Q_ca)

    click.echo("Issuer initialized.")
    click.echo(f"  Keyfile:        {keyfile}")
    click.echo(f"  Issuer DID:     {issuer_did}")
    click.echo(f"  Pubkey hash:    {pubkey_hash}")
    click.echo()
    click.echo("Pin this pubkey hash in the gateway's TOFU store on first contact.")


# ---------------------------------------------------------------------------
# provision
# ---------------------------------------------------------------------------

@cli.command()
@click.option(
    "--device-U-hex",
    required=True,
    help="Device's contribution U as 66-hex-char compressed point.",
)
@click.option(
    "--cert-info",
    required=True,
    help="Certificate metadata string (opaque to issuer; gateway parses it).",
)
@click.option(
    "--output-json",
    type=click.Path(path_type=Path),
    default=None,
    help="Write the issued certificate to this JSON file. If omitted, prints "
         "to stdout.",
)
@click.pass_context
def provision(ctx: click.Context,
              device_u_hex: str,
              cert_info: str,
              output_json: Optional[Path]) -> None:
    """Issue an implicit certificate for a device.

    The device must have already generated its contribution (u, U) and sent
    U along with desired cert_info. The issuer returns (R, s, cert_info).
    """
    keyfile: Path = ctx.obj["keyfile"]

    try:
        keypair = load_issuer_keypair(keyfile)
    except FileNotFoundError:
        click.echo(f"Keyfile {keyfile} not found. Run 'init' first.", err=True)
        sys.exit(1)

    try:
        U_bytes = bytes.fromhex(device_u_hex)
        U = compressed_to_point(U_bytes)
    except ValueError as e:
        click.echo(f"Invalid device U: {e}", err=True)
        sys.exit(1)

    cert_info_bytes = cert_info.encode("utf-8")

    try:
        cert = issuer_generate_cert(U, cert_info_bytes, keypair)
    except ValueError as e:
        click.echo(f"Cert issuance failed: {e}", err=True)
        sys.exit(1)

    result = {
        "R_compressed_hex": point_to_compressed(cert.R).hex(),
        "s_hex": number_to_string(cert.s, N).hex(),
        "cert_info_utf8": cert_info,
        "cert_info_hex": cert_info_bytes.hex(),
    }

    if output_json:
        output_json.write_text(json.dumps(result, indent=2))
        click.echo(f"Certificate written to {output_json}")
    else:
        click.echo(json.dumps(result, indent=2))


# ---------------------------------------------------------------------------
# export
# ---------------------------------------------------------------------------

@cli.command()
@click.option(
    "--domain",
    required=True,
    help="Domain used at init time.",
)
@click.pass_context
def export(ctx: click.Context, domain: str) -> None:
    """Print issuer DID, Q_ca (compressed hex), and pubkey hash for TOFU pinning."""
    keyfile: Path = ctx.obj["keyfile"]

    try:
        keypair = load_issuer_keypair(keyfile)
    except FileNotFoundError:
        click.echo(f"Keyfile {keyfile} not found. Run 'init' first.", err=True)
        sys.exit(1)

    issuer_did = f"did:web:{domain}"
    Q_ca_hex = point_to_compressed(keypair.Q_ca).hex()
    pubkey_hash = compute_issuer_public_key_hash(keypair.Q_ca)

    result = {
        "issuer_did": issuer_did,
        "Q_ca_compressed_hex": Q_ca_hex,
        "pubkey_hash_sha256": pubkey_hash,
    }
    click.echo(json.dumps(result, indent=2))


# ---------------------------------------------------------------------------
# list-revoked
# ---------------------------------------------------------------------------

@cli.command(name="list-revoked")
@click.option(
    "--registry-url",
    required=True,
    help="Base URL of the DID registry (e.g., http://127.0.0.1:5000).",
)
def list_revoked(registry_url: str) -> None:
    """Fetch the registry's revocation list and print entries."""
    url = registry_url.rstrip("/") + "/revocation.json"
    try:
        response = httpx.get(url, timeout=5.0)
        response.raise_for_status()
    except httpx.RequestError as e:
        click.echo(f"Failed to reach registry at {url}: {e}", err=True)
        sys.exit(1)
    except httpx.HTTPStatusError as e:
        click.echo(f"Registry returned {e.response.status_code}", err=True)
        sys.exit(1)

    data = response.json()
    entries = data.get("entries", {})

    if not entries:
        click.echo("No revocations currently recorded.")
        return

    click.echo(f"Revocation list fetched at {data.get('revoked_at')}:")
    for did, timestamp in entries.items():
        click.echo(f"  {did} (revoked at {timestamp})")


# ---------------------------------------------------------------------------
# generate-device: full device provisioning in one shot (for simulation)
# ---------------------------------------------------------------------------

@cli.command(name="generate-device")
@click.option(
    "--domain",
    required=True,
    help="Issuer domain (e.g., '127.0.0.1%3A5000').",
)
@click.option(
    "--device-name",
    default="device_001",
    show_default=True,
    help="Human-readable label for this device.",
)
@click.option(
    "--max-age",
    default=31_536_000,
    show_default=True,
    help="Certificate validity in seconds (default: 1 year).",
)
@click.option(
    "--output-json",
    required=True,
    type=click.Path(path_type=Path),
    help="Write full device credentials to this JSON file.",
)
@click.pass_context
def generate_device(ctx: click.Context,
                    domain: str,
                    device_name: str,
                    max_age: int,
                    output_json: Path) -> None:
    """Generate complete device credentials for simulation.

    Performs the full ECQV provisioning flow in one command:
        1. Generate device ephemeral contribution (u, U)
        2. Issue implicit certificate (R, s, cert_info)
        3. Derive device private key d
        4. Export all values to JSON for credentials.h generation

    SIMULATION ONLY: private key d is exported to disk, which is only
    appropriate for testing. In production, d is derived on-device
    and never leaves the device.
    """
    from datetime import datetime, timezone
    from src.ecqv_core import (
        device_derive_private_key,
        device_generate_contribution,
    )

    keyfile: Path = ctx.obj["keyfile"]

    try:
        keypair = load_issuer_keypair(keyfile)
    except FileNotFoundError:
        click.echo(f"Keyfile {keyfile} not found. Run 'init' first.", err=True)
        sys.exit(1)

    # Step 1: device-side contribution
    contribution = device_generate_contribution()

    # Step 2: build cert_info
    now = datetime.now(timezone.utc)
    issuer_did = f"did:web:{domain}"
    cert_info_str = f"{issuer_did}||{now.isoformat()}||{max_age}"
    cert_info_bytes = cert_info_str.encode("utf-8")

    # Step 3: issuer signs the cert
    try:
        cert = issuer_generate_cert(contribution.U, cert_info_bytes, keypair)
    except ValueError as e:
        click.echo(f"Cert issuance failed: {e}", err=True)
        sys.exit(1)

    # Step 4: device derives d
    d = device_derive_private_key(contribution, cert)

    # Step 5: export everything
    result = {
        "device_name": device_name,
        "d_hex": number_to_string(d, N).hex(),
        "R_compressed_hex": point_to_compressed(cert.R).hex(),
        "s_hex": number_to_string(cert.s, N).hex(),
        "cert_info_utf8": cert_info_str,
        "cert_info_hex": cert_info_bytes.hex(),
        "issuer_did": issuer_did,
        "simulation_note": (
            "SIMULATION ONLY: d is exported. "
            "In production, d is derived on-device and never exported."
        ),
    }

    output_json.parent.mkdir(parents=True, exist_ok=True)
    output_json.write_text(json.dumps(result, indent=2))

    click.echo(f"Device credentials written to {output_json}")
    click.echo(f"  Device name:  {device_name}")
    click.echo(f"  Issuer DID:   {issuer_did}")
    click.echo(f"  d (private):  {result['d_hex'][:16]}... (KEEP SECRET)")
    click.echo(f"  cert_info:    {cert_info_str}")
    click.echo(f"  cert valid:   {max_age} seconds from now")


# ---------------------------------------------------------------------------
# export-c: generate credentials.h for Contiki-NG firmware
# ---------------------------------------------------------------------------

@cli.command(name="export-c")
@click.option(
    "--domain",
    required=True,
    help="Issuer domain (must match what was used at init).",
)
@click.option(
    "--device-json",
    required=True,
    type=click.Path(path_type=Path),
    help="JSON file from 'generate-device --output-json'.",
)
@click.option(
    "--gateway-keystore",
    required=True,
    type=click.Path(path_type=Path),
    help="Path to gateway_keystore.json (for gateway public key).",
)
@click.option(
    "--output",
    required=True,
    type=click.Path(path_type=Path),
    help="Output path for credentials.h (e.g., contiki/credentials.h).",
)
@click.pass_context
def export_c(ctx: click.Context,
             domain: str,
             device_json: Path,
             gateway_keystore: Path,
             output: Path) -> None:
    """Generate credentials.h for Contiki-NG firmware.

    Reads the device's provisioned credentials (from 'generate-device') and
    the gateway's public key (from gateway_keystore.json), then writes a C
    header file containing all values as static byte arrays.

    The generated file is included by device_auth.c and compiled directly
    into the firmware — equivalent to factory provisioning of credentials.
    """
    from src.gateway_keystore import load_keystore

    keyfile: Path = ctx.obj["keyfile"]

    # Load issuer (for Q_ca)
    try:
        issuer = load_issuer_keypair(keyfile)
    except FileNotFoundError:
        click.echo(f"Keyfile {keyfile} not found. Run 'init' first.", err=True)
        sys.exit(1)

    # Load device JSON
    if not device_json.exists():
        click.echo(f"Device JSON not found: {device_json}", err=True)
        sys.exit(1)
    cert_data = json.loads(device_json.read_text())

    required_fields = ["d_hex", "R_compressed_hex", "cert_info_hex"]
    for field in required_fields:
        if field not in cert_data:
            click.echo(
                f"Device JSON missing required field: {field}\n"
                f"Did you generate it with 'generate-device'?",
                err=True,
            )
            sys.exit(1)

    # Load gateway keystore
    try:
        keystore = load_keystore(gateway_keystore)
    except Exception as e:
        click.echo(f"Failed to load gateway keystore: {e}", err=True)
        sys.exit(1)

    gw_pubkey_hex = point_to_compressed(keystore.gateway_identity.public_key).hex()
    Q_ca_hex = point_to_compressed(issuer.Q_ca).hex()
    issuer_did = f"did:web:{domain}"

    def hex_to_c_array(hex_str: str, name: str) -> str:
        data = bytes.fromhex(hex_str)
        length = len(data)
        hex_bytes = ", ".join(f"0x{b:02x}" for b in data)
        return (
            f"#define {name.upper()}_LEN {length}\n"
            f"static const uint8_t {name}[{name.upper()}_LEN] = {{\n"
            f"  {hex_bytes}\n"
            f"}};\n"
        )

    lines = [
        "/* credentials.h — Auto-generated by issuer_cli.py export-c",
        " * DO NOT EDIT MANUALLY.",
        " * Generated from: issuer keyfile + device JSON + gateway keystore",
        " * This file is compiled into the Contiki-NG firmware to simulate",
        " * factory provisioning of ECQV credentials.",
        " *",
        " * SECURITY NOTE: DEVICE_PRIVATE_KEY is included for simulation only.",
        " * In production, d is derived on-device and never exported.",
        " */",
        "",
        "#ifndef CREDENTIALS_H_",
        "#define CREDENTIALS_H_",
        "",
        "#include <stdint.h>",
        "",
        f"/* Issuer DID: {issuer_did} */",
        f"/* cert_info:  {cert_data['cert_info_utf8']} */",
        "",
        hex_to_c_array(cert_data["d_hex"], "DEVICE_PRIVATE_KEY"),
        hex_to_c_array(cert_data["R_compressed_hex"], "DEVICE_CERT_R"),
        hex_to_c_array(cert_data["cert_info_hex"], "DEVICE_CERT_INFO"),
        hex_to_c_array(gw_pubkey_hex, "GATEWAY_PUBLIC_KEY"),
        hex_to_c_array(Q_ca_hex, "ISSUER_PUBLIC_KEY"),
        "#endif /* CREDENTIALS_H_ */",
    ]

    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text("\n".join(lines))

    click.echo(f"credentials.h written to {output}")
    click.echo(f"  DEVICE_PRIVATE_KEY: 32 bytes")
    click.echo(f"  DEVICE_CERT_R:      33 bytes (compressed point)")
    click.echo(f"  DEVICE_CERT_INFO:   {len(bytes.fromhex(cert_data['cert_info_hex']))} bytes")
    click.echo(f"  GATEWAY_PUBLIC_KEY: 33 bytes (compressed point)")
    click.echo(f"  ISSUER_PUBLIC_KEY:  33 bytes (compressed point)")

# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------

if __name__ == "__main__":
    cli(obj={})