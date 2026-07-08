"""
Test suite for issuer_cli.

Combines unit tests (keyfile persistence) with end-to-end integration tests
(full provisioning flow via CLI, then verify reconstruction identity holds).
"""

import json
from pathlib import Path

import pytest
from click.testing import CliRunner
from ecdsa.util import number_to_string, string_to_number

from src.ecqv_core import (
    G,
    N,
    ImplicitCertificate,
    compressed_to_point,
    device_derive_private_key,
    device_generate_contribution,
    gateway_reconstruct_public_key,
    point_to_compressed,
    verify_reconstruction_identity,
)
from src.issuer_cli import (
    cli,
    compute_issuer_public_key_hash,
    load_issuer_keypair,
    save_issuer_keypair,
)


# ---------------------------------------------------------------------------
# Keyfile persistence unit tests
# ---------------------------------------------------------------------------

def test_save_and_load_keyfile_roundtrip(tmp_path: Path):
    from src.ecqv_core import issuer_generate_keypair
    original = issuer_generate_keypair()
    keyfile = tmp_path / "issuer_key.json"

    save_issuer_keypair(original, keyfile)
    assert keyfile.exists()

    loaded = load_issuer_keypair(keyfile)
    assert loaded.k_ca == original.k_ca
    assert loaded.Q_ca == original.Q_ca


def test_load_keyfile_detects_tamper(tmp_path: Path):
    """Corrupting k_ca in the file must cause load to fail."""
    from src.ecqv_core import issuer_generate_keypair
    original = issuer_generate_keypair()
    keyfile = tmp_path / "issuer_key.json"
    save_issuer_keypair(original, keyfile)

    data = json.loads(keyfile.read_text())
    # Flip one byte of k_ca
    k_ca_bytes = bytearray(bytes.fromhex(data["k_ca_hex"]))
    k_ca_bytes[0] ^= 0x01
    data["k_ca_hex"] = bytes(k_ca_bytes).hex()
    keyfile.write_text(json.dumps(data))

    with pytest.raises(ValueError, match="integrity check"):
        load_issuer_keypair(keyfile)


def test_load_missing_file_raises(tmp_path: Path):
    with pytest.raises(FileNotFoundError):
        load_issuer_keypair(tmp_path / "nonexistent.json")


def test_pubkey_hash_is_deterministic():
    from src.ecqv_core import issuer_generate_keypair
    issuer = issuer_generate_keypair()
    h1 = compute_issuer_public_key_hash(issuer.Q_ca)
    h2 = compute_issuer_public_key_hash(issuer.Q_ca)
    assert h1 == h2
    assert len(h1) == 64   # SHA-256 hex


def test_pubkey_hash_differs_between_issuers():
    from src.ecqv_core import issuer_generate_keypair
    i1 = issuer_generate_keypair()
    i2 = issuer_generate_keypair()
    assert compute_issuer_public_key_hash(i1.Q_ca) != compute_issuer_public_key_hash(i2.Q_ca)


# ---------------------------------------------------------------------------
# CLI command: init
# ---------------------------------------------------------------------------

def test_cli_init_creates_keyfile(tmp_path: Path):
    runner = CliRunner()
    keyfile = tmp_path / "issuer_key.json"
    result = runner.invoke(
        cli,
        ["--keyfile", str(keyfile), "init", "--domain", "example.com"],
    )
    assert result.exit_code == 0, result.output
    assert keyfile.exists()
    assert "Issuer DID" in result.output
    assert "Pubkey hash" in result.output


def test_cli_init_refuses_overwrite_without_force(tmp_path: Path):
    runner = CliRunner()
    keyfile = tmp_path / "issuer_key.json"

    # First init succeeds
    runner.invoke(cli, ["--keyfile", str(keyfile), "init", "--domain", "example.com"])

    # Second init without --force fails
    result = runner.invoke(
        cli, ["--keyfile", str(keyfile), "init", "--domain", "example.com"],
    )
    assert result.exit_code == 1
    assert "already exists" in result.output


def test_cli_init_overwrites_with_force(tmp_path: Path):
    runner = CliRunner()
    keyfile = tmp_path / "issuer_key.json"

    runner.invoke(cli, ["--keyfile", str(keyfile), "init", "--domain", "example.com"])
    original_content = keyfile.read_text()

    result = runner.invoke(
        cli,
        ["--keyfile", str(keyfile), "init", "--domain", "example.com", "--force"],
    )
    assert result.exit_code == 0
    # Content should have changed (new keypair)
    assert keyfile.read_text() != original_content


# ---------------------------------------------------------------------------
# CLI command: provision (unit-level)
# ---------------------------------------------------------------------------

def test_cli_provision_requires_keyfile(tmp_path: Path):
    runner = CliRunner()
    keyfile = tmp_path / "nonexistent.json"

    # Use arbitrary valid hex
    contribution = device_generate_contribution()
    U_hex = point_to_compressed(contribution.U).hex()

    result = runner.invoke(
        cli,
        [
            "--keyfile", str(keyfile),
            "provision",
            "--device-U-hex", U_hex,
            "--cert-info", "test-info",
        ],
    )
    assert result.exit_code == 1
    assert "not found" in result.output


def test_cli_provision_rejects_invalid_U(tmp_path: Path):
    runner = CliRunner()
    keyfile = tmp_path / "issuer_key.json"
    runner.invoke(cli, ["--keyfile", str(keyfile), "init", "--domain", "example.com"])

    result = runner.invoke(
        cli,
        [
            "--keyfile", str(keyfile),
            "provision",
            "--device-U-hex", "deadbeef",   # Not 33 bytes
            "--cert-info", "test-info",
        ],
    )
    assert result.exit_code == 1
    assert "Invalid device U" in result.output


# ---------------------------------------------------------------------------
# End-to-end integration test
# ---------------------------------------------------------------------------

def test_end_to_end_provisioning_flow(tmp_path: Path):
    """Complete flow: init issuer, device generates U, issuer provisions,
    device derives d, gateway reconstructs Q_dev, identity holds.

    This is THE test that proves the CLI plumbing matches the crypto math.
    """
    runner = CliRunner()
    keyfile = tmp_path / "issuer_key.json"

    # Step 1: init issuer
    init_result = runner.invoke(
        cli,
        ["--keyfile", str(keyfile), "init", "--domain", "test.example"],
    )
    assert init_result.exit_code == 0

    # Step 2: device generates contribution
    contribution = device_generate_contribution()
    U_hex = point_to_compressed(contribution.U).hex()

    # Step 3: device requests provisioning via CLI
    cert_info_str = "did:web:test.example||2026-04-19T00:00:00Z||31536000"
    provision_result = runner.invoke(
        cli,
        [
            "--keyfile", str(keyfile),
            "provision",
            "--device-U-hex", U_hex,
            "--cert-info", cert_info_str,
        ],
    )
    assert provision_result.exit_code == 0, provision_result.output

    # Step 4: parse the certificate from CLI output
    cert_data = json.loads(provision_result.output)
    R = compressed_to_point(bytes.fromhex(cert_data["R_compressed_hex"]))
    s = string_to_number(bytes.fromhex(cert_data["s_hex"]))
    cert_info_bytes = bytes.fromhex(cert_data["cert_info_hex"])

    cert = ImplicitCertificate(R=R, s=s, cert_info=cert_info_bytes)

    # Step 5: device derives its private key
    d = device_derive_private_key(contribution, cert)

    # Step 6: gateway reconstructs public key (needs issuer's Q_ca)
    issuer = load_issuer_keypair(keyfile)
    Q_dev_reconstructed = gateway_reconstruct_public_key(cert, issuer.Q_ca)

    # Step 7: THE identity must hold
    assert d * G == Q_dev_reconstructed
    assert verify_reconstruction_identity(d, cert, issuer.Q_ca)


# ---------------------------------------------------------------------------
# CLI command: export
# ---------------------------------------------------------------------------

def test_cli_export_prints_did_and_hash(tmp_path: Path):
    runner = CliRunner()
    keyfile = tmp_path / "issuer_key.json"
    runner.invoke(cli, ["--keyfile", str(keyfile), "init", "--domain", "example.com"])

    result = runner.invoke(
        cli,
        ["--keyfile", str(keyfile), "export", "--domain", "example.com"],
    )
    assert result.exit_code == 0

    data = json.loads(result.output)
    assert data["issuer_did"] == "did:web:example.com"
    assert len(data["pubkey_hash_sha256"]) == 64
    assert len(data["Q_ca_compressed_hex"]) == 66   # 33 bytes hex