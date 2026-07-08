"""
Test suite for parse_cert_info (from gateway_verifier).

parse_cert_info is shared by the live two-message EDHOC handshake path; these
unit tests exercise its edge cases directly with raw byte input. Extracted from
the former test_gateway_verifier.py when the superseded challenge-response
(Path A) tests were removed.
"""
from datetime import timezone

import pytest

from src.gateway_verifier import parse_cert_info


def test_parse_cert_info_happy_path():
    ci = b"did:web:x||2026-04-19T00:00:00+00:00||31536000"
    parsed = parse_cert_info(ci)
    assert parsed.issuer_did == "did:web:x"
    assert parsed.max_age_seconds == 31_536_000
    assert parsed.issued_at.tzinfo is not None


def test_parse_cert_info_naive_datetime_becomes_utc():
    ci = b"did:web:x||2026-04-19T00:00:00||31536000"
    parsed = parse_cert_info(ci)
    assert parsed.issued_at.tzinfo is timezone.utc


def test_parse_cert_info_rejects_wrong_field_count():
    with pytest.raises(ValueError, match="3 pipe-delimited"):
        parse_cert_info(b"only||two")


def test_parse_cert_info_rejects_non_did_issuer():
    with pytest.raises(ValueError, match="not a DID"):
        parse_cert_info(b"not-a-did||2026-04-19T00:00:00||31536000")


def test_parse_cert_info_rejects_bad_timestamp():
    with pytest.raises(ValueError, match="ISO 8601"):
        parse_cert_info(b"did:web:x||not-a-date||31536000")


def test_parse_cert_info_rejects_non_integer_max_age():
    with pytest.raises(ValueError, match="not an integer"):
        parse_cert_info(b"did:web:x||2026-04-19T00:00:00||abc")


def test_parse_cert_info_rejects_negative_max_age():
    with pytest.raises(ValueError, match="positive"):
        parse_cert_info(b"did:web:x||2026-04-19T00:00:00||-1")


def test_parse_cert_info_rejects_invalid_utf8():
    with pytest.raises(ValueError, match="UTF-8"):
        parse_cert_info(b"\xff\xfe||x||1")
