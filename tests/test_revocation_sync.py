"""
Test suite for revocation_sync.

Uses injected clock and fetch function to avoid real sleep and network.
All tests are deterministic.

Covers:
    - ONLINE state: fresh sync, not revoked / revoked lookups
    - GRACE state: stale sync but within grace window, still serves
    - OFFLINE state: past grace, fail closed (UNAVAILABLE)
    - Sync failure handling: consecutive failures, no state corruption
    - Snapshot observability
    - Thread lifecycle: start/stop, no leaks
    - Malformed registry responses rejected
    - Integration with verifier (via verify_authentication_with_revocation)
"""

import threading
import time
from datetime import datetime, timedelta, timezone
from typing import Optional

import pytest

from src.cbor_codec import AuthResponse
from src.ecqv_core import (
    device_derive_private_key,
    device_generate_contribution,
    issuer_generate_cert,
    issuer_generate_keypair,
)
from src.gateway_keystore import PinnedIssuer, _compute_q_ca_hash
from src.gateway_verifier import (
    AuthFailureReason,
)
from src.revocation_sync import (
    DEFAULT_GRACE_WINDOW_SECONDS,
    DEFAULT_SYNC_INTERVAL_SECONDS,
    RevocationCheck,
    RevocationSyncManager,
    SyncState,
)


ISSUER_DID = "did:web:issuer.example"


# ---------------------------------------------------------------------------
# Mock clock helper
# ---------------------------------------------------------------------------

class MockClock:
    """Advance-able clock for deterministic time-based testing."""

    def __init__(self, start: Optional[datetime] = None):
        self._now = start or datetime(2026, 4, 19, 12, 0, 0, tzinfo=timezone.utc)

    def __call__(self) -> datetime:
        return self._now

    def advance(self, seconds: float) -> None:
        self._now += timedelta(seconds=seconds)


# ---------------------------------------------------------------------------
# Mock fetcher
# ---------------------------------------------------------------------------

class MockFetcher:
    """Records calls and returns canned responses; can be programmed to fail."""

    def __init__(self):
        self.entries: dict[str, str] = {}
        self.call_count = 0
        self.fail_next: Optional[Exception] = None

    def __call__(self, url: str, timeout: float) -> dict:
        self.call_count += 1
        if self.fail_next is not None:
            e = self.fail_next
            self.fail_next = None
            raise e
        return {
            "revoked_at": "2026-04-19T12:00:00Z",
            "entries": dict(self.entries),
        }


# ---------------------------------------------------------------------------
# Construction and validation
# ---------------------------------------------------------------------------

def test_manager_rejects_invalid_interval():
    with pytest.raises(ValueError, match="sync_interval"):
        RevocationSyncManager("http://x", sync_interval=0)


def test_manager_rejects_negative_grace():
    with pytest.raises(ValueError, match="grace_window"):
        RevocationSyncManager("http://x", grace_window=-1)


# ---------------------------------------------------------------------------
# ONLINE state
# ---------------------------------------------------------------------------

def test_initial_state_is_offline():
    """Before any sync, the manager is OFFLINE."""
    clock = MockClock()
    fetcher = MockFetcher()
    mgr = RevocationSyncManager(
        "http://x", now_fn=clock, fetch_fn=fetcher,
    )
    assert mgr.get_state() is SyncState.OFFLINE


def test_online_after_successful_sync():
    clock = MockClock()
    fetcher = MockFetcher()
    mgr = RevocationSyncManager(
        "http://x",
        sync_interval=60,
        now_fn=clock,
        fetch_fn=fetcher,
    )
    assert mgr.sync_now() is True
    assert mgr.get_state() is SyncState.ONLINE


def test_online_not_revoked():
    clock = MockClock()
    fetcher = MockFetcher()
    mgr = RevocationSyncManager("http://x", now_fn=clock, fetch_fn=fetcher)
    mgr.sync_now()
    assert mgr.check_revocation("did:key:zAlice") is RevocationCheck.NOT_REVOKED


def test_online_revoked():
    clock = MockClock()
    fetcher = MockFetcher()
    fetcher.entries = {"did:key:zAlice": "2026-04-19T11:00:00Z"}
    mgr = RevocationSyncManager("http://x", now_fn=clock, fetch_fn=fetcher)
    mgr.sync_now()
    assert mgr.check_revocation("did:key:zAlice") is RevocationCheck.REVOKED
    assert mgr.check_revocation("did:key:zBob") is RevocationCheck.NOT_REVOKED


# ---------------------------------------------------------------------------
# GRACE state
# ---------------------------------------------------------------------------

def test_transitions_to_grace_after_interval():
    clock = MockClock()
    fetcher = MockFetcher()
    mgr = RevocationSyncManager(
        "http://x",
        sync_interval=60,
        grace_window=300,
        now_fn=clock,
        fetch_fn=fetcher,
    )
    mgr.sync_now()
    assert mgr.get_state() is SyncState.ONLINE

    clock.advance(61)   # Just past sync interval
    assert mgr.get_state() is SyncState.GRACE


def test_grace_still_serves_revocation_data():
    """Even in GRACE, check_revocation returns sensible answers."""
    clock = MockClock()
    fetcher = MockFetcher()
    fetcher.entries = {"did:key:zAlice": "2026-04-19T11:00:00Z"}
    mgr = RevocationSyncManager(
        "http://x",
        sync_interval=60,
        grace_window=300,
        now_fn=clock,
        fetch_fn=fetcher,
    )
    mgr.sync_now()
    clock.advance(100)   # Into grace

    assert mgr.get_state() is SyncState.GRACE
    assert mgr.check_revocation("did:key:zAlice") is RevocationCheck.REVOKED
    assert mgr.check_revocation("did:key:zBob") is RevocationCheck.NOT_REVOKED


# ---------------------------------------------------------------------------
# OFFLINE state (fail closed)
# ---------------------------------------------------------------------------

def test_transitions_to_offline_past_grace():
    clock = MockClock()
    fetcher = MockFetcher()
    mgr = RevocationSyncManager(
        "http://x",
        sync_interval=60,
        grace_window=300,
        now_fn=clock,
        fetch_fn=fetcher,
    )
    mgr.sync_now()
    clock.advance(61 + 301)   # Past I + G
    assert mgr.get_state() is SyncState.OFFLINE


def test_offline_reports_unavailable():
    clock = MockClock()
    fetcher = MockFetcher()
    fetcher.entries = {"did:key:zAlice": "2026-04-19T11:00:00Z"}
    mgr = RevocationSyncManager(
        "http://x",
        sync_interval=60,
        grace_window=300,
        now_fn=clock,
        fetch_fn=fetcher,
    )
    mgr.sync_now()
    clock.advance(1000)   # Way past grace

    # Even for a known-revoked device, we return UNAVAILABLE, not REVOKED
    # (OFFLINE means we don't trust our own data)
    assert mgr.check_revocation("did:key:zAlice") is RevocationCheck.UNAVAILABLE
    assert mgr.check_revocation("did:key:zBob") is RevocationCheck.UNAVAILABLE


# ---------------------------------------------------------------------------
# Sync failures
# ---------------------------------------------------------------------------

def test_sync_failure_increments_counter():
    clock = MockClock()
    fetcher = MockFetcher()
    mgr = RevocationSyncManager("http://x", now_fn=clock, fetch_fn=fetcher)
    fetcher.fail_next = ConnectionError("simulated network failure")
    assert mgr.sync_now() is False
    snap = mgr.snapshot()
    assert snap.consecutive_failures == 1
    assert snap.last_sync_attempt is not None
    assert snap.last_successful_sync is None


def test_sync_recovery_resets_failure_counter():
    clock = MockClock()
    fetcher = MockFetcher()
    mgr = RevocationSyncManager("http://x", now_fn=clock, fetch_fn=fetcher)
    fetcher.fail_next = ConnectionError("boom")
    mgr.sync_now()
    fetcher.fail_next = ConnectionError("again")
    mgr.sync_now()
    assert mgr.snapshot().consecutive_failures == 2
    # Next call succeeds
    mgr.sync_now()
    snap = mgr.snapshot()
    assert snap.consecutive_failures == 0
    assert snap.last_successful_sync is not None


def test_failed_sync_does_not_corrupt_state():
    """Stale-but-valid state should persist through a failed sync."""
    clock = MockClock()
    fetcher = MockFetcher()
    fetcher.entries = {"did:key:zAlice": "2026-04-19T11:00:00Z"}
    mgr = RevocationSyncManager("http://x", now_fn=clock, fetch_fn=fetcher)
    mgr.sync_now()
    assert mgr.check_revocation("did:key:zAlice") is RevocationCheck.REVOKED

    # Later, a sync fails — we keep old data, state might drift to GRACE
    clock.advance(70)
    fetcher.fail_next = ConnectionError("network blip")
    mgr.sync_now()

    assert mgr.check_revocation("did:key:zAlice") is RevocationCheck.REVOKED
# ---------------------------------------------------------------------------
# Malformed responses
# ---------------------------------------------------------------------------

def test_malformed_entries_rejected():
    clock = MockClock()

    class BadFetcher:
        call_count = 0
        def __call__(self, url, timeout):
            self.call_count += 1
            return {"revoked_at": "now", "entries": "not-a-dict"}

    mgr = RevocationSyncManager("http://x", now_fn=clock, fetch_fn=BadFetcher())
    assert mgr.sync_now() is False
    assert mgr.snapshot().consecutive_failures == 1


def test_missing_entries_defaults_to_empty():
    """If response has no 'entries' key, treat as empty list (not a failure)."""
    clock = MockClock()

    class EmptyFetcher:
        def __call__(self, url, timeout):
            return {"revoked_at": "now"}   # No 'entries'

    mgr = RevocationSyncManager("http://x", now_fn=clock, fetch_fn=EmptyFetcher())
    assert mgr.sync_now() is True
    assert mgr.check_revocation("did:key:zAnyone") is RevocationCheck.NOT_REVOKED


# ---------------------------------------------------------------------------
# Thread lifecycle
# ---------------------------------------------------------------------------

def test_start_stop_does_not_leak_thread():
    fetcher = MockFetcher()
    mgr = RevocationSyncManager(
        "http://x", sync_interval=1, fetch_fn=fetcher,
    )
    mgr.start(initial_sync=True)
    assert mgr._thread is not None and mgr._thread.is_alive()

    mgr.stop(timeout=2.0)
    assert mgr._thread is None or not mgr._thread.is_alive()


def test_start_twice_raises():
    fetcher = MockFetcher()
    mgr = RevocationSyncManager("http://x", fetch_fn=fetcher)
    mgr.start(initial_sync=True)
    try:
        with pytest.raises(RuntimeError, match="already started"):
            mgr.start()
    finally:
        mgr.stop()


# ---------------------------------------------------------------------------
# Integration with the verifier (end-to-end auth + revocation)
# ---------------------------------------------------------------------------
