"""
Revocation sync: ONLINE/GRACE/OFFLINE state machine for periodic revocation
list synchronization.

Implements the bounded-exposure revocation model described in
THREAT_MODEL.md G5 and PAPER_CLAIMS.md PC-005.

States:
    ONLINE:  last successful sync <= I seconds ago.
             Behavior: authenticate using cached revocation list.
    GRACE:   I < time since last sync <= I + G.
             Behavior: continue authenticating with stale data; warn.
    OFFLINE: time since last sync > I + G.
             Behavior: FAIL CLOSED — reject all authentications.

Default parameters (configurable, see THREAT_MODEL.md G5):
    I = 60 seconds (sync interval)
    G = 300 seconds (grace window)
    Worst-case exposure window = I + G = 360 seconds

Threading:
    A background thread periodically fetches the revocation list.
    The main thread calls check_revocation() synchronously, which reads
    a mutex-protected snapshot. The sync thread never blocks the main
    thread's authentication work.

Testability:
    - now_fn: injectable clock (default: datetime.now(UTC))
    - fetch_fn: injectable HTTP fetcher (default: httpx.get)
    Tests override both to avoid real sleep/network, making the state
    machine deterministic.
"""

import logging
import threading
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from enum import Enum
from typing import Callable, Optional

import httpx


log = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Defaults and types
# ---------------------------------------------------------------------------

DEFAULT_SYNC_INTERVAL_SECONDS = 60
DEFAULT_GRACE_WINDOW_SECONDS = 300


class SyncState(Enum):
    ONLINE = "online"
    GRACE = "grace"
    OFFLINE = "offline"


class RevocationCheck(Enum):
    NOT_REVOKED = "not_revoked"
    REVOKED = "revoked"
    UNAVAILABLE = "unavailable"   # Gateway is OFFLINE — fail closed


@dataclass
class SyncSnapshot:
    """Immutable snapshot of sync state at a point in time."""
    state: SyncState
    last_successful_sync: Optional[datetime]
    last_sync_attempt: Optional[datetime]
    revoked_dids: frozenset[str] = field(default_factory=frozenset)
    consecutive_failures: int = 0


# ---------------------------------------------------------------------------
# Fetcher protocol (default implementation)
# ---------------------------------------------------------------------------

def _default_fetch(url: str, timeout: float) -> dict:
    """Default fetcher: HTTP GET via httpx. Returns parsed JSON."""
    response = httpx.get(url, timeout=timeout)
    response.raise_for_status()
    return response.json()


# ---------------------------------------------------------------------------
# The sync manager
# ---------------------------------------------------------------------------

class RevocationSyncManager:
    """Manages periodic revocation list sync and the ONLINE/GRACE/OFFLINE
    state machine.

    Usage:
        manager = RevocationSyncManager(
            registry_url="http://issuer.example/revocation.json",
            sync_interval=60,
            grace_window=300,
        )
        manager.start()   # Launches background sync thread

        # On each authentication attempt:
        check = manager.check_revocation(device_did)
        if check is RevocationCheck.REVOKED:
            reject(...)
        elif check is RevocationCheck.UNAVAILABLE:
            reject(...)   # Fail closed
        else:
            accept(...)

        manager.stop()   # On shutdown
    """

    def __init__(
        self,
        registry_url: str,
        sync_interval: int = DEFAULT_SYNC_INTERVAL_SECONDS,
        grace_window: int = DEFAULT_GRACE_WINDOW_SECONDS,
        fetch_timeout: float = 5.0,
        now_fn: Callable[[], datetime] = lambda: datetime.now(timezone.utc),
        fetch_fn: Optional[Callable[[str, float], dict]] = None,
    ):
        if sync_interval <= 0:
            raise ValueError("sync_interval must be positive")
        if grace_window < 0:
            raise ValueError("grace_window must be non-negative")

        self.registry_url = registry_url
        self.sync_interval = sync_interval
        self.grace_window = grace_window
        self.fetch_timeout = fetch_timeout
        self._now_fn = now_fn
        self._fetch_fn = fetch_fn or _default_fetch

        self._lock = threading.Lock()
        self._stop_event = threading.Event()
        self._thread: Optional[threading.Thread] = None

        # Protected state (always access under self._lock)
        self._last_successful_sync: Optional[datetime] = None
        self._last_sync_attempt: Optional[datetime] = None
        self._revoked_dids: frozenset[str] = frozenset()
        self._consecutive_failures: int = 0

    # -----------------------------------------------------------------------
    # Thread lifecycle
    # -----------------------------------------------------------------------

    def start(self, initial_sync: bool = True) -> None:
        """Launch the background sync thread.

        If initial_sync is True (default), performs a synchronous sync
        before returning. This ensures the gateway has fresh revocation
        data on startup before accepting authentications.
        """
        if self._thread is not None and self._thread.is_alive():
            raise RuntimeError("Sync manager already started")

        if initial_sync:
            self._sync_once()

        self._stop_event.clear()
        self._thread = threading.Thread(
            target=self._sync_loop,
            daemon=True,
            name="RevocationSync",
        )
        self._thread.start()

    def stop(self, timeout: float = 2.0) -> None:
        """Signal the sync thread to exit and wait for it to finish."""
        self._stop_event.set()
        if self._thread is not None:
            self._thread.join(timeout=timeout)
            self._thread = None

    # -----------------------------------------------------------------------
    # Sync operations
    # -----------------------------------------------------------------------

    def _sync_loop(self) -> None:
        """Background loop: wake every second, sync if interval elapsed.

        Sleeps in 1-second increments so stop() is responsive.
        """
        last_sync_wall = self._now_fn()
        while not self._stop_event.is_set():
            self._stop_event.wait(timeout=1.0)
            if self._stop_event.is_set():
                break

            now = self._now_fn()
            if (now - last_sync_wall).total_seconds() >= self.sync_interval:
                self._sync_once()
                last_sync_wall = self._now_fn()

    def _sync_once(self) -> bool:
        """Perform one sync attempt. Returns True on success, False on failure.

        Public method (sync_now) is a thin wrapper for testability.
        """
        attempt_time = self._now_fn()
        try:
            data = self._fetch_fn(self.registry_url, self.fetch_timeout)
        except Exception as e:
            with self._lock:
                self._last_sync_attempt = attempt_time
                self._consecutive_failures += 1
            log.warning(
                "Revocation sync failed (attempt #%d): %s",
                self._consecutive_failures, e,
            )
            return False

        # Parse the revocation list
        try:
            entries = data.get("entries", {})
            if not isinstance(entries, dict):
                raise ValueError(f"entries is not a dict: {type(entries).__name__}")
            revoked = frozenset(entries.keys())
        except Exception as e:
            with self._lock:
                self._last_sync_attempt = attempt_time
                self._consecutive_failures += 1
            log.warning("Revocation list has malformed structure: %s", e)
            return False

        with self._lock:
            self._last_sync_attempt = attempt_time
            self._last_successful_sync = attempt_time
            self._revoked_dids = revoked
            self._consecutive_failures = 0

        log.info(
            "Revocation sync successful: %d revoked entries", len(revoked),
        )
        return True

    def sync_now(self) -> bool:
        """Trigger an immediate sync (blocks until complete).

        Used by tests and by operators wanting to force a refresh.
        """
        return self._sync_once()

    # # -----------------------------------------------------------------------
    # # State inspection
    # # -----------------------------------------------------------------------

    # def get_state(self) -> SyncState:
    #     """Current ONLINE/GRACE/OFFLINE state based on time since last sync."""
    #     with self._lock:
    #         last = self._last_successful_sync
    #     if last is None:
    #         return SyncState.OFFLINE   # Never synced successfully

    #     elapsed = (self._now_fn() - last).total_seconds()
    #     if elapsed <= self.sync_interval:
    #         return SyncState.ONLINE
    #     if elapsed <= self.sync_interval + self.grace_window:
    #         return SyncState.GRACE
    #     return SyncState.OFFLINE

    # def snapshot(self) -> SyncSnapshot:
    #     """Immutable observation of current state + data.

    #     Useful for logging, monitoring, and test assertions.
    #     """
    #     with self._lock:
    #         return SyncSnapshot(
    #             state=self.get_state(),
    #             last_successful_sync=self._last_successful_sync,
    #             last_sync_attempt=self._last_sync_attempt,
    #             revoked_dids=self._revoked_dids,
    #             consecutive_failures=self._consecutive_failures,
    #         )

    # -----------------------------------------------------------------------
    # State inspection
    # -----------------------------------------------------------------------

    def _compute_state_from(self, last_successful_sync: Optional[datetime]) -> SyncState:
        """Pure function: compute state given a last-sync timestamp.

        Takes the timestamp as an argument (rather than reading self) so
        the caller controls lock ordering. Used by both get_state() (which
        acquires the lock itself) and snapshot() (which already holds it).
        """
        if last_successful_sync is None:
            return SyncState.OFFLINE

        elapsed = (self._now_fn() - last_successful_sync).total_seconds()
        if elapsed <= self.sync_interval:
            return SyncState.ONLINE
        if elapsed <= self.sync_interval + self.grace_window:
            return SyncState.GRACE
        return SyncState.OFFLINE

    def get_state(self) -> SyncState:
        """Current ONLINE/GRACE/OFFLINE state based on time since last sync."""
        with self._lock:
            last = self._last_successful_sync
        # Compute outside the lock — _now_fn() may be slow and doesn't need
        # to hold the lock, and we already have the snapshot data we need.
        return self._compute_state_from(last)

    def snapshot(self) -> SyncSnapshot:
        """Immutable observation of current state + data.

        Useful for logging, monitoring, and test assertions.
        """
        with self._lock:
            last_successful = self._last_successful_sync
            last_attempt = self._last_sync_attempt
            revoked = self._revoked_dids
            failures = self._consecutive_failures

        # Compute state outside the lock, using the snapshot we took.
        # This avoids the deadlock of calling get_state() from inside the lock.
        state = self._compute_state_from(last_successful)

        return SyncSnapshot(
            state=state,
            last_successful_sync=last_successful,
            last_sync_attempt=last_attempt,
            revoked_dids=revoked,
            consecutive_failures=failures,
        )
    # -----------------------------------------------------------------------
    # The operation the verifier calls during auth
    # -----------------------------------------------------------------------

    def check_revocation(self, device_did: str) -> RevocationCheck:
        """Check whether a device is revoked.

        Returns:
            NOT_REVOKED:  gateway has fresh data and device is not in list
            REVOKED:      gateway has data (fresh or stale during grace) and
                          device is in the list
            UNAVAILABLE:  gateway is OFFLINE — fail closed per G5

        Thread-safe; called from the main verifier thread while sync runs
        in the background.
        """
        # Single atomic snapshot of the state we need
        with self._lock:
            last_successful = self._last_successful_sync
            is_revoked = device_did in self._revoked_dids

        state = self._compute_state_from(last_successful)

        if state is SyncState.OFFLINE:
            return RevocationCheck.UNAVAILABLE
        if is_revoked:
            return RevocationCheck.REVOKED
        return RevocationCheck.NOT_REVOKED