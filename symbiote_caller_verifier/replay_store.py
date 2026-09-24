"""Atomic single-use ledger for assertion ids, backed by one SQLite file.

Supported topology: any number of processes and threads on **one host**
sharing one file on persistent local disk owned by the service user
(stdio or hosted). ``BEGIN IMMEDIATE`` serialises writers across processes,
and the primary key makes the second consumer of an id fail. Replicas on
several hosts need a shared atomic store this module does not supply;
independent files on different hosts do not protect each other, and this
ledger offers no business idempotency for a new assertion id.

Every failure to reach or write the file is :class:`ReplayStoreUnavailable`;
the verifier refuses the call rather than proceeding unprotected.
"""

from __future__ import annotations

import os
import sqlite3
import threading
import time

_MAX_JTI_LENGTH = 128
# First-open setup (WAL switch + schema) is the one step the busy handler does
# not cover; several processes opening a fresh file together can see
# "database is locked" there. Setup is serialised per process and retried a
# bounded number of times; a file that stays locked is still unavailable.
_SETUP_ATTEMPTS = 20
_SETUP_RETRY_SECONDS = 0.05
_SETUP_LOCK = threading.Lock()
_SCHEMA = (
    "CREATE TABLE IF NOT EXISTS consumed_assertions ("
    "jti TEXT PRIMARY KEY, expires_at INTEGER NOT NULL)"
)


class ReplayStoreUnavailable(RuntimeError):
    """The ledger could not be read or written; the call must be refused."""


class ReplayDetected(Exception):
    """The assertion id was already consumed on this store."""


class SqliteReplayStore:
    def __init__(self, path: str | os.PathLike[str], *, busy_timeout_seconds: float = 5.0) -> None:
        if not busy_timeout_seconds > 0:
            raise ValueError("busy_timeout_seconds must be positive")
        self._path = os.fspath(path)
        self._busy_timeout = float(busy_timeout_seconds)
        # sqlite3 connections are bound to the thread that opened them.
        self._local = threading.local()

    @property
    def path(self) -> str:
        return self._path

    def _connection(self) -> sqlite3.Connection:
        connection: sqlite3.Connection | None = getattr(self._local, "connection", None)
        if connection is not None:
            return connection
        with _SETUP_LOCK:
            connection = self._open()
        self._local.connection = connection
        return connection

    def _open(self) -> sqlite3.Connection:
        try:
            connection = sqlite3.connect(
                self._path, timeout=self._busy_timeout, isolation_level=None
            )
        except sqlite3.Error as exc:
            raise ReplayStoreUnavailable(f"Replay store unavailable: {self._path}") from exc
        for attempt in range(1, _SETUP_ATTEMPTS + 1):
            try:
                connection.execute("PRAGMA journal_mode=WAL")
                connection.execute(_SCHEMA)
                return connection
            except sqlite3.OperationalError as exc:
                locked = "database is locked" in str(exc)
                if not locked or attempt == _SETUP_ATTEMPTS:
                    connection.close()
                    raise ReplayStoreUnavailable(f"Replay store unavailable: {self._path}") from exc
                time.sleep(_SETUP_RETRY_SECONDS)
            except sqlite3.Error as exc:
                connection.close()
                raise ReplayStoreUnavailable(f"Replay store unavailable: {self._path}") from exc
        raise AssertionError("unreachable")  # pragma: no cover

    def _discard(self, connection: sqlite3.Connection) -> None:
        self._local.connection = None
        connection.close()

    def _abandon(self, connection: sqlite3.Connection) -> None:
        # A rollback that itself fails leaves the connection unusable; drop it
        # so the next call reopens. The original failure is what propagates.
        try:
            connection.execute("ROLLBACK")
        except sqlite3.Error:
            self._discard(connection)

    def consume(self, jti: str, *, expires_at: int, now: int | None = None) -> None:
        """Record ``jti`` once; raise if it was seen or the store cannot answer.

        Rows whose ``expires_at`` is in the past are pruned first; the caller
        supplies ``exp + skew`` so a replay stays refused for as long as the
        verifier would still accept the assertion.
        """
        if not isinstance(jti, str) or not 1 <= len(jti) <= _MAX_JTI_LENGTH:
            raise ValueError("jti must be a non-empty string of at most 128 characters")
        if type(expires_at) is not int:
            raise ValueError("expires_at must be an integer")
        current = int(time.time()) if now is None else now
        if type(current) is not int:
            raise ValueError("now must be an integer")
        connection = self._connection()
        try:
            connection.execute("BEGIN IMMEDIATE")
        except sqlite3.Error as exc:
            self._discard(connection)
            raise ReplayStoreUnavailable(f"Replay store unavailable: {self._path}") from exc
        try:
            connection.execute("DELETE FROM consumed_assertions WHERE expires_at < ?", (current,))
            connection.execute(
                "INSERT INTO consumed_assertions (jti, expires_at) VALUES (?, ?)",
                (jti, expires_at),
            )
            connection.execute("COMMIT")
        except sqlite3.IntegrityError:
            self._abandon(connection)
            raise ReplayDetected("Caller assertion already consumed") from None
        except sqlite3.Error as exc:
            self._abandon(connection)
            raise ReplayStoreUnavailable(f"Replay store unavailable: {self._path}") from exc

    def close(self) -> None:
        """Close the calling thread's connection, if any."""
        connection: sqlite3.Connection | None = getattr(self._local, "connection", None)
        if connection is not None:
            self._discard(connection)
