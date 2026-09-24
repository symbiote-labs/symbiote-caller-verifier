"""One assertion id is consumed exactly once per store file, or the call is refused."""

from __future__ import annotations

import sqlite3
import subprocess
import sys
import threading
import time
from pathlib import Path

import pytest

from symbiote_caller_verifier.replay_store import (
    ReplayDetected,
    ReplayStoreUnavailable,
    SqliteReplayStore,
)

NOW = 1_800_000_000


def test_consume_once_then_replay(tmp_path: Path):
    store = SqliteReplayStore(tmp_path / "replay.sqlite")
    store.consume("jti-1", expires_at=NOW + 65, now=NOW)
    with pytest.raises(ReplayDetected):
        store.consume("jti-1", expires_at=NOW + 65, now=NOW + 1)
    store.consume("jti-2", expires_at=NOW + 65, now=NOW)


def test_restart_keeps_consumed_id_refused_until_retention_ends(tmp_path: Path):
    path = tmp_path / "replay.sqlite"
    SqliteReplayStore(path).consume("jti-1", expires_at=NOW + 65, now=NOW)
    restarted = SqliteReplayStore(path)
    with pytest.raises(ReplayDetected):
        restarted.consume("jti-1", expires_at=NOW + 65, now=NOW + 65)
    # Past exp + skew the verifier refuses the assertion as expired anyway;
    # the row is pruned so the file does not grow without bound.
    restarted.consume("jti-1", expires_at=NOW + 200, now=NOW + 66)
    with sqlite3.connect(path) as conn:
        assert conn.execute("select count(*) from consumed_assertions").fetchone()[0] == 1


def test_missing_directory_is_unavailable_not_created(tmp_path: Path):
    store = SqliteReplayStore(tmp_path / "missing" / "replay.sqlite")
    with pytest.raises(ReplayStoreUnavailable):
        store.consume("jti-1", expires_at=NOW + 65, now=NOW)
    assert not (tmp_path / "missing").exists()


def test_corrupt_file_is_unavailable(tmp_path: Path):
    path = tmp_path / "replay.sqlite"
    path.write_bytes(b"this is not a sqlite database, it is 64 bytes of junk......")
    with pytest.raises(ReplayStoreUnavailable):
        SqliteReplayStore(path).consume("jti-1", expires_at=NOW + 65, now=NOW)


def test_path_that_is_a_directory_is_unavailable(tmp_path: Path):
    with pytest.raises(ReplayStoreUnavailable):
        SqliteReplayStore(tmp_path).consume("jti-1", expires_at=NOW + 65, now=NOW)


def test_locked_past_busy_timeout_is_unavailable(tmp_path: Path):
    path = tmp_path / "replay.sqlite"
    store = SqliteReplayStore(path, busy_timeout_seconds=0.2)
    store.consume("seed", expires_at=NOW + 65, now=NOW)
    holder = sqlite3.connect(path, isolation_level=None)
    holder.execute("BEGIN IMMEDIATE")
    try:
        started = time.monotonic()
        with pytest.raises(ReplayStoreUnavailable):
            store.consume("jti-1", expires_at=NOW + 65, now=NOW)
        assert time.monotonic() - started < 5
    finally:
        holder.execute("ROLLBACK")
        holder.close()
    # The store recovers once the lock clears and the id was never recorded.
    store.consume("jti-1", expires_at=NOW + 65, now=NOW)


@pytest.mark.parametrize("jti", ["", "x" * 129, 7, None])
def test_invalid_jti_is_refused_before_touching_the_store(tmp_path: Path, jti):
    store = SqliteReplayStore(tmp_path / "missing" / "replay.sqlite")
    with pytest.raises(ValueError):
        store.consume(jti, expires_at=NOW + 65, now=NOW)  # type: ignore[arg-type]


def test_connections_are_thread_local(tmp_path: Path):
    store = SqliteReplayStore(tmp_path / "replay.sqlite")
    seen: dict[str, int] = {}
    errors: list[BaseException] = []

    def worker(name: str) -> None:
        try:
            store.consume(name, expires_at=NOW + 65, now=NOW)
            seen[name] = id(store._connection())
        except BaseException as exc:  # pragma: no cover - surfaced below
            errors.append(exc)

    threads = [threading.Thread(target=worker, args=(f"jti-{i}",)) for i in range(4)]
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join()
    assert not errors
    assert len(seen) == 4
    assert len(set(seen.values())) == 4
    with pytest.raises(ReplayDetected):
        store.consume("jti-0", expires_at=NOW + 65, now=NOW)


RACER = """
import sys, time
from symbiote_caller_verifier.replay_store import ReplayDetected, SqliteReplayStore
path, start = sys.argv[1], float(sys.argv[2])
store = SqliteReplayStore(path)
while time.time() < start:
    time.sleep(0.001)
try:
    store.consume("shared-jti", expires_at=1800000065, now=1800000000)
    print("consumed")
except ReplayDetected:
    print("replayed")
"""


def test_two_processes_sharing_one_file_consume_one_jti_exactly_once(tmp_path: Path):
    path = tmp_path / "replay.sqlite"
    SqliteReplayStore(path).consume("warm", expires_at=NOW + 65, now=NOW)
    start = time.time() + 1.0
    procs = [
        subprocess.Popen(
            [sys.executable, "-c", RACER, str(path), str(start)],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
        )
        for _ in range(2)
    ]
    outputs = [proc.communicate(timeout=30) for proc in procs]
    assert all(proc.returncode == 0 for proc in procs), outputs
    results = sorted(out.strip() for out, _ in outputs)
    assert results == ["consumed", "replayed"]
