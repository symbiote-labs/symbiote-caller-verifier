"""Verified-caller MCP server: identity is proven before the tool runs.

``greet`` is exempt (standard-mode guarantees only). ``archive_shot`` requires
a verified caller and then applies the studio's own policy, mapping the
platform subject id to permitted operations. Run over stdio with
``python hello_verified_server.py``; configure through environment variables
or the files next to this script. Never print to stdout.
"""

from __future__ import annotations

import json
import logging
import os
import sys
from collections.abc import Callable
from pathlib import Path
from typing import Any

from fastmcp import FastMCP
from fastmcp.exceptions import ToolError

from symbiote_caller_verifier import (
    SqliteReplayStore,
    VerifierConfig,
    require_verified_caller,
)
from symbiote_caller_verifier.fastmcp_middleware import (
    CallerVerificationMiddleware,
    register_probe,
)

HERE = Path(__file__).resolve().parent
CONFIG_ENV = "SYMBIOTE_VERIFIER_CONFIG"
REPLAY_ENV = "SYMBIOTE_REPLAY_DB"
POLICY_ENV = "SYMBIOTE_CALLER_POLICY"
OPERATIONS = frozenset({"archive_shot"})
PolicyObserver = Callable[[str, str], None]


def load_policy(path: str | os.PathLike[str]) -> dict[str, frozenset[str]]:
    """``{"subjects": {"<platform user UUID>": ["archive_shot", ...]}}``."""
    with open(path, encoding="utf-8") as handle:
        body = json.load(handle)
    if not isinstance(body, dict) or set(body) != {"subjects"}:
        raise ValueError(f"policy must be an object with a single 'subjects' key: {path}")
    subjects = body["subjects"]
    if not isinstance(subjects, dict):
        raise ValueError(f"policy 'subjects' must be an object: {path}")
    policy: dict[str, frozenset[str]] = {}
    for subject, operations in subjects.items():
        if not isinstance(operations, list) or not set(operations) <= OPERATIONS:
            raise ValueError(f"unknown operation for subject {subject}: {path}")
        policy[subject] = frozenset(operations)
    return policy


def build_server(
    *,
    config_path: str | os.PathLike[str],
    replay_path: str | os.PathLike[str],
    policy_path: str | os.PathLike[str],
    on_policy_check: PolicyObserver | None = None,
) -> tuple[FastMCP, list[str]]:
    """Return the server and the in-memory archive its side effect writes to."""
    config = VerifierConfig.from_file(config_path)
    store = SqliteReplayStore(replay_path)
    policy = load_policy(policy_path)
    archive: list[str] = []

    mcp = FastMCP("hello-verified")
    mcp.add_middleware(CallerVerificationMiddleware(config, store))
    register_probe(mcp)

    @mcp.tool
    def greet(name: str) -> str:
        """Greet someone. Exempt from verification: no identity guarantee."""
        return f"Hello, {name}!"

    @mcp.tool
    def archive_shot(shot: str) -> dict[str, Any]:
        """Archive a shot. Requires a verified caller permitted by policy."""
        caller = require_verified_caller()
        if on_policy_check is not None:
            on_policy_check(caller.subject_id, "archive_shot")
        if "archive_shot" not in policy.get(caller.subject_id, frozenset()):
            raise ToolError("policy_denied: subject is not permitted to archive shots")
        archive.append(shot)
        return {"status": "archived", "shot": shot, "by": caller.subject_id}

    return mcp, archive


def configure_logging() -> None:
    """Send log records (the verifier's refusal lines) to stderr, never stdout.

    stdout carries the MCP protocol on a stdio server; anything else written
    there corrupts the stream. The Symbiote CLI keeps a local server's stderr only
    when started with ``--server-log-dir``.
    """
    logging.basicConfig(
        level=logging.INFO,
        stream=sys.stderr,
        format="%(asctime)s %(levelname)s %(name)s %(message)s",
        force=True,
    )


def main() -> None:
    configure_logging()
    mcp, _ = build_server(
        config_path=os.environ.get(CONFIG_ENV, HERE / "verifier.json"),
        replay_path=os.environ.get(REPLAY_ENV, HERE / "replay.sqlite"),
        policy_path=os.environ.get(POLICY_ENV, HERE / "allowed_callers.json"),
    )
    mcp.run()


if __name__ == "__main__":
    main()
