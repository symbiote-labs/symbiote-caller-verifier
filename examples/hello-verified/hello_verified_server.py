"""Verified-caller MCP server: identity is proven before the tool runs.

``greet`` is exempt (standard-mode guarantees only). ``archive_shot`` requires a
verified caller and then applies the studio's own policy:

- An ``idp+email`` caller is looked up by the email the IdP verified, and the
  IdP ``(issuer, subject)`` pair is the stable key. Once a policy entry records
  that pair, the pair decides: it keeps its permissions if the address changes,
  and a reassigned address arriving under another pair gets nothing.
- A ``uuid`` caller (assertion v1) is looked up by platform user UUID.

Tool results never carry the caller's identity. Run over stdio with
``python hello_verified_server.py``; configure through environment variables or
the files next to this script. Never print to stdout.
"""

from __future__ import annotations

import json
import logging
import os
import sys
from collections.abc import Callable, Mapping
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from fastmcp import FastMCP
from fastmcp.exceptions import ToolError

from symbiote_caller_verifier import (
    SqliteReplayStore,
    VerifiedCaller,
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
NOTHING: frozenset[str] = frozenset()
PolicyObserver = Callable[[VerifiedCaller, str], None]


@dataclass(frozen=True)
class Entry:
    """One studio user: permitted operations, and the IdP pair once known."""

    operations: frozenset[str]
    idp: tuple[str, str] | None = None


@dataclass(frozen=True)
class Policy:
    by_email: Mapping[str, Entry]
    by_idp: Mapping[tuple[str, str], Entry]
    by_subject: Mapping[str, frozenset[str]]

    def permitted(self, caller: VerifiedCaller) -> frozenset[str]:
        if caller.idp is None:
            return self.by_subject.get(caller.subject_id, NOTHING)
        pair = (caller.idp.iss, caller.idp.sub)
        if pair in self.by_idp:
            return self.by_idp[pair].operations
        if caller.email is None:
            return NOTHING
        entry = self.by_email.get(caller.email.casefold())
        if entry is None or entry.idp is not None:
            # Unknown address, or one recorded under another (issuer, subject):
            # an address reassigned to someone else inherits nothing.
            return NOTHING
        return entry.operations


def _operations(value: object, who: str) -> frozenset[str]:
    if not isinstance(value, list) or not set(value) <= OPERATIONS:
        raise ValueError(f"unknown operation for {who}")
    return frozenset(value)


def _entry(raw: object) -> tuple[str, Entry]:
    if not isinstance(raw, dict) or not {"email", "operations"} <= set(raw) <= {
        "email",
        "operations",
        "idp",
    }:
        raise ValueError("each caller needs 'email', 'operations' and optionally 'idp'")
    email = raw["email"]
    if not isinstance(email, str) or "@" not in email:
        raise ValueError("caller 'email' must be an address")
    idp = raw.get("idp")
    pair = None
    if idp is not None:
        if (
            not isinstance(idp, dict)
            or set(idp) != {"iss", "sub"}
            or not all(isinstance(part, str) and part for part in idp.values())
        ):
            raise ValueError(f"caller {email!r}: 'idp' must be {{'iss', 'sub'}} strings")
        pair = (idp["iss"], idp["sub"])
    return email.casefold(), Entry(_operations(raw["operations"], email), pair)


def load_policy(path: str | os.PathLike[str]) -> Policy:
    """``{"callers": [{"email", "operations", "idp"?}], "subjects": {"<UUID>": [...]}}``.

    ``callers`` serves ``idp+email`` integrations and ``subjects`` serves ``uuid``
    ones; either may be empty. In a real server, read both from your directory.
    """
    with open(path, encoding="utf-8") as handle:
        body = json.load(handle)
    if not isinstance(body, dict) or set(body) - {"callers", "subjects"}:
        raise ValueError(f"policy must be an object with 'callers' and 'subjects': {path}")
    callers = body.get("callers", [])
    subjects = body.get("subjects", {})
    if not isinstance(callers, list) or not isinstance(subjects, dict):
        raise ValueError(f"policy 'callers' must be a list and 'subjects' an object: {path}")
    entries = [_entry(raw) for raw in callers]
    by_email = dict(entries)
    if len(by_email) != len(entries):
        raise ValueError(f"policy lists an email twice: {path}")
    by_idp = {entry.idp: entry for _, entry in entries if entry.idp is not None}
    if len(by_idp) != sum(entry.idp is not None for _, entry in entries):
        raise ValueError(f"policy records one (issuer, subject) twice: {path}")
    return Policy(
        by_email=by_email,
        by_idp=by_idp,
        by_subject={subject: _operations(ops, subject) for subject, ops in subjects.items()},
    )


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
            on_policy_check(caller, "archive_shot")
        if "archive_shot" not in policy.permitted(caller):
            raise ToolError("policy_denied: caller is not permitted to archive shots")
        archive.append(shot)
        # The result goes back through the platform to its model provider and
        # retention: report the identity level, never who the caller is.
        return {"status": "archived", "shot": shot, "identity_level": caller.identity_level}

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
