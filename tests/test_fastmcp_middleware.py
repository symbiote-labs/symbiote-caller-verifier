"""Refusals happen before tool code runs, on a real in-process FastMCP server."""

from __future__ import annotations

import asyncio
import dataclasses
import json
import logging
import traceback
from pathlib import Path
from typing import Any
from unittest.mock import AsyncMock, MagicMock

import mcp.types as mt
import pytest
from fastmcp import Client, FastMCP

from symbiote_caller_verifier import codec, fastmcp_middleware, verifier
from symbiote_caller_verifier.fastmcp_middleware import (
    CallerVerificationMiddleware,
    register_probe,
)
from symbiote_caller_verifier.replay_store import SqliteReplayStore
from symbiote_caller_verifier.verifier import (
    PROBE_TOOL_NAME,
    VerifiedCaller,
    require_verified_caller,
    verified_caller,
)

from .conftest import FAKE_LOGIN_JWT, IDP_ISSUER, IDP_SUBJECT, NOW, SUBJECT_ID, claims, mint

ARGS = {"shot": "sq010_sh020"}
DENIED_SUBJECT = "11111111-2222-4333-8444-555555555555"
ALLOWED = {SUBJECT_ID: {"archive_shot"}}


@dataclasses.dataclass
class Effects:
    entered: int = 0
    policy_checked: list[str] = dataclasses.field(default_factory=list)
    archived: list[str] = dataclasses.field(default_factory=list)


def build(config, store, *, clock=lambda: NOW + 1) -> tuple[FastMCP, Effects]:
    effects = Effects()
    mcp = FastMCP("studio")
    mcp.add_middleware(CallerVerificationMiddleware(config, store, clock=clock))
    register_probe(mcp)

    @mcp.tool
    def archive_shot(shot: str) -> dict[str, Any]:
        effects.entered += 1
        caller = require_verified_caller()
        effects.policy_checked.append(caller.subject_id)
        if "archive_shot" not in ALLOWED.get(caller.subject_id, set()):
            return {"policy": "denied"}
        effects.archived.append(shot)
        return {"policy": "allowed", "subject": caller.subject_id, "jti": caller.jti}

    @mcp.tool
    def greet(name: str) -> str:
        effects.entered += 1
        assert verified_caller() is None or isinstance(verified_caller(), VerifiedCaller)
        return f"hello {name}"

    return mcp, effects


def call(mcp, name, arguments, meta):
    async def run():
        async with Client(mcp) as client:
            return await client.call_tool(name, arguments, meta=meta, raise_on_error=False)

    return asyncio.run(run())


def rejected(result) -> str:
    assert result.is_error
    assert result.structured_content is not None
    body = result.structured_content[codec.META_KEY]
    assert set(body) == {"rejected"}
    assert [block.text for block in result.content] == ["caller_rejected"]
    return body["rejected"]


@pytest.fixture
def store(tmp_path: Path) -> SqliteReplayStore:
    return SqliteReplayStore(tmp_path / "replay.sqlite")


def test_allowed_caller_runs_with_verified_caller(key, config, store):
    mcp, effects = build(config, store)
    assertion = claims(arguments=ARGS)
    result = call(mcp, "archive_shot", ARGS, mint(key, assertion))
    assert not result.is_error
    assert result.data == {"policy": "allowed", "subject": SUBJECT_ID, "jti": assertion.jti}
    assert effects.archived == ["sq010_sh020"]
    assert effects.policy_checked == [SUBJECT_ID]
    assert verified_caller() is None


def test_denied_caller_reaches_policy_but_never_the_side_effect(key, config, store):
    mcp, effects = build(config, store)
    meta = mint(key, claims(arguments=ARGS, subject_id=DENIED_SUBJECT))
    result = call(mcp, "archive_shot", ARGS, meta)
    assert not result.is_error
    assert result.data == {"policy": "denied"}
    assert effects.policy_checked == [DENIED_SUBJECT]
    assert effects.archived == []


@pytest.mark.parametrize(
    ("label", "make_meta", "tool", "arguments", "code"),
    [
        ("absent", lambda key: None, "archive_shot", ARGS, "absent"),
        ("empty", lambda key: {}, "archive_shot", ARGS, "absent"),
        (
            "foreign",
            lambda key: {**mint(key, claims(arguments=ARGS)), "fastmcp": {"version": "2"}},
            "archive_shot",
            ARGS,
            "foreign_meta",
        ),
        (
            "forged",
            lambda key: mint(codec.SigningKey.generate("2026-09"), claims(arguments=ARGS)),
            "archive_shot",
            ARGS,
            "signature",
        ),
        (
            "altered",
            lambda key: _altered(mint(key, claims(arguments=ARGS))),
            "archive_shot",
            ARGS,
            "signature",
        ),
        (
            "expired",
            lambda key: mint(key, claims(arguments=ARGS, now=NOW - 120)),
            "archive_shot",
            ARGS,
            "expired",
        ),
        (
            "future",
            lambda key: mint(key, claims(arguments=ARGS, now=NOW + 60)),
            "archive_shot",
            ARGS,
            "expired",
        ),
        (
            "wrong-aud",
            lambda key: mint(key, claims(arguments=ARGS, aud="symbiote-mcp:x/y")),
            "archive_shot",
            ARGS,
            "audience",
        ),
        (
            "wrong-tool",
            lambda key: mint(key, claims(arguments=ARGS, tool_name="greet")),
            "archive_shot",
            ARGS,
            "tool_mismatch",
        ),
        (
            "wrong-args",
            lambda key: mint(key, claims(arguments={"shot": "other"})),
            "archive_shot",
            ARGS,
            "argument_digest",
        ),
        (
            "jwt",
            lambda key: {codec.META_KEY: FAKE_LOGIN_JWT},
            "archive_shot",
            ARGS,
            "shape",
        ),
    ],
)
def test_refusal_matrix_has_zero_side_effects(
    key, config, store, label, make_meta, tool, arguments, code
):
    mcp, effects = build(config, store)
    result = call(mcp, tool, arguments, make_meta(key))
    assert rejected(result) == code, label
    assert effects.entered == 0
    assert effects.policy_checked == []
    assert effects.archived == []
    assert "claims" not in json.dumps(result.structured_content)


def _altered(meta):
    meta[codec.META_KEY]["claims"]["sub"]["id"] = DENIED_SUBJECT
    return meta


def test_iat_older_than_skew_but_within_exp_passes(key, config, store):
    mcp, effects = build(config, store)
    result = call(mcp, "archive_shot", ARGS, mint(key, claims(arguments=ARGS, now=NOW - 40)))
    assert not result.is_error
    assert effects.archived == ["sq010_sh020"]


def test_replay_refused_after_first_use(key, config, store):
    mcp, effects = build(config, store)
    meta = mint(key, claims(arguments=ARGS))
    assert not call(mcp, "archive_shot", ARGS, meta).is_error
    assert rejected(call(mcp, "archive_shot", ARGS, meta)) == "replayed"
    assert effects.entered == 1


def test_store_unavailable_refuses(key, config, tmp_path):
    store = SqliteReplayStore(tmp_path / "missing" / "replay.sqlite")
    mcp, effects = build(config, store)
    assert rejected(call(mcp, "archive_shot", ARGS, mint(key, claims(arguments=ARGS)))) == (
        "store_unavailable"
    )
    assert effects.entered == 0


def test_exempt_tool_runs_without_assertion_but_refuses_foreign_meta(key, config, store):
    exempt = dataclasses.replace(config, exempt_tools=frozenset({"greet"}))
    mcp, effects = build(exempt, store)
    result = call(mcp, "greet", {"name": "x"}, None)
    assert not result.is_error and result.data == "hello x"
    assert rejected(call(mcp, "greet", {"name": "x"}, {"fastmcp": {"version": "2"}})) == (
        "foreign_meta"
    )
    assert rejected(call(mcp, "archive_shot", ARGS, None)) == "absent"
    assert effects.entered == 1


def _server_parsed_meta(raw: dict[str, Any]) -> mt.RequestParams.Meta:
    """``_meta`` exactly as the server's request model parses it off the wire.

    The in-process ``Client`` cannot carry these cases: mcp serialises client
    requests with ``exclude_none``, so a null-valued key never leaves the
    client. A raw JSON-RPC client is under no such constraint, and the server
    model keeps the null (asserted here) before the middleware ever sees it.
    """
    params = mt.CallToolRequestParams.model_validate(
        {"name": "archive_shot", "arguments": ARGS, "_meta": raw}
    )
    assert params.meta is not None
    assert params.meta.model_dump() == {"progressToken": None, **raw}
    return params.meta


def _call_direct(middleware, meta, tool_name="archive_shot"):
    """Drive ``on_call_tool`` with a real ``Meta`` and a mocked ``call_next``."""
    context = MagicMock()
    context.fastmcp_context.request_context.meta = meta
    context.message.name = tool_name
    context.message.arguments = ARGS
    call_next = AsyncMock()
    result = asyncio.run(middleware.on_call_tool(context, call_next))
    return result, call_next


@pytest.mark.parametrize(
    ("raw", "code"),
    [
        ({"fastmcp": None}, "foreign_meta"),
        ({"zzz": None}, "foreign_meta"),
        ({"fastmcp": None, "progressToken": "p"}, "foreign_meta"),
        ({codec.META_KEY: None}, "shape"),
        ({codec.META_KEY: None, "progressToken": None}, "shape"),
        ({"progressToken": None}, "absent"),
    ],
)
def test_null_meta_values_off_the_wire_are_refused(config, store, raw, code):
    """A null-valued undeclared key is present and foreign; a null assertion is
    malformed; only a declared field left null reads as absent."""
    middleware = CallerVerificationMiddleware(config, store, clock=lambda: NOW + 1)
    result, call_next = _call_direct(middleware, _server_parsed_meta(raw))
    assert rejected(result) == code
    call_next.assert_not_called()


def test_null_fastmcp_key_beside_valid_assertion_is_foreign_meta(key, config, store):
    middleware = CallerVerificationMiddleware(config, store, clock=lambda: NOW + 1)
    raw = {**mint(key, claims(arguments=ARGS)), "fastmcp": None}
    result, call_next = _call_direct(middleware, _server_parsed_meta(raw))
    assert rejected(result) == "foreign_meta"
    call_next.assert_not_called()


def test_absent_progress_token_is_not_read_as_a_null_key(key, config, store):
    """The declared ``progressToken`` dumps as ``None`` when the client never
    sent it; that must neither refuse the call nor reach ``classify_meta``."""
    middleware = CallerVerificationMiddleware(config, store, clock=lambda: NOW + 1)
    result, call_next = _call_direct(
        middleware, _server_parsed_meta(mint(key, claims(arguments=ARGS)))
    )
    call_next.assert_awaited_once()
    assert result is call_next.return_value


def test_probe_echoes_only_verified_claims(key, config, store):
    mcp, effects = build(config, store)
    assertion = claims(tool_name=PROBE_TOOL_NAME, arguments={})
    result = call(mcp, PROBE_TOOL_NAME, {}, mint(key, assertion))
    assert not result.is_error
    assert result.data == {
        "protocol": "caller/verified.v1",
        "helper_version": "0.2.0",
        "kid": "2026-09",
        "jti": assertion.jti,
        "args_digest": assertion.args.digest,
    }
    assert rejected(call(mcp, PROBE_TOOL_NAME, {}, None)) == "absent"
    forged = mint(codec.SigningKey.generate("2026-09"), claims(tool_name=PROBE_TOOL_NAME))
    assert rejected(call(mcp, PROBE_TOOL_NAME, {}, forged)) == "signature"


def test_missing_request_context_is_refused_before_call_next(config, store):
    middleware = CallerVerificationMiddleware(config, store)
    context = MagicMock()
    context.fastmcp_context.request_context = None
    context.message.name = "archive_shot"
    context.message.arguments = ARGS
    call_next = AsyncMock()
    result = asyncio.run(middleware.on_call_tool(context, call_next))
    assert rejected(result) == "absent"
    call_next.assert_not_called()
    context.fastmcp_context = None
    result = asyncio.run(middleware.on_call_tool(context, call_next))
    assert rejected(result) == "absent"
    call_next.assert_not_called()


def test_unexpected_parse_error_is_a_structured_shape_refusal(config, store, monkeypatch):
    """Any non-CallerRejected failure inside verification keeps the closed-code contract."""

    def explode(*args, **kwargs):
        raise TypeError("unhashable type: 'list'")

    monkeypatch.setattr(fastmcp_middleware, "verify_call", explode)
    mcp, effects = build(config, store)
    result = call(mcp, "archive_shot", ARGS, {codec.META_KEY: {"v": 1}})
    assert rejected(result) == "shape"
    assert effects.entered == 0
    assert "unhashable" not in json.dumps([block.text for block in result.content])


def test_declared_meta_fields_are_exactly_the_ones_this_release_was_reviewed_for():
    """A new declared field on `RequestParams.Meta` must be reviewed: with a
    None default it is dropped when unsent and `foreign_meta` when sent; with
    a non-None default every call becomes `foreign_meta`. Both fail closed."""
    assert fastmcp_middleware.DECLARED_META_FIELDS == frozenset({"progressToken"})


def test_chained_store_exception_never_puts_the_jti_in_the_log(key, config, store, caplog):
    """A studio ReplayStore that wraps its errors with `from` must not leak the
    jti it was handed through the rendered exception chain."""

    class WrappingStore:
        def consume(self, jti: str, *, expires_at: int, now: int) -> None:
            try:
                raise RuntimeError(f"disk I/O jti={jti} expires_at={expires_at}")
            except RuntimeError as exc:
                raise RuntimeError("wrapper") from exc

    mcp, effects = build(config, WrappingStore())
    meta = mint(key, claims(arguments=ARGS))
    with caplog.at_level(logging.ERROR, logger="symbiote_caller_verifier"):
        assert rejected(call(mcp, "archive_shot", ARGS, meta)) == "shape"
    errors = [r for r in caplog.records if r.levelno == logging.ERROR]
    assert len(errors) == 1
    assert "wrapper" in errors[0].getMessage()
    assert meta[codec.META_KEY]["claims"]["jti"] not in caplog.text
    assert "disk I/O" not in caplog.text
    assert effects.entered == 0


def test_progress_token_is_tolerated_but_fastmcp_key_is_not(key, config, store):
    """progressToken is a declared MCP meta field and selects no tool; a `fastmcp`
    key would select another tool version and stays `foreign_meta`."""
    mcp, effects = build(config, store)
    good = {**mint(key, claims(arguments=ARGS)), "progressToken": "p"}
    result = call(mcp, "archive_shot", ARGS, good)
    assert not result.is_error, result.content
    assert effects.archived == ["sq010_sh020"]
    bad = {**mint(key, claims(arguments=ARGS)), "fastmcp": {"version": "2"}}
    assert rejected(call(mcp, "archive_shot", ARGS, bad)) == "foreign_meta"
    assert effects.entered == 1


def test_refusal_is_logged_with_code_and_tool_but_no_claim_material(key, config, store, caplog):
    mcp, _ = build(config, store)
    forged_key = codec.SigningKey.generate("2026-09")
    meta = mint(forged_key, claims(arguments=ARGS, subject_id=DENIED_SUBJECT))
    with caplog.at_level(logging.WARNING, logger="symbiote_caller_verifier"):
        assert rejected(call(mcp, "archive_shot", ARGS, meta)) == "signature"
    warnings = [r for r in caplog.records if r.levelno == logging.WARNING]
    assert len(warnings) == 1
    assert "signature" in warnings[0].getMessage()
    assert "archive_shot" in warnings[0].getMessage()
    assert meta[codec.META_KEY]["sig"] not in caplog.text
    assert DENIED_SUBJECT not in caplog.text
    assert "claims" not in caplog.text
    # An allowed call logs nothing at WARNING.
    caplog.clear()
    with caplog.at_level(logging.WARNING, logger="symbiote_caller_verifier"):
        assert not call(mcp, "archive_shot", ARGS, mint(key, claims(arguments=ARGS))).is_error
    assert [r for r in caplog.records if r.levelno >= logging.WARNING] == []


def test_missing_request_context_refusal_is_logged(config, store, caplog):
    middleware = CallerVerificationMiddleware(config, store)
    context = MagicMock()
    context.fastmcp_context.request_context = None
    context.message.name = "archive_shot"
    context.message.arguments = ARGS
    with caplog.at_level(logging.WARNING, logger="symbiote_caller_verifier"):
        assert rejected(asyncio.run(middleware.on_call_tool(context, AsyncMock()))) == "absent"
    assert any(
        "absent" in r.getMessage() and "archive_shot" in r.getMessage() for r in caplog.records
    )


def test_probe_cannot_be_exempted(config, store):
    with pytest.raises(ValueError):
        CallerVerificationMiddleware(
            dataclasses.replace(config, exempt_tools=frozenset({PROBE_TOOL_NAME})), store
        )


def test_tolerated_meta_set_is_the_single_gate_at_the_middleware(key, config, store, monkeypatch):
    """`progressToken` is a field mcp declares on `RequestParams.Meta`; it must
    still reach `classify_meta`, so emptying the tolerated set refuses it. If
    the middleware dropped declared fields before classifying, a future mcp
    release declaring another Meta field would bypass `foreign_meta` silently."""
    monkeypatch.setattr(verifier, "TOLERATED_META_KEYS", frozenset())
    mcp, effects = build(config, store)
    meta = {**mint(key, claims(arguments=ARGS)), "progressToken": "p"}
    assert rejected(call(mcp, "archive_shot", ARGS, meta)) == "foreign_meta"
    assert effects.entered == 0


class _LocalsCapturingHandler(logging.Handler):
    """What Sentry (``include_local_variables``), ``rich.traceback`` with
    ``show_locals`` and structlog's ``dict_tracebacks`` do with a record that
    carries a live exception: walk its frames and render every local."""

    def __init__(self) -> None:
        super().__init__(level=logging.DEBUG)
        self.rendered: list[str] = []

    def emit(self, record: logging.LogRecord) -> None:
        if record.exc_info is not None and record.exc_info[0] is not None:
            exc_type, exc, tb = record.exc_info
            assert exc_type is not None and exc is not None
            rendered = traceback.TracebackException(exc_type, exc, tb, capture_locals=True).format()
            self.rendered.append("".join(rendered))


def test_unexpected_error_logs_one_error_record_with_traceback_and_no_claims(
    key, config, store, monkeypatch, caplog
):
    """A misconfiguration surfaces once, at ERROR, with the traceback rendered
    into the message text and NO exception object on the record: a handler
    that captures frame locals would otherwise lift `meta`, `extra` and the
    claims out of `on_call_tool`'s frame. The client still gets the structured
    `shape` refusal and no second line."""

    def explode(*args, **kwargs):
        raise TypeError("unhashable type: 'list'")

    monkeypatch.setattr(fastmcp_middleware, "verify_call", explode)
    mcp, effects = build(config, store)
    meta = mint(key, claims(arguments=ARGS, subject_id=DENIED_SUBJECT))
    sig = meta[codec.META_KEY]["sig"]
    capturing = _LocalsCapturingHandler()
    target = logging.getLogger("symbiote_caller_verifier")
    target.addHandler(capturing)
    try:
        with caplog.at_level(logging.DEBUG, logger="symbiote_caller_verifier"):
            assert rejected(call(mcp, "archive_shot", ARGS, meta)) == "shape"
    finally:
        target.removeHandler(capturing)
    records = [r for r in caplog.records if r.name.startswith("symbiote_caller_verifier")]
    assert len(records) == 1
    (record,) = records
    assert record.levelno == logging.ERROR
    assert record.exc_info is None
    message = record.getMessage()
    assert "archive_shot" in message
    assert "Traceback (most recent call last)" in message
    assert "TypeError: unhashable type: 'list'" in message
    assert sig not in message and DENIED_SUBJECT not in message and "claims" not in message
    assert capturing.rendered == []
    assert sig not in caplog.text
    assert DENIED_SUBJECT not in caplog.text
    assert "claims" not in caplog.text
    assert effects.entered == 0


def test_meta_dump_failure_is_a_structured_shape_refusal(config, store, caplog):
    """Reading `_meta` sits inside the same guard as verification: a failure
    there is the structured `shape` refusal, logged once, never a raised
    exception that FastMCP would turn into an unnamed error result."""
    middleware = CallerVerificationMiddleware(config, store)
    meta = MagicMock()
    meta.model_dump.side_effect = RuntimeError("dump exploded")
    with caplog.at_level(logging.DEBUG, logger="symbiote_caller_verifier"):
        result, call_next = _call_direct(middleware, meta)
    assert rejected(result) == "shape"
    call_next.assert_not_called()
    records = [r for r in caplog.records if r.name.startswith("symbiote_caller_verifier")]
    assert [r.levelno for r in records] == [logging.ERROR]
    assert records[0].exc_info is None
    assert "RuntimeError: dump exploded" in records[0].getMessage()


@pytest.mark.parametrize("path", ["refused", "unexpected"])
def test_logged_tool_name_is_bounded_and_escaped(config, store, monkeypatch, caplog, path):
    """The client picks the tool name; a 10,000-char name with a newline must
    not become a 10,000-char log line with the newline intact (log injection)."""
    hostile = "archive_shot\nWARNING forged line " + "x" * 10_000
    if path == "unexpected":

        def explode(*args, **kwargs):
            raise TypeError("boom")

        monkeypatch.setattr(fastmcp_middleware, "verify_call", explode)
    mcp, effects = build(config, store)
    with caplog.at_level(logging.DEBUG, logger="symbiote_caller_verifier"):
        result = call(mcp, hostile, ARGS, None)
    assert rejected(result) == ("absent" if path == "refused" else "shape")
    records = [r for r in caplog.records if r.name.startswith("symbiote_caller_verifier")]
    assert len(records) == 1
    message = records[0].getMessage()
    # The client's name lands only on the header line, repr-escaped and cut;
    # the lines after it (the rendered traceback on the unexpected path) are
    # the server's own source lines and never carry client text.
    header, *rest = message.splitlines()
    assert "archive_shot" in header
    assert "forged line" not in header.replace("\\n", "\n").split("\n", 1)[0]
    assert len(header) <= codec.MAX_TOOL_NAME_LENGTH + 80
    if path == "refused":
        assert rest == []
    else:
        assert rest and rest[0].startswith("Traceback")
    assert all("forged line" not in line and "xxxx" not in line for line in rest)
    assert effects.entered == 0


def test_identity_insufficient_refusal_is_structured_and_runs_nothing(key, config, store):
    strict = dataclasses.replace(config, require_identity="idp")
    mcp, effects = build(strict, store)
    assert rejected(call(mcp, "archive_shot", ARGS, mint(key, claims(arguments=ARGS)))) == (
        "identity_insufficient"
    )
    assert (effects.entered, effects.policy_checked, effects.archived) == (0, [], [])


def test_v2_identity_reaches_tool_code(key, config, store):
    seen: list[VerifiedCaller] = []
    mcp = FastMCP("studio")
    mcp.add_middleware(
        CallerVerificationMiddleware(
            dataclasses.replace(config, require_identity="idp"), store, clock=lambda: NOW + 1
        )
    )

    @mcp.tool
    def archive_shot(shot: str) -> str:
        seen.append(require_verified_caller())
        return shot

    identity = codec.IdpIdentity(iss=IDP_ISSUER, sub=IDP_SUBJECT, verified_at=NOW - 60)
    result = call(mcp, "archive_shot", ARGS, mint(key, claims(arguments=ARGS, idp=identity)))
    assert not result.is_error
    assert [(c.identity_level, c.idp, c.email) for c in seen] == [("idp", identity, None)]


def test_the_probe_is_subject_to_the_identity_age_bound(key, config, store):
    """An administrator whose SSO sign-in is older than the bound cannot re-prove the server."""
    bounded = dataclasses.replace(config, require_identity="idp", max_identity_age_seconds=3600)
    mcp, _ = build(bounded, store)
    stale = codec.IdpIdentity(iss=IDP_ISSUER, sub=IDP_SUBJECT, verified_at=NOW + 1 - 3601)
    result = call(mcp, PROBE_TOOL_NAME, {}, mint(key, claims(tool_name=PROBE_TOOL_NAME, idp=stale)))
    assert rejected(result) == "identity_stale"
    fresh = codec.IdpIdentity(iss=IDP_ISSUER, sub=IDP_SUBJECT, verified_at=NOW - 60)
    assert not call(
        mcp, PROBE_TOOL_NAME, {}, mint(key, claims(tool_name=PROBE_TOOL_NAME, idp=fresh))
    ).is_error
