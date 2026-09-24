"""Every check in the verifier refuses with its own code and nothing else runs."""

from __future__ import annotations

import dataclasses
import json
from pathlib import Path

import pytest

from symbiote_caller_verifier import codec, verifier
from symbiote_caller_verifier.replay_store import SqliteReplayStore
from symbiote_caller_verifier.verifier import (
    PROBE_TOOL_NAME,
    REJECTION_CODES,
    CallerRejected,
    VerifiedCaller,
    VerifiedCallerRequired,
    VerifierConfig,
    bind_verified_caller,
    require_verified_caller,
    verified_caller,
    verify_call,
)

from .conftest import (
    FAKE_LOGIN_JWT,
    INTEGRATION_ID,
    ISSUER,
    NOW,
    SERVER_ID,
    SUBJECT_ID,
    claims,
    mint,
)

ARGS = {"shot": "sq010_sh020"}


@pytest.fixture
def store(tmp_path: Path) -> SqliteReplayStore:
    return SqliteReplayStore(tmp_path / "replay.sqlite")


def verify(config, store, meta, *, tool_name="archive_shot", arguments=ARGS, now=NOW + 1):
    return verify_call(config, store, meta=meta, tool_name=tool_name, arguments=arguments, now=now)


def test_valid_assertion_yields_immutable_verified_caller(key, config, store):
    assertion = claims(arguments=ARGS)
    caller = verify(config, store, mint(key, assertion))
    assert isinstance(caller, VerifiedCaller)
    assert caller.subject_id == SUBJECT_ID
    assert caller.subject_auth == "jwt"
    assert caller.tool_name == "archive_shot"
    assert caller.jti == assertion.jti
    assert caller.kid == "2026-09"
    assert caller.args_digest == assertion.args.digest
    assert caller.revisions == codec.Revisions(config=3, contract=2, tool=5, publication=1)
    assert caller.call_id == assertion.call.id
    assert (caller.iat, caller.exp) == (NOW, NOW + 60)
    with pytest.raises(dataclasses.FrozenInstanceError):
        caller.subject_id = "other"  # type: ignore[misc]


def refused(config, store, meta, **kw) -> str:
    with pytest.raises(CallerRejected) as error:
        verify(config, store, meta, **kw)
    assert error.value.code in REJECTION_CODES
    envelope = meta.get(codec.META_KEY) if isinstance(meta, dict) else None
    if isinstance(envelope, dict):
        assert envelope["sig"] not in str(error.value)
        assert envelope["claims"]["sub"]["id"] not in str(error.value)
    return error.value.code


def test_absent_is_refused_unless_tool_is_exempt(config, store):
    assert refused(config, store, None) == "absent"
    assert refused(config, store, {}) == "absent"
    exempt = dataclasses.replace(config, exempt_tools=frozenset({"greet"}))
    assert verify(exempt, store, None, tool_name="greet") is None
    assert refused(exempt, store, None, tool_name="archive_shot") == "absent"


def test_foreign_meta_key_refused_even_for_exempt_tool(key, config, store):
    meta = {**mint(key, claims(arguments=ARGS)), "fastmcp": {"version": "2"}}
    assert refused(config, store, meta) == "foreign_meta"
    exempt = dataclasses.replace(config, exempt_tools=frozenset({"greet"}))
    assert refused(exempt, store, {"fastmcp": {"version": "2"}}, tool_name="greet") == (
        "foreign_meta"
    )
    # progressToken is a declared MCP meta field and selects no tool: tolerated, so a
    # bare one is merely `absent`, and one beside a valid assertion still verifies.
    assert refused(config, store, {"progressToken": "p"}) == "absent"
    meta = {**mint(key, claims(arguments=ARGS)), "progressToken": "p"}
    assert verify(config, store, meta).tool_name == "archive_shot"


def test_null_assertion_value_is_shape_never_absent(config, store):
    """`{META_KEY: None}` is a present, malformed assertion. Reading it as
    "no assertion" would let a non-exempt tool run unverified and an exempt
    one run on a client that explicitly sent a broken assertion."""
    assert refused(config, store, {codec.META_KEY: None}) == "shape"
    assert refused(config, store, {codec.META_KEY: None, "progressToken": "p"}) == "shape"
    exempt = dataclasses.replace(config, exempt_tools=frozenset({"greet"}))
    assert refused(exempt, store, {codec.META_KEY: None}, tool_name="greet") == "shape"
    assert refused(exempt, store, {codec.META_KEY: None}, tool_name="archive_shot") == "shape"


@pytest.mark.parametrize("value", [None, "", 0, [], b""], ids=repr)
def test_verify_call_refuses_whatever_classify_meta_returns_that_is_not_a_mapping(
    config, store, monkeypatch, value
):
    """Belt and braces below classify_meta: verify_call never treats a
    non-mapping as "exempt, no assertion" for a tool that is not exempt."""
    monkeypatch.setattr(verifier, "classify_meta", lambda *args, **kwargs: value)
    assert refused(config, store, {}) == "shape"
    exempt = dataclasses.replace(config, exempt_tools=frozenset({"greet"}))
    if value is None:
        assert verify(exempt, store, {}, tool_name="greet") is None
    else:
        assert refused(exempt, store, {}, tool_name="greet") == "shape"


@pytest.mark.parametrize("meta", ["jwt", ["x"], b"x", ("x",), 7], ids=repr)
def test_non_mapping_meta_is_shape(config, store, meta):
    assert refused(config, store, meta) == "shape"
    exempt = dataclasses.replace(config, exempt_tools=frozenset({"greet"}))
    assert refused(exempt, store, meta, tool_name="greet") == "shape"


def test_exempt_tool_with_assertion_is_still_verified(key, config, store):
    exempt = dataclasses.replace(config, exempt_tools=frozenset({"greet"}))
    good = mint(key, claims(tool_name="greet", arguments=ARGS))
    assert verify(exempt, store, good, tool_name="greet").tool_name == "greet"
    # The assertion was consumed even though the tool is exempt.
    assert refused(exempt, store, good, tool_name="greet") == "replayed"
    bad = mint(key, claims(tool_name="greet", arguments={"other": 1}))
    assert refused(exempt, store, bad, tool_name="greet") == "argument_digest"


def test_forged_signature_refused(key, config, store):
    other = codec.SigningKey.generate("2026-09")  # same kid, different key
    assert refused(config, store, mint(other, claims(arguments=ARGS))) == "signature"


def test_unknown_kid_refused(config, store):
    other = codec.SigningKey.generate("2030-01")
    assert refused(config, store, mint(other, claims(arguments=ARGS))) == "signature"


def test_altered_claim_refused_as_signature(key, config, store):
    meta = mint(key, claims(arguments=ARGS))
    meta[codec.META_KEY]["claims"]["sub"]["id"] = "00000000-0000-4000-8000-000000000000"
    assert refused(config, store, meta) == "signature"


def test_login_jwt_in_meta_is_shape(config, store):
    meta = {codec.META_KEY: FAKE_LOGIN_JWT}
    assert refused(config, store, meta) == "shape"


@pytest.mark.parametrize(
    ("field", "value", "code"),
    [
        ("typ", "symbiote-caller-assertion-v2", "shape"),
        ("iss", "https://other.example.test", "audience"),
        ("aud", codec.audience(INTEGRATION_ID, "6d1b0c9a-2e4f-4a6b-8c0d-000000000000"), "audience"),
        ("aud", codec.audience("0f5b2b5e-1c3a-4d2e-9b1f-000000000000", SERVER_ID), "audience"),
    ],
)
def test_wrong_target_refused(key, config, store, field, value, code):
    assertion = dataclasses.replace(claims(arguments=ARGS), **{field: value})
    assert refused(config, store, mint(key, assertion)) == code


def test_freshness_bounds_use_corrected_skew(key, config, store):
    skew = config.max_skew_seconds
    # Expired beyond skew.
    assert refused(config, store, mint(key, claims(arguments=ARGS, now=NOW - 60 - skew - 1))) == (
        "expired"
    )
    # Expired but within skew: still accepted.
    verify(config, store, mint(key, claims(arguments=ARGS, now=NOW - 60 - skew)), now=NOW)
    # Issued in the future beyond skew.
    assert refused(config, store, mint(key, claims(arguments=ARGS, now=NOW + skew + 2))) == (
        "expired"
    )
    # Issued in the future within skew.
    verify(config, store, mint(key, claims(arguments=ARGS, now=NOW + skew)), now=NOW)
    # iat older than skew but exp still ahead must pass.
    verify(config, store, mint(key, claims(arguments=ARGS, now=NOW - 40)), now=NOW)


def test_lifetime_bound_refuses_long_lived_assertions(key, config, store):
    limit = config.max_lifetime_seconds
    assert limit == 300
    # Exactly at the bound: accepted.
    verify(config, store, mint(key, claims(arguments=ARGS, lifetime=limit)))
    # One second over: refused even though `now` sits inside [iat, exp].
    assert refused(config, store, mint(key, claims(arguments=ARGS, lifetime=limit + 1))) == (
        "expired"
    )
    # The motivating case: a 10^9-second assertion presented 5x10^6 s after iat.
    stale = mint(key, claims(arguments=ARGS, now=NOW - 5_000_000, lifetime=10**9))
    assert refused(config, store, stale) == "expired"
    tight = dataclasses.replace(config, max_lifetime_seconds=30)
    verify(tight, store, mint(key, claims(arguments=ARGS, lifetime=30)))
    assert refused(tight, store, mint(key, claims(arguments=ARGS, lifetime=31))) == "expired"


def test_tool_mismatch_and_argument_tampering(key, config, store):
    meta = mint(key, claims(arguments=ARGS))
    assert refused(config, store, meta, tool_name="delete_shot") == "tool_mismatch"
    assert refused(config, store, meta, arguments={"shot": "sq010_sh999"}) == "argument_digest"
    assert refused(config, store, meta, arguments={**ARGS, "force": True}) == "argument_digest"
    assert refused(config, store, meta, arguments={"n": 2**53 + 1}) == "argument_digest"
    # Raw arguments are digested: 1.0 and 1 share a JCS digest by design.
    assertion = claims(arguments={"count": 1})
    assert verify(config, store, mint(key, assertion), arguments={"count": 1.0}) is not None


def test_replay_refused_and_never_consumed_before_earlier_checks(key, config, store):
    assertion = claims(arguments=ARGS)
    meta = mint(key, assertion)
    verify(config, store, meta)
    assert refused(config, store, meta) == "replayed"
    # A refusal before the store never consumes the id.
    fresh = mint(key, claims(arguments=ARGS))
    assert refused(config, store, fresh, tool_name="delete_shot") == "tool_mismatch"
    verify(config, store, fresh)


def test_store_unavailable_refuses(key, config, tmp_path):
    store = SqliteReplayStore(tmp_path / "missing" / "replay.sqlite")
    assert refused(config, store, mint(key, claims(arguments=ARGS))) == "store_unavailable"


def test_contextvar_helpers(key, config, store):
    assert verified_caller() is None
    with pytest.raises(VerifiedCallerRequired):
        require_verified_caller()
    caller = verify(config, store, mint(key, claims(arguments=ARGS)))
    with bind_verified_caller(caller):
        assert require_verified_caller() is caller
        assert verified_caller() is caller
    assert verified_caller() is None


def test_config_from_file_pins_everything_and_refuses_probe_exemption(tmp_path, key):
    entry = key.bundle_entry()
    body = {
        "issuer": ISSUER,
        "integration_id": INTEGRATION_ID,
        "server_id": SERVER_ID,
        "trust_bundle": {"issuer": ISSUER, "keys": [entry]},
        "max_skew_seconds": 3,
        "max_lifetime_seconds": 120,
        "exempt_tools": ["greet"],
    }
    path = tmp_path / "verifier.json"
    path.write_text(json.dumps(body))
    config = VerifierConfig.from_file(path)
    assert config.audience == codec.audience(INTEGRATION_ID, SERVER_ID)
    assert config.max_skew_seconds == 3
    assert config.max_lifetime_seconds == 120
    without_lifetime = {k: v for k, v in body.items() if k != "max_lifetime_seconds"}
    assert VerifierConfig.from_dict(without_lifetime).max_lifetime_seconds == 300
    assert config.exempt_tools == frozenset({"greet"})
    for patch in (
        {"exempt_tools": [PROBE_TOOL_NAME]},
        {"exempt_tools": [["greet"]]},
        {"exempt_tools": [1]},
        {"exempt_tools": "greet"},
        {"max_skew_seconds": -1},
        {"max_skew_seconds": 3600},
        {"max_lifetime_seconds": 0},
        {"max_lifetime_seconds": 3601},
        {"max_lifetime_seconds": "120"},
        {"integration_id": "nope"},
        {"trust_bundle": {"issuer": "https://other", "keys": [entry]}},
        {"issuer": ""},
        {"unexpected": 1},
    ):
        with pytest.raises(ValueError):
            VerifierConfig.from_dict({**body, **patch})
    with pytest.raises(ValueError):
        VerifierConfig.from_file(tmp_path / "absent.json")
    unhashable = tmp_path / "unhashable.json"
    unhashable.write_text(json.dumps({**body, "exempt_tools": [["greet"]]}))
    with pytest.raises(ValueError):
        VerifierConfig.from_file(unhashable)
