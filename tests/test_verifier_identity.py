"""A studio can read the caller's IdP identity and require a minimum identity level."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from symbiote_caller_verifier import codec
from symbiote_caller_verifier.replay_store import SqliteReplayStore
from symbiote_caller_verifier.verifier import (
    IDENTITY_LEVELS,
    REJECTION_CODES,
    CallerRejected,
    VerifierConfig,
    verify_assertion,
    verify_call,
)

from .conftest import (
    EMAIL,
    IDP_ISSUER,
    IDP_SUBJECT,
    IDP_VERIFIED_AT,
    INTEGRATION_ID,
    ISSUER,
    NOW,
    SERVER_ID,
    SUBJECT_ID,
    claims,
    mint,
)

ARGS = {"shot": "sq010_sh020"}
IDP = codec.IdpIdentity(iss=IDP_ISSUER, sub=IDP_SUBJECT, verified_at=IDP_VERIFIED_AT)


@pytest.fixture
def store(tmp_path: Path) -> SqliteReplayStore:
    return SqliteReplayStore(tmp_path / "replay.sqlite")


def configured(bundle, **overrides) -> VerifierConfig:
    return VerifierConfig(
        issuer=ISSUER,
        integration_id=INTEGRATION_ID,
        server_id=SERVER_ID,
        trust_bundle=bundle,
        **overrides,
    )


def assertion_at(level: str):
    if level == "uuid":
        return claims(arguments=ARGS)
    return claims(arguments=ARGS, idp=IDP, email=EMAIL if level == "idp+email" else None)


def test_v2_caller_exposes_idp_and_email(key, bundle, store):
    caller = verify_call(
        configured(bundle),
        store,
        meta=mint(key, assertion_at("idp+email")),
        tool_name="archive_shot",
        arguments=ARGS,
        now=NOW + 1,
    )
    assert caller is not None
    assert caller.identity_level == "idp+email"
    assert caller.idp == IDP and caller.email == EMAIL
    assert caller.subject_id == SUBJECT_ID


def test_v2_caller_without_email_is_idp_level(key, bundle, store):
    caller = verify_call(
        configured(bundle),
        store,
        meta=mint(key, assertion_at("idp")),
        tool_name="archive_shot",
        arguments=ARGS,
        now=NOW + 1,
    )
    assert caller is not None
    assert (caller.identity_level, caller.idp, caller.email) == ("idp", IDP, None)


def test_v1_caller_has_uuid_level_and_no_identity(key, bundle, store):
    caller = verify_call(
        configured(bundle),
        store,
        meta=mint(key, assertion_at("uuid")),
        tool_name="archive_shot",
        arguments=ARGS,
        now=NOW + 1,
    )
    assert caller is not None
    assert (caller.identity_level, caller.idp, caller.email) == ("uuid", None, None)


@pytest.mark.parametrize(
    ("required", "sent", "allowed"),
    [
        (required, sent, IDENTITY_LEVELS.index(sent) >= IDENTITY_LEVELS.index(required))
        for required in ("uuid", "idp", "idp+email")
        for sent in ("uuid", "idp", "idp+email")
    ],
)
def test_require_identity_refuses_lower_levels_without_consuming(
    key, bundle, store, required, sent, allowed
):
    config = configured(bundle, require_identity=required)
    meta = mint(key, assertion_at(sent))
    if allowed:
        assert verify_call(
            config, store, meta=meta, tool_name="archive_shot", arguments=ARGS, now=NOW + 1
        )
        return
    with pytest.raises(CallerRejected) as error:
        verify_call(config, store, meta=meta, tool_name="archive_shot", arguments=ARGS, now=NOW + 1)
    assert error.value.code == "identity_insufficient"
    # The refusal consumed nothing: a relaxed verifier on the same store accepts it once.
    assert verify_call(
        configured(bundle), store, meta=meta, tool_name="archive_shot", arguments=ARGS, now=NOW + 1
    )


def test_identity_level_is_checked_by_verify_assertion_itself(key, bundle):
    with pytest.raises(CallerRejected) as error:
        verify_assertion(
            configured(bundle, require_identity="idp"),
            mint(key, assertion_at("uuid"))[codec.META_KEY],
            tool_name="archive_shot",
            arguments=ARGS,
            now=NOW + 1,
        )
    assert error.value.code == "identity_insufficient"


def test_identity_checks_run_after_the_signature(key, bundle, store):
    """A forged v1 assertion is ``signature``, never a hint about the required level."""
    meta = mint(codec.SigningKey.generate("2026-09"), assertion_at("uuid"))
    with pytest.raises(CallerRejected) as error:
        verify_call(
            configured(bundle, require_identity="idp"),
            store,
            meta=meta,
            tool_name="archive_shot",
            arguments=ARGS,
            now=NOW + 1,
        )
    assert error.value.code == "signature"


def test_allowed_idp_issuers_pins_the_identity_provider(key, bundle, store):
    pinned = configured(bundle, require_identity="idp", allowed_idp_issuers=frozenset({IDP_ISSUER}))
    assert verify_call(
        pinned,
        store,
        meta=mint(key, assertion_at("idp")),
        tool_name="archive_shot",
        arguments=ARGS,
        now=NOW + 1,
    )
    other = codec.IdpIdentity(
        iss="https://other-idp.example.test/", sub=IDP_SUBJECT, verified_at=IDP_VERIFIED_AT
    )
    meta = mint(key, claims(arguments=ARGS, idp=other))
    with pytest.raises(CallerRejected) as error:
        verify_call(pinned, store, meta=meta, tool_name="archive_shot", arguments=ARGS, now=NOW + 1)
    assert error.value.code == "identity_issuer"


def test_an_issuer_pin_without_an_identity_level_is_refused(bundle):
    """A v1 assertion carries no issuer, so a pin at level ``uuid`` would silently be skipped."""
    with pytest.raises(ValueError, match="require_identity"):
        configured(bundle, allowed_idp_issuers=frozenset({IDP_ISSUER}))


def test_new_codes_are_declared():
    assert {"identity_insufficient", "identity_issuer"} <= REJECTION_CODES
    assert IDENTITY_LEVELS == ("uuid", "idp", "idp+email")


def test_config_from_dict_reads_identity_settings(bundle, tmp_path):
    body = {
        "issuer": ISSUER,
        "integration_id": INTEGRATION_ID,
        "server_id": SERVER_ID,
        "trust_bundle": bundle.to_dict(),
        "require_identity": "idp+email",
        "allowed_idp_issuers": [IDP_ISSUER],
    }
    path = tmp_path / "verifier.json"
    path.write_text(json.dumps(body))
    config = VerifierConfig.from_file(path)
    assert config.require_identity == "idp+email"
    assert config.allowed_idp_issuers == frozenset({IDP_ISSUER})
    defaults = VerifierConfig.from_dict(
        {
            k: v
            for k, v in body.items()
            if k in {"issuer", "integration_id", "server_id", "trust_bundle"}
        }
    )
    assert (defaults.require_identity, defaults.allowed_idp_issuers) == ("uuid", frozenset())


@pytest.mark.parametrize(
    "patch",
    [
        {"require_identity": "email"},
        {"require_identity": None},
        {"require_identity": 1},
        {"allowed_idp_issuers": IDP_ISSUER},
        {"allowed_idp_issuers": [""]},
        {"allowed_idp_issuers": ["not-a-url"]},
        {"allowed_idp_issuers": [7]},
    ],
)
def test_config_refuses_invalid_identity_settings(bundle, patch):
    body = {
        "issuer": ISSUER,
        "integration_id": INTEGRATION_ID,
        "server_id": SERVER_ID,
        "trust_bundle": bundle.to_dict(),
        **patch,
    }
    with pytest.raises(ValueError):
        VerifierConfig.from_dict(body)


@pytest.mark.parametrize(
    ("verified_at", "allowed"),
    [
        (NOW + 1 - 86_400, True),  # exactly the maximum age at verification time
        (NOW + 1 - 86_401, False),  # one second older
        (NOW + 1 - 3600, True),
        (NOW + 4, True),  # IdP clock ahead, within the assertion skew: not stale
    ],
    ids=["at-limit", "one-second-over", "fresh", "clock-ahead"],
)
def test_max_identity_age_refuses_an_identity_the_idp_verified_too_long_ago(
    key, bundle, store, verified_at, allowed
):
    config = configured(bundle, require_identity="idp", max_identity_age_seconds=86_400)
    identity = codec.IdpIdentity(iss=IDP_ISSUER, sub=IDP_SUBJECT, verified_at=verified_at)
    meta = mint(key, claims(arguments=ARGS, idp=identity))
    if allowed:
        caller = verify_call(
            config, store, meta=meta, tool_name="archive_shot", arguments=ARGS, now=NOW + 1
        )
        assert caller is not None and caller.idp is not None
        assert caller.idp.verified_at == verified_at
        return
    with pytest.raises(CallerRejected) as error:
        verify_call(config, store, meta=meta, tool_name="archive_shot", arguments=ARGS, now=NOW + 1)
    assert error.value.code == "identity_stale"
    # The refusal consumed nothing: a verifier without the bound accepts it once.
    assert verify_call(
        configured(bundle, require_identity="idp"),
        store,
        meta=meta,
        tool_name="archive_shot",
        arguments=ARGS,
        now=NOW + 1,
    )


def test_without_max_identity_age_any_verified_at_is_accepted(key, bundle, store):
    identity = codec.IdpIdentity(iss=IDP_ISSUER, sub=IDP_SUBJECT, verified_at=0)
    caller = verify_call(
        configured(bundle, require_identity="idp"),
        store,
        meta=mint(key, claims(arguments=ARGS, idp=identity)),
        tool_name="archive_shot",
        arguments=ARGS,
        now=NOW + 1,
    )
    assert caller is not None and caller.idp is not None and caller.idp.verified_at == 0


def test_identity_age_runs_after_the_level_check(key, bundle):
    """A v1 assertion under a bound is ``identity_insufficient``, never mistaken for stale."""
    config = configured(bundle, require_identity="idp", max_identity_age_seconds=60)
    with pytest.raises(CallerRejected) as error:
        verify_assertion(
            config,
            mint(key, claims(arguments=ARGS))[codec.META_KEY],
            tool_name="archive_shot",
            arguments=ARGS,
            now=NOW + 1,
        )
    assert error.value.code == "identity_insufficient"


@pytest.mark.parametrize(
    "overrides",
    [
        {"max_identity_age_seconds": 3600},  # a bound v1 assertions would skip
        {"require_identity": "idp", "max_identity_age_seconds": 0},
        {"require_identity": "idp", "max_identity_age_seconds": -5},
        {"require_identity": "idp", "max_identity_age_seconds": 1.5},
        {"require_identity": "idp", "max_identity_age_seconds": True},
        {"require_identity": "idp", "max_identity_age_seconds": 400 * 86_400},
    ],
    ids=["without-level", "zero", "negative", "float", "bool", "over-a-year"],
)
def test_config_refuses_an_invalid_identity_age(bundle, overrides):
    with pytest.raises(ValueError, match="max_identity_age_seconds"):
        configured(bundle, **overrides)


def test_config_from_dict_reads_max_identity_age(bundle):
    config = VerifierConfig.from_dict(
        {
            "issuer": ISSUER,
            "integration_id": INTEGRATION_ID,
            "server_id": SERVER_ID,
            "trust_bundle": bundle.to_dict(),
            "require_identity": "idp+email",
            "max_identity_age_seconds": 604_800,
        }
    )
    assert config.max_identity_age_seconds == 604_800
    assert "identity_stale" in REJECTION_CODES


def test_an_identity_verified_after_the_assertion_was_minted_is_shape(key, bundle, store):
    """``verified_at`` later than ``iat`` plus skew cannot be real: refuse, never call it fresh."""
    config = configured(bundle, require_identity="idp", max_identity_age_seconds=3600)
    late = codec.IdpIdentity(iss=IDP_ISSUER, sub=IDP_SUBJECT, verified_at=NOW + 5 + 1)
    with pytest.raises(CallerRejected) as error:
        verify_call(
            config,
            store,
            meta=mint(key, claims(arguments=ARGS, idp=late)),
            tool_name="archive_shot",
            arguments=ARGS,
            now=NOW + 1,
        )
    assert error.value.code == "shape"
    at_skew = codec.IdpIdentity(iss=IDP_ISSUER, sub=IDP_SUBJECT, verified_at=NOW + 5)
    assert verify_call(
        config,
        store,
        meta=mint(key, claims(arguments=ARGS, idp=at_skew)),
        tool_name="archive_shot",
        arguments=ARGS,
        now=NOW + 1,
    )
