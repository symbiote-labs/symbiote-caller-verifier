"""The shipped example server verifies, applies its policy, and refuses forgeries."""

from __future__ import annotations

import asyncio
import importlib.util
import json
import sys
import time
from pathlib import Path
from types import ModuleType
from typing import Any

import pytest
from fastmcp import Client

from symbiote_caller_verifier import VerifiedCaller, codec

from .conftest import (
    EMAIL,
    IDP_ISSUER,
    IDP_SUBJECT,
    INTEGRATION_ID,
    ISSUER,
    SERVER_ID,
    SUBJECT_ID,
    mint,
)
from .conftest import claims as make_claims

EXAMPLE = Path(__file__).resolve().parents[1] / "examples" / "hello-verified"
DENIED_SUBJECT = "11111111-2222-4333-8444-555555555555"
OTHER_ISSUER = "https://auth.elsewhere.example.test/application/o/symbiote/"
NEW_HIRE = "new.hire@studio.example.test"
NEW_HIRE_SUBJECT = "f" * 64
ARGS = {"shot": "sq010_sh020"}


def load_example() -> ModuleType:
    spec = importlib.util.spec_from_file_location(
        "hello_verified_server", EXAMPLE / "hello_verified_server.py"
    )
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    # Dataclasses resolve their module through sys.modules while the class is built.
    sys.modules[spec.name] = module
    try:
        spec.loader.exec_module(module)
    finally:
        del sys.modules[spec.name]
    return module


def policy_body() -> dict[str, Any]:
    return {
        "callers": [
            {
                "email": EMAIL,
                "operations": ["archive_shot"],
                "idp": {"iss": IDP_ISSUER, "sub": IDP_SUBJECT},
            },
            {"email": NEW_HIRE, "operations": ["archive_shot"]},
            {"email": "bob.bystander@studio.example.test", "operations": []},
        ],
        "subjects": {SUBJECT_ID: ["archive_shot"], DENIED_SUBJECT: []},
    }


def write_files(tmp_path: Path, key: codec.SigningKey, **overrides: Any) -> dict[str, Path]:
    config = json.loads((EXAMPLE / "verifier.example.json").read_text())
    config.update(
        issuer=ISSUER,
        integration_id=INTEGRATION_ID,
        server_id=SERVER_ID,
        trust_bundle={"issuer": ISSUER, "keys": [key.bundle_entry()]},
        allowed_idp_issuers=[IDP_ISSUER],
    )
    config.update(overrides)
    config = {name: value for name, value in config.items() if value is not None}
    paths = {
        "config_path": tmp_path / "verifier.json",
        "policy_path": tmp_path / "allowed_callers.json",
        "replay_path": tmp_path / "replay.sqlite",
    }
    paths["config_path"].write_text(json.dumps(config))
    paths["policy_path"].write_text(json.dumps(policy_body()))
    return paths


def call(mcp: Any, name: str, arguments: dict[str, Any], meta: dict[str, Any] | None) -> Any:
    async def run() -> Any:
        async with Client(mcp) as client:
            return await client.call_tool(name, arguments, meta=meta, raise_on_error=False)

    return asyncio.run(run())


def v2(
    key: codec.SigningKey,
    *,
    iss: str = IDP_ISSUER,
    sub: str = IDP_SUBJECT,
    email: str | None = EMAIL,
    age: int = 3600,
    subject_id: str = DENIED_SUBJECT,
) -> dict[str, Any]:
    """A v2 assertion; the platform UUID defaults to one the UUID policy denies."""
    now = int(time.time())
    identity = codec.IdpIdentity(iss=iss, sub=sub, verified_at=now - age)
    assertion = make_claims(
        arguments=ARGS, now=now, idp=identity, email=email, subject_id=subject_id
    )
    return mint(key, assertion)


def test_example_config_template_matches_the_verifier_schema() -> None:
    body = json.loads((EXAMPLE / "verifier.example.json").read_text())
    assert set(body) <= {
        "issuer",
        "integration_id",
        "server_id",
        "trust_bundle",
        "max_skew_seconds",
        "max_lifetime_seconds",
        "exempt_tools",
        "require_identity",
        "allowed_idp_issuers",
        "max_identity_age_seconds",
    }
    assert body["exempt_tools"] == ["greet"]
    assert body["require_identity"] == "idp+email"
    assert all(issuer.startswith("https://") for issuer in body["allowed_idp_issuers"])
    assert body["max_identity_age_seconds"] == 7 * 86_400


def test_example_policy_file_loads() -> None:
    policy = load_example().load_policy(EXAMPLE / "allowed_callers.json")
    assert policy.by_email and policy.by_idp and policy.by_subject


@pytest.mark.parametrize(
    ("body", "message"),
    [
        ({"callers": [{"email": "a@b.test"}]}, "operations"),
        ({"callers": [{"email": "a@b.test", "operations": ["rm_rf"]}]}, "unknown operation"),
        ({"callers": [{"email": "a@b.test", "operations": [], "idp": {"iss": "x"}}]}, "idp"),
        (
            {
                "callers": [
                    {"email": "a@b.test", "operations": []},
                    {"email": "A@B.test", "operations": []},
                ]
            },
            "email twice",
        ),
        (
            {
                "callers": [
                    {"email": "a@b.test", "operations": [], "idp": {"iss": "i", "sub": "s"}},
                    {"email": "c@b.test", "operations": [], "idp": {"iss": "i", "sub": "s"}},
                ]
            },
            "twice",
        ),
        ({"people": []}, "policy must be"),
    ],
)
def test_example_policy_refuses_malformed_files(
    tmp_path: Path, body: dict[str, Any], message: str
) -> None:
    path = tmp_path / "policy.json"
    path.write_text(json.dumps(body))
    with pytest.raises(ValueError, match=message):
        load_example().load_policy(path)


def test_idp_email_caller_archives_and_the_result_carries_no_identity(tmp_path: Path) -> None:
    key = codec.SigningKey.generate("test")
    seen: list[VerifiedCaller] = []
    mcp, archive = load_example().build_server(
        **write_files(tmp_path, key), on_policy_check=lambda caller, _op: seen.append(caller)
    )

    result = call(mcp, "archive_shot", ARGS, v2(key))

    assert not result.is_error
    assert result.structured_content == {
        "status": "archived",
        "shot": "sq010_sh020",
        "identity_level": "idp+email",
    }
    assert archive == ["sq010_sh020"]
    [caller] = seen
    assert caller.idp is not None
    assert (caller.idp.iss, caller.idp.sub, caller.email) == (IDP_ISSUER, IDP_SUBJECT, EMAIL)
    text = json.dumps(result.structured_content) + "".join(
        getattr(block, "text", "") for block in result.content
    )
    for value in (IDP_ISSUER, IDP_SUBJECT, EMAIL, DENIED_SUBJECT, str(caller.idp.verified_at)):
        assert value not in text


def test_recorded_pair_is_the_stable_key(tmp_path: Path) -> None:
    """The pair keeps its permissions under a new address; the old address under
    another pair (reassigned to someone else) gets nothing."""
    key = codec.SigningKey.generate("test")
    mcp, archive = load_example().build_server(**write_files(tmp_path, key))

    renamed = call(mcp, "archive_shot", ARGS, v2(key, email="ada.renamed@studio.example.test"))
    reassigned = call(mcp, "archive_shot", ARGS, v2(key, sub="someone-else"))

    assert not renamed.is_error
    assert reassigned.is_error
    assert archive == ["sq010_sh020"]


def test_unrecorded_caller_is_matched_by_verified_email(tmp_path: Path) -> None:
    key = codec.SigningKey.generate("test")
    mcp, archive = load_example().build_server(**write_files(tmp_path, key))

    new_hire = call(
        mcp, "archive_shot", ARGS, v2(key, sub=NEW_HIRE_SUBJECT, email=NEW_HIRE.upper())
    )
    stranger = call(mcp, "archive_shot", ARGS, v2(key, sub=NEW_HIRE_SUBJECT, email="who@else.test"))
    bystander = call(
        mcp,
        "archive_shot",
        ARGS,
        v2(key, sub=NEW_HIRE_SUBJECT, email="bob.bystander@studio.example.test"),
    )

    assert not new_hire.is_error
    assert stranger.is_error and bystander.is_error
    assert archive == ["sq010_sh020"]


@pytest.mark.parametrize(
    ("overrides", "assertion", "code"),
    [
        ({}, lambda key: v2(key, email=None), "identity_insufficient"),
        ({}, lambda key: v2(key, iss=OTHER_ISSUER), "identity_issuer"),
        ({"max_identity_age_seconds": 60}, lambda key: v2(key, age=3600), "identity_stale"),
    ],
)
def test_identity_refusals_happen_before_the_policy_runs(
    tmp_path: Path, overrides: dict[str, Any], assertion: Any, code: str
) -> None:
    key = codec.SigningKey.generate("test")
    seen: list[VerifiedCaller] = []
    mcp, archive = load_example().build_server(
        **write_files(tmp_path, key, **overrides),
        on_policy_check=lambda caller, _op: seen.append(caller),
    )

    result = call(mcp, "archive_shot", ARGS, assertion(key))

    assert result.structured_content == {codec.META_KEY: {"rejected": code}}
    assert seen == [] and archive == []


def test_uuid_integration_still_works_without_require_identity(tmp_path: Path) -> None:
    key = codec.SigningKey.generate("test")
    mcp, archive = load_example().build_server(
        **write_files(
            tmp_path,
            key,
            require_identity=None,
            allowed_idp_issuers=None,
            max_identity_age_seconds=None,
        )
    )
    now = int(time.time())

    assert call(mcp, "greet", {"name": "hello"}, None).data == "Hello, hello!"
    allowed = call(mcp, "archive_shot", ARGS, mint(key, make_claims(arguments=ARGS, now=now)))
    assert allowed.structured_content == {
        "status": "archived",
        "shot": "sq010_sh020",
        "identity_level": "uuid",
    }
    denied = call(
        mcp,
        "archive_shot",
        ARGS,
        mint(key, make_claims(arguments=ARGS, now=now, subject_id=DENIED_SUBJECT)),
    )
    assert denied.is_error
    forged = mint(codec.SigningKey.generate("test"), make_claims(arguments=ARGS, now=now))
    refused = call(mcp, "archive_shot", ARGS, forged)
    assert refused.structured_content == {codec.META_KEY: {"rejected": "signature"}}
    assert archive == ["sq010_sh020"]
