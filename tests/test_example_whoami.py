"""The example's opt-in ``whoami`` tool: off by default, verified and policy-checked."""

from __future__ import annotations

import asyncio
import json
import time
from pathlib import Path
from typing import Any

import pytest
from fastmcp import Client

from symbiote_caller_verifier import VerifiedCaller, codec

from .conftest import EMAIL, IDP_ISSUER, IDP_SUBJECT, SUBJECT_ID, mint
from .conftest import claims as make_claims
from .test_example import ARGS, DENIED_SUBJECT, call, load_example, write_files

BYSTANDER = "bob.bystander@studio.example.test"
BYSTANDER_SUBJECT = "b" * 64


def whoami_policy() -> dict[str, Any]:
    return {
        "callers": [
            {
                "email": EMAIL,
                "operations": ["archive_shot", "whoami"],
                "idp": {"iss": IDP_ISSUER, "sub": IDP_SUBJECT},
            },
            {"email": BYSTANDER, "operations": ["archive_shot"]},
        ],
        "subjects": {SUBJECT_ID: ["archive_shot", "whoami"]},
    }


def server(
    tmp_path: Path,
    key: codec.SigningKey,
    *,
    expose_whoami: bool | None,
    seen: list[VerifiedCaller] | None = None,
    **config: Any,
) -> tuple[Any, list[str]]:
    paths = write_files(tmp_path, key, **config)
    paths["policy_path"].write_text(json.dumps(whoami_policy()))
    kwargs: dict[str, Any] = dict(paths)
    if expose_whoami is not None:
        kwargs["expose_whoami"] = expose_whoami
    if seen is not None:
        kwargs["on_policy_check"] = lambda caller, _op: seen.append(caller)
    mcp, archive = load_example().build_server(**kwargs)
    return mcp, archive


def v2_for(
    key: codec.SigningKey,
    arguments: dict[str, Any],
    *,
    tool_name: str,
    sub: str = IDP_SUBJECT,
    email: str | None = EMAIL,
    verified_at: int | None = None,
) -> dict[str, Any]:
    now = int(time.time())
    identity = codec.IdpIdentity(
        iss=IDP_ISSUER, sub=sub, verified_at=now - 3600 if verified_at is None else verified_at
    )
    return mint(
        key,
        make_claims(
            tool_name=tool_name,
            arguments=arguments,
            now=now,
            idp=identity,
            email=email,
            subject_id=DENIED_SUBJECT,
        ),
    )


def tool_names(mcp: Any) -> set[str]:
    async def run() -> set[str]:
        async with Client(mcp) as client:
            return {tool.name for tool in await client.list_tools()}

    return asyncio.run(run())


@pytest.mark.parametrize("expose_whoami", [None, False])
def test_whoami_is_absent_unless_enabled(tmp_path: Path, expose_whoami: bool | None) -> None:
    key = codec.SigningKey.generate("test")
    mcp, _ = server(tmp_path, key, expose_whoami=expose_whoami)

    assert "whoami" not in tool_names(mcp)
    result = call(mcp, "whoami", {}, v2_for(key, {}, tool_name="whoami"))
    assert result.is_error


def test_shipped_example_leaves_whoami_off() -> None:
    example = load_example()
    assert example.whoami_enabled({}) is False
    assert example.whoami_enabled({example.WHOAMI_ENV: "0"}) is False
    assert example.whoami_enabled({example.WHOAMI_ENV: "1"}) is True
    with pytest.raises(ValueError, match=example.WHOAMI_ENV):
        example.whoami_enabled({example.WHOAMI_ENV: "yes"})
    shipped = json.loads((Path(example.__file__).parent / "allowed_callers.json").read_text())
    assert all("whoami" not in entry["operations"] for entry in shipped["callers"])


def test_whoami_returns_exactly_the_verified_identity(tmp_path: Path) -> None:
    key = codec.SigningKey.generate("test")
    mcp, _ = server(tmp_path, key, expose_whoami=True)
    verified_at = int(time.time()) - 120

    assert "whoami" in tool_names(mcp)
    result = call(mcp, "whoami", {}, v2_for(key, {}, tool_name="whoami", verified_at=verified_at))

    assert not result.is_error
    assert result.structured_content == {
        "identity_level": "idp+email",
        "subject_id": DENIED_SUBJECT,
        "idp": {"iss": IDP_ISSUER, "sub": IDP_SUBJECT, "verified_at": verified_at},
        "email": EMAIL,
    }


def test_whoami_at_uuid_level_has_no_idp_or_email(tmp_path: Path) -> None:
    key = codec.SigningKey.generate("test")
    mcp, _ = server(
        tmp_path,
        key,
        expose_whoami=True,
        require_identity=None,
        allowed_idp_issuers=None,
        max_identity_age_seconds=None,
    )
    assertion = make_claims(tool_name="whoami", arguments={}, now=int(time.time()))

    result = call(mcp, "whoami", {}, mint(key, assertion))

    assert result.structured_content == {
        "identity_level": "uuid",
        "subject_id": SUBJECT_ID,
        "idp": None,
        "email": None,
    }


@pytest.mark.parametrize(
    ("assertion", "code"),
    [
        (lambda key: None, "absent"),
        (
            lambda key: v2_for(codec.SigningKey.generate("test"), {}, tool_name="whoami"),
            "signature",
        ),
        (lambda key: v2_for(key, {}, tool_name="whoami", email=None), "identity_insufficient"),
        (lambda key: v2_for(key, {}, tool_name="archive_shot"), "tool_mismatch"),
    ],
)
def test_whoami_is_verified_like_any_other_tool(tmp_path: Path, assertion: Any, code: str) -> None:
    key = codec.SigningKey.generate("test")
    seen: list[VerifiedCaller] = []
    mcp, _ = server(tmp_path, key, expose_whoami=True, seen=seen)

    result = call(mcp, "whoami", {}, assertion(key))

    assert result.structured_content == {codec.META_KEY: {"rejected": code}}
    assert seen == []


def test_whoami_needs_the_policy_to_permit_it(tmp_path: Path) -> None:
    key = codec.SigningKey.generate("test")
    seen: list[VerifiedCaller] = []
    mcp, _ = server(tmp_path, key, expose_whoami=True, seen=seen)

    result = call(
        mcp,
        "whoami",
        {},
        v2_for(key, {}, tool_name="whoami", sub=BYSTANDER_SUBJECT, email=BYSTANDER),
    )

    assert result.is_error
    assert "policy_denied" in "".join(getattr(block, "text", "") for block in result.content)
    assert EMAIL not in json.dumps(result.structured_content)
    assert [caller.email for caller in seen] == [BYSTANDER]


def test_archive_shot_still_carries_no_identity_with_whoami_on(tmp_path: Path) -> None:
    key = codec.SigningKey.generate("test")
    mcp, archive = server(tmp_path, key, expose_whoami=True)
    verified_at = int(time.time()) - 60

    result = call(
        mcp,
        "archive_shot",
        ARGS,
        v2_for(key, ARGS, tool_name="archive_shot", verified_at=verified_at),
    )

    assert result.structured_content == {
        "status": "archived",
        "shot": "sq010_sh020",
        "identity_level": "idp+email",
    }
    text = json.dumps(result.structured_content) + "".join(
        getattr(block, "text", "") for block in result.content
    )
    for value in (IDP_ISSUER, IDP_SUBJECT, EMAIL, DENIED_SUBJECT, str(verified_at)):
        assert value not in text
    assert archive == ["sq010_sh020"]
