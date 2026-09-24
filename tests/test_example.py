"""The shipped example server verifies, applies its policy, and refuses forgeries."""

from __future__ import annotations

import asyncio
import importlib.util
import json
import time
from pathlib import Path
from types import ModuleType
from typing import Any

from fastmcp import Client

from symbiote_caller_verifier import codec

from .conftest import INTEGRATION_ID, ISSUER, SERVER_ID, SUBJECT_ID, claims, mint

EXAMPLE = Path(__file__).resolve().parents[1] / "examples" / "hello-verified"
DENIED_SUBJECT = "11111111-2222-4333-8444-555555555555"


def load_example() -> ModuleType:
    spec = importlib.util.spec_from_file_location(
        "hello_verified_server", EXAMPLE / "hello_verified_server.py"
    )
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def write_files(tmp_path: Path, key: codec.SigningKey) -> dict[str, Path]:
    config = json.loads((EXAMPLE / "verifier.example.json").read_text())
    config.update(
        issuer=ISSUER,
        integration_id=INTEGRATION_ID,
        server_id=SERVER_ID,
        trust_bundle={"issuer": ISSUER, "keys": [key.bundle_entry()]},
    )
    paths = {
        "config_path": tmp_path / "verifier.json",
        "policy_path": tmp_path / "allowed_callers.json",
        "replay_path": tmp_path / "replay.sqlite",
    }
    paths["config_path"].write_text(json.dumps(config))
    paths["policy_path"].write_text(
        json.dumps({"subjects": {SUBJECT_ID: ["archive_shot"], DENIED_SUBJECT: []}})
    )
    return paths


def call(mcp: Any, name: str, arguments: dict[str, Any], meta: dict[str, Any] | None) -> Any:
    async def run() -> Any:
        async with Client(mcp) as client:
            return await client.call_tool(name, arguments, meta=meta, raise_on_error=False)

    return asyncio.run(run())


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
    }
    assert body["exempt_tools"] == ["greet"]


def test_example_archives_for_a_permitted_caller_and_refuses_the_rest(tmp_path: Path) -> None:
    key = codec.SigningKey.generate("test")
    mcp, archive = load_example().build_server(**write_files(tmp_path, key))
    args = {"shot": "sq010_sh020"}
    now = int(time.time())

    assert call(mcp, "greet", {"name": "hello"}, None).data == "Hello, hello!"

    allowed = call(mcp, "archive_shot", args, mint(key, claims(arguments=args, now=now)))
    assert not allowed.is_error
    assert archive == ["sq010_sh020"]

    denied = call(
        mcp,
        "archive_shot",
        args,
        mint(key, claims(arguments=args, now=now, subject_id=DENIED_SUBJECT)),
    )
    assert denied.is_error

    forged = mint(codec.SigningKey.generate("test"), claims(arguments=args, now=now))
    refused = call(mcp, "archive_shot", args, forged)
    assert refused.structured_content == {codec.META_KEY: {"rejected": "signature"}}
    assert archive == ["sq010_sh020"]
