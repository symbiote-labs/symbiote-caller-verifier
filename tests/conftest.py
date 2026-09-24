"""Minting helpers that stand in for the platform side of the protocol.

Tests mint with a throwaway Ed25519 key so every refusal below is exercised
against a signature that would otherwise verify.
"""

from __future__ import annotations

import base64
import json
import uuid
from typing import Any

import pytest

from symbiote_caller_verifier import codec
from symbiote_caller_verifier.verifier import VerifierConfig

NOW = 1_800_000_000
ISSUER = "https://symbiote.example.test"
INTEGRATION_ID = "0f5b2b5e-1c3a-4d2e-9b1f-6a8c2d4e5f60"
SERVER_ID = "6d1b0c9a-2e4f-4a6b-8c0d-1e2f3a4b5c6d"
SUBJECT_ID = "9b7c8d6e-5f4a-4b3c-8d2e-1f0a9b8c7d6e"
TOOL_ID = "3c2b1a0f-9e8d-4c7b-a6f5-e4d3c2b1a0f9"


def _b64url_json(value: dict[str, str]) -> str:
    return base64.urlsafe_b64encode(json.dumps(value).encode()).rstrip(b"=").decode()


# A login-style JWT with a dummy signature, built here rather than written out
# so no token-shaped literal sits in the tree. It must never verify as an assertion.
FAKE_LOGIN_JWT = ".".join([_b64url_json({"alg": "HS256"}), _b64url_json({"sub": "x"}), "c2ln"])


def claims(
    *,
    tool_name: str = "archive_shot",
    arguments: dict[str, Any] | None = None,
    now: int = NOW,
    lifetime: int = 60,
    aud: str | None = None,
    jti: str | None = None,
    subject_id: str = SUBJECT_ID,
    issuer: str = ISSUER,
    typ: str = codec.ASSERTION_TYP,
) -> codec.Claims:
    return codec.Claims(
        typ=typ,
        iss=issuer,
        jti=jti or str(uuid.uuid4()),
        aud=aud or codec.audience(INTEGRATION_ID, SERVER_ID),
        call=codec.CallRef(id=str(uuid.uuid4()), source="local", generation=str(uuid.uuid4())),
        tool=codec.ToolRef(id=TOOL_ID, name=tool_name),
        rev=codec.Revisions(config=3, contract=2, tool=5, publication=1),
        args=codec.ArgumentDigest(
            alg=codec.ARGS_ALG,
            digest=codec.argument_digest({} if arguments is None else arguments),
        ),
        sub=codec.Subject(id=subject_id, auth="jwt"),
        iat=now,
        exp=now + lifetime,
    )


def mint(key: codec.SigningKey, assertion: codec.Claims) -> dict[str, Any]:
    """Return the request ``_meta`` a platform would send for ``assertion``."""
    return codec.encode_metadata(codec.sign(assertion, key))


@pytest.fixture
def key() -> codec.SigningKey:
    return codec.SigningKey.generate("2026-09")


@pytest.fixture
def bundle(key: codec.SigningKey) -> codec.TrustBundle:
    return codec.TrustBundle.from_dict({"issuer": ISSUER, "keys": [key.bundle_entry()]})


@pytest.fixture
def config(bundle: codec.TrustBundle) -> VerifierConfig:
    return VerifierConfig(
        issuer=ISSUER,
        integration_id=INTEGRATION_ID,
        server_id=SERVER_ID,
        trust_bundle=bundle,
        max_skew_seconds=5,
    )
