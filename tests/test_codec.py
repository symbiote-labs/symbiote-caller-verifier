"""The envelope codec accepts exactly one shape and one signature per claim set."""

from __future__ import annotations

import base64
import copy
import json
import socket
import urllib.request
from pathlib import Path

import pytest

from symbiote_caller_verifier import codec

from .conftest import ISSUER, NOW, claims, mint

FIXTURES = Path(__file__).parent / "fixtures"


def _envelope(meta: dict) -> dict:
    return meta[codec.META_KEY]


def test_round_trip_sign_verify(key, bundle):
    meta = mint(key, claims())
    envelope = codec.parse_envelope(_envelope(meta))
    codec.verify_signature(envelope, bundle)
    assert envelope.kid == "2026-09"
    assert envelope.claims.typ == codec.ASSERTION_TYP
    assert set(meta) == {codec.META_KEY}


def test_signing_input_excludes_sig_and_is_prefixed(key):
    envelope = codec.sign(claims(), key)
    data = codec.signing_input(envelope)
    assert data.startswith(codec.SIGNING_PREFIX)
    canonical = json.loads(data[len(codec.SIGNING_PREFIX) :])
    assert "sig" not in canonical
    assert canonical["claims"]["typ"] == codec.ASSERTION_TYP
    assert b" " not in data[len(codec.SIGNING_PREFIX) :]


@pytest.mark.parametrize(
    "mutate",
    [
        lambda env: env["claims"].__setitem__("exp", env["claims"]["exp"] + 1),
        lambda env: env["claims"]["sub"].__setitem__("id", "00000000-0000-4000-8000-000000000000"),
        lambda env: env["claims"]["args"].__setitem__("digest", "arguments-v1:" + "0" * 64),
        lambda env: env["claims"]["tool"].__setitem__("name", "other"),
    ],
)
def test_altered_claim_fails_signature(key, bundle, mutate):
    raw = _envelope(mint(key, claims()))
    mutate(raw)
    envelope = codec.parse_envelope(raw)
    with pytest.raises(codec.CodecError) as error:
        codec.verify_signature(envelope, bundle)
    assert error.value.code == "signature"


def test_altered_sig_fails_signature(key, bundle):
    raw = _envelope(mint(key, claims()))
    sig = bytearray(base64.urlsafe_b64decode(raw["sig"] + "=="))
    sig[0] ^= 0x01
    raw["sig"] = base64.urlsafe_b64encode(bytes(sig)).rstrip(b"=").decode()
    with pytest.raises(codec.CodecError) as error:
        codec.verify_signature(codec.parse_envelope(raw), bundle)
    assert error.value.code == "signature"


def test_unknown_kid_refused_without_any_fetch(key, bundle, monkeypatch):
    def tripwire(*args, **kwargs):
        raise AssertionError("verifier attempted network access")

    monkeypatch.setattr(socket, "socket", tripwire)
    monkeypatch.setattr(urllib.request, "urlopen", tripwire)
    raw = _envelope(mint(key, claims()))
    raw["kid"] = "2027-01"
    with pytest.raises(codec.CodecError) as error:
        codec.verify_signature(codec.parse_envelope(raw), bundle)
    assert error.value.code == "signature"


@pytest.mark.parametrize(
    "patch",
    [
        {"alg": "HS256"},
        {"alg": "ed25519"},
        {"v": 2},
        {"v": "1"},
        {"kid": ""},
        {"kid": 7},
        {"sig": "not-base64url!"},
        {"sig": "AAAA"},
        {"extra": True},
    ],
)
def test_wrong_envelope_shape(key, patch):
    raw = {**_envelope(mint(key, claims())), **patch}
    with pytest.raises(codec.CodecError) as error:
        codec.parse_envelope(raw)
    assert error.value.code == "shape"


@pytest.mark.parametrize(
    "patch",
    [
        {"typ": "jwt"},
        {"iat": 1.5},
        {"iat": True},
        {"exp": "1800000000"},
        {"rev": {"config": 2**53 + 1, "contract": 1, "tool": 1, "publication": 1}},
        {"rev": {"config": -1, "contract": 1, "tool": 1, "publication": 1}},
        {"rev": {"config": 1, "contract": 1, "tool": 1}},
        {"args": {"alg": "sha256-jcs-v1", "digest": "arguments-v1:short"}},
        {"args": {"alg": "sha1", "digest": "arguments-v1:" + "0" * 64}},
        {"sub": {"id": "not-a-uuid", "auth": "jwt"}},
        {"sub": {"id": "9b7c8d6e-5f4a-4b3c-8d2e-1f0a9b8c7d6e", "auth": "session"}},
        {"sub": {"id": "9b7c8d6e-5f4a-4b3c-8d2e-1f0a9b8c7d6e", "auth": "jwt", "email": "x"}},
        {"call": {"id": "not-a-uuid", "source": "local", "generation": None}},
        {"call": {"id": "3c2b1a0f-9e8d-4c7b-a6f5-e4d3c2b1a0f9", "source": "remote"}},
        # Unhashable values must be a `shape` refusal, never a TypeError escaping the codec.
        {"call": {"id": "3c2b1a0f-9e8d-4c7b-a6f5-e4d3c2b1a0f9", "source": [], "generation": None}},
        {"call": {"id": "3c2b1a0f-9e8d-4c7b-a6f5-e4d3c2b1a0f9", "source": {"local": 1}}},
        {"sub": {"id": "9b7c8d6e-5f4a-4b3c-8d2e-1f0a9b8c7d6e", "auth": []}},
        {"sub": {"id": "9b7c8d6e-5f4a-4b3c-8d2e-1f0a9b8c7d6e", "auth": {"jwt": 1}}},
        {"tool": {"id": "3c2b1a0f-9e8d-4c7b-a6f5-e4d3c2b1a0f9", "name": ""}},
        {"aud": ""},
        {"jti": "1"},
    ],
)
def test_wrong_claim_shape(key, patch):
    raw = _envelope(mint(key, claims()))
    raw["claims"] = {**raw["claims"], **patch}
    with pytest.raises(codec.CodecError) as error:
        codec.parse_envelope(raw)
    assert error.value.code == "shape"


def test_missing_claim_is_shape(key):
    raw = _envelope(mint(key, claims()))
    del raw["claims"]["sub"]
    with pytest.raises(codec.CodecError) as error:
        codec.parse_envelope(raw)
    assert error.value.code == "shape"


def test_oversize_envelope_refused_at_encode_and_parse(key):
    assertion = claims(aud="a" * 5000)
    with pytest.raises(codec.CodecError) as error:
        codec.encode_metadata(codec.sign(assertion, key))
    assert error.value.code == "shape"
    raw = _envelope(mint(key, claims()))
    raw["claims"]["aud"] = "a" * 5000
    with pytest.raises(codec.CodecError) as error:
        codec.parse_envelope(raw)
    assert error.value.code == "shape"


def test_login_jwt_string_is_shape_not_signature():
    jwt = "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiJ4In0.c2ln"
    for value in (jwt, {"token": jwt}, [jwt], None, 1):
        with pytest.raises(codec.CodecError) as error:
            codec.parse_envelope(value)
        assert error.value.code == "shape"


def test_argument_digest_matches_platform_formula():
    arguments = {"shot": "sq010_sh020", "count": 1.0, "nested": {"z": [1, "é"]}}
    digest = codec.argument_digest(arguments)
    assert digest.startswith("arguments-v1:") and len(digest) == len("arguments-v1:") + 64
    # JCS: 1.0 canonicalises to 1, so both spellings share one digest.
    assert digest == codec.argument_digest({**arguments, "count": 1})
    assert digest != codec.argument_digest({**arguments, "count": 2})


def test_argument_digest_refuses_uncanonicalisable_arguments():
    with pytest.raises(codec.CodecError) as error:
        codec.argument_digest({"n": 2**53 + 1})
    assert error.value.code == "argument_digest"


def test_rotation_next_key_signs_and_old_kid_removal_revokes(key):
    next_key = codec.SigningKey.generate("2026-10")
    overlap = codec.TrustBundle.from_dict(
        {"issuer": ISSUER, "keys": [key.bundle_entry(), next_key.bundle_entry()]}
    )
    old_meta = mint(key, claims())
    new_meta = mint(next_key, claims())
    codec.verify_signature(codec.parse_envelope(_envelope(old_meta)), overlap)
    codec.verify_signature(codec.parse_envelope(_envelope(new_meta)), overlap)
    rotated = codec.TrustBundle.from_dict({"issuer": ISSUER, "keys": [next_key.bundle_entry()]})
    codec.verify_signature(codec.parse_envelope(_envelope(new_meta)), rotated)
    with pytest.raises(codec.CodecError) as error:
        codec.verify_signature(codec.parse_envelope(_envelope(old_meta)), rotated)
    assert error.value.code == "signature"


def test_bundle_rejects_duplicate_kid_and_wrong_alg(key):
    with pytest.raises(codec.CodecError):
        codec.TrustBundle.from_dict(
            {"issuer": ISSUER, "keys": [key.bundle_entry(), key.bundle_entry()]}
        )
    with pytest.raises(codec.CodecError):
        codec.TrustBundle.from_dict(
            {"issuer": ISSUER, "keys": [{**key.bundle_entry(), "alg": "RSA"}]}
        )
    with pytest.raises(codec.CodecError):
        codec.TrustBundle.from_dict({"issuer": ISSUER, "keys": []})


def test_seed_round_trip_and_bundle_entry_is_public_only():
    # The key object exposes no seed accessor (a raw private seed must never be
    # reachable from a status or serialisation path); the test owns its seed.
    seed = b"\x07" * 32
    key = codec.SigningKey.from_seed("2026-09", seed)
    assert not hasattr(key, "seed")
    restored = codec.SigningKey.from_seed(key.kid, seed)
    assert restored.bundle_entry() == key.bundle_entry()
    entry = key.bundle_entry()
    assert set(entry) == {"kid", "alg", "public_key"}
    assert len(base64.urlsafe_b64decode(entry["public_key"] + "==")) == 32
    with pytest.raises(codec.CodecError):
        codec.SigningKey.from_seed("k", b"short")


def test_shared_fixture_pins_signing_input_and_signature():
    """The JSON fixture is the cross-package contract with the platform signer."""
    fixture = json.loads((FIXTURES / "assertion_v1.json").read_text())
    key = codec.SigningKey.from_seed(fixture["kid"], bytes.fromhex(fixture["seed_hex"]))
    assertion = codec.claims_from_dict(fixture["claims"])
    envelope = codec.sign(assertion, key)
    assert codec.signing_input(envelope) == base64.b64decode(fixture["signing_input_b64"])
    assert envelope.sig == fixture["sig"]
    assert codec.envelope_to_dict(envelope) == fixture["envelope"]
    bundle = codec.TrustBundle.from_dict(fixture["trust_bundle"])
    codec.verify_signature(codec.parse_envelope(copy.deepcopy(fixture["envelope"])), bundle)
    assert fixture["claims"]["iat"] == NOW


def test_bundle_issuer_is_pinned_not_learned(key, bundle):
    assert bundle.issuer == ISSUER
    assert not hasattr(bundle, "fetch")
    assert not hasattr(bundle, "url")
