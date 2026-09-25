"""Assertion v2: the subject carries the caller's identity-provider identity.

v1 stays byte-identical (``test_codec.py`` pins it); v2 is a separate claim
schema under its own ``typ`` and its own signing domain, so neither version can
be read as the other.
"""

from __future__ import annotations

import base64
import copy
import json
from pathlib import Path

import pytest

from symbiote_caller_verifier import codec

from .conftest import EMAIL, IDP_ISSUER, IDP_SUBJECT, IDP_VERIFIED_AT, NOW, claims, mint

FIXTURES = Path(__file__).parent / "fixtures"
IDP = codec.IdpIdentity(iss=IDP_ISSUER, sub=IDP_SUBJECT, verified_at=IDP_VERIFIED_AT)


def _envelope(meta: dict) -> dict:
    return meta[codec.META_KEY]


def test_v2_round_trip_sign_verify(key, bundle):
    raw = _envelope(mint(key, claims(idp=IDP, email=EMAIL)))
    envelope = codec.parse_envelope(copy.deepcopy(raw))
    codec.verify_signature(envelope, bundle)
    assert envelope.claims.typ == codec.ASSERTION_TYP_V2 == "symbiote-caller-assertion-v2"
    assert envelope.claims.sub.idp == IDP
    assert envelope.claims.sub.email == EMAIL
    assert raw["v"] == 1
    assert raw["claims"]["sub"] == {
        "id": envelope.claims.sub.id,
        "auth": "jwt",
        "idp": {"iss": IDP_ISSUER, "sub": IDP_SUBJECT, "verified_at": IDP_VERIFIED_AT},
        "email": EMAIL,
    }


def test_v2_without_email_omits_the_member(key, bundle):
    raw = _envelope(mint(key, claims(idp=IDP)))
    assert set(raw["claims"]["sub"]) == {"id", "auth", "idp"}
    envelope = codec.parse_envelope(raw)
    codec.verify_signature(envelope, bundle)
    assert envelope.claims.sub.email is None


def test_v2_signing_input_uses_the_v2_domain_prefix(key):
    envelope = codec.sign(claims(idp=IDP), key)
    data = codec.signing_input(envelope)
    assert codec.SIGNING_PREFIX_V2 == b"symbiote-caller-assertion-v2\0"
    assert data.startswith(codec.SIGNING_PREFIX_V2)
    assert not data.startswith(codec.SIGNING_PREFIX)
    assert codec.signing_input(codec.sign(claims(), key)).startswith(codec.SIGNING_PREFIX)


def test_v2_relabelled_as_v1_fails_the_signature(key, bundle):
    """Domain separation: stripping the identity and relabelling cannot reuse the signature."""
    raw = _envelope(mint(key, claims(idp=IDP, email=EMAIL)))
    raw["claims"]["typ"] = codec.ASSERTION_TYP
    raw["claims"]["sub"] = {"id": raw["claims"]["sub"]["id"], "auth": "jwt"}
    envelope = codec.parse_envelope(raw)
    with pytest.raises(codec.CodecError) as error:
        codec.verify_signature(envelope, bundle)
    assert error.value.code == "signature"


def test_v1_relabelled_as_v2_is_shape(key):
    raw = _envelope(mint(key, claims()))
    raw["claims"]["typ"] = codec.ASSERTION_TYP_V2
    with pytest.raises(codec.CodecError) as error:
        codec.parse_envelope(raw)
    assert error.value.code == "shape"


def test_altered_identity_fails_the_signature(key, bundle):
    raw = _envelope(mint(key, claims(idp=IDP, email=EMAIL)))
    raw["claims"]["sub"]["idp"]["sub"] = "someone-else"
    with pytest.raises(codec.CodecError) as error:
        codec.verify_signature(codec.parse_envelope(raw), bundle)
    assert error.value.code == "signature"


_UUID = "9b7c8d6e-5f4a-4b3c-8d2e-1f0a9b8c7d6e"
_IDP = {"iss": IDP_ISSUER, "sub": IDP_SUBJECT, "verified_at": IDP_VERIFIED_AT}


@pytest.mark.parametrize(
    "sub",
    [
        {"id": _UUID, "auth": "jwt"},  # v2 without idp
        {"id": _UUID, "auth": "jwt", "email": EMAIL},  # email without idp
        {"id": _UUID, "auth": "jwt", "idp": _IDP, "extra": 1},
        {"id": _UUID, "auth": "jwt", "idp": {"iss": IDP_ISSUER}},
        {"id": _UUID, "auth": "jwt", "idp": {**_IDP, "email": EMAIL}},
        {"id": _UUID, "auth": "jwt", "idp": [IDP_ISSUER, IDP_SUBJECT]},
        {"id": _UUID, "auth": "jwt", "idp": {**_IDP, "iss": ""}},
        {"id": _UUID, "auth": "jwt", "idp": {**_IDP, "iss": "auth.example.test"}},
        {"id": _UUID, "auth": "jwt", "idp": {**_IDP, "iss": "ftp://auth.example.test/"}},
        {"id": _UUID, "auth": "jwt", "idp": {**_IDP, "iss": "https://" + "a" * 250}},
        {"id": _UUID, "auth": "jwt", "idp": {**_IDP, "iss": 7}},
        {"id": _UUID, "auth": "jwt", "idp": {**_IDP, "iss": "https://auth example.test/"}},
        {"id": _UUID, "auth": "jwt", "idp": {**_IDP, "sub": ""}},
        {"id": _UUID, "auth": "jwt", "idp": {**_IDP, "sub": "a" * 256}},
        {"id": _UUID, "auth": "jwt", "idp": {**_IDP, "sub": "é" * 128}},  # 256 UTF-8 bytes
        {"id": _UUID, "auth": "jwt", "idp": {**_IDP, "sub": "ada\nINFO forged"}},
        {"id": _UUID, "auth": "jwt", "idp": {**_IDP, "sub": "ada‮evil"}},  # bidi override (Cf)
        {"id": _UUID, "auth": "jwt", "idp": {**_IDP, "sub": "ada x"}},  # line separator (Zl)
        {"id": _UUID, "auth": "jwt", "idp": {**_IDP, "sub": None}},
        {
            "id": _UUID,
            "auth": "jwt",
            "idp": {"iss": IDP_ISSUER, "sub": IDP_SUBJECT},
        },  # no verified_at
        {"id": _UUID, "auth": "jwt", "idp": {**_IDP, "verified_at": None}},
        {"id": _UUID, "auth": "jwt", "idp": {**_IDP, "verified_at": "1800000000"}},
        {"id": _UUID, "auth": "jwt", "idp": {**_IDP, "verified_at": 1.5}},
        {"id": _UUID, "auth": "jwt", "idp": {**_IDP, "verified_at": True}},
        {"id": _UUID, "auth": "jwt", "idp": {**_IDP, "verified_at": -1}},
        {"id": _UUID, "auth": "jwt", "idp": {**_IDP, "verified_at": 2**53}},
        {"id": _UUID, "auth": "jwt", "idp": _IDP, "email": ""},
        {"id": _UUID, "auth": "jwt", "idp": _IDP, "email": "no-at-sign"},
        {"id": _UUID, "auth": "jwt", "idp": _IDP, "email": "@studio.test"},
        {"id": _UUID, "auth": "jwt", "idp": _IDP, "email": "ada@"},
        {"id": _UUID, "auth": "jwt", "idp": _IDP, "email": "a@b@c"},
        {"id": _UUID, "auth": "jwt", "idp": _IDP, "email": "ada lovelace@studio.test"},
        {"id": _UUID, "auth": "jwt", "idp": _IDP, "email": "a" * 250 + "@x.io"},
        {"id": _UUID, "auth": "jwt", "idp": _IDP, "email": None},
        {"id": "not-a-uuid", "auth": "jwt", "idp": _IDP},
        {"id": _UUID, "auth": "session", "idp": _IDP},
    ],
)
def test_v2_subject_shape_is_strict(key, sub):
    raw = _envelope(mint(key, claims(idp=IDP)))
    raw["claims"]["sub"] = sub
    with pytest.raises(codec.CodecError) as error:
        codec.parse_envelope(raw)
    assert error.value.code == "shape"


def test_v1_typ_with_an_identity_is_shape(key):
    raw = _envelope(mint(key, claims()))
    raw["claims"]["sub"] = {**raw["claims"]["sub"], "idp": dict(_IDP)}
    with pytest.raises(codec.CodecError) as error:
        codec.parse_envelope(raw)
    assert error.value.code == "shape"


@pytest.mark.parametrize(
    "assertion",
    [
        claims(typ=codec.ASSERTION_TYP, idp=IDP),
        claims(typ=codec.ASSERTION_TYP_V2),
        claims(email=EMAIL),
    ],
    ids=["v1-with-idp", "v2-without-idp", "email-without-idp"],
)
def test_sign_refuses_mixed_version_claims(key, assertion):
    with pytest.raises(codec.CodecError) as error:
        codec.sign(assertion, key)
    assert error.value.code == "shape"


def test_http_issuer_is_accepted_for_dev_identity_providers(key, bundle):
    dev = codec.IdpIdentity(
        iss="http://authentik-server:9000/application/o/symbiote/",
        sub="7",
        verified_at=IDP_VERIFIED_AT,
    )
    codec.verify_signature(codec.parse_envelope(_envelope(mint(key, claims(idp=dev)))), bundle)


def test_validators_are_the_parsers_rules():
    assert codec.validate_idp_issuer(IDP_ISSUER) == IDP_ISSUER
    assert codec.validate_idp_subject(IDP_SUBJECT) == IDP_SUBJECT
    assert codec.validate_email(EMAIL) == EMAIL
    for check, bad in (
        (codec.validate_idp_issuer, "not a url"),
        (codec.validate_idp_subject, "x\ty"),
        (codec.validate_email, "nobody"),
    ):
        with pytest.raises(codec.CodecError) as error:
            check(bad)
        assert error.value.code == "shape"


def test_maximal_v2_envelope_with_four_byte_characters_fits_the_metadata_bound(key, bundle):
    """Every identity member at its byte bound, in 4-byte characters, still encodes."""
    widest = "\U0001f3ac"  # 4 UTF-8 bytes
    identity = codec.IdpIdentity(
        iss="https://" + widest * 62, sub=widest * 63, verified_at=IDP_VERIFIED_AT
    )
    email = widest * 30 + "@" + widest * 30 + ".io"
    assert len(identity.iss.encode()) <= 256 and len(identity.sub.encode()) <= 255
    assert len(email.encode()) <= 254
    assertion = claims(idp=identity, email=email, tool_name=widest * 32)
    meta = codec.encode_metadata(codec.sign(assertion, key))
    assert len(codec.canonical_bytes(meta)) <= codec.MAX_METADATA_BYTES
    codec.verify_signature(codec.parse_envelope(_envelope(meta)), bundle)


def test_shared_v2_fixture_pins_signing_input_and_signature():
    """The v2 JSON fixture is the cross-package contract with the platform signer."""
    fixture = json.loads((FIXTURES / "assertion_v2.json").read_text())
    key = codec.SigningKey.from_seed(fixture["kid"], bytes.fromhex(fixture["seed_hex"]))
    assertion = codec.claims_from_dict(fixture["claims"])
    envelope = codec.sign(assertion, key)
    signing_input = codec.signing_input(envelope)
    assert signing_input == base64.b64decode(fixture["signing_input_b64"])
    assert signing_input == codec.SIGNING_PREFIX_V2 + fixture["signing_input_text"].encode()
    assert envelope.sig == fixture["sig"]
    assert codec.envelope_to_dict(envelope) == fixture["envelope"]
    bundle = codec.TrustBundle.from_dict(fixture["trust_bundle"])
    codec.verify_signature(codec.parse_envelope(copy.deepcopy(fixture["envelope"])), bundle)
    assert fixture["claims"]["iat"] == NOW
    assert fixture["claims"]["sub"]["idp"] == {
        "iss": IDP_ISSUER,
        "sub": IDP_SUBJECT,
        "verified_at": IDP_VERIFIED_AT,
    }


def test_altered_verified_at_fails_the_signature(key, bundle):
    """A relay cannot freshen a stale identity: verified_at is signed."""
    raw = _envelope(mint(key, claims(idp=IDP)))
    raw["claims"]["sub"]["idp"]["verified_at"] = NOW
    with pytest.raises(codec.CodecError) as error:
        codec.verify_signature(codec.parse_envelope(raw), bundle)
    assert error.value.code == "signature"
