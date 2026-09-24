"""Caller assertion envelope: one shape, JCS signing input, Ed25519 signatures.

The platform signs with :func:`sign`; a studio verifier parses with
:func:`parse_envelope` and checks with :func:`verify_signature`. Both sides
compute the signed bytes through :func:`signing_input`, so the JSON fixtures
under ``tests/fixtures`` are the cross-package contract.
"""

from __future__ import annotations

import base64
import binascii
import hashlib
import re
from collections.abc import Mapping
from dataclasses import dataclass
from typing import Any
from uuid import UUID

import rfc8785
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)

META_KEY = "symbiote/caller.v1"
ASSERTION_TYP = "symbiote-caller-assertion"
ALG = "Ed25519"
ARGS_ALG = "sha256-jcs-v1"
ENVELOPE_VERSION = 1
MAX_METADATA_BYTES = 4096
MAX_SAFE_INTEGER = 2**53 - 1
SIGNING_PREFIX = b"symbiote-caller-assertion-v1\0"
ARGUMENTS_PREFIX = b"symbiote-mcp-arguments-v1\0"
ARGUMENT_DIGEST_PREFIX = "arguments-v1:"

_SEED_BYTES = 32
_PUBLIC_KEY_BYTES = 32
_SIGNATURE_BYTES = 64
_MAX_KID_LENGTH = 64
_MAX_ISSUER_LENGTH = 256
_MAX_AUDIENCE_LENGTH = 256
MAX_TOOL_NAME_LENGTH = 128
_CALL_SOURCES = frozenset({"local", "hosted"})
_SUBJECT_AUTHS = frozenset({"jwt", "pat"})
_ENVELOPE_KEYS = frozenset({"v", "alg", "kid", "claims", "sig"})
_CLAIM_KEYS = frozenset(
    {"typ", "iss", "jti", "aud", "call", "tool", "rev", "args", "sub", "iat", "exp"}
)
_REVISION_KEYS = ("config", "contract", "tool", "publication")
_DIGEST_PATTERN = re.compile(r"^arguments-v1:[0-9a-f]{64}$")
_B64URL_PATTERN = re.compile(r"^[A-Za-z0-9_-]+$")


class CodecError(ValueError):
    """A refusal named by ``code``; the message never echoes the input."""

    def __init__(self, code: str) -> None:
        super().__init__(f"Caller assertion refused: {code}")
        self.code = code


@dataclass(frozen=True)
class CallRef:
    id: str
    source: str
    generation: str | None


@dataclass(frozen=True)
class ToolRef:
    id: str
    name: str


@dataclass(frozen=True)
class Revisions:
    config: int
    contract: int
    tool: int
    publication: int


@dataclass(frozen=True)
class ArgumentDigest:
    alg: str
    digest: str


@dataclass(frozen=True)
class Subject:
    id: str
    auth: str


@dataclass(frozen=True)
class Claims:
    typ: str
    iss: str
    jti: str
    aud: str
    call: CallRef
    tool: ToolRef
    rev: Revisions
    args: ArgumentDigest
    sub: Subject
    iat: int
    exp: int


@dataclass(frozen=True)
class Envelope:
    v: int
    alg: str
    kid: str
    claims: Claims
    sig: str


def audience(integration_id: str, server_id: str) -> str:
    return f"symbiote-mcp:{_uuid(integration_id)}/{_uuid(server_id)}"


def canonical_bytes(value: Any, *, code: str = "shape") -> bytes:
    try:
        return rfc8785.dumps(value)
    except (ValueError, TypeError, RecursionError):
        raise CodecError(code) from None


def argument_digest(arguments: Mapping[str, Any]) -> str:
    """``arguments-v1:`` + sha256 over the platform's canonical argument bytes."""
    if not isinstance(arguments, Mapping):
        raise CodecError("argument_digest")
    canonical = canonical_bytes(dict(arguments), code="argument_digest")
    return ARGUMENT_DIGEST_PREFIX + hashlib.sha256(ARGUMENTS_PREFIX + canonical).hexdigest()


def _b64url_encode(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")


def _b64url_decode(value: Any, length: int) -> bytes:
    if not isinstance(value, str) or not _B64URL_PATTERN.match(value):
        raise CodecError("shape")
    try:
        data = base64.urlsafe_b64decode(value + "=" * (-len(value) % 4))
    except (binascii.Error, ValueError):
        raise CodecError("shape") from None
    if len(data) != length or _b64url_encode(data) != value:
        raise CodecError("shape")
    return data


def _uuid(value: Any) -> str:
    if not isinstance(value, str):
        raise CodecError("shape")
    try:
        parsed = UUID(value)
    except ValueError:
        raise CodecError("shape") from None
    if str(parsed) != value:
        raise CodecError("shape")
    return value


def _text(value: Any, max_length: int) -> str:
    if not isinstance(value, str) or not 1 <= len(value) <= max_length:
        raise CodecError("shape")
    return value


def _safe_int(value: Any) -> int:
    if type(value) is not int or not 0 <= value <= MAX_SAFE_INTEGER:
        raise CodecError("shape")
    return value


def _mapping(value: Any, keys: frozenset[str]) -> Mapping[str, Any]:
    if not isinstance(value, Mapping) or set(value) != keys:
        raise CodecError("shape")
    return value


def _parse_call(value: Any) -> CallRef:
    if not isinstance(value, Mapping) or not {"id", "source"} <= set(value):
        raise CodecError("shape")
    source = value["source"]
    if not isinstance(source, str) or source not in _CALL_SOURCES:
        raise CodecError("shape")
    if source == "local":
        call = _mapping(value, frozenset({"id", "source", "generation"}))
        return CallRef(id=_uuid(call["id"]), source="local", generation=_uuid(call["generation"]))
    call = _mapping(value, frozenset({"id", "source"}))
    return CallRef(id=_uuid(call["id"]), source="hosted", generation=None)


def _parse_revisions(value: Any) -> Revisions:
    rev = _mapping(value, frozenset(_REVISION_KEYS))
    return Revisions(**{key: _safe_int(rev[key]) for key in _REVISION_KEYS})


def _parse_args(value: Any) -> ArgumentDigest:
    args = _mapping(value, frozenset({"alg", "digest"}))
    digest = args["digest"]
    if args["alg"] != ARGS_ALG or not isinstance(digest, str) or not _DIGEST_PATTERN.match(digest):
        raise CodecError("shape")
    return ArgumentDigest(alg=ARGS_ALG, digest=digest)


def _parse_subject(value: Any) -> Subject:
    sub = _mapping(value, frozenset({"id", "auth"}))
    auth = sub["auth"]
    if not isinstance(auth, str) or auth not in _SUBJECT_AUTHS:
        raise CodecError("shape")
    return Subject(id=_uuid(sub["id"]), auth=auth)


def claims_from_dict(value: Any) -> Claims:
    raw = _mapping(value, _CLAIM_KEYS)
    if raw["typ"] != ASSERTION_TYP:
        raise CodecError("shape")
    tool = _mapping(raw["tool"], frozenset({"id", "name"}))
    iat, exp = _safe_int(raw["iat"]), _safe_int(raw["exp"])
    if exp <= iat:
        raise CodecError("shape")
    return Claims(
        typ=ASSERTION_TYP,
        iss=_text(raw["iss"], _MAX_ISSUER_LENGTH),
        jti=_uuid(raw["jti"]),
        aud=_text(raw["aud"], _MAX_AUDIENCE_LENGTH),
        call=_parse_call(raw["call"]),
        tool=ToolRef(id=_uuid(tool["id"]), name=_text(tool["name"], MAX_TOOL_NAME_LENGTH)),
        rev=_parse_revisions(raw["rev"]),
        args=_parse_args(raw["args"]),
        sub=_parse_subject(raw["sub"]),
        iat=iat,
        exp=exp,
    )


def claims_to_dict(claims: Claims) -> dict[str, Any]:
    call: dict[str, Any] = {"id": claims.call.id, "source": claims.call.source}
    if claims.call.source == "local":
        call["generation"] = claims.call.generation
    return {
        "typ": claims.typ,
        "iss": claims.iss,
        "jti": claims.jti,
        "aud": claims.aud,
        "call": call,
        "tool": {"id": claims.tool.id, "name": claims.tool.name},
        "rev": {key: getattr(claims.rev, key) for key in _REVISION_KEYS},
        "args": {"alg": claims.args.alg, "digest": claims.args.digest},
        "sub": {"id": claims.sub.id, "auth": claims.sub.auth},
        "iat": claims.iat,
        "exp": claims.exp,
    }


def _unsigned_dict(kid: str, claims: Claims) -> dict[str, Any]:
    return {"v": ENVELOPE_VERSION, "alg": ALG, "kid": kid, "claims": claims_to_dict(claims)}


def envelope_to_dict(envelope: Envelope) -> dict[str, Any]:
    return {**_unsigned_dict(envelope.kid, envelope.claims), "sig": envelope.sig}


def _check_metadata_size(envelope_dict: Mapping[str, Any]) -> None:
    if len(canonical_bytes({META_KEY: dict(envelope_dict)})) > MAX_METADATA_BYTES:
        raise CodecError("shape")


def parse_envelope(value: Any) -> Envelope:
    """Strictly parse an envelope value; any deviation is ``shape``."""
    raw = _mapping(value, _ENVELOPE_KEYS)
    if type(raw["v"]) is not int or raw["v"] != ENVELOPE_VERSION or raw["alg"] != ALG:
        raise CodecError("shape")
    kid = _text(raw["kid"], _MAX_KID_LENGTH)
    sig = raw["sig"]
    _b64url_decode(sig, _SIGNATURE_BYTES)
    claims = claims_from_dict(raw["claims"])
    _check_metadata_size(raw)
    return Envelope(v=ENVELOPE_VERSION, alg=ALG, kid=kid, claims=claims, sig=sig)


def signing_input(envelope: Envelope) -> bytes:
    """Domain-separated JCS bytes of the envelope without ``sig``."""
    return SIGNING_PREFIX + canonical_bytes(_unsigned_dict(envelope.kid, envelope.claims))


class SigningKey:
    """A platform signing key; never exposed to the CLI or studio side."""

    def __init__(self, kid: str, private_key: Ed25519PrivateKey) -> None:
        self.kid = _text(kid, _MAX_KID_LENGTH)
        self._private_key = private_key

    @classmethod
    def generate(cls, kid: str) -> SigningKey:
        return cls(kid, Ed25519PrivateKey.generate())

    @classmethod
    def from_seed(cls, kid: str, seed: bytes) -> SigningKey:
        if not isinstance(seed, bytes | bytearray) or len(seed) != _SEED_BYTES:
            raise CodecError("shape")
        return cls(kid, Ed25519PrivateKey.from_private_bytes(bytes(seed)))

    def public_key_b64(self) -> str:
        return _b64url_encode(self._private_key.public_key().public_bytes_raw())

    def bundle_entry(self) -> dict[str, str]:
        return {"kid": self.kid, "alg": ALG, "public_key": self.public_key_b64()}

    def sign_bytes(self, data: bytes) -> bytes:
        return self._private_key.sign(data)


def sign(claims: Claims, key: SigningKey) -> Envelope:
    unsigned = Envelope(v=ENVELOPE_VERSION, alg=ALG, kid=key.kid, claims=claims, sig="")
    signature = key.sign_bytes(signing_input(unsigned))
    return Envelope(
        v=ENVELOPE_VERSION, alg=ALG, kid=key.kid, claims=claims, sig=_b64url_encode(signature)
    )


def encode_metadata(envelope: Envelope) -> dict[str, Any]:
    """The request ``_meta`` for a signed envelope: exactly one key, bounded."""
    envelope_dict = envelope_to_dict(envelope)
    _check_metadata_size(envelope_dict)
    return {META_KEY: envelope_dict}


class TrustBundle:
    """Pinned issuer and public keys; never fetched, never refreshed."""

    def __init__(self, issuer: str, keys: Mapping[str, Ed25519PublicKey]) -> None:
        if not keys:
            raise CodecError("shape")
        self.issuer = _text(issuer, _MAX_ISSUER_LENGTH)
        self._keys = dict(keys)

    @classmethod
    def from_dict(cls, value: Any) -> TrustBundle:
        raw = _mapping(value, frozenset({"issuer", "keys"}))
        entries = raw["keys"]
        if not isinstance(entries, list):
            raise CodecError("shape")
        keys: dict[str, Ed25519PublicKey] = {}
        for entry in entries:
            item = _mapping(entry, frozenset({"kid", "alg", "public_key"}))
            kid = _text(item["kid"], _MAX_KID_LENGTH)
            if item["alg"] != ALG or kid in keys:
                raise CodecError("shape")
            keys[kid] = Ed25519PublicKey.from_public_bytes(
                _b64url_decode(item["public_key"], _PUBLIC_KEY_BYTES)
            )
        return cls(raw["issuer"], keys)

    def to_dict(self) -> dict[str, Any]:
        return {
            "issuer": self.issuer,
            "keys": [
                {"kid": kid, "alg": ALG, "public_key": _b64url_encode(key.public_bytes_raw())}
                for kid, key in self._keys.items()
            ],
        }

    @property
    def kids(self) -> frozenset[str]:
        return frozenset(self._keys)

    def public_key(self, kid: str) -> Ed25519PublicKey:
        try:
            return self._keys[kid]
        except KeyError:
            raise CodecError("signature") from None


def verify_signature(envelope: Envelope, bundle: TrustBundle) -> None:
    """Raise ``CodecError('signature')`` unless ``bundle`` vouches for ``envelope``."""
    public_key = bundle.public_key(envelope.kid)
    signature = _b64url_decode(envelope.sig, _SIGNATURE_BYTES)
    try:
        public_key.verify(signature, signing_input(envelope))
    except InvalidSignature:
        raise CodecError("signature") from None
