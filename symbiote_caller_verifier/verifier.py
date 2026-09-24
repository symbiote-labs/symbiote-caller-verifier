"""Framework-agnostic verification of one call's caller assertion.

:func:`verify_call` runs every check in a fixed order and consumes the
assertion id last, so a refusal never burns an id and a consumed id always
belongs to a call that was allowed to proceed. Allowed is not the same as
ran: a request cancelled after the id is consumed (the FastMCP middleware
verifies in a worker thread that cancellation cannot interrupt) leaves the id
burned while the tool never runs. The platform never re-mints, so that call
reports as unknown. This is fail-closed by design: an id, once consumed, is
never made reusable. The result is exposed to tool code through a
request-local context variable.
"""

from __future__ import annotations

import hmac
import json
import os
import time
from collections.abc import Iterator, Mapping
from contextlib import contextmanager
from contextvars import ContextVar
from dataclasses import dataclass
from typing import Any, Protocol
from uuid import UUID

from symbiote_caller_verifier.codec import (
    META_KEY,
    CodecError,
    Revisions,
    TrustBundle,
    argument_digest,
    audience,
    parse_envelope,
    verify_signature,
)
from symbiote_caller_verifier.replay_store import ReplayDetected, ReplayStoreUnavailable

CALLER_PROTOCOL = "caller/verified.v1"
PROBE_TOOL_NAME = "symbiote_caller_probe"
REJECTION_CODES = frozenset(
    {
        "absent",
        "foreign_meta",
        "shape",
        "signature",
        "audience",
        "expired",
        "tool_mismatch",
        "argument_digest",
        "replayed",
        "store_unavailable",
    }
)
DEFAULT_MAX_SKEW_SECONDS = 5
MAX_SKEW_SECONDS = 300
# Longest ``exp - iat`` accepted. The platform mints at most 120 s; the bound
# stops a signed assertion with an absurd lifetime from verifying for years.
DEFAULT_MAX_LIFETIME_SECONDS = 300
MAX_LIFETIME_SECONDS = 3600
# Declared MCP ``_meta`` fields that select no tool and may sit beside the
# assertion. Anything else (``fastmcp`` picks another tool version) is foreign.
TOLERATED_META_KEYS = frozenset({"progressToken"})
_CONFIG_KEYS = frozenset(
    {
        "issuer",
        "integration_id",
        "server_id",
        "trust_bundle",
        "max_skew_seconds",
        "max_lifetime_seconds",
        "exempt_tools",
    }
)
_REQUIRED_CONFIG_KEYS = frozenset({"issuer", "integration_id", "server_id", "trust_bundle"})


class CallerRejected(Exception):
    """The call must not run; ``code`` names the failed check."""

    def __init__(self, code: str) -> None:
        if code not in REJECTION_CODES:
            raise ValueError(f"Unknown rejection code: {code}")
        super().__init__(f"Caller assertion rejected: {code}")
        self.code = code


class VerifiedCallerRequired(RuntimeError):
    """Tool code asked for a verified caller outside a verified call."""


class ReplayStore(Protocol):
    def consume(self, jti: str, *, expires_at: int, now: int | None = None) -> None: ...


@dataclass(frozen=True)
class VerifiedCaller:
    """What the platform attested for this call. Revisions are informational;
    the helper never pins them."""

    subject_id: str
    subject_auth: str
    tool_id: str
    tool_name: str
    revisions: Revisions
    call_id: str
    call_source: str
    generation: str | None
    jti: str
    kid: str
    iat: int
    exp: int
    args_digest: str


def _canonical_uuid(value: Any, field: str) -> str:
    if not isinstance(value, str):
        raise ValueError(f"{field} must be a canonical UUID string")
    try:
        parsed = UUID(value)
    except ValueError:
        raise ValueError(f"{field} must be a canonical UUID string") from None
    if str(parsed) != value:
        raise ValueError(f"{field} must be a canonical UUID string")
    return value


@dataclass(frozen=True)
class VerifierConfig:
    issuer: str
    integration_id: str
    server_id: str
    trust_bundle: TrustBundle
    max_skew_seconds: int = DEFAULT_MAX_SKEW_SECONDS
    max_lifetime_seconds: int = DEFAULT_MAX_LIFETIME_SECONDS
    exempt_tools: frozenset[str] = frozenset()

    def __post_init__(self) -> None:
        if not isinstance(self.issuer, str) or not self.issuer:
            raise ValueError("issuer must be a non-empty string")
        _canonical_uuid(self.integration_id, "integration_id")
        _canonical_uuid(self.server_id, "server_id")
        if not isinstance(self.trust_bundle, TrustBundle):
            raise ValueError("trust_bundle must be a TrustBundle")
        if self.trust_bundle.issuer != self.issuer:
            raise ValueError("trust_bundle issuer must equal the pinned issuer")
        if (
            type(self.max_skew_seconds) is not int
            or not 0 <= self.max_skew_seconds <= MAX_SKEW_SECONDS
        ):
            raise ValueError(f"max_skew_seconds must be an integer in 0..{MAX_SKEW_SECONDS}")
        if (
            type(self.max_lifetime_seconds) is not int
            or not 1 <= self.max_lifetime_seconds <= MAX_LIFETIME_SECONDS
        ):
            raise ValueError(
                f"max_lifetime_seconds must be an integer in 1..{MAX_LIFETIME_SECONDS}"
            )
        if not isinstance(self.exempt_tools, frozenset) or not all(
            isinstance(name, str) and name for name in self.exempt_tools
        ):
            raise ValueError("exempt_tools must be a frozenset of tool names")
        if PROBE_TOOL_NAME in self.exempt_tools:
            raise ValueError(f"{PROBE_TOOL_NAME} cannot be exempt from verification")

    @property
    def audience(self) -> str:
        return audience(self.integration_id, self.server_id)

    @classmethod
    def from_dict(cls, value: Any) -> VerifierConfig:
        if not isinstance(value, Mapping):
            raise ValueError("verifier config must be a JSON object")
        keys = set(value)
        if not _REQUIRED_CONFIG_KEYS <= keys or not keys <= _CONFIG_KEYS:
            raise ValueError(
                "verifier config keys must be issuer, integration_id, server_id, "
                "trust_bundle and optionally max_skew_seconds, max_lifetime_seconds, "
                "exempt_tools"
            )
        exempt = value.get("exempt_tools", [])
        if not isinstance(exempt, list) or not all(isinstance(name, str) for name in exempt):
            raise ValueError("exempt_tools must be a list of tool names")
        return cls(
            issuer=value["issuer"],
            integration_id=value["integration_id"],
            server_id=value["server_id"],
            trust_bundle=TrustBundle.from_dict(value["trust_bundle"]),
            max_skew_seconds=value.get("max_skew_seconds", DEFAULT_MAX_SKEW_SECONDS),
            max_lifetime_seconds=value.get("max_lifetime_seconds", DEFAULT_MAX_LIFETIME_SECONDS),
            exempt_tools=frozenset(exempt),
        )

    @classmethod
    def from_file(cls, path: str | os.PathLike[str]) -> VerifierConfig:
        try:
            with open(path, encoding="utf-8") as handle:
                body = json.load(handle)
        except OSError as exc:
            raise ValueError(f"verifier config unreadable: {os.fspath(path)}") from exc
        except json.JSONDecodeError as exc:
            raise ValueError(f"verifier config is not valid JSON: {os.fspath(path)}") from exc
        return cls.from_dict(body)


_current: ContextVar[VerifiedCaller | None] = ContextVar("symbiote_verified_caller", default=None)


def verified_caller() -> VerifiedCaller | None:
    return _current.get()


def require_verified_caller() -> VerifiedCaller:
    caller = _current.get()
    if caller is None:
        raise VerifiedCallerRequired("This tool requires a verified caller")
    return caller


@contextmanager
def bind_verified_caller(caller: VerifiedCaller | None) -> Iterator[None]:
    token = _current.set(caller)
    try:
        yield
    finally:
        _current.reset(token)


def classify_meta(config: VerifierConfig, meta: Any, tool_name: str) -> Any | None:
    """Return the envelope value, ``None`` for an exempt tool without one, or refuse.

    ``None`` is returned only when the key is absent. A present key whose value
    is null is a malformed assertion (``shape``), never "no assertion": the
    caller of this function treats ``None`` as the exempt sentinel.
    """
    if meta is None:
        extra: Mapping[str, Any] = {}
    elif isinstance(meta, Mapping):
        extra = meta
    else:
        raise CallerRejected("shape")
    if set(extra) - {META_KEY} - TOLERATED_META_KEYS:
        raise CallerRejected("foreign_meta")
    if META_KEY not in extra:
        if tool_name in config.exempt_tools:
            return None
        raise CallerRejected("absent")
    value = extra[META_KEY]
    if value is None:
        raise CallerRejected("shape")
    return value


def verify_assertion(
    config: VerifierConfig,
    value: Any,
    *,
    tool_name: str,
    arguments: Mapping[str, Any],
    now: int,
) -> VerifiedCaller:
    """Every check except replay, in order; raises :class:`CallerRejected`."""
    try:
        envelope = parse_envelope(value)
        verify_signature(envelope, config.trust_bundle)
    except CodecError as exc:
        raise CallerRejected(exc.code) from None
    claims = envelope.claims
    if claims.iss != config.issuer or claims.aud != config.audience:
        raise CallerRejected("audience")
    skew = config.max_skew_seconds
    if claims.exp - claims.iat > config.max_lifetime_seconds:
        raise CallerRejected("expired")
    if claims.iat > now + skew or now > claims.exp + skew:
        raise CallerRejected("expired")
    if claims.tool.name != tool_name:
        raise CallerRejected("tool_mismatch")
    try:
        digest = argument_digest(arguments)
    except CodecError:
        raise CallerRejected("argument_digest") from None
    if not hmac.compare_digest(digest, claims.args.digest):
        raise CallerRejected("argument_digest")
    return VerifiedCaller(
        subject_id=claims.sub.id,
        subject_auth=claims.sub.auth,
        tool_id=claims.tool.id,
        tool_name=claims.tool.name,
        revisions=claims.rev,
        call_id=claims.call.id,
        call_source=claims.call.source,
        generation=claims.call.generation,
        jti=claims.jti,
        kid=envelope.kid,
        iat=claims.iat,
        exp=claims.exp,
        args_digest=claims.args.digest,
    )


def verify_call(
    config: VerifierConfig,
    store: ReplayStore,
    *,
    meta: Any,
    tool_name: str,
    arguments: Mapping[str, Any],
    now: int | None = None,
) -> VerifiedCaller | None:
    """Verify then consume; ``None`` only for an exempt tool with no assertion."""
    current = int(time.time()) if now is None else now
    value = classify_meta(config, meta, tool_name)
    if value is None and tool_name in config.exempt_tools:
        return None
    if not isinstance(value, Mapping):
        # classify_meta refuses these itself; this keeps a null or scalar from
        # ever reading as "exempt, no assertion" should that contract slip.
        raise CallerRejected("shape")
    caller = verify_assertion(config, value, tool_name=tool_name, arguments=arguments, now=current)
    try:
        store.consume(caller.jti, expires_at=caller.exp + config.max_skew_seconds, now=current)
    except ReplayDetected:
        raise CallerRejected("replayed") from None
    except ReplayStoreUnavailable:
        raise CallerRejected("store_unavailable") from None
    return caller
