"""FastMCP middleware that refuses unverified calls before the tool runs.

Requires the ``[fastmcp]`` extra. The client's ``_meta`` is read from the
low-level request context (``request_context.meta``), never from
``context.message.meta``, which FastMCP rebuilds and which never carries it.
Every undeclared key the client sent, null-valued or not, and every declared
``RequestParams.Meta`` field with a non-null value, is handed to
:func:`~symbiote_caller_verifier.verifier.classify_meta`, so the tolerated set
in ``verifier`` is the single gate on foreign keys. A declared field that is
``None`` (unsent, or sent as null) is dropped before classification; for the
one declared field, ``progressToken``, both read as "no token".
"""

from __future__ import annotations

import asyncio
import logging
import time
import traceback
from collections.abc import Callable
from typing import Any

try:
    import mcp.types as mt
    from fastmcp import FastMCP
    from fastmcp.server.middleware import CallNext, Middleware, MiddlewareContext
    from fastmcp.tools import ToolResult
except ImportError as exc:  # pragma: no cover - exercised only without the extra
    raise ImportError(
        "symbiote_caller_verifier.fastmcp_middleware needs the [fastmcp] extra of "
        "symbiote-caller-verifier; see its README for the install command"
    ) from exc

from symbiote_caller_verifier import __version__
from symbiote_caller_verifier.codec import MAX_TOOL_NAME_LENGTH, META_KEY
from symbiote_caller_verifier.verifier import (
    CALLER_PROTOCOL,
    PROBE_TOOL_NAME,
    REJECTION_CODES,
    CallerRejected,
    ReplayStore,
    VerifierConfig,
    bind_verified_caller,
    require_verified_caller,
    verify_call,
)

REFUSAL_TEXT = "caller_rejected"
# Fields mcp declares on ``RequestParams.Meta`` (``progressToken``). They dump
# as ``None`` when the client never sent them; every other key is an extra the
# client did send, so its null value is kept for ``classify_meta`` to refuse.
DECLARED_META_FIELDS = frozenset(mt.RequestParams.Meta.model_fields)
logger = logging.getLogger(__name__)


def refusal(code: str) -> ToolResult:
    """An error result naming the failed check and nothing else."""
    if code not in REJECTION_CODES:
        raise ValueError(f"Unknown rejection code: {code}")
    return ToolResult(
        content=REFUSAL_TEXT,
        structured_content={META_KEY: {"rejected": code}},
        is_error=True,
    )


def _sent_meta(meta: mt.RequestParams.Meta | None) -> dict[str, Any]:
    """Every undeclared key the client sent, null values included.
    ``exclude_none`` would hide ``{"fastmcp": null}`` and
    ``{"symbiote/caller.v1": null}`` from ``classify_meta``; a declared field
    that is ``None`` (unsent or sent as null) is the only kind of key dropped."""
    if meta is None:
        return {}
    dump = meta.model_dump()
    return {k: v for k, v in dump.items() if not (k in DECLARED_META_FIELDS and v is None)}


def _loggable(tool_name: str) -> str:
    """The client-chosen name cut to the codec's bound; callers log it with
    ``%r`` so a newline cannot forge a second log line."""
    return tool_name[:MAX_TOOL_NAME_LENGTH]


class CallerVerificationMiddleware(Middleware):
    def __init__(
        self,
        config: VerifierConfig,
        store: ReplayStore,
        *,
        clock: Callable[[], float] = time.time,
    ) -> None:
        if not isinstance(config, VerifierConfig):
            raise ValueError("config must be a VerifierConfig")
        self._config = config
        self._store = store
        self._clock = clock

    @staticmethod
    def _refuse(code: str, tool_name: str) -> ToolResult:
        """Log the code and tool for the operator; never the assertion."""
        logger.warning("caller refused: %s tool=%r", code, _loggable(tool_name))
        return refusal(code)

    async def on_call_tool(
        self,
        context: MiddlewareContext[mt.CallToolRequestParams],
        call_next: CallNext[mt.CallToolRequestParams, ToolResult],
    ) -> ToolResult:
        tool_name = context.message.name
        fastmcp_context = context.fastmcp_context
        request_context = fastmcp_context.request_context if fastmcp_context is not None else None
        if request_context is None:
            return self._refuse("absent", tool_name)
        arguments = context.message.arguments or {}
        try:
            # Inside the guard so a failure reading ``_meta`` is the same
            # structured ``shape`` refusal as one raised by verification.
            extra = _sent_meta(request_context.meta)
            # The store may wait on busy_timeout; never block the event loop.
            # The thread cannot be cancelled: a request cancelled after the
            # assertion id is consumed leaves it burned and the tool never
            # runs. The platform never re-mints, so that call reports as
            # unknown. Fail-closed by design; an id is never made reusable.
            caller = await asyncio.to_thread(
                verify_call,
                self._config,
                self._store,
                meta=extra,
                tool_name=tool_name,
                arguments=arguments,
                now=int(self._clock()),
            )
        except CallerRejected as rejected:
            return self._refuse(rejected.code, tool_name)
        except Exception as exc:
            # A failure the codec did not name is a bug or a misconfiguration,
            # not a client fault: log it once at ERROR and fail closed as
            # `shape`. The traceback is rendered to text here (source lines,
            # never claim values) and the record carries NO exception object:
            # ``exc_info`` would hand every handler the live frames, and a
            # locals-capturing one (Sentry, rich, structlog) would lift
            # ``meta``, ``extra`` and the claims out of this frame. The
            # exception text never reaches `content`; the platform reads only
            # the structured `rejected` code.
            logger.error(
                "caller verification raised; refusing as shape tool=%r\n%s",
                _loggable(tool_name),
                # chain=False: a studio ReplayStore may wrap its own errors
                # with `from`, and a chained message could carry the jti it
                # was handed. The helper's own exceptions are all `from None`.
                "".join(traceback.format_exception(exc, chain=False)).rstrip("\n"),
            )
            return refusal("shape")
        with bind_verified_caller(caller):
            return await call_next(context)


def register_probe(mcp: FastMCP) -> None:
    """Register the reserved probe that echoes the verified assertion id."""

    def symbiote_caller_probe() -> dict[str, str]:
        """Echo the verified caller assertion id and argument digest."""
        caller = require_verified_caller()
        return {
            "protocol": CALLER_PROTOCOL,
            "helper_version": __version__,
            "kid": caller.kid,
            "jti": caller.jti,
            "args_digest": caller.args_digest,
        }

    mcp.tool(symbiote_caller_probe, name=PROBE_TOOL_NAME)
