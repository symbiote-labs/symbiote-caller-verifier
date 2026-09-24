"""Verify Symbiote caller assertions before an MCP tool runs.

The core modules (``codec``, ``replay_store``, ``verifier``) depend only on
``cryptography`` and ``rfc8785``. ``fastmcp_middleware`` needs the ``[fastmcp]``
extra and is imported explicitly by servers that use it.
"""

from __future__ import annotations

from symbiote_caller_verifier.codec import (
    META_KEY,
    CodecError,
    SigningKey,
    TrustBundle,
)
from symbiote_caller_verifier.replay_store import (
    ReplayDetected,
    ReplayStoreUnavailable,
    SqliteReplayStore,
)
from symbiote_caller_verifier.verifier import (
    CALLER_PROTOCOL,
    PROBE_TOOL_NAME,
    REJECTION_CODES,
    CallerRejected,
    VerifiedCaller,
    VerifiedCallerRequired,
    VerifierConfig,
    bind_verified_caller,
    require_verified_caller,
    verified_caller,
    verify_call,
)

__version__ = "0.1.0"

__all__ = [
    "CALLER_PROTOCOL",
    "META_KEY",
    "PROBE_TOOL_NAME",
    "REJECTION_CODES",
    "CallerRejected",
    "CodecError",
    "ReplayDetected",
    "ReplayStoreUnavailable",
    "SigningKey",
    "SqliteReplayStore",
    "TrustBundle",
    "VerifiedCaller",
    "VerifiedCallerRequired",
    "VerifierConfig",
    "__version__",
    "bind_verified_caller",
    "require_verified_caller",
    "verified_caller",
    "verify_call",
]
