# symbiote-caller-verifier

Verifies the signed caller assertion that Symbiote attaches to every call it sends
to a verified-caller MCP server. A call is refused before any tool code runs if its
assertion is forged, altered, expired, meant for another server, bound to other
arguments, or replayed. Your tool then gets the verified platform user id and maps
it to its own permissions.

The assertion travels in the MCP request `_meta` under the key `symbiote/caller.v1`.
Its claims are JCS-canonical and signed with Ed25519. The helper never fetches keys:
it trusts only the bundle you pin in its config.

## Install

The package is published as assets on this repository's
[releases](https://github.com/symbiote-labs/symbiote-caller-verifier/releases), not on
PyPI. Each release carries the wheel, the sdist and a `SHA256SUMS` file.

Connected host:

```
pip install "symbiote-caller-verifier[fastmcp] @ https://github.com/symbiote-labs/symbiote-caller-verifier/releases/download/v0.1.0/symbiote_caller_verifier-0.1.0-py3-none-any.whl"
```

Air-gapped host. On a connected machine with the same OS, CPU architecture and Python
version as the target, download the wheel, check it, and collect its dependencies:

```
curl -LO https://github.com/symbiote-labs/symbiote-caller-verifier/releases/download/v0.1.0/symbiote_caller_verifier-0.1.0-py3-none-any.whl
curl -LO https://github.com/symbiote-labs/symbiote-caller-verifier/releases/download/v0.1.0/SHA256SUMS
sha256sum --check --ignore-missing SHA256SUMS
pip download --dest wheels "./symbiote_caller_verifier-0.1.0-py3-none-any.whl[fastmcp]"
```

Copy `wheels/` to the target and install with no index:

```
pip install --no-index --find-links wheels "symbiote-caller-verifier[fastmcp]"
```

The core depends only on `cryptography` and `rfc8785`. The `[fastmcp]` extra adds the
FastMCP middleware. Python 3.11 to 3.13.

## Use with FastMCP

```python
from fastmcp import FastMCP
from symbiote_caller_verifier import SqliteReplayStore, VerifierConfig, require_verified_caller
from symbiote_caller_verifier.fastmcp_middleware import CallerVerificationMiddleware, register_probe

mcp = FastMCP("studio-tools")
config = VerifierConfig.from_file("verifier.json")
store = SqliteReplayStore("/var/lib/studio-mcp/replay.sqlite")
mcp.add_middleware(CallerVerificationMiddleware(config, store))
register_probe(mcp)  # reserved tool symbiote_caller_probe

@mcp.tool
def archive_shot(shot: str) -> str:
    caller = require_verified_caller()  # raises if the call was not verified
    ...  # map caller.subject_id to your own permissions
```

A runnable server is in [`examples/hello-verified`](examples/hello-verified).

## Configuration

`verifier.json`:

| Field | Value |
|---|---|
| `issuer` | Your platform's assertion issuer, exactly as it signs it |
| `integration_id`, `server_id` | The UUIDs this server is registered as on the platform |
| `trust_bundle` | The platform's published bundle: `{"issuer", "keys": [{"kid", "alg": "Ed25519", "public_key"}]}` |
| `max_skew_seconds` | Clock tolerance on `iat` and `exp`. Default 5, at most 300 |
| `max_lifetime_seconds` | Upper bound on `exp - iat`. Default 300, at most 3600 |
| `exempt_tools` | Tools that may run without an assertion, with no caller identity. Default empty |

To rotate keys, add the next key to `trust_bundle`, switch the platform to sign with
it, then remove the old `kid`. Removing a `kid` revokes it.

## Refusal codes

A refused call returns an MCP error whose `structuredContent` is
`{"symbiote/caller.v1": {"rejected": "<code>"}}`. The helper also logs
`caller refused: <code> tool='<name>'` at `WARNING` on the `symbiote_caller_verifier`
logger. It never logs or echoes the assertion.

| Code | Meaning |
|---|---|
| `absent` | No assertion on a tool that is not exempt |
| `foreign_meta` | `_meta` carries a key other than the assertion and `progressToken` |
| `shape` | The assertion is malformed, or verification failed in an unexpected way |
| `signature` | Unknown `kid`, or the signature does not verify against the trust bundle |
| `audience` | Issuer, integration or server does not match this config |
| `expired` | Outside its time window (after skew), or its lifetime is too long |
| `tool_mismatch` | Signed for a different tool name |
| `argument_digest` | Signed for different arguments |
| `replayed` | This assertion id was already used |
| `store_unavailable` | The replay store could not record the id; the call is refused |

## Limits

- **The replay store covers one host.** `SqliteReplayStore` protects any number of
  processes on one host that share one file on persistent local disk. Replicas on
  several hosts need a shared atomic store, which this package does not supply.
  Separate files on separate hosts do not protect each other.
- An assertion id is consumed just before the tool runs. If the request is cancelled
  in between, the id stays used and the tool does not run.
- The helper proves who the platform admitted. It does not protect a compromised
  host.

## License

MIT
