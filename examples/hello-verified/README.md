# hello-verified

A stdio FastMCP server with three tools:

| Tool | Verified? | Behaviour |
|---|---|---|
| `greet` | no (`exempt_tools`) | Says hello. No caller identity |
| `archive_shot` | yes | Checks the verified caller against `allowed_callers.json`, then records the shot |
| `symbiote_caller_probe` | yes | Reserved. Lets the platform confirm this server verifies assertions |

```
pip install "symbiote-caller-verifier[fastmcp] @ https://github.com/symbiote-labs/symbiote-caller-verifier/releases/download/v0.1.0/symbiote_caller_verifier-0.1.0-py3-none-any.whl"
cp verifier.example.json verifier.json   # fill in the issuer, UUIDs and trust bundle
python hello_verified_server.py
```

Put the platform user UUIDs allowed to archive in `allowed_callers.json`. The paths
can also come from `SYMBIOTE_VERIFIER_CONFIG`, `SYMBIOTE_REPLAY_DB` and
`SYMBIOTE_CALLER_POLICY`. Refusals are logged to stderr, never stdout.
