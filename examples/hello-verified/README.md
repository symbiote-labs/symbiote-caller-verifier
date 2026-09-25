# hello-verified

A stdio FastMCP server with three tools:

| Tool | Verified? | Behaviour |
|---|---|---|
| `greet` | no (`exempt_tools`) | Says hello. No caller identity |
| `archive_shot` | yes | Checks the verified caller against `allowed_callers.json`, then records the shot |
| `whoami` | yes | Only with `SYMBIOTE_EXPOSE_WHOAMI=1`. Returns the verified identity; testing only |
| `symbiote_caller_probe` | yes | Reserved. Lets the platform confirm this server verifies assertions |

```
pip install "symbiote-caller-verifier[fastmcp] @ https://github.com/symbiote-labs/symbiote-caller-verifier/releases/download/v0.2.0/symbiote_caller_verifier-0.2.0-py3-none-any.whl"
cp verifier.example.json verifier.json   # fill in the issuer, UUIDs, trust bundle and IdP issuer
python hello_verified_server.py
```

The paths can also come from `SYMBIOTE_VERIFIER_CONFIG`, `SYMBIOTE_REPLAY_DB` and
`SYMBIOTE_CALLER_POLICY`. Refusals are logged to stderr, never stdout.

## Identity

`verifier.example.json` is set up for an integration at `caller_identity`
`idp+email`:

- `require_identity: "idp+email"` refuses a weaker assertion as
  `identity_insufficient`.
- `allowed_idp_issuers` accepts only your IdP. Replace the example issuer with
  yours. Use `https://` in production; `http://` is for development IdPs only.
- `max_identity_age_seconds: 604800` refuses a caller whose last SSO sign-in is over
  7 days old as `identity_stale`. This includes the administrator who runs the
  platform's probe, so they need a recent sign-in before re-probing.

`allowed_callers.json` lists callers by email:

```json
{"email": "ada.artist@studio.example.com", "operations": ["archive_shot"],
 "idp": {"iss": "https://auth.studio.example.com/application/o/symbiote/", "sub": "0c8f..."}}
```

The email is how a caller is first found, because with authentik's default subject
mode `sub` is an opaque hash your directory cannot know. The (`iss`, `sub`) pair is
the stable key: once you record it in the entry, that pair keeps the entry's
permissions if the address changes, and the address arriving under another pair gets
nothing. An entry without `idp` matches on verified email alone. Email matching
ignores case.

For a `uuid` integration, list platform user UUIDs under `subjects` and drop the
three identity settings from `verifier.json`.

`archive_shot` returns only the status, the shot and the identity level. It never
echoes the issuer, subject, email, `verified_at` or platform UUID, because a tool
result goes back through the platform.

## `whoami` (testing only, off by default)

Start the server with `SYMBIOTE_EXPOSE_WHOAMI=1` to add a `whoami` tool that returns
the caller's verified identity: `identity_level`, `subject_id`, `idp` (`iss`, `sub`,
`verified_at`, or `null` at `uuid`) and `email` (`null` unless `idp+email`). Use it to
check what the verifier sees while onboarding.

It deliberately puts identity into the result, and so into the model context and the
chat transcript. Keep it off in production. It is verified and policy-checked like any
other tool: add `"whoami"` to a caller's `operations` to permit it. The shipped
`allowed_callers.json` permits it for nobody.
