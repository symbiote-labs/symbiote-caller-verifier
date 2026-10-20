# Changelog

## 0.2.0

- Caller assertion v2: `typ` `symbiote-caller-assertion-v2`, signed under the domain
  prefix `symbiote-caller-assertion-v2\0`. `sub` adds `idp: {iss, sub, verified_at}`
  (the caller's identity-provider issuer and subject, and the `iat` of the last ID
  token the platform verified for them) and, optionally, an IdP-verified `email`.
  The envelope (`v: 1`) and the `_meta` key `symbiote/caller.v1` are unchanged. v1
  assertions verify exactly as before.
- `VerifiedCaller` adds `identity_level`, `idp` and `email` (defaults keep the
  constructor source-compatible).
- `VerifierConfig` adds `require_identity` (`uuid` default, `idp`, `idp+email`),
  `allowed_idp_issuers` and `max_identity_age_seconds`. New rejection codes
  `identity_insufficient`, `identity_issuer` and `identity_stale`, checked after the
  signature and before the replay id is consumed. An issuer pin or an age bound
  without an identity level is refused at configuration time. The age bound also
  applies to `symbiote_caller_probe`. A `verified_at` later than the assertion's
  `iat` plus `max_skew_seconds` is refused as `shape`.
- `codec` exports `IdpIdentity`, `ASSERTION_TYP_V2`, `SIGNING_PREFIX_V2` and the
  validators `validate_idp_issuer`, `validate_idp_subject`, `validate_email`.
  Identity members are bounded in UTF-8 bytes and refuse control, format and
  line-separator characters. `http://` issuers are accepted for development IdPs;
  pin `https://` issuers in production.
- `examples/hello-verified` requires `idp+email`, pins the IdP issuer, bounds the
  identity age at 7 days, looks callers up by verified email with (`iss`, `sub`) as
  the stable key, and keeps identity out of tool results. An opt-in `whoami` tool
  (`SYMBIOTE_EXPOSE_WHOAMI=1`, testing only) returns the verified identity.
- Compatibility: 0.1.0 refuses every v2 assertion as `shape`. Upgrade the verifier
  before switching an integration's `caller_identity` away from `uuid`.

## 0.1.0

First release: assertion codec, verifier, SQLite replay store, FastMCP middleware and the `symbiote_caller_probe` tool.
