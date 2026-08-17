# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Repository layout

The git repository root is the parent directory (`jaguar-dart/`), which holds four
independent Dart packages: `jaguar_jwt` (this package), `jaguar_session_jwt`,
`jaguar_session_mongo`, and `example_models`. Only `jaguar_jwt` is null-safe and
maintained; the sibling packages still pin `sdk: ">=2.0.0-dev.65 <3.0.0"` and depend on
the pre-null-safety `jaguar_jwt ^2.1.5`. Work inside `jaguar_jwt/` unless told otherwise,
and remember that `git` commands operate on the whole multi-package tree.

`jaguar_jwt` is a pure-Dart library (no Flutter, no `dart:io`) published to pub.dev.
`crypto` is its only runtime dependency.

## Commands

All commands run from the `jaguar_jwt/` package directory.

```sh
dart pub get                                   # install dependencies
dart test                                      # run all tests
dart test test/decoding/validation_test.dart   # run a single test file
dart test -n 'Audience'                        # run tests whose name matches
dart analyze --fatal-infos                     # static analysis, as CI runs it
dart format .                                  # format
dart run example/example.dart                  # end-to-end issue + verify demo
```

CI runs exactly these (`.github/workflows/jaguar_jwt.yml`, at the repository root rather
than in this directory) on stable and beta, and treats analyzer infos as failures. Run
them locally before pushing and CI will not surprise you.

## Architecture

Everything is exported through `lib/jaguar_jwt.dart`, which re-exports four of the eight
files in `lib/src/`. The remaining files (`date.dart`, `prettify.dart`, `secure_compare.dart`,
`splay.dart`) are internal helpers and are deliberately not part of the public API — adding
a symbol to them does not make it public.

The library has exactly two entry points, both in `lib/src/jaguar_jwt.dart`:

- `issueJwtHS256(JwtClaim, hmacKey)` — serializes the claim set, signs with HMAC-SHA256.
- `verifyJwtHS256Signature(token, hmacKey, {headerCheck, defaultIatExp, maxAge})` —
  verifies signature and returns a `JwtClaim`.

Verification and validation are deliberately separate steps. `verifyJwtHS256Signature`
only checks the JOSE header and the signature; it does **not** check expiry, issuer, or
audience. Callers must then call `JwtClaim.validate(issuer:, audience:, allowedClockSkew:,
currentTime:)`. Keep this split when adding features — tests and the README both depend on it.

### JwtClaim (`lib/src/claim.dart`)

The central model, immutable, and the source of most of the subtlety:

- Claims are split into the seven **registered** names (`registeredClaimNames`: iss, sub,
  aud, exp, nbf, iat, jti), each with its own typed field, and everything else, held in a
  private `_otherClaims` map reached via `operator[]`, `containsKey`, and `claimNames`.
  Passing a registered name in `otherClaims` throws `ArgumentError` — registered claims
  must use their named constructor parameter. Providing the `pld` claim through both
  `otherClaims` and the legacy `payload` parameter also throws.
- `defaultIatExp` (default `true` on the constructor) auto-populates `iat` with now and
  `exp` with `iat + maxAge` (`defaultMaxAge` = 1 day) when they are absent. This is an
  *issuing* convenience: `verifyJwtHS256Signature` defaults it to **false**, so a decoded
  claim set holds exactly the claims the token carried. Do not flip that default back — a
  fabricated `exp` is always in the future, which is what previously made a token with no
  expiry look like one that expires (see git history for #2).
- The public constructor is a `factory` that resolves the defaulted `iat`/`exp` from a
  single clock reading and delegates to the private generative `JwtClaim._`. Nothing
  subclasses `JwtClaim`; if that changes, this is why the constructor cannot be extended.
- All `DateTime` values are normalized to UTC on construction. Encoding to/from JWT
  NumericDate goes through `JwtDate` in `date.dart`, which accepts both int and double on
  decode but always emits whole seconds on encode. `decode` range-checks *before*
  multiplying seconds by 1000: that product overflows a 64-bit int and wraps, which used
  to turn an absurd date into a plausible one. Every rejection there must be a
  `JwtException` — anything else escapes the `on JwtException` handling that callers are
  documented to write.
- `validate()` rejects a token when the current time is *at or after* `exp` (inclusive) but
  accepts it exactly at `nbf`; it also rejects claim sets where `exp` is not after `nbf`
  or not after `iat`. `iat` itself is never checked against the clock — see the comment
  in `validate` for why.
- `validate()`'s `issuer` and `audience` checks are only performed when the caller supplies
  the expected value, but a token *missing* the corresponding claim is then rejected.
  `requireExpiry` (default false) additionally rejects a token with no `exp` at all, since
  `exp` is optional in RFC 7519 and such a token never expires.
- The `payload` getter is a legacy accessor for the non-registered `pld` claim, returning
  null when it is absent. `claimSet['pld']` reaches the same value and is preferred.

### Supporting invariants

- **Base64url**: `B64urlEncRfc7515` implements RFC 7515 Base64url (no padding), which is
  *not* `dart:convert`'s `base64Url` (RFC 4648). Its `decode` actively rejects `=`, `+`,
  and `/`. Always use this class for JWT parts; never `base64Url` directly.
- **Deterministic JSON**: both the JOSE header and the claim payload are built into
  `SplayTreeMap`s so keys are emitted in sorted order, and `splay()` in `splay.dart`
  applies this recursively to nested Maps inside non-registered claim values. Tests assert
  on exact encoded token strings, so breaking key ordering breaks them.
- **Signature comparison** goes through `secureCompareIntList` (constant-time). Do not
  replace it with `==` or `ListEquality`.
- **Key bytes**: the `List<int>` functions (`issueJwtHS256Bytes`,
  `verifyJwtHS256SignatureBytes`) are the real implementations; the String forms are
  thin wrappers that apply `utf8.encode`. Never derive key bytes from `String.codeUnits`
  — that diverges from every other JWT implementation above U+007F, and `Hmac` masks
  each element to a byte, so code units above 255 silently lose their high bits (which
  once made `'€'` and `'¬'` the same key). A key that is not valid UTF-8 must go through
  the bytes API; the RFC 7515 fixtures in the tests do exactly that.
- **Algorithm pinning**: the algorithm is fixed by the function the caller chose, not read
  from the token. `verifyJwtHS256SignatureBytes` builds `Hmac(sha256, ...)` unconditionally
  and then checks `header['alg'] != 'HS256'`, throwing `JwtException.algorithmMismatch`;
  `alg` is an assertion checked against what the code will do, never a selector that picks
  it. Do not add an "expected algorithm" parameter: a constant cannot be misconfigured and
  a parameter can, and it is the parameterised form that lets an RSA public key be accepted
  as an HMAC secret. Adding RS256 later means a *separate* `issueJwtRS256` /
  `verifyJwtRS256Signature` pair pinning `'RS256'`, so the key type and the algorithm are
  bound together by the signature of the function — not a unified `verify` taking both.
  The check sits with the `crit`/`b64` checks, ahead of `headerCheck`, for the reason below.
- **Header extensions**: `verifyJwtHS256Signature` rejects any header carrying `crit`
  (RFC 7515 §4.1.11) or `b64: false` (RFC 7797) *before* calling `headerCheck`, and the
  callback cannot override it. That placement is deliberate: honouring such an extension
  means processing the token differently, which a header-inspection callback cannot do, so
  letting one accept `crit` would be a false claim of support. Unrecognised header
  parameters that are *not* marked critical are ignored, as the RFC allows.
- **Errors**: all token/validation failures throw one of the `const JwtException`
  singletons in `exception.dart`. Tests match on identity (`throwsA(equals(JwtException.tokenExpired))`),
  so reuse the existing constants rather than constructing new instances.
- Encoding failures for unsuitable claim values surface as `JsonUnsupportedObjectError`
  from `JwtClaim.toJson`.

### RS256

Not implemented, deliberately. `lib/src/rsa_sha256_signer.dart` — a stub entirely inside a
`/* TODO ... */` comment, never exported, depending on a package absent from
`pubspec.yaml`, and setting `'alg': 'HS256'` in its own header map — was deleted in #10
rather than finished, since nothing consuming this fork needs asymmetric signing. The
"RS256 support" commit in the history never shipped anything. If it is wanted later, see
the algorithm-pinning invariant above for the shape it has to take.

## Conventions

- **`dart analyze` is clean, and CI runs it with `--fatal-infos`.** That is the baseline
  now: any finding you introduce is a build failure, and there is no backlog to hide in.
- `analysis_options.yaml` sets `language: strict-casts: true`, which forbids implicit
  downcasts from `dynamic`. This matters more here than in most packages, because decoded
  JSON arrives as `dynamic` and an unchecked cast is how a malformed token turns into a
  wrong value rather than a rejection. Prefer `Object?` with an explicit `is` check over
  `dynamic` for anything coming out of a token. (Do not restore
  `analyzer: strong-mode: implicit-casts:` — Dart 3 ignores it *silently*, which is how
  the package went years believing it was strict when it was not.)
  Lint rules worth knowing: `public_member_api_docs` (every public member needs a doc
  comment), `prefer_single_quotes`, `sort_constructors_first`, `type_annotate_public_apis`,
  and `avoid_annotating_with_dynamic`.
- `dart format` is clean across the package and CI enforces it.
- Tests are grouped by concern under `test/` (`encode/`, `decoding/`, `prettify/`,
  `secure_compare/`) and lean on the RFC 7515 Appendix A.1 example token as a known-good
  fixture. `decoding_test.dart` has a `signWithHeader` helper for tokens needing a JOSE
  header that `issueJwtHS256` will not produce.
- `example/example.dart` is run by CI, so it has to keep working: it is documentation that
  compiles.

## Working on this fork

This repo is a fork of an upstream package that went unmaintained for years, and it is
consumed as a security-critical dependency, so doc drift and latent defects are expected
rather than surprising. Two habits follow:

- Verify what documentation and comments claim before relying on them. Several have
  asserted behaviour the code does not have.
- Carry documentation updates in the same change as the code: dartdoc on touched members,
  `README.md`, `CHANGELOG.md`, `example/`, and this file.

Open issues track the known outstanding defects; check them before starting work, since
`git log` may already have closed one.
