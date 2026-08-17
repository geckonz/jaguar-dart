# Changelog

## 4.0.0

A major version: the changes below alter which tokens are accepted, and the
signature produced by a non-ASCII textual key.

**Breaking changes** — these tighten verification and validation, so tokens
that were previously accepted may now be rejected. For what a consumer of the
published 3.0.0 has to actually do about them, see *Migrating from jaguar_jwt
3.0.0 on pub.dev* in `README.md`:

+ The HMAC key is now derived from a String using UTF-8, rather than from
  `String.codeUnits`. Tokens issued with a secret containing **any non-ASCII
  character** will therefore have a different signature to those issued by
  earlier versions, and will no longer verify against them. In exchange they
  now interoperate with other JWT implementations, which all treat a textual
  secret as UTF-8. An ASCII secret is unaffected: the two encodings agree
  below U+0080. (#4)

  This also fixes silent loss of key material. `Hmac` masks each element of
  the key to a byte, so a code unit above 255 previously contributed only its
  low byte: the secrets `'€'` (U+20AC) and `'¬'` (U+00AC) produced an
  identical key, and a token signed with one verified with the other.

+ New `issueJwtHS256Bytes` and `verifyJwtHS256SignatureBytes` accept the key as
  `List<int>`. Use these when the shared secret is binary key material rather
  than text — such a key cannot be carried through a String, since not every
  byte sequence is valid UTF-8.

+ `verifyJwtHS256Signature` now rejects a token whose JOSE header has a 'crit'
  Header Parameter, with the new `JwtException.unsupportedHeaderExtension`.
  Section 4.1.11 of RFC 7515 requires this: a recipient must not process a JWS
  that marks an extension critical unless it understands that extension, and
  this implementation understands none. A header requesting an unencoded
  payload with 'b64' (RFC 7797) is rejected for the same reason. Both checks
  run before `headerCheck` and cannot be disabled by it. (#3)

+ `JwtClaim.validate(audience: ...)` now rejects a token that has no Audience
  Claim, instead of skipping the check. Previously a token issued for no
  audience was accepted by every service that validated an audience. (#1)
+ `verifyJwtHS256Signature` no longer assigns default Issued At and Expiration
  Time Claims: `defaultIatExp` now defaults to false, so the returned claim set
  contains exactly the claims that were in the token. The old behaviour
  fabricated an expiry that was always in the future, which made a token
  without an Expiration Time Claim appear to expire while in fact never
  expiring. Pass `defaultIatExp: true` to restore it (not recommended). (#2)
+ `JwtClaim.validate` gained a `requireExpiry` parameter (default false).
  Set it to true to reject tokens that have no Expiration Time Claim with the
  new `JwtException.expiryRequired`.

+ Providing the 'pld' claim through both the `otherClaims` and the legacy
  `payload` parameter now throws an `ArgumentError`, which is what the
  documentation already said it did. Previously `payload` silently discarded
  the value given in `otherClaims`.

+ `JwtDate.decode` now rejects a NumericDate too large to represent as a
  `DateTime`, instead of letting a `RangeError` escape. Verification is
  documented to throw `JwtException`, so the old behaviour escaped a caller's
  error handling. Values large enough to overflow the seconds-to-milliseconds
  multiplication were worse than out of range: they wrapped around and were
  accepted as a plausible date, so an `exp` of 18446744073709552 decoded to
  384 milliseconds after the epoch. Both require a validly signed token. (#7)
+ `JwtClaim.payload` returns `Map<String, dynamic>?` rather than
  `Map<String, dynamic>`, and returns null when the token has no 'pld' claim.
  It previously threw a `TypeError` in that case, by casting null to a
  non-nullable Map. (#5)

+ A token whose 'alg' Header Parameter is absent, or is anything other than
  'HS256', is now rejected with the new `JwtException.algorithmMismatch`
  instead of `JwtException.hashMismatch`. Such a token was already rejected —
  the algorithm has always been pinned by the verifying function rather than
  selected from the header, which is what prevents the RS256-to-HS256 key
  confusion attack — but reporting it as a hash mismatch made a forgery attempt
  indistinguishable from a key that needs rotating. Code matching on
  `JwtException.hashMismatch` to detect a rejected algorithm must now match on
  `JwtException.algorithmMismatch`. (#10)

  The check also moved ahead of `headerCheck`, alongside the 'crit' and 'b64'
  checks, so every decision about whether a token can be processed at all is
  made in one place and none of them can appear to involve the callback. A
  header check could only ever reject a token, so this does not change which
  tokens are accepted; a header that fails both checks now reports the
  algorithm rather than the header check.

+ The minimum SDK is now Dart 3.0.0. The package already required a Dart 3
  toolchain in practice; the declared bound of `>=2.12.0 <3.0.0` was stale. (#9)

Other changes:

+ Deleted `lib/src/rsa_sha256_signer.dart`. Despite a commit titled "RS256
  support", the file was entirely inside a `/* TODO */` comment, was never
  exported, depended on a package absent from `pubspec.yaml`, and set
  `'alg': 'HS256'` in its own header map. It advertised an algorithm the
  package does not implement. Only HS256 is supported; if RSA signing is added
  later it will be a separate pair of functions, so that the key type and the
  algorithm stay bound together. (#10)

+ Removed the `auth_header` dependency, which nothing imported. `crypto` is now
  the only runtime dependency. (#8)
+ Restored a strictness setting the package had silently lost. It configured
  `analyzer: strong-mode: implicit-casts: false`, which Dart 3 ignores without
  reporting anything, so implicit downcasts from `dynamic` had been permitted
  for some time. Replaced with `language: strict-casts: true`; the code needed
  no changes to satisfy it. (#9)
+ The analyzer now reports nothing, down from 21 findings, mostly `dynamic?`
  written during the 3.0.0 null-safety migration (`dynamic` is already
  nullable). Parameters that accept anything are now `Object?` rather than
  `dynamic`, so a type check is required before use. (#9)
+ `JOSEHeaderCheck` is declared with the modern function-type syntax. (#9)
+ Replaced the dead Travis CI configuration with a GitHub Actions workflow
  running formatting, analysis, tests and the example on stable and beta. Its
  analysis step treats infos as failures. Deleted `tool/travis.sh` and
  `tool/ensure_dartfmt.sh`, which invoked the long-removed `pub run` and
  `dartfmt` commands and referenced a test file that does not exist, along with
  `analysis_options.yaml.complete`, an aspirational rule set naming lints that
  no longer exist. (#9)

+ `JwtClaim.toString` now escapes quotes and backslashes in Claim Names and
  Claim Values, which it had only appeared to do: the escaping used cascades,
  which discard the result of `String.replaceAll`. Newlines, carriage returns
  and tabs are escaped as well, so a Claim Value can no longer make part of a
  logged claim set look like a separate entry. (#6)
+ `JwtDate.decode` accepts a NumericDate of `0.0`, having already accepted an
  integer `0`. (#7)

+ The defaulted Issued At and Expiration Time Claims are now derived from a
  single reading of the clock, so the interval between them is exactly
  `maxAge`.
+ Documentation corrections: the `audience` field documented an empty-list
  default it has never had since null safety; the README referred to a
  `JwtClaimSet` class that does not exist, showed an example using the wrong
  variable, and carried a build badge for a decommissioned CI service.
+ The example now seeds its JWT ID from `Random.secure()` rather than from the
  clock.

## 3.0.0

+ Null safety  

**Breaking changes:**
+ Changed all Object to dynamic Dart type

## 2.1.6

+ Added support for optional Not Before (`nbf`) time claims.
+ Fixed validation to reject token when current time equals the Expiry time.
+ Added more validation unit tests.
+ Fixed generation of JWT to use correct Base64url Encoding.
+ Added general support for non-registered claims.
+ Tidy up for static analysis and Dart linter.
+ Implemented toString method for JwtClaim.
+ Allow for customized checking of the JWT header.
+ Fixed use of _splayify/_spaly in toJson and changed dynamic to Object.
+ Improved format of output produced by JwtClaim.toString().

## 2.1.2

+ Fixed when `typ` is not present

## 2.1.1

+ Dart 2 compatibility
