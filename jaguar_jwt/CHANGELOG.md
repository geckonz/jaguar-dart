# Changelog

## Unreleased

**Breaking changes** — these tighten verification and validation, so tokens
that were previously accepted may now be rejected:

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

Other changes:

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
