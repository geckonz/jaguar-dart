# Changelog

## Unreleased

**Breaking changes** — all three tighten validation, so tokens that were
previously accepted may now be rejected:

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
