[![jaguar_jwt](https://github.com/geckonz/jaguar-dart/actions/workflows/jaguar_jwt.yml/badge.svg)](https://github.com/geckonz/jaguar-dart/actions/workflows/jaguar_jwt.yml)

# jaguar_jwt

JWT utilities for Dart.

This library can be used to generate and process JSON Web Tokens (JWT).
For more information about JSON Web Tokens, see
[RFC 7519](https://tools.ietf.org/html/rfc7519).

Currently, only the HMAC SHA-256 algorithm is supported to generate/process
a JSON Web Signature (JWS). Tokens signed with any other algorithm are
rejected, as are tokens whose header marks an extension critical (`crit`) or
requests an unencoded payload (`b64`), since neither is supported.

The algorithm is chosen by the code doing the verifying, never by the token.
`verifyJwtHS256Signature` always verifies with HMAC SHA-256, and treats the
`alg` Header Parameter as an assertion to check against that: a header naming
any other algorithm — including `none` — is rejected with
`JwtException.algorithmMismatch` before the signature is examined. This is the
step that libraries which pick their algorithm from the header get wrong, and
it is why adding another algorithm here will mean adding a separate pair of
functions rather than a parameter.

# Usage

## Issuing a JWT

```dart
  final key = 's3cr3t';
  final claimSet = JwtClaim(
      subject: 'kleak',
      issuer: 'teja',
      audience: <String>['audience1.example.com', 'audience2.example.com'],
      otherClaims: <String,dynamic>{
        'typ': 'authnresponse',
        'pld': {'k': 'v'}},
      maxAge: const Duration(minutes: 5));

  String token = issueJwtHS256(claimSet, key);
  print(token);
```

## Processing a JWT

To process a JWT:

1. Verify the signature and extract the claim set.
2. Validate the claim set.
3. Extract claims from the claim set.

Step 2 is not optional: `verifyJwtHS256Signature` only checks the signature and
the header. It does not check the issuer, the audience, or whether the token has
expired — `validate` does that.

Both `issuer` and `audience` are only checked when you pass them, and a token
that lacks the corresponding claim is rejected. The Expiration Time Claim is
optional in a JWT, so a token without one never expires: pass
`requireExpiry: true` to reject those.

```dart
  try {
    final JwtClaim decClaimSet = verifyJwtHS256Signature(token, key);
    // print(decClaimSet);

    decClaimSet.validate(
        issuer: 'teja',
        audience: 'audience1.example.com',
        requireExpiry: true);

    if (decClaimSet.jwtId != null) {
       print(decClaimSet.jwtId);
    }
    if (decClaimSet.containsKey('typ')) {
      final v = decClaimSet['typ'];
      if (v is String) {
         print(v);
      } else {
        ...
      }
    }

    ...
  } on JwtException {
    ...
  }
```

The claim set returned by `verifyJwtHS256Signature` contains exactly the claims
that were in the token. Registered claims that the token did not carry are null,
so check before use (or use `containsKey`).

# Configuration

## JwtClaim

`JwtClaim` is the model that holds JWT claim set information.

These are the registered claims:

1. `issuer`  
Authority issuing the token. This will be used during authorization to verify that expected issuer has 
issued the token.
Fills the `iss` field of the JWT.
2. `subject`  
Subject of the token. Usually stores the user ID of the user to which the token is issued.
Fills the `sub` field of the JWT.
3. `audience`  
List of audience that accept this token. This will be used during authorization to verify that 
JWT has expected audience for the service.
Fills `aud` field in JWT.
4. `expiry`  
Time when the token becomes no longer acceptable for process.
Fills `exp` field in JWT.
5. `notBefore`  
Time when the token becomes acceptable for processing.
Fills the `nbf` field in the JWT.
6. `issuedAt`  
Time when the token was issued.
Fills the `iat` field in the JWT.
7. `jwtId`  
Unique identifier across services that identifies the token.
Fills `jti` field in JWT.

### Default time claims

When constructing a `JwtClaim`, `issuedAt` defaults to the current time and
`expiry` defaults to `maxAge` after it (`JwtClaim.defaultMaxAge`, one day, if no
`maxAge` is given). Pass `defaultIatExp: false` to leave both unset unless you
provide them explicitly.

These defaults apply when *issuing* a token. They are not applied when verifying
one: a default expiry is always in the future, so it would mask a token that
never expires.

### The signing key

`issueJwtHS256` and `verifyJwtHS256Signature` take the shared secret as a
String and convert it to key bytes using UTF-8, which is what other JWT
implementations do with a textual secret.

If the secret is binary key material rather than text — decoded from Base64 or
hex, say — pass the bytes directly instead. Not every byte sequence is valid
UTF-8, so such a key cannot survive a round trip through a String:

```dart
  final keyBytes = base64.decode(encodedKey);

  final token = issueJwtHS256Bytes(claimSet, keyBytes);
  final claimSet = verifyJwtHS256SignatureBytes(token, keyBytes);
```

### Non-registered claims

Any other claims are provided with the `otherClaims` parameter, and read back
with `operator[]` / `containsKey` / `claimNames`:

```dart
  final claimSet = JwtClaim(
      subject: 'kleak',
      otherClaims: <String, dynamic>{'pld': {'k': 'v'}});

  if (claimSet.containsKey('pld')) {
    print(claimSet['pld']);
  }
```

Claim Values must be convertible to JSON: a scalar, a List, or a
`Map<String, dynamic>`. Passing a registered claim name in `otherClaims` throws
an `ArgumentError` — use the dedicated parameter for it.

# Migrating from jaguar_jwt 3.0.0 on pub.dev

This fork is version 4.0.0, and the major bump is meant literally: it tightens
verification and validation, so tokens the published 3.0.0 accepted may now be
rejected. That is the point of the change, but it means the upgrade needs
reading rather than just a version bump. `CHANGELOG.md` lists every change
with its rationale; this section is the part that requires action.

## 1. Depend on the fork

The fork is not published on pub.dev, so depend on it from git. The repository
holds several packages, so the `path` is required:

```yaml
dependencies:
  jaguar_jwt:
    git:
      url: https://github.com/geckonz/jaguar-dart.git
      path: jaguar_jwt
      ref: <commit or tag>
```

Pin `ref` to a commit or tag rather than tracking a branch: this is a
security-critical dependency, and a floating ref means the signature checks your
build performs can change without a change to your repository. Then
`dart pub get` (or `dart pub upgrade jaguar_jwt` if you already had it).

## 2. Changes the compiler will find

+ **`JwtClaim.payload` is now `Map<String, dynamic>?`.** It returns null when
  the token has no `pld` claim, where before it threw a `TypeError` casting null
  to a non-nullable Map. Assignments to a non-nullable variable stop compiling;
  handle the null. `claimSet['pld']` reads the same value and is preferred.
+ **The minimum SDK is Dart 3.0.0.**

## 3. Changes the compiler will not find

These are the ones worth budgeting review time for.

+ **The HMAC key is derived from a String with UTF-8, not `String.codeUnits`.**
  If your shared secret is pure ASCII, nothing changes — the two encodings agree
  below U+0080. If it contains **any** non-ASCII character, every token issued
  by the old version stops verifying, and tokens you issue now will not verify
  against a service still on the old version. Plan that as a flag day, or rotate
  to an ASCII secret first. The old behaviour also silently discarded key
  material above U+00FF, so `'€'` and `'¬'` were the same key; if your secret is
  in that range, treat it as compromised rather than merely incompatible.
+ **A binary secret must use the new bytes API.** `issueJwtHS256Bytes` and
  `verifyJwtHS256SignatureBytes` take `List<int>`. A key that is not valid UTF-8
  cannot be carried through a String at all — if you were decoding a Base64 or
  hex secret into a String, switch to these.
+ **`verifyJwtHS256Signature` no longer invents `iat` and `exp`.**
  `defaultIatExp` now defaults to false, so the returned claim set contains
  exactly the claims the token carried. Code reading `claimSet.expiry` or
  `claimSet.issuedAt` must handle null. More importantly, `validate` can no
  longer decide a token expired when the token has no expiry at all: the old
  default fabricated an expiry that was always in the future, so a token that
  never expires looked like one that does. **Pass `requireExpiry: true` to
  `validate`** if you treat a JWT as a time-limited credential — which, for an
  access or refresh token, you do.
+ **`validate(audience: ...)` rejects a token with no Audience Claim.**
  Previously the check was skipped for such a token, so a token issued for no
  audience was accepted by every service that validated one. If you issue
  tokens without `aud` and validate with it, add the claim before upgrading the
  verifying side.
+ **New exceptions to match on.** All are `JwtException` and all are thrown from
  the same places as before, so a broad `on JwtException` handler needs no
  change. Code matching specific constants may:
  + `JwtException.algorithmMismatch` — the header's `alg` is absent or is not
    `HS256`. Previously reported as `JwtException.hashMismatch`. Match on this
    if you distinguish a forgery attempt from a key that needs rotating.
  + `JwtException.unsupportedHeaderExtension` — the header carries `crit`
    (RFC 7515 §4.1.11) or `b64: false` (RFC 7797). Neither is supported, and
    neither can be waved through by a `headerCheck`.
  + `JwtException.expiryRequired` — only thrown if you opt in with
    `requireExpiry: true`.
+ **A malformed date in a token throws `JwtException`, not `RangeError`.** A
  NumericDate too large to represent used to escape a caller's documented
  `on JwtException` handling; worse, values large enough to overflow the
  seconds-to-milliseconds multiplication wrapped around and were accepted as a
  plausible date. If you were catching `RangeError` around verification to work
  around this, remove it.
+ **Supplying `pld` through both `otherClaims` and the legacy `payload`
  parameter now throws `ArgumentError`.** This is only reachable when issuing,
  and the documentation always said it threw; previously `payload` silently
  discarded the `otherClaims` value.

## 4. Checklist

+ [ ] Secret is ASCII text, or the flag day is planned, or it moved to the bytes
      API.
+ [ ] Every `validate` call passes `issuer:` — it is not checked otherwise, so
      tokens signed with the same secret by any other component cross-validate.
      Read the expected issuer from the same constant the issuing side uses, so
      the two cannot drift.
+ [ ] Every `validate` call passes `requireExpiry: true`, unless you genuinely
      accept tokens that never expire.
+ [ ] Every `validate` call passes `audience:` if you issue `aud`.
+ [ ] Null checks added where `expiry`, `issuedAt` or `payload` are read.
+ [ ] Verification is wrapped in `on JwtException`, and any code matching
      individual exception constants has been rechecked against the list above.
