# jaguar_jwt

JWT utilities for Dart.

This library can be used to generate and process JSON Web Tokens (JWT).
For more information about JSON Web Tokens, see
[RFC 7519](https://tools.ietf.org/html/rfc7519).

Currently, only the HMAC SHA-256 algorithm is supported to generate/process
a JSON Web Signature (JWS). Tokens signed with any other algorithm are
rejected, as are tokens whose header marks an extension critical (`crit`) or
requests an unencoded payload (`b64`), since neither is supported.

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
