// Copyright (c) 2016, 2019, Ravi Teja Gudapati. All rights reserved.
//
// Use of this source code is governed by a BSD-style license that can be found
// in the LICENSE file.

library jaguar_jwt.src;

import 'dart:collection';
import 'dart:convert';

import 'package:crypto/crypto.dart';
import 'package:jaguar_jwt/src/secure_compare.dart';

import 'b64url_rfc7515.dart';
import 'claim.dart';
import 'exception.dart';

/// Issues a HMAC SHA-256 signed JWT.
///
/// Creates a JWT using the [claimSet] for the payload and signing it using
/// the [hmacKey] with the HMAC SHA-256 algorithm.
///
/// The [hmacKey] is converted to key bytes using UTF-8, which is what other
/// JWT implementations do with a shared secret expressed as text. A key that
/// is a sequence of bytes rather than text should be passed to
/// [issueJwtHS256Bytes] instead of being squeezed through a String.
///
/// Throws a [JsonUnsupportedObjectError] if any of the Claim Values are not
/// suitable for a JWT.
///
///     final claimSet = JwtClaim(
///       subject: 'kleak',
///       issuer: 'teja',
///       audience: <String>['example.com', 'hello.com'],
///       payload: {'k': 'v'});
///       String token = issueJwtHS256(claimSet, key);
///       print(token);
String issueJwtHS256(JwtClaim claimSet, String hmacKey) =>
    issueJwtHS256Bytes(claimSet, utf8.encode(hmacKey));

/// Issues a HMAC SHA-256 signed JWT, using a key of raw bytes.
///
/// Identical to [issueJwtHS256], except the signing key is provided as bytes.
/// Use this when the shared secret is binary key material (for example, one
/// that was decoded from Base64 or hex) rather than text.
///
/// Throws a [JsonUnsupportedObjectError] if any of the Claim Values are not
/// suitable for a JWT.
String issueJwtHS256Bytes(JwtClaim claimSet, List<int> hmacKey) {
  final hmac = Hmac(sha256, hmacKey);

  // Use SplayTreeMap to ensure ordering in JSON: i.e. alg before typ.
  // Ordering is not required for JWT: it is deterministic and neater.
  final header = SplayTreeMap<String, String>.from(
      <String, String>{'alg': 'HS256', 'typ': 'JWT'});

  final String encHdr = B64urlEncRfc7515.encodeUtf8(json.encode(header));
  final String encPld =
      B64urlEncRfc7515.encodeUtf8(json.encode(claimSet.toJson()));
  final String data = '${encHdr}.${encPld}';
  // The signing input is Base64url Encoding and a period, so it is all ASCII:
  // encoding it as UTF-8 reproduces those characters exactly.
  final String encSig =
      B64urlEncRfc7515.encode(hmac.convert(utf8.encode(data)).bytes);
  return data + '.' + encSig;
}

/// Header checking function type used by [verifyJwtHS256Signature].
typedef JOSEHeaderCheck = bool Function(Map<String, dynamic> joseHeader);

/// Default JOSE Header checker.
///
/// Returns true (header is ok) if the 'typ' Header Parameter is absent, or it
/// is present with the exact value of 'JWT'. Otherwise, false (header is
/// rejected).
///
/// This implementation allows [verifyJwtHS256Signature] to exactly replicate
/// its previous behaviour.
///
/// Note: this check is more restrictive than what RFC 7519 requires, since the
/// value of 'JWT' is only a recommendation and it is supposed to be case
/// insensitive. See <https://tools.ietf.org/html/rfc7519#section-5.1>
///
/// Note: [verifyJwtHS256Signature] checks the 'alg' Header Parameter, and
/// rejects headers with a 'crit' or 'b64' Header Parameter, before invoking any
/// header check. A replacement for this function does not need to check for
/// them, and cannot accept them.
bool defaultJWTHeaderCheck(Map<String, dynamic> h) {
  if (!h.containsKey('typ')) {
    return true;
  }

  final dynamic typ = h['typ'];
  return typ == 'JWT';
}

/// Verifies the signature and extracts the claim set from a JWT.
///
/// The signature is verified using the [hmacKey] with the HMAC SHA-256
/// algorithm.
///
/// The [hmacKey] is converted to key bytes using UTF-8, which is what other
/// JWT implementations do with a shared secret expressed as text. A key that
/// is a sequence of bytes rather than text should be passed to
/// [verifyJwtHS256SignatureBytes] instead of being squeezed through a String.
///
/// The token is always verified with HMAC SHA-256, regardless of what its
/// header says. A header whose 'alg' Header Parameter is absent, or is anything
/// other than 'HS256', is rejected with [JwtException.algorithmMismatch]: the
/// algorithm is pinned by the choice of this function, and 'alg' is only an
/// assertion to be checked against it. A verifier that instead selected its
/// algorithm from the header would let an attacker choose how their own token
/// is checked, which is the classic way these libraries are broken.
///
/// The [headerCheck] is an optional function to check the header.
/// It defaults to [defaultJWTHeaderCheck].
///
/// The 'alg' check runs before the [headerCheck] and cannot be disabled by it.
///
/// Regardless of the [headerCheck], a header with a 'crit' Header Parameter is
/// rejected with [JwtException.unsupportedHeaderExtension], as required by
/// section 4.1.11 of [RFC 7515](https://tools.ietf.org/html/rfc7515): this
/// implementation understands no header extensions, and a token marking one as
/// critical must not be processed as if the extension were absent. Requesting
/// unencoded payloads with 'b64' (RFC 7797) is rejected for the same reason.
///
/// The returned claim set contains exactly the claims that were in the token.
/// In particular, if the token has no _Issued At Claim_ and/or no _Expiration
/// Time Claim_, the returned claim set will not have them either.
///
/// Setting [defaultIatExp] to true restores the legacy behaviour of assigning
/// default values to those two claims when they are absent from the token
/// (see the constructor [JwtClaim] for what defaults are used and how [maxAge]
/// is used). **This is dangerous and is not recommended.** A fabricated
/// _Expiration Time Claim_ is always in the future, so validating the claim set
/// can never detect that the token itself has no expiry: such a token is
/// effectively immortal, while appearing to expire. To reject tokens that do
/// not expire, leave [defaultIatExp] false and validate with
/// `requireExpiry: true`.
///
/// Throws a [JwtException] if the signature does not verify or the
/// JWT is invalid.
///
///     final decClaimSet = verifyJwtHS256Signature(token, key);
///     print(decClaimSet);
JwtClaim verifyJwtHS256Signature(String token, String hmacKey,
        {JOSEHeaderCheck? headerCheck = defaultJWTHeaderCheck,
        bool defaultIatExp = false,
        Duration maxAge = JwtClaim.defaultMaxAge}) =>
    verifyJwtHS256SignatureBytes(token, utf8.encode(hmacKey),
        headerCheck: headerCheck, defaultIatExp: defaultIatExp, maxAge: maxAge);

/// Verifies the signature and extracts the claim set from a JWT, using a key
/// of raw bytes.
///
/// Identical to [verifyJwtHS256Signature], except the verification key is
/// provided as bytes. Use this when the shared secret is binary key material
/// (for example, one that was decoded from Base64 or hex) rather than text.
///
/// Throws a [JwtException] if the signature does not verify or the
/// JWT is invalid.
JwtClaim verifyJwtHS256SignatureBytes(String token, List<int> hmacKey,
    {JOSEHeaderCheck? headerCheck = defaultJWTHeaderCheck,
    bool defaultIatExp = false,
    Duration maxAge = JwtClaim.defaultMaxAge}) {
  try {
    final hmac = Hmac(sha256, hmacKey);

    final parts = token.split('.');
    if (parts.length != 3) {
      throw JwtException.invalidToken;
    }

    // Decode header and payload
    final headerString = B64urlEncRfc7515.decodeUtf8(parts[0]);
    // Check header
    final dynamic header = json.decode(headerString);
    if (header is Map) {
      // Reject extensions that change how the JWS must be processed.
      //
      // This is done before the custom headerCheck, and cannot be disabled by
      // it: understanding one of these extensions requires processing the token
      // differently, which a header check has no way to do.

      // RFC 7515 section 4.1.11 requires a recipient to reject a JWS carrying
      // a 'crit' Header Parameter listing extensions it does not understand.
      // This implementation understands none, so any 'crit' is rejected.
      if (header.containsKey('crit')) {
        throw JwtException.unsupportedHeaderExtension;
      }

      // RFC 7797 'b64': when false, the payload is not Base64url encoded and
      // the signing input is computed differently. Conforming producers must
      // also list it in 'crit' (rejected above), but reject it here too so a
      // non-conforming token cannot be interpreted differently to how its
      // issuer intended.
      if (header.containsKey('b64') && header['b64'] != true) {
        throw JwtException.unsupportedHeaderExtension;
      }

      // The signing algorithm is fixed by this function: the HMAC above is
      // already built around SHA-256, whatever the token says. So 'alg' is an
      // assertion to be checked against what this code will actually do, never
      // an input that selects it -- selecting on 'alg' is how a verifier is
      // talked into checking an RS256 token's signature with the public key as
      // an HMAC secret, or into accepting 'none'.
      //
      // Checked here, with the other header parameters that decide whether the
      // token can be processed at all, and before the caller's headerCheck. A
      // header check can only reject a token, so it could never weaken this;
      // but the pinning should not read as though a callback participates in
      // it.
      if (header['alg'] != 'HS256') {
        throw JwtException.algorithmMismatch;
      }

      // Perform any custom checks on the header
      if (headerCheck != null && !headerCheck(header.cast<String, dynamic>())) {
        throw JwtException.invalidToken;
      }
    } else {
      throw JwtException.headerNotJson;
    }

    // Verify signature: calculate signature and compare to token's signature
    final data = '${parts[0]}.${parts[1]}';
    // As when signing: the signing input is all ASCII, so UTF-8 reproduces it.
    final calcSig = hmac.convert(utf8.encode(data)).bytes;
    final tokenSig = B64urlEncRfc7515.decode(parts[2]);
    // Signature does not match calculated
    if (!secureCompareIntList(calcSig, tokenSig))
      throw JwtException.hashMismatch;

    // Convert payload into a claim set
    final payloadString = B64urlEncRfc7515.decodeUtf8(parts[1]);
    final dynamic payload = json.decode(payloadString);
    if (payload is Map) {
      return JwtClaim.fromMap(payload.cast(),
          defaultIatExp: defaultIatExp, maxAge: maxAge);
    } else {
      throw JwtException.payloadNotJson; // is JSON, but not a JSON object
    }
  } on FormatException {
    // Can be caused by:
    //   - header or payload parts are not Base64url Encoding
    //   - bytes in the header or payload are not proper UTF-8
    //   - string in header or payload cannot be parsed into JSON
    throw JwtException.invalidToken;
  }
}
