library test.decoding;

import 'dart:convert';

import 'package:crypto/crypto.dart';
import 'package:test/test.dart';
import 'package:jaguar_jwt/jaguar_jwt.dart';

const String key = 'secret';

/// Creates a correctly signed JWT from an arbitrary JOSE header.
///
/// [issueJwtHS256] always produces a header of exactly 'alg' and 'typ', so
/// tests that need other Header Parameters have to assemble the token
/// themselves. The signature is genuine, so a token this produces is rejected
/// only because of its contents and never because it failed to verify.
String signWithHeader(
    Map<String, dynamic> header, Map<String, dynamic> payload, String hmacKey) {
  final encHdr = B64urlEncRfc7515.encodeUtf8(json.encode(header));
  final encPld = B64urlEncRfc7515.encodeUtf8(json.encode(payload));
  final data = '$encHdr.$encPld';
  final sig = B64urlEncRfc7515.encode(
      Hmac(sha256, hmacKey.codeUnits).convert(data.codeUnits).bytes);

  return '$data.$sig';
}

void main() {
  group('Decoding', () {
    // Test JWT decoding using pre-encoded JWT values.

    const secret = 's3cr3t';

    //----------------------------------------------------------------

    test('JWS example from RFC 7515', () {
      // Example token from Appendix A.1. of "JSON Web Signature (JWS)" RFC 7515
      // <https://tools.ietf.org/html/rfc7515#appendix-A.1>
      //
      // Payload is:
      //     {"iss":"joe",
      //      "exp":1300819380,
      //      "http://example.com/is_root":true}

      final token = 'eyJ0eXAiOiJKV1QiLA0KICJhbGciOiJIUzI1NiJ9'
          '.'
          'eyJpc3MiOiJqb2UiLA0KICJleHAiOjEzMDA4MTkzODAsDQogImh0dHA6Ly9leGFt'
          'cGxlLmNvbS9pc19yb290Ijp0cnVlfQ'
          '.'
          'dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk';

      final k = 'AyM1SysPpbyDfgZld3umj1qzKObwVMkoqQ-EstJQLr_T-1qS0gZH75'
          'aKtMN3Yj0iPS4hcgUuTwjAzZr1Z9CAow';

      final issuer = 'joe';
      final exp = DateTime.utc(2011, 03, 22, 18, 43); // 1300819380

      // Note: this secret is binary key material, not text. It has to be
      // supplied as bytes: a String cannot carry these bytes through UTF-8.
      final hmacKey = B64urlEncRfc7515.decode(k);

      // Verify signature

      final claimSet =
          verifyJwtHS256SignatureBytes(token, hmacKey, defaultIatExp: false);
      expect(claimSet, isNotNull);

      // Validate the claim set

      claimSet.validate(
          issuer: issuer,
          currentTime: exp.subtract(const Duration(seconds: 60)));
    });

    //----------------------------------------------------------------

    test('Malformed claims', () {
      // Tokens to test.
      //
      // Note: in the cases with an actual signature, that signature is correct.
      // So the tests do not fail because the signature is invalid, but fails
      // after signature verification when it tries to convert the payload into
      // a claim set.

      // TODO: create more test cases, simulating malicious JWTs
      // For example:
      // - iss is an integer (when it expects a string)
      // - sub is an array (when it expects a string)
      // - aud is an array of integers (when it expects an array of strings)
      // - exp is a string (when it expects a numeric)
      // - nbf is a negative integer (can NotBefore be before 1970?)

      const badTokens = {
        'token is an empty string': '',
        'token is a single character': '0',
        'token is a single period': '.',
        'token is two periods': '..',
        'token is three periods': '...',
        'token is missing signature part': '1234.5678',
        'token has too many parts': '1111.2222.3333.4444',
        'encoded payload is empty string':
            'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9..'
                'iE8S5laiOzOYJxr411Fw2HrI9I-n2F8MREyuXFwqCDo',
      };
      assert(badTokens.isNotEmpty);

      badTokens.forEach((desc, token) {
        expect(() => verifyJwtHS256Signature(token, secret),
            throwsA(equals(JwtException.invalidToken)),
            reason: 'test failed when $desc');
      });
    });

    //----------------------------------------------------------------

    test('No claims', () {
      // This JWT has no claims in its payload.
      //
      // The payload is the string "{}", which is a JSON object with no members.
      // So there are no claims, not even 'iss', 'aud', 'iat' or 'exp'.

      final token = 'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.'
          'e30.'
          'mwiDnq8rTFp5Oyy5i7pT8qktTB4tZOAfiJXTEbEqn2g';
      assert(B64urlEncRfc7515.decodeUtf8(token.split('.')[1]) == '{}');

      final claimSet =
          verifyJwtHS256Signature(token, secret, defaultIatExp: false);

      // No registered claims

      expect(claimSet.issuer, isNull);
      expect(claimSet.subject, isNull);
      expect(claimSet.audience, isNull);
      expect(claimSet.expiry, isNull);
      expect(claimSet.notBefore, isNull);
      expect(claimSet.issuedAt, isNull);
      expect(claimSet.jwtId, isNull);

      // There are no non-registered claims too

      final allClaimNames = claimSet.claimNames(includeRegisteredClaims: true);

      expect(allClaimNames.length, isZero);

      // containsKey and list accessor operator also reports there are no claims

      expect(claimSet.containsKey('iss'), isFalse);
      expect(claimSet['iss'], isNull);

      expect(claimSet.containsKey('aud'), isFalse);
      expect(claimSet['aud'], isNull);

      expect(claimSet.containsKey('noSuchClaim'), isFalse);
      expect(claimSet['noSuchClaim'], isNull);

      // The legacy payload getter reports the absent 'pld' claim as null,
      // rather than throwing on a cast of null to a Map.
      expect(claimSet.payload, isNull);
    });

    //----------------------------------------------------------------

    test('Example with two non-registered claims', () {
      // A more complicated JWT.
      //
      // {
      //   "iss": "https://issuer.example.com",
      //   "aud": [ "http://audience.example.com"],
      //   "iat": 1547519119,
      //   "nbf": 1547519119,
      //   "exp": 1547519239,
      //   "jti": "R4k4dsWcmS9pbpSmGHwCCeoh9RjGLfIg",
      //   "sub": "https://example.com!http://localhost:10000!000abcdefghijklmnopqrstuvwxyz",
      //   "https://aaf.edu.au/attributes": {
      //     "auedupersonsharedtoken": "ABCDEFGHIJKLMNOPQRSTUVWXYZ1",
      //     "cn": John Bigboote,
      //     "displayname": "John Bigboote",
      //     "edupersonorcid": "http://orcid.org/0000-0000-0000-0000",
      //     "edupersonprincipalname": jbigboote@example.com",
      //     "edupersonscopedaffiliation": staff@example.com",
      //     "edupersontargetedid": "https://example.com!http://localhost:10000!000abcdefghijklmnopqrstuvwxyz",
      //     "givenname": "John,
      //     "mail": "bigboote@example.com",
      //     "surname": "Bigboote"
      //     }
      // }

      final token = 'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.'
          'eyJhdWQiOlsiaHR0cDovL2F1ZGllbmNlLmV4YW1wbGUuY29tIl0sImV4cCI6MTU0'
          'NzUxOTIzOSwiaHR0cHM6Ly9hYWYuZWR1LmF1L2F0dHJpYnV0ZXMiOnsiYXVlZHVw'
          'ZXJzb25zaGFyZWR0b2tlbiI6IkFCQ0RFRkdISUpLTE1OT1BRUlNUVVZXWFlaMSIs'
          'ImNuIjoiSm9obiBCaWdib290ZSIsImRpc3BsYXluYW1lIjoiSm9obiBCaWdib290'
          'ZSIsImVkdXBlcnNvbm9yY2lkIjoiaHR0cDovL29yY2lkLm9yZy8wMDAwLTAwMDAt'
          'MDAwMC0wMDAwIiwiZWR1cGVyc29ucHJpbmNpcGFsbmFtZSI6ImpiaWdib290ZUBl'
          'eGFtcGxlLmNvbSIsImVkdXBlcnNvbnNjb3BlZGFmZmlsaWF0aW9uIjoic3RhZmZA'
          'ZXhhbXBsZS5jb20iLCJlZHVwZXJzb250YXJnZXRlZGlkIjoiaHR0cHM6Ly9leGFt'
          'cGxlLmNvbSFodHRwOi8vbG9jYWxob3N0OjEwMDAwITAwMGFiY2RlZmdoaWprbG1u'
          'b3BxcnN0dXZ3eHl6IiwiZ2l2ZW5uYW1lIjoiSm9obiIsIm1haWwiOiJiaWdib290'
          'ZUBleGFtcGxlLmNvbSIsInN1cm5hbWUiOiJCaWdib290ZSJ9LCJpYXQiOjE1NDc1'
          'MTkxMTksImlzcyI6Imh0dHBzOi8vaXNzdWVyLmV4YW1wbGUuY29tIiwianRpIjoi'
          'UjRrNGRzV2NtUzlwYnBTbUdId0NDZW9oOVJqR0xmSWciLCJuYmYiOjE1NDc1MTkx'
          'MTksInN1YiI6Imh0dHBzOi8vZXhhbXBsZS5jb20haHR0cDovL2xvY2FsaG9zdDox'
          'MDAwMCEwMDBhYmNkZWZnaGlqa2xtbm9wcXJzdHV2d3h5eiJ9.'
          'OlCUOj66oPagFoy0MOKvg5g86ts46mY6A2WhuVhi9c0';

      final issuer = 'https://issuer.example.com';
      final subject =
          'https://example.com!http://localhost:10000!000abcdefghijklmnopqrstuvwxyz';
      final audience = 'http://audience.example.com';
      final expiry = DateTime.utc(2019, 1, 15, 2, 27, 19);
      final notBefore = DateTime.utc(2019, 1, 15, 2, 25, 19);
      final issuedAt = DateTime.utc(2019, 1, 15, 2, 25, 19);
      final jwtId = 'R4k4dsWcmS9pbpSmGHwCCeoh9RjGLfIg';

      final secret = 's3cr3t';

      // Verify the signature

      final claimSet = verifyJwtHS256Signature(token, secret);
      expect(claimSet, isNotNull);

      // Validate the claim set

      claimSet.validate(
          issuer: issuer,
          audience: audience,
          currentTime: issuedAt.add(const Duration(seconds: 5)));

      // Check claim set has expected values

      expect(claimSet.subject, equals(subject));
      expect(claimSet.expiry, equals(expiry));
      expect(claimSet.notBefore, equals(notBefore));
      expect(claimSet.issuedAt, equals(issuedAt));
      expect(claimSet.jwtId, equals(jwtId));

      expect(claimSet['sub'], equals(subject));
      expect(claimSet['exp'], equals(expiry));
      expect(claimSet['nbf'], equals(notBefore));
      expect(claimSet['iat'], equals(issuedAt));
      expect(claimSet['jti'], equals(jwtId));

      expect(claimSet.containsKey('sub'), isTrue);
      expect(claimSet.containsKey('exp'), isTrue);
      expect(claimSet.containsKey('nbf'), isTrue);
      expect(claimSet.containsKey('iat'), isTrue);
      expect(claimSet.containsKey('jti'), isTrue);

      expect(claimSet.containsKey('no-such-claim'), isFalse);
      expect(claimSet.containsKey(''), isFalse);

      expect(claimSet['no-such-claim'], isNull);
      expect(claimSet[''], isNull);
    });

    //================================================================

    group('Time claims are not fabricated', () {
      // Verification must report exactly the claims that were in the token.
      // A fabricated Expiration Time Claim is always in the future, which
      // would make a token that never expires look like one that does.

      const secret = 's3cr3t';

      // Token whose payload is exactly '{"iss":"joe"}': no 'iat', no 'exp'.
      final tokenWithoutTimeClaims =
          issueJwtHS256(JwtClaim(issuer: 'joe', defaultIatExp: false), secret);

      test('Absent iat and exp stay absent', () {
        final claimSet =
            verifyJwtHS256Signature(tokenWithoutTimeClaims, secret);

        expect(claimSet.issuer, equals('joe'));
        expect(claimSet.expiry, isNull);
        expect(claimSet.issuedAt, isNull);
        expect(claimSet.containsKey('exp'), isFalse);
        expect(claimSet.containsKey('iat'), isFalse);
      });

      test('Re-encoding a decoded token does not add claims', () {
        final claimSet =
            verifyJwtHS256Signature(tokenWithoutTimeClaims, secret);

        expect(issueJwtHS256(claimSet, secret), equals(tokenWithoutTimeClaims));
      });

      test('Present iat and exp are preserved', () {
        final issuedAt = DateTime.utc(2019, 1, 15, 2, 25, 19);
        final expiry = DateTime.utc(2019, 1, 15, 2, 27, 19);

        final token = issueJwtHS256(
            JwtClaim(issuer: 'joe', issuedAt: issuedAt, expiry: expiry),
            secret);

        final claimSet = verifyJwtHS256Signature(token, secret);

        expect(claimSet.issuedAt, equals(issuedAt));
        expect(claimSet.expiry, equals(expiry));
      });

      test('Legacy defaultIatExp: true still fabricates them', () {
        final claimSet = verifyJwtHS256Signature(tokenWithoutTimeClaims, secret,
            defaultIatExp: true);

        expect(claimSet.expiry, isNotNull);
        expect(claimSet.issuedAt, isNotNull);
      });
    });

    //================================================================

    group('NumericDate values', () {
      // Time claims arrive as a NumericDate: seconds since the epoch, as an
      // integer or a double (RFC 7519 section 2).

      JwtClaim decodeExp(Object? exp) =>
          JwtClaim.fromMap(<dynamic, dynamic>{'iss': 'joe', 'exp': exp},
              defaultIatExp: false);

      test('The epoch is accepted as an integer and as a double', () {
        // Zero is a valid NumericDate. The two spellings are the same instant,
        // so accepting one and rejecting the other would be arbitrary.
        final epoch = DateTime.fromMillisecondsSinceEpoch(0, isUtc: true);

        expect(decodeExp(0).expiry, equals(epoch));
        expect(decodeExp(0.0).expiry, equals(epoch));
      });

      test('A double keeps its fraction of a second', () {
        expect(decodeExp(1.5).expiry,
            equals(DateTime.fromMillisecondsSinceEpoch(1500, isUtc: true)));
      });

      test('Values too large for a DateTime are rejected', () {
        // Not merely out of range: seconds are multiplied by 1000, and that
        // product overflows a 64-bit integer and wraps around. Unchecked,
        // 18446744073709552 decoded to 384 milliseconds after the epoch.
        for (final tooBig in <dynamic>[
          18446744073709552,
          18446744073709551,
          36893488147419103,
          9000000000000000000,
          1000000000000000,
          1e30,
        ]) {
          expect(() => decodeExp(tooBig),
              throwsA(equals(JwtException.invalidToken)),
              reason: 'should have rejected $tooBig');
        }
      });

      test('The largest representable NumericDate is still accepted', () {
        const maxSeconds = 8640000000000000 ~/ 1000;

        expect(decodeExp(maxSeconds).expiry, isNotNull);
      });

      test('Malformed values are rejected as invalid tokens', () {
        // Every rejection must be a JwtException: callers are documented to
        // catch that, so anything else escapes their error handling.
        for (final bad in <dynamic>[
          -1,
          -1.0,
          double.nan,
          double.infinity,
          double.negativeInfinity,
          '123',
          true,
          <int>[1],
        ]) {
          expect(
              () => decodeExp(bad), throwsA(equals(JwtException.invalidToken)),
              reason: 'should have rejected $bad');
        }
      });

      test('An out of range value in a real token throws JwtException', () {
        // End to end, through the documented catch-JwtException path.
        final token = signWithHeader(
            <String, dynamic>{'alg': 'HS256', 'typ': 'JWT'},
            <String, dynamic>{'iss': 'joe', 'exp': 18446744073709552},
            secret);

        expect(() => verifyJwtHS256Signature(token, secret),
            throwsA(isA<JwtException>()));
      });
    });

    //================================================================

    group('Header extensions', () {
      // A JWS whose header marks an extension critical must not be processed
      // as though the extension were absent. This implementation understands
      // no extensions, so it has to reject them all.

      const secret = 's3cr3t';
      const payload = <String, dynamic>{'iss': 'joe'};
      const baseHeader = <String, dynamic>{'alg': 'HS256', 'typ': 'JWT'};

      test('Control: the same token without extensions verifies', () {
        // Establishes that signWithHeader produces genuinely valid tokens, so
        // the rejections below cannot be signature failures in disguise.
        final token = signWithHeader(baseHeader, payload, secret);

        expect(verifyJwtHS256Signature(token, secret).issuer, equals('joe'));
      });

      test('Header with crit is rejected', () {
        final token = signWithHeader(<String, dynamic>{
          ...baseHeader,
          'crit': <String>['exp']
        }, payload, secret);

        expect(() => verifyJwtHS256Signature(token, secret),
            throwsA(equals(JwtException.unsupportedHeaderExtension)));
      });

      test('Header with an empty crit list is rejected', () {
        // RFC 7515 forbids producing this, so it is malformed either way.
        final token = signWithHeader(
            <String, dynamic>{...baseHeader, 'crit': <String>[]},
            payload,
            secret);

        expect(() => verifyJwtHS256Signature(token, secret),
            throwsA(equals(JwtException.unsupportedHeaderExtension)));
      });

      test('crit cannot be waved through by a permissive headerCheck', () {
        // Understanding an extension means processing the token differently,
        // which a header check cannot do. So it must not be able to accept one.
        final token = signWithHeader(<String, dynamic>{
          ...baseHeader,
          'crit': <String>['exp']
        }, payload, secret);

        expect(
            () => verifyJwtHS256Signature(token, secret,
                headerCheck: (h) => true),
            throwsA(equals(JwtException.unsupportedHeaderExtension)));

        expect(() => verifyJwtHS256Signature(token, secret, headerCheck: null),
            throwsA(equals(JwtException.unsupportedHeaderExtension)));
      });

      test('Header requesting an unencoded payload (b64 false) is rejected',
          () {
        final token = signWithHeader(
            <String, dynamic>{...baseHeader, 'b64': false}, payload, secret);

        expect(() => verifyJwtHS256Signature(token, secret),
            throwsA(equals(JwtException.unsupportedHeaderExtension)));
      });

      test('Header with b64 explicitly true is accepted', () {
        // True is the default behaviour, so there is nothing unsupported here.
        final token = signWithHeader(
            <String, dynamic>{...baseHeader, 'b64': true}, payload, secret);

        expect(verifyJwtHS256Signature(token, secret).issuer, equals('joe'));
      });

      test('Unrecognised but non-critical header parameters are accepted', () {
        // RFC 7515 section 4: a parameter that is not marked critical may be
        // ignored. Rejecting these would break interoperability.
        final token = signWithHeader(
            <String, dynamic>{...baseHeader, 'kid': 'key-1', 'cty': 'JWT'},
            payload,
            secret);

        expect(verifyJwtHS256Signature(token, secret).issuer, equals('joe'));
      });
    });

    //================================================================

    group('Signature', () {
      final claimSet = JwtClaim(
          subject: 'kleak',
          issuer: 'issuer.example.com',
          audience: <String>[
            'audience.example.com'
          ],
          otherClaims: <String, dynamic>{
            'pld': {'foo': 'bar'}
          });

      final correctSecret = 's3cr3t';
      final wrongSecret = 'S3cr3t'; // wrong case for first character
      final token = issueJwtHS256(claimSet, correctSecret);

      test('Correct secret verifies', () {
        expect(verifyJwtHS256Signature(token, correctSecret),
            const TypeMatcher<JwtClaim>());
      });

      test('Wrong secret does not verify', () {
        // Verifying with a different secret
        expect(() => verifyJwtHS256Signature(token, wrongSecret),
            throwsA(equals(JwtException.hashMismatch)));
      });

      test('Tampered header', () {
        // Tamper with the header so its checksum does not match the signature

        final parts = token.split('.');
        assert(parts.length == 3);

        const goodHeader = '{"alg":"HS256","typ":"JWT"}'; // control value

        // Make sure the generated JWT has the expected header, otherwise
        // tampering with the header might not produce the desired results.
        // Probably the only way the header could differ is that order of the
        // members is different (i.e. `{"typ":"JWT","alg":"HS256"}`) since
        // order is not significant in a JSON object.
        assert(B64urlEncRfc7515.decodeUtf8(parts[0]) == goodHeader,
            'assumption about generated JWT header is wrong');

        // Note: verifyJwtHS256Signature checks the header values before
        // checking the signature, so bad values in the header should produce
        // other exceptions before the signature verification fails
        // (i.e. can have other exceptions besides [JwtException.hashMismatch]).

        <String, JwtException?>{
          // Different alg
          '{"typ":"JWT"}': JwtException.hashMismatch, // algorithm missing
          '{"alg":"none","typ":"JWT"}': JwtException.hashMismatch, // not HS256

          // Different typ
          '{"alg":"HS256"}': JwtException.hashMismatch, // typ missing
          '{"alg":"HS256","typ":"badValue"}': JwtException.invalidToken,
          '{"alg":"HS256","typ":"jwt"}': JwtException.invalidToken, // case diff
          '{"alg":"HS256","typ":"Jwt"}': JwtException.invalidToken, // case diff
          '{"alg":"HS256","typ":"JWt"}': JwtException.invalidToken, // case diff
          // Note: In RFC 7519, "JWT" is only RECOMMENDED. Other values are OK.

          // Semantically same JSON, but the hash is different
          '{"typ":"JWT","alg":"HS256"}': JwtException.hashMismatch,
          '{"alg":"HS256","typ":"JWT" }': JwtException.hashMismatch,
          '{"alg":"HS256","typ":"JWT","a":"b"}': JwtException.hashMismatch,

          goodHeader: null, // control
        }.forEach((header, Exception? expectedException) {
          final newHead = B64urlEncRfc7515.encodeUtf8(header);
          final tamperedToken = [newHead, parts[1], parts[2]].join('.');

          if (expectedException != null) {
            expect(() => verifyJwtHS256Signature(tamperedToken, correctSecret),
                throwsA(equals(expectedException)),
                reason: 'test failed with header=$header');
          } else {
            // Control: check the tampering code did not mess up something else
            // and the above testing were succeeding because of a different
            // cause than the one being tested.
            try {
              expect(tamperedToken, equals(token));

              expect(verifyJwtHS256Signature(tamperedToken, correctSecret),
                  const TypeMatcher<JwtClaim>(),
                  reason: 'control case failed with header=$header');
            } on Exception catch (e) {
              fail('control case failed (header=$header): threw: $e');
            }
          }
        });
      });

      //----------------------------------------------------------------

      test('Tampered body', () {
        // Tamper with the body so its checksum does not match the signature

        final parts = token.split('.');
        assert(parts.length == 3);

        final body = B64urlEncRfc7515.decodeUtf8(parts[1]);
        final t = body.replaceAll('"pld":{"foo":"bar"}', '"pld":{"foo":"baz"}');
        expect(t, isNot(equals(body)),
            reason: 'expected substring was not in payload');

        final tamperedEncoding = B64urlEncRfc7515.encodeUtf8(t);
        expect(tamperedEncoding, isNot(equals(parts[1])),
            reason: 'tampering did not modify the encoded payload');

        final tamperedToken = [parts[0], tamperedEncoding, parts[2]].join('.');
        expect(tamperedToken, isNot(equals(token)),
            reason: 'tampering did not modify the JWT');

        expect(() => verifyJwtHS256Signature(tamperedToken, correctSecret),
            throwsA(equals(JwtException.hashMismatch)),
            reason: 'unexpected result when body was tampered with');
      });

      //----------------------------------------------------------------

      test('Tampered signature', () {
        // Tamper with the signature

        final parts = token.split('.');
        assert(parts.length == 3);

        // Try tampering with different bits in the signature

        for (var x = 0; x < 3; x++) {
          final sigBytes = B64urlEncRfc7515.decode(parts[2]);
          switch (x) {
            case 0:
              sigBytes[0] ^= 0x80; // flip MSB of first byte
              break;
            case 1:
              sigBytes[sigBytes.length - 1] ^= 0x01; // flip LSB of last byte
              break;
            case 2:
              sigBytes[8] ^= 0x18; // flip some other bits in the signature
              break;
            default:
              assert(false);
              break;
          }

          final tamperedSig = B64urlEncRfc7515.encode(sigBytes);
          expect(tamperedSig != parts[2], isTrue); // tampering did not change

          final tamperedToken = [parts[0], parts[1], tamperedSig].join('.');

          expect(() => verifyJwtHS256Signature(tamperedToken, correctSecret),
              throwsA(equals(JwtException.hashMismatch)),
              reason:
                  'signature valid even though signature was tampered with');
        }
      });
    });
  });
}
