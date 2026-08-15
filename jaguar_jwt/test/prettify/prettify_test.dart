library test.prettify;

import 'package:test/test.dart';
import 'package:jaguar_jwt/jaguar_jwt.dart';

void main() {
  group('Prettify', () {
    // JwtClaim.toString produces a display form of the claim set. Claim Values
    // come from a token, so they cannot be assumed to be well behaved.

    JwtClaim claimWith(Object? value) => JwtClaim(
        otherClaims: <String, dynamic>{'x': value}, defaultIatExp: false);

    test('A quote in a Claim Value is escaped', () {
      // Unescaped, this would look like the string had ended.
      expect(claimWith('a"b').toString(), contains(r'"a\"b"'));
    });

    test('A backslash in a Claim Value is escaped', () {
      expect(claimWith(r'a\b').toString(), contains(r'"a\\b"'));
    });

    test('A backslash before a quote is escaped once each', () {
      // The backslash must be escaped before the quote, otherwise the
      // backslash introduced by escaping the quote gets escaped in turn.
      expect(claimWith(r'a\"b').toString(), contains(r'"a\\\"b"'));
    });

    test('A newline in a Claim Value cannot break the display over lines', () {
      // A claim set is one entry when logged. A value containing a newline
      // must not be able to make part of itself look like a separate entry.
      final text = claimWith('real\nforged').toString();

      expect(text, contains(r'"real\nforged"'));
      expect(text, isNot(contains('\nforged')));
    });

    test('Carriage returns and tabs are escaped', () {
      expect(claimWith('a\rb\tc').toString(), contains(r'"a\rb\tc"'));
    });

    test('A Claim Name is escaped as well as a Claim Value', () {
      final claimSet = JwtClaim(
          otherClaims: <String, dynamic>{'we"ird': 'v'}, defaultIatExp: false);

      expect(claimSet.toString(), contains(r'"we\"ird"'));
    });

    test('Values nested in a Map or List are escaped', () {
      final claimSet = claimWith(<dynamic>[
        'a"b',
        <String, dynamic>{'k': 'c\nd'}
      ]);

      final text = claimSet.toString();

      expect(text, contains(r'"a\"b"'));
      expect(text, contains(r'"c\nd"'));
    });

    test('An ordinary Claim Value is left alone', () {
      expect(claimWith('plain value').toString(), contains('"plain value"'));
    });

    test('Registered claims appear in the output', () {
      final claimSet = JwtClaim(
          issuer: 'issuer.example.com',
          subject: 'subject-1',
          defaultIatExp: false);

      expect(claimSet.toString(), contains('"iss": "issuer.example.com"'));
      expect(claimSet.toString(), contains('"sub": "subject-1"'));
    });
  });
}
