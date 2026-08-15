import 'exception.dart';

/// Encodes and decodes JWT dates
class JwtDate {
  // A _NumericDate_ is how the 'iss', 'nbf' and 'exp' times are represented in
  // a JWT.
  //
  // A _NumericDate_ is specified in section 2 of RFC 7797
  // <https://tools.ietf.org/html/rfc7519#section-2> as the number of seconds
  // since 1970-01-01T00:00:00Z ignoring leap seconds.
  // Note: it could be an integer or non-integer number (i.e. doubles).
  //
  // **Leap seconds**
  //
  // Non-conformance: this implementation does not ignore leap seconds.
  // It uses the Dart DateTime value, which uses UTC or the local time of
  // the computer and should include leap seconds.
  //
  // In limited testing, it appears other implementations also simply use
  // their computer's clock. So for better interoperability, this implementation
  // does not attempt to ignore leap seconds. If this is a problem, the
  // validation of tokens can compensate for it by allowing for clock skew.
  // Alternatively, this implementation could be modified to subtract/add
  // the leap seconds when encoding/decoding a NumericDate.

  /// Converts an optional NumericDate into a DateTime.
  ///
  /// If the [value] is null, null is returned. Otherwise, the value (which
  /// could be an integer or double) is interpreted as a NumericDate and
  /// returned as a DateTime.
  ///
  /// If the value is a double, any milliseconds are included in the result.
  ///
  /// Throws [JwtException.invalidToken] if the value is not the correct type
  /// or is out of range.
  static DateTime? decode(dynamic value) {
    if (value == null) {
      // Absent
      return null;
    } else if (value is int) {
      // Integer
      if (value < 0 || _maxNumericDate < value) {
        throw JwtException.invalidToken; // negative or out of range
      }
      return DateTime.fromMillisecondsSinceEpoch(value * 1000, isUtc: true);
    } else if (value is double) {
      // Double
      //
      // Note: zero is permitted here, as it is for an integer. The two must
      // agree: a NumericDate of 0 is the same instant however it is written.
      if (!value.isFinite || value < 0.0 || _maxNumericDate < value) {
        throw JwtException.invalidToken; // NaN, infinity, negative, or too big
      }
      return DateTime.fromMillisecondsSinceEpoch((value * 1000).round(),
          isUtc: true);
    } else {
      throw JwtException.invalidToken; // not an integer, nor a double
    }
  }

  /// Largest NumericDate, in seconds, that can be represented as a [DateTime].
  ///
  /// The range must be checked _before_ converting seconds to milliseconds.
  /// The multiplication overflows a 64-bit integer for large values and wraps
  /// around, which silently turns an absurd date into a plausible one: without
  /// this check, a NumericDate of 18446744073709552 decodes to 384 milliseconds
  /// after the epoch rather than being rejected.
  ///
  /// The limit is [DateTime]'s own: 100,000,000 days either side of the epoch.
  static const int _maxNumericDate = 8640000000000000 ~/ 1000;

  /// Converts an optional DateTime to an integer NumericDate.
  ///
  /// Note: although NumericDate values can be doubles, but this implementation
  /// only returns an integer, ignoring any fractions of a second that might
  /// have been in the value. This is more portable, since non-conforming
  /// implementations might not expect non-integer values.
  static int encode(DateTime value) {
    value = value.toUtc();
    return value.millisecondsSinceEpoch ~/ 1000;
  }
}
