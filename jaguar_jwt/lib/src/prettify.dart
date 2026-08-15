import 'claim.dart';

/// Converts a JwtClaim into a multi-line String for display.
String prettify(JwtClaim claim) {
  final buf = StringBuffer('{\n');

  var hadPrev = false;
  for (String claimName in claim.claimNames(includeRegisteredClaims: true)) {
    if (hadPrev) buf.write(',\n');
    buf.write(_toStringIndent);
    _toStringDump(claimName, buf);
    buf.write(': ');
    _toStringDump(claim[claimName], buf, 1);
    hadPrev = true;
  }

  if (hadPrev) buf.write('\n');
  buf.write('}');

  return buf.toString();
}

const String _toStringIndent = '  ';

/// Escapes a String so it can be shown inside double quotes.
///
/// Claim Values come from a token, so they are not necessarily well behaved.
/// A value containing a quote would otherwise appear to close the string, and
/// one containing a newline would spread a claim set over lines that look like
/// separate log entries.
///
/// The backslash must be escaped first, so that the backslashes introduced by
/// the later replacements are not escaped a second time.
String _escape(String value) => value
    .replaceAll('\\', '\\\\')
    .replaceAll('"', '\\"')
    .replaceAll('\n', '\\n')
    .replaceAll('\r', '\\r')
    .replaceAll('\t', '\\t');

void _toStringDump(Object? value, StringBuffer buf, [int indent = 0]) {
  if (value is Iterable<dynamic>) {
    // Dump an Iterable
    buf.write('[\n');
    var hadPrev = false;
    for (var v in value) {
      if (hadPrev) {
        buf.write(',\n');
      }
      buf.write(_toStringIndent * (indent + 1));
      _toStringDump(v, buf, indent + 1);
      hadPrev = true;
    }
    if (hadPrev) {
      buf.write('\n');
    }
    buf
      ..write(_toStringIndent * (indent))
      ..write(']');
  } else if (value is Map) {
    // Dump a Map
    buf.write('{\n');
    var hadPrev = false;
    for (var k in value.keys) {
      if (hadPrev) {
        buf.write(',\n');
      }
      buf.write(_toStringIndent * (indent + 1));
      _toStringDump(k, buf, 0);
      buf.write(': ');
      _toStringDump(value[k], buf, indent + 1);
      hadPrev = true;
    }
    if (hadPrev) {
      buf.write('\n');
    }
    buf
      ..write(_toStringIndent * (indent))
      ..write('}');
  } else if (value is String) {
    // Dump a String value
    buf.write('"${_escape(value)}"');
  } else if (value is DateTime) {
    // Dump a DateTime value
    buf.write('<$value>');
    // buf.write('DateTime.parse("$value")');
  } else {
    // Dump some other
    buf.write(value);
  }
}
