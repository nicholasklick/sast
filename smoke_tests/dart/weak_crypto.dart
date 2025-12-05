// Weak Cryptography vulnerabilities in Dart

import 'dart:convert';
import 'dart:math';
import 'package:crypto/crypto.dart';

// Test 1: MD5 for password hashing
String vulnerableMd5Password(String password) {
  // VULNERABLE: MD5 is weak for passwords
  return md5.convert(utf8.encode(password)).toString();
}

// Test 2: SHA1 for security purposes
String vulnerableSha1(String data) {
  // VULNERABLE: SHA1 is deprecated
  return sha1.convert(utf8.encode(data)).toString();
}

// Test 3: Weak random number generation
String vulnerableRandom() {
  // VULNERABLE: Math.Random is not cryptographically secure
  var random = Random();
  var token = List.generate(16, (_) => random.nextInt(256));
  return base64Encode(token);
}

// Test 4: Predictable seed
String vulnerablePredictableSeed() {
  // VULNERABLE: Predictable seed
  var random = Random(DateTime.now().millisecondsSinceEpoch);
  return random.nextInt(1000000).toString();
}

// Test 5: Short key generation
String vulnerableShortKey() {
  // VULNERABLE: Key too short
  var random = Random.secure();
  var key = List.generate(8, (_) => random.nextInt(256)); // Only 64 bits
  return base64Encode(key);
}

// Test 6: Hardcoded IV
List<int> vulnerableHardcodedIv() {
  // VULNERABLE: Hardcoded IV
  return [0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15];
}

// Test 7: Static IV for all encryptions
class WeakEncryption {
  // VULNERABLE: Same IV for all encryptions
  static final List<int> iv = List.filled(16, 0);

  static List<int> encrypt(List<int> data, List<int> key) {
    // Using static IV
    return data; // Simplified
  }
}

// Test 8: Weak key derivation
String vulnerableKeyDerivation(String password) {
  // VULNERABLE: Simple hash for key derivation
  return md5.convert(utf8.encode(password)).toString();
}

// Test 9: Base64 as encryption
String vulnerableBase64Encoding(String secret) {
  // VULNERABLE: Base64 is encoding, not encryption
  return base64Encode(utf8.encode(secret));
}

// Test 10: XOR cipher
String vulnerableXorCipher(String data, String key) {
  // VULNERABLE: XOR cipher is weak
  var result = <int>[];
  for (var i = 0; i < data.length; i++) {
    result.add(data.codeUnitAt(i) ^ key.codeUnitAt(i % key.length));
  }
  return String.fromCharCodes(result);
}

// Test 11: Timestamp-based token
String vulnerableTimestampToken() {
  // VULNERABLE: Predictable token
  return DateTime.now().millisecondsSinceEpoch.toString();
}

// Test 12: Sequential ID as secret
String vulnerableSequentialId(int lastId) {
  // VULNERABLE: Predictable sequential ID
  return 'TOKEN-${lastId + 1}';
}

// Test 13: Weak password hash comparison
bool vulnerableHashComparison(String inputHash, String storedHash) {
  // VULNERABLE: Non-constant-time comparison (timing attack)
  return inputHash == storedHash;
}

// Test 14: MD5 for file integrity
String vulnerableFileMd5(List<int> fileBytes) {
  // VULNERABLE: MD5 for integrity (collision attacks possible)
  return md5.convert(fileBytes).toString();
}

// Test 15: Weak session token
String vulnerableSessionToken(String username) {
  // VULNERABLE: Predictable session token
  var timestamp = DateTime.now().millisecondsSinceEpoch;
  return md5.convert(utf8.encode('$username:$timestamp')).toString();
}

// Test 16: ROT13 as encryption
String vulnerableRot13(String text) {
  // VULNERABLE: ROT13 is not encryption
  return text.split('').map((char) {
    var code = char.codeUnitAt(0);
    if (code >= 65 && code <= 90) {
      return String.fromCharCode((code - 65 + 13) % 26 + 65);
    } else if (code >= 97 && code <= 122) {
      return String.fromCharCode((code - 97 + 13) % 26 + 97);
    }
    return char;
  }).join();
}

// Test 17: Password in hash
String vulnerablePasswordInHash(String password) {
  // VULNERABLE: Password visible in output
  return 'hash_of_$password';
}

// Test 18: Insufficient iterations for PBKDF2
List<int> vulnerablePbkdf2(String password, List<int> salt) {
  // VULNERABLE: Too few iterations
  // In real code: Pbkdf2(hmacSha256, iterations: 100) - too few
  return utf8.encode(password);
}
