// Insecure Random Number Generation vulnerabilities in Dart

import 'dart:math';
import 'dart:convert';

// Test 1: Math.Random for security
String vulnerableMathRandom() {
  // VULNERABLE: Math.Random is not cryptographically secure
  var random = Random();
  return random.nextInt(1000000).toString().padLeft(6, '0');
}

// Test 2: Seeded with timestamp
String vulnerableTimestampSeed() {
  // VULNERABLE: Predictable seed
  var random = Random(DateTime.now().millisecondsSinceEpoch);
  return random.nextDouble().toString();
}

// Test 3: Static seed
String vulnerableStaticSeed() {
  // VULNERABLE: Same seed always
  var random = Random(42);
  return random.nextInt(1000000).toString();
}

// Test 4: Token from weak random
String vulnerableToken() {
  // VULNERABLE: Weak PRNG for token
  var random = Random();
  var chars = 'abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789';
  return List.generate(16, (_) => chars[random.nextInt(chars.length)]).join();
}

// Test 5: UUID-like with weak random
String vulnerableUuid() {
  // VULNERABLE: Weak random for UUID
  var random = Random();
  var bytes = List.generate(16, (_) => random.nextInt(256));
  return bytes.map((b) => b.toRadixString(16).padLeft(2, '0')).join();
}

// Test 6: Password generation with weak random
String vulnerablePassword() {
  // VULNERABLE: Password from weak PRNG
  var random = Random();
  var chars = 'abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789!@#\$%';
  return List.generate(12, (_) => chars[random.nextInt(chars.length)]).join();
}

// Test 7: OTP generation with weak random
String vulnerableOtp() {
  // VULNERABLE: OTP from weak PRNG
  var random = Random();
  return random.nextInt(1000000).toString().padLeft(6, '0');
}

// Test 8: Session ID with weak random
String vulnerableSessionId() {
  // VULNERABLE: Session ID from weak PRNG
  var random = Random();
  var bytes = List.generate(32, (_) => random.nextInt(256));
  return base64Encode(bytes);
}

// Test 9: Nonce with weak random
String vulnerableNonce() {
  // VULNERABLE: Nonce should be cryptographically random
  var random = Random();
  return random.nextInt(1 << 32).toRadixString(16);
}

// Test 10: IV generation with weak random
List<int> vulnerableIv() {
  // VULNERABLE: IV from weak PRNG
  var random = Random();
  return List.generate(16, (_) => random.nextInt(256));
}

// Test 11: Salt generation with weak random
List<int> vulnerableSalt() {
  // VULNERABLE: Salt from weak PRNG
  var random = Random();
  return List.generate(16, (_) => random.nextInt(256));
}

// Test 12: Shuffle with weak random
List<T> vulnerableShuffle<T>(List<T> list) {
  // VULNERABLE: Shuffle with weak PRNG
  var random = Random();
  var shuffled = List<T>.from(list);
  shuffled.shuffle(random);
  return shuffled;
}

// Test 13: Random selection with weak random
T vulnerableRandomSelect<T>(List<T> options) {
  // VULNERABLE: Selection with weak PRNG
  var random = Random();
  return options[random.nextInt(options.length)];
}

// Test 14: Verification code with weak random
String vulnerableVerificationCode() {
  // VULNERABLE: Verification code from weak PRNG
  var random = Random();
  return random.nextInt(10000).toString().padLeft(4, '0');
}

// Test 15: API key generation with weak random
String vulnerableApiKey() {
  // VULNERABLE: API key from weak PRNG
  var random = Random();
  var bytes = List.generate(24, (_) => random.nextInt(256));
  return base64Encode(bytes).replaceAll(RegExp(r'[+/=]'), '');
}

// SAFE: Using Random.secure()
String safeSecureRandom() {
  // SAFE: Cryptographically secure random
  var random = Random.secure();
  var bytes = List.generate(32, (_) => random.nextInt(256));
  return base64Encode(bytes);
}
