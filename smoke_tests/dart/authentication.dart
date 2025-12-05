// Authentication vulnerabilities in Dart

import 'dart:convert';
import 'dart:io';
import 'package:crypto/crypto.dart';

// Test 1: Plaintext password comparison
bool vulnerablePlaintextCompare(String input, String stored) {
  // VULNERABLE: Comparing passwords in plaintext
  return input == stored;
}

// Test 2: MD5 password hash
String vulnerableMd5Password(String password) {
  // VULNERABLE: MD5 is weak for passwords
  return md5.convert(utf8.encode(password)).toString();
}

// Test 3: SHA1 password hash
String vulnerableSha1Password(String password) {
  // VULNERABLE: SHA1 is deprecated
  return sha1.convert(utf8.encode(password)).toString();
}

// Test 4: No salt in password hash
String vulnerableNoSalt(String password) {
  // VULNERABLE: No salt
  return sha256.convert(utf8.encode(password)).toString();
}

// Test 5: Hardcoded credentials check
bool vulnerableHardcodedCreds(String username, String password) {
  // VULNERABLE: Hardcoded credentials
  return username == 'admin' && password == 'password123';
}

// Test 6: Weak password validation
bool vulnerableWeakValidation(String password) {
  // VULNERABLE: Weak password requirements
  return password.length >= 4;
}

// Test 7: No rate limiting
int failedAttempts = 0;
bool vulnerableNoRateLimit(String username, String password) {
  // VULNERABLE: No rate limiting on login attempts
  failedAttempts++;
  return password == 'secret';
}

// Test 8: Password in URL
String vulnerablePasswordInUrl(String username, String password) {
  // VULNERABLE: Password in URL
  return 'https://api.example.com/login?user=$username&pass=$password';
}

// Test 9: Password logged
void vulnerablePasswordLogged(String username, String password) {
  // VULNERABLE: Password in logs
  print('Login attempt: $username with password $password');
}

// Test 10: Weak session token
String vulnerableSessionToken() {
  // VULNERABLE: Predictable session token
  return DateTime.now().millisecondsSinceEpoch.toString();
}

// Test 11: No session expiration
class VulnerableSession {
  String token;
  DateTime created;
  // VULNERABLE: No expiration

  VulnerableSession(this.token) : created = DateTime.now();

  bool isValid() {
    // No expiration check
    return token.isNotEmpty;
  }
}

// Test 12: Session fixation
String vulnerableSessionFixation(String existingToken) {
  // VULNERABLE: Not regenerating session after login
  return existingToken;
}

// Test 13: Cookie without secure flag
Map<String, String> vulnerableCookieNoSecure(String sessionId) {
  // VULNERABLE: Missing Secure flag
  return {
    'Set-Cookie': 'session=$sessionId; HttpOnly',
  };
}

// Test 14: Cookie without HttpOnly
Map<String, String> vulnerableCookieNoHttpOnly(String sessionId) {
  // VULNERABLE: Missing HttpOnly flag
  return {
    'Set-Cookie': 'session=$sessionId; Secure',
  };
}

// Test 15: Basic auth over HTTP
Future<void> vulnerableBasicAuthHttp(String username, String password) async {
  // VULNERABLE: Basic auth over HTTP
  var credentials = base64Encode(utf8.encode('$username:$password'));
  var client = HttpClient();
  var request = await client.getUrl(Uri.parse('http://api.example.com/data'));
  request.headers.add('Authorization', 'Basic $credentials');
}

// Test 16: Remember me token
String vulnerableRememberMe(String username) {
  // VULNERABLE: Weak remember me token
  return md5.convert(utf8.encode(username)).toString();
}

// Test 17: Password reset token
String vulnerableResetToken(String email) {
  // VULNERABLE: Predictable reset token
  return sha1.convert(utf8.encode('$email${DateTime.now()}')).toString();
}

// Test 18: No account lockout
class VulnerableAuth {
  // VULNERABLE: No lockout after failed attempts
  bool authenticate(String username, String password) {
    // Always allows retry
    return password == 'correct';
  }
}
