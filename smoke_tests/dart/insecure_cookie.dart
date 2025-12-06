// Insecure Cookie vulnerabilities in Dart

import 'dart:io';

// Test 1: Cookie without Secure flag
void vulnerableNoSecureFlag(HttpResponse response, String sessionId) {
  // VULNERABLE: Missing Secure flag
  response.headers.add('Set-Cookie', 'session=$sessionId; HttpOnly');
}

// Test 2: Cookie without HttpOnly flag
void vulnerableNoHttpOnly(HttpResponse response, String sessionId) {
  // VULNERABLE: Missing HttpOnly flag - vulnerable to XSS
  response.headers.add('Set-Cookie', 'session=$sessionId; Secure');
}

// Test 3: Cookie without SameSite attribute
void vulnerableNoSameSite(HttpResponse response, String sessionId) {
  // VULNERABLE: Missing SameSite - vulnerable to CSRF
  response.headers.add('Set-Cookie', 'session=$sessionId; Secure; HttpOnly');
}

// Test 4: SameSite=None without Secure
void vulnerableSameSiteNone(HttpResponse response, String sessionId) {
  // VULNERABLE: SameSite=None requires Secure flag
  response.headers.add('Set-Cookie', 'session=$sessionId; SameSite=None');
}

// Test 5: Sensitive data in cookie
void vulnerableSensitiveData(HttpResponse response, String username, String password) {
  // VULNERABLE: Storing credentials in cookies
  response.headers.add('Set-Cookie', 'user=$username');
  response.headers.add('Set-Cookie', 'pass=$password');
}

// Test 6: No expiration on sensitive cookie
void vulnerableNoExpiration(HttpResponse response, String token) {
  // VULNERABLE: Session cookie without expiration
  response.headers.add('Set-Cookie', 'auth_token=$token; Secure; HttpOnly');
}

// Test 7: Overly long expiration
void vulnerableLongExpiration(HttpResponse response, String sessionId) {
  // VULNERABLE: Cookie valid for 1 year
  var expiry = DateTime.now().add(Duration(days: 365));
  response.headers.add('Set-Cookie',
    'session=$sessionId; Expires=${HttpDate.format(expiry)}; Secure; HttpOnly');
}

// Test 8: Cookie with broad path
void vulnerableBroadPath(HttpResponse response, String sessionId) {
  // VULNERABLE: Cookie available to entire domain
  response.headers.add('Set-Cookie', 'session=$sessionId; Path=/; Secure; HttpOnly');
}

// Test 9: Cookie with broad domain
void vulnerableBroadDomain(HttpResponse response, String sessionId) {
  // VULNERABLE: Cookie shared across subdomains
  response.headers.add('Set-Cookie',
    'session=$sessionId; Domain=.example.com; Secure; HttpOnly');
}

// Test 10: Predictable session ID
void vulnerablePredictableSession(HttpResponse response) {
  // VULNERABLE: Predictable session identifier
  var sessionId = DateTime.now().millisecondsSinceEpoch.toString();
  response.headers.add('Set-Cookie', 'session=$sessionId; Secure; HttpOnly');
}

// Test 11: Session fixation
void vulnerableSessionFixation(HttpRequest request, HttpResponse response) {
  // VULNERABLE: Not regenerating session after login
  var existingSession = request.cookies.firstWhere(
    (c) => c.name == 'session',
    orElse: () => Cookie('session', 'new'),
  );
  response.headers.add('Set-Cookie',
    'session=${existingSession.value}; Secure; HttpOnly');
}

// Test 12: Cookie over HTTP
void vulnerableCookieOverHttp(HttpResponse response, String token) {
  // VULNERABLE: Setting cookie that may be sent over HTTP
  response.headers.add('Set-Cookie', 'token=$token; HttpOnly');
}

// Test 13: Multiple cookies with mixed security
void vulnerableMixedSecurity(HttpResponse response, String sessionId, String prefs) {
  // VULNERABLE: Inconsistent cookie security
  response.headers.add('Set-Cookie', 'session=$sessionId; Secure; HttpOnly');
  response.headers.add('Set-Cookie', 'preferences=$prefs'); // No flags
}

// Test 14: Cookie value not encoded
void vulnerableUnencodedCookie(HttpResponse response, String userData) {
  // VULNERABLE: Cookie value should be URL encoded
  response.headers.add('Set-Cookie', 'user_data=$userData; Secure; HttpOnly');
}

// Test 15: JWT in cookie without proper flags
void vulnerableJwtCookie(HttpResponse response, String jwt) {
  // VULNERABLE: JWT cookie missing security attributes
  response.headers.add('Set-Cookie', 'jwt=$jwt');
}

// Test 16: Remember me token insecure
void vulnerableRememberMe(HttpResponse response, String token) {
  // VULNERABLE: Long-lived token without proper security
  var expiry = DateTime.now().add(Duration(days: 30));
  response.headers.add('Set-Cookie',
    'remember_me=$token; Expires=${HttpDate.format(expiry)}');
}

// Test 17: Cookie class without secure settings
void vulnerableCookieClass(HttpResponse response, String sessionId) {
  // VULNERABLE: Cookie object without security flags
  var cookie = Cookie('session', sessionId);
  response.cookies.add(cookie);
}

// Test 18: Clearing cookie improperly
void vulnerableClearCookie(HttpResponse response) {
  // VULNERABLE: Should set to empty with past expiry
  response.headers.add('Set-Cookie', 'session=; Path=/');
}
