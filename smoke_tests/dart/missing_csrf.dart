// Missing CSRF Protection vulnerabilities in Dart

import 'dart:io';
import 'dart:convert';

// Test 1: State-changing GET request
Future<void> vulnerableGetStateChange(HttpRequest request) async {
  // VULNERABLE: GET request that changes state
  if (request.method == 'GET') {
    var userId = request.uri.queryParameters['user_id'];
    var action = request.uri.queryParameters['action'];
    if (action == 'delete') {
      await deleteUser(userId!);
    }
  }
}

// Test 2: POST without CSRF token
Future<void> vulnerablePostNoCsrf(HttpRequest request) async {
  // VULNERABLE: No CSRF token validation
  if (request.method == 'POST') {
    var body = await utf8.decoder.bind(request).join();
    var data = jsonDecode(body);
    await updateUserProfile(data);
  }
}

// Test 3: Form submission without token
String vulnerableFormNoToken() {
  // VULNERABLE: Form without CSRF token
  return '''
    <form action="/api/transfer" method="POST">
      <input name="amount" type="text">
      <input name="to_account" type="text">
      <button type="submit">Transfer</button>
    </form>
  ''';
}

// Test 4: AJAX without CSRF header
Future<void> vulnerableAjaxNoCsrf(HttpRequest request) async {
  // VULNERABLE: Not checking for CSRF token in AJAX requests
  if (request.method == 'POST') {
    // No X-CSRF-Token header check
    var body = await utf8.decoder.bind(request).join();
    await processTransaction(jsonDecode(body));
  }
}

// Test 5: Token in URL (exposed in logs/history)
String vulnerableTokenInUrl(String csrfToken) {
  // VULNERABLE: CSRF token in URL
  return '''
    <form action="/api/action?csrf_token=$csrfToken" method="POST">
      <button type="submit">Submit</button>
    </form>
  ''';
}

// Test 6: Predictable CSRF token
String vulnerablePredictableToken() {
  // VULNERABLE: Predictable token
  var token = DateTime.now().millisecondsSinceEpoch.toString();
  return token;
}

// Test 7: CSRF token not tied to session
class VulnerableTokenManager {
  static final Map<String, String> tokens = {};

  // VULNERABLE: Global token not tied to user session
  static String generateToken() {
    var token = 'csrf_${DateTime.now().millisecondsSinceEpoch}';
    tokens['global'] = token;
    return token;
  }

  static bool validateToken(String token) {
    return tokens['global'] == token;
  }
}

// Test 8: Token reuse allowed
class VulnerableTokenReuse {
  final Set<String> usedTokens = {};

  // VULNERABLE: Token can be used multiple times
  bool validateToken(String token, String expectedToken) {
    return token == expectedToken;
    // Should invalidate after use
  }
}

// Test 9: Weak token validation
Future<void> vulnerableWeakValidation(HttpRequest request) async {
  // VULNERABLE: Only checking token presence, not value
  var token = request.headers.value('X-CSRF-Token');
  if (token != null && token.isNotEmpty) {
    // Should validate against session token
    await processRequest(request);
  }
}

// Test 10: Cookie-based token without double submit
void vulnerableCookieOnlyToken(HttpResponse response, String token) {
  // VULNERABLE: Token only in cookie, not in form
  response.cookies.add(Cookie('csrf_token', token));
  // Should also be submitted in form/header
}

// Test 11: JSON API without CSRF check
Future<void> vulnerableJsonApiNoCsrf(HttpRequest request) async {
  // VULNERABLE: JSON APIs still need CSRF protection
  if (request.headers.contentType?.mimeType == 'application/json') {
    var body = await utf8.decoder.bind(request).join();
    var data = jsonDecode(body);
    await executeAction(data);
  }
}

// Test 12: Logout without CSRF
Future<void> vulnerableLogoutNoCsrf(HttpRequest request, HttpResponse response) async {
  // VULNERABLE: Logout should be protected against CSRF
  if (request.method == 'GET' || request.method == 'POST') {
    await invalidateSession(request);
    response.redirect(Uri.parse('/'));
  }
}

// Test 13: Password change without CSRF
Future<void> vulnerablePasswordChangeNoCsrf(HttpRequest request) async {
  // VULNERABLE: Critical action without CSRF
  if (request.method == 'POST') {
    var body = await utf8.decoder.bind(request).join();
    var data = jsonDecode(body);
    await changePassword(data['user_id'], data['new_password']);
  }
}

// Test 14: File upload without CSRF
Future<void> vulnerableFileUploadNoCsrf(HttpRequest request) async {
  // VULNERABLE: File upload without CSRF protection
  if (request.method == 'POST') {
    var boundary = request.headers.contentType?.parameters['boundary'];
    // Process multipart without CSRF validation
    await processUpload(request, boundary!);
  }
}

// Test 15: CORS misconfiguration enabling CSRF
void vulnerableCorsEnablesCsrf(HttpResponse response) {
  // VULNERABLE: CORS settings that enable cross-origin CSRF
  response.headers.add('Access-Control-Allow-Origin', '*');
  response.headers.add('Access-Control-Allow-Methods', 'POST, PUT, DELETE');
  response.headers.add('Access-Control-Allow-Headers', 'Content-Type');
}

// Helper functions
Future<void> deleteUser(String userId) async {}
Future<void> updateUserProfile(Map<String, dynamic> data) async {}
Future<void> processTransaction(Map<String, dynamic> data) async {}
Future<void> processRequest(HttpRequest request) async {}
Future<void> executeAction(Map<String, dynamic> data) async {}
Future<void> invalidateSession(HttpRequest request) async {}
Future<void> changePassword(String userId, String newPassword) async {}
Future<void> processUpload(HttpRequest request, String boundary) async {}
