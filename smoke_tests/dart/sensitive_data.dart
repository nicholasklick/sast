// Sensitive Data Exposure vulnerabilities in Dart

import 'dart:io';
import 'dart:convert';

// Test 1: Logging sensitive data
void vulnerableLogPassword(String username, String password) {
  // VULNERABLE: Password in logs
  print('Login attempt: $username / $password');
}

// Test 2: Credit card in logs
void vulnerableLogCreditCard(String cardNumber, String cvv) {
  // VULNERABLE: Credit card data in logs
  print('Processing payment: $cardNumber, CVV: $cvv');
}

// Test 3: API key in error message
void vulnerableApiKeyInError(String apiKey, Exception error) {
  // VULNERABLE: API key exposed in error
  throw Exception('API call failed with key $apiKey: $error');
}

// Test 4: Sensitive data in URL
String vulnerableSensitiveInUrl(String ssn) {
  // VULNERABLE: SSN in URL
  return 'https://api.example.com/verify?ssn=$ssn';
}

// Test 5: PII in response
Map<String, dynamic> vulnerablePiiInResponse(Map<String, dynamic> user) {
  // VULNERABLE: Returning sensitive fields
  return {
    'id': user['id'],
    'name': user['name'],
    'ssn': user['ssn'],
    'password_hash': user['password_hash'],
    'credit_card': user['credit_card'],
  };
}

// Test 6: Sensitive data in exception
void vulnerableSensitiveException(String token) {
  // VULNERABLE: Token in exception message
  throw StateError('Invalid authentication token: $token');
}

// Test 7: Debug mode exposing data
void vulnerableDebugMode(HttpRequest request, HttpResponse response, Object error) {
  // VULNERABLE: Full error details in production
  var debug = true;
  if (debug) {
    response.write(jsonEncode({
      'error': error.toString(),
      'stack': StackTrace.current.toString(),
      'request': {
        'headers': request.headers.toString(),
        'cookies': request.cookies.map((c) => '${c.name}=${c.value}').toList(),
      }
    }));
  }
}

// Test 8: Verbose error messages
void vulnerableVerboseError(HttpResponse response, String query, Exception e) {
  // VULNERABLE: SQL query in error response
  response.write('Database error executing: $query - ${e.toString()}');
}

// Test 9: Sensitive data in comments
class VulnerableComments {
  // Default admin password: admin123
  // API Key: sk_live_abc123xyz
  void authenticate() {}
}

// Test 10: Hardcoded test credentials
class VulnerableTestCreds {
  // VULNERABLE: Test credentials in code
  static const testUser = 'admin@example.com';
  static const testPassword = 'Password123!';
  static const testApiKey = 'test_api_key_12345';
}

// Test 11: Sensitive data in temp file
Future<void> vulnerableTempFile(String creditCard) async {
  // VULNERABLE: Sensitive data in temp file
  var tempFile = File('/tmp/payment_${DateTime.now().millisecondsSinceEpoch}.txt');
  await tempFile.writeAsString('Card: $creditCard');
}

// Test 12: Caching sensitive data
class VulnerableCache {
  static final Map<String, String> cache = {};

  // VULNERABLE: Caching sensitive data in memory
  static void cacheUserData(String id, String ssn, String password) {
    cache['user_$id'] = jsonEncode({'ssn': ssn, 'password': password});
  }
}

// Test 13: Sensitive data in analytics
void vulnerableAnalytics(String userId, String email, String ipAddress) {
  // VULNERABLE: PII in analytics
  analytics.track('user_login', {
    'user_id': userId,
    'email': email,
    'ip': ipAddress,
  });
}

// Test 14: Autocomplete on sensitive fields
String vulnerableAutocomplete() {
  // VULNERABLE: Autocomplete enabled on sensitive fields
  return '''
    <input type="text" name="ssn" autocomplete="on">
    <input type="password" name="password" autocomplete="on">
  ''';
}

// Test 15: Sensitive data in local storage
void vulnerableLocalStorage(String token) {
  // VULNERABLE: Token in local storage (web context)
  window.localStorage['auth_token'] = token;
}

// Test 16: Sensitive headers logged
void vulnerableLogHeaders(HttpRequest request) {
  // VULNERABLE: Logging authorization header
  print('Headers: ${request.headers}');
  print('Auth: ${request.headers.value("Authorization")}');
}

// Test 17: Returning stack trace to client
void vulnerableStackTrace(HttpResponse response, Exception e, StackTrace stack) {
  // VULNERABLE: Stack trace to client
  response.write(jsonEncode({
    'error': e.toString(),
    'trace': stack.toString(),
  }));
}

// Test 18: Sensitive data in form action
String vulnerableFormAction(String accountId) {
  // VULNERABLE: Account ID in form action URL
  return '<form action="/api/account/$accountId/update" method="POST">';
}

// Test 19: Session data exposure
void vulnerableSessionExposure(HttpResponse response, Map<String, dynamic> session) {
  // VULNERABLE: Full session data in response
  response.write(jsonEncode({'session': session}));
}

// Test 20: Backup with sensitive data
Future<void> vulnerableBackup(Map<String, dynamic> userData) async {
  // VULNERABLE: Unencrypted backup of sensitive data
  var backupFile = File('/backups/user_data.json');
  await backupFile.writeAsString(jsonEncode(userData));
}

// Mock classes
class Analytics {
  void track(String event, Map<String, dynamic> properties) {}
}

class Window {
  final Map<String, String> localStorage = {};
}

final analytics = Analytics();
final window = Window();
