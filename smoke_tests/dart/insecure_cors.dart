// Insecure CORS Configuration vulnerabilities in Dart

import 'dart:io';

// Test 1: Allow all origins
void vulnerableAllowAllOrigins(HttpResponse response) {
  // VULNERABLE: Allows any origin
  response.headers.add('Access-Control-Allow-Origin', '*');
}

// Test 2: Reflecting origin without validation
void vulnerableReflectOrigin(HttpRequest request, HttpResponse response) {
  // VULNERABLE: Reflecting origin header without validation
  var origin = request.headers.value('Origin');
  if (origin != null) {
    response.headers.add('Access-Control-Allow-Origin', origin);
  }
}

// Test 3: Allow credentials with wildcard
void vulnerableCredentialsWildcard(HttpResponse response) {
  // VULNERABLE: Credentials with wildcard origin
  response.headers.add('Access-Control-Allow-Origin', '*');
  response.headers.add('Access-Control-Allow-Credentials', 'true');
}

// Test 4: Credentials with reflected origin
void vulnerableCredentialsReflected(HttpRequest request, HttpResponse response) {
  // VULNERABLE: Credentials enabled with any origin
  var origin = request.headers.value('Origin');
  response.headers.add('Access-Control-Allow-Origin', origin ?? '*');
  response.headers.add('Access-Control-Allow-Credentials', 'true');
}

// Test 5: Overly permissive methods
void vulnerableAllMethods(HttpResponse response) {
  // VULNERABLE: Allowing all HTTP methods
  response.headers.add('Access-Control-Allow-Origin', '*');
  response.headers.add('Access-Control-Allow-Methods', '*');
}

// Test 6: Overly permissive headers
void vulnerableAllHeaders(HttpResponse response) {
  // VULNERABLE: Allowing all headers
  response.headers.add('Access-Control-Allow-Origin', '*');
  response.headers.add('Access-Control-Allow-Headers', '*');
}

// Test 7: Null origin allowed
void vulnerableNullOrigin(HttpRequest request, HttpResponse response) {
  // VULNERABLE: Accepting null origin
  var origin = request.headers.value('Origin');
  if (origin == 'null' || origin != null) {
    response.headers.add('Access-Control-Allow-Origin', origin!);
    response.headers.add('Access-Control-Allow-Credentials', 'true');
  }
}

// Test 8: Regex bypass in origin validation
void vulnerableRegexBypass(HttpRequest request, HttpResponse response) {
  // VULNERABLE: Weak regex can be bypassed
  var origin = request.headers.value('Origin') ?? '';
  if (origin.contains('trusted.com')) {
    // attacker-trusted.com would match
    response.headers.add('Access-Control-Allow-Origin', origin);
  }
}

// Test 9: Subdomain wildcard
void vulnerableSubdomainWildcard(HttpRequest request, HttpResponse response) {
  // VULNERABLE: Any subdomain allowed
  var origin = request.headers.value('Origin') ?? '';
  if (origin.endsWith('.example.com')) {
    // evil.example.com would match
    response.headers.add('Access-Control-Allow-Origin', origin);
  }
}

// Test 10: Long preflight cache
void vulnerableLongPreflight(HttpResponse response) {
  // VULNERABLE: Very long preflight cache
  response.headers.add('Access-Control-Allow-Origin', '*');
  response.headers.add('Access-Control-Max-Age', '86400000'); // ~1000 days
}

// Test 11: Exposing sensitive headers
void vulnerableExposeHeaders(HttpResponse response) {
  // VULNERABLE: Exposing sensitive headers
  response.headers.add('Access-Control-Allow-Origin', '*');
  response.headers.add('Access-Control-Expose-Headers', 'Authorization, X-API-Key, Set-Cookie');
}

// Test 12: CORS in middleware without validation
class VulnerableCorsMiddleware {
  void handle(HttpRequest request, HttpResponse response) {
    // VULNERABLE: Blanket CORS headers on all responses
    response.headers.add('Access-Control-Allow-Origin', '*');
    response.headers.add('Access-Control-Allow-Methods', 'GET, POST, PUT, DELETE, OPTIONS');
    response.headers.add('Access-Control-Allow-Headers', 'Content-Type, Authorization');
  }
}

// Test 13: Protocol downgrade
void vulnerableProtocolDowngrade(HttpRequest request, HttpResponse response) {
  // VULNERABLE: Allows HTTP origin from HTTPS site
  var origin = request.headers.value('Origin') ?? '';
  if (origin.contains('example.com')) {
    // http://example.com would be allowed
    response.headers.add('Access-Control-Allow-Origin', origin);
  }
}

// Test 14: Port not validated
void vulnerablePortNotValidated(HttpRequest request, HttpResponse response) {
  // VULNERABLE: Any port on trusted domain
  var origin = request.headers.value('Origin') ?? '';
  if (origin.startsWith('https://trusted.com')) {
    // https://trusted.com:8080 would match (could be different app)
    response.headers.add('Access-Control-Allow-Origin', origin);
  }
}

// Test 15: Configuration from environment
void vulnerableCorsFromEnv(HttpResponse response) {
  // VULNERABLE: CORS origin from potentially unsafe env var
  var allowedOrigin = Platform.environment['CORS_ORIGIN'] ?? '*';
  response.headers.add('Access-Control-Allow-Origin', allowedOrigin);
}
