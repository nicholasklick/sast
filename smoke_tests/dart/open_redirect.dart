// Open Redirect vulnerabilities in Dart

import 'dart:io';
import 'package:shelf/shelf.dart' as shelf;
import 'package:url_launcher/url_launcher.dart';

// Test 1: Redirect with user URL
shelf.Response vulnerableRedirect(String redirectUrl) {
  // VULNERABLE: Open redirect
  return shelf.Response.found(redirectUrl);
}

// Test 2: Location header with user input
shelf.Response vulnerableLocationHeader(String url) {
  // VULNERABLE: User-controlled Location header
  return shelf.Response(302, headers: {'Location': url});
}

// Test 3: Redirect from query parameter
shelf.Response vulnerableQueryRedirect(shelf.Request request) {
  // VULNERABLE: Redirect URL from query parameter
  var returnUrl = request.requestedUri.queryParameters['return_url'];
  if (returnUrl != null) {
    return shelf.Response.found(returnUrl);
  }
  return shelf.Response.ok('No redirect');
}

// Test 4: Meta refresh redirect
shelf.Response vulnerableMetaRefresh(String url) {
  // VULNERABLE: Meta refresh redirect
  return shelf.Response.ok(
    '<html><head><meta http-equiv="refresh" content="0;url=$url"></head></html>',
    headers: {'content-type': 'text/html'},
  );
}

// Test 5: JavaScript redirect in response
shelf.Response vulnerableJsRedirect(String url) {
  // VULNERABLE: JavaScript redirect
  return shelf.Response.ok(
    '<script>window.location.href="$url";</script>',
    headers: {'content-type': 'text/html'},
  );
}

// Test 6: URL launcher with user URL
Future<void> vulnerableLaunchUrl(String url) async {
  // VULNERABLE: Opening arbitrary URL
  await launchUrl(Uri.parse(url));
}

// Test 7: Callback URL without validation
shelf.Response vulnerableCallback(String callbackUrl, String data) {
  // VULNERABLE: Unvalidated callback URL
  return shelf.Response.found('$callbackUrl?data=$data');
}

// Test 8: OAuth redirect URI
shelf.Response vulnerableOAuthRedirect(String redirectUri, String code) {
  // VULNERABLE: OAuth redirect without validation
  return shelf.Response.found('$redirectUri?code=$code');
}

// Test 9: Login redirect
shelf.Response vulnerableLoginRedirect(String nextUrl) {
  // VULNERABLE: Post-login redirect
  // After successful login
  return shelf.Response.found(nextUrl);
}

// Test 10: Logout redirect
shelf.Response vulnerableLogoutRedirect(String postLogoutUrl) {
  // VULNERABLE: Post-logout redirect
  return shelf.Response.found(postLogoutUrl);
}

// Test 11: Error page redirect
shelf.Response vulnerableErrorRedirect(String returnPath) {
  // VULNERABLE: Redirect after error
  return shelf.Response.found('/error?return=$returnPath');
}

// Test 12: Form action redirect
String vulnerableFormAction(String action) {
  // VULNERABLE: User-controlled form action
  return '<form action="$action" method="POST">';
}

// Test 13: Window.open equivalent
shelf.Response vulnerableWindowOpen(String url) {
  // VULNERABLE: Opening new window to user URL
  return shelf.Response.ok(
    '<script>window.open("$url", "_blank");</script>',
    headers: {'content-type': 'text/html'},
  );
}

// Test 14: Anchor href redirect
String vulnerableAnchorRedirect(String href) {
  // VULNERABLE: User-controlled href
  return '<a href="$href">Click here to continue</a>';
}

// Test 15: Base URL manipulation
String vulnerableBaseUrl(String baseUrl) {
  // VULNERABLE: User-controlled base URL
  return '<base href="$baseUrl">';
}
