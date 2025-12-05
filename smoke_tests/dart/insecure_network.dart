// Insecure Network Configuration vulnerabilities in Dart

import 'dart:io';
import 'package:http/http.dart' as http;

// Test 1: HTTP instead of HTTPS
Future<String> vulnerableHttp(String endpoint) async {
  // VULNERABLE: Using HTTP instead of HTTPS
  var response = await http.get(Uri.parse('http://api.example.com/$endpoint'));
  return response.body;
}

// Test 2: Disable certificate verification
Future<void> vulnerableNoCertVerify() async {
  // VULNERABLE: Disabling SSL certificate verification
  var client = HttpClient();
  client.badCertificateCallback = (cert, host, port) => true;
}

// Test 3: Accept any certificate
class VulnerableCertificateCheck {
  bool onBadCertificate(X509Certificate cert, String host, int port) {
    // VULNERABLE: Accepting all certificates
    return true;
  }
}

// Test 4: Weak TLS version
Future<void> vulnerableWeakTls() async {
  // VULNERABLE: Not enforcing TLS 1.2+
  var context = SecurityContext();
  // Not setting minimum TLS version
}

// Test 5: No certificate pinning
Future<String> vulnerableNoPinning(String url) async {
  // VULNERABLE: No certificate pinning
  var response = await http.get(Uri.parse(url));
  return response.body;
}

// Test 6: Sensitive data over HTTP
Future<void> vulnerableSensitiveHttp(String password) async {
  // VULNERABLE: Sending password over HTTP
  await http.post(
    Uri.parse('http://api.example.com/login'),
    body: {'password': password},
  );
}

// Test 7: Basic auth over HTTP
Future<void> vulnerableBasicAuthHttp(String username, String password) async {
  // VULNERABLE: Basic auth over HTTP
  var client = HttpClient();
  var request = await client.getUrl(Uri.parse('http://api.example.com/data'));
  request.headers.add('Authorization', 'Basic $username:$password');
}

// Test 8: API key in HTTP request
Future<void> vulnerableApiKeyHttp(String apiKey) async {
  // VULNERABLE: API key over HTTP
  await http.get(
    Uri.parse('http://api.example.com/data'),
    headers: {'X-API-Key': apiKey},
  );
}

// Test 9: Unencrypted WebSocket
Future<WebSocket> vulnerableWs(String host) async {
  // VULNERABLE: Unencrypted WebSocket
  return await WebSocket.connect('ws://$host/socket');
}

// Test 10: Ignoring SSL errors
Future<String> vulnerableIgnoreSsl(String url) async {
  // VULNERABLE: Ignoring all SSL errors
  var client = HttpClient();
  client.badCertificateCallback = (_, __, ___) => true;
  var request = await client.getUrl(Uri.parse(url));
  var response = await request.close();
  return await response.transform(SystemEncoding().decoder).join();
}

// Test 11: No hostname verification
Future<void> vulnerableNoHostnameVerify() async {
  // VULNERABLE: Would not verify hostname matches certificate
  var client = HttpClient();
  // Not verifying hostname
}

// Test 12: Hardcoded proxy
Future<void> vulnerableHardcodedProxy() async {
  // VULNERABLE: Hardcoded proxy (could be malicious)
  var client = HttpClient();
  client.findProxy = (uri) => 'PROXY proxy.example.com:8080';
}

// Test 13: Clear text traffic allowed
class NetworkConfig {
  // VULNERABLE: Allowing clear text traffic
  static const bool allowClearText = true;
}

// Test 14: Socket without TLS
Future<Socket> vulnerableRawSocket(String host, int port) async {
  // VULNERABLE: Raw socket without TLS
  return await Socket.connect(host, port);
}

// Test 15: FTP connection
Future<void> vulnerableFtp(String host, String username, String password) async {
  // VULNERABLE: FTP is unencrypted
  var socket = await Socket.connect(host, 21);
  socket.write('USER $username\r\n');
  socket.write('PASS $password\r\n');
}
