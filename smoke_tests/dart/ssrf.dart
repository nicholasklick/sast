// SSRF (Server-Side Request Forgery) vulnerabilities in Dart

import 'dart:io';
import 'dart:convert';
import 'package:http/http.dart' as http;
import 'package:dio/dio.dart';

// Test 1: HttpClient with user URL
Future<String> vulnerableHttpClient(String userUrl) async {
  // VULNERABLE: SSRF via user-controlled URL
  var client = HttpClient();
  var request = await client.getUrl(Uri.parse(userUrl));
  var response = await request.close();
  return await response.transform(utf8.decoder).join();
}

// Test 2: http package with user URL
Future<http.Response> vulnerableHttpGet(String url) async {
  // VULNERABLE: SSRF via http.get
  return await http.get(Uri.parse(url));
}

// Test 3: http.post with user URL
Future<http.Response> vulnerableHttpPost(String url, String body) async {
  // VULNERABLE: SSRF via http.post
  return await http.post(Uri.parse(url), body: body);
}

// Test 4: Dio with user URL
Future<Response> vulnerableDio(String url) async {
  // VULNERABLE: SSRF via Dio
  var dio = Dio();
  return await dio.get(url);
}

// Test 5: URL with user-controlled host
Future<String> vulnerableHost(String host) async {
  // VULNERABLE: User-controlled host
  var client = HttpClient();
  var uri = Uri.parse('http://$host/api/data');
  var request = await client.getUrl(uri);
  var response = await request.close();
  return await response.transform(utf8.decoder).join();
}

// Test 6: URL with user-controlled port
Future<String> vulnerablePort(String port) async {
  // VULNERABLE: User-controlled port (port scanning)
  var client = HttpClient();
  var uri = Uri.parse('http://localhost:$port/health');
  var request = await client.getUrl(uri);
  var response = await request.close();
  return await response.transform(utf8.decoder).join();
}

// Test 7: URL from query parameter
Future<String> vulnerableQueryUrl(Uri requestUri) async {
  // VULNERABLE: URL from query parameter
  var targetUrl = requestUri.queryParameters['url'];
  if (targetUrl != null) {
    var response = await http.get(Uri.parse(targetUrl));
    return response.body;
  }
  return '';
}

// Test 8: Redirect following
Future<String> vulnerableRedirect(String url) async {
  // VULNERABLE: Following redirects to arbitrary locations
  var client = HttpClient();
  client.autoUncompress = true;
  var request = await client.getUrl(Uri.parse(url));
  var response = await request.close();
  return await response.transform(utf8.decoder).join();
}

// Test 9: WebSocket with user URL
Future<WebSocket> vulnerableWebSocket(String wsUrl) async {
  // VULNERABLE: WebSocket SSRF
  return await WebSocket.connect(wsUrl);
}

// Test 10: Socket connection with user host
Future<Socket> vulnerableSocket(String host, int port) async {
  // VULNERABLE: Raw socket SSRF
  return await Socket.connect(host, port);
}

// Test 11: Image/resource fetch
Future<List<int>> vulnerableImageFetch(String imageUrl) async {
  // VULNERABLE: Image URL SSRF
  var response = await http.get(Uri.parse(imageUrl));
  return response.bodyBytes;
}

// Test 12: API proxy pattern
Future<http.Response> vulnerableApiProxy(String endpoint) async {
  // VULNERABLE: API proxy SSRF
  var internalUrl = 'http://internal-api:8080/$endpoint';
  return await http.get(Uri.parse(internalUrl));
}

// Test 13: URL from JSON body
Future<String> vulnerableJsonUrl(String jsonBody) async {
  // VULNERABLE: URL extracted from JSON
  var data = jsonDecode(jsonBody);
  var url = data['callback_url'];
  var response = await http.post(Uri.parse(url), body: 'status=complete');
  return response.body;
}

// Test 14: DNS rebinding potential
Future<String> vulnerableDnsLookup(String hostname) async {
  // VULNERABLE: DNS rebinding
  var addresses = await InternetAddress.lookup(hostname);
  var client = HttpClient();
  var request = await client.getUrl(Uri.parse('http://${addresses.first.address}/'));
  var response = await request.close();
  return await response.transform(utf8.decoder).join();
}

// Test 15: File protocol SSRF
Future<String> vulnerableFileProtocol(String path) async {
  // VULNERABLE: file:// protocol (if supported)
  var response = await http.get(Uri.parse('file://$path'));
  return response.body;
}
