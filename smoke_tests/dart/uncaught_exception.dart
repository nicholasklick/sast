// Uncaught Exception vulnerabilities in Dart

import 'dart:io';
import 'dart:async';
import 'dart:convert';

// Test 1: No try-catch around file operations
Future<String> vulnerableFileRead(String path) async {
  // VULNERABLE: No exception handling
  var file = File(path);
  return await file.readAsString();
}

// Test 2: Unhandled JSON parse
Map<String, dynamic> vulnerableJsonParse(String data) {
  // VULNERABLE: JSON parse can throw
  return jsonDecode(data);
}

// Test 3: Unhandled int parse
int vulnerableIntParse(String value) {
  // VULNERABLE: int.parse throws on invalid input
  return int.parse(value);
}

// Test 4: Unhandled network request
Future<String> vulnerableHttpRequest(String url) async {
  // VULNERABLE: No error handling for network failures
  var client = HttpClient();
  var request = await client.getUrl(Uri.parse(url));
  var response = await request.close();
  return await response.transform(utf8.decoder).join();
}

// Test 5: Empty catch block
Future<void> vulnerableEmptyCatch(String path) async {
  try {
    var file = File(path);
    await file.readAsString();
  } catch (e) {
    // VULNERABLE: Empty catch block silently swallows errors
  }
}

// Test 6: Catching Exception but not Error
Future<void> vulnerableCatchOnlyException(String data) async {
  try {
    jsonDecode(data);
  } on Exception catch (e) {
    // VULNERABLE: Doesn't catch Error types
    print('Exception: $e');
  }
}

// Test 7: No finally for resource cleanup
Future<void> vulnerableNoFinally(String path) async {
  // VULNERABLE: Resource may not be closed on error
  var file = File(path).openSync();
  var content = file.readStringSync();
  file.closeSync();
}

// Test 8: Rethrowing without logging
Future<void> vulnerableRethrowNoLog(String path) async {
  try {
    await File(path).readAsString();
  } catch (e) {
    // VULNERABLE: No logging before rethrow
    rethrow;
  }
}

// Test 9: Generic exception handling
Future<void> vulnerableGenericCatch() async {
  try {
    await someOperation();
  } catch (e) {
    // VULNERABLE: Catches everything, loses specific error info
    print('An error occurred');
  }
}

// Test 10: Async without error handling
void vulnerableAsyncNoAwait() {
  // VULNERABLE: Fire-and-forget async without error handling
  riskyAsyncOperation();
}

// Test 11: Stream without error handling
void vulnerableStreamNoErrorHandler(Stream<String> stream) {
  // VULNERABLE: No error handler on stream
  stream.listen((data) {
    print(data);
  });
}

// Test 12: Future.then without catchError
void vulnerableThenNoCatch(Future<String> future) {
  // VULNERABLE: No error handling in chain
  future.then((value) {
    print(value);
  });
}

// Test 13: Unhandled zone error
void vulnerableZoneNoErrorHandler() {
  // VULNERABLE: Zone without error handler
  runZoned(() {
    throw Exception('Unhandled in zone');
  });
}

// Test 14: Isolate without error port
void vulnerableIsolateNoErrorPort() {
  // VULNERABLE: Isolate errors won't be caught
  // Isolate.spawn(someFunction, message);
}

// Test 15: HTTP server without error handling
Future<void> vulnerableServerNoErrorHandler() async {
  // VULNERABLE: Server errors not handled
  var server = await HttpServer.bind('localhost', 8080);
  await for (var request in server) {
    handleRequest(request); // No try-catch
  }
}

// Test 16: Database operation without error handling
Future<void> vulnerableDatabaseOp(String query) async {
  // VULNERABLE: Database errors not handled
  await database.execute(query);
}

// Test 17: Division without zero check
double vulnerableDivision(int a, int b) {
  // VULNERABLE: Division by zero not handled
  return a / b;
}

// Test 18: List access without bounds check
String vulnerableListAccess(List<String> items, int index) {
  // VULNERABLE: Out of bounds not handled
  return items[index];
}

// Test 19: Map access without null check
String vulnerableMapAccess(Map<String, String> map, String key) {
  // VULNERABLE: Key may not exist
  return map[key]!;
}

// Test 20: Completer without error completion
class VulnerableCompleter {
  final Completer<String> _completer = Completer();

  Future<String> get future => _completer.future;

  void complete(String value) {
    // VULNERABLE: Only completes with value, never with error
    _completer.complete(value);
  }
}

// Test 21: Timer callback without error handling
void vulnerableTimerCallback() {
  // VULNERABLE: Timer callback errors are unhandled
  Timer(Duration(seconds: 1), () {
    riskyOperation();
  });
}

// Test 22: Event handler without error handling
void vulnerableEventHandler(Stream<String> events) {
  // VULNERABLE: Event processing errors not caught
  events.listen((event) {
    processEvent(event); // May throw
  });
}

// Helper functions and mocks
Future<void> someOperation() async {}
Future<void> riskyAsyncOperation() async => throw Exception('Async error');
void handleRequest(HttpRequest request) {}
void riskyOperation() => throw Exception('Risky');
void processEvent(String event) {}

class Database {
  Future<void> execute(String query) async {}
}

final database = Database();
