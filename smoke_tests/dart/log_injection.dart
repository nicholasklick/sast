// Log Injection vulnerabilities in Dart

import 'dart:io';
import 'package:logging/logging.dart';

final _logger = Logger('App');

// Test 1: Print with user input
void vulnerablePrint(String userInput) {
  // VULNERABLE: User input in print
  print('User action: $userInput');
}

// Test 2: Logger with user input
void vulnerableLoggerInfo(String userInput) {
  // VULNERABLE: User input in log
  _logger.info('Processing request: $userInput');
}

// Test 3: Logger warning with user data
void vulnerableLoggerWarning(String errorDetails) {
  // VULNERABLE: User-controlled error in warning
  _logger.warning('Error occurred: $errorDetails');
}

// Test 4: Logger severe with user data
void vulnerableLoggerSevere(String exceptionMessage) {
  // VULNERABLE: User input in severe log
  _logger.severe('Critical error: $exceptionMessage');
}

// Test 5: Debug print with user input
void vulnerableDebugPrint(String data) {
  // VULNERABLE: User input in debug log
  debugPrint('Debug data: $data');
}

// Test 6: stdout.write with user input
void vulnerableStdoutWrite(String message) {
  // VULNERABLE: User input to stdout
  stdout.write('Message: $message\n');
}

// Test 7: stderr.write with user input
void vulnerableStderrWrite(String error) {
  // VULNERABLE: User input to stderr
  stderr.write('Error: $error\n');
}

// Test 8: File logging with user input
Future<void> vulnerableFileLog(String logPath, String message) async {
  // VULNERABLE: User input in file log
  var file = File(logPath);
  await file.writeAsString(
    '${DateTime.now()}: $message\n',
    mode: FileMode.append,
  );
}

// Test 9: Multi-line log injection
void vulnerableMultilineLog(String userInput) {
  // VULNERABLE: Can inject fake log entries
  print('[INFO] User submitted: $userInput');
}

// Test 10: JSON log with user input
void vulnerableJsonLog(String username, String action) {
  // VULNERABLE: JSON injection in logs
  print('{"user": "$username", "action": "$action", "timestamp": "${DateTime.now()}"}');
}

// Test 11: Log with HTTP headers
void vulnerableHeaderLog(Map<String, String> headers) {
  // VULNERABLE: Headers in logs
  print('Request headers: $headers');
}

// Test 12: Log with query parameters
void vulnerableQueryLog(Map<String, String> queryParams) {
  // VULNERABLE: Query params in logs
  print('Query parameters: $queryParams');
}

// Test 13: Exception logging with user message
void vulnerableExceptionLog(String userMessage) {
  // VULNERABLE: User message in exception log
  try {
    throw Exception(userMessage);
  } catch (e) {
    print('Exception: $e');
  }
}

// Test 14: Audit log with user data
void vulnerableAuditLog(String userId, String action, String details) {
  // VULNERABLE: User-controlled audit log
  _logger.info('AUDIT: User $userId performed $action: $details');
}

// Test 15: Stack trace with user input
void vulnerableStackTraceLog(String errorContext) {
  // VULNERABLE: User context in stack trace log
  try {
    throw Exception('Error in: $errorContext');
  } catch (e, stackTrace) {
    print('$e\n$stackTrace');
  }
}

// Test 16: CSV log format
Future<void> vulnerableCsvLog(String logPath, String field1, String field2) async {
  // VULNERABLE: CSV injection in logs
  var file = File(logPath);
  await file.writeAsString(
    '$field1,$field2,${DateTime.now()}\n',
    mode: FileMode.append,
  );
}

// Test 17: Syslog-style logging
void vulnerableSyslog(String facility, String message) {
  // VULNERABLE: User input in syslog format
  print('<$facility> ${DateTime.now()}: $message');
}

// Test 18: Analytics logging
void vulnerableAnalyticsLog(String eventName, Map<String, dynamic> params) {
  // VULNERABLE: User-controlled analytics
  print('Analytics: $eventName - $params');
}
