// Insecure Data Storage vulnerabilities in Dart

import 'dart:io';
import 'dart:convert';
import 'package:shared_preferences/shared_preferences.dart';

// Test 1: Password in SharedPreferences
Future<void> vulnerableStorePassword(String password) async {
  // VULNERABLE: Storing password in SharedPreferences
  var prefs = await SharedPreferences.getInstance();
  await prefs.setString('user_password', password);
}

// Test 2: API key in SharedPreferences
Future<void> vulnerableStoreApiKey(String apiKey) async {
  // VULNERABLE: API key in SharedPreferences
  var prefs = await SharedPreferences.getInstance();
  await prefs.setString('api_key', apiKey);
}

// Test 3: Token in plain text file
Future<void> vulnerableTokenFile(String token) async {
  // VULNERABLE: Token in plain text file
  var file = File('auth_token.txt');
  await file.writeAsString(token);
}

// Test 4: Credentials in JSON file
Future<void> vulnerableCredentialsJson(String username, String password) async {
  // VULNERABLE: Credentials in JSON file
  var file = File('credentials.json');
  await file.writeAsString(jsonEncode({
    'username': username,
    'password': password,
  }));
}

// Test 5: Secret in world-readable file
Future<void> vulnerableWorldReadable(String secret) async {
  // VULNERABLE: World-readable file
  var file = File('/tmp/app_secret.txt');
  await file.writeAsString(secret);
}

// Test 6: Encryption key in SharedPreferences
Future<void> vulnerableStoreEncryptionKey(String key) async {
  // VULNERABLE: Encryption key in SharedPreferences
  var prefs = await SharedPreferences.getInstance();
  await prefs.setString('encryption_key', key);
}

// Test 7: Credit card data in preferences
Future<void> vulnerableStoreCreditCard(String cardNumber, String cvv) async {
  // VULNERABLE: Credit card data in preferences
  var prefs = await SharedPreferences.getInstance();
  await prefs.setString('card_number', cardNumber);
  await prefs.setString('card_cvv', cvv);
}

// Test 8: Session token in plain file
Future<void> vulnerableSessionFile(String sessionToken) async {
  // VULNERABLE: Session token in file
  var file = File('session.txt');
  await file.writeAsString(sessionToken);
}

// Test 9: PII in SharedPreferences
Future<void> vulnerableStorePii(String ssn, String dob) async {
  // VULNERABLE: PII in SharedPreferences
  var prefs = await SharedPreferences.getInstance();
  await prefs.setString('ssn', ssn);
  await prefs.setString('date_of_birth', dob);
}

// Test 10: Private key in file
Future<void> vulnerablePrivateKeyFile(String privateKey) async {
  // VULNERABLE: Private key in plain file
  var file = File('private_key.pem');
  await file.writeAsString(privateKey);
}

// Test 11: OAuth tokens in preferences
Future<void> vulnerableOAuthTokens(String accessToken, String refreshToken) async {
  // VULNERABLE: OAuth tokens in SharedPreferences
  var prefs = await SharedPreferences.getInstance();
  await prefs.setString('access_token', accessToken);
  await prefs.setString('refresh_token', refreshToken);
}

// Test 12: Database credentials in config file
Future<void> vulnerableDbCredentials(String host, String user, String pass) async {
  // VULNERABLE: DB credentials in config file
  var file = File('db_config.json');
  await file.writeAsString(jsonEncode({
    'host': host,
    'username': user,
    'password': pass,
  }));
}

// Test 13: Biometric data in preferences (simulated)
Future<void> vulnerableBiometricData(String fingerprintHash) async {
  // VULNERABLE: Biometric data in preferences
  var prefs = await SharedPreferences.getInstance();
  await prefs.setString('fingerprint', fingerprintHash);
}

// Test 14: Health data in plain storage
Future<void> vulnerableHealthData(Map<String, dynamic> healthRecords) async {
  // VULNERABLE: Health data in plain file
  var file = File('health_records.json');
  await file.writeAsString(jsonEncode(healthRecords));
}

// Test 15: Backup codes in preferences
Future<void> vulnerableBackupCodes(List<String> codes) async {
  // VULNERABLE: 2FA backup codes in preferences
  var prefs = await SharedPreferences.getInstance();
  await prefs.setStringList('backup_codes', codes);
}
