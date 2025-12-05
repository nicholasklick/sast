// Hardcoded Secrets vulnerabilities in Dart

import 'dart:io';

// Test 1: Hardcoded password
class DatabaseConfig {
  // VULNERABLE: Hardcoded password
  static const String password = 'SuperSecretP@ssw0rd123!';
  static const String username = 'admin';
}

// Test 2: Hardcoded API key
class ApiConfig {
  // VULNERABLE: Hardcoded API key
  static const String apiKey = 'sk_live_abcdef1234567890abcdef1234567890';
}

// Test 3: Hardcoded AWS credentials
class AwsConfig {
  // VULNERABLE: Hardcoded AWS credentials
  static const String accessKeyId = 'AKIAIOSFODNN7EXAMPLE';
  static const String secretAccessKey = 'wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY';
}

// Test 4: Hardcoded JWT secret
class JwtConfig {
  // VULNERABLE: Hardcoded JWT secret
  static const String jwtSecret = 'super_secret_jwt_key_12345';
}

// Test 5: Hardcoded encryption key
class EncryptionConfig {
  // VULNERABLE: Hardcoded encryption key
  static const String encryptionKey = '0123456789abcdef0123456789abcdef';
  static const String iv = '1234567890abcdef';
}

// Test 6: Hardcoded OAuth credentials
class OAuthConfig {
  // VULNERABLE: Hardcoded OAuth credentials
  static const String clientId = 'my-app-client-id';
  static const String clientSecret = 'GOCSPX-abcdefghijklmnopqrstuvwxyz';
}

// Test 7: Hardcoded Firebase config
class FirebaseConfig {
  // VULNERABLE: Hardcoded Firebase credentials
  static const String apiKey = 'AIzaSyxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx';
  static const String projectId = 'my-project-12345';
}

// Test 8: Hardcoded Stripe key
class StripeConfig {
  // VULNERABLE: Hardcoded Stripe secret key
  static const String secretKey = 'sk_live_4eC39HqLyjWDarjtT1zdp7dc';
  static const String publishableKey = 'pk_live_abcdefghijklmnop';
}

// Test 9: Hardcoded database connection string
String getDatabaseUrl() {
  // VULNERABLE: Credentials in connection string
  return 'postgresql://admin:password123@localhost:5432/mydb';
}

// Test 10: Hardcoded private key
const String privateKey = '''
-----BEGIN RSA PRIVATE KEY-----
MIIEowIBAAKCAQEA0Z3VS5JJcds3xfn
-----END RSA PRIVATE KEY-----
''';

// Test 11: Hardcoded Bearer token
class AuthHeaders {
  // VULNERABLE: Hardcoded Bearer token
  static const String authToken = 'Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.dozjgNryP4J3jVmNHl0w5N_XgL0n3I9PlFUP0THsR8U';
}

// Test 12: Hardcoded webhook URL with token
class WebhookConfig {
  // VULNERABLE: Hardcoded webhook with secret
  static const String slackWebhook = 'https://hooks.slack.com/services/T00000000/B00000000/XXXXXXXXXXXXXXXXXXXXXXXX';
}

// Test 13: Hardcoded GitHub token
class GitHubConfig {
  // VULNERABLE: Hardcoded GitHub token
  static const String token = 'ghp_xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx';
}

// Test 14: Hardcoded SendGrid API key
class EmailConfig {
  // VULNERABLE: Hardcoded SendGrid key
  static const String sendgridApiKey = 'SG.xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx';
}

// Test 15: Password in function
Future<void> connectToDatabase() async {
  // VULNERABLE: Password in code
  var host = 'db.example.com';
  var user = 'dbuser';
  var pass = 'MyDatabaseP@ssword!';
  print('Connecting to $host with $user');
}

// Test 16: Basic auth credentials
Map<String, String> getAuthHeaders() {
  // VULNERABLE: Hardcoded Basic auth
  return {
    'Authorization': 'Basic YWRtaW46cGFzc3dvcmQxMjM=',
  };
}

// Test 17: Twilio credentials
class TwilioConfig {
  // VULNERABLE: Hardcoded Twilio credentials
  static const String accountSid = 'ACxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx';
  static const String authToken = 'your_auth_token_here';
}

// Test 18: Encryption passphrase
void encryptData(String data) {
  // VULNERABLE: Hardcoded passphrase
  var passphrase = 'my_super_secret_passphrase';
  print('Encrypting with passphrase');
}
