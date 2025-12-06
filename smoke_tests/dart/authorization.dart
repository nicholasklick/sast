// Authorization vulnerabilities in Dart

import 'dart:io';

// Test 1: Missing authorization check
Future<String> vulnerableNoAuthCheck(String userId, String resourceId) async {
  // VULNERABLE: No authorization check before accessing resource
  var resource = await getResource(resourceId);
  return resource;
}

// Test 2: Insecure direct object reference (IDOR)
Future<Map<String, dynamic>> vulnerableIdor(String oderId) async {
  // VULNERABLE: Direct access without ownership verification
  var order = await database.query('orders', where: 'id = ?', whereArgs: [oderId]);
  return order.first;
}

// Test 3: Missing role check
void vulnerableNoRoleCheck(HttpRequest request) {
  // VULNERABLE: Admin action without role verification
  var action = request.uri.queryParameters['action'];
  if (action == 'delete_all') {
    deleteAllRecords();
  }
}

// Test 4: Client-side authorization
bool vulnerableClientSideAuth(Map<String, dynamic> user) {
  // VULNERABLE: Authorization decision based on client-provided data
  return user['isAdmin'] == true;
}

// Test 5: Horizontal privilege escalation
Future<void> vulnerableHorizontalPrivEsc(String currentUserId, String targetUserId) async {
  // VULNERABLE: Can access other users' data
  var profile = await getUserProfile(targetUserId);
  print(profile);
}

// Test 6: Vertical privilege escalation
Future<void> vulnerableVerticalPrivEsc(HttpRequest request) async {
  // VULNERABLE: Role from user input
  var role = request.uri.queryParameters['role'];
  await setUserRole(request.session['userId'], role);
}

// Test 7: Broken function level authorization
class VulnerableAdminController {
  // VULNERABLE: No authorization decorator/check
  Future<void> deleteUser(String userId) async {
    await database.execute('DELETE FROM users WHERE id = ?', [userId]);
  }

  Future<void> modifySettings(Map<String, dynamic> settings) async {
    await database.execute('UPDATE settings SET data = ?', [settings]);
  }
}

// Test 8: Path-based authorization bypass
Future<void> vulnerablePathBypass(HttpRequest request) async {
  var path = request.uri.path;
  // VULNERABLE: Path manipulation can bypass check
  if (!path.startsWith('/admin')) {
    // Allow access
    handleRequest(request);
  }
}

// Test 9: JWT without verification
Map<String, dynamic> vulnerableJwtNoVerify(String token) {
  // VULNERABLE: Decoding JWT without signature verification
  var parts = token.split('.');
  var payload = base64Decode(parts[1]);
  return jsonDecode(utf8.decode(payload));
}

// Test 10: Insecure permission check
bool vulnerableWeakPermCheck(Map<String, dynamic> user, String permission) {
  // VULNERABLE: Case-sensitive permission check can be bypassed
  var permissions = user['permissions'] as List<String>;
  return permissions.contains(permission);
}

// Test 11: Missing ownership check
Future<void> vulnerableNoOwnershipCheck(String userId, String documentId, String content) async {
  // VULNERABLE: Updates document without verifying ownership
  await database.execute(
    'UPDATE documents SET content = ? WHERE id = ?',
    [content, documentId]
  );
}

// Test 12: Predictable resource IDs
Future<String> vulnerablePredictableIds(int resourceId) async {
  // VULNERABLE: Sequential IDs allow enumeration
  var resource = await database.query('resources', where: 'id = ?', whereArgs: [resourceId]);
  return resource.first['data'];
}

// Test 13: Mass assignment
Future<void> vulnerableMassAssignment(HttpRequest request) async {
  // VULNERABLE: Directly using request data to update user
  var body = await utf8.decoder.bind(request).join();
  var data = jsonDecode(body);
  await database.execute(
    'UPDATE users SET role = ?, is_admin = ? WHERE id = ?',
    [data['role'], data['is_admin'], data['id']]
  );
}

// Test 14: Insecure API key check
bool vulnerableApiKeyCheck(HttpRequest request) {
  // VULNERABLE: Timing attack possible
  var providedKey = request.headers.value('X-API-Key');
  var validKey = 'secret-api-key-12345';
  return providedKey == validKey;
}

// Test 15: Missing scope validation
Future<void> vulnerableNoScopeCheck(String accessToken, String action) async {
  // VULNERABLE: Token accepted without scope verification
  if (await isValidToken(accessToken)) {
    await performAction(action);
  }
}

// Helper stubs
Future<String> getResource(String id) async => '';
Future<Map<String, dynamic>> getUserProfile(String id) async => {};
Future<void> setUserRole(String? userId, String? role) async {}
void deleteAllRecords() {}
void handleRequest(HttpRequest request) {}
Future<bool> isValidToken(String token) async => true;
Future<void> performAction(String action) async {}

// Mock database
class Database {
  Future<List<Map<String, dynamic>>> query(String table, {String? where, List<dynamic>? whereArgs}) async => [];
  Future<void> execute(String sql, [List<dynamic>? args]) async {}
}
final database = Database();
