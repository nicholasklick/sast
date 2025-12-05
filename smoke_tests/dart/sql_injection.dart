// SQL Injection vulnerabilities in Dart

import 'package:sqflite/sqflite.dart';

// Test 1: Raw query with string interpolation
Future<void> vulnerableRawQuery(Database db, String userId) async {
  // VULNERABLE: SQL injection via interpolation
  await db.rawQuery('SELECT * FROM users WHERE id = $userId');
}

// Test 2: Raw query with concatenation
Future<void> vulnerableQueryConcat(Database db, String name) async {
  // VULNERABLE: SQL injection via concatenation
  await db.rawQuery('SELECT * FROM users WHERE name = \'' + name + '\'');
}

// Test 3: Raw insert with user data
Future<void> vulnerableRawInsert(Database db, String username, String email) async {
  // VULNERABLE: SQL injection in INSERT
  await db.rawInsert(
    'INSERT INTO users (username, email) VALUES (\'$username\', \'$email\')'
  );
}

// Test 4: Raw update with user data
Future<void> vulnerableRawUpdate(Database db, String status, String id) async {
  // VULNERABLE: SQL injection in UPDATE
  await db.rawUpdate('UPDATE orders SET status = \'$status\' WHERE id = $id');
}

// Test 5: Raw delete with user data
Future<void> vulnerableRawDelete(Database db, String condition) async {
  // VULNERABLE: SQL injection in DELETE
  await db.rawDelete('DELETE FROM logs WHERE $condition');
}

// Test 6: Execute with user input
Future<void> vulnerableExecute(Database db, String tableName) async {
  // VULNERABLE: Table name injection
  await db.execute('DROP TABLE IF EXISTS $tableName');
}

// Test 7: ORDER BY injection
Future<void> vulnerableOrderBy(Database db, String column, String direction) async {
  // VULNERABLE: ORDER BY injection
  await db.rawQuery('SELECT * FROM products ORDER BY $column $direction');
}

// Test 8: LIKE clause injection
Future<void> vulnerableLike(Database db, String search) async {
  // VULNERABLE: LIKE injection
  await db.rawQuery('SELECT * FROM items WHERE name LIKE \'%$search%\'');
}

// Test 9: LIMIT injection
Future<void> vulnerableLimit(Database db, String limit, String offset) async {
  // VULNERABLE: LIMIT/OFFSET injection
  await db.rawQuery('SELECT * FROM data LIMIT $limit OFFSET $offset');
}

// Test 10: UNION injection
Future<void> vulnerableUnion(Database db, String input) async {
  // VULNERABLE: UNION injection
  await db.rawQuery('SELECT id, name FROM users WHERE id = $input');
}

// Test 11: Subquery injection
Future<void> vulnerableSubquery(Database db, String subquery) async {
  // VULNERABLE: Subquery injection
  await db.rawQuery('SELECT * FROM orders WHERE customer_id IN ($subquery)');
}

// Test 12: Column name injection
Future<void> vulnerableColumnName(Database db, String column) async {
  // VULNERABLE: Column name injection
  await db.rawQuery('SELECT $column FROM users');
}

// Test 13: WHERE clause injection
Future<void> vulnerableWhere(Database db, String whereClause) async {
  // VULNERABLE: WHERE clause injection
  await db.rawQuery('SELECT * FROM products WHERE $whereClause');
}

// Test 14: Batch operations with user input
Future<void> vulnerableBatch(Database db, List<String> queries) async {
  // VULNERABLE: Batch of user-controlled queries
  var batch = db.batch();
  for (var query in queries) {
    batch.rawQuery(query);
  }
  await batch.commit();
}

// Test 15: Transaction with user query
Future<void> vulnerableTransaction(Database db, String userId) async {
  // VULNERABLE: SQL injection in transaction
  await db.transaction((txn) async {
    await txn.rawQuery('SELECT * FROM accounts WHERE user_id = $userId');
    await txn.rawUpdate('UPDATE users SET last_login = NOW() WHERE id = $userId');
  });
}
