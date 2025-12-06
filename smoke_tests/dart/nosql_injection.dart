// NoSQL Injection vulnerabilities in Dart

import 'dart:convert';

// Test 1: Firestore query with user input
Future<void> vulnerableFirestoreQuery(String userId) async {
  // VULNERABLE: Direct user input in query
  var snapshot = await firestore
      .collection('users')
      .where('userId', isEqualTo: userId)
      .get();
}

// Test 2: MongoDB-style query building
Future<void> vulnerableMongoQuery(String username) async {
  // VULNERABLE: String concatenation in query
  var query = {'username': username};
  await mongodb.collection('users').find(query);
}

// Test 3: Dynamic field name
Future<void> vulnerableDynamicField(String fieldName, String value) async {
  // VULNERABLE: User-controlled field name
  var query = {fieldName: value};
  await mongodb.collection('data').find(query);
}

// Test 4: JSON query from user input
Future<void> vulnerableJsonQuery(String jsonQuery) async {
  // VULNERABLE: Parsing user JSON as query
  var query = jsonDecode(jsonQuery);
  await mongodb.collection('data').find(query);
}

// Test 5: Operator injection
Future<void> vulnerableOperatorInjection(String value) async {
  // VULNERABLE: Value could contain operators like $gt, $ne
  var query = jsonDecode('{"age": $value}');
  await mongodb.collection('users').find(query);
}

// Test 6: Firestore with user-controlled path
Future<void> vulnerableFirestorePath(String collection, String docId) async {
  // VULNERABLE: User controls document path
  var doc = await firestore.collection(collection).doc(docId).get();
}

// Test 7: Array contains with user input
Future<void> vulnerableArrayContains(String tag) async {
  // VULNERABLE: Direct user input in array query
  var snapshot = await firestore
      .collection('posts')
      .where('tags', arrayContains: tag)
      .get();
}

// Test 8: Regex injection in MongoDB
Future<void> vulnerableRegexInjection(String pattern) async {
  // VULNERABLE: User-controlled regex pattern
  var query = {
    'name': {'\$regex': pattern}
  };
  await mongodb.collection('users').find(query);
}

// Test 9: Where clause from string
Future<void> vulnerableWhereString(String condition) async {
  // VULNERABLE: User-controlled where clause
  var query = {'\$where': condition};
  await mongodb.collection('data').find(query);
}

// Test 10: Aggregation pipeline injection
Future<void> vulnerableAggregation(String matchStage) async {
  // VULNERABLE: User input in aggregation pipeline
  var pipeline = [
    jsonDecode(matchStage),
    {'\$group': {'_id': '\$category', 'count': {'\$sum': 1}}}
  ];
  await mongodb.collection('products').aggregate(pipeline);
}

// Test 11: Update with user data
Future<void> vulnerableUpdate(String id, String updateJson) async {
  // VULNERABLE: User-controlled update document
  var update = jsonDecode(updateJson);
  await mongodb.collection('users').updateOne({'_id': id}, update);
}

// Test 12: Firestore security rules bypass attempt
Future<void> vulnerableSecurityRulesData(String userId, Map<String, dynamic> data) async {
  // VULNERABLE: Data may contain fields that bypass security rules
  await firestore.collection('sensitive').doc(userId).set(data);
}

// Test 13: Bulk write with user queries
Future<void> vulnerableBulkWrite(List<String> operations) async {
  // VULNERABLE: User-controlled bulk operations
  var bulkOps = operations.map((op) => jsonDecode(op)).toList();
  await mongodb.collection('data').bulkWrite(bulkOps);
}

// Test 14: Text search injection
Future<void> vulnerableTextSearch(String searchText) async {
  // VULNERABLE: User input in text search
  var query = {
    '\$text': {'\$search': searchText}
  };
  await mongodb.collection('articles').find(query);
}

// Test 15: Projection injection
Future<void> vulnerableProjection(String fields) async {
  // VULNERABLE: User-controlled field projection
  var projection = jsonDecode(fields);
  await mongodb.collection('users').find({}, projection: projection);
}

// Test 16: Sort injection
Future<void> vulnerableSort(String sortField) async {
  // VULNERABLE: User-controlled sort field
  await mongodb.collection('data').find({}).sort({sortField: 1});
}

// Test 17: Limit/Skip from user
Future<void> vulnerablePagination(String limit, String skip) async {
  // VULNERABLE: Could cause DoS with large values
  var limitNum = int.parse(limit);
  var skipNum = int.parse(skip);
  await mongodb.collection('data').find({}).skip(skipNum).limit(limitNum);
}

// Test 18: Redis command injection
Future<void> vulnerableRedisCommand(String key) async {
  // VULNERABLE: User input in Redis command
  await redis.send('GET', [key]);
}

// Mock classes
class Firestore {
  CollectionReference collection(String path) => CollectionReference();
}

class CollectionReference {
  Query where(String field, {dynamic isEqualTo, dynamic arrayContains}) => Query();
  DocumentReference doc(String id) => DocumentReference();
}

class Query {
  Future<QuerySnapshot> get() async => QuerySnapshot();
}

class DocumentReference {
  Future<DocumentSnapshot> get() async => DocumentSnapshot();
  Future<void> set(Map<String, dynamic> data) async {}
}

class QuerySnapshot {}
class DocumentSnapshot {}

class MongoDB {
  MongoCollection collection(String name) => MongoCollection();
}

class MongoCollection {
  Future<void> find(Map<String, dynamic> query, {Map<String, dynamic>? projection}) async {}
  Future<void> aggregate(List<Map<String, dynamic>> pipeline) async {}
  Future<void> updateOne(Map<String, dynamic> filter, Map<String, dynamic> update) async {}
  Future<void> bulkWrite(List<dynamic> operations) async {}
  MongoCollection sort(Map<String, dynamic> sort) => this;
  MongoCollection skip(int n) => this;
  MongoCollection limit(int n) => this;
}

class Redis {
  Future<void> send(String command, List<String> args) async {}
}

final firestore = Firestore();
final mongodb = MongoDB();
final redis = Redis();
