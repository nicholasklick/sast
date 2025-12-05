// Race Condition vulnerabilities in Dart

import 'dart:io';
import 'dart:async';

// Test 1: TOCTOU in file check
Future<String> vulnerableToctouRead(String path) async {
  // VULNERABLE: Time-of-check to time-of-use
  var file = File(path);
  if (await file.exists()) {
    return await file.readAsString();
  }
  throw Exception('File not found');
}

// Test 2: TOCTOU in file write
Future<void> vulnerableToctouWrite(String path, String content) async {
  // VULNERABLE: Check then write race condition
  var file = File(path);
  if (!await file.exists()) {
    await file.writeAsString(content);
  }
}

// Test 3: TOCTOU in directory check
Future<void> vulnerableToctouDir(String dirPath) async {
  // VULNERABLE: Directory race condition
  var dir = Directory(dirPath);
  if (!await dir.exists()) {
    await dir.create();
  }
}

// Test 4: Non-atomic counter
class VulnerableCounter {
  int count = 0;

  // VULNERABLE: Non-atomic increment
  void increment() {
    var current = count;
    count = current + 1;
  }
}

// Test 5: Non-atomic balance update
class VulnerableAccount {
  double balance = 0;

  // VULNERABLE: Non-atomic transfer
  Future<void> transfer(VulnerableAccount to, double amount) async {
    if (balance >= amount) {
      balance -= amount;
      await Future.delayed(Duration(milliseconds: 1)); // Simulate async
      to.balance += amount;
    }
  }
}

// Test 6: Shared state without synchronization
class VulnerableCache {
  final Map<String, dynamic> _cache = {};

  // VULNERABLE: No synchronization on shared state
  void set(String key, dynamic value) {
    _cache[key] = value;
  }

  dynamic get(String key) {
    return _cache[key];
  }
}

// Test 7: File lock race
Future<void> vulnerableLockFile(String lockPath) async {
  // VULNERABLE: Lock file race condition
  var lockFile = File(lockPath);
  if (!await lockFile.exists()) {
    await lockFile.writeAsString('locked');
    // Critical section
    await lockFile.delete();
  }
}

// Test 8: Double-checked locking (incorrect)
class VulnerableSingleton {
  static VulnerableSingleton? _instance;

  // VULNERABLE: Double-checked locking doesn't work in Dart the same way
  static VulnerableSingleton getInstance() {
    if (_instance == null) {
      _instance = VulnerableSingleton._();
    }
    return _instance!;
  }

  VulnerableSingleton._();
}

// Test 9: Parallel modification of list
Future<void> vulnerableParallelListMod(List<int> list) async {
  // VULNERABLE: Parallel modification without synchronization
  await Future.wait([
    Future(() => list.add(1)),
    Future(() => list.add(2)),
    Future(() => list.removeAt(0)),
  ]);
}

// Test 10: Race in initialization
class VulnerableInit {
  String? _data;
  bool _initialized = false;

  // VULNERABLE: Race in lazy initialization
  Future<String> getData() async {
    if (!_initialized) {
      _data = await _loadData();
      _initialized = true;
    }
    return _data!;
  }

  Future<String> _loadData() async {
    await Future.delayed(Duration(milliseconds: 100));
    return 'data';
  }
}

// Test 11: Session race
class VulnerableSession {
  String? token;

  // VULNERABLE: Race in session update
  Future<void> updateToken(String newToken) async {
    await Future.delayed(Duration(milliseconds: 10));
    token = newToken;
  }
}

// Test 12: Resource pool race
class VulnerableResourcePool {
  final List<String> _available = ['r1', 'r2', 'r3'];

  // VULNERABLE: Race in resource acquisition
  String? acquire() {
    if (_available.isNotEmpty) {
      return _available.removeLast();
    }
    return null;
  }
}

// Test 13: Flag race
class VulnerableFlag {
  bool isRunning = false;

  // VULNERABLE: Race on flag
  Future<void> start() async {
    if (!isRunning) {
      isRunning = true;
      await _doWork();
      isRunning = false;
    }
  }

  Future<void> _doWork() async {
    await Future.delayed(Duration(seconds: 1));
  }
}

// Test 14: Counter race in loop
Future<int> vulnerableLoopCounter() async {
  int count = 0;

  // VULNERABLE: Race in parallel loop
  await Future.wait(
    List.generate(100, (_) => Future(() => count++))
  );

  return count;
}

// Test 15: Temp file race
Future<void> vulnerableTempFileRace(String data) async {
  // VULNERABLE: Temp file race condition
  var tempPath = '/tmp/app_${DateTime.now().millisecondsSinceEpoch}.tmp';
  var file = File(tempPath);

  if (!await file.exists()) {
    await file.writeAsString(data);
  }
}
