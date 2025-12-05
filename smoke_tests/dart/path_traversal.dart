// Path Traversal vulnerabilities in Dart

import 'dart:io';

// Test 1: File read with user path
Future<String> vulnerableFileRead(String userPath) async {
  // VULNERABLE: Path traversal via user input
  var file = File(userPath);
  return await file.readAsString();
}

// Test 2: File read with base path concatenation
Future<String> vulnerablePathConcat(String filename) async {
  // VULNERABLE: Path traversal via concatenation
  var file = File('/var/data/' + filename);
  return await file.readAsString();
}

// Test 3: File write with user path
Future<void> vulnerableFileWrite(String userPath, String content) async {
  // VULNERABLE: Arbitrary file write
  var file = File(userPath);
  await file.writeAsString(content);
}

// Test 4: File delete with user path
Future<void> vulnerableFileDelete(String userPath) async {
  // VULNERABLE: Arbitrary file deletion
  var file = File(userPath);
  await file.delete();
}

// Test 5: Directory listing with user path
Future<List<FileSystemEntity>> vulnerableDirList(String userDir) async {
  // VULNERABLE: Directory traversal
  var dir = Directory(userDir);
  return await dir.list().toList();
}

// Test 6: Directory creation with user path
Future<void> vulnerableDirCreate(String userDir) async {
  // VULNERABLE: Arbitrary directory creation
  var dir = Directory(userDir);
  await dir.create(recursive: true);
}

// Test 7: File copy with user paths
Future<void> vulnerableFileCopy(String src, String dst) async {
  // VULNERABLE: Path traversal in copy
  var srcFile = File(src);
  await srcFile.copy(dst);
}

// Test 8: File rename/move with user paths
Future<void> vulnerableFileRename(String oldPath, String newPath) async {
  // VULNERABLE: Path traversal in rename
  var file = File(oldPath);
  await file.rename(newPath);
}

// Test 9: Symlink creation with user paths
Future<void> vulnerableSymlink(String target, String link) async {
  // VULNERABLE: Symlink attack
  var linkEntity = Link(link);
  await linkEntity.create(target);
}

// Test 10: File path from query parameter
Future<String> vulnerableQueryParam(Uri uri) async {
  // VULNERABLE: Path from query parameter
  var filename = uri.queryParameters['file'];
  if (filename != null) {
    return await File('/uploads/$filename').readAsString();
  }
  return '';
}

// Test 11: Archive extraction with user path
Future<void> vulnerableArchiveExtract(String archivePath, String destDir) async {
  // VULNERABLE: Zip slip
  await Process.run('unzip', [archivePath, '-d', destDir]);
}

// Test 12: File from form data
Future<void> vulnerableFormUpload(String uploadedFilename, List<int> data) async {
  // VULNERABLE: User-controlled filename
  var file = File('/uploads/$uploadedFilename');
  await file.writeAsBytes(data);
}

// Test 13: Path with URL decoding
Future<String> vulnerableUrlDecoded(String encodedPath) async {
  // VULNERABLE: URL-decoded path
  var decodedPath = Uri.decodeComponent(encodedPath);
  return await File(decodedPath).readAsString();
}

// Test 14: FileSystemEntity.type with user path
Future<void> vulnerableFileType(String path) async {
  // VULNERABLE: Information disclosure
  var type = await FileSystemEntity.type(path);
  print('Type: $type');
}

// Test 15: RandomAccessFile with user path
Future<void> vulnerableRandomAccess(String path) async {
  // VULNERABLE: Direct file access
  var file = await File(path).open(mode: FileMode.read);
  var contents = await file.read(1024);
  await file.close();
}
