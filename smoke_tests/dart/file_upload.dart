// File Upload vulnerabilities in Dart

import 'dart:io';
import 'dart:convert';

// Test 1: No file type validation
Future<void> vulnerableNoTypeValidation(HttpRequest request) async {
  // VULNERABLE: Accepting any file type
  var boundary = request.headers.contentType?.parameters['boundary'];
  var transformer = MimeMultipartTransformer(boundary!);
  await for (var part in transformer.bind(request)) {
    var filename = getFilename(part.headers);
    var file = File('/uploads/$filename');
    await part.pipe(file.openWrite());
  }
}

// Test 2: Client-side filename used directly
Future<void> vulnerableUnsafeFilename(String clientFilename, List<int> data) async {
  // VULNERABLE: Using client-provided filename without sanitization
  var file = File('/uploads/$clientFilename');
  await file.writeAsBytes(data);
}

// Test 3: Path traversal in upload
Future<void> vulnerablePathTraversalUpload(String filename, List<int> content) async {
  // VULNERABLE: Filename may contain ../
  var uploadPath = '/var/www/uploads/$filename';
  var file = File(uploadPath);
  await file.writeAsBytes(content);
}

// Test 4: Executable file upload
Future<void> vulnerableExecutableUpload(HttpRequest request) async {
  // VULNERABLE: No check for executable extensions
  var filename = request.headers.value('X-Filename')!;
  var content = await request.toList();
  var file = File('/uploads/$filename');
  await file.writeAsBytes(content.expand((x) => x).toList());
}

// Test 5: MIME type from client
Future<void> vulnerableTrustedMimeType(HttpRequest request) async {
  // VULNERABLE: Trusting client-provided content type
  var contentType = request.headers.contentType?.mimeType;
  if (contentType == 'image/jpeg' || contentType == 'image/png') {
    // Accepts file based on client header
    var data = await request.toList();
    await File('/uploads/image.dat').writeAsBytes(data.expand((x) => x).toList());
  }
}

// Test 6: No file size limit
Future<void> vulnerableNoSizeLimit(HttpRequest request) async {
  // VULNERABLE: No size limit on upload
  var data = <int>[];
  await for (var chunk in request) {
    data.addAll(chunk);
  }
  await File('/uploads/large_file.dat').writeAsBytes(data);
}

// Test 7: Double extension bypass
Future<void> vulnerableDoubleExtension(String filename, List<int> data) async {
  // VULNERABLE: Only checking last extension
  if (filename.endsWith('.jpg') || filename.endsWith('.png')) {
    // file.php.jpg would pass
    await File('/uploads/$filename').writeAsBytes(data);
  }
}

// Test 8: Null byte injection
Future<void> vulnerableNullByte(String filename, List<int> data) async {
  // VULNERABLE: Null byte could truncate extension check
  var uploadPath = '/uploads/$filename';
  await File(uploadPath).writeAsBytes(data);
}

// Test 9: Upload to web root
Future<void> vulnerableWebRootUpload(String filename, List<int> data) async {
  // VULNERABLE: Uploading to publicly accessible directory
  var webRoot = '/var/www/html';
  await File('$webRoot/uploads/$filename').writeAsBytes(data);
}

// Test 10: SVG upload (XSS vector)
Future<void> vulnerableSvgUpload(String svgContent) async {
  // VULNERABLE: SVG can contain JavaScript
  await File('/uploads/image.svg').writeAsString(svgContent);
}

// Test 11: ZIP file upload without scanning
Future<void> vulnerableZipUpload(List<int> zipData) async {
  // VULNERABLE: ZIP could contain malicious files
  await File('/uploads/archive.zip').writeAsBytes(zipData);
  // Extracts without validation
  await Process.run('unzip', ['/uploads/archive.zip', '-d', '/uploads/extracted']);
}

// Test 12: Overwrite existing files
Future<void> vulnerableFileOverwrite(String filename, List<int> data) async {
  // VULNERABLE: Can overwrite existing files
  var file = File('/uploads/$filename');
  await file.writeAsBytes(data); // No check if file exists
}

// Test 13: Race condition in upload
Future<void> vulnerableRaceCondition(String filename, List<int> data) async {
  // VULNERABLE: TOCTOU race condition
  var file = File('/uploads/$filename');
  if (!await file.exists()) {
    await Future.delayed(Duration(milliseconds: 10)); // Simulated delay
    await file.writeAsBytes(data);
  }
}

// Test 14: Symlink attack
Future<void> vulnerableSymlinkAttack(String filename, List<int> data) async {
  // VULNERABLE: Following symlinks
  var file = File('/uploads/$filename');
  await file.writeAsBytes(data); // May follow symlink to sensitive location
}

// Test 15: Image processing without validation
Future<void> vulnerableImageProcessing(List<int> imageData) async {
  // VULNERABLE: Processing potentially malicious image
  var tempFile = File('/tmp/temp_image.jpg');
  await tempFile.writeAsBytes(imageData);
  // ImageMagick could be vulnerable to image-based exploits
  await Process.run('convert', [tempFile.path, '-resize', '100x100', '/uploads/thumb.jpg']);
}

// Helper functions
String? getFilename(Map<String, String> headers) {
  var contentDisposition = headers['content-disposition'];
  if (contentDisposition != null) {
    var match = RegExp(r'filename="([^"]*)"').firstMatch(contentDisposition);
    return match?.group(1);
  }
  return null;
}

// Mock transformer
class MimeMultipartTransformer extends StreamTransformerBase<List<int>, MimeMultipart> {
  final String boundary;
  MimeMultipartTransformer(this.boundary);

  @override
  Stream<MimeMultipart> bind(Stream<List<int>> stream) {
    throw UnimplementedError();
  }
}

class MimeMultipart extends Stream<List<int>> {
  final Map<String, String> headers = {};

  @override
  StreamSubscription<List<int>> listen(void Function(List<int>)? onData, {Function? onError, void Function()? onDone, bool? cancelOnError}) {
    throw UnimplementedError();
  }
}
