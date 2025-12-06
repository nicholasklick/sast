// Zip Slip vulnerabilities in Dart

import 'dart:io';
import 'package:archive/archive.dart';

// Test 1: Basic zip slip vulnerability
Future<void> vulnerableZipExtract(String zipPath, String destDir) async {
  // VULNERABLE: No path validation during extraction
  var bytes = await File(zipPath).readAsBytes();
  var archive = ZipDecoder().decodeBytes(bytes);

  for (var file in archive) {
    var filename = file.name;
    // VULNERABLE: filename could contain ../
    var outFile = File('$destDir/$filename');

    if (file.isFile) {
      await outFile.create(recursive: true);
      await outFile.writeAsBytes(file.content as List<int>);
    }
  }
}

// Test 2: Tar extraction without validation
Future<void> vulnerableTarExtract(String tarPath, String destDir) async {
  // VULNERABLE: Tar files can also contain path traversal
  var bytes = await File(tarPath).readAsBytes();
  var archive = TarDecoder().decodeBytes(bytes);

  for (var file in archive) {
    var outPath = '$destDir/${file.name}';
    // VULNERABLE: No path normalization
    var outFile = File(outPath);
    await outFile.create(recursive: true);
    await outFile.writeAsBytes(file.content as List<int>);
  }
}

// Test 3: Gzip extraction
Future<void> vulnerableGzipExtract(String gzPath, String outputPath) async {
  // VULNERABLE: Output path from user input
  var bytes = await File(gzPath).readAsBytes();
  var decompressed = GZipDecoder().decodeBytes(bytes);
  await File(outputPath).writeAsBytes(decompressed);
}

// Test 4: Using entry name directly
Future<void> vulnerableEntryName(Archive archive, String baseDir) async {
  for (var entry in archive) {
    // VULNERABLE: Using entry name without sanitization
    var targetPath = '$baseDir/${entry.name}';
    await File(targetPath).writeAsBytes(entry.content as List<int>);
  }
}

// Test 5: Symbolic link following
Future<void> vulnerableSymlinkExtract(String zipPath, String destDir) async {
  // VULNERABLE: Archive may contain symlinks pointing outside
  var bytes = await File(zipPath).readAsBytes();
  var archive = ZipDecoder().decodeBytes(bytes);

  for (var file in archive) {
    var outPath = '$destDir/${file.name}';
    // VULNERABLE: Symlinks could point to sensitive files
    if (file.isSymbolicLink) {
      await Link(outPath).create(String.fromCharCodes(file.content as List<int>));
    } else {
      await File(outPath).writeAsBytes(file.content as List<int>);
    }
  }
}

// Test 6: Insufficient path check
Future<void> vulnerableWeakCheck(String filename, String destDir, List<int> content) async {
  // VULNERABLE: Weak check that can be bypassed
  if (!filename.startsWith('..')) {
    // foo/../../../etc/passwd would pass
    await File('$destDir/$filename').writeAsBytes(content);
  }
}

// Test 7: Path join without normalization
Future<void> vulnerablePathJoin(String baseDir, String entryName, List<int> content) async {
  // VULNERABLE: Path.join doesn't prevent traversal
  var outputPath = '$baseDir/$entryName';
  await File(outputPath).writeAsBytes(content);
}

// Test 8: Extraction to temp directory
Future<void> vulnerableTempExtract(String zipPath) async {
  // VULNERABLE: Even temp dir can be escaped
  var tempDir = Directory.systemTemp.path;
  var bytes = await File(zipPath).readAsBytes();
  var archive = ZipDecoder().decodeBytes(bytes);

  for (var file in archive) {
    var outPath = '$tempDir/${file.name}';
    await File(outPath).writeAsBytes(file.content as List<int>);
  }
}

// Test 9: User-provided destination
Future<void> vulnerableUserDestination(String zipPath, String userDestDir) async {
  // VULNERABLE: User controls both zip and destination
  var bytes = await File(zipPath).readAsBytes();
  var archive = ZipDecoder().decodeBytes(bytes);

  for (var file in archive) {
    await File('$userDestDir/${file.name}').writeAsBytes(file.content as List<int>);
  }
}

// Test 10: Nested archive extraction
Future<void> vulnerableNestedArchive(String zipPath, String destDir) async {
  // VULNERABLE: Inner archives also need validation
  var bytes = await File(zipPath).readAsBytes();
  var archive = ZipDecoder().decodeBytes(bytes);

  for (var file in archive) {
    if (file.name.endsWith('.zip')) {
      // Extract inner zip without validation
      var innerArchive = ZipDecoder().decodeBytes(file.content as List<int>);
      for (var inner in innerArchive) {
        await File('$destDir/${inner.name}').writeAsBytes(inner.content as List<int>);
      }
    }
  }
}

// Test 11: Archive from URL
Future<void> vulnerableRemoteArchive(String url, String destDir) async {
  // VULNERABLE: Extracting untrusted remote archive
  var client = HttpClient();
  var request = await client.getUrl(Uri.parse(url));
  var response = await request.close();
  var bytes = await response.fold<List<int>>([], (a, b) => a..addAll(b));

  var archive = ZipDecoder().decodeBytes(bytes);
  for (var file in archive) {
    await File('$destDir/${file.name}').writeAsBytes(file.content as List<int>);
  }
}

// Test 12: Overwriting existing files
Future<void> vulnerableOverwrite(String zipPath, String destDir) async {
  // VULNERABLE: Can overwrite existing files
  var bytes = await File(zipPath).readAsBytes();
  var archive = ZipDecoder().decodeBytes(bytes);

  for (var file in archive) {
    var outFile = File('$destDir/${file.name}');
    // No check if file already exists
    await outFile.writeAsBytes(file.content as List<int>);
  }
}

// Test 13: Directory creation from archive
Future<void> vulnerableDirCreation(String zipPath, String destDir) async {
  // VULNERABLE: Creating directories from archive paths
  var bytes = await File(zipPath).readAsBytes();
  var archive = ZipDecoder().decodeBytes(bytes);

  for (var file in archive) {
    var outPath = '$destDir/${file.name}';
    if (file.isFile) {
      await File(outPath).create(recursive: true);
      await File(outPath).writeAsBytes(file.content as List<int>);
    } else {
      await Directory(outPath).create(recursive: true);
    }
  }
}

// Test 14: Stream-based extraction
Future<void> vulnerableStreamExtract(Stream<List<int>> zipStream, String destDir) async {
  // VULNERABLE: Stream extraction also needs validation
  var bytes = await zipStream.fold<List<int>>([], (a, b) => a..addAll(b));
  var archive = ZipDecoder().decodeBytes(bytes);

  for (var file in archive) {
    await File('$destDir/${file.name}').writeAsBytes(file.content as List<int>);
  }
}

// Test 15: Absolute path in archive
Future<void> vulnerableAbsolutePath(Archive archive, String destDir) async {
  for (var file in archive) {
    String outputPath;
    if (file.name.startsWith('/')) {
      // VULNERABLE: Using absolute path from archive
      outputPath = file.name;
    } else {
      outputPath = '$destDir/${file.name}';
    }
    await File(outputPath).writeAsBytes(file.content as List<int>);
  }
}

// Mock archive classes (simplified)
class Archive extends Iterable<ArchiveFile> {
  @override
  Iterator<ArchiveFile> get iterator => throw UnimplementedError();
}

class ArchiveFile {
  final String name;
  final dynamic content;
  final bool isFile;
  final bool isSymbolicLink;

  ArchiveFile(this.name, this.content, {this.isFile = true, this.isSymbolicLink = false});
}

class ZipDecoder {
  Archive decodeBytes(List<int> bytes) => Archive();
}

class TarDecoder {
  Archive decodeBytes(List<int> bytes) => Archive();
}

class GZipDecoder {
  List<int> decodeBytes(List<int> bytes) => [];
}
