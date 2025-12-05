// Zip Slip Test Cases

import * as fs from 'fs';
import * as path from 'path';

// Test 1: Extracting zip without path validation
function extractZipEntry(entry: any, destDir: string): void {
    const fileName = entry.fileName;
    const destPath = path.join(destDir, fileName);
    // VULNERABLE: No validation - fileName could be "../../../etc/passwd"
    fs.writeFileSync(destPath, entry.getData());
}

// Test 2: Tar extraction without sanitization
function extractTarFile(entryPath: string, outputDir: string, data: Buffer): void {
    // VULNERABLE: Direct path join without sanitization
    const outputPath = outputDir + '/' + entryPath;
    fs.writeFileSync(outputPath, data);
}

// Test 3: Archive extraction with normalize but no validation
function extractArchive(entry: any, baseDir: string): void {
    const normalizedPath = path.normalize(entry.name);
    const fullPath = path.join(baseDir, normalizedPath);
    // VULNERABLE: normalize doesn't prevent path traversal
    fs.mkdirSync(path.dirname(fullPath), { recursive: true });
    fs.writeFileSync(fullPath, entry.data);
}

// Test 4: Using user-provided filename
function saveUploadedArchiveEntry(filename: string, content: Buffer, uploadDir: string): void {
    // VULNERABLE: filename from archive could contain ../
    const filePath = `${uploadDir}/${filename}`;
    fs.writeFileSync(filePath, content);
}

// Test 5: Concatenating paths without validation
function unpackFile(archiveEntry: any, destination: string): void {
    const targetPath = destination + path.sep + archiveEntry.path;
    // VULNERABLE: No check if targetPath escapes destination
    const dir = path.dirname(targetPath);
    if (!fs.existsSync(dir)) {
        fs.mkdirSync(dir, { recursive: true });
    }
    fs.writeFileSync(targetPath, archiveEntry.content);
}
