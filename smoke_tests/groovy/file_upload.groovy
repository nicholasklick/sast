// Insecure File Upload vulnerabilities in Groovy
package com.example.security

class FileUploadVulnerabilities {

    String uploadDir = "/var/uploads"

    // Test 1: No file type validation
    boolean uploadFile(String filename, InputStream inputStream) {
        // VULNERABLE: No file type check
        def file = new File("${uploadDir}/${filename}")
        file.bytes = inputStream.bytes
        true
    }

    // Test 2: Client-provided content type
    boolean uploadWithContentType(String filename, byte[] data, String contentType) {
        // VULNERABLE: Trusting client content type
        if (contentType.startsWith("image/")) {
            new File("${uploadDir}/${filename}").bytes = data
            return true
        }
        false
    }

    // Test 3: Extension-only validation
    boolean uploadImage(String filename, byte[] data) {
        def validExtensions = ["jpg", "jpeg", "png", "gif"]
        def ext = filename.tokenize('.').last().toLowerCase()

        // VULNERABLE: Only checking extension
        if (ext in validExtensions) {
            new File("${uploadDir}/${filename}").bytes = data
            return true
        }
        false
    }

    // Test 4: Path traversal in filename
    File uploadDocument(String filename, byte[] data) {
        // VULNERABLE: No path sanitization
        def file = new File("${uploadDir}/${filename}")
        file.bytes = data
        file
    }

    // Test 5: No size limit
    boolean uploadLargeFile(String filename, InputStream inputStream) {
        // VULNERABLE: No file size check (DoS)
        new File("${uploadDir}/${filename}").bytes = inputStream.bytes
        true
    }

    // Test 6: Double extension bypass
    boolean uploadSafeFile(String filename, byte[] data) {
        def ext = filename.tokenize('.').last().toLowerCase()
        def dangerousExtensions = ["php", "jsp", "exe", "sh"]

        // VULNERABLE: Can bypass with file.php.jpg
        if (!(ext in dangerousExtensions)) {
            new File("${uploadDir}/${filename}").bytes = data
            return true
        }
        false
    }

    // Test 7: SVG upload (XSS vector)
    boolean uploadSvg(String filename, byte[] data) {
        // VULNERABLE: SVG can contain JavaScript
        if (filename.endsWith(".svg")) {
            new File("${uploadDir}/${filename}").bytes = data
            return true
        }
        false
    }

    // Test 8: Archive upload without scanning
    boolean uploadArchive(String filename, byte[] data) {
        def archiveExtensions = ["zip", "tar", "gz"]
        def ext = filename.tokenize('.').last().toLowerCase()

        // VULNERABLE: No content scanning
        if (ext in archiveExtensions) {
            new File("${uploadDir}/${filename}").bytes = data
            return true
        }
        false
    }

    // Test 9: Upload to webroot
    boolean uploadToWebroot(String filename, byte[] data) {
        // VULNERABLE: Uploading to web-accessible directory
        new File("/var/www/html/uploads/${filename}").bytes = data
        true
    }

    // Test 10: Groovy withOutputStream
    boolean uploadWithStream(String filename, byte[] data) {
        // VULNERABLE: Direct filename use
        new File("${uploadDir}/${filename}").withOutputStream { out ->
            out.write(data)
        }
        true
    }

    // Test 11: Magic bytes only check
    boolean uploadImageByMagic(String filename, byte[] data) {
        def pngMagic = [0x89, 0x50, 0x4E, 0x47] as byte[]
        def jpgMagic = [0xFF, 0xD8, 0xFF] as byte[]

        // VULNERABLE: Only checking header, can embed code
        if (data.take(4) == pngMagic.toList() || data.take(3) == jpgMagic.toList()) {
            new File("${uploadDir}/${filename}").bytes = data
            return true
        }
        false
    }

    // Test 12: Temp file not cleaned
    boolean processUpload(String filename, byte[] data) {
        def tempPath = "/tmp/${UUID.randomUUID()}_${filename}"
        // VULNERABLE: Temp file left on disk
        new File(tempPath).bytes = data
        processFile(tempPath)
    }

    private boolean processFile(String path) { true }
}
