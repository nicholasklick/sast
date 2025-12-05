// Insecure File Upload vulnerabilities in Kotlin
package com.example.security

import java.io.File
import java.io.InputStream
import javax.servlet.http.Part

class FileUploadVulnerabilities {

    private val uploadDir = "/var/uploads"

    // Test 1: No file type validation
    fun uploadFile(filename: String, inputStream: InputStream): Boolean {
        // VULNERABLE: No file type check
        val file = File("$uploadDir/$filename")
        file.outputStream().use { inputStream.copyTo(it) }
        return true
    }

    // Test 2: Client-provided content type
    fun uploadWithContentType(filename: String, data: ByteArray, contentType: String): Boolean {
        // VULNERABLE: Trusting client content type
        if (contentType.startsWith("image/")) {
            File("$uploadDir/$filename").writeBytes(data)
            return true
        }
        return false
    }

    // Test 3: Extension-only validation
    fun uploadImage(filename: String, data: ByteArray): Boolean {
        val validExtensions = listOf("jpg", "jpeg", "png", "gif")
        val ext = filename.substringAfterLast('.').lowercase()

        // VULNERABLE: Only checking extension
        if (ext in validExtensions) {
            File("$uploadDir/$filename").writeBytes(data)
            return true
        }
        return false
    }

    // Test 4: Path traversal in filename
    fun uploadDocument(filename: String, data: ByteArray): File? {
        // VULNERABLE: No path sanitization
        val file = File("$uploadDir/$filename")
        file.writeBytes(data)
        return file
    }

    // Test 5: No size limit
    fun uploadLargeFile(filename: String, inputStream: InputStream): Boolean {
        // VULNERABLE: No file size check (DoS)
        File("$uploadDir/$filename").outputStream().use {
            inputStream.copyTo(it)
        }
        return true
    }

    // Test 6: Double extension bypass
    fun uploadSafeFile(filename: String, data: ByteArray): Boolean {
        val ext = filename.substringAfterLast('.').lowercase()
        val dangerousExtensions = listOf("php", "jsp", "exe", "sh")

        // VULNERABLE: Can bypass with file.php.jpg
        if (ext !in dangerousExtensions) {
            File("$uploadDir/$filename").writeBytes(data)
            return true
        }
        return false
    }

    // Test 7: Servlet Part upload
    fun handlePartUpload(part: Part): Boolean {
        val filename = part.submittedFileName
        // VULNERABLE: Using submitted filename directly
        File("$uploadDir/$filename").outputStream().use {
            part.inputStream.copyTo(it)
        }
        return true
    }

    // Test 8: SVG upload (XSS vector)
    fun uploadSvg(filename: String, data: ByteArray): Boolean {
        // VULNERABLE: SVG can contain JavaScript
        if (filename.endsWith(".svg")) {
            File("$uploadDir/$filename").writeBytes(data)
            return true
        }
        return false
    }

    // Test 9: Archive upload without scanning
    fun uploadArchive(filename: String, data: ByteArray): Boolean {
        val archiveExtensions = listOf("zip", "tar", "gz")
        val ext = filename.substringAfterLast('.').lowercase()

        // VULNERABLE: No content scanning
        if (ext in archiveExtensions) {
            File("$uploadDir/$filename").writeBytes(data)
            return true
        }
        return false
    }

    // Test 10: Upload to webroot
    fun uploadToWebroot(filename: String, data: ByteArray): Boolean {
        // VULNERABLE: Uploading to web-accessible directory
        val webrootPath = "/var/www/html/uploads/$filename"
        File(webrootPath).writeBytes(data)
        return true
    }

    // Test 11: Magic bytes only check
    fun uploadImageByMagic(filename: String, data: ByteArray): Boolean {
        val pngMagic = byteArrayOf(0x89.toByte(), 0x50, 0x4E, 0x47)
        val jpgMagic = byteArrayOf(0xFF.toByte(), 0xD8.toByte(), 0xFF.toByte())

        // VULNERABLE: Only checking header, can embed code
        if (data.take(4).toByteArray().contentEquals(pngMagic) ||
            data.take(3).toByteArray().contentEquals(jpgMagic)) {
            File("$uploadDir/$filename").writeBytes(data)
            return true
        }
        return false
    }

    // Test 12: Temp file not cleaned
    fun processUpload(filename: String, data: ByteArray): Boolean {
        val tempPath = "/tmp/${java.util.UUID.randomUUID()}_$filename"
        // VULNERABLE: Temp file left on disk
        File(tempPath).writeBytes(data)
        return processFile(tempPath)
    }

    private fun processFile(path: String): Boolean = true
}
