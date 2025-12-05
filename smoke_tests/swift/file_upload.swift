// Insecure File Upload vulnerabilities in Swift
import Foundation

class FileUploadVulnerabilities {

    let uploadDir = "/var/uploads"

    // Test 1: No file type validation
    func uploadFile(filename: String, data: Data) -> Bool {
        // VULNERABLE: No file type check
        let path = "\(uploadDir)/\(filename)"
        return FileManager.default.createFile(atPath: path, contents: data)
    }

    // Test 2: Client-provided content type
    func uploadWithContentType(filename: String, data: Data, contentType: String) -> Bool {
        // VULNERABLE: Trusting client content type
        if contentType.hasPrefix("image/") {
            let path = "\(uploadDir)/\(filename)"
            return FileManager.default.createFile(atPath: path, contents: data)
        }
        return false
    }

    // Test 3: Extension-only validation
    func uploadImage(filename: String, data: Data) -> Bool {
        let validExtensions = ["jpg", "jpeg", "png", "gif"]
        let ext = (filename as NSString).pathExtension.lowercased()

        // VULNERABLE: Only checking extension, not content
        if validExtensions.contains(ext) {
            let path = "\(uploadDir)/\(filename)"
            return FileManager.default.createFile(atPath: path, contents: data)
        }
        return false
    }

    // Test 4: Executable upload
    func uploadScript(filename: String, data: Data) -> Bool {
        // VULNERABLE: Allows executable uploads
        let path = "\(uploadDir)/\(filename)"
        FileManager.default.createFile(atPath: path, contents: data)
        // Make executable
        try? FileManager.default.setAttributes(
            [.posixPermissions: 0o755],
            ofItemAtPath: path
        )
        return true
    }

    // Test 5: No size limit
    func uploadLargeFile(filename: String, data: Data) -> Bool {
        // VULNERABLE: No file size check (DoS risk)
        let path = "\(uploadDir)/\(filename)"
        return FileManager.default.createFile(atPath: path, contents: data)
    }

    // Test 6: Path traversal in filename
    func uploadDocument(filename: String, data: Data) -> URL? {
        // VULNERABLE: No sanitization of filename
        let path = "\(uploadDir)/\(filename)"
        if FileManager.default.createFile(atPath: path, contents: data) {
            return URL(fileURLWithPath: path)
        }
        return nil
    }

    // Test 7: Double extension bypass
    func uploadSafeFile(filename: String, data: Data) -> Bool {
        // VULNERABLE: Can bypass with file.php.jpg
        let ext = (filename as NSString).pathExtension.lowercased()
        let dangerousExtensions = ["php", "exe", "sh", "bat"]

        if dangerousExtensions.contains(ext) {
            return false
        }
        let path = "\(uploadDir)/\(filename)"
        return FileManager.default.createFile(atPath: path, contents: data)
    }

    // Test 8: Null byte injection
    func uploadWithNullByte(filename: String, data: Data) -> Bool {
        // VULNERABLE: Null byte in filename
        let path = "\(uploadDir)/\(filename)"
        return FileManager.default.createFile(atPath: path, contents: data)
    }

    // Test 9: SVG upload (XSS vector)
    func uploadSvg(filename: String, data: Data) -> Bool {
        // VULNERABLE: SVG can contain JavaScript
        if filename.hasSuffix(".svg") {
            let path = "\(uploadDir)/\(filename)"
            return FileManager.default.createFile(atPath: path, contents: data)
        }
        return false
    }

    // Test 10: Archive upload without scanning
    func uploadArchive(filename: String, data: Data) -> Bool {
        let archiveExtensions = ["zip", "tar", "gz"]
        let ext = (filename as NSString).pathExtension.lowercased()

        // VULNERABLE: No content scanning of archives
        if archiveExtensions.contains(ext) {
            let path = "\(uploadDir)/\(filename)"
            return FileManager.default.createFile(atPath: path, contents: data)
        }
        return false
    }

    // Test 11: Upload to web-accessible directory
    func uploadToWebroot(filename: String, data: Data) -> Bool {
        // VULNERABLE: Uploading to web-accessible location
        let webrootPath = "/var/www/html/uploads/\(filename)"
        return FileManager.default.createFile(atPath: webrootPath, contents: data)
    }

    // Test 12: Image with embedded PHP
    func uploadImageFile(filename: String, data: Data) -> Bool {
        // VULNERABLE: Image magic bytes but embedded code
        let header = data.prefix(8)
        let pngMagic = Data([0x89, 0x50, 0x4E, 0x47])
        let jpgMagic = Data([0xFF, 0xD8, 0xFF])

        if header.starts(with: pngMagic) || header.starts(with: jpgMagic) {
            // Only checking header, not full content
            let path = "\(uploadDir)/\(filename)"
            return FileManager.default.createFile(atPath: path, contents: data)
        }
        return false
    }

    // Test 13: Temporary file not cleaned up
    func processUpload(filename: String, data: Data) -> Bool {
        let tempPath = "/tmp/\(UUID().uuidString)_\(filename)"
        // VULNERABLE: Temp file left on disk
        FileManager.default.createFile(atPath: tempPath, contents: data)
        // Process file but never delete temp
        return processFile(path: tempPath)
    }

    private func processFile(path: String) -> Bool { true }
}
