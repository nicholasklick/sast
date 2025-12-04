// Path Traversal vulnerabilities in Swift
import Foundation

class PathTraversalVulnerabilities {
    func readFileUnsafe(filename: String) throws -> String {
        // VULNERABLE: Path traversal via concatenation
        let path = "/var/data/\(filename)"
        return try String(contentsOfFile: path, encoding: .utf8)
    }

    func serveFileUnsafe(userPath: String) throws -> Data {
        // VULNERABLE: No path validation
        let url = URL(fileURLWithPath: "/public/files/\(userPath)")
        return try Data(contentsOf: url)
    }

    func deleteFileUnsafe(filename: String) throws {
        // VULNERABLE: Arbitrary file deletion
        let path = "/tmp/\(filename)"
        try FileManager.default.removeItem(atPath: path)
    }

    func writeFileUnsafe(filename: String, content: String) throws {
        // VULNERABLE: User controls path
        let path = "/uploads/\(filename)"
        try content.write(toFile: path, atomically: true, encoding: .utf8)
    }

    func listDirectoryUnsafe(dirName: String) throws -> [String] {
        // VULNERABLE: Directory listing with user input
        let path = "/data/\(dirName)"
        return try FileManager.default.contentsOfDirectory(atPath: path)
    }
}
