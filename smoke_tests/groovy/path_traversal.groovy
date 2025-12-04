// Path Traversal vulnerabilities in Groovy
package com.example.vulnerabilities

class PathTraversalVulnerabilities {
    String readFileUnsafe(String filename) {
        // VULNERABLE: Path traversal via concatenation
        return new File("/var/data/${filename}").text
    }

    byte[] serveFileUnsafe(String userPath) {
        // VULNERABLE: No path validation
        return new File("/public/files/${userPath}").bytes
    }

    boolean deleteFileUnsafe(String filename) {
        // VULNERABLE: Arbitrary file deletion
        return new File("/tmp/${filename}").delete()
    }

    void writeFileUnsafe(String filename, String content) {
        // VULNERABLE: User controls path
        new File("/uploads/${filename}").text = content
    }

    String[] listDirectoryUnsafe(String dirName) {
        // VULNERABLE: Directory listing with user input
        return new File("/data/${dirName}").list()
    }
}
