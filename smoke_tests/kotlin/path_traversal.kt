// Path Traversal vulnerabilities in Kotlin
import java.io.File

class PathTraversalVulnerabilities {
    fun readFileUnsafe(filename: String): String {
        // VULNERABLE: Path traversal via concatenation
        val path = "/var/data/$filename"
        return File(path).readText()
    }

    fun serveFileUnsafe(userPath: String): ByteArray {
        // VULNERABLE: No path validation
        val file = File("/public/files", userPath)
        return file.readBytes()
    }

    fun deleteFileUnsafe(filename: String) {
        // VULNERABLE: Arbitrary file deletion
        val path = "/tmp/$filename"
        File(path).delete()
    }

    fun writeFileUnsafe(filename: String, content: String) {
        // VULNERABLE: User controls path
        File("/uploads/$filename").writeText(content)
    }

    fun listDirectoryUnsafe(dirName: String): List<String> {
        // VULNERABLE: Directory listing with user input
        return File("/data/$dirName").list()?.toList() ?: emptyList()
    }
}
