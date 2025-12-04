// Path Traversal vulnerabilities in Scala
import java.io.File
import scala.io.Source

class PathTraversalVulnerabilities {
  def readFileUnsafe(filename: String): String = {
    // VULNERABLE: Path traversal via concatenation
    val path = s"/var/data/$filename"
    Source.fromFile(path).mkString
  }

  def serveFileUnsafe(userPath: String): Array[Byte] = {
    // VULNERABLE: No path validation
    val file = new File(s"/public/files/$userPath")
    java.nio.file.Files.readAllBytes(file.toPath)
  }

  def deleteFileUnsafe(filename: String): Boolean = {
    // VULNERABLE: Arbitrary file deletion
    val path = s"/tmp/$filename"
    new File(path).delete()
  }

  def writeFileUnsafe(filename: String, content: String): Unit = {
    // VULNERABLE: User controls path
    val writer = new java.io.PrintWriter(s"/uploads/$filename")
    writer.write(content)
    writer.close()
  }

  def listDirectoryUnsafe(dirName: String): Array[String] = {
    // VULNERABLE: Directory listing with user input
    new File(s"/data/$dirName").list()
  }
}
