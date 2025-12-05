// Insecure File Upload vulnerabilities in Scala
package com.example.security

import java.io.{File, FileOutputStream, InputStream}

class FileUploadVulnerabilities {

  private val uploadDir = "/var/uploads"

  // Test 1: No file type validation
  def uploadFile(filename: String, inputStream: InputStream): Boolean = {
    // VULNERABLE: No file type check
    val file = new File(s"$uploadDir/$filename")
    val fos = new FileOutputStream(file)
    val buffer = new Array[Byte](1024)
    Iterator.continually(inputStream.read(buffer)).takeWhile(_ != -1).foreach(fos.write(buffer, 0, _))
    fos.close()
    true
  }

  // Test 2: Client-provided content type
  def uploadWithContentType(filename: String, data: Array[Byte], contentType: String): Boolean = {
    // VULNERABLE: Trusting client content type
    if (contentType.startsWith("image/")) {
      val file = new File(s"$uploadDir/$filename")
      val fos = new FileOutputStream(file)
      fos.write(data)
      fos.close()
      true
    } else {
      false
    }
  }

  // Test 3: Extension-only validation
  def uploadImage(filename: String, data: Array[Byte]): Boolean = {
    val validExtensions = Set("jpg", "jpeg", "png", "gif")
    val ext = filename.split('.').lastOption.getOrElse("").toLowerCase

    // VULNERABLE: Only checking extension
    if (validExtensions.contains(ext)) {
      val file = new File(s"$uploadDir/$filename")
      val fos = new FileOutputStream(file)
      fos.write(data)
      fos.close()
      true
    } else {
      false
    }
  }

  // Test 4: Path traversal in filename
  def uploadDocument(filename: String, data: Array[Byte]): Option[File] = {
    // VULNERABLE: No path sanitization
    val file = new File(s"$uploadDir/$filename")
    val fos = new FileOutputStream(file)
    fos.write(data)
    fos.close()
    Some(file)
  }

  // Test 5: No size limit
  def uploadLargeFile(filename: String, inputStream: InputStream): Boolean = {
    // VULNERABLE: No file size check (DoS)
    val file = new File(s"$uploadDir/$filename")
    val fos = new FileOutputStream(file)
    val buffer = new Array[Byte](8192)
    Iterator.continually(inputStream.read(buffer)).takeWhile(_ != -1).foreach(fos.write(buffer, 0, _))
    fos.close()
    true
  }

  // Test 6: Double extension bypass
  def uploadSafeFile(filename: String, data: Array[Byte]): Boolean = {
    val ext = filename.split('.').lastOption.getOrElse("").toLowerCase
    val dangerousExtensions = Set("php", "jsp", "exe", "sh")

    // VULNERABLE: Can bypass with file.php.jpg
    if (!dangerousExtensions.contains(ext)) {
      val file = new File(s"$uploadDir/$filename")
      val fos = new FileOutputStream(file)
      fos.write(data)
      fos.close()
      true
    } else {
      false
    }
  }

  // Test 7: SVG upload (XSS vector)
  def uploadSvg(filename: String, data: Array[Byte]): Boolean = {
    // VULNERABLE: SVG can contain JavaScript
    if (filename.endsWith(".svg")) {
      val file = new File(s"$uploadDir/$filename")
      val fos = new FileOutputStream(file)
      fos.write(data)
      fos.close()
      true
    } else {
      false
    }
  }

  // Test 8: Archive upload without scanning
  def uploadArchive(filename: String, data: Array[Byte]): Boolean = {
    val archiveExtensions = Set("zip", "tar", "gz")
    val ext = filename.split('.').lastOption.getOrElse("").toLowerCase

    // VULNERABLE: No content scanning
    if (archiveExtensions.contains(ext)) {
      val file = new File(s"$uploadDir/$filename")
      val fos = new FileOutputStream(file)
      fos.write(data)
      fos.close()
      true
    } else {
      false
    }
  }

  // Test 9: Upload to webroot
  def uploadToWebroot(filename: String, data: Array[Byte]): Boolean = {
    // VULNERABLE: Uploading to web-accessible directory
    val file = new File(s"/var/www/html/uploads/$filename")
    val fos = new FileOutputStream(file)
    fos.write(data)
    fos.close()
    true
  }

  // Test 10: Play Framework multipart (conceptual)
  def handlePlayUpload(filename: String, tempFile: File): Boolean = {
    // VULNERABLE: Using original filename
    tempFile.renameTo(new File(s"$uploadDir/$filename"))
  }

  // Test 11: Temp file not cleaned
  def processUpload(filename: String, data: Array[Byte]): Boolean = {
    val tempPath = s"/tmp/${java.util.UUID.randomUUID()}_$filename"
    // VULNERABLE: Temp file left on disk
    val file = new File(tempPath)
    val fos = new FileOutputStream(file)
    fos.write(data)
    fos.close()
    processFile(tempPath)
  }

  // Test 12: Akka HTTP file upload
  def akkaUpload(filename: String, data: Array[Byte]): Boolean = {
    // VULNERABLE: Direct filename use
    val file = new File(s"$uploadDir/$filename")
    val fos = new FileOutputStream(file)
    fos.write(data)
    fos.close()
    true
  }

  private def processFile(path: String): Boolean = true
}
