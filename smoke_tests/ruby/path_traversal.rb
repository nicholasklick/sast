# Path Traversal vulnerabilities in Ruby
require 'fileutils'

class PathTraversalVulnerabilities
  def read_file_unsafe(filename)
    # VULNERABLE: Path traversal via concatenation
    path = "/var/data/#{filename}"
    File.read(path)
  end

  def serve_file_unsafe(user_path)
    # VULNERABLE: No path validation
    File.read(File.join('/public/files', user_path))
  end

  def delete_file_unsafe(filename)
    # VULNERABLE: Arbitrary file deletion
    path = "/tmp/#{filename}"
    File.delete(path)
  end

  def write_file_unsafe(filename, content)
    # VULNERABLE: User controls path
    File.write("/uploads/#{filename}", content)
  end

  def send_file_unsafe(requested_path)
    # VULNERABLE: Direct file serving
    send_file("/public/#{requested_path}")
  end

  def copy_file_unsafe(src, dest)
    # VULNERABLE: Arbitrary file copy
    FileUtils.cp(src, dest)
  end
end
