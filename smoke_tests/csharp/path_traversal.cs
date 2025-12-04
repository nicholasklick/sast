// Path Traversal vulnerabilities in C#
using System;
using System.IO;

public class PathTraversalVulnerabilities
{
    public string ReadFileUnsafe(string filename)
    {
        // VULNERABLE: Path traversal via concatenation
        string path = "/var/data/" + filename;
        return File.ReadAllText(path);
    }

    public byte[] DownloadFileUnsafe(string fileName)
    {
        // VULNERABLE: No path validation
        string basePath = @"C:\uploads\";
        string fullPath = Path.Combine(basePath, fileName);
        return File.ReadAllBytes(fullPath);
    }

    public void DeleteFileUnsafe(string userPath)
    {
        // VULNERABLE: Arbitrary file deletion
        string path = Path.Combine("/tmp/", userPath);
        File.Delete(path);
    }

    public void SaveFileUnsafe(string filename, byte[] data)
    {
        // VULNERABLE: User controls save location
        string path = @"C:\uploads\" + filename;
        File.WriteAllBytes(path, data);
    }

    public FileStream OpenFileUnsafe(string requestedFile)
    {
        // VULNERABLE: Direct path usage
        return new FileStream("/public/files/" + requestedFile, FileMode.Open);
    }
}
