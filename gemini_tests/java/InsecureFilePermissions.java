import java.io.File;
import java.io.IOException;

public class InsecureFilePermissions {
    public void createInsecureFile() throws IOException {
        File tempFile = new File("temp.tmp");

        // --- VULNERABLE CODE ---
        // Creating a file and then setting permissions is a race condition.
        // A better approach is to use APIs that set permissions atomically on creation (e.g., Files.createFile with PosixFilePermissions).
        // CWE-732: Incorrect Permission Assignment for Critical Resource
        tempFile.createNewFile();
        tempFile.setReadable(true, false); // readable by everyone
        tempFile.setWritable(true, false); // writable by everyone
        // -----------------------
    }
}
