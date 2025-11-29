
import java.io.File;
import java.io.IOException;

public class InsecureTempFile {
    public void createTemp() throws IOException {
        // Insecure temporary file creation
        File tempFile = File.createTempFile("prefix", ".tmp");
        // The file is created with default permissions, which might be too permissive
    }
}
