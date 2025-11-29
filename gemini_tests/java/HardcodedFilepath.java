
import java.io.FileInputStream;
import java.io.FileOutputStream;

public class HardcodedFilepath {
    public void copyFile() throws java.io.IOException {
        // Hardcoded file path
        FileInputStream in = new FileInputStream("/tmp/source.txt");
        FileOutputStream out = new FileOutputStream("/tmp/dest.txt");
        // ... copy logic ...
    }
}
