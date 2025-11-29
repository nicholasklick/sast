import java.io.IOException;

public class CommandInjectionProcessBuilder {
    public void vulnerableProcessBuilder(String command) throws IOException {
        // --- VULNERABLE CODE ---
        // On Windows, or when used with a shell, ProcessBuilder can be vulnerable
        // if the command is not properly split into arguments.
        // A safer way is to pass command and arguments as a list.
        // CWE-78: Improper Neutralization of Special Elements used in an OS Command ('OS Command Injection')
        new ProcessBuilder(command).start();
        // A more explicit vulnerability:
        new ProcessBuilder("/bin/sh", "-c", command).start();
        // -----------------------
    }
}
