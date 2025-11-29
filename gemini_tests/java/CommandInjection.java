
import java.io.IOException;
import javax.servlet.http.HttpServletRequest;

public class CommandInjection {
    public void vulnerable(HttpServletRequest request) throws IOException {
        String command = request.getParameter("command");
        // Vulnerable to Command Injection
        Runtime.getRuntime().exec("cmd.exe /c " + command);
    }
}
