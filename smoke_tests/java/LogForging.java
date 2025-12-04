
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import javax.servlet.http.HttpServletRequest;

public class LogForging {
    private static final Logger logger = LogManager.getLogger(LogForging.class);

    public void vulnerable(HttpServletRequest request) {
        String input = request.getParameter("input");
        // Vulnerable to log forging if input is not sanitized
        logger.info("User input: " + input);
    }
}
