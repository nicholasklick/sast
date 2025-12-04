
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;

public class OpenRedirect {
    public void vulnerable(HttpServletRequest request, HttpServletResponse response) throws IOException {
        String url = request.getParameter("url");
        // Vulnerable to Open Redirect
        response.sendRedirect(url);
    }
}
