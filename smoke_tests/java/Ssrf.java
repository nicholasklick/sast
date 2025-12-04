
import java.net.URL;
import java.net.URLConnection;
import java.io.InputStream;
import javax.servlet.http.HttpServletRequest;

public class Ssrf {
    public void vulnerable(HttpServletRequest request) throws Exception {
        String url = request.getParameter("url");
        // Vulnerable to SSRF
        URL u = new URL(url);
        URLConnection conn = u.openConnection();
        InputStream in = conn.getInputStream();
    }
}
