
import java.io.File;
import javax.servlet.http.HttpServletRequest;

public class PathTraversal {
    public void vulnerable(HttpServletRequest request) {
        String filename = request.getParameter("filename");
        // Vulnerable to Path Traversal
        File file = new File("/var/www/images/" + filename);
    }
}
