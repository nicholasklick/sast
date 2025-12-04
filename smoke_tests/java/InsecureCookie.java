
import javax.servlet.http.Cookie;
import javax.servlet.http.HttpServletResponse;

public class InsecureCookie {
    public void setCookie(HttpServletResponse response) {
        Cookie cookie = new Cookie("sessionID", "12345");
        // Cookie is not marked as HttpOnly or Secure
        response.addCookie(cookie);
    }
}
