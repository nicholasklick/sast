
import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.ResultSet;
import java.sql.Statement;
import javax.servlet.http.HttpServletRequest;

public class SqlInjection {
    public void vulnerable(HttpServletRequest request) throws Exception {
        String userId = request.getParameter("userId");
        Connection con = DriverManager.getConnection("jdbc:mysql://localhost:3306/db");
        Statement stmt = con.createStatement();
        // Vulnerable to SQL Injection
        String query = "SELECT * FROM users WHERE id = '" + userId + "'";
        ResultSet rs = stmt.executeQuery(query);
    }
}
