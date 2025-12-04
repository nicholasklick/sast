
public class EmptyPassword {
    public void connect() throws java.sql.SQLException {
        // Connecting to a database with an empty password
        java.sql.DriverManager.getConnection("jdbc:mysql://localhost:3306/db", "root", "");
    }
}
