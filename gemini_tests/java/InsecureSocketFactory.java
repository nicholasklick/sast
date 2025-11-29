
import javax.net.ssl.SSLSocketFactory;

public class InsecureSocketFactory {
    public void createSocket() throws java.io.IOException {
        // Using the default SSLSocketFactory is insecure on some older platforms
        SSLSocketFactory factory = (SSLSocketFactory) SSLSocketFactory.getDefault();
        factory.createSocket("example.com", 443);
    }
}
