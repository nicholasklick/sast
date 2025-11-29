import javax.net.ssl.SSLContext;
import javax.net.ssl.TrustManager;
import javax.net.ssl.X509TrustManager;
import java.security.cert.X509Certificate;

public class TrustAllCertificates {
    public void createInsecureSslContext() throws Exception {
        // --- VULNERABLE CODE ---
        // Creating a trust manager that does not validate certificate chains.
        // This is highly insecure and makes the connection vulnerable to MITM attacks.
        // CWE-295: Improper Certificate Validation
        TrustManager[] trustAllCerts = new TrustManager[] {
            new X509TrustManager() {
                public X509Certificate[] getAcceptedIssuers() { return null; }
                public void checkClientTrusted(X509Certificate[] certs, String authType) { }
                public void checkServerTrusted(X509Certificate[] certs, String authType) { }
            }
        };

        SSLContext sc = SSLContext.getInstance("SSL");
        sc.init(null, trustAllCerts, new java.security.SecureRandom());
        // -----------------------
    }
}
