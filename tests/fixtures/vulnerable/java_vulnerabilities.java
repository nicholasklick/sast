// Java Vulnerability Test Fixtures
package com.example.vulnerabilities;

import java.sql.*;
import java.io.*;
import javax.crypto.*;
import javax.crypto.spec.*;
import javax.naming.directory.*;
import javax.xml.parsers.*;
import java.net.*;
import java.security.*;

public class JavaVulnerabilities {

    // 1. SQL Injection - Statement with concatenation
    public String sqlInjectionConcat(String userId) throws SQLException {
        Connection conn = DriverManager.getConnection("jdbc:mysql://localhost/db");
        Statement stmt = conn.createStatement();
        String query = "SELECT * FROM users WHERE id = '" + userId + "'";
        ResultSet rs = stmt.executeQuery(query);
        return rs.next() ? rs.getString("name") : "";
    }

    // 2. SQL Injection - String format
    public boolean sqlInjectionFormat(String username) throws SQLException {
        Connection conn = DriverManager.getConnection("jdbc:mysql://localhost/db");
        Statement stmt = conn.createStatement();
        String query = String.format("SELECT * FROM users WHERE username = '%s'", username);
        ResultSet rs = stmt.executeQuery(query);
        return rs.next();
    }

    // 3. Command Injection - Runtime.exec
    public void commandInjectionRuntime(String filename) throws IOException {
        Runtime.getRuntime().exec("cat " + filename);
    }

    // 4. Command Injection - ProcessBuilder
    public String commandInjectionBuilder(String userInput) throws IOException {
        Process process = new ProcessBuilder("sh", "-c", "ls " + userInput).start();
        BufferedReader reader = new BufferedReader(new InputStreamReader(process.getInputStream()));
        return reader.readLine();
    }

    // 5. Path Traversal
    public String pathTraversal(String filename) throws IOException {
        File file = new File("/var/data/" + filename);
        BufferedReader reader = new BufferedReader(new FileReader(file));
        return reader.readLine();
    }

    // 6. Hardcoded Credentials - API Key
    private static final String API_KEY = "sk_live_java1234567890abcdef";

    // 7. Hardcoded Credentials - Database Password
    public Connection connectToDatabase() throws SQLException {
        String password = "JavaSecret123!";
        return DriverManager.getConnection("jdbc:mysql://localhost/db", "admin", password);
    }

    // 8. Weak Cryptography - DES
    public byte[] weakCryptoDes(byte[] data) throws Exception {
        SecretKeySpec key = new SecretKeySpec("12345678".getBytes(), "DES");
        Cipher cipher = Cipher.getInstance("DES/ECB/PKCS5Padding");
        cipher.init(Cipher.ENCRYPT_MODE, key);
        return cipher.doFinal(data);
    }

    // 9. Weak Cryptography - MD5
    public String weakHashMd5(String input) throws NoSuchAlgorithmException {
        MessageDigest md = MessageDigest.getInstance("MD5");
        byte[] hash = md.digest(input.getBytes());
        return new String(hash);
    }

    // 10. XXE Vulnerability
    public void parseXml(String xmlContent) throws Exception {
        DocumentBuilderFactory factory = DocumentBuilderFactory.newInstance();
        // Missing: factory.setFeature(XMLConstants.FEATURE_SECURE_PROCESSING, true);
        DocumentBuilder builder = factory.newDocumentBuilder();
        builder.parse(new ByteArrayInputStream(xmlContent.getBytes()));
    }

    // 11. Insecure Deserialization
    public Object deserializeObject(byte[] data) throws IOException, ClassNotFoundException {
        ObjectInputStream ois = new ObjectInputStream(new ByteArrayInputStream(data));
        return ois.readObject();
    }

    // 12. LDAP Injection
    public boolean ldapInjection(String username) throws Exception {
        java.util.Hashtable<String, String> env = new java.util.Hashtable<>();
        env.put("java.naming.factory.initial", "com.sun.jndi.ldap.LdapCtxFactory");
        env.put("java.naming.provider.url", "ldap://localhost:389");
        InitialDirContext ctx = new InitialDirContext(env);
        String filter = "(uid=" + username + ")";
        NamingEnumeration<?> results = ctx.search("ou=users,dc=example,dc=com", filter, null);
        return results.hasMore();
    }

    // 13. SSRF Vulnerability
    public String fetchUrl(String url) throws IOException {
        URLConnection conn = new URL(url).openConnection();
        BufferedReader reader = new BufferedReader(new InputStreamReader(conn.getInputStream()));
        return reader.readLine();
    }

    // 14. Unsafe Random Number Generation
    public String generateToken() {
        java.util.Random random = new java.util.Random();
        return String.valueOf(random.nextLong());
    }

    // 15. XPath Injection
    public void xpathInjection(String userId) throws Exception {
        DocumentBuilderFactory factory = DocumentBuilderFactory.newInstance();
        DocumentBuilder builder = factory.newDocumentBuilder();
        org.w3c.dom.Document doc = builder.newDocument();

        javax.xml.xpath.XPathFactory xpathFactory = javax.xml.xpath.XPathFactory.newInstance();
        javax.xml.xpath.XPath xpath = xpathFactory.newXPath();
        String expression = "//users/user[@id='" + userId + "']";
        xpath.evaluate(expression, doc);
    }

    // 16. Open Redirect
    public void redirect(String url) {
        // response.sendRedirect(url); - vulnerable to open redirect
        System.out.println("Redirecting to: " + url);
    }

    // 17. Zip Slip Vulnerability
    public File extractZip(java.util.zip.ZipEntry entry, String targetDir) {
        File targetFile = new File(targetDir, entry.getName());
        // Missing path traversal check
        return targetFile;
    }

    // 18. Server-Side Template Injection (Velocity)
    public String renderTemplate(String userInput) {
        String template = "<html><body><h1>Welcome " + userInput + "</h1></body></html>";
        // Vulnerable if used with template engine
        return template;
    }

    // 19. Weak SSL/TLS Configuration
    public void disableSslValidation() throws Exception {
        javax.net.ssl.TrustManager[] trustAllCerts = new javax.net.ssl.TrustManager[] {
            new javax.net.ssl.X509TrustManager() {
                public java.security.cert.X509Certificate[] getAcceptedIssuers() { return null; }
                public void checkClientTrusted(java.security.cert.X509Certificate[] certs, String authType) {}
                public void checkServerTrusted(java.security.cert.X509Certificate[] certs, String authType) {}
            }
        };
        javax.net.ssl.SSLContext sc = javax.net.ssl.SSLContext.getInstance("SSL");
        sc.init(null, trustAllCerts, new java.security.SecureRandom());
    }

    // 20. NoSQL Injection (MongoDB-like pattern)
    public void mongoQuery(String userId) {
        String query = "{ \"userId\": \"" + userId + "\" }";
        // db.collection.find(query) - vulnerable to injection
    }
}
