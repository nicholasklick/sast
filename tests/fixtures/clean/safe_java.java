// Clean Java code with no vulnerabilities
package com.example.safe;

import java.sql.*;
import java.nio.file.*;
import java.security.*;
import javax.crypto.*;
import javax.crypto.spec.*;

public class SafeJavaCode {

    // 1. Safe SQL Query - PreparedStatement
    public String getUserById(Connection conn, int userId) throws SQLException {
        String query = "SELECT * FROM users WHERE id = ?";
        try (PreparedStatement stmt = conn.prepareStatement(query)) {
            stmt.setInt(1, userId);
            ResultSet rs = stmt.executeQuery();
            return rs.next() ? rs.getString("name") : null;
        }
    }

    // 2. Safe File Access - Path validation
    public String readFile(String filename) throws Exception {
        Path basePath = Paths.get("/var/data").toAbsolutePath().normalize();
        Path filePath = basePath.resolve(filename).normalize();

        if (!filePath.startsWith(basePath)) {
            throw new SecurityException("Path traversal detected");
        }

        return new String(Files.readAllBytes(filePath));
    }

    // 3. Safe Configuration
    public String getApiKey() {
        String apiKey = System.getenv("API_KEY");
        if (apiKey == null) {
            throw new IllegalStateException("API_KEY not set");
        }
        return apiKey;
    }

    // 4. Safe Cryptography - AES-256-GCM
    public byte[] encryptData(byte[] data, byte[] keyBytes) throws Exception {
        SecretKeySpec key = new SecretKeySpec(keyBytes, "AES");
        Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
        cipher.init(Cipher.ENCRYPT_MODE, key);
        return cipher.doFinal(data);
    }

    // 5. Safe Hashing - SHA-256
    public String hashPassword(String password) throws NoSuchAlgorithmException {
        MessageDigest digest = MessageDigest.getInstance("SHA-256");
        byte[] hash = digest.digest(password.getBytes());
        StringBuilder hexString = new StringBuilder();
        for (byte b : hash) {
            hexString.append(String.format("%02x", b));
        }
        return hexString.toString();
    }

    // 6. Safe Random Generation
    public String generateSecureToken() {
        SecureRandom random = new SecureRandom();
        byte[] bytes = new byte[32];
        random.nextBytes(bytes);
        StringBuilder token = new StringBuilder();
        for (byte b : bytes) {
            token.append(String.format("%02x", b));
        }
        return token.toString();
    }

    // 7. Safe XML Processing
    public void parseXmlSafely(String xmlContent) throws Exception {
        javax.xml.parsers.DocumentBuilderFactory factory =
            javax.xml.parsers.DocumentBuilderFactory.newInstance();
        factory.setFeature("http://xml.org/sax/features/external-general-entities", false);
        factory.setFeature("http://xml.org/sax/features/external-parameter-entities", false);
        factory.setFeature("http://apache.org/xml/features/disallow-doctype-decl", true);

        javax.xml.parsers.DocumentBuilder builder = factory.newDocumentBuilder();
        builder.parse(new java.io.ByteArrayInputStream(xmlContent.getBytes()));
    }

    // 8. Safe Command Execution
    public String listFiles(String directory) throws Exception {
        java.util.Set<String> allowedDirs = java.util.Set.of("/tmp", "/var/log");
        if (!allowedDirs.contains(directory)) {
            throw new SecurityException("Directory not allowed");
        }

        ProcessBuilder pb = new ProcessBuilder("ls", "-la", directory);
        Process process = pb.start();
        java.io.BufferedReader reader = new java.io.BufferedReader(
            new java.io.InputStreamReader(process.getInputStream()));
        return reader.lines().collect(java.util.stream.Collectors.joining("\n"));
    }

    // 9. Safe Input Validation
    public String validateAndSanitize(String input) {
        return input.replaceAll("[^a-zA-Z0-9_-]", "");
    }

    // 10. Safe URL Validation
    public String fetchUrl(String url) throws Exception {
        java.util.Set<String> allowedHosts = java.util.Set.of("api.example.com");
        java.net.URI uri = new java.net.URI(url);

        if (!allowedHosts.contains(uri.getHost())) {
            throw new SecurityException("Host not allowed");
        }

        java.net.URLConnection conn = new java.net.URL(url).openConnection();
        java.io.BufferedReader reader = new java.io.BufferedReader(
            new java.io.InputStreamReader(conn.getInputStream()));
        return reader.lines().collect(java.util.stream.Collectors.joining("\n"));
    }
}
