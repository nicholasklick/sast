// Groovy Vulnerability Test Fixtures
package com.example.vulnerabilities

import java.sql.Connection
import java.sql.DriverManager
import java.sql.Statement

class GroovyVulnerabilities {

    // 1. SQL Injection - GString interpolation
    def sqlInjectionGString(userId) {
        Connection connection = DriverManager.getConnection("jdbc:mysql://localhost/db")
        Statement statement = connection.createStatement()
        def query = "SELECT * FROM users WHERE id = '${userId}'"
        def resultSet = statement.executeQuery(query)
        return resultSet.next() ? resultSet.getString("name") : ""
    }

    // 2. SQL Injection - String concatenation
    def sqlInjectionConcat(username) {
        def connection = DriverManager.getConnection("jdbc:mysql://localhost/db")
        def query = "SELECT * FROM users WHERE username = '" + username + "'"
        def statement = connection.createStatement()
        def resultSet = statement.executeQuery(query)
        return resultSet.next()
    }

    // 3. Command Injection - execute()
    def commandInjectionExecute(filename) {
        "cat ${filename}".execute()
    }

    // 4. Command Injection - shell execution
    def commandInjectionShell(userInput) {
        def process = "sh -c ls ${userInput}".execute()
        process.waitFor()
        return process.text
    }

    // 5. Path Traversal
    def pathTraversal(filename) {
        def file = new File("/var/data/${filename}")
        return file.text
    }

    // 6. Hardcoded Credentials - API Key
    def apiKey = "sk_live_groovy1234567890"

    // 7. Hardcoded Credentials - Database Password
    def connectToDb() {
        def password = "GroovySecret789!"
        def conn = DriverManager.getConnection("jdbc:mysql://localhost/db", "admin", password)
        return conn
    }

    // 8. Weak Cryptography - DES
    def weakCryptoDes(data) {
        import javax.crypto.Cipher
        import javax.crypto.spec.SecretKeySpec

        def key = new SecretKeySpec("12345678".bytes, "DES")
        def cipher = Cipher.getInstance("DES/ECB/PKCS5Padding")
        cipher.init(Cipher.ENCRYPT_MODE, key)
        return cipher.doFinal(data)
    }

    // 9. Weak Cryptography - MD5
    def weakHashMd5(input) {
        import java.security.MessageDigest
        def md = MessageDigest.getInstance("MD5")
        return md.digest(input.bytes).encodeHex().toString()
    }

    // 10. XXE Vulnerability
    def parseXml(xmlContent) {
        def factory = javax.xml.parsers.DocumentBuilderFactory.newInstance()
        // Missing secure processing
        def builder = factory.newDocumentBuilder()
        def doc = builder.parse(new ByteArrayInputStream(xmlContent.bytes))
        return doc
    }

    // 11. Insecure Deserialization
    def deserializeObject(byte[] data) {
        def ois = new ObjectInputStream(new ByteArrayInputStream(data))
        return ois.readObject()
    }

    // 12. LDAP Injection
    def ldapInjection(username) {
        def env = new Hashtable()
        env.put("java.naming.factory.initial", "com.sun.jndi.ldap.LdapCtxFactory")
        env.put("java.naming.provider.url", "ldap://localhost:389")
        def ctx = new javax.naming.directory.InitialDirContext(env)
        def filter = "(uid=${username})"
        def results = ctx.search("ou=users,dc=example,dc=com", filter, null)
        return results.hasMore()
    }

    // 13. Code Injection - GroovyShell eval
    def codeInjection(userCode) {
        def shell = new GroovyShell()
        return shell.evaluate(userCode)
    }

    // 14. SSRF Vulnerability
    def fetchUrl(url) {
        return new URL(url).text
    }

    // 15. Unsafe Random
    def generateToken() {
        def random = new Random()
        return random.nextLong().toString()
    }

    // 16. Gradle Script Injection (common in build.gradle files)
    def executeBuildTask(taskName) {
        def cmd = "gradle ${taskName}"
        cmd.execute()
    }

    // 17. Template Injection
    def renderTemplate(userInput) {
        def template = """
            <html>
                <body>
                    <h1>Welcome ${userInput}</h1>
                </body>
            </html>
        """
        return template
    }

    // 18. Open Redirect
    def redirect(url) {
        // response.sendRedirect(url) - vulnerable
        println "Redirecting to: ${url}"
    }

    // 19. Path Manipulation in File Operations
    def deleteFile(filename) {
        new File("/tmp/${filename}").delete()
    }

    // 20. Unsafe Reflection
    def invokeMethod(className, methodName) {
        def clazz = Class.forName(className)
        def method = clazz.getMethod(methodName)
        return method.invoke(clazz.newInstance())
    }
}
