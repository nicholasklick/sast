// Grails Framework Security vulnerabilities in Groovy
package com.example.security

// Conceptual Grails-style vulnerabilities

class GrailsSecurityVulnerabilities {

    // Test 1: GORM dynamic finders injection
    def findUser(String username) {
        // VULNERABLE: Dynamic finder with user input
        User."findByUsername${username}"()
    }

    // Test 2: Unsafe params binding
    def updateUser(Long id, Map params) {
        def user = User.get(id)
        // VULNERABLE: Binding all params to domain
        user.properties = params
        user.save()
    }

    // Test 3: HQL injection
    List searchUsers(String query) {
        // VULNERABLE: HQL with string interpolation
        User.executeQuery("from User u where u.name like '%${query}%'")
    }

    // Test 4: Criteria builder injection
    List findByCriteria(String fieldName, String value) {
        // VULNERABLE: Field name from user
        User.createCriteria().list {
            eq(fieldName, value)
        }
    }

    // Test 5: GSP raw output
    String renderUserContent(String content) {
        // VULNERABLE: Raw GSP output
        "<div>\${raw(content)}</div>"
    }

    // Test 6: URL mapping vulnerability
    def handleRequest(String controller, String action) {
        // VULNERABLE: Dynamic controller/action
        redirect(controller: controller, action: action)
    }

    // Test 7: Session fixation
    def login(String username, String password, session) {
        if (authenticate(username, password)) {
            // VULNERABLE: No session regeneration
            session.user = username
        }
    }

    // Test 8: CORS misconfiguration
    def configCors() {
        // VULNERABLE: Allow all origins
        [
            allowedOrigins: ["*"],
            allowedMethods: ["GET", "POST", "PUT", "DELETE"],
            allowCredentials: true
        ]
    }

    // Test 9: Unsafe file serving
    def downloadFile(String filename, response) {
        // VULNERABLE: Path traversal in file serving
        def file = new File("/uploads/${filename}")
        response.outputStream << file.bytes
    }

    // Test 10: Command object binding
    def createUser(UserCommand cmd) {
        // VULNERABLE: All command properties bound
        def user = new User(cmd.properties)
        user.save()
    }

    // Test 11: Plugin version exposure
    def getPluginInfo() {
        // VULNERABLE: Version information leaked
        [
            grailsVersion: grailsApplication.metadata['app.grails.version'],
            plugins: grailsApplication.pluginManager.allPlugins.collect {
                [name: it.name, version: it.version]
            }
        ]
    }

    // Test 12: Unsafe redirect
    def handleRedirect(String url) {
        // VULNERABLE: Open redirect
        redirect(url: url)
    }

    // Test 13: Asset pipeline bypass
    def serveAsset(String path) {
        // VULNERABLE: Direct asset serving
        def asset = grailsApplication.mainContext.getResource("assets/${path}")
        asset.inputStream.text
    }

    // Helper classes
    static class User {
        Long id
        String username
        String email
        String role
        boolean isAdmin

        static User get(Long id) { new User() }
        static def executeQuery(String hql) { [] }
        static def createCriteria() { new CriteriaBuilder() }
        static def "findByUsername${String}"() { new User() }
        def save() { this }
    }

    static class CriteriaBuilder {
        def list(Closure c) { [] }
        def eq(String field, Object value) { this }
    }

    static class UserCommand {
        String username
        String email
        String role
    }

    // Stub methods
    private def grailsApplication
    private boolean authenticate(String u, String p) { true }
    private void redirect(Map params) {}
}
