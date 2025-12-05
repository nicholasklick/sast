// Mass Assignment vulnerabilities in Groovy
package com.example.security

class MassAssignmentVulnerabilities {

    // Test 1: Direct map assignment
    void updateUser(int userId, Map params) {
        def user = getUser(userId)
        // VULNERABLE: All params assigned
        params.each { key, value ->
            user."${key}" = value
        }
        saveUser(user)
    }

    // Test 2: Groovy properties spread
    User createUserFromParams(Map params) {
        // VULNERABLE: All params used in construction
        new User(params)
    }

    // Test 3: Grails bindData (conceptual)
    void grailsBindData(Object obj, Map params) {
        // VULNERABLE: Binding all params
        params.each { key, value ->
            if (obj.hasProperty(key)) {
                obj."${key}" = value
            }
        }
    }

    // Test 4: JsonSlurper to object
    User createUserFromJson(String json) {
        def slurper = new groovy.json.JsonSlurper()
        def data = slurper.parseText(json)
        // VULNERABLE: All fields from JSON
        new User(data)
    }

    // Test 5: Form data binding
    Profile handleFormSubmission(Map formData) {
        // VULNERABLE: All form fields accepted
        new Profile(
            name: formData.name ?: "",
            bio: formData.bio ?: "",
            isVerified: formData.isVerified?.toBoolean() ?: false, // VULNERABLE
            permissions: formData.permissions ?: "" // VULNERABLE
        )
    }

    // Test 6: Domain object merge
    void mergeUserData(int userId, Map newData) {
        def user = getUser(userId)
        // VULNERABLE: Merging untrusted data
        user.properties.putAll(newData)
        saveUser(user)
    }

    // Test 7: with block assignment
    void updateWithBlock(User user, Map params) {
        user.with {
            // VULNERABLE: All params applied
            params.each { key, value ->
                delegate."${key}" = value
            }
        }
    }

    // Test 8: Tap method assignment
    User createWithTap(Map params) {
        // VULNERABLE: Tap with all params
        new User().tap {
            params.each { key, value ->
                delegate."${key}" = value
            }
        }
    }

    // Test 9: ConfigSlurper binding
    void loadConfig(String configScript) {
        // VULNERABLE: ConfigSlurper can set arbitrary properties
        def config = new ConfigSlurper()
        def settings = config.parse(configScript)
        applySettings(settings)
    }

    // Test 10: Builder pattern abuse
    User buildFromParams(Map params) {
        // VULNERABLE: Builder accepts all params
        def builder = new UserBuilder()
        params.each { key, value ->
            builder."${key}"(value)
        }
        builder.build()
    }

    // Test 11: Expando object
    def createExpando(Map params) {
        // VULNERABLE: All params on Expando
        def obj = new Expando()
        params.each { key, value ->
            obj."${key}" = value
        }
        obj
    }

    // Test 12: GORM domain update (conceptual)
    void gormUpdate(int userId, Map params) {
        def user = User.get(userId)
        // VULNERABLE: All params bound to domain
        user.properties = params
        user.save()
    }

    private User getUser(int userId) { new User() }
    private void saveUser(User user) {}
    private void applySettings(def settings) {}
}

class User {
    int id
    String name
    String email
    boolean isAdmin = false
    String role = "user"
}

class Profile {
    String name
    String bio
    boolean isVerified
    String permissions
}

class UserBuilder {
    def props = [:]
    def methodMissing(String name, args) {
        props[name] = args[0]
        this
    }
    User build() {
        new User(props)
    }
}
