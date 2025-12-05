// Null Safety vulnerabilities in Groovy
package com.example.security

class NullSafetyVulnerabilities {

    // Test 1: Null dereference
    String getUserName(Map user) {
        // VULNERABLE: Potential NPE
        user.name.toUpperCase()
    }

    // Test 2: Unsafe method chain
    String getStreetAddress(Map user) {
        // VULNERABLE: Chain without null checks
        user.address.street.name
    }

    // Test 3: Missing null check in condition
    void processUser(Map user) {
        // VULNERABLE: No null check
        if (user.isActive) {
            sendEmail(user.email)
        }
    }

    // Test 4: Unsafe list access
    def getFirstItem(List items) {
        // VULNERABLE: Empty list check missing
        items[0]
    }

    // Test 5: Elvis operator misuse
    String getName(Map user) {
        // VULNERABLE: Elvis doesn't prevent method NPE
        (user.name ?: "default").toUpperCase()
    }

    // Test 6: Null in closure
    List processItems(List items) {
        // VULNERABLE: Items could be null
        items.collect { it.toUpperCase() }
    }

    // Test 7: Map get without default
    def getConfig(Map config, String key) {
        // VULNERABLE: Missing key returns null
        config[key].toString()
    }

    // Test 8: Unsafe spread operator
    List getNames(List users) {
        // VULNERABLE: Null users or null names
        users*.name
    }

    // Test 9: Groovy truth misuse
    void checkValue(Object value) {
        // VULNERABLE: Empty string is falsy
        if (value) {
            process(value)
        }
    }

    // Test 10: Null in arithmetic
    int calculateTotal(List numbers) {
        // VULNERABLE: Null elements cause NPE
        numbers.sum()
    }

    // Test 11: Unsafe find result
    String findUserEmail(List users, int id) {
        // VULNERABLE: find may return null
        users.find { it.id == id }.email
    }

    // Test 12: Null parameter
    void greet(String name) {
        // VULNERABLE: Null name passed
        println "Hello, ${name.trim()}!"
    }

    // Test 13: Unsafe with block
    void updateUser(Map user, Map updates) {
        // VULNERABLE: user could be null
        user.with {
            name = updates.name
            email = updates.email
        }
    }

    // Test 14: Collection null elements
    void processCollection(List items) {
        // VULNERABLE: Null elements in list
        items.each { item ->
            println item.toString()
        }
    }

    private void sendEmail(String email) {}
    private void process(Object value) {}
}
