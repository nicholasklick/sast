// Race Condition vulnerabilities in Groovy
package com.example.security

class RaceConditionVulnerabilities {

    int balance = 1000
    def inventory = [item1: 10]
    def usedCoupons = [] as Set

    // Test 1: TOCTOU in balance check
    boolean withdraw(int amount) {
        // VULNERABLE: Check and update not atomic
        if (balance >= amount) {
            Thread.sleep(1) // Race window
            balance -= amount
            return true
        }
        false
    }

    // Test 2: Double-spend on inventory
    boolean purchaseItem(String itemId) {
        // VULNERABLE: Check and decrement not atomic
        def count = inventory[itemId]
        if (count && count > 0) {
            inventory[itemId] = count - 1
            return true
        }
        false
    }

    // Test 3: Coupon reuse race
    boolean applyCoupon(String code) {
        // VULNERABLE: Check and add not atomic
        if (usedCoupons.contains(code)) {
            return false
        }
        Thread.sleep(1) // Race window
        usedCoupons.add(code)
        true
    }

    // Test 4: File write race
    void writeToFile(String path, String content) {
        // VULNERABLE: No file locking
        new File(path).text = content
    }

    // Test 5: Counter increment race
    int counter = 0

    void incrementCounter() {
        // VULNERABLE: Not thread-safe
        def current = counter
        counter = current + 1
    }

    // Test 6: Lazy initialization race
    def _singleton = null

    def getSingleton() {
        // VULNERABLE: Race in lazy init
        if (_singleton == null) {
            _singleton = new ExpensiveObject()
        }
        _singleton
    }

    // Test 7: Token refresh race
    String accessToken = ""
    boolean isRefreshing = false

    String getToken() {
        // VULNERABLE: Multiple threads may refresh
        if (!accessToken && !isRefreshing) {
            isRefreshing = true
            accessToken = refreshToken()
            isRefreshing = false
        }
        accessToken
    }

    // Test 8: Cache stampede
    def cache = [:]

    def getCachedValue(String key) {
        // VULNERABLE: Multiple threads regenerate
        if (!cache[key]) {
            cache[key] = expensiveComputation(key)
        }
        cache[key]
    }

    // Test 9: Rate limit bypass
    def requestCounts = [:]
    int rateLimit = 100

    boolean checkRateLimit(String clientId) {
        // VULNERABLE: Race allows exceeding limit
        def count = requestCounts[clientId] ?: 0
        if (count >= rateLimit) {
            return false
        }
        requestCounts[clientId] = count + 1
        true
    }

    // Test 10: Voting race condition
    def votes = [:]

    void vote(String candidate) {
        // VULNERABLE: Vote count race
        def current = votes[candidate] ?: 0
        votes[candidate] = current + 1
    }

    // Test 11: GPars parallel race
    void gparsRace(List items) {
        def results = []
        // VULNERABLE: Non-thread-safe collection in parallel
        items.each { item ->
            results.add(processItem(item))
        }
    }

    // Test 12: Session fixation race
    def sessions = [:]

    String createSession(String userId) {
        def sessionId = UUID.randomUUID().toString()
        // VULNERABLE: Race between check and set
        if (!sessions[sessionId]) {
            sessions[sessionId] = userId
        }
        sessionId
    }

    private String refreshToken() { "new_token" }
    private def expensiveComputation(String key) { "" }
    private def processItem(item) { item }
}

class ExpensiveObject {
    ExpensiveObject() {
        Thread.sleep(100)
    }
}
