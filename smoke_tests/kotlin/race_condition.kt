// Race Condition vulnerabilities in Kotlin
package com.example.security

import java.util.concurrent.ConcurrentHashMap

class RaceConditionVulnerabilities {

    private var balance = 1000
    private val inventory = mutableMapOf("item1" to 10)
    private val usedCoupons = mutableSetOf<String>()

    // Test 1: TOCTOU in balance check
    fun withdraw(amount: Int): Boolean {
        // VULNERABLE: Check and update not atomic
        if (balance >= amount) {
            Thread.sleep(1) // Race window
            balance -= amount
            return true
        }
        return false
    }

    // Test 2: Double-spend on inventory
    fun purchaseItem(itemId: String): Boolean {
        // VULNERABLE: Check and decrement not atomic
        val count = inventory[itemId] ?: return false
        if (count > 0) {
            inventory[itemId] = count - 1
            return true
        }
        return false
    }

    // Test 3: Coupon reuse race
    fun applyCoupon(code: String): Boolean {
        // VULNERABLE: Check and add not atomic
        if (usedCoupons.contains(code)) {
            return false
        }
        Thread.sleep(1) // Race window
        usedCoupons.add(code)
        return true
    }

    // Test 4: File write race
    fun writeToFile(path: String, content: String) {
        // VULNERABLE: No file locking
        java.io.File(path).writeText(content)
    }

    // Test 5: Counter increment race
    private var counter = 0

    fun incrementCounter() {
        // VULNERABLE: Not thread-safe
        val current = counter
        counter = current + 1
    }

    // Test 6: Lazy initialization race
    private var _singleton: ExpensiveObject? = null
    val singleton: ExpensiveObject
        get() {
            // VULNERABLE: Race in lazy init
            if (_singleton == null) {
                _singleton = ExpensiveObject()
            }
            return _singleton!!
        }

    // Test 7: Token refresh race
    private var accessToken = ""
    private var isRefreshing = false

    fun getToken(): String {
        // VULNERABLE: Multiple threads may refresh
        if (accessToken.isEmpty() && !isRefreshing) {
            isRefreshing = true
            accessToken = refreshToken()
            isRefreshing = false
        }
        return accessToken
    }

    // Test 8: Database transaction race
    fun transferFunds(from: Int, to: Int, amount: Int) {
        // VULNERABLE: No transaction isolation
        val fromBalance = getBalance(from)
        val toBalance = getBalance(to)

        if (fromBalance >= amount) {
            setBalance(from, fromBalance - amount)
            setBalance(to, toBalance + amount)
        }
    }

    // Test 9: Cache stampede
    private val cache = ConcurrentHashMap<String, Any>()

    fun getCachedValue(key: String): Any {
        // VULNERABLE: Multiple threads regenerate
        return cache.getOrPut(key) {
            expensiveComputation(key)
        }
    }

    // Test 10: Session fixation race
    private val sessions = mutableMapOf<String, String>()

    fun createSession(userId: String): String {
        val sessionId = java.util.UUID.randomUUID().toString()
        // VULNERABLE: Race between check and set
        if (!sessions.containsKey(sessionId)) {
            sessions[sessionId] = userId
        }
        return sessionId
    }

    // Test 11: Rate limit bypass
    private val requestCounts = mutableMapOf<String, Int>()
    private val rateLimit = 100

    fun checkRateLimit(clientId: String): Boolean {
        // VULNERABLE: Race allows exceeding limit
        val count = requestCounts[clientId] ?: 0
        if (count >= rateLimit) {
            return false
        }
        requestCounts[clientId] = count + 1
        return true
    }

    // Test 12: Voting race condition
    private val votes = mutableMapOf<String, Int>()

    fun vote(candidate: String) {
        // VULNERABLE: Vote count race
        val current = votes[candidate] ?: 0
        votes[candidate] = current + 1
    }

    private fun refreshToken(): String = "new_token"
    private fun getBalance(userId: Int): Int = 0
    private fun setBalance(userId: Int, balance: Int) {}
    private fun expensiveComputation(key: String): Any = ""
}

class ExpensiveObject {
    init {
        Thread.sleep(100)
    }
}
