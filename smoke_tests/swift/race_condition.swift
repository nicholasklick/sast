// Race Condition vulnerabilities in Swift
import Foundation

class RaceConditionVulnerabilities {

    var balance: Int = 1000
    var inventory: [String: Int] = ["item1": 10]
    var usedCoupons: Set<String> = []

    // Test 1: TOCTOU in balance check
    func withdraw(amount: Int) -> Bool {
        // VULNERABLE: Check and update not atomic
        if balance >= amount {
            // Race window here
            Thread.sleep(forTimeInterval: 0.001)
            balance -= amount
            return true
        }
        return false
    }

    // Test 2: Double-spend on inventory
    func purchaseItem(itemId: String) -> Bool {
        // VULNERABLE: Check and decrement not atomic
        guard let count = inventory[itemId], count > 0 else {
            return false
        }
        // Race window
        inventory[itemId] = count - 1
        return true
    }

    // Test 3: Coupon reuse race
    func applyCoupon(code: String) -> Bool {
        // VULNERABLE: Check and mark not atomic
        if usedCoupons.contains(code) {
            return false
        }
        // Race window - coupon can be used multiple times
        usedCoupons.insert(code)
        return true
    }

    // Test 4: File write race
    func writeToFile(path: String, content: String) {
        // VULNERABLE: No file locking
        if let data = content.data(using: .utf8) {
            try? data.write(to: URL(fileURLWithPath: path))
        }
    }

    // Test 5: Shared state without synchronization
    var counter: Int = 0

    func incrementCounter() {
        // VULNERABLE: Not thread-safe
        let current = counter
        counter = current + 1
    }

    // Test 6: Lazy initialization race
    var _singleton: ExpensiveObject?
    var singleton: ExpensiveObject {
        // VULNERABLE: Race in lazy init
        if _singleton == nil {
            _singleton = ExpensiveObject()
        }
        return _singleton!
    }

    // Test 7: Token refresh race
    var accessToken: String = ""
    var isRefreshing: Bool = false

    func getToken() -> String {
        // VULNERABLE: Multiple threads may refresh
        if accessToken.isEmpty && !isRefreshing {
            isRefreshing = true
            accessToken = refreshToken()
            isRefreshing = false
        }
        return accessToken
    }

    // Test 8: Database transaction race
    func transferFunds(from: Int, to: Int, amount: Int) {
        // VULNERABLE: No transaction isolation
        let fromBalance = getBalance(userId: from)
        let toBalance = getBalance(userId: to)

        if fromBalance >= amount {
            setBalance(userId: from, balance: fromBalance - amount)
            setBalance(userId: to, balance: toBalance + amount)
        }
    }

    // Test 9: Cache stampede
    var cache: [String: Any] = [:]

    func getCachedValue(key: String) -> Any {
        // VULNERABLE: Multiple threads may regenerate
        if let value = cache[key] {
            return value
        }
        let value = expensiveComputation(key: key)
        cache[key] = value
        return value
    }

    // Test 10: Session fixation race
    var sessions: [String: String] = [:]

    func createSession(userId: String) -> String {
        let sessionId = UUID().uuidString
        // VULNERABLE: Race between check and set
        if sessions[sessionId] == nil {
            sessions[sessionId] = userId
        }
        return sessionId
    }

    // Test 11: Rate limit bypass
    var requestCounts: [String: Int] = [:]
    let rateLimit = 100

    func checkRateLimit(clientId: String) -> Bool {
        // VULNERABLE: Race allows exceeding limit
        let count = requestCounts[clientId] ?? 0
        if count >= rateLimit {
            return false
        }
        requestCounts[clientId] = count + 1
        return true
    }

    // Test 12: Voting race condition
    var votes: [String: Int] = [:]

    func vote(for candidate: String) {
        // VULNERABLE: Vote count race
        let current = votes[candidate] ?? 0
        votes[candidate] = current + 1
    }

    private func refreshToken() -> String { "new_token" }
    private func getBalance(userId: Int) -> Int { 0 }
    private func setBalance(userId: Int, balance: Int) {}
    private func expensiveComputation(key: String) -> Any { "" }
}

class ExpensiveObject {
    init() {
        Thread.sleep(forTimeInterval: 0.1)
    }
}
