import Foundation

// Test Swift file with potential vulnerabilities
class UserManager {
    // Hardcoded credentials
    let apiKey = "sk_live_12345"
    let password = "admin123"
    
    // SQL injection potential
    func getUser(id: String) {
        let query = "SELECT * FROM users WHERE id = '\(id)'"
        // execute(query)
    }
    
    // Weak crypto
    func hashPassword(_ password: String) -> String {
        return password.md5  // MD5 is weak
    }
}
