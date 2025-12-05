// Insecure Data Storage vulnerabilities in Swift
import Foundation
import Security

class InsecureStorage {

    // Test 1: UserDefaults for sensitive data
    func storePasswordUserDefaults(password: String) {
        // VULNERABLE: UserDefaults is not secure storage
        UserDefaults.standard.set(password, forKey: "user_password")
    }

    // Test 2: Plist storage
    func storeToPlist(secrets: [String: Any]) {
        // VULNERABLE: Plist files are easily readable
        let paths = FileManager.default.urls(for: .documentDirectory, in: .userDomainMask)
        let plistPath = paths[0].appendingPathComponent("secrets.plist")
        (secrets as NSDictionary).write(to: plistPath, atomically: true)
    }

    // Test 3: Plain text file storage
    func storeToFile(sensitiveData: String) {
        // VULNERABLE: Plain text file storage
        let paths = FileManager.default.urls(for: .documentDirectory, in: .userDomainMask)
        let filePath = paths[0].appendingPathComponent("sensitive.txt")
        try? sensitiveData.write(to: filePath, atomically: true, encoding: .utf8)
    }

    // Test 4: NSKeyedArchiver without encryption
    func archiveData(object: NSObject) {
        // VULNERABLE: Archived data is not encrypted
        let data = try? NSKeyedArchiver.archivedData(withRootObject: object, requiringSecureCoding: false)
        let paths = FileManager.default.urls(for: .documentDirectory, in: .userDomainMask)
        let filePath = paths[0].appendingPathComponent("archived.dat")
        try? data?.write(to: filePath)
    }

    // Test 5: SQLite without encryption
    func storeInDatabase(password: String) {
        // VULNERABLE: SQLite database without encryption
        // Data stored in plain text
    }

    // Test 6: CoreData without encryption
    func storeCoreData(sensitiveField: String) {
        // VULNERABLE: CoreData default storage is unencrypted
        // Would store in unencrypted SQLite
    }

    // Test 7: Keychain without access control
    func storeInKeychainInsecure(password: String) {
        let query: [String: Any] = [
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrAccount as String: "password",
            kSecValueData as String: password.data(using: .utf8)!,
            // VULNERABLE: Missing kSecAttrAccessible restrictions
        ]
        SecItemAdd(query as CFDictionary, nil)
    }

    // Test 8: Keychain accessible when unlocked
    func storeKeychainWhenUnlocked(data: Data) {
        let query: [String: Any] = [
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrAccount as String: "sensitive",
            kSecValueData as String: data,
            // VULNERABLE: Accessible when device unlocked
            kSecAttrAccessible as String: kSecAttrAccessibleWhenUnlocked
        ]
        SecItemAdd(query as CFDictionary, nil)
    }

    // Test 9: Logging sensitive data
    func logSensitiveData(creditCard: String, cvv: String) {
        // VULNERABLE: Logging sensitive information
        print("Processing card: \(creditCard), CVV: \(cvv)")
        NSLog("Card number: %@", creditCard)
    }

    // Test 10: Clipboard sensitive data
    func copyToClipboard(password: String) {
        // VULNERABLE: Clipboard can be read by other apps
        UIPasteboard.general.string = password
    }

    // Test 11: Screenshot not disabled for sensitive views
    // VULNERABLE: iOS can screenshot sensitive data
    // Should use UITextField.isSecureTextEntry or disable screenshots

    // Test 12: Backup includes sensitive data
    func createBackupableFile(data: Data) {
        let paths = FileManager.default.urls(for: .documentDirectory, in: .userDomainMask)
        var filePath = paths[0].appendingPathComponent("secrets.dat")
        try? data.write(to: filePath)
        // VULNERABLE: File included in iCloud/iTunes backup
        // Should set: var resourceValues = URLResourceValues()
        // resourceValues.isExcludedFromBackup = true
    }

    // Test 13: Shared container storage
    func storeInSharedContainer(secret: String) {
        // VULNERABLE: Shared containers accessible by app group
        let sharedDefaults = UserDefaults(suiteName: "group.com.example.shared")
        sharedDefaults?.set(secret, forKey: "shared_secret")
    }
}

// Placeholder for iOS-specific types
class UIPasteboard {
    static var general = UIPasteboard()
    var string: String?
}
