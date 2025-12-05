// Insecure Deserialization vulnerabilities in Swift
import Foundation

class DeserializationVulnerabilities {

    // Test 1: NSKeyedUnarchiver with untrusted data
    func unarchiveUntrusted(data: Data) -> Any? {
        // VULNERABLE: Deserializing untrusted data
        return try? NSKeyedUnarchiver.unarchiveTopLevelObjectWithData(data)
    }

    // Test 2: Unarchive from file
    func loadFromFile(path: String) -> Any? {
        guard let data = FileManager.default.contents(atPath: path) else { return nil }
        // VULNERABLE: File contents could be tampered
        return try? NSKeyedUnarchiver.unarchiveTopLevelObjectWithData(data)
    }

    // Test 3: Network data deserialization
    func fetchAndDeserialize(url: URL, completion: @escaping (Any?) -> Void) {
        URLSession.shared.dataTask(with: url) { data, _, _ in
            guard let data = data else {
                completion(nil)
                return
            }
            // VULNERABLE: Deserializing network data
            let obj = try? NSKeyedUnarchiver.unarchiveTopLevelObjectWithData(data)
            completion(obj)
        }.resume()
    }

    // Test 4: PropertyList deserialization
    func deserializePlist(data: Data) -> Any? {
        // VULNERABLE: Plist can contain arbitrary object graphs
        return try? PropertyListSerialization.propertyList(from: data,
                                                           options: .mutableContainersAndLeaves,
                                                           format: nil)
    }

    // Test 5: JSON deserialization without validation
    func deserializeJson(data: Data) -> Any? {
        // VULNERABLE: No schema validation
        return try? JSONSerialization.jsonObject(with: data, options: .allowFragments)
    }

    // Test 6: Codable with untrusted data
    func decodeUser(data: Data) -> User? {
        // VULNERABLE: Decoding untrusted data
        return try? JSONDecoder().decode(User.self, from: data)
    }

    // Test 7: UserDefaults for complex objects
    func loadCachedObject(key: String) -> Any? {
        guard let data = UserDefaults.standard.data(forKey: key) else { return nil }
        // VULNERABLE: Cached data could be manipulated
        return try? NSKeyedUnarchiver.unarchiveTopLevelObjectWithData(data)
    }

    // Test 8: Pasteboard data
    func pasteObject() -> Any? {
        guard let data = UIPasteboard.general.data(forPasteboardType: "com.app.object") else {
            return nil
        }
        // VULNERABLE: Pasteboard can contain malicious data
        return try? NSKeyedUnarchiver.unarchiveTopLevelObjectWithData(data)
    }

    // Test 9: Deep link parameter deserialization
    func handleDeepLink(url: URL) {
        guard let components = URLComponents(url: url, resolvingAgainstBaseURL: false),
              let dataParam = components.queryItems?.first(where: { $0.name == "data" })?.value,
              let data = Data(base64Encoded: dataParam) else { return }
        // VULNERABLE: Deep link data deserialization
        let _ = try? NSKeyedUnarchiver.unarchiveTopLevelObjectWithData(data)
    }

    // Test 10: Shared container data
    func loadSharedData() -> Any? {
        let containerUrl = FileManager.default.containerURL(
            forSecurityApplicationGroupIdentifier: "group.com.app")
        guard let fileUrl = containerUrl?.appendingPathComponent("shared.data"),
              let data = try? Data(contentsOf: fileUrl) else { return nil }
        // VULNERABLE: Shared container could be written by other apps
        return try? NSKeyedUnarchiver.unarchiveTopLevelObjectWithData(data)
    }

    // Test 11: Core Data external binary
    func importExternalData(data: Data, context: NSManagedObjectContext) {
        // VULNERABLE: Importing untrusted binary data into Core Data
        let decoder = JSONDecoder()
        decoder.userInfo[.managedObjectContext] = context
        _ = try? decoder.decode([ManagedEntity].self, from: data)
    }

    // Test 12: Archive migration
    func migrateOldArchive(path: String) -> Any? {
        guard let data = FileManager.default.contents(atPath: path) else { return nil }
        // VULNERABLE: Old archive format parsing
        return NSUnarchiver.unarchiveObject(with: data)
    }
}

struct User: Codable {
    var id: Int
    var name: String
    var role: String
}

struct ManagedEntity: Codable {
    var id: Int
}

class UIPasteboard {
    static var general = UIPasteboard()
    func data(forPasteboardType type: String) -> Data? { nil }
}

class NSManagedObjectContext {}
extension CodingUserInfoKey {
    static let managedObjectContext = CodingUserInfoKey(rawValue: "context")!
}
