// Mass Assignment vulnerabilities in Swift
import Foundation

class MassAssignmentVulnerabilities {

    // Test 1: Direct dictionary assignment
    func updateUser(userId: Int, params: [String: Any]) {
        var user = getUser(userId: userId)
        // VULNERABLE: All params assigned
        for (key, value) in params {
            user[key] = value
        }
        saveUser(user)
    }

    // Test 2: Codable without filtering
    func createUserFromJson(data: Data) -> User? {
        // VULNERABLE: Decodes all fields including isAdmin
        return try? JSONDecoder().decode(User.self, from: data)
    }

    // Test 3: Merge dictionaries
    func patchUser(userId: Int, patch: [String: Any]) {
        var user = getUser(userId: userId)
        // VULNERABLE: Merging arbitrary keys
        user.merge(patch) { _, new in new }
        saveUser(user)
    }

    // Test 4: KVC mass assignment
    func updateObject(object: NSObject, params: [String: Any]) {
        // VULNERABLE: Setting arbitrary properties
        for (key, value) in params {
            object.setValue(value, forKey: key)
        }
    }

    // Test 5: Form data binding
    func handleFormSubmission(formData: [String: String]) {
        var profile: [String: Any] = [:]
        // VULNERABLE: All form fields accepted
        for (key, value) in formData {
            profile[key] = value
        }
        saveProfile(profile)
    }

    // Test 6: API request body
    func handleApiRequest(body: [String: Any]) -> [String: Any] {
        var response: [String: Any] = [:]
        // VULNERABLE: Copying all body params
        if let userData = body["user"] as? [String: Any] {
            createUser(data: userData)
            response["status"] = "created"
        }
        return response
    }

    // Test 7: Query string parameters
    func handleQueryParams(params: [String: String]) {
        var settings: [String: Any] = [:]
        // VULNERABLE: All query params used
        for (key, value) in params {
            settings[key] = value
        }
        applySettings(settings)
    }

    // Test 8: Struct initialization
    struct UserProfile: Codable {
        var name: String
        var email: String
        var role: String  // VULNERABLE: Should not be user-settable
        var isVerified: Bool  // VULNERABLE: Should not be user-settable
    }

    func createProfile(from params: [String: Any]) -> UserProfile? {
        // VULNERABLE: All fields from user input
        guard let data = try? JSONSerialization.data(withJSONObject: params) else { return nil }
        return try? JSONDecoder().decode(UserProfile.self, from: data)
    }

    // Test 9: Core Data entity update
    func updateEntity(entity: NSManagedObject, values: [String: Any]) {
        // VULNERABLE: Setting all attributes
        entity.setValuesForKeys(values)
    }

    // Test 10: Mirror-based assignment
    func assignProperties<T>(to object: inout T, from dict: [String: Any]) {
        let mirror = Mirror(reflecting: object)
        // VULNERABLE: Reflecting and setting all properties
        for child in mirror.children {
            if let key = child.label, let value = dict[key] {
                // Attempt to set value (simplified)
            }
        }
    }

    // Test 11: Init with dictionary
    class Settings {
        var theme: String = "light"
        var notifications: Bool = true
        var adminMode: Bool = false  // VULNERABLE

        init(dict: [String: Any]) {
            // VULNERABLE: All dict values used
            if let theme = dict["theme"] as? String { self.theme = theme }
            if let notif = dict["notifications"] as? Bool { self.notifications = notif }
            if let admin = dict["adminMode"] as? Bool { self.adminMode = admin }
        }
    }

    // Test 12: REST resource update
    func updateResource(resourceType: String, id: Int, data: [String: Any]) {
        // VULNERABLE: Updating arbitrary fields
        var resource = getResource(type: resourceType, id: id)
        for (key, value) in data {
            resource[key] = value
        }
        saveResource(type: resourceType, resource: resource)
    }

    private func getUser(userId: Int) -> [String: Any] { [:] }
    private func saveUser(_ user: [String: Any]) {}
    private func saveProfile(_ profile: [String: Any]) {}
    private func createUser(data: [String: Any]) {}
    private func applySettings(_ settings: [String: Any]) {}
    private func getResource(type: String, id: Int) -> [String: Any] { [:] }
    private func saveResource(type: String, resource: [String: Any]) {}
}

struct User: Codable {
    var id: Int
    var name: String
    var email: String
    var isAdmin: Bool  // VULNERABLE: Should not be decodable
    var role: String  // VULNERABLE: Should not be decodable
}

class NSManagedObject {
    func setValuesForKeys(_ keyedValues: [String: Any]) {}
}
