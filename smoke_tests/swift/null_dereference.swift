// Null Pointer Dereference vulnerabilities in Swift
import Foundation

class NullDereferenceVulnerabilities {

    // Test 1: Force unwrapping optional
    func getUserName(userId: Int) -> String {
        let user = findUser(userId: userId)
        // VULNERABLE: Force unwrap can crash
        return user!.name
    }

    // Test 2: Implicitly unwrapped optional
    var database: Database!

    func query(sql: String) -> [Any] {
        // VULNERABLE: IUO may be nil
        return database.execute(sql: sql)
    }

    // Test 3: Force cast
    func processResponse(data: Any) -> [String: Any] {
        // VULNERABLE: Force cast can crash
        return data as! [String: Any]
    }

    // Test 4: Array index without bounds check
    func getItem(items: [String], index: Int) -> String {
        // VULNERABLE: No bounds check
        return items[index]
    }

    // Test 5: Dictionary force unwrap
    func getConfig(key: String) -> String {
        let config = loadConfig()
        // VULNERABLE: Key may not exist
        return config[key]!
    }

    // Test 6: Optional chaining result force unwrap
    func getNestedValue(data: [String: Any]) -> String {
        // VULNERABLE: Chain result force unwrapped
        return (data["user"] as? [String: Any])?["name"] as! String
    }

    // Test 7: Try! with throwing function
    func parseJson(data: Data) -> [String: Any] {
        // VULNERABLE: try! can crash
        return try! JSONSerialization.jsonObject(with: data) as! [String: Any]
    }

    // Test 8: First element without check
    func getFirstUser(users: [User]) -> User {
        // VULNERABLE: Array might be empty
        return users.first!
    }

    // Test 9: URL force unwrap
    func makeRequest(urlString: String) {
        // VULNERABLE: URL init can return nil
        let url = URL(string: urlString)!
        URLSession.shared.dataTask(with: url).resume()
    }

    // Test 10: Range subscript crash
    func substring(str: String, start: Int, length: Int) -> String {
        // VULNERABLE: Index out of bounds
        let startIndex = str.index(str.startIndex, offsetBy: start)
        let endIndex = str.index(startIndex, offsetBy: length)
        return String(str[startIndex..<endIndex])
    }

    // Test 11: IBOutlet force unwrap
    @IBOutlet var label: UILabel!
    @IBOutlet var button: UIButton!

    func updateUI() {
        // VULNERABLE: Outlets may be nil before viewDidLoad
        label.text = "Hello"
        button.isEnabled = true
    }

    // Test 12: Singleton initialization
    static var shared: NullDereferenceVulnerabilities!

    func useShared() {
        // VULNERABLE: shared may not be initialized
        NullDereferenceVulnerabilities.shared.query(sql: "SELECT 1")
    }

    // Test 13: Closure capture force unwrap
    func fetchData(completion: @escaping (Data) -> Void) {
        URLSession.shared.dataTask(with: URL(string: "https://api.example.com")!) { data, _, _ in
            // VULNERABLE: data can be nil
            completion(data!)
        }.resume()
    }

    // Test 14: Optional binding with force
    func processOptional(value: String?) {
        // VULNERABLE: Unnecessary force unwrap
        if value != nil {
            print(value!)
        }
    }

    // Test 15: Last element access
    func getLastItem<T>(array: [T]) -> T {
        // VULNERABLE: Empty array crash
        return array.last!
    }

    private func findUser(userId: Int) -> (name: String, id: Int)? { nil }
    private func loadConfig() -> [String: String] { [:] }
}

struct User {
    var name: String
}

class Database {
    func execute(sql: String) -> [Any] { [] }
}

class UILabel {
    var text: String?
}

class UIButton {
    var isEnabled: Bool = true
}

@propertyWrapper
struct IBOutlet<T> {
    var wrappedValue: T
}
