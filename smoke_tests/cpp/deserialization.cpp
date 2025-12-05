// Insecure Deserialization vulnerabilities in C++
#include <iostream>
#include <fstream>
#include <sstream>
#include <vector>
#include <cstring>

// Test 1: Deserializing untrusted binary data
struct UserData {
    char name[64];
    int age;
    char role[32];
};

void deserialize_user(const char* data, size_t len) {
    // VULNERABLE: Direct memory copy of untrusted data
    UserData user;
    memcpy(&user, data, sizeof(UserData));
    std::cout << "User: " << user.name << std::endl;
}

// Test 2: Loading object from file without validation
class Config {
public:
    int version;
    char server[256];
    int port;

    static Config load(const std::string& filename) {
        Config cfg;
        std::ifstream file(filename, std::ios::binary);
        // VULNERABLE: Reading binary config without validation
        file.read(reinterpret_cast<char*>(&cfg), sizeof(Config));
        return cfg;
    }
};

// Test 3: Function pointer in serialized data
struct Command {
    void (*execute)(const char*);
    char argument[128];
};

void execute_command(const char* data) {
    Command cmd;
    // VULNERABLE: Function pointer from untrusted source
    memcpy(&cmd, data, sizeof(Command));
    cmd.execute(cmd.argument);
}

// Test 4: Vtable hijacking setup
class Serializable {
public:
    virtual void process() = 0;
    char data[100];
};

void deserialize_object(void* buffer) {
    // VULNERABLE: Vtable can be corrupted
    Serializable* obj = reinterpret_cast<Serializable*>(buffer);
    obj->process();  // May call attacker-controlled function
}

// Test 5: Size-based buffer allocation from untrusted header
void read_message(std::istream& input) {
    uint32_t size;
    input.read(reinterpret_cast<char*>(&size), sizeof(size));
    // VULNERABLE: Attacker controls size
    char* buffer = new char[size];
    input.read(buffer, size);
    delete[] buffer;
}

// Test 6: Type tag without validation
enum class ObjectType { STRING, INT, ARRAY };

void deserialize_typed(const char* data) {
    ObjectType type = *reinterpret_cast<const ObjectType*>(data);
    // VULNERABLE: Type tag can be arbitrary value
    switch (type) {
        case ObjectType::STRING:
            std::cout << (data + sizeof(ObjectType)) << std::endl;
            break;
        default:
            break;
    }
}

// Test 7: Object graph deserialization (reference following)
struct Node {
    int value;
    size_t next_offset;  // Offset to next node in buffer
};

void traverse_serialized_list(const char* buffer, size_t buffer_size) {
    size_t offset = 0;
    while (offset < buffer_size) {
        // VULNERABLE: next_offset can point anywhere
        Node* node = (Node*)(buffer + offset);
        std::cout << node->value << std::endl;
        offset = node->next_offset;
    }
}

// Test 8: Polymorphic deserialization
class BaseMessage {
public:
    virtual void handle() = 0;
    virtual ~BaseMessage() {}
};

BaseMessage* deserialize_message(const char* data, int type_id) {
    // VULNERABLE: type_id controls object creation
    // Attacker could specify unexpected type
    return nullptr;  // Simplified - would create based on type_id
}
