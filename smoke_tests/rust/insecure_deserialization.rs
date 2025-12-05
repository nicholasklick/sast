// Insecure Deserialization Test Cases

use serde::{Deserialize, Serialize};

#[derive(Deserialize, Serialize)]
struct UserData {
    username: String,
    role: String,
}

// Test 1: Deserializing untrusted JSON
fn deserialize_json(json_str: &str) -> Result<UserData, serde_json::Error> {
    // VULNERABLE: Deserializing untrusted data without validation
    serde_json::from_str(json_str)
}

// Test 2: Bincode deserialization
fn deserialize_bincode(data: &[u8]) -> Result<UserData, Box<bincode::ErrorKind>> {
    // VULNERABLE: Binary deserialization from untrusted source
    bincode::deserialize(data)
}

// Test 3: MessagePack deserialization
fn deserialize_msgpack(data: &[u8]) -> Result<UserData, rmp_serde::decode::Error> {
    // VULNERABLE: Deserializing untrusted MessagePack data
    rmp_serde::from_slice(data)
}

// Test 4: YAML deserialization
fn deserialize_yaml(yaml_str: &str) -> Result<UserData, serde_yaml::Error> {
    // VULNERABLE: YAML deserialization can execute arbitrary code
    serde_yaml::from_str(yaml_str)
}

// Test 5: TOML deserialization from user input
fn deserialize_toml(toml_str: &str) -> Result<UserData, toml::de::Error> {
    // VULNERABLE: Deserializing configuration from untrusted source
    toml::from_str(toml_str)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_insecure_deserialization() {
        let json = r#"{"username":"admin","role":"admin"}"#;
        let _ = deserialize_json(json);
    }
}
