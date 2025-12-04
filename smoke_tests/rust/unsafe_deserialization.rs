// Unsafe Deserialization vulnerability in Rust
use serde::{Deserialize, Serialize};

#[derive(Serialize, Deserialize)]
struct UserData {
    name: String,
    role: String,
}

fn deserialize_user_input(data: &[u8]) -> Result<UserData, Box<dyn std::error::Error>> {
    // VULNERABLE: Deserializing untrusted data without validation
    let user: UserData = bincode::deserialize(data)?;
    Ok(user)
}

fn load_config_from_user(yaml_str: &str) -> Result<serde_yaml::Value, serde_yaml::Error> {
    // VULNERABLE: YAML deserialization of untrusted input
    serde_yaml::from_str(yaml_str)
}

fn parse_json_command(json: &str) -> Result<serde_json::Value, serde_json::Error> {
    // VULNERABLE: JSON parsing without schema validation
    serde_json::from_str(json)
}
