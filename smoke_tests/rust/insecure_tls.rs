// Insecure TLS Test Cases

// Test 1: Disabling certificate validation
fn make_insecure_request(url: &str) -> Result<String, Box<dyn std::error::Error>> {
    use reqwest;

    // VULNERABLE: Certificate validation disabled
    let client = reqwest::blocking::Client::builder()
        .danger_accept_invalid_certs(true)
        .build()?;

    let response = client.get(url).send()?;
    Ok(response.text()?)
}

// Test 2: Accepting invalid hostnames
fn make_request_without_hostname_validation(url: &str) -> Result<String, Box<dyn std::error::Error>> {
    use reqwest;

    // VULNERABLE: Hostname verification disabled
    let client = reqwest::blocking::Client::builder()
        .danger_accept_invalid_hostnames(true)
        .build()?;

    let response = client.get(url).send()?;
    Ok(response.text()?)
}

// Test 3: Using outdated TLS version
fn create_tls_connector_with_old_version() -> Result<native_tls::TlsConnector, native_tls::Error> {
    use native_tls::{TlsConnector, Protocol};

    // VULNERABLE: Allowing TLS 1.0/1.1 which are deprecated
    TlsConnector::builder()
        .min_protocol_version(Some(Protocol::Tlsv10))
        .build()
}

// Test 4: Disabled certificate validation with native-tls
fn create_insecure_connector() -> Result<native_tls::TlsConnector, native_tls::Error> {
    use native_tls::TlsConnector;

    // VULNERABLE: Accepting invalid certificates
    TlsConnector::builder()
        .danger_accept_invalid_certs(true)
        .build()
}

// Test 5: Rustls with custom verifier that accepts all
fn create_permissive_rustls_config() -> rustls::ClientConfig {
    use rustls::ClientConfig;
    use std::sync::Arc;

    // VULNERABLE: Custom verifier that doesn't validate properly
    let mut config = ClientConfig::new();
    // In real code, this would set a dangerous verifier
    config
}
