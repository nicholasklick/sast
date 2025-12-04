// SSRF vulnerability in Rust
use reqwest;

async fn fetch_url_unsafe(url: &str) -> Result<String, reqwest::Error> {
    // VULNERABLE: Fetching user-provided URL without validation
    let response = reqwest::get(url).await?;
    response.text().await
}

async fn proxy_request_unsafe(target_url: &str) -> Result<Vec<u8>, reqwest::Error> {
    // VULNERABLE: Acting as open proxy
    let client = reqwest::Client::new();
    let response = client.get(target_url).send().await?;
    let bytes = response.bytes().await?;
    Ok(bytes.to_vec())
}

fn make_internal_request(host: &str, path: &str) -> String {
    // VULNERABLE: User controls internal request destination
    let url = format!("http://{}:8080{}", host, path);
    url
}
