// --- VULNERABLE CODE ---
const config = {
  apiKey: "ak_test_a1b2c3d4e5f6g7h8i9j0", // CWE-798: Use of Hard-coded Credentials
  apiSecret: "secret-key-from-a-service-provider", // CWE-798
  password: "MySuperSecurePassword123" // CWE-798
};
// -----------------------

function connectToApi() {
  console.log(`Connecting with key: ${config.apiKey}`);
}

connectToApi();