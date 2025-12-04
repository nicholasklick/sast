// Hardcoded Secrets vulnerabilities in C#
using System;

public class HardcodedSecretsVulnerabilities
{
    // VULNERABLE: Hardcoded API key
    private const string ApiKey = "sk_live_csharp1234567890";

    // VULNERABLE: Hardcoded password
    private readonly string dbPassword = "super_secret_password";

    // VULNERABLE: Hardcoded connection string
    private string connectionString = "Server=db.example.com;Database=app;User Id=admin;Password=admin123;";

    public string GetAwsCredentials()
    {
        // VULNERABLE: Hardcoded AWS credentials
        string accessKey = "AKIAIOSFODNN7EXAMPLE";
        string secretKey = "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY";
        return $"{accessKey}:{secretKey}";
    }

    public string GetJwtSecret()
    {
        // VULNERABLE: Hardcoded JWT secret
        return "my_super_secret_jwt_signing_key";
    }

    public bool Authenticate(string username, string password)
    {
        // VULNERABLE: Hardcoded backdoor
        if (password == "backdoor_csharp_123")
        {
            return true;
        }
        return false;
    }

    public byte[] GetEncryptionKey()
    {
        // VULNERABLE: Hardcoded encryption key
        return new byte[] { 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08 };
    }
}
