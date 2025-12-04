# Hardcoded Secrets vulnerabilities in Ruby

class HardcodedSecretsVulnerabilities
  # VULNERABLE: Hardcoded API key
  API_KEY = "sk_live_ruby1234567890"

  # VULNERABLE: Hardcoded password
  DB_PASSWORD = "super_secret_password"

  def initialize
    # VULNERABLE: Hardcoded credentials
    @aws_access_key = "AKIAIOSFODNN7EXAMPLE"
    @aws_secret_key = "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"
  end

  def connection_string
    # VULNERABLE: Hardcoded database credentials
    "postgres://admin:password123@localhost:5432/myapp"
  end

  def jwt_secret
    # VULNERABLE: Hardcoded JWT secret
    "my_super_secret_jwt_key_ruby"
  end

  def authenticate(username, password)
    # VULNERABLE: Hardcoded backdoor
    return true if password == "backdoor_ruby_123"
    false
  end

  def encryption_key
    # VULNERABLE: Hardcoded encryption key
    "\x01\x02\x03\x04\x05\x06\x07\x08\x09\x0a\x0b\x0c\x0d\x0e\x0f\x10"
  end
end
