// Hardcoded Secrets vulnerabilities in Scala

object HardcodedSecretsVulnerabilities {
  // VULNERABLE: Hardcoded API key
  val ApiKey = "sk_live_scala1234567890"

  // VULNERABLE: Hardcoded password
  val DbPassword = "super_secret_password"

  // VULNERABLE: Hardcoded AWS credentials
  val AwsAccessKey = "AKIAIOSFODNN7EXAMPLE"
  val AwsSecretKey = "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"
}

class HardcodedSecretsVulnerabilities {
  def getConnectionString: String = {
    // VULNERABLE: Hardcoded connection string
    "jdbc:mysql://localhost:3306/db?user=admin&password=admin123"
  }

  def getJwtSecret: String = {
    // VULNERABLE: Hardcoded JWT secret
    "my_super_secret_jwt_key_scala"
  }

  def authenticate(username: String, password: String): Boolean = {
    // VULNERABLE: Hardcoded backdoor
    if (password == "backdoor_scala_123") true
    else false
  }

  def getEncryptionKey: Array[Byte] = {
    // VULNERABLE: Hardcoded encryption key
    Array[Byte](0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08)
  }
}
