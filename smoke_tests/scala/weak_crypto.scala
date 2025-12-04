// Weak Cryptography vulnerabilities in Scala
import java.security.MessageDigest
import javax.crypto.Cipher
import javax.crypto.spec.SecretKeySpec
import scala.util.Random

class WeakCryptoVulnerabilities {
  def hashMd5(input: String): String = {
    // VULNERABLE: MD5 is cryptographically broken
    val md = MessageDigest.getInstance("MD5")
    val digest = md.digest(input.getBytes)
    digest.map("%02x".format(_)).mkString
  }

  def hashSha1(input: String): String = {
    // VULNERABLE: SHA1 is deprecated
    val md = MessageDigest.getInstance("SHA-1")
    val digest = md.digest(input.getBytes)
    digest.map("%02x".format(_)).mkString
  }

  def encryptDes(data: Array[Byte], key: Array[Byte]): Array[Byte] = {
    // VULNERABLE: DES is obsolete
    val secretKey = new SecretKeySpec(key, "DES")
    val cipher = Cipher.getInstance("DES/ECB/PKCS5Padding")
    cipher.init(Cipher.ENCRYPT_MODE, secretKey)
    cipher.doFinal(data)
  }

  def generateToken: Int = {
    // VULNERABLE: Non-cryptographic random
    Random.nextInt(1000000)
  }

  def weakSessionId: String = {
    // VULNERABLE: Predictable session ID
    System.currentTimeMillis().toString
  }

  def ecbEncryption(data: Array[Byte], key: Array[Byte]): Array[Byte] = {
    // VULNERABLE: ECB mode
    val cipher = Cipher.getInstance("AES/ECB/PKCS5Padding")
    cipher.init(Cipher.ENCRYPT_MODE, new SecretKeySpec(key, "AES"))
    cipher.doFinal(data)
  }
}
