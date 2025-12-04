// Weak Cryptography vulnerabilities in Kotlin
import java.security.MessageDigest
import javax.crypto.Cipher
import javax.crypto.spec.SecretKeySpec
import java.util.Random

class WeakCryptoVulnerabilities {
    fun hashMd5(input: String): String {
        // VULNERABLE: MD5 is cryptographically broken
        val md = MessageDigest.getInstance("MD5")
        val digest = md.digest(input.toByteArray())
        return digest.joinToString("") { "%02x".format(it) }
    }

    fun hashSha1(input: String): String {
        // VULNERABLE: SHA1 is deprecated
        val md = MessageDigest.getInstance("SHA-1")
        val digest = md.digest(input.toByteArray())
        return digest.joinToString("") { "%02x".format(it) }
    }

    fun encryptDes(data: ByteArray, key: ByteArray): ByteArray {
        // VULNERABLE: DES is obsolete
        val secretKey = SecretKeySpec(key, "DES")
        val cipher = Cipher.getInstance("DES/ECB/PKCS5Padding")
        cipher.init(Cipher.ENCRYPT_MODE, secretKey)
        return cipher.doFinal(data)
    }

    fun generateToken(): Int {
        // VULNERABLE: Non-cryptographic random
        return Random().nextInt(1000000)
    }

    fun weakSessionId(): String {
        // VULNERABLE: Predictable session ID
        return System.currentTimeMillis().toString()
    }

    fun ecbEncryption(data: ByteArray, key: ByteArray): ByteArray {
        // VULNERABLE: ECB mode
        val cipher = Cipher.getInstance("AES/ECB/PKCS5Padding")
        cipher.init(Cipher.ENCRYPT_MODE, SecretKeySpec(key, "AES"))
        return cipher.doFinal(data)
    }
}
