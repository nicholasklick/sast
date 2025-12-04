// Weak Cryptography vulnerabilities in C#
using System;
using System.Security.Cryptography;
using System.Text;

public class WeakCryptoVulnerabilities
{
    public string HashMd5(string input)
    {
        // VULNERABLE: MD5 is cryptographically broken
        using (MD5 md5 = MD5.Create())
        {
            byte[] hash = md5.ComputeHash(Encoding.UTF8.GetBytes(input));
            return BitConverter.ToString(hash);
        }
    }

    public string HashSha1(string input)
    {
        // VULNERABLE: SHA1 is deprecated
        using (SHA1 sha1 = SHA1.Create())
        {
            byte[] hash = sha1.ComputeHash(Encoding.UTF8.GetBytes(input));
            return BitConverter.ToString(hash);
        }
    }

    public byte[] EncryptDes(byte[] data, byte[] key)
    {
        // VULNERABLE: DES is obsolete
        using (DES des = DES.Create())
        {
            des.Key = key;
            des.Mode = CipherMode.ECB; // VULNERABLE: ECB mode
            return des.CreateEncryptor().TransformFinalBlock(data, 0, data.Length);
        }
    }

    public int GenerateToken()
    {
        // VULNERABLE: Non-cryptographic random
        Random rand = new Random();
        return rand.Next();
    }

    public string WeakSessionId()
    {
        // VULNERABLE: Predictable session ID
        return DateTime.Now.Ticks.ToString();
    }
}
