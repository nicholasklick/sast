// Cryptographic Failures in C#
using System;
using System.IO;
using System.Security.Cryptography;
using System.Text;
using System.Web.Mvc;

namespace VulnerableApp
{
    public class CryptoController : Controller
    {
        // Test 1: ECB mode usage
        public ActionResult EncryptEcb(string data)
        {
            using (var aes = Aes.Create())
            {
                // VULNERABLE: ECB mode reveals patterns
                aes.Mode = CipherMode.ECB;
                aes.GenerateKey();
                var encryptor = aes.CreateEncryptor();
                byte[] input = Encoding.UTF8.GetBytes(data);
                byte[] output = encryptor.TransformFinalBlock(input, 0, input.Length);
                return Content(Convert.ToBase64String(output));
            }
        }

        // Test 2: Hardcoded key
        public ActionResult EncryptWithKey(string data)
        {
            using (var aes = Aes.Create())
            {
                // VULNERABLE: Hardcoded encryption key
                aes.Key = Encoding.UTF8.GetBytes("0123456789abcdef");
                aes.IV = new byte[16];
                var encryptor = aes.CreateEncryptor();
                byte[] input = Encoding.UTF8.GetBytes(data);
                byte[] output = encryptor.TransformFinalBlock(input, 0, input.Length);
                return Content(Convert.ToBase64String(output));
            }
        }

        // Test 3: Static IV
        public ActionResult EncryptStaticIv(string data)
        {
            using (var aes = Aes.Create())
            {
                aes.GenerateKey();
                // VULNERABLE: Static IV
                aes.IV = new byte[] { 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0 };
                var encryptor = aes.CreateEncryptor();
                byte[] input = Encoding.UTF8.GetBytes(data);
                byte[] output = encryptor.TransformFinalBlock(input, 0, input.Length);
                return Content(Convert.ToBase64String(output));
            }
        }

        // Test 4: DES usage (weak)
        public ActionResult EncryptDes(string data)
        {
            // VULNERABLE: DES is weak (56-bit key)
            using (var des = DES.Create())
            {
                des.GenerateKey();
                des.GenerateIV();
                var encryptor = des.CreateEncryptor();
                byte[] input = Encoding.UTF8.GetBytes(data);
                byte[] output = encryptor.TransformFinalBlock(input, 0, input.Length);
                return Content(Convert.ToBase64String(output));
            }
        }

        // Test 5: TripleDES (deprecated)
        public ActionResult EncryptTripleDes(string data)
        {
            // VULNERABLE: 3DES is deprecated
            using (var tdes = TripleDES.Create())
            {
                tdes.GenerateKey();
                tdes.GenerateIV();
                var encryptor = tdes.CreateEncryptor();
                byte[] input = Encoding.UTF8.GetBytes(data);
                byte[] output = encryptor.TransformFinalBlock(input, 0, input.Length);
                return Content(Convert.ToBase64String(output));
            }
        }

        // Test 6: Small RSA key
        public ActionResult GenerateRsaKey()
        {
            // VULNERABLE: 1024-bit RSA is too weak
            using (var rsa = new RSACryptoServiceProvider(1024))
            {
                return Content(rsa.ToXmlString(false));
            }
        }

        // Test 7: MD5 for integrity
        public ActionResult HashMd5(string data)
        {
            // VULNERABLE: MD5 is broken
            using (var md5 = MD5.Create())
            {
                byte[] hash = md5.ComputeHash(Encoding.UTF8.GetBytes(data));
                return Content(BitConverter.ToString(hash));
            }
        }

        // Test 8: SHA1 for security
        public ActionResult HashSha1(string data)
        {
            // VULNERABLE: SHA1 is deprecated
            using (var sha1 = SHA1.Create())
            {
                byte[] hash = sha1.ComputeHash(Encoding.UTF8.GetBytes(data));
                return Content(BitConverter.ToString(hash));
            }
        }

        // Test 9: Insufficient PBKDF2 iterations
        public ActionResult DeriveKey(string password)
        {
            byte[] salt = new byte[16];
            new RNGCryptoServiceProvider().GetBytes(salt);
            // VULNERABLE: Only 1000 iterations (should be 100000+)
            using (var pbkdf2 = new Rfc2898DeriveBytes(password, salt, 1000))
            {
                byte[] key = pbkdf2.GetBytes(32);
                return Content(Convert.ToBase64String(key));
            }
        }

        // Test 10: Fixed salt
        public ActionResult DeriveKeyFixedSalt(string password)
        {
            // VULNERABLE: Salt should be random per password
            byte[] salt = Encoding.UTF8.GetBytes("static_salt_value");
            using (var pbkdf2 = new Rfc2898DeriveBytes(password, salt, 100000))
            {
                byte[] key = pbkdf2.GetBytes(32);
                return Content(Convert.ToBase64String(key));
            }
        }

        // Test 11: No authenticated encryption
        public ActionResult EncryptNoAuth(string data)
        {
            using (var aes = Aes.Create())
            {
                aes.Mode = CipherMode.CBC;
                aes.GenerateKey();
                aes.GenerateIV();
                // VULNERABLE: No authentication (susceptible to padding oracle)
                var encryptor = aes.CreateEncryptor();
                byte[] input = Encoding.UTF8.GetBytes(data);
                byte[] output = encryptor.TransformFinalBlock(input, 0, input.Length);
                return Content(Convert.ToBase64String(output));
            }
        }

        // Test 12: Key in connection string
        public ActionResult GetConnection()
        {
            // VULNERABLE: Key/password in code
            string connStr = "Server=myserver;Database=mydb;User=admin;Password=secret123;";
            return Content(connStr);
        }
    }
}
