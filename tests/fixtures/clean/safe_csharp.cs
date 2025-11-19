// Clean C# code with no vulnerabilities
using System;
using System.Data.SqlClient;
using System.IO;
using System.Security.Cryptography;
using System.Text;
using System.Linq;

namespace SafeCode
{
    public class SafeCSharpCode
    {
        // Safe SQL Query - Parameterized
        public string GetUserById(SqlConnection conn, int userId)
        {
            string query = "SELECT name FROM users WHERE id = @userId";
            using (SqlCommand cmd = new SqlCommand(query, conn))
            {
                cmd.Parameters.AddWithValue("@userId", userId);
                using (SqlDataReader reader = cmd.ExecuteReader())
                {
                    return reader.Read() ? reader["name"].ToString() : null;
                }
            }
        }

        // Safe File Access - Path validation
        public string ReadFile(string filename)
        {
            string basePath = Path.GetFullPath("/var/data");
            string fullPath = Path.GetFullPath(Path.Combine(basePath, filename));

            if (!fullPath.StartsWith(basePath))
            {
                throw new SecurityException("Path traversal detected");
            }

            return File.ReadAllText(fullPath);
        }

        // Safe Configuration
        public string GetApiKey()
        {
            string apiKey = Environment.GetEnvironmentVariable("API_KEY");
            if (string.IsNullOrEmpty(apiKey))
            {
                throw new InvalidOperationException("API_KEY not set");
            }
            return apiKey;
        }

        // Safe Cryptography - AES-GCM
        public byte[] EncryptData(byte[] data, byte[] key)
        {
            using (AesGcm aesGcm = new AesGcm(key))
            {
                byte[] nonce = new byte[AesGcm.NonceByteSizes.MaxSize];
                byte[] tag = new byte[AesGcm.TagByteSizes.MaxSize];
                byte[] ciphertext = new byte[data.Length];

                RandomNumberGenerator.Fill(nonce);
                aesGcm.Encrypt(nonce, data, ciphertext, tag);

                return ciphertext.Concat(tag).Concat(nonce).ToArray();
            }
        }

        // Safe Hashing - SHA-256
        public string HashPassword(string password)
        {
            using (SHA256 sha256 = SHA256.Create())
            {
                byte[] hash = sha256.ComputeHash(Encoding.UTF8.GetBytes(password));
                return BitConverter.ToString(hash).Replace("-", "").ToLower();
            }
        }

        // Safe Random Generation
        public string GenerateSecureToken()
        {
            byte[] bytes = new byte[32];
            using (RandomNumberGenerator rng = RandomNumberGenerator.Create())
            {
                rng.GetBytes(bytes);
            }
            return BitConverter.ToString(bytes).Replace("-", "").ToLower();
        }

        // Safe XML Processing
        public void ParseXmlSafely(string xmlContent)
        {
            System.Xml.XmlDocument doc = new System.Xml.XmlDocument();
            doc.XmlResolver = null;  // Disable external entity resolution
            doc.LoadXml(xmlContent);
        }

        // Safe Input Validation
        public string ValidateAndSanitize(string input)
        {
            return new string(input.Where(c => char.IsLetterOrDigit(c) || c == '_' || c == '-').ToArray());
        }

        // Safe URL Validation
        public string FetchUrl(string url)
        {
            var allowedHosts = new[] { "api.example.com", "data.example.com" };
            Uri uri = new Uri(url);

            if (!allowedHosts.Contains(uri.Host))
            {
                throw new SecurityException("Host not allowed");
            }

            using (var client = new System.Net.WebClient())
            {
                return client.DownloadString(url);
            }
        }

        // Safe Exception Handling
        public void SafeOperation()
        {
            try
            {
                // Potentially dangerous operation
                int[] array = new int[10];
                int value = array[5];  // Safe access
            }
            catch (Exception ex)
            {
                Console.WriteLine($"Error: {ex.Message}");
            }
        }
    }
}
