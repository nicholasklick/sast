// C# Vulnerability Test Fixtures
using System;
using System.Data.SqlClient;
using System.Diagnostics;
using System.IO;
using System.Security.Cryptography;
using System.Text;
using System.Xml;

namespace VulnerabilityExamples
{
    public class CSharpVulnerabilities
    {
        // 1. SQL Injection - String concatenation
        public string SqlInjectionConcat(string userId)
        {
            using (SqlConnection conn = new SqlConnection("connectionString"))
            {
                conn.Open();
                string query = "SELECT * FROM users WHERE id = '" + userId + "'";
                SqlCommand cmd = new SqlCommand(query, conn);
                SqlDataReader reader = cmd.ExecuteReader();
                return reader.Read() ? reader["name"].ToString() : "";
            }
        }

        // 2. SQL Injection - String.Format
        public bool SqlInjectionFormat(string username)
        {
            using (SqlConnection conn = new SqlConnection("connectionString"))
            {
                conn.Open();
                string query = string.Format("SELECT * FROM users WHERE username = '{0}'", username);
                SqlCommand cmd = new SqlCommand(query, conn);
                SqlDataReader reader = cmd.ExecuteReader();
                return reader.Read();
            }
        }

        // 3. Command Injection
        public void CommandInjection(string filename)
        {
            Process.Start("cmd.exe", "/c type " + filename);
        }

        // 4. Command Injection - ProcessStartInfo
        public string CommandInjectionProcess(string userInput)
        {
            ProcessStartInfo psi = new ProcessStartInfo()
            {
                FileName = "cmd.exe",
                Arguments = "/c dir " + userInput,
                RedirectStandardOutput = true,
                UseShellExecute = false
            };
            Process process = Process.Start(psi);
            return process.StandardOutput.ReadToEnd();
        }

        // 5. Path Traversal
        public string PathTraversal(string filename)
        {
            string path = Path.Combine("/var/data", filename);
            return File.ReadAllText(path);
        }

        // 6. Hardcoded Credentials - API Key
        private const string API_KEY = "sk_live_csharp1234567890";

        // 7. Hardcoded Credentials - Password
        public void ConnectToDatabase()
        {
            string password = "CSharpSecret789!";
            string connString = $"Server=localhost;Database=mydb;User=admin;Password={password}";
        }

        // 8. Weak Cryptography - DES
        public byte[] WeakCryptoDes(byte[] data)
        {
            using (DESCryptoServiceProvider des = new DESCryptoServiceProvider())
            {
                des.Key = Encoding.UTF8.GetBytes("12345678");
                des.IV = Encoding.UTF8.GetBytes("12345678");
                using (ICryptoTransform encryptor = des.CreateEncryptor())
                {
                    return encryptor.TransformFinalBlock(data, 0, data.Length);
                }
            }
        }

        // 9. Weak Cryptography - MD5
        public string WeakHashMd5(string input)
        {
            using (MD5 md5 = MD5.Create())
            {
                byte[] hash = md5.ComputeHash(Encoding.UTF8.GetBytes(input));
                return BitConverter.ToString(hash);
            }
        }

        // 10. XXE Vulnerability
        public void ParseXml(string xmlContent)
        {
            XmlDocument doc = new XmlDocument();
            // Missing: doc.XmlResolver = null;
            doc.LoadXml(xmlContent);
        }

        // 11. Insecure Deserialization
        public object DeserializeObject(byte[] data)
        {
            using (MemoryStream ms = new MemoryStream(data))
            {
                System.Runtime.Serialization.Formatters.Binary.BinaryFormatter bf =
                    new System.Runtime.Serialization.Formatters.Binary.BinaryFormatter();
                return bf.Deserialize(ms);
            }
        }

        // 12. LDAP Injection
        public bool LdapInjection(string username)
        {
            string filter = $"(uid={username})";
            // LDAP query with unvalidated user input
            return false;
        }

        // 13. XSS (in ASP.NET context)
        public string RenderHtml(string userInput)
        {
            return $"<html><body><h1>Welcome {userInput}</h1></body></html>";
        }

        // 14. SSRF Vulnerability
        public string FetchUrl(string url)
        {
            using (System.Net.WebClient client = new System.Net.WebClient())
            {
                return client.DownloadString(url);
            }
        }

        // 15. Unsafe Random Number Generation
        public string GenerateToken()
        {
            Random random = new Random();
            return random.Next().ToString();
        }

        // 16. Open Redirect
        public void Redirect(string url)
        {
            // Response.Redirect(url); - vulnerable
            Console.WriteLine($"Redirecting to: {url}");
        }

        // 17. Zip Slip Vulnerability
        public string ExtractZip(System.IO.Compression.ZipArchiveEntry entry, string targetDir)
        {
            string destinationPath = Path.Combine(targetDir, entry.FullName);
            // Missing path traversal check
            return destinationPath;
        }

        // 18. Template Injection
        public string RenderTemplate(string userInput)
        {
            return $"<html><body><h1>Welcome {userInput}</h1></body></html>";
        }

        // 19. Disabled Certificate Validation
        public void DisableCertValidation()
        {
            System.Net.ServicePointManager.ServerCertificateValidationCallback =
                (sender, certificate, chain, sslPolicyErrors) => true;
        }

        // 20. NoSQL Injection (MongoDB-like)
        public string MongoQuery(string userId)
        {
            return $"{{ \"userId\": \"{userId}\" }}";
        }
    }
}
