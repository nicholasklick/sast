// Authentication vulnerabilities in C#
using System;
using System.Web;
using System.Web.Mvc;
using System.Web.Security;
using System.Security.Cryptography;
using System.Text;

namespace VulnerableApp
{
    public class AuthController : Controller
    {
        // Test 1: Plaintext password storage
        public ActionResult Register()
        {
            string username = Request.Form["username"];
            string password = Request.Form["password"];
            // VULNERABLE: Storing plaintext password
            SaveUser(username, password);
            return Ok();
        }

        // Test 2: Weak password hashing (MD5)
        public ActionResult RegisterMd5()
        {
            string password = Request.Form["password"];
            // VULNERABLE: MD5 is too weak for passwords
            using (var md5 = MD5.Create())
            {
                byte[] hash = md5.ComputeHash(Encoding.UTF8.GetBytes(password));
                string hashedPassword = BitConverter.ToString(hash).Replace("-", "");
                SaveUser(Request.Form["username"], hashedPassword);
            }
            return Ok();
        }

        // Test 3: Unsalted SHA hash
        public ActionResult RegisterSha()
        {
            string password = Request.Form["password"];
            // VULNERABLE: No salt, allows rainbow table attacks
            using (var sha = SHA256.Create())
            {
                byte[] hash = sha.ComputeHash(Encoding.UTF8.GetBytes(password));
                SaveUser(Request.Form["username"], Convert.ToBase64String(hash));
            }
            return Ok();
        }

        // Test 4: Hardcoded credentials
        public ActionResult AdminLogin()
        {
            string username = Request.Form["username"];
            string password = Request.Form["password"];
            // VULNERABLE: Hardcoded credentials
            if (username == "admin" && password == "admin123")
            {
                FormsAuthentication.SetAuthCookie(username, false);
                return RedirectToAction("Dashboard");
            }
            return View();
        }

        // Test 5: Timing attack in comparison
        public ActionResult Login()
        {
            string username = Request.Form["username"];
            string password = Request.Form["password"];
            string storedHash = GetPasswordHash(username);
            string inputHash = HashPassword(password);
            // VULNERABLE: String comparison leaks timing information
            if (storedHash == inputHash)
            {
                return Ok();
            }
            return Unauthorized();
        }

        // Test 6: No account lockout
        public ActionResult LoginNoLockout()
        {
            string username = Request.Form["username"];
            string password = Request.Form["password"];
            // VULNERABLE: No failed attempt tracking/lockout
            if (ValidateCredentials(username, password))
            {
                return Ok();
            }
            return Unauthorized();
        }

        // Test 7: Password in URL
        public ActionResult LoginViaGet(string username, string password)
        {
            // VULNERABLE: Credentials in URL (logged, cached, referer header)
            if (ValidateCredentials(username, password))
            {
                return Ok();
            }
            return Unauthorized();
        }

        // Test 8: Password logged
        public ActionResult LoginWithLogging()
        {
            string username = Request.Form["username"];
            string password = Request.Form["password"];
            // VULNERABLE: Password in logs
            System.Diagnostics.Debug.WriteLine($"Login attempt: {username}/{password}");
            return Ok();
        }

        // Test 9: Weak session configuration
        public ActionResult CreateSession()
        {
            // VULNERABLE: Session cookie without secure flags
            Response.Cookies.Add(new HttpCookie("sessionId", Guid.NewGuid().ToString())
            {
                HttpOnly = false,  // Vulnerable to XSS
                Secure = false     // Sent over HTTP
            });
            return Ok();
        }

        // Test 10: Insufficient password requirements
        public ActionResult SetPassword()
        {
            string password = Request.Form["password"];
            // VULNERABLE: No complexity requirements
            if (password.Length >= 4)  // Too short, no complexity check
            {
                SavePassword(password);
            }
            return Ok();
        }

        // Test 11: Remember me with long expiration
        public ActionResult PersistentLogin()
        {
            string username = Request.Form["username"];
            // VULNERABLE: Very long token lifetime
            FormsAuthentication.SetAuthCookie(username, true);
            var cookie = Response.Cookies[FormsAuthentication.FormsCookieName];
            cookie.Expires = DateTime.Now.AddYears(10);  // Too long
            return Ok();
        }

        // Placeholder methods
        private void SaveUser(string username, string password) { }
        private string GetPasswordHash(string username) => "";
        private string HashPassword(string password) => "";
        private bool ValidateCredentials(string u, string p) => false;
        private void SavePassword(string p) { }
    }
}
