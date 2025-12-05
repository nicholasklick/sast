// Insecure Randomness vulnerabilities in C#
using System;
using System.Security.Cryptography;
using System.Text;
using System.Web.Mvc;

namespace VulnerableApp
{
    public class RandomController : Controller
    {
        // Test 1: System.Random for security-sensitive token
        public ActionResult GenerateToken()
        {
            // VULNERABLE: System.Random is not cryptographically secure
            var random = new Random();
            var token = new StringBuilder();
            for (int i = 0; i < 32; i++)
            {
                token.Append(random.Next(16).ToString("x"));
            }
            return Content(token.ToString());
        }

        // Test 2: Random with predictable seed
        public ActionResult GenerateWithSeed()
        {
            // VULNERABLE: Predictable seed
            var random = new Random(42);
            return Json(random.Next());
        }

        // Test 3: Time-based seed
        public ActionResult TimeBasedRandom()
        {
            // VULNERABLE: Time-based seed is predictable
            var random = new Random((int)DateTime.Now.Ticks);
            return Json(random.Next());
        }

        // Test 4: Random for password generation
        public ActionResult GeneratePassword()
        {
            const string chars = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789";
            // VULNERABLE: Using Random for password
            var random = new Random();
            var password = new char[12];
            for (int i = 0; i < 12; i++)
            {
                password[i] = chars[random.Next(chars.Length)];
            }
            return Content(new string(password));
        }

        // Test 5: Random for session ID
        public ActionResult CreateSession()
        {
            // VULNERABLE: Session ID must be cryptographically random
            var random = new Random();
            string sessionId = random.Next().ToString("x8") +
                             random.Next().ToString("x8");
            return Content(sessionId);
        }

        // Test 6: Random for CSRF token
        public ActionResult GetCsrfToken()
        {
            // VULNERABLE: CSRF token needs crypto random
            var random = new Random();
            byte[] tokenBytes = new byte[16];
            for (int i = 0; i < 16; i++)
            {
                tokenBytes[i] = (byte)random.Next(256);
            }
            return Content(Convert.ToBase64String(tokenBytes));
        }

        // Test 7: Random for encryption key
        public ActionResult GenerateKey()
        {
            // VULNERABLE: Encryption keys must be crypto random
            var random = new Random();
            byte[] key = new byte[32];
            random.NextBytes(key);
            return Content(Convert.ToBase64String(key));
        }

        // Test 8: Random for IV/nonce
        public ActionResult GenerateIv()
        {
            // VULNERABLE: IV must be unpredictable
            var random = new Random();
            byte[] iv = new byte[16];
            random.NextBytes(iv);
            return Content(Convert.ToBase64String(iv));
        }

        // Test 9: Random for API key
        public ActionResult GenerateApiKey()
        {
            // VULNERABLE: API key should be crypto random
            var random = new Random();
            return Content(Guid.NewGuid().ToString() + random.Next().ToString("x8"));
        }

        // Test 10: Static Random instance (thread safety issues)
        private static Random _staticRandom = new Random();

        public ActionResult StaticRandom()
        {
            // VULNERABLE: Not thread-safe and not crypto secure
            return Json(_staticRandom.Next());
        }

        // Test 11: Random for OTP
        public ActionResult GenerateOtp()
        {
            // VULNERABLE: OTP must be crypto random
            var random = new Random();
            int otp = random.Next(100000, 999999);
            return Content(otp.ToString());
        }

        // Test 12: Environment.TickCount seed
        public ActionResult TickCountSeed()
        {
            // VULNERABLE: TickCount is predictable
            var random = new Random(Environment.TickCount);
            return Json(random.Next());
        }
    }
}
