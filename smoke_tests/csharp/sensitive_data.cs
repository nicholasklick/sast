// Sensitive Data Exposure vulnerabilities in C#
using System;
using System.IO;
using System.Web.Mvc;
using System.Diagnostics;

namespace VulnerableApp
{
    public class SensitiveDataController : Controller
    {
        // Test 1: Sensitive data in error message
        public ActionResult Login()
        {
            try
            {
                ProcessLogin();
            }
            catch (Exception ex)
            {
                // VULNERABLE: Stack trace exposes internals
                return Content($"Error: {ex.ToString()}");
            }
            return Ok();
        }

        // Test 2: Debug info in production
        public ActionResult GetData()
        {
            var data = LoadData();
            // VULNERABLE: Debug information in response
            return Json(new
            {
                data,
                debug = new
                {
                    server = Environment.MachineName,
                    user = Environment.UserName,
                    path = Environment.CurrentDirectory
                }
            });
        }

        // Test 3: Logging sensitive data
        public ActionResult ProcessPayment()
        {
            string ccNumber = Request.Form["cardNumber"];
            string cvv = Request.Form["cvv"];
            // VULNERABLE: Logging credit card data
            Debug.WriteLine($"Processing card: {ccNumber}, CVV: {cvv}");
            return Ok();
        }

        // Test 4: Sensitive data in URL
        public ActionResult ShowAccount(string ssn, string accountNumber)
        {
            // VULNERABLE: SSN and account in URL (logs, history, referer)
            return View(new { SSN = ssn, Account = accountNumber });
        }

        // Test 5: Caching sensitive responses
        [OutputCache(Duration = 3600)]
        public ActionResult GetUserDetails()
        {
            // VULNERABLE: Sensitive user data being cached
            return Json(new
            {
                userId = User.Identity.Name,
                email = "user@example.com",
                ssn = "123-45-6789"
            });
        }

        // Test 6: Missing encryption for sensitive data
        public ActionResult StoreData()
        {
            string ssn = Request.Form["ssn"];
            // VULNERABLE: Storing SSN without encryption
            File.WriteAllText("/data/user.txt", ssn);
            return Ok();
        }

        // Test 7: Verbose error pages
        public ActionResult Detail(int id)
        {
            try
            {
                var item = GetItem(id);
                return Json(item);
            }
            catch (Exception ex)
            {
                // VULNERABLE: Full exception details to client
                return Json(new
                {
                    error = ex.Message,
                    stackTrace = ex.StackTrace,
                    source = ex.Source,
                    innerException = ex.InnerException?.Message
                });
            }
        }

        // Test 8: API key in response
        public ActionResult GetConfig()
        {
            // VULNERABLE: API keys exposed to client
            return Json(new
            {
                apiEndpoint = "https://api.example.com",
                apiKey = "sk-12345-secret-key",  // Sensitive!
                dbConnection = "Server=prod;Password=secret123"  // Sensitive!
            });
        }

        // Test 9: Missing secure header
        public ActionResult SecurePage()
        {
            // VULNERABLE: Missing security headers
            // No X-Content-Type-Options
            // No X-Frame-Options
            // No Content-Security-Policy
            return View();
        }

        // Test 10: HTTP for sensitive data
        public ActionResult RedirectToPayment()
        {
            // VULNERABLE: Using HTTP for payment page
            return Redirect("http://payment.example.com/checkout");
        }

        // Test 11: PII in ViewBag
        public ActionResult Profile()
        {
            ViewBag.SSN = "123-45-6789";
            ViewBag.CreditCard = "4111111111111111";
            // VULNERABLE: PII might be exposed in view
            return View();
        }

        // Test 12: Autocomplete enabled for sensitive fields
        public ActionResult PaymentForm()
        {
            // VULNERABLE: Form doesn't disable autocomplete for sensitive fields
            return View();  // View has <input name="ccNumber" /> without autocomplete="off"
        }

        // Placeholder methods
        private void ProcessLogin() { }
        private object LoadData() => new { };
        private object GetItem(int id) => new { };
    }
}
