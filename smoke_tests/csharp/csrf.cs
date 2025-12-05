// Cross-Site Request Forgery (CSRF) vulnerabilities in C#
using System;
using System.Web.Mvc;

namespace VulnerableApp
{
    public class CsrfController : Controller
    {
        // Test 1: Missing ValidateAntiForgeryToken
        [HttpPost]
        public ActionResult TransferFunds(decimal amount, string toAccount)
        {
            // VULNERABLE: No CSRF token validation
            ProcessTransfer(amount, toAccount);
            return Ok();
        }

        // Test 2: State change via GET request
        [HttpGet]
        public ActionResult DeleteAccount(int id)
        {
            // VULNERABLE: State change should not be GET
            DeleteUser(id);
            return RedirectToAction("Index");
        }

        // Test 3: Missing token on sensitive action
        [HttpPost]
        public ActionResult ChangePassword(string newPassword)
        {
            // VULNERABLE: Password change without CSRF protection
            UpdatePassword(User.Identity.Name, newPassword);
            return Ok();
        }

        // Test 4: Missing token on email change
        [HttpPost]
        public ActionResult ChangeEmail(string newEmail)
        {
            // VULNERABLE: Email change without CSRF protection
            UpdateEmail(User.Identity.Name, newEmail);
            return Ok();
        }

        // Test 5: AJAX without anti-forgery
        [HttpPost]
        public JsonResult UpdateProfile(string name, string bio)
        {
            // VULNERABLE: AJAX endpoint without CSRF token
            UpdateUserProfile(name, bio);
            return Json(new { success = true });
        }

        // Test 6: Token only checked on some methods
        [HttpPost]
        [ValidateAntiForgeryToken]
        public ActionResult CreateOrder(Order order)
        {
            return Ok();
        }

        [HttpPost]
        public ActionResult CancelOrder(int orderId)
        {
            // VULNERABLE: Related action without token
            CancelOrderById(orderId);
            return Ok();
        }

        // Test 7: CORS misconfiguration allowing CSRF
        [HttpPost]
        public ActionResult ApiEndpoint()
        {
            // VULNERABLE: If CORS allows any origin with credentials
            Response.Headers.Add("Access-Control-Allow-Origin", "*");
            Response.Headers.Add("Access-Control-Allow-Credentials", "true");
            return Ok();
        }

        // Test 8: Cookie without SameSite
        public ActionResult SetAuthCookie()
        {
            var cookie = new System.Web.HttpCookie("auth", "value")
            {
                // VULNERABLE: Missing SameSite attribute
                HttpOnly = true,
                Secure = true
                // SameSite not set
            };
            Response.Cookies.Add(cookie);
            return Ok();
        }

        // Test 9: Admin action without CSRF
        [HttpPost]
        [Authorize(Roles = "Admin")]
        public ActionResult PromoteUser(int userId)
        {
            // VULNERABLE: Admin action without CSRF protection
            SetUserRole(userId, "Admin");
            return Ok();
        }

        // Test 10: Form with autocomplete for sensitive data
        public ActionResult PaymentForm()
        {
            // VULNERABLE: No CSRF token in form
            return View();  // View would need @Html.AntiForgeryToken()
        }

        // Test 11: Token in query string
        [HttpPost]
        public ActionResult ProcessPayment(string token)
        {
            // VULNERABLE: Token should be in header or form body
            // Query string tokens can leak via Referer
            if (ValidateToken(token))
            {
                return Ok();
            }
            return Unauthorized();
        }

        // Placeholder methods
        private void ProcessTransfer(decimal amount, string to) { }
        private void DeleteUser(int id) { }
        private void UpdatePassword(string user, string pass) { }
        private void UpdateEmail(string user, string email) { }
        private void UpdateUserProfile(string name, string bio) { }
        private void CancelOrderById(int id) { }
        private void SetUserRole(int id, string role) { }
        private bool ValidateToken(string token) => true;
    }

    public class Order
    {
        public int ProductId { get; set; }
        public int Quantity { get; set; }
    }
}
