// Authorization vulnerabilities in C#
using System;
using System.Web.Mvc;

namespace VulnerableApp
{
    public class AuthorizationController : Controller
    {
        // Test 1: Missing authorization attribute
        public ActionResult AdminDashboard()
        {
            // VULNERABLE: No [Authorize] attribute
            return View();
        }

        // Test 2: Insecure Direct Object Reference (IDOR)
        public ActionResult ViewDocument(int documentId)
        {
            // VULNERABLE: No ownership check
            var document = GetDocument(documentId);
            return Json(document);
        }

        // Test 3: Horizontal privilege escalation
        public ActionResult ViewProfile(int userId)
        {
            // VULNERABLE: Can view any user's profile
            var profile = GetUserProfile(userId);
            return Json(profile);
        }

        // Test 4: Vertical privilege escalation
        [Authorize]
        public ActionResult DeleteUser(int userId)
        {
            // VULNERABLE: No role check for admin action
            DeleteUserById(userId);
            return Ok();
        }

        // Test 5: Client-side authorization
        public ActionResult GetSecretData()
        {
            // VULNERABLE: Relying on client-side check
            // JavaScript checks role but server doesn't
            return Json(new { secret = "sensitive data" });
        }

        // Test 6: Predictable resource IDs
        public ActionResult GetOrder(int orderId)
        {
            // VULNERABLE: Sequential IDs allow enumeration
            var order = GetOrderById(orderId);
            return Json(order);
        }

        // Test 7: Missing function level access control
        public ActionResult ExecuteAdminFunction(string function)
        {
            // VULNERABLE: No check if user can execute function
            ExecuteFunction(function);
            return Ok();
        }

        // Test 8: Path-based authorization bypass
        public ActionResult AdminApi()
        {
            string path = Request.Path;
            // VULNERABLE: Path check can be bypassed
            // /ADMIN/api or /admin/../admin/api
            if (path.ToLower().StartsWith("/admin"))
            {
                return Json(new { data = "admin data" });
            }
            return Unauthorized();
        }

        // Test 9: JWT without signature verification
        public ActionResult ValidateToken()
        {
            string token = Request.Headers["Authorization"];
            // VULNERABLE: Not verifying JWT signature
            var parts = token.Split('.');
            var payload = parts[1];  // Just decoding, not verifying
            return Ok();
        }

        // Test 10: Role check in wrong place
        public ActionResult UpdateSettings()
        {
            UpdateSystemSettings();  // Action happens first
            // VULNERABLE: Check after action
            if (!User.IsInRole("Admin"))
            {
                return Unauthorized();
            }
            return Ok();
        }

        // Test 11: Trusting user-provided role
        public ActionResult ActionWithRole()
        {
            string role = Request.Headers["X-User-Role"];
            // VULNERABLE: Trusting client-provided role
            if (role == "admin")
            {
                return Json(new { adminData = true });
            }
            return Ok();
        }

        // Test 12: Cached authorization
        [OutputCache(Duration = 3600)]
        [Authorize(Roles = "Admin")]
        public ActionResult CachedAdminPage()
        {
            // VULNERABLE: Cached page may be served to non-admins
            return View();
        }

        // Placeholder methods
        private object GetDocument(int id) => new { };
        private object GetUserProfile(int id) => new { };
        private void DeleteUserById(int id) { }
        private object GetOrderById(int id) => new { };
        private void ExecuteFunction(string f) { }
        private void UpdateSystemSettings() { }
    }
}
