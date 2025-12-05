// Null Dereference vulnerabilities in C#
using System;
using System.Collections.Generic;
using System.Linq;
using System.Web.Mvc;

namespace VulnerableApp
{
    public class NullDereferenceController : Controller
    {
        // Test 1: Unchecked query string
        public ActionResult GetParam()
        {
            string param = Request.QueryString["param"];
            // VULNERABLE: param might be null
            return Content(param.ToUpper());
        }

        // Test 2: Dictionary lookup without check
        public ActionResult LookupValue(string key)
        {
            var dict = new Dictionary<string, string>();
            // VULNERABLE: Key might not exist
            string value = dict[key];
            return Content(value);
        }

        // Test 3: FirstOrDefault without null check
        public ActionResult GetFirstUser()
        {
            var users = new List<User>();
            // VULNERABLE: FirstOrDefault returns null if empty
            var user = users.FirstOrDefault();
            return Content(user.Name);  // Null dereference
        }

        // Test 4: Find without null check
        public ActionResult FindItem(int id)
        {
            var items = new List<Item>();
            // VULNERABLE: Find returns null if not found
            var item = items.Find(i => i.Id == id);
            return Json(item.Name);
        }

        // Test 5: Casting that returns null
        public ActionResult CastObject(object obj)
        {
            // VULNERABLE: as returns null if cast fails
            var user = obj as User;
            return Content(user.Name);
        }

        // Test 6: Header without null check
        public ActionResult GetHeader()
        {
            string authHeader = Request.Headers["Authorization"];
            // VULNERABLE: Header might not exist
            return Content(authHeader.Substring(7));
        }

        // Test 7: Cookie without null check
        public ActionResult GetCookie()
        {
            var cookie = Request.Cookies["session"];
            // VULNERABLE: Cookie might not exist
            return Content(cookie.Value);
        }

        // Test 8: Session value without check
        public ActionResult GetSessionData()
        {
            // VULNERABLE: Session value might be null
            var data = Session["userData"];
            return Content(data.ToString());
        }

        // Test 9: ViewBag/ViewData without check
        public ActionResult UseViewData()
        {
            ViewData["user"] = GetUser();
            // In view: VULNERABLE if GetUser returns null
            return View();
        }

        // Test 10: LINQ Single on empty
        public ActionResult GetSingle(int id)
        {
            var items = new List<Item>();
            // VULNERABLE: Throws if not found or multiple
            var item = items.SingleOrDefault(i => i.Id == id);
            return Json(item.Name);  // Null if not found
        }

        // Test 11: Array element access
        public ActionResult GetElement()
        {
            string[] arr = new string[5];
            // VULNERABLE: Elements initialized to null
            return Content(arr[0].Length.ToString());
        }

        // Test 12: Return value not checked
        public ActionResult ProcessResult()
        {
            var result = GetNullableResult();
            // VULNERABLE: result might be null
            return Content(result.Status);
        }

        // Test 13: Chained null access
        public ActionResult ChainedAccess()
        {
            var order = GetOrder();
            // VULNERABLE: Any link in chain could be null
            return Content(order.Customer.Address.City);
        }

        // Test 14: Conditional access incomplete
        public ActionResult PartialCheck()
        {
            var user = GetUser();
            if (user != null)
            {
                // VULNERABLE: Address might still be null
                return Content(user.Address.Street);
            }
            return Ok();
        }

        // Placeholder types and methods
        private User GetUser() => null;
        private Order GetOrder() => null;
        private Result GetNullableResult() => null;

        private class User { public string Name; public Address Address; }
        private class Address { public string Street; public string City; }
        private class Item { public int Id; public string Name; }
        private class Order { public Customer Customer; }
        private class Customer { public Address Address; }
        private class Result { public string Status; }
    }
}
