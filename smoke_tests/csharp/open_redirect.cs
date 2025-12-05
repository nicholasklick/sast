// Open Redirect vulnerabilities in C#
using System;
using System.Web;
using System.Web.Mvc;

namespace VulnerableApp
{
    public class RedirectController : Controller
    {
        // Test 1: Direct redirect from query parameter
        public ActionResult Login()
        {
            string returnUrl = Request.QueryString["returnUrl"];
            // VULNERABLE: Unvalidated redirect
            return Redirect(returnUrl);
        }

        // Test 2: RedirectToAction with external URL
        public ActionResult Logout()
        {
            string target = Request.QueryString["target"];
            // VULNERABLE: Can redirect to external URL
            return Redirect(target);
        }

        // Test 3: Response.Redirect
        public void DirectRedirect()
        {
            string url = Request.QueryString["url"];
            // VULNERABLE: Unvalidated redirect
            Response.Redirect(url);
        }

        // Test 4: Partial validation bypass
        public ActionResult SafeRedirect()
        {
            string url = Request.QueryString["url"];
            // VULNERABLE: Can be bypassed with //evil.com
            if (url.StartsWith("/"))
            {
                return Redirect(url);
            }
            return RedirectToAction("Index");
        }

        // Test 5: URL in form data
        public ActionResult ProcessForm()
        {
            string nextPage = Request.Form["next"];
            // VULNERABLE: Form data redirect
            return Redirect(nextPage);
        }

        // Test 6: Cookie-based redirect
        public ActionResult RestoreSession()
        {
            string returnUrl = Request.Cookies["returnUrl"]?.Value;
            // VULNERABLE: Cookie can be manipulated
            if (!string.IsNullOrEmpty(returnUrl))
            {
                return Redirect(returnUrl);
            }
            return RedirectToAction("Index");
        }

        // Test 7: Header-based redirect
        public ActionResult HandleRequest()
        {
            string referer = Request.Headers["X-Return-Url"];
            // VULNERABLE: Header-based redirect
            if (!string.IsNullOrEmpty(referer))
            {
                return Redirect(referer);
            }
            return View();
        }

        // Test 8: JavaScript redirect
        public ActionResult JsRedirect()
        {
            string url = Request.QueryString["url"];
            // VULNERABLE: JavaScript redirect with user URL
            return Content($"<script>window.location='{url}';</script>", "text/html");
        }

        // Test 9: Meta refresh redirect
        public ActionResult MetaRedirect()
        {
            string target = Request.QueryString["target"];
            // VULNERABLE: Meta refresh with user URL
            return Content($"<meta http-equiv='refresh' content='0;url={target}'>", "text/html");
        }

        // Test 10: Domain validation bypass
        public ActionResult DomainCheck()
        {
            string url = Request.QueryString["url"];
            // VULNERABLE: evil.example.com contains example.com
            if (url.Contains("example.com"))
            {
                return Redirect(url);
            }
            return RedirectToAction("Index");
        }

        // Test 11: LocalRedirect misuse
        public ActionResult AfterAuth()
        {
            string returnUrl = Request.QueryString["returnUrl"];
            // VULNERABLE: If Url.IsLocalUrl is not called first
            if (!string.IsNullOrEmpty(returnUrl))
            {
                return Redirect(returnUrl);
            }
            return RedirectToAction("Index");
        }
    }
}
