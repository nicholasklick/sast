// HTTP Header Injection vulnerabilities in C#
using System;
using System.Web;
using System.Web.Mvc;

namespace VulnerableApp
{
    public class HeaderInjectionController : Controller
    {
        // Test 1: Response splitting via Location header
        public ActionResult Redirect()
        {
            string target = Request.QueryString["target"];
            // VULNERABLE: CRLF can inject additional headers
            Response.Headers.Add("Location", target);
            Response.StatusCode = 302;
            return new EmptyResult();
        }

        // Test 2: Cookie value injection
        public ActionResult SetCookie()
        {
            string value = Request.QueryString["value"];
            // VULNERABLE: Value can contain CRLF
            var cookie = new HttpCookie("session", value);
            Response.Cookies.Add(cookie);
            return Ok();
        }

        // Test 3: Content-Disposition header
        public ActionResult Download()
        {
            string filename = Request.QueryString["filename"];
            // VULNERABLE: Filename can contain CRLF
            Response.Headers.Add("Content-Disposition", $"attachment; filename=\"{filename}\"");
            return File(new byte[0], "application/octet-stream");
        }

        // Test 4: Custom header with user input
        public ActionResult CustomHeader()
        {
            string headerValue = Request.QueryString["header"];
            // VULNERABLE: User controls header value
            Response.Headers.Add("X-Custom-Header", headerValue);
            return Ok();
        }

        // Test 5: Set-Cookie injection
        public ActionResult SetMultipleCookies()
        {
            string name = Request.Form["name"];
            string value = Request.Form["value"];
            // VULNERABLE: Can inject Set-Cookie headers
            Response.Headers.Add("Set-Cookie", $"{name}={value}");
            return Ok();
        }

        // Test 6: Cache-Control header injection
        public ActionResult SetCache()
        {
            string cacheDirective = Request.QueryString["cache"];
            // VULNERABLE: User controls caching behavior
            Response.Headers.Add("Cache-Control", cacheDirective);
            return Ok();
        }

        // Test 7: CORS header injection
        public ActionResult SetCors()
        {
            string origin = Request.Headers["Origin"];
            // VULNERABLE: Reflecting origin without validation
            Response.Headers.Add("Access-Control-Allow-Origin", origin);
            Response.Headers.Add("Access-Control-Allow-Credentials", "true");
            return Ok();
        }

        // Test 8: WWW-Authenticate header
        public ActionResult RequireAuth()
        {
            string realm = Request.QueryString["realm"];
            // VULNERABLE: Realm from user input
            Response.StatusCode = 401;
            Response.Headers.Add("WWW-Authenticate", $"Basic realm=\"{realm}\"");
            return new EmptyResult();
        }

        // Test 9: Link header injection
        public ActionResult AddLinkHeader()
        {
            string url = Request.QueryString["preload"];
            // VULNERABLE: URL in Link header
            Response.Headers.Add("Link", $"<{url}>; rel=preload");
            return Ok();
        }

        // Test 10: Content-Type header
        public ActionResult SetContentType()
        {
            string contentType = Request.QueryString["type"];
            // VULNERABLE: User controls content type
            Response.ContentType = contentType;
            return Content("data");
        }

        // Test 11: X-Forwarded-For reflection
        public ActionResult LogIp()
        {
            string ip = Request.Headers["X-Forwarded-For"];
            // VULNERABLE: Can contain malicious data
            Response.Headers.Add("X-Client-IP", ip);
            return Ok();
        }
    }
}
