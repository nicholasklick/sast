// Regular Expression DoS (ReDoS) vulnerabilities in C#
using System;
using System.Text.RegularExpressions;
using System.Web.Mvc;

namespace VulnerableApp
{
    public class RegexController : Controller
    {
        // Test 1: Nested quantifiers
        public ActionResult ValidateNested()
        {
            string input = Request.QueryString["input"];
            // VULNERABLE: (a+)+ causes exponential backtracking
            var regex = new Regex(@"(a+)+b");
            bool match = regex.IsMatch(input);
            return Json(match);
        }

        // Test 2: Overlapping alternation
        public ActionResult ValidateOverlap()
        {
            string input = Request.QueryString["input"];
            // VULNERABLE: Overlapping alternatives
            var regex = new Regex(@"(a|a)+b");
            return Json(regex.IsMatch(input));
        }

        // Test 3: Email validation with ReDoS
        public ActionResult ValidateEmail()
        {
            string email = Request.Form["email"];
            // VULNERABLE: Classic email ReDoS pattern
            var regex = new Regex(@"^([a-zA-Z0-9]+)+@([a-zA-Z0-9]+)+\.([a-zA-Z]+)+$");
            return Json(regex.IsMatch(email));
        }

        // Test 4: URL validation ReDoS
        public ActionResult ValidateUrl()
        {
            string url = Request.QueryString["url"];
            // VULNERABLE: Nested groups in URL pattern
            var regex = new Regex(@"^(https?://)?([a-zA-Z0-9.-]+)+(/.*)*$");
            return Json(regex.IsMatch(url));
        }

        // Test 5: User-supplied regex pattern
        public ActionResult CustomMatch()
        {
            string input = Request.Form["input"];
            string pattern = Request.Form["pattern"];
            // VULNERABLE: User can supply malicious pattern
            var regex = new Regex(pattern);
            return Json(regex.IsMatch(input));
        }

        // Test 6: No timeout set
        public ActionResult NoTimeout()
        {
            string input = Request.QueryString["input"];
            // VULNERABLE: No timeout, can hang forever
            var regex = new Regex(@"(.*)*evil");
            return Json(regex.IsMatch(input));
        }

        // Test 7: Static regex with ReDoS pattern
        private static readonly Regex BadPattern = new Regex(@"([a-z]+)*$");

        public ActionResult StaticRegex()
        {
            string input = Request.QueryString["input"];
            // VULNERABLE: Static pattern with backtracking
            return Json(BadPattern.IsMatch(input));
        }

        // Test 8: Compiled regex with ReDoS
        public ActionResult CompiledRegex()
        {
            string input = Request.QueryString["input"];
            // VULNERABLE: Compiled doesn't prevent ReDoS
            var regex = new Regex(@"(x+x+)+y", RegexOptions.Compiled);
            return Json(regex.IsMatch(input));
        }

        // Test 9: Replace with ReDoS
        public ActionResult ReplacePattern()
        {
            string input = Request.Form["input"];
            // VULNERABLE: Replace also affected by ReDoS
            var regex = new Regex(@"(a+)+");
            string result = regex.Replace(input, "X");
            return Content(result);
        }

        // Test 10: Split with ReDoS
        public ActionResult SplitPattern()
        {
            string input = Request.Form["input"];
            // VULNERABLE: Split can trigger ReDoS
            var regex = new Regex(@"(\s+)+");
            string[] parts = regex.Split(input);
            return Json(parts);
        }

        // Test 11: Multiline ReDoS
        public ActionResult MultilinePattern()
        {
            string input = Request.Form["content"];
            // VULNERABLE: Multiline doesn't prevent ReDoS
            var regex = new Regex(@"^(.+)+$", RegexOptions.Multiline);
            return Json(regex.IsMatch(input));
        }

        // Test 12: HTML tag matching ReDoS
        public ActionResult MatchHtmlTag()
        {
            string html = Request.Form["html"];
            // VULNERABLE: Complex HTML pattern
            var regex = new Regex(@"<([a-z]+)([^>]*)*>");
            return Json(regex.Matches(html).Count);
        }
    }
}
