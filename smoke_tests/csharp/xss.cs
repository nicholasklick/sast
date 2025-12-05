// Cross-Site Scripting (XSS) vulnerabilities in C#
using System;
using System.Web;
using System.Web.UI;
using System.Web.Mvc;
using System.Text;

namespace VulnerableApp
{
    public class XssController : Controller
    {
        // Test 1: Direct output of user input
        public ActionResult Echo()
        {
            string input = Request.QueryString["input"];
            // VULNERABLE: Direct output without encoding
            Response.Write("<div>" + input + "</div>");
            return Content("");
        }

        // Test 2: Using Html.Raw with user input
        public ActionResult RawHtml()
        {
            string content = Request.Form["content"];
            // VULNERABLE: Html.Raw bypasses encoding
            ViewBag.Content = new HtmlString(content);
            return View();
        }

        // Test 3: Building HTML string
        public ActionResult BuildHtml()
        {
            string name = Request.QueryString["name"];
            var sb = new StringBuilder();
            // VULNERABLE: User input in HTML
            sb.Append("<h1>Hello, " + name + "</h1>");
            return Content(sb.ToString(), "text/html");
        }

        // Test 4: JavaScript context
        public ActionResult JsContext()
        {
            string callback = Request.QueryString["callback"];
            // VULNERABLE: User input in JavaScript
            string script = $"<script>{callback}(data);</script>";
            return Content(script, "text/html");
        }

        // Test 5: Attribute context
        public ActionResult AttrContext()
        {
            string url = Request.QueryString["url"];
            // VULNERABLE: User input in attribute
            string html = $"<a href=\"{url}\">Click here</a>";
            return Content(html, "text/html");
        }

        // Test 6: Event handler context
        public ActionResult EventHandler()
        {
            string action = Request.QueryString["action"];
            // VULNERABLE: User input in event handler
            string html = $"<button onclick=\"{action}\">Click</button>";
            return Content(html, "text/html");
        }

        // Test 7: CSS context injection
        public ActionResult CssContext()
        {
            string color = Request.QueryString["color"];
            // VULNERABLE: User input in style
            string html = $"<div style=\"background:{color}\">Content</div>";
            return Content(html, "text/html");
        }

        // Test 8: JSON response without encoding
        public ActionResult JsonOutput()
        {
            string data = Request.QueryString["data"];
            // VULNERABLE: Unencoded JSON can break out
            string json = "{\"message\": \"" + data + "\"}";
            return Content(json, "application/json");
        }

        // Test 9: URL redirect with user input
        public ActionResult Redirect()
        {
            string target = Request.QueryString["target"];
            // VULNERABLE: javascript: URLs possible
            return Redirect(target);
        }

        // Test 10: ViewData with unencoded content
        public ActionResult ViewDataXss()
        {
            ViewData["UserInput"] = Request.QueryString["input"];
            // VULNERABLE: If view uses @Html.Raw(ViewData["UserInput"])
            return View();
        }
    }

    // Test 11: WebForms Response.Write
    public class XssPage : Page
    {
        protected void Page_Load(object sender, EventArgs e)
        {
            string input = Request.QueryString["q"];
            // VULNERABLE: Direct response write
            Response.Write("Search: " + input);
        }
    }
}
