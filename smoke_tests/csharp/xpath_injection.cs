// XPath Injection vulnerabilities in C#
using System;
using System.Xml;
using System.Xml.XPath;
using System.Xml.Linq;
using System.Web.Mvc;

namespace VulnerableApp
{
    public class XPathInjectionController : Controller
    {
        private XmlDocument _usersDoc;

        public XPathInjectionController()
        {
            _usersDoc = new XmlDocument();
            _usersDoc.LoadXml(@"
                <users>
                    <user id='1'><name>admin</name><password>secret</password><role>admin</role></user>
                    <user id='2'><name>john</name><password>pass123</password><role>user</role></user>
                </users>");
        }

        // Test 1: Authentication bypass
        public ActionResult Login()
        {
            string username = Request.Form["username"];
            string password = Request.Form["password"];
            // VULNERABLE: ' or '1'='1 bypasses auth
            string xpath = $"//user[name='{username}' and password='{password}']";
            XmlNode user = _usersDoc.SelectSingleNode(xpath);
            if (user != null)
            {
                return Json(new { authenticated = true });
            }
            return Json(new { authenticated = false });
        }

        // Test 2: Data extraction via XPath
        public ActionResult FindUser()
        {
            string name = Request.QueryString["name"];
            // VULNERABLE: Can extract other users
            string xpath = $"//user[name='{name}']";
            XmlNode user = _usersDoc.SelectSingleNode(xpath);
            return Content(user?.OuterXml ?? "Not found", "application/xml");
        }

        // Test 3: XPathNavigator injection
        public ActionResult NavigateXml()
        {
            string query = Request.QueryString["query"];
            XPathNavigator nav = _usersDoc.CreateNavigator();
            // VULNERABLE: User controls XPath query
            XPathNodeIterator iter = nav.Select(query);
            var results = "";
            while (iter.MoveNext())
            {
                results += iter.Current.OuterXml;
            }
            return Content(results, "application/xml");
        }

        // Test 4: XPath in LINQ to XML
        public ActionResult LinqXPath()
        {
            string id = Request.QueryString["id"];
            var doc = XDocument.Parse(_usersDoc.OuterXml);
            // VULNERABLE: XPath injection in LINQ
            var elements = doc.XPathSelectElements($"//user[@id='{id}']");
            return Json(elements.Count());
        }

        // Test 5: Numeric injection
        public ActionResult GetUserById()
        {
            string id = Request.QueryString["id"];
            // VULNERABLE: 1 or 1=1 returns all
            string xpath = $"//user[@id={id}]";
            XmlNodeList users = _usersDoc.SelectNodes(xpath);
            return Json(users?.Count ?? 0);
        }

        // Test 6: Function injection
        public ActionResult SearchByPattern()
        {
            string pattern = Request.QueryString["pattern"];
            // VULNERABLE: contains() can be manipulated
            string xpath = $"//user[contains(name, '{pattern}')]";
            XmlNodeList users = _usersDoc.SelectNodes(xpath);
            return Json(users?.Count ?? 0);
        }

        // Test 7: Blind XPath injection
        public ActionResult CheckUser()
        {
            string username = Request.QueryString["username"];
            string check = Request.QueryString["check"];
            // VULNERABLE: Boolean-based blind injection
            string xpath = $"//user[name='{username}' and {check}]";
            try
            {
                XmlNode user = _usersDoc.SelectSingleNode(xpath);
                return Json(user != null);
            }
            catch
            {
                return Json(false);
            }
        }

        // Test 8: OR injection
        public ActionResult GetByRole()
        {
            string role = Request.QueryString["role"];
            // VULNERABLE: ' or '1'='1 returns all
            string xpath = $"//user[role='{role}']";
            XmlNodeList users = _usersDoc.SelectNodes(xpath);
            return Json(users?.Count ?? 0);
        }

        // Test 9: Axis injection
        public ActionResult GetParent()
        {
            string element = Request.QueryString["element"];
            // VULNERABLE: Can navigate to unintended nodes
            string xpath = $"//user/{element}";
            XmlNodeList nodes = _usersDoc.SelectNodes(xpath);
            return Json(nodes?.Count ?? 0);
        }

        // Test 10: Comment-based injection
        public ActionResult SearchWithComment()
        {
            string search = Request.QueryString["search"];
            // VULNERABLE: ] comment [ can break query
            string xpath = $"//user[name[contains(., '{search}')]]";
            XmlNodeList users = _usersDoc.SelectNodes(xpath);
            return Json(users?.Count ?? 0);
        }
    }
}
