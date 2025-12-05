// LDAP Injection vulnerabilities in C#
using System;
using System.DirectoryServices;
using System.DirectoryServices.Protocols;
using System.Web.Mvc;

namespace VulnerableApp
{
    public class LdapController : Controller
    {
        private const string LdapPath = "LDAP://dc=example,dc=com";

        // Test 1: DirectorySearcher with user input
        public ActionResult SearchUser()
        {
            string username = Request.QueryString["username"];
            using (var entry = new DirectoryEntry(LdapPath))
            using (var searcher = new DirectorySearcher(entry))
            {
                // VULNERABLE: User input in LDAP filter
                searcher.Filter = $"(&(objectClass=user)(sAMAccountName={username}))";
                var result = searcher.FindOne();
                return Json(result?.Properties["cn"][0]);
            }
        }

        // Test 2: Authentication bypass
        public ActionResult Authenticate()
        {
            string user = Request.Form["user"];
            string pass = Request.Form["pass"];

            using (var entry = new DirectoryEntry(LdapPath))
            using (var searcher = new DirectorySearcher(entry))
            {
                // VULNERABLE: Can inject *)(&(1=1 to bypass
                searcher.Filter = $"(&(uid={user})(userPassword={pass}))";
                var result = searcher.FindOne();
                if (result != null)
                {
                    return Json(new { authenticated = true });
                }
            }
            return Json(new { authenticated = false });
        }

        // Test 3: Group membership check
        public ActionResult CheckGroup()
        {
            string user = Request.QueryString["user"];
            string group = Request.QueryString["group"];

            using (var entry = new DirectoryEntry(LdapPath))
            using (var searcher = new DirectorySearcher(entry))
            {
                // VULNERABLE: Both parameters from user
                searcher.Filter = $"(&(member={user})(cn={group}))";
                var result = searcher.FindOne();
                return Json(result != null);
            }
        }

        // Test 4: Email lookup
        public ActionResult FindByEmail()
        {
            string email = Request.QueryString["email"];

            using (var entry = new DirectoryEntry(LdapPath))
            using (var searcher = new DirectorySearcher(entry))
            {
                // VULNERABLE: Email from user
                searcher.Filter = $"(mail={email})";
                searcher.PropertiesToLoad.Add("cn");
                searcher.PropertiesToLoad.Add("mail");
                var results = searcher.FindAll();
                return Json(results.Count);
            }
        }

        // Test 5: OR clause injection
        public ActionResult SearchMultiple()
        {
            string search = Request.QueryString["q"];

            using (var entry = new DirectoryEntry(LdapPath))
            using (var searcher = new DirectorySearcher(entry))
            {
                // VULNERABLE: Search term in OR filter
                searcher.Filter = $"(|(cn={search})(sn={search})(mail={search}))";
                var results = searcher.FindAll();
                return Json(results.Count);
            }
        }

        // Test 6: Distinguished Name manipulation
        public ActionResult GetUser()
        {
            string dn = Request.QueryString["dn"];
            // VULNERABLE: DN from user input
            using (var entry = new DirectoryEntry($"LDAP://{dn}"))
            {
                return Json(entry.Properties["cn"].Value);
            }
        }

        // Test 7: Wildcard search
        public ActionResult WildcardSearch()
        {
            string prefix = Request.QueryString["prefix"];

            using (var entry = new DirectoryEntry(LdapPath))
            using (var searcher = new DirectorySearcher(entry))
            {
                // VULNERABLE: Prefix + wildcard can enumerate all
                searcher.Filter = $"(cn={prefix}*)";
                var results = searcher.FindAll();
                return Json(results.Count);
            }
        }

        // Test 8: LdapConnection with unsafe filter
        public ActionResult SearchWithProtocol()
        {
            string filter = Request.QueryString["filter"];

            using (var connection = new LdapConnection("localhost"))
            {
                // VULNERABLE: Entire filter from user
                var request = new SearchRequest(
                    "dc=example,dc=com",
                    filter,
                    SearchScope.Subtree,
                    null
                );
                var response = (SearchResponse)connection.SendRequest(request);
                return Json(response.Entries.Count);
            }
        }

        // Test 9: Attribute value injection
        public ActionResult UpdateAttribute()
        {
            string user = Request.Form["user"];
            string description = Request.Form["description"];

            using (var entry = new DirectoryEntry($"LDAP://cn={user},dc=example,dc=com"))
            {
                // VULNERABLE: Description value injection
                entry.Properties["description"].Value = description;
                entry.CommitChanges();
            }
            return Ok();
        }
    }
}
