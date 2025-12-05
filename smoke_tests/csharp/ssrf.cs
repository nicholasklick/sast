// Server-Side Request Forgery (SSRF) vulnerabilities in C#
using System;
using System.Net;
using System.Net.Http;
using System.IO;
using System.Threading.Tasks;
using System.Web.Mvc;

namespace VulnerableApp
{
    public class SsrfController : Controller
    {
        private readonly HttpClient _httpClient = new HttpClient();

        // Test 1: Direct URL from user
        public async Task<ActionResult> Fetch()
        {
            string url = Request.QueryString["url"];
            // VULNERABLE: User-controlled URL
            var response = await _httpClient.GetStringAsync(url);
            return Content(response);
        }

        // Test 2: WebClient with user URL
        public ActionResult Download()
        {
            string url = Request.QueryString["url"];
            using (var client = new WebClient())
            {
                // VULNERABLE: User-controlled download URL
                string content = client.DownloadString(url);
                return Content(content);
            }
        }

        // Test 3: WebRequest with user URL
        public ActionResult FetchData()
        {
            string url = Request.QueryString["target"];
            // VULNERABLE: User-controlled WebRequest
            WebRequest request = WebRequest.Create(url);
            using (var response = request.GetResponse())
            using (var reader = new StreamReader(response.GetResponseStream()))
            {
                return Content(reader.ReadToEnd());
            }
        }

        // Test 4: Partial URL construction
        public async Task<ActionResult> FetchFromHost()
        {
            string host = Request.QueryString["host"];
            // VULNERABLE: User controls hostname
            string url = $"http://{host}/api/data";
            var response = await _httpClient.GetStringAsync(url);
            return Content(response);
        }

        // Test 5: Port scanning via SSRF
        public async Task<ActionResult> CheckPort()
        {
            string port = Request.QueryString["port"];
            // VULNERABLE: User controls port, can scan internal network
            string url = $"http://internal-server:{port}/";
            try
            {
                var response = await _httpClient.GetAsync(url);
                return Json(new { status = "open" });
            }
            catch
            {
                return Json(new { status = "closed" });
            }
        }

        // Test 6: Image proxy
        public async Task<ActionResult> ImageProxy()
        {
            string imageUrl = Request.QueryString["src"];
            // VULNERABLE: Can fetch internal resources
            var bytes = await _httpClient.GetByteArrayAsync(imageUrl);
            return File(bytes, "image/png");
        }

        // Test 7: Webhook URL
        public async Task<ActionResult> SendWebhook()
        {
            string webhookUrl = Request.Form["webhook"];
            string data = Request.Form["data"];
            // VULNERABLE: User-controlled webhook destination
            var content = new StringContent(data);
            await _httpClient.PostAsync(webhookUrl, content);
            return Ok();
        }

        // Test 8: DNS rebinding vulnerable
        public async Task<ActionResult> FetchExternal()
        {
            string domain = Request.QueryString["domain"];
            // VULNERABLE: DNS can resolve to internal IP
            string url = $"http://{domain}/data";
            var response = await _httpClient.GetStringAsync(url);
            return Content(response);
        }

        // Test 9: File protocol SSRF
        public ActionResult ReadResource()
        {
            string uri = Request.QueryString["uri"];
            // VULNERABLE: Could be file:///etc/passwd
            WebRequest request = WebRequest.Create(uri);
            using (var response = request.GetResponse())
            using (var reader = new StreamReader(response.GetResponseStream()))
            {
                return Content(reader.ReadToEnd());
            }
        }

        // Test 10: Redirect following
        public async Task<ActionResult> FetchWithRedirect()
        {
            string url = Request.QueryString["url"];
            var handler = new HttpClientHandler
            {
                // VULNERABLE: Follows redirects to internal resources
                AllowAutoRedirect = true,
                MaxAutomaticRedirections = 10
            };
            using (var client = new HttpClient(handler))
            {
                var response = await client.GetStringAsync(url);
                return Content(response);
            }
        }
    }
}
