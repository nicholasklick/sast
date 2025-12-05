// Resource Leak vulnerabilities in C#
using System;
using System.IO;
using System.Net;
using System.Net.Sockets;
using System.Data.SqlClient;
using System.Web.Mvc;

namespace VulnerableApp
{
    public class ResourceLeakController : Controller
    {
        // Test 1: FileStream not disposed
        public ActionResult ReadFile(string path)
        {
            // VULNERABLE: Stream not disposed on exception
            FileStream fs = new FileStream(path, FileMode.Open);
            byte[] buffer = new byte[1024];
            fs.Read(buffer, 0, buffer.Length);
            // fs.Close() missing if exception occurs
            return Ok();
        }

        // Test 2: StreamReader not disposed
        public ActionResult ReadText(string path)
        {
            // VULNERABLE: No using block or dispose
            StreamReader reader = new StreamReader(path);
            string content = reader.ReadToEnd();
            return Content(content);
            // reader never disposed
        }

        // Test 3: SqlConnection not disposed
        public ActionResult QueryDatabase(string query)
        {
            // VULNERABLE: Connection leak
            SqlConnection conn = new SqlConnection("connection_string");
            conn.Open();
            SqlCommand cmd = new SqlCommand(query, conn);
            var result = cmd.ExecuteScalar();
            return Json(result);
            // conn never closed
        }

        // Test 4: WebClient not disposed
        public ActionResult FetchUrl(string url)
        {
            // VULNERABLE: WebClient not disposed
            WebClient client = new WebClient();
            string content = client.DownloadString(url);
            return Content(content);
        }

        // Test 5: Socket not disposed
        public ActionResult ConnectSocket(string host, int port)
        {
            // VULNERABLE: Socket leak
            Socket socket = new Socket(AddressFamily.InterNetwork,
                SocketType.Stream, ProtocolType.Tcp);
            socket.Connect(host, port);
            // socket never disposed
            return Ok();
        }

        // Test 6: MemoryStream in return path
        public ActionResult CreateStream()
        {
            // VULNERABLE: Stream returned without dispose tracking
            MemoryStream ms = new MemoryStream();
            byte[] data = new byte[1000];
            ms.Write(data, 0, data.Length);
            // If caller doesn't dispose, leak occurs
            return File(ms, "application/octet-stream");
        }

        // Test 7: Exception path leak
        public ActionResult ProcessFile(string path)
        {
            FileStream fs = null;
            try
            {
                fs = new FileStream(path, FileMode.Open);
                ProcessData(fs);
            }
            catch
            {
                // VULNERABLE: fs not disposed in catch
                throw;
            }
            fs.Close();
            return Ok();
        }

        // Test 8: Nested resources not disposed
        public ActionResult ReadCompressed(string path)
        {
            // VULNERABLE: Inner stream may leak
            FileStream fs = new FileStream(path, FileMode.Open);
            var gzip = new System.IO.Compression.GZipStream(fs,
                System.IO.Compression.CompressionMode.Decompress);
            // If only gzip is disposed, fs may leak
            return Ok();
        }

        // Test 9: Early return leak
        public ActionResult ConditionalRead(string path, bool condition)
        {
            FileStream fs = new FileStream(path, FileMode.Open);
            if (condition)
            {
                // VULNERABLE: Early return without dispose
                return BadRequest();
            }
            byte[] data = new byte[100];
            fs.Read(data, 0, 100);
            fs.Close();
            return Ok();
        }

        // Test 10: Disposed in wrong scope
        public ActionResult MultipleResources()
        {
            FileStream fs1 = new FileStream("/tmp/a.txt", FileMode.Open);
            FileStream fs2 = new FileStream("/tmp/b.txt", FileMode.Open);
            // VULNERABLE: If fs2 creation fails, fs1 leaks
            fs1.Close();
            fs2.Close();
            return Ok();
        }

        // Test 11: Timer not disposed
        public ActionResult CreateTimer()
        {
            // VULNERABLE: Timer keeps running
            var timer = new System.Threading.Timer(
                state => { /* callback */ },
                null,
                0,
                1000
            );
            return Ok();
            // Timer never disposed
        }

        // Test 12: HttpClient created per request
        public ActionResult FetchData(string url)
        {
            // VULNERABLE: Creating HttpClient per request causes socket exhaustion
            var client = new System.Net.Http.HttpClient();
            var result = client.GetStringAsync(url).Result;
            return Content(result);
            // client not disposed (also shouldn't create per request)
        }

        // Placeholder
        private void ProcessData(Stream s) { }
    }
}
