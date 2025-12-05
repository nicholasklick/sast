// Denial of Service vulnerabilities in C#
using System;
using System.Collections.Generic;
using System.IO;
using System.Text.RegularExpressions;
using System.Web.Mvc;
using System.Xml;

namespace VulnerableApp
{
    public class DosController : Controller
    {
        // Test 1: Unbounded allocation
        public ActionResult CreateArray()
        {
            int size = int.Parse(Request.QueryString["size"]);
            // VULNERABLE: User controls array size
            byte[] data = new byte[size];
            return Json(data.Length);
        }

        // Test 2: Unbounded list growth
        public ActionResult AddItems()
        {
            int count = int.Parse(Request.QueryString["count"]);
            var list = new List<string>();
            // VULNERABLE: User controls iteration count
            for (int i = 0; i < count; i++)
            {
                list.Add(new string('x', 1000));
            }
            return Json(list.Count);
        }

        // Test 3: ReDoS
        public ActionResult ValidateInput()
        {
            string input = Request.QueryString["input"];
            // VULNERABLE: Catastrophic backtracking
            var regex = new Regex(@"^(a+)+$");
            bool match = regex.IsMatch(input);
            return Json(match);
        }

        // Test 4: XML bomb (billion laughs)
        public ActionResult ParseXml()
        {
            string xml = Request.Form["xml"];
            var settings = new XmlReaderSettings
            {
                // VULNERABLE: Entity expansion not limited
                DtdProcessing = DtdProcessing.Parse,
                MaxCharactersFromEntities = 0
            };
            using (var reader = XmlReader.Create(new StringReader(xml), settings))
            {
                while (reader.Read()) { }
            }
            return Ok();
        }

        // Test 5: Hash collision attack
        public ActionResult StoreData()
        {
            var dict = new Dictionary<string, string>();
            // VULNERABLE: Hash collision with crafted keys
            foreach (string key in Request.Form.AllKeys)
            {
                dict[key] = Request.Form[key];
            }
            return Json(dict.Count);
        }

        // Test 6: Recursive depth attack
        public ActionResult ProcessJson()
        {
            string json = Request.Form["json"];
            // VULNERABLE: Deep nesting causes stack overflow
            var obj = Newtonsoft.Json.JsonConvert.DeserializeObject(json);
            return Json(obj);
        }

        // Test 7: CPU exhaustion via computation
        public ActionResult Compute()
        {
            int iterations = int.Parse(Request.QueryString["n"]);
            // VULNERABLE: User controls computation
            double result = 0;
            for (int i = 0; i < iterations; i++)
            {
                result += Math.Sin(i) * Math.Cos(i);
            }
            return Json(result);
        }

        // Test 8: File read amplification
        public ActionResult ReadLargeFile()
        {
            string path = Request.QueryString["path"];
            // VULNERABLE: No size limit on file read
            string content = System.IO.File.ReadAllText(path);
            return Content(content);
        }

        // Test 9: Connection exhaustion
        public ActionResult OpenConnections()
        {
            int count = int.Parse(Request.QueryString["count"]);
            var connections = new List<System.Net.Http.HttpClient>();
            // VULNERABLE: User controls number of connections
            for (int i = 0; i < count; i++)
            {
                connections.Add(new System.Net.Http.HttpClient());
            }
            return Json(connections.Count);
        }

        // Test 10: ZIP bomb
        public ActionResult ExtractZip()
        {
            var file = Request.Files["file"];
            string tempPath = Path.GetTempFileName();
            file.SaveAs(tempPath);
            // VULNERABLE: No decompression ratio limit
            System.IO.Compression.ZipFile.ExtractToDirectory(tempPath, "/tmp/extracted");
            return Ok();
        }

        // Test 11: Synchronous blocking
        public ActionResult SlowOperation()
        {
            int delay = int.Parse(Request.QueryString["delay"]);
            // VULNERABLE: User controls blocking time
            System.Threading.Thread.Sleep(delay);
            return Ok();
        }

        // Test 12: Lock contention
        private static object _lock = new object();

        public ActionResult LockOperation()
        {
            int duration = int.Parse(Request.QueryString["duration"]);
            lock (_lock)
            {
                // VULNERABLE: User controls lock duration
                System.Threading.Thread.Sleep(duration);
            }
            return Ok();
        }
    }
}
