// Log Injection vulnerabilities in C#
using System;
using System.IO;
using System.Diagnostics;
using System.Web.Mvc;
using Microsoft.Extensions.Logging;
using log4net;
using NLog;

namespace VulnerableApp
{
    public class LogInjectionController : Controller
    {
        private readonly ILog _log4net = LogManager.GetLogger(typeof(LogInjectionController));
        private readonly Logger _nlog = LogManager.GetCurrentClassLogger();
        private readonly ILogger<LogInjectionController> _msLogger;

        // Test 1: Console.WriteLine with user input
        public ActionResult ConsoleLog()
        {
            string username = Request.QueryString["username"];
            // VULNERABLE: Can inject newlines to forge log entries
            Console.WriteLine($"[INFO] User logged in: {username}");
            return Ok();
        }

        // Test 2: Debug.WriteLine
        public ActionResult DebugLog()
        {
            string action = Request.Form["action"];
            // VULNERABLE: User input in debug log
            Debug.WriteLine($"Action performed: {action}");
            return Ok();
        }

        // Test 3: File logging with user input
        public ActionResult FileLog()
        {
            string message = Request.Form["message"];
            // VULNERABLE: Message can contain CRLF
            File.AppendAllText("/var/log/app.log",
                $"[{DateTime.Now}] {message}\n");
            return Ok();
        }

        // Test 4: EventLog with user input
        public ActionResult EventLogEntry()
        {
            string source = "MyApp";
            string logName = "Application";
            string userInput = Request.QueryString["data"];

            if (!EventLog.SourceExists(source))
            {
                EventLog.CreateEventSource(source, logName);
            }

            // VULNERABLE: User input in event log
            EventLog.WriteEntry(source, $"User action: {userInput}");
            return Ok();
        }

        // Test 5: log4net logging
        public ActionResult Log4NetLog()
        {
            string userId = Request.QueryString["userId"];
            // VULNERABLE: Log forging via CRLF
            _log4net.Info($"User {userId} accessed resource");
            return Ok();
        }

        // Test 6: NLog logging
        public ActionResult NLogLog()
        {
            string error = Request.Form["error"];
            // VULNERABLE: User-controlled error message
            _nlog.Error($"Error occurred: {error}");
            return Ok();
        }

        // Test 7: Microsoft.Extensions.Logging
        public ActionResult MsLog()
        {
            string data = Request.QueryString["data"];
            // VULNERABLE: User input in structured log
            _msLogger.LogInformation("Request data: {Data}", data);
            return Ok();
        }

        // Test 8: Trace logging
        public ActionResult TraceLog()
        {
            string input = Request.Form["input"];
            // VULNERABLE: User input in trace
            Trace.WriteLine($"Processing: {input}");
            return Ok();
        }

        // Test 9: StreamWriter logging
        public ActionResult StreamLog()
        {
            string audit = Request.Form["audit"];
            using (var writer = new StreamWriter("/var/log/audit.log", true))
            {
                // VULNERABLE: Can break log format
                writer.WriteLine($"[AUDIT] {DateTime.Now}: {audit}");
            }
            return Ok();
        }

        // Test 10: JSON log format breaking
        public ActionResult JsonLog()
        {
            string message = Request.QueryString["msg"];
            // VULNERABLE: Can break JSON structure
            string logEntry = $"{{\"timestamp\":\"{DateTime.Now}\",\"message\":\"{message}\"}}";
            File.AppendAllText("/var/log/json.log", logEntry + "\n");
            return Ok();
        }

        // Test 11: Exception message logging
        public ActionResult ExceptionLog()
        {
            try
            {
                throw new Exception(Request.QueryString["error"]);
            }
            catch (Exception ex)
            {
                // VULNERABLE: Exception message from user input
                Console.WriteLine($"Exception: {ex.Message}");
            }
            return Ok();
        }
    }
}
