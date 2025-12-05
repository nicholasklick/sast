// Exception Handling vulnerabilities in C#
using System;
using System.IO;
using System.Web.Mvc;

namespace VulnerableApp
{
    public class ExceptionController : Controller
    {
        // Test 1: Empty catch block
        public ActionResult SwallowException()
        {
            try
            {
                ProcessData();
            }
            catch (Exception)
            {
                // VULNERABLE: Exception silently swallowed
            }
            return Ok();
        }

        // Test 2: Catching base Exception
        public ActionResult CatchAll()
        {
            try
            {
                ProcessData();
            }
            catch (Exception ex)
            {
                // VULNERABLE: Catches everything including critical exceptions
                return Json(new { error = ex.Message });
            }
            return Ok();
        }

        // Test 3: Exception in exception handler
        public ActionResult BadHandler()
        {
            try
            {
                ProcessData();
            }
            catch (Exception ex)
            {
                // VULNERABLE: Logging might throw
                File.AppendAllText("/var/log/errors.log", ex.ToString());
            }
            return Ok();
        }

        // Test 4: Throwing in finally
        public ActionResult ThrowInFinally()
        {
            try
            {
                ProcessData();
            }
            finally
            {
                // VULNERABLE: Can mask original exception
                throw new Exception("Finally exception");
            }
        }

        // Test 5: Losing stack trace
        public ActionResult LoseStackTrace()
        {
            try
            {
                ProcessData();
            }
            catch (Exception ex)
            {
                // VULNERABLE: Loses original stack trace
                throw ex;  // Should be: throw;
            }
            return Ok();
        }

        // Test 6: Generic exception type
        public void DoWork()
        {
            // VULNERABLE: Throwing generic Exception
            throw new Exception("Something went wrong");
            // Should use specific exception type
        }

        // Test 7: Exposing internal details
        public ActionResult ExposeDetails()
        {
            try
            {
                ProcessData();
            }
            catch (Exception ex)
            {
                // VULNERABLE: Internal details exposed
                return Content($"Error: {ex.Message}\nStack: {ex.StackTrace}\nSource: {ex.Source}");
            }
            return Ok();
        }

        // Test 8: Not logging exception
        public ActionResult NoLogging()
        {
            try
            {
                ProcessData();
            }
            catch (Exception)
            {
                // VULNERABLE: Exception occurs but no logging
                return BadRequest("An error occurred");
            }
            return Ok();
        }

        // Test 9: Catch and continue
        public ActionResult CatchAndContinue()
        {
            for (int i = 0; i < 10; i++)
            {
                try
                {
                    ProcessItem(i);
                }
                catch (Exception)
                {
                    // VULNERABLE: Silently continues, may leave state inconsistent
                    continue;
                }
            }
            return Ok();
        }

        // Test 10: Overly broad exception handling
        public ActionResult BroadCatch()
        {
            try
            {
                var data = GetData();
                ProcessData(data);
                SaveData(data);
            }
            catch (Exception)
            {
                // VULNERABLE: Can't tell which operation failed
                return BadRequest("Operation failed");
            }
            return Ok();
        }

        // Test 11: Exception thrown in using
        public ActionResult UsingException()
        {
            using (var stream = new FileStream("/tmp/test.txt", FileMode.Open))
            {
                // VULNERABLE: If this throws, Dispose still called but
                // exception handling may be confused
                throw new InvalidOperationException("Error");
            }
        }

        // Test 12: Async exception not awaited
        public ActionResult FireAndForget()
        {
            // VULNERABLE: Exception in async operation lost
            ProcessAsync();  // Not awaited
            return Ok();
        }

        // Placeholder methods
        private void ProcessData() { }
        private void ProcessData(object data) { }
        private void ProcessItem(int i) { }
        private object GetData() => new object();
        private void SaveData(object data) { }
        private async System.Threading.Tasks.Task ProcessAsync()
        {
            await System.Threading.Tasks.Task.Delay(100);
            throw new Exception("Async error");
        }
    }
}
