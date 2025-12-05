// Race Condition vulnerabilities in C#
using System;
using System.IO;
using System.Threading;
using System.Threading.Tasks;
using System.Collections.Generic;
using System.Web.Mvc;

namespace VulnerableApp
{
    public class RaceConditionController : Controller
    {
        private static int _balance = 1000;
        private static Dictionary<string, object> _cache = new Dictionary<string, object>();

        // Test 1: Check-then-act on balance
        public ActionResult Withdraw(int amount)
        {
            // VULNERABLE: Race condition between check and update
            if (_balance >= amount)
            {
                Thread.Sleep(10);  // Simulates processing time
                _balance -= amount;
                return Json(new { newBalance = _balance });
            }
            return Json(new { error = "Insufficient funds" });
        }

        // Test 2: Double-checked locking antipattern
        private static object _instance;
        private static object _lockObj = new object();

        public ActionResult GetSingleton()
        {
            // VULNERABLE: Double-checked locking can fail without volatile
            if (_instance == null)
            {
                lock (_lockObj)
                {
                    if (_instance == null)
                    {
                        _instance = new object();
                    }
                }
            }
            return Json(_instance.GetHashCode());
        }

        // Test 3: File TOCTOU (Time-of-check to time-of-use)
        public ActionResult ReadConfig(string filename)
        {
            string path = Path.Combine("/config", filename);
            // VULNERABLE: File can change between check and read
            if (System.IO.File.Exists(path))
            {
                Thread.Sleep(10);
                string content = System.IO.File.ReadAllText(path);
                return Content(content);
            }
            return NotFound();
        }

        // Test 4: Unsynchronized collection access
        public ActionResult AddToCache(string key, string value)
        {
            // VULNERABLE: Dictionary not thread-safe
            if (!_cache.ContainsKey(key))
            {
                _cache[key] = value;
            }
            return Ok();
        }

        // Test 5: Lazy initialization race
        private static string _config;

        public ActionResult GetConfig()
        {
            // VULNERABLE: Multiple threads may initialize
            if (_config == null)
            {
                _config = LoadExpensiveConfig();
            }
            return Content(_config);
        }

        // Test 6: Session race condition
        public ActionResult UpdateSession()
        {
            // VULNERABLE: Session operations not atomic
            int count = (int)(Session["count"] ?? 0);
            Thread.Sleep(10);
            Session["count"] = count + 1;
            return Json(Session["count"]);
        }

        // Test 7: Increment not atomic
        private static int _counter;

        public ActionResult IncrementCounter()
        {
            // VULNERABLE: ++ is not atomic
            _counter++;
            return Json(_counter);
        }

        // Test 8: Read-modify-write race
        public ActionResult UpdateInventory(int productId, int quantity)
        {
            // VULNERABLE: Read-modify-write not atomic
            int current = GetInventory(productId);
            if (current >= quantity)
            {
                Thread.Sleep(10);
                SetInventory(productId, current - quantity);
                return Ok();
            }
            return Json(new { error = "Out of stock" });
        }

        // Test 9: Async race condition
        public async Task<ActionResult> ProcessAsync()
        {
            // VULNERABLE: Shared state modified in async
            int localValue = _counter;
            await Task.Delay(100);
            _counter = localValue + 1;  // Race with other async ops
            return Json(_counter);
        }

        // Test 10: Lock ordering deadlock potential
        private static object _lockA = new object();
        private static object _lockB = new object();

        public ActionResult TransferFunds(int from, int to, decimal amount)
        {
            // VULNERABLE: Different lock ordering can cause deadlock
            lock (_lockA)
            {
                lock (_lockB)
                {
                    // Transfer logic
                }
            }
            return Ok();
        }

        // Test 11: Singleton initialization race
        private static Lazy<object> _lazySingleton;

        public ActionResult InitLazy()
        {
            // VULNERABLE: Lazy initialization without thread safety mode
            if (_lazySingleton == null)
            {
                _lazySingleton = new Lazy<object>(() => new object());
            }
            return Json(_lazySingleton.Value.GetHashCode());
        }

        // Placeholder methods
        private string LoadExpensiveConfig() => "config";
        private int GetInventory(int id) => 100;
        private void SetInventory(int id, int qty) { }
    }
}
