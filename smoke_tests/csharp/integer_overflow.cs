// Integer Overflow vulnerabilities in C#
using System;
using System.Web.Mvc;

namespace VulnerableApp
{
    public class IntegerOverflowController : Controller
    {
        // Test 1: Multiplication overflow
        public ActionResult CalculateTotal(int quantity, int price)
        {
            // VULNERABLE: Can overflow with large values
            int total = quantity * price;
            return Json(total);
        }

        // Test 2: Addition overflow
        public ActionResult AddFunds(int balance, int amount)
        {
            // VULNERABLE: Integer overflow possible
            int newBalance = balance + amount;
            return Json(newBalance);
        }

        // Test 3: Array allocation with user size
        public ActionResult CreateBuffer(int size)
        {
            // VULNERABLE: Size can overflow, creating small array
            int bufferSize = size * 4;
            byte[] buffer = new byte[bufferSize];
            return Json(buffer.Length);
        }

        // Test 4: Subtraction underflow
        public ActionResult Withdraw(int balance, int amount)
        {
            // VULNERABLE: Can underflow to large positive number
            int newBalance = balance - amount;
            if (newBalance >= 0)  // Check may pass due to overflow
            {
                return Json(new { success = true, balance = newBalance });
            }
            return Json(new { success = false });
        }

        // Test 5: Cast truncation
        public ActionResult ConvertSize(long size)
        {
            // VULNERABLE: Truncation when casting
            int intSize = (int)size;
            byte[] data = new byte[intSize];
            return Json(data.Length);
        }

        // Test 6: Signed to unsigned conversion
        public ActionResult ProcessData(int length)
        {
            // VULNERABLE: Negative becomes large unsigned
            uint uLength = (uint)length;
            byte[] buffer = new byte[uLength];
            return Json(buffer.Length);
        }

        // Test 7: Loop counter overflow
        public ActionResult ProcessItems(int count)
        {
            int sum = 0;
            // VULNERABLE: If count is close to int.MaxValue
            for (int i = 0; i < count + 10; i++)  // count + 10 can overflow
            {
                sum++;
            }
            return Json(sum);
        }

        // Test 8: Bounds calculation overflow
        public ActionResult GetSubArray(int start, int length)
        {
            byte[] data = new byte[100];
            // VULNERABLE: start + length can overflow
            int end = start + length;
            if (end <= data.Length)
            {
                // Access data[start..end]
            }
            return Ok();
        }

        // Test 9: Memory allocation size
        public ActionResult AllocateMemory(int width, int height, int bytesPerPixel)
        {
            // VULNERABLE: Multiplication chain can overflow
            int size = width * height * bytesPerPixel;
            byte[] image = new byte[size];
            return Json(image.Length);
        }

        // Test 10: DateTime Ticks overflow
        public ActionResult AddTime(long ticksToAdd)
        {
            DateTime now = DateTime.Now;
            // VULNERABLE: Can overflow DateTime range
            DateTime future = new DateTime(now.Ticks + ticksToAdd);
            return Json(future.ToString());
        }

        // Test 11: Division edge case
        public ActionResult Divide(int numerator, int denominator)
        {
            // VULNERABLE: int.MinValue / -1 overflows
            int result = numerator / denominator;
            return Json(result);
        }

        // Test 12: Increment overflow
        public ActionResult IncrementCounter()
        {
            int counter = int.MaxValue;
            // VULNERABLE: Overflow without checked context
            counter++;
            return Json(counter);
        }
    }
}
