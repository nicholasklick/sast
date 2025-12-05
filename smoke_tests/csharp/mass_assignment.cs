// Mass Assignment vulnerabilities in C#
using System;
using System.Web.Mvc;

namespace VulnerableApp
{
    // Vulnerable model with sensitive properties
    public class User
    {
        public int Id { get; set; }
        public string Username { get; set; }
        public string Email { get; set; }
        public string Password { get; set; }
        public bool IsAdmin { get; set; }  // Sensitive!
        public decimal Balance { get; set; }  // Sensitive!
        public string Role { get; set; }  // Sensitive!
    }

    public class UserController : Controller
    {
        // Test 1: Direct model binding without protection
        [HttpPost]
        public ActionResult Create(User user)
        {
            // VULNERABLE: All properties bound including IsAdmin
            // Attacker can POST IsAdmin=true
            SaveUser(user);
            return Ok();
        }

        // Test 2: UpdateModel without whitelist
        [HttpPost]
        public ActionResult Update(int id)
        {
            var user = GetUserById(id);
            // VULNERABLE: Updates all posted properties
            UpdateModel(user);
            SaveUser(user);
            return Ok();
        }

        // Test 3: TryUpdateModel without include list
        [HttpPost]
        public ActionResult Edit(int id)
        {
            var user = GetUserById(id);
            // VULNERABLE: No property filtering
            if (TryUpdateModel(user))
            {
                SaveUser(user);
            }
            return Ok();
        }

        // Test 4: Bind attribute missing sensitive properties
        [HttpPost]
        public ActionResult Register([Bind(Include = "Username,Email,Password,IsAdmin")] User user)
        {
            // VULNERABLE: IsAdmin should not be in Include list
            SaveUser(user);
            return Ok();
        }

        // Test 5: FormCollection to model mapping
        [HttpPost]
        public ActionResult FromForm(FormCollection form)
        {
            var user = new User();
            // VULNERABLE: Manual binding without filtering
            user.Username = form["Username"];
            user.Email = form["Email"];
            user.IsAdmin = bool.Parse(form["IsAdmin"] ?? "false");  // Should not bind
            SaveUser(user);
            return Ok();
        }

        // Test 6: JSON deserialization mass assignment
        [HttpPost]
        public ActionResult JsonCreate()
        {
            var serializer = new System.Web.Script.Serialization.JavaScriptSerializer();
            string json = new System.IO.StreamReader(Request.InputStream).ReadToEnd();
            // VULNERABLE: All JSON properties deserialized
            var user = serializer.Deserialize<User>(json);
            SaveUser(user);
            return Ok();
        }

        // Test 7: ModelState with direct property access
        [HttpPost]
        public ActionResult Partial(int id)
        {
            var user = GetUserById(id);
            foreach (string key in Request.Form.AllKeys)
            {
                // VULNERABLE: Setting properties by name from form
                var prop = typeof(User).GetProperty(key);
                if (prop != null)
                {
                    prop.SetValue(user, Convert.ChangeType(Request.Form[key], prop.PropertyType));
                }
            }
            SaveUser(user);
            return Ok();
        }

        // Test 8: Automapper without configuration
        public ActionResult MapFromDto(UserDto dto)
        {
            var user = new User();
            // VULNERABLE: If automapper maps IsAdmin
            // AutoMapper.Mapper.Map(dto, user);
            foreach (var prop in typeof(UserDto).GetProperties())
            {
                var targetProp = typeof(User).GetProperty(prop.Name);
                if (targetProp != null)
                {
                    targetProp.SetValue(user, prop.GetValue(dto));
                }
            }
            SaveUser(user);
            return Ok();
        }

        // Placeholder methods
        private User GetUserById(int id) => new User { Id = id };
        private void SaveUser(User user) { }
    }

    public class UserDto
    {
        public string Username { get; set; }
        public string Email { get; set; }
        public bool IsAdmin { get; set; }  // Should not be in DTO
    }
}
