// Unsafe Reflection vulnerabilities in C#
using System;
using System.Reflection;
using System.Web.Mvc;

namespace VulnerableApp
{
    public class ReflectionController : Controller
    {
        // Test 1: Type.GetType with user input
        public ActionResult LoadType()
        {
            string typeName = Request.QueryString["type"];
            // VULNERABLE: User controls type instantiation
            Type type = Type.GetType(typeName);
            if (type != null)
            {
                object instance = Activator.CreateInstance(type);
                return Json(instance.ToString());
            }
            return NotFound();
        }

        // Test 2: Assembly.Load with user input
        public ActionResult LoadAssembly()
        {
            string assemblyName = Request.QueryString["assembly"];
            // VULNERABLE: User can load arbitrary assemblies
            Assembly assembly = Assembly.Load(assemblyName);
            return Json(assembly.GetTypes().Length);
        }

        // Test 3: Method invocation by name
        public ActionResult InvokeMethod()
        {
            string typeName = Request.Form["type"];
            string methodName = Request.Form["method"];

            Type type = Type.GetType(typeName);
            // VULNERABLE: User controls method invocation
            MethodInfo method = type?.GetMethod(methodName);
            object instance = Activator.CreateInstance(type);
            object result = method?.Invoke(instance, null);
            return Json(result);
        }

        // Test 4: Property access by name
        public ActionResult GetProperty()
        {
            string typeName = Request.QueryString["type"];
            string propName = Request.QueryString["property"];

            Type type = Type.GetType(typeName);
            object instance = Activator.CreateInstance(type);
            // VULNERABLE: User-controlled property access
            PropertyInfo prop = type?.GetProperty(propName);
            object value = prop?.GetValue(instance);
            return Json(value);
        }

        // Test 5: Field access by name
        public ActionResult GetField()
        {
            string typeName = Request.QueryString["type"];
            string fieldName = Request.QueryString["field"];

            Type type = Type.GetType(typeName);
            object instance = Activator.CreateInstance(type);
            // VULNERABLE: User-controlled field access
            FieldInfo field = type?.GetField(fieldName,
                BindingFlags.Public | BindingFlags.NonPublic | BindingFlags.Instance);
            return Json(field?.GetValue(instance));
        }

        // Test 6: Constructor invocation with parameters
        public ActionResult CreateWithParams()
        {
            string typeName = Request.Form["type"];
            string param = Request.Form["param"];

            Type type = Type.GetType(typeName);
            // VULNERABLE: User-controlled instantiation
            object instance = Activator.CreateInstance(type, param);
            return Json(instance.ToString());
        }

        // Test 7: Assembly.LoadFrom with path
        public ActionResult LoadFromPath()
        {
            string path = Request.QueryString["path"];
            // VULNERABLE: Load assembly from user-controlled path
            Assembly assembly = Assembly.LoadFrom(path);
            return Json(assembly.FullName);
        }

        // Test 8: Dynamic method invocation with arguments
        public ActionResult InvokeWithArgs()
        {
            string typeName = Request.Form["type"];
            string methodName = Request.Form["method"];
            string[] args = Request.Form["args"]?.Split(',');

            Type type = Type.GetType(typeName);
            object instance = Activator.CreateInstance(type);
            MethodInfo method = type?.GetMethod(methodName);
            // VULNERABLE: User controls method and arguments
            object result = method?.Invoke(instance, args);
            return Json(result);
        }

        // Test 9: Setting property value
        public ActionResult SetProperty()
        {
            string typeName = Request.Form["type"];
            string propName = Request.Form["property"];
            string value = Request.Form["value"];

            Type type = Type.GetType(typeName);
            object instance = Activator.CreateInstance(type);
            PropertyInfo prop = type?.GetProperty(propName);
            // VULNERABLE: User-controlled property modification
            prop?.SetValue(instance, value);
            return Ok();
        }

        // Test 10: GetMethod with binding flags
        public ActionResult InvokePrivate()
        {
            string typeName = Request.Form["type"];
            string methodName = Request.Form["method"];

            Type type = Type.GetType(typeName);
            object instance = Activator.CreateInstance(type);
            // VULNERABLE: Accessing private methods
            MethodInfo method = type?.GetMethod(methodName,
                BindingFlags.NonPublic | BindingFlags.Instance);
            return Json(method?.Invoke(instance, null));
        }
    }
}
