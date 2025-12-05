// XML Injection vulnerabilities in C#
using System;
using System.Xml;
using System.Xml.Linq;
using System.IO;
using System.Text;
using System.Web.Mvc;

namespace VulnerableApp
{
    public class XmlInjectionController : Controller
    {
        // Test 1: String concatenation for XML
        public ActionResult BuildXml()
        {
            string username = Request.QueryString["username"];
            string email = Request.QueryString["email"];
            // VULNERABLE: Direct string concatenation
            string xml = $"<user><name>{username}</name><email>{email}</email></user>";
            return Content(xml, "application/xml");
        }

        // Test 2: XmlWriter with unescaped content
        public ActionResult WriteXml()
        {
            string data = Request.Form["data"];
            var sb = new StringBuilder();
            using (var writer = XmlWriter.Create(sb))
            {
                writer.WriteStartElement("root");
                // VULNERABLE: WriteRaw doesn't escape
                writer.WriteRaw(data);
                writer.WriteEndElement();
            }
            return Content(sb.ToString(), "application/xml");
        }

        // Test 3: CDATA injection
        public ActionResult WriteCData()
        {
            string content = Request.Form["content"];
            var sb = new StringBuilder();
            using (var writer = XmlWriter.Create(sb))
            {
                writer.WriteStartElement("data");
                // VULNERABLE: ]]> can break out of CDATA
                writer.WriteCData(content);
                writer.WriteEndElement();
            }
            return Content(sb.ToString(), "application/xml");
        }

        // Test 4: XElement with raw content
        public ActionResult CreateXElement()
        {
            string input = Request.QueryString["input"];
            // VULNERABLE: Parsing user input as XML
            var element = XElement.Parse($"<item>{input}</item>");
            return Content(element.ToString(), "application/xml");
        }

        // Test 5: Comment injection
        public ActionResult AddComment()
        {
            string comment = Request.Form["comment"];
            var sb = new StringBuilder();
            using (var writer = XmlWriter.Create(sb))
            {
                writer.WriteStartElement("root");
                // VULNERABLE: --> can close comment and inject XML
                writer.WriteComment(comment);
                writer.WriteEndElement();
            }
            return Content(sb.ToString(), "application/xml");
        }

        // Test 6: Processing instruction injection
        public ActionResult AddPI()
        {
            string target = Request.Form["target"];
            string data = Request.Form["data"];
            var sb = new StringBuilder();
            using (var writer = XmlWriter.Create(sb))
            {
                writer.WriteStartDocument();
                // VULNERABLE: Can inject malicious PI
                writer.WriteProcessingInstruction(target, data);
                writer.WriteStartElement("root");
                writer.WriteEndElement();
            }
            return Content(sb.ToString(), "application/xml");
        }

        // Test 7: Attribute injection
        public ActionResult BuildWithAttribute()
        {
            string id = Request.QueryString["id"];
            string name = Request.QueryString["name"];
            // VULNERABLE: Can inject additional attributes
            string xml = $"<user id=\"{id}\" name=\"{name}\"/>";
            return Content(xml, "application/xml");
        }

        // Test 8: Namespace injection
        public ActionResult AddNamespace()
        {
            string prefix = Request.Form["prefix"];
            string uri = Request.Form["uri"];
            var sb = new StringBuilder();
            using (var writer = XmlWriter.Create(sb))
            {
                writer.WriteStartElement("root");
                // VULNERABLE: Arbitrary namespace declaration
                writer.WriteAttributeString("xmlns", prefix, null, uri);
                writer.WriteEndElement();
            }
            return Content(sb.ToString(), "application/xml");
        }

        // Test 9: SOAP message injection
        public ActionResult BuildSoap()
        {
            string action = Request.Form["action"];
            string param = Request.Form["param"];
            // VULNERABLE: Building SOAP manually
            string soap = $@"<?xml version='1.0'?>
                <soap:Envelope xmlns:soap='http://schemas.xmlsoap.org/soap/envelope/'>
                    <soap:Body>
                        <{action}>
                            <param>{param}</param>
                        </{action}>
                    </soap:Body>
                </soap:Envelope>";
            return Content(soap, "text/xml");
        }

        // Test 10: XmlDocument manipulation
        public ActionResult ModifyXml()
        {
            string elementName = Request.Form["element"];
            string value = Request.Form["value"];

            var doc = new XmlDocument();
            doc.LoadXml("<root><item/></root>");
            var newElement = doc.CreateElement(elementName);
            // VULNERABLE: User controls element creation
            newElement.InnerText = value;
            doc.DocumentElement.AppendChild(newElement);

            return Content(doc.OuterXml, "application/xml");
        }
    }
}
