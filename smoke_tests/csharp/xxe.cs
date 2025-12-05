// XXE (XML External Entity) vulnerabilities in C#
using System;
using System.Xml;
using System.Xml.Linq;
using System.Xml.XPath;
using System.Xml.Xsl;
using System.IO;
using System.Web.Mvc;

namespace VulnerableApp
{
    public class XxeController : Controller
    {
        // Test 1: XmlDocument with DTD processing enabled
        public ActionResult ParseXml()
        {
            string xml = Request.Form["xml"];
            var doc = new XmlDocument();
            // VULNERABLE: DTD processing enabled by default in older .NET
            doc.XmlResolver = new XmlUrlResolver();
            doc.LoadXml(xml);
            return Content(doc.DocumentElement?.InnerText ?? "");
        }

        // Test 2: XmlReader with unsafe settings
        public ActionResult ReadXml()
        {
            string xml = Request.Form["xml"];
            var settings = new XmlReaderSettings
            {
                // VULNERABLE: DTD processing enabled
                DtdProcessing = DtdProcessing.Parse,
                XmlResolver = new XmlUrlResolver()
            };
            using (var reader = XmlReader.Create(new StringReader(xml), settings))
            {
                while (reader.Read()) { }
            }
            return Ok();
        }

        // Test 3: XDocument with XmlResolver
        public ActionResult ParseXDocument()
        {
            string xml = Request.Form["xml"];
            var settings = new XmlReaderSettings
            {
                // VULNERABLE: External entities enabled
                DtdProcessing = DtdProcessing.Parse,
                XmlResolver = new XmlUrlResolver()
            };
            using (var reader = XmlReader.Create(new StringReader(xml), settings))
            {
                var doc = XDocument.Load(reader);
                return Content(doc.Root?.Value ?? "");
            }
        }

        // Test 4: XPathDocument with DTD
        public ActionResult XPathQuery()
        {
            string xml = Request.Form["xml"];
            var settings = new XmlReaderSettings
            {
                // VULNERABLE: DTD processing
                DtdProcessing = DtdProcessing.Parse
            };
            using (var reader = XmlReader.Create(new StringReader(xml), settings))
            {
                var doc = new XPathDocument(reader);
                var nav = doc.CreateNavigator();
                return Content(nav.SelectSingleNode("//data")?.Value ?? "");
            }
        }

        // Test 5: XSLT transformation with document() function
        public ActionResult TransformXml()
        {
            string xml = Request.Form["xml"];
            string xslt = Request.Form["xslt"];

            var xsltSettings = new XsltSettings
            {
                // VULNERABLE: document() function enabled
                EnableDocumentFunction = true,
                EnableScript = true
            };

            var transform = new XslCompiledTransform();
            using (var xsltReader = XmlReader.Create(new StringReader(xslt)))
            {
                transform.Load(xsltReader, xsltSettings, new XmlUrlResolver());
            }

            using (var xmlReader = XmlReader.Create(new StringReader(xml)))
            using (var writer = new StringWriter())
            {
                transform.Transform(xmlReader, null, writer);
                return Content(writer.ToString());
            }
        }

        // Test 6: XmlTextReader (deprecated, unsafe by default)
        public ActionResult ParseWithTextReader()
        {
            string xml = Request.Form["xml"];
            // VULNERABLE: XmlTextReader processes DTDs by default
            using (var reader = new XmlTextReader(new StringReader(xml)))
            {
                while (reader.Read()) { }
            }
            return Ok();
        }

        // Test 7: External schema loading
        public ActionResult ValidateWithSchema()
        {
            string xml = Request.Form["xml"];
            var settings = new XmlReaderSettings
            {
                // VULNERABLE: External schema can be loaded
                XmlResolver = new XmlUrlResolver(),
                ValidationType = ValidationType.Schema
            };
            using (var reader = XmlReader.Create(new StringReader(xml), settings))
            {
                while (reader.Read()) { }
            }
            return Ok();
        }

        // Test 8: Billion laughs (entity expansion)
        public ActionResult ParseUntrusted()
        {
            string xml = Request.Form["xml"];
            var settings = new XmlReaderSettings
            {
                // VULNERABLE: No entity expansion limit
                DtdProcessing = DtdProcessing.Parse,
                MaxCharactersFromEntities = 0  // No limit
            };
            using (var reader = XmlReader.Create(new StringReader(xml), settings))
            {
                while (reader.Read()) { }
            }
            return Ok();
        }
    }
}
