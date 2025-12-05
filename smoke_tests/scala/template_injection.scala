// Template Injection vulnerabilities in Scala
package com.example.security

import java.io.StringWriter

class TemplateInjectionVulnerabilities {

  // Test 1: String interpolation as template
  def renderStringTemplate(template: String, values: Map[String, String]): String = {
    // VULNERABLE: User template with interpolation
    var result = template
    values.foreach { case (key, value) =>
      result = result.replace(s"$${$key}", value)
    }
    result
  }

  // Test 2: Twirl template with raw HTML (Play Framework)
  def renderTwirlRaw(content: String): String = {
    // VULNERABLE: Raw HTML output
    s"@Html($content)"
  }

  // Test 3: Scalate template
  def renderScalate(templateContent: String, attributes: Map[String, Any]): String = {
    // VULNERABLE: User-controlled template
    import org.fusesource.scalate._
    val engine = new TemplateEngine
    engine.layout("user.ssp", attributes)
  }

  // Test 4: Velocity template
  def renderVelocity(templateContent: String, context: Map[String, Any]): String = {
    import org.apache.velocity.app.VelocityEngine
    import org.apache.velocity.VelocityContext
    // VULNERABLE: User-controlled Velocity template
    val engine = new VelocityEngine()
    engine.init()
    val velocityContext = new VelocityContext()
    context.foreach { case (k, v) => velocityContext.put(k, v) }
    val writer = new StringWriter()
    engine.evaluate(velocityContext, writer, "user", templateContent)
    writer.toString
  }

  // Test 5: FreeMarker template
  def renderFreemarker(templateContent: String, data: Map[String, Any]): String = {
    import freemarker.template.{Configuration, Template}
    import java.io.StringReader
    // VULNERABLE: User-controlled template
    val config = new Configuration(Configuration.VERSION_2_3_31)
    val template = new Template("userTemplate", new StringReader(templateContent), config)
    val writer = new StringWriter()
    import scala.jdk.CollectionConverters._
    template.process(data.asJava, writer)
    writer.toString
  }

  // Test 6: Mustache template
  def renderMustache(templateContent: String, data: Map[String, Any]): String = {
    import com.github.mustachejava.DefaultMustacheFactory
    import java.io.StringReader
    // VULNERABLE: User-controlled Mustache template
    val factory = new DefaultMustacheFactory()
    val mustache = factory.compile(new StringReader(templateContent), "user")
    val writer = new StringWriter()
    import scala.jdk.CollectionConverters._
    mustache.execute(writer, data.asJava)
    writer.toString
  }

  // Test 7: Scala XML interpolation
  def xmlTemplate(userContent: String): scala.xml.Elem = {
    // VULNERABLE: User content in XML
    <html>
      <body>
        {scala.xml.Unparsed(userContent)}
      </body>
    </html>
  }

  // Test 8: HTML construction with interpolation
  def buildHtml(title: String, body: String): String = {
    // VULNERABLE: User data in HTML template
    s"""
      <html>
      <head><title>$title</title></head>
      <body>$body</body>
      </html>
    """
  }

  // Test 9: Email template
  def renderEmailTemplate(templateName: String, data: Map[String, String]): String = {
    // VULNERABLE: Template name from user
    val templatePath = s"templates/$templateName.html"
    val template = scala.io.Source.fromFile(templatePath).mkString
    renderStringTemplate(template, data)
  }

  // Test 10: Expression evaluation
  def evaluateExpression(expression: String, context: Map[String, Any]): Any = {
    // VULNERABLE: User-controlled expression
    import scala.tools.reflect.ToolBox
    import scala.reflect.runtime.currentMirror
    val toolbox = currentMirror.mkToolBox()
    toolbox.eval(toolbox.parse(expression))
  }

  // Test 11: JSP-like expression
  def jspExpression(userInput: String): String = {
    // VULNERABLE: User input in expression
    s"<%= $userInput %>"
  }

  // Test 12: Handlebars template
  def renderHandlebars(templateContent: String, data: Map[String, Any]): String = {
    // VULNERABLE: User-controlled Handlebars template
    import com.github.jknack.handlebars.Handlebars
    val handlebars = new Handlebars()
    val template = handlebars.compileInline(templateContent)
    import scala.jdk.CollectionConverters._
    template.apply(data.asJava)
  }
}
