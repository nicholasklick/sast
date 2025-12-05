// Template Injection vulnerabilities in Kotlin
package com.example.security

import freemarker.template.Configuration
import freemarker.template.Template
import java.io.StringWriter
import java.io.StringReader

class TemplateInjectionVulnerabilities {

    private val freemarkerConfig = Configuration(Configuration.VERSION_2_3_31)

    // Test 1: FreeMarker with user input in template
    fun renderFreemarker(templateContent: String, data: Map<String, Any>): String {
        // VULNERABLE: User-controlled template
        val template = Template("userTemplate", StringReader(templateContent), freemarkerConfig)
        val writer = StringWriter()
        template.process(data, writer)
        return writer.toString()
    }

    // Test 2: String interpolation as template
    fun renderStringTemplate(template: String, values: Map<String, String>): String {
        // VULNERABLE: User template with interpolation
        var result = template
        values.forEach { (key, value) ->
            result = result.replace("\${$key}", value)
        }
        return result
    }

    // Test 3: Velocity template
    fun renderVelocity(templateContent: String, context: Map<String, Any>): String {
        // VULNERABLE: User-controlled Velocity template
        val engine = org.apache.velocity.app.VelocityEngine()
        engine.init()
        val velocityContext = org.apache.velocity.VelocityContext(context)
        val writer = StringWriter()
        engine.evaluate(velocityContext, writer, "user", templateContent)
        return writer.toString()
    }

    // Test 4: Thymeleaf with user input
    fun renderThymeleaf(templateContent: String, variables: Map<String, Any>): String {
        // VULNERABLE: User-controlled template
        val templateEngine = org.thymeleaf.TemplateEngine()
        val context = org.thymeleaf.context.Context()
        context.setVariables(variables)
        return templateEngine.process(templateContent, context)
    }

    // Test 5: JSP expression
    fun generateJspExpression(userInput: String): String {
        // VULNERABLE: User input in JSP expression
        return "<%= $userInput %>"
    }

    // Test 6: Kotlin string template abuse
    fun dangerousStringTemplate(expression: String): String {
        // VULNERABLE: If evaluated dynamically
        return "Result: $expression"
    }

    // Test 7: Mustache template
    fun renderMustache(templateContent: String, data: Map<String, Any>): String {
        // VULNERABLE: User-controlled Mustache template
        val factory = com.github.mustachejava.DefaultMustacheFactory()
        val mustache = factory.compile(StringReader(templateContent), "user")
        val writer = StringWriter()
        mustache.execute(writer, data)
        return writer.toString()
    }

    // Test 8: Pebble template
    fun renderPebble(templateContent: String, context: Map<String, Any>): String {
        // VULNERABLE: User template with Pebble
        val engine = com.mitchellbosecke.pebble.PebbleEngine.Builder().build()
        val template = engine.getLiteralTemplate(templateContent)
        val writer = StringWriter()
        template.evaluate(writer, context)
        return writer.toString()
    }

    // Test 9: HTML construction with user data
    fun buildHtml(title: String, body: String): String {
        // VULNERABLE: User data in HTML template
        return """
            <html>
            <head><title>$title</title></head>
            <body>$body</body>
            </html>
        """.trimIndent()
    }

    // Test 10: Email template
    fun renderEmailTemplate(templateName: String, data: Map<String, String>): String {
        // VULNERABLE: Template name from user
        val templatePath = "templates/$templateName.ftl"
        val template = freemarkerConfig.getTemplate(templatePath)
        val writer = StringWriter()
        template.process(data, writer)
        return writer.toString()
    }

    // Test 11: JEXL expression injection
    fun evaluateExpression(expression: String, context: Map<String, Any>): Any? {
        // VULNERABLE: User-controlled expression
        val jexl = org.apache.commons.jexl3.JexlBuilder().create()
        val jexlExpression = jexl.createExpression(expression)
        val jexlContext = org.apache.commons.jexl3.MapContext(context)
        return jexlExpression.evaluate(jexlContext)
    }

    // Test 12: SpEL expression injection
    fun evaluateSpel(expression: String): Any? {
        // VULNERABLE: User-controlled SpEL
        val parser = org.springframework.expression.spel.standard.SpelExpressionParser()
        val expr = parser.parseExpression(expression)
        return expr.value
    }
}
