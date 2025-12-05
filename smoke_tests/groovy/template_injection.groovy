// Template Injection vulnerabilities in Groovy
package com.example.security

import groovy.text.SimpleTemplateEngine
import groovy.text.GStringTemplateEngine

class TemplateInjectionVulnerabilities {

    // Test 1: SimpleTemplateEngine with user input
    String renderSimpleTemplate(String templateContent, Map data) {
        // VULNERABLE: User-controlled template
        def engine = new SimpleTemplateEngine()
        def template = engine.createTemplate(templateContent)
        template.make(data).toString()
    }

    // Test 2: GStringTemplateEngine
    String renderGStringTemplate(String templateContent, Map data) {
        // VULNERABLE: User-controlled GString template
        def engine = new GStringTemplateEngine()
        def template = engine.createTemplate(templateContent)
        template.make(data).toString()
    }

    // Test 3: StreamingTemplateEngine
    String renderStreamingTemplate(String templateContent, Map data) {
        // VULNERABLE: User-controlled streaming template
        def engine = new groovy.text.StreamingTemplateEngine()
        def template = engine.createTemplate(templateContent)
        template.make(data).toString()
    }

    // Test 4: MarkupTemplateEngine
    String renderMarkupTemplate(String templateContent, Map data) {
        // VULNERABLE: User-controlled markup template
        def config = new groovy.text.markup.MarkupTemplateEngine.TemplateConfiguration()
        def engine = new groovy.text.markup.MarkupTemplateEngine(config)
        def template = engine.createTemplate(templateContent)
        template.make(data).toString()
    }

    // Test 5: GString interpolation as template
    String renderGString(String template, Map values) {
        // VULNERABLE: User template with GString
        def binding = new Binding(values)
        def shell = new GroovyShell(binding)
        shell.evaluate("\"${template}\"")
    }

    // Test 6: Grails GSP (conceptual)
    String renderGsp(String content) {
        // VULNERABLE: Raw GSP output
        "\${raw('${content}')}"
    }

    // Test 7: HTML construction with GString
    String buildHtml(String title, String body) {
        // VULNERABLE: User data in HTML template
        """
        <html>
        <head><title>${title}</title></head>
        <body>${body}</body>
        </html>
        """
    }

    // Test 8: Email template from user
    String renderEmailTemplate(String templateName, Map data) {
        // VULNERABLE: Template name from user
        def templatePath = "templates/${templateName}.gsp"
        def templateContent = new File(templatePath).text
        renderSimpleTemplate(templateContent, data)
    }

    // Test 9: XmlTemplateEngine
    String renderXmlTemplate(String templateContent, Map data) {
        // VULNERABLE: User XML template
        def engine = new groovy.text.XmlTemplateEngine()
        def template = engine.createTemplate(templateContent)
        template.make(data).toString()
    }

    // Test 10: Closure-based template
    def renderClosureTemplate(String code, Map data) {
        // VULNERABLE: User code in closure
        def shell = new GroovyShell()
        def closure = shell.evaluate("{ -> ${code} }")
        closure.delegate = data
        closure.call()
    }

    // Test 11: MarkupBuilder with user content
    String buildMarkup(String content) {
        def writer = new StringWriter()
        def builder = new groovy.xml.MarkupBuilder(writer)
        builder.html {
            body {
                // VULNERABLE: User content
                mkp.yieldUnescaped(content)
            }
        }
        writer.toString()
    }

    // Test 12: ConfigSlurper as template
    def renderConfigTemplate(String configScript) {
        // VULNERABLE: Config script from user
        def config = new ConfigSlurper()
        config.parse(configScript)
    }

    // Test 13: Builder pattern injection
    String buildWithClosure(String builderCode) {
        // VULNERABLE: Builder code from user
        def shell = new GroovyShell()
        shell.evaluate("""
            def builder = new groovy.xml.MarkupBuilder()
            builder.${builderCode}
        """)
    }
}
