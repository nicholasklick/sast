// Cross-Site Scripting (XSS) vulnerabilities in Groovy
package com.example.security

class XssVulnerabilities {

    // Test 1: Reflected XSS in response
    String handleRequest(String name) {
        // VULNERABLE: Direct output
        "<html><body>Hello, ${name}!</body></html>"
    }

    // Test 2: Stored XSS via database
    String displayComment(int commentId) {
        def comment = getCommentFromDb(commentId)
        // VULNERABLE: Unsanitized database content
        "<div class='comment'>${comment}</div>"
    }

    // Test 3: GString interpolation in JavaScript
    String generateScript(String userId) {
        // VULNERABLE: User data in JavaScript
        """
        <script>
            var userId = '${userId}';
            document.getElementById('user').innerHTML = userId;
        </script>
        """
    }

    // Test 4: JSONP callback injection
    String jsonResponse(String callback, String data) {
        // VULNERABLE: JSONP callback
        "${callback}(${data})"
    }

    // Test 5: Attribute injection
    String generateLink(String url) {
        // VULNERABLE: URL in href attribute
        "<a href=\"${url}\">Click here</a>"
    }

    // Test 6: Event handler injection
    String generateButton(String handler) {
        // VULNERABLE: Handler from user
        "<button onclick=\"${handler}\">Submit</button>"
    }

    // Test 7: Groovy MarkupBuilder without escaping
    String buildHtml(String userContent) {
        def writer = new StringWriter()
        def builder = new groovy.xml.MarkupBuilder(writer)
        builder.div {
            // VULNERABLE: User content unescaped
            mkp.yieldUnescaped(userContent)
        }
        writer.toString()
    }

    // Test 8: Template engine with user input
    String renderTemplate(String title, String content) {
        // VULNERABLE: Both parameters unescaped
        """
        <html>
        <head><title>${title}</title></head>
        <body>${content}</body>
        </html>
        """
    }

    // Test 9: Style injection
    String applyStyle(String userStyle) {
        // VULNERABLE: CSS injection
        "<div style=\"${userStyle}\">Content</div>"
    }

    // Test 10: Meta tag injection
    String setMetaTag(String content) {
        // VULNERABLE: Meta refresh injection
        "<meta http-equiv=\"refresh\" content=\"${content}\">"
    }

    // Test 11: Iframe source injection
    String embedIframe(String src) {
        // VULNERABLE: javascript: URLs possible
        "<iframe src=\"${src}\"></iframe>"
    }

    // Test 12: Grails GSP (conceptual)
    String gspRaw(String content) {
        // VULNERABLE: Raw output in GSP
        "\${raw(${content})}"
    }

    private String getCommentFromDb(int id) { "comment" }
}
