// Cross-Site Scripting (XSS) vulnerabilities in Kotlin
package com.example.security

import javax.servlet.http.HttpServletRequest
import javax.servlet.http.HttpServletResponse
import java.io.PrintWriter

class XssVulnerabilities {

    // Test 1: Reflected XSS in response
    fun handleRequest(request: HttpServletRequest, response: HttpServletResponse) {
        val name = request.getParameter("name")
        val writer = response.writer
        // VULNERABLE: Direct output
        writer.println("<html><body>Hello, $name!</body></html>")
    }

    // Test 2: Stored XSS via database
    fun displayComment(commentId: Int, writer: PrintWriter) {
        val comment = getCommentFromDb(commentId)
        // VULNERABLE: Unsanitized database content
        writer.println("<div class='comment'>$comment</div>")
    }

    // Test 3: DOM XSS setup
    fun generateScript(userId: String): String {
        // VULNERABLE: User data in JavaScript
        return """
            <script>
                var userId = '$userId';
                document.getElementById('user').innerHTML = userId;
            </script>
        """.trimIndent()
    }

    // Test 4: JSON response injection
    fun jsonResponse(callback: String, data: String): String {
        // VULNERABLE: JSONP callback
        return "$callback($data)"
    }

    // Test 5: Attribute injection
    fun generateLink(url: String): String {
        // VULNERABLE: URL in href attribute
        return "<a href=\"$url\">Click here</a>"
    }

    // Test 6: Event handler injection
    fun generateButton(handler: String): String {
        // VULNERABLE: Handler from user
        return "<button onclick=\"$handler\">Submit</button>"
    }

    // Test 7: Style injection
    fun applyStyle(userStyle: String): String {
        // VULNERABLE: CSS injection
        return "<div style=\"$userStyle\">Content</div>"
    }

    // Test 8: Template literal injection
    fun renderTemplate(title: String, content: String): String {
        // VULNERABLE: Both parameters unescaped
        return """
            <html>
            <head><title>$title</title></head>
            <body>$content</body>
            </html>
        """.trimIndent()
    }

    // Test 9: SVG injection
    fun embedSvg(svgContent: String): String {
        // VULNERABLE: SVG can contain scripts
        return "<div>$svgContent</div>"
    }

    // Test 10: Meta tag injection
    fun setMetaTag(content: String): String {
        // VULNERABLE: Meta refresh injection
        return "<meta http-equiv=\"refresh\" content=\"$content\">"
    }

    // Test 11: Iframe source injection
    fun embedIframe(src: String): String {
        // VULNERABLE: javascript: URLs possible
        return "<iframe src=\"$src\"></iframe>"
    }

    // Test 12: Object/Embed injection
    fun embedObject(data: String): String {
        // VULNERABLE: Data URL injection
        return "<object data=\"$data\"></object>"
    }

    private fun getCommentFromDb(id: Int): String = "comment"
}
