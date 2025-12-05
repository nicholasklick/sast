// XSS (Cross-Site Scripting) vulnerabilities in Dart

import 'dart:html';
import 'package:shelf/shelf.dart' as shelf;
import 'package:flutter_html/flutter_html.dart';

// Test 1: innerHTML assignment
void vulnerableInnerHtml(String userInput) {
  // VULNERABLE: Direct innerHTML assignment
  var element = document.getElementById('output');
  element?.innerHtml = userInput;
}

// Test 2: setInnerHtml without sanitizer
void vulnerableSetInnerHtml(String content) {
  // VULNERABLE: setInnerHtml without validator
  var element = DivElement();
  element.setInnerHtml(content);
}

// Test 3: document.write
void vulnerableDocumentWrite(String input) {
  // VULNERABLE: document.write with user input
  document.write(input);
}

// Test 4: Element creation with user content
void vulnerableCreateElement(String tagName, String content) {
  // VULNERABLE: User-controlled tag and content
  var element = Element.tag(tagName);
  element.text = content;
  document.body?.append(element);
}

// Test 5: Script element creation
void vulnerableScriptElement(String scriptContent) {
  // VULNERABLE: Creating script with user content
  var script = ScriptElement();
  script.text = scriptContent;
  document.head?.append(script);
}

// Test 6: Event handler attribute
void vulnerableEventHandler(String handler) {
  // VULNERABLE: User input in event handler
  var button = ButtonElement();
  button.setAttribute('onclick', handler);
}

// Test 7: href attribute injection
void vulnerableHrefInjection(String url) {
  // VULNERABLE: javascript: URL injection
  var link = AnchorElement();
  link.href = url;
  document.body?.append(link);
}

// Test 8: style attribute injection
void vulnerableStyleInjection(String style) {
  // VULNERABLE: CSS injection
  var element = DivElement();
  element.setAttribute('style', style);
}

// Test 9: Shelf response with HTML
shelf.Response vulnerableShelfResponse(String userContent) {
  // VULNERABLE: Unescaped HTML in response
  return shelf.Response.ok(
    '<html><body>$userContent</body></html>',
    headers: {'content-type': 'text/html'},
  );
}

// Test 10: Template literal injection
String vulnerableTemplate(String name) {
  // VULNERABLE: Template injection
  return '''
    <html>
      <body>
        <h1>Hello, $name!</h1>
      </body>
    </html>
  ''';
}

// Test 11: Flutter WebView HTML
void vulnerableWebViewHtml(String htmlContent) {
  // VULNERABLE: Loading user HTML in WebView
  // WebViewController().loadHtmlString(htmlContent);
  print('Would load: $htmlContent');
}

// Test 12: Flutter Html widget
Widget vulnerableHtmlWidget(String html) {
  // VULNERABLE: Rendering user HTML
  return Html(data: html);
}

// Test 13: JSON response with user data
shelf.Response vulnerableJsonResponse(String userData) {
  // VULNERABLE: User data in JSON that may be rendered
  return shelf.Response.ok(
    '{"message": "$userData"}',
    headers: {'content-type': 'application/json'},
  );
}

// Test 14: SVG injection
void vulnerableSvgInjection(String svgContent) {
  // VULNERABLE: SVG can contain scripts
  var container = DivElement();
  container.setInnerHtml(svgContent,
    treeSanitizer: NodeTreeSanitizer.trusted);
}

// Test 15: postMessage with user data
void vulnerablePostMessage(String message) {
  // VULNERABLE: Cross-origin message with user data
  window.postMessage(message, '*');
}
