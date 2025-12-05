// Template Injection Test Cases

// Test 1: Handlebars template injection
fn render_handlebars_template(template_str: &str, data: &serde_json::Value) -> Result<String, handlebars::RenderError> {
    use handlebars::Handlebars;

    let handlebars = Handlebars::new();
    // VULNERABLE: Rendering user-provided template
    handlebars.render_template(template_str, data)
}

// Test 2: Tera template injection
fn render_tera_template(template_str: &str, context: &tera::Context) -> Result<String, tera::Error> {
    use tera::Tera;

    let mut tera = Tera::default();
    // VULNERABLE: User-controlled template string
    tera.add_raw_template("user_template", template_str)?;
    tera.render("user_template", context)
}

// Test 3: Liquid template injection
fn render_liquid_template(template_str: &str) -> Result<String, liquid::Error> {
    use liquid::ParserBuilder;

    let parser = ParserBuilder::with_stdlib().build()?;
    // VULNERABLE: Compiling user input as template
    let template = parser.parse(template_str)?;
    let globals = liquid::Object::new();
    template.render(&globals)
}

// Test 4: Askama-like format string injection
fn format_user_content(format_str: &str, name: &str) -> String {
    // VULNERABLE: User-controlled format string
    format_str.replace("{name}", name)
}

// Test 5: String interpolation vulnerability
fn generate_html_from_template(user_template: &str, data: &std::collections::HashMap<String, String>) -> String {
    let mut result = user_template.to_string();
    // VULNERABLE: Simple replacement without proper escaping
    for (key, value) in data {
        result = result.replace(&format!("{{{}}}", key), value);
    }
    result
}
