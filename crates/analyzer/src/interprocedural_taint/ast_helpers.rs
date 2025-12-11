//! AST Helper Functions for Taint Analysis
//!
//! Pure functions for extracting information from AST nodes.
//! These functions don't depend on analysis state.

use gittera_parser::ast::{AstNode, AstNodeKind};

/// Extract the variable name from an AST node.
/// For identifiers, returns the name directly.
/// For member expressions, returns the full path (e.g., "obj.field").
pub fn extract_variable_name(node: &AstNode) -> Option<String> {
    match &node.kind {
        AstNodeKind::Identifier { name } => Some(name.clone()),
        AstNodeKind::MemberExpression { .. } => {
            // For member expressions like obj.field, return the whole thing
            Some(node.text.trim().to_string())
        }
        // Handle Rust reference expressions: &var, &mut var
        AstNodeKind::Other { node_type } if node_type == "reference_expression" => {
            // The identifier is usually the last child
            for child in node.children.iter().rev() {
                if let Some(name) = extract_variable_name(child) {
                    return Some(name);
                }
            }
            None
        }
        _ => {
            // Try to find an identifier in children
            for child in &node.children {
                if let AstNodeKind::Identifier { name } = &child.kind {
                    return Some(name.clone());
                }
            }
            // Last resort: use the text, but clean it up
            let mut text = node.text.trim();
            // Strip parentheses from argument lists
            text = text.trim_start_matches('(').trim_end_matches(')').trim();
            // Strip Rust reference operators
            if text.starts_with('&') {
                text = text[1..].trim_start_matches("mut").trim();
            }
            if !text.is_empty() && text.len() < 100
               && text.chars().all(|c| c.is_alphanumeric() || c == '_' || c == '.') {
                Some(text.to_string())
            } else {
                None
            }
        }
    }
}

/// Extract the receiver of a method call expression.
/// For `bar.toCharArray()`, returns Some("bar").
/// This handles cases where sanitized data flows through value-preserving methods.
pub fn extract_method_call_receiver(node: &AstNode) -> Option<String> {
    // Check CallExpression with member callee
    if let AstNodeKind::CallExpression { .. } = &node.kind {
        // Find the member expression child which contains the object name
        for child in &node.children {
            if let AstNodeKind::MemberExpression { object, .. } = &child.kind {
                // `object` is a String containing the object name
                let obj_text = object.trim();
                if !obj_text.is_empty()
                    && obj_text.chars().all(|c| c.is_alphanumeric() || c == '_')
                    && !obj_text.chars().next().map(|c| c.is_numeric()).unwrap_or(true)
                {
                    return Some(obj_text.to_string());
                }
            }
        }
    }

    // Try text-based parsing for "bar.method()" patterns
    // Also handles "(bar.toCharArray())" from argument_list nodes
    let text = node.text.trim();
    // Strip leading/trailing parentheses that come from argument_list nodes
    let text = text.trim_start_matches('(').trim_end_matches(')').trim();

    if text.contains('.') && text.contains('(') {
        // Extract receiver before the first dot
        if let Some(dot_pos) = text.find('.') {
            let receiver = &text[..dot_pos];
            // Only return if it looks like a simple identifier
            if !receiver.is_empty()
                && receiver.chars().all(|c| c.is_alphanumeric() || c == '_')
                && !receiver.chars().next().map(|c| c.is_numeric()).unwrap_or(true)
            {
                return Some(receiver.to_string());
            }
        }
    }

    None
}

/// Extract an identifier from an AST node.
/// Simpler than extract_variable_name - only returns actual identifiers.
pub fn extract_identifier(node: &AstNode) -> Option<String> {
    if let AstNodeKind::Identifier { name } = &node.kind {
        return Some(name.clone());
    }

    // Try children
    for child in &node.children {
        if let AstNodeKind::Identifier { name } = &child.kind {
            return Some(name.clone());
        }
    }

    None
}

/// Find the argument at a specific index in a CallExpression node.
pub fn find_arg_at_index<'a>(node: &'a AstNode, index: usize) -> Option<&'a AstNode> {
    for child in &node.children {
        if matches!(&child.kind, AstNodeKind::Other { node_type } if node_type == "argument_list" || node_type == "arguments") {
            let args: Vec<&AstNode> = child.children.iter()
                .filter(|c| !matches!(&c.kind, AstNodeKind::Other { node_type } if node_type == "(" || node_type == ")" || node_type == ","))
                .collect();
            return args.get(index).copied();
        }
    }
    None
}

/// Check if text contains a word (with word boundaries).
/// Returns true if the word appears surrounded by non-identifier characters.
pub fn text_contains_word(text: &str, word: &str) -> bool {
    // Simple word boundary check: the word must be surrounded by non-identifier chars
    for (idx, _) in text.match_indices(word) {
        let before = if idx > 0 { text.chars().nth(idx - 1) } else { None };
        let after = text.chars().nth(idx + word.len());

        let before_is_boundary = before.map_or(true, |c| !c.is_alphanumeric() && c != '_');
        let after_is_boundary = after.map_or(true, |c| !c.is_alphanumeric() && c != '_');

        if before_is_boundary && after_is_boundary {
            return true;
        }
    }
    false
}

/// Find a function declaration node by name in an AST.
pub fn find_function_node<'a>(ast: &'a AstNode, func_name: &str) -> Option<&'a AstNode> {
    match &ast.kind {
        AstNodeKind::FunctionDeclaration { name, .. } if name == func_name => {
            return Some(ast);
        }
        AstNodeKind::MethodDeclaration { name, .. } => {
            // Handle both "ClassName.methodName" and just "methodName"
            if func_name.ends_with(&format!(".{}", name)) || name == func_name {
                return Some(ast);
            }
        }
        _ => {}
    }

    for child in &ast.children {
        if let Some(found) = find_function_node(child, func_name) {
            return Some(found);
        }
    }

    None
}

/// Extract parameter names from a function/method declaration.
pub fn extract_parameters(func: &AstNode) -> Vec<String> {
    match &func.kind {
        AstNodeKind::FunctionDeclaration { parameters, .. } => {
            parameters.iter().map(|p| p.name.clone()).collect()
        }
        AstNodeKind::MethodDeclaration { parameters, .. } => {
            parameters.iter().map(|p| p.name.clone()).collect()
        }
        _ => vec![],
    }
}

/// Check if a node or any of its descendants contains a return statement.
pub fn has_early_return(node: &AstNode) -> bool {
    match &node.kind {
        AstNodeKind::ReturnStatement => true,
        AstNodeKind::ThrowStatement { .. } => true,
        // Also consider raise in Python (represented as CallExpression to "raise")
        AstNodeKind::CallExpression { callee, .. } if callee == "raise" => true,
        _ => {
            // Check children
            node.children.iter().any(|c| has_early_return(c))
        }
    }
}

/// Check if a node is a collection initialization.
/// e.g., new ArrayList<>(), [], {}
pub fn is_collection_init(node: &AstNode) -> bool {
    let text = node.text.trim();

    // Java collection patterns - handle both simple and fully-qualified names
    let collection_types = [
        "ArrayList", "LinkedList", "Vector", "Stack", "ArrayDeque",
        "PriorityQueue", "CopyOnWriteArrayList", "HashSet", "TreeSet",
        "HashMap", "TreeMap", "LinkedHashMap", "Hashtable",
    ];

    // Check for "new" followed by collection type
    if text.contains("new ") {
        for ctype in collection_types {
            // Match "new ArrayList", "new java.util.ArrayList", etc.
            if text.contains(&format!("new {}", ctype))
                || text.contains(&format!(".{}<", ctype))
                || text.contains(&format!(".{}(", ctype))
                || text.ends_with(&format!(".{}", ctype))
            {
                return true;
            }
        }
    }

    // Python list/dict patterns
    if text == "[]" || text == "{}" || text.starts_with('[') || text.starts_with('{') {
        return true;
    }

    // Recursive check in children
    for child in &node.children {
        if is_collection_init(child) {
            return true;
        }
    }

    false
}

/// Extract all arguments from a call expression node.
pub fn extract_call_arguments(node: &AstNode) -> Vec<&AstNode> {
    for child in &node.children {
        if matches!(&child.kind, AstNodeKind::Other { node_type } if node_type == "argument_list" || node_type == "arguments") {
            return child.children.iter()
                .filter(|c| !matches!(&c.kind, AstNodeKind::Other { node_type } if node_type == "(" || node_type == ")" || node_type == ","))
                .collect();
        }
    }
    vec![]
}

/// Get the method name from a callee string.
/// For "obj.method", returns "method".
/// For "method", returns "method".
pub fn get_method_name(callee: &str) -> &str {
    callee.split('.').last().unwrap_or(callee)
}

/// Check if a callee looks like a getter method.
/// e.g., getParameter, readData, fetchInput
pub fn is_getter_method(callee: &str) -> bool {
    let method_lower = get_method_name(callee).to_lowercase();
    method_lower.starts_with("get")
        || method_lower.starts_with("read")
        || method_lower.starts_with("fetch")
        || method_lower.starts_with("retrieve")
}

#[cfg(test)]
mod tests {
    use super::*;
    use gittera_parser::ast::{Location, Span};

    fn test_location() -> Location {
        Location {
            file_path: "test.java".to_string(),
            span: Span {
                start_line: 1,
                start_column: 0,
                end_line: 1,
                end_column: 10,
                start_byte: 0,
                end_byte: 10,
            },
        }
    }

    fn make_identifier(name: &str) -> AstNode {
        AstNode {
            id: 1,
            kind: AstNodeKind::Identifier { name: name.to_string() },
            text: name.to_string(),
            location: test_location(),
            children: vec![],
        }
    }

    #[test]
    fn test_extract_variable_name_identifier() {
        let node = make_identifier("foo");
        assert_eq!(extract_variable_name(&node), Some("foo".to_string()));
    }

    #[test]
    fn test_text_contains_word() {
        assert!(text_contains_word("hello world", "hello"));
        assert!(text_contains_word("hello world", "world"));
        assert!(!text_contains_word("helloworld", "hello"));
        assert!(text_contains_word("foo(bar)", "bar"));
        assert!(!text_contains_word("foobar", "bar"));
    }

    #[test]
    fn test_get_method_name() {
        assert_eq!(get_method_name("obj.method"), "method");
        assert_eq!(get_method_name("a.b.c"), "c");
        assert_eq!(get_method_name("method"), "method");
    }

    #[test]
    fn test_is_getter_method() {
        assert!(is_getter_method("getParameter"));
        assert!(is_getter_method("obj.getParameter"));
        assert!(is_getter_method("readData"));
        assert!(is_getter_method("fetchInput"));
        assert!(!is_getter_method("setParameter"));
        assert!(!is_getter_method("processData"));
    }
}
