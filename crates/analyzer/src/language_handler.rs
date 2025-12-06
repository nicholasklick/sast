//! Language-specific taint analysis handlers
//!
//! This module defines the `LanguageTaintHandler` trait that abstracts
//! language-specific behavior in taint analysis, enabling isolated handling
//! of Python vs Java vs other languages without cross-contamination.

use crate::symbolic::{SymbolicValue, SymbolicState, BinaryOperator};
use crate::taint::{TaintSink, TaintSource};
use gittera_parser::ast::{AstNode, AstNodeKind, LiteralValue};
use gittera_parser::language::Language;

/// Indices for conditional expression branches (ternary operators)
/// Different languages have different AST structures for ternaries.
#[derive(Debug, Clone, Copy)]
pub struct ConditionalIndices {
    /// Index of the condition expression
    pub condition: usize,
    /// Index of the true branch expression
    pub true_branch: usize,
    /// Index of the false branch expression
    pub false_branch: usize,
}

/// Type of safe sink pattern detected
#[derive(Debug, Clone, PartialEq)]
pub enum SafeSinkPattern {
    /// Parameterized SQL query (e.g., cursor.execute(sql, (params,)))
    ParameterizedQuery,
    /// Prepared statement (e.g., Java PreparedStatement)
    PreparedStatement,
    /// Subprocess with list arguments (safer than shell=True)
    SubprocessWithList,
    /// Compiled XPath expression
    CompiledXPath,
    /// Input sanitized (e.g., quote escaping)
    SanitizedInput,
    /// No safe pattern detected
    None,
}

/// Trait for language-specific taint analysis behavior
///
/// Each language has unique AST structures, node types, and security patterns.
/// Implementing this trait allows the core taint analyzer to delegate
/// language-specific decisions without hardcoding conditional logic.
pub trait LanguageTaintHandler: Send + Sync {
    /// Get the language this handler supports
    fn language(&self) -> Language;

    // ========== AST Structure ==========

    /// Get the indices for conditional expression (ternary) branches
    ///
    /// Python: `value if condition else other` → [true_val, "if", condition, "else", false_val]
    /// Java/C: `condition ? value : other` → [condition, "?", true_val, ":", false_val]
    fn get_conditional_indices(&self, node: &AstNode) -> ConditionalIndices;

    /// Check if the child at the given index is the callee (not an argument)
    ///
    /// When checking if call arguments are tainted, we need to skip the callee
    /// (e.g., `root` in `root.xpath(query)` should not be considered as an argument)
    fn is_callee_position(&self, node: &AstNode, child_idx: usize) -> bool;

    /// Get the node type string for argument lists in this language
    fn get_argument_list_node_type(&self) -> &'static str;

    // ========== Symbolic Evaluation ==========

    /// Evaluate a literal node to a symbolic value
    ///
    /// Different languages have different AST representations for literals:
    /// - Java: `Literal { value: Number("106") }`
    /// - Python: `Other { node_type: "integer" }` with text "106"
    fn evaluate_literal(&self, node: &AstNode) -> Option<SymbolicValue>;

    /// Evaluate a binary operator node to a symbolic value
    ///
    /// Python has `binary_operator` nodes, Java has `BinaryExpression`
    fn evaluate_binary_op(&self, node: &AstNode, sym_state: &SymbolicState) -> Option<SymbolicValue>;

    /// Evaluate a comparison operator node to a symbolic value
    fn evaluate_comparison(&self, node: &AstNode, sym_state: &SymbolicState) -> Option<SymbolicValue>;

    // ========== Safe Patterns (FP Reduction) ==========

    /// Check if a sink call matches a safe pattern
    ///
    /// Returns the type of safe pattern detected, or None if unsafe
    fn detect_safe_sink_pattern(&self, callee: &str, node: &AstNode) -> SafeSinkPattern;

    // ========== Taint Configuration ==========

    /// Get language-specific taint sources
    fn get_sources(&self) -> Vec<TaintSource>;

    /// Get language-specific taint sinks
    fn get_sinks(&self) -> Vec<TaintSink>;

    /// Get language-specific sanitizer patterns
    fn get_sanitizers(&self) -> Vec<String>;
}

/// Get a handler for the specified language
pub fn get_handler_for_language(language: Language) -> Box<dyn LanguageTaintHandler> {
    match language {
        Language::Python => Box::new(PythonTaintHandler::new()),
        Language::Java => Box::new(JavaTaintHandler::new()),
        Language::Kotlin => Box::new(JavaTaintHandler::new()), // Kotlin is similar to Java
        Language::Scala => Box::new(JavaTaintHandler::new()),  // Scala is similar to Java
        _ => Box::new(GenericTaintHandler::new(language)),
    }
}

// ============================================================================
// Python Handler
// ============================================================================

/// Python-specific taint analysis handler
pub struct PythonTaintHandler;

impl PythonTaintHandler {
    pub fn new() -> Self {
        Self
    }
}

impl LanguageTaintHandler for PythonTaintHandler {
    fn language(&self) -> Language {
        Language::Python
    }

    fn get_conditional_indices(&self, _node: &AstNode) -> ConditionalIndices {
        // Python: `value if condition else other`
        // Structure: [true_val, "if", condition, "else", false_val]
        ConditionalIndices {
            condition: 2,
            true_branch: 0,
            false_branch: 4,
        }
    }

    fn is_callee_position(&self, node: &AstNode, child_idx: usize) -> bool {
        if child_idx != 0 {
            return false;
        }
        // Python callees are "attribute" or "identifier" nodes
        match node.children.get(0).map(|c| &c.kind) {
            Some(AstNodeKind::Identifier { .. }) => true,
            Some(AstNodeKind::MemberExpression { .. }) => true,
            Some(AstNodeKind::Other { node_type }) => {
                node_type == "attribute" || node_type == "identifier"
            }
            _ => false,
        }
    }

    fn get_argument_list_node_type(&self) -> &'static str {
        "argument_list"
    }

    fn evaluate_literal(&self, node: &AstNode) -> Option<SymbolicValue> {
        match &node.kind {
            // Standard literal handling
            AstNodeKind::Literal { value } => match value {
                LiteralValue::Number(n) => n.parse::<i64>().ok().map(SymbolicValue::Concrete),
                LiteralValue::Boolean(b) => Some(SymbolicValue::ConcreteBool(*b)),
                LiteralValue::String(s) => {
                    // Strip outer quotes if present (Python AST often includes them)
                    let text = s.trim();
                    let content = if (text.starts_with('"') && text.ends_with('"')) ||
                                   (text.starts_with('\'') && text.ends_with('\'')) {
                        text[1..text.len()-1].to_string()
                    } else {
                        text.to_string()
                    };
                    Some(SymbolicValue::ConcreteString(content))
                }
                LiteralValue::Null => Some(SymbolicValue::Null),
                LiteralValue::Undefined => Some(SymbolicValue::Undefined),
            },
            // Python-specific: integer and float nodes
            AstNodeKind::Other { node_type } if node_type == "integer" => {
                node.text.trim().parse::<i64>().ok().map(SymbolicValue::Concrete)
            }
            AstNodeKind::Other { node_type } if node_type == "float" => {
                node.text.trim().parse::<f64>().ok()
                    .map(|f| SymbolicValue::Concrete(f as i64))
            }
            AstNodeKind::Other { node_type } if node_type == "string" || node_type == "concatenated_string" => {
                // Extract string content (remove quotes)
                let text = node.text.trim();
                let content = if (text.starts_with('"') && text.ends_with('"')) ||
                               (text.starts_with('\'') && text.ends_with('\'')) {
                    text[1..text.len()-1].to_string()
                } else {
                    text.to_string()
                };
                Some(SymbolicValue::ConcreteString(content))
            }
            AstNodeKind::Other { node_type } if node_type == "true" => {
                Some(SymbolicValue::ConcreteBool(true))
            }
            AstNodeKind::Other { node_type } if node_type == "false" => {
                Some(SymbolicValue::ConcreteBool(false))
            }
            AstNodeKind::Other { node_type } if node_type == "none" => {
                Some(SymbolicValue::Null)
            }
            _ => None,
        }
    }

    fn evaluate_binary_op(&self, node: &AstNode, sym_state: &SymbolicState) -> Option<SymbolicValue> {
        // Python binary_operator has children: [left, operator, right]
        match &node.kind {
            AstNodeKind::Other { node_type } if node_type == "binary_operator" => {
                if node.children.len() >= 3 {
                    let left = evaluate_node_symbolic(node.children.get(0)?, sym_state, self);
                    let right = evaluate_node_symbolic(node.children.get(2)?, sym_state, self);

                    let op_text = node.children.get(1).map(|c| c.text.trim()).unwrap_or("");

                    let op = match op_text {
                        "+" => BinaryOperator::Add,
                        "-" => BinaryOperator::Subtract,
                        "*" => BinaryOperator::Multiply,
                        "/" => BinaryOperator::Divide,
                        "%" => BinaryOperator::Modulo,
                        _ => return None,
                    };

                    Some(SymbolicValue::binary(op, left, right).simplify())
                } else {
                    None
                }
            }
            _ => None,
        }
    }

    fn evaluate_comparison(&self, node: &AstNode, sym_state: &SymbolicState) -> Option<SymbolicValue> {
        // Python comparison_operator has children: [left, operator, right]
        match &node.kind {
            AstNodeKind::Other { node_type } if node_type == "comparison_operator" => {
                if node.children.len() >= 3 {
                    let left = evaluate_node_symbolic(node.children.get(0)?, sym_state, self);
                    let right = evaluate_node_symbolic(node.children.get(2)?, sym_state, self);

                    let op_text = node.children.get(1).map(|c| c.text.trim()).unwrap_or("");

                    let op = match op_text {
                        "==" => BinaryOperator::Equal,
                        "!=" => BinaryOperator::NotEqual,
                        "<" => BinaryOperator::LessThan,
                        "<=" => BinaryOperator::LessThanOrEqual,
                        ">" => BinaryOperator::GreaterThan,
                        ">=" => BinaryOperator::GreaterThanOrEqual,
                        _ => return None,
                    };

                    Some(SymbolicValue::binary(op, left, right).simplify())
                } else {
                    None
                }
            }
            _ => None,
        }
    }

    fn detect_safe_sink_pattern(&self, callee: &str, node: &AstNode) -> SafeSinkPattern {
        let method = callee.split('.').last().unwrap_or(callee).to_lowercase();

        // Check for parameterized SQL query pattern
        if method == "execute" || method == "query" || method == "executemany" {
            if self.is_parameterized_query(node) {
                return SafeSinkPattern::ParameterizedQuery;
            }
        }

        // Check for subprocess with list (safer pattern)
        if method == "run" || method == "popen" || method == "call" {
            if self.is_subprocess_with_list(node) {
                return SafeSinkPattern::SubprocessWithList;
            }
        }

        // Check for XPath with quote escaping (.replace('\'', '&apos;'))
        if method == "xpath" || method == "select" {
            if self.has_xpath_quote_escaping(node) {
                return SafeSinkPattern::SanitizedInput;
            }
        }

        SafeSinkPattern::None
    }

    fn get_sources(&self) -> Vec<TaintSource> {
        use crate::taint::TaintSourceKind;
        vec![
            // Flask/Django request inputs
            TaintSource { name: "request.args".into(), kind: TaintSourceKind::UserInput, node_id: 0 },
            TaintSource { name: "request.form".into(), kind: TaintSourceKind::UserInput, node_id: 0 },
            TaintSource { name: "request.values".into(), kind: TaintSourceKind::UserInput, node_id: 0 },
            TaintSource { name: "request.json".into(), kind: TaintSourceKind::UserInput, node_id: 0 },
            TaintSource { name: "request.data".into(), kind: TaintSourceKind::UserInput, node_id: 0 },
            TaintSource { name: "request.cookies".into(), kind: TaintSourceKind::UserInput, node_id: 0 },
            TaintSource { name: "request.headers".into(), kind: TaintSourceKind::UserInput, node_id: 0 },
            TaintSource { name: "request.GET".into(), kind: TaintSourceKind::UserInput, node_id: 0 },
            TaintSource { name: "request.POST".into(), kind: TaintSourceKind::UserInput, node_id: 0 },
            // Input functions
            TaintSource { name: "input".into(), kind: TaintSourceKind::UserInput, node_id: 0 },
            TaintSource { name: "raw_input".into(), kind: TaintSourceKind::UserInput, node_id: 0 },
            // Environment
            TaintSource { name: "os.environ".into(), kind: TaintSourceKind::EnvironmentVariable, node_id: 0 },
            TaintSource { name: "os.getenv".into(), kind: TaintSourceKind::EnvironmentVariable, node_id: 0 },
        ]
    }

    fn get_sinks(&self) -> Vec<TaintSink> {
        use crate::taint::TaintSinkKind;
        vec![
            // SQL
            TaintSink { name: "execute".into(), kind: TaintSinkKind::SqlQuery, node_id: 0 },
            TaintSink { name: "executemany".into(), kind: TaintSinkKind::SqlQuery, node_id: 0 },
            TaintSink { name: "cursor.execute".into(), kind: TaintSinkKind::SqlQuery, node_id: 0 },
            // Command execution
            TaintSink { name: "os.system".into(), kind: TaintSinkKind::CommandExecution, node_id: 0 },
            TaintSink { name: "subprocess.run".into(), kind: TaintSinkKind::CommandExecution, node_id: 0 },
            TaintSink { name: "subprocess.call".into(), kind: TaintSinkKind::CommandExecution, node_id: 0 },
            TaintSink { name: "subprocess.Popen".into(), kind: TaintSinkKind::CommandExecution, node_id: 0 },
            // Code eval
            TaintSink { name: "eval".into(), kind: TaintSinkKind::CodeEval, node_id: 0 },
            TaintSink { name: "exec".into(), kind: TaintSinkKind::CodeEval, node_id: 0 },
        ]
    }

    fn get_sanitizers(&self) -> Vec<String> {
        vec![
            "escape".into(),
            "html.escape".into(),
            "bleach.clean".into(),
            "markupsafe.escape".into(),
            "quote".into(),
            "shlex.quote".into(),
        ]
    }
}

impl PythonTaintHandler {
    /// Check if this is a parameterized SQL query
    /// Pattern: cursor.execute(sql, (params,)) or cursor.execute(sql, [params])
    fn is_parameterized_query(&self, node: &AstNode) -> bool {
        for child in &node.children {
            if let AstNodeKind::Other { node_type } = &child.kind {
                if node_type == "argument_list" {
                    let mut arg_count = 0;
                    let mut has_tuple_or_list = false;

                    for arg_child in &child.children {
                        match &arg_child.kind {
                            AstNodeKind::Other { node_type } => {
                                let nt = node_type.as_str();
                                if nt == "tuple" || nt == "list" || nt == "dictionary" {
                                    has_tuple_or_list = true;
                                    arg_count += 1;
                                } else if nt != "(" && nt != ")" && nt != "," {
                                    arg_count += 1;
                                }
                            }
                            AstNodeKind::Identifier { .. } => {
                                arg_count += 1;
                            }
                            _ => {}
                        }
                    }

                    // Parameterized query has 2+ args with tuple/list as 2nd arg
                    if arg_count >= 2 && has_tuple_or_list {
                        return true;
                    }
                }
            }
        }
        false
    }

    /// Check if subprocess is called with a list (safer than shell=True)
    fn is_subprocess_with_list(&self, node: &AstNode) -> bool {
        for child in &node.children {
            if let AstNodeKind::Other { node_type } = &child.kind {
                if node_type == "argument_list" {
                    // Check if first argument is a list
                    for (idx, arg_child) in child.children.iter().enumerate() {
                        if idx == 0 {
                            continue; // Skip opening paren
                        }
                        if let AstNodeKind::Other { node_type } = &arg_child.kind {
                            if node_type == "list" {
                                return true;
                            }
                        }
                        break; // Only check first real argument
                    }
                }
            }
        }
        false
    }

    /// Check if XPath query has quote escaping (e.g., .replace('\'', '&apos;'))
    /// This is a safe pattern for XPath injection
    fn has_xpath_quote_escaping(&self, node: &AstNode) -> bool {
        // Recursively search the node text for quote escaping patterns
        let text = &node.text;

        // Check for .replace('\'', '&apos;') or .replace("'", "&apos;") patterns
        if text.contains(".replace") && text.contains("&apos;") {
            return true;
        }

        // Check for .replace('\'', "'") or similar quote escaping
        if text.contains(".replace") && (text.contains("\\'") || text.contains("\"'\"")) {
            return true;
        }

        false
    }
}

// ============================================================================
// Java Handler
// ============================================================================

/// Java-specific taint analysis handler
pub struct JavaTaintHandler;

impl JavaTaintHandler {
    pub fn new() -> Self {
        Self
    }
}

impl LanguageTaintHandler for JavaTaintHandler {
    fn language(&self) -> Language {
        Language::Java
    }

    fn get_conditional_indices(&self, _node: &AstNode) -> ConditionalIndices {
        // Java/C: `condition ? value : other`
        // Structure: [condition, "?", true_val, ":", false_val]
        ConditionalIndices {
            condition: 0,
            true_branch: 2,
            false_branch: 4,
        }
    }

    fn is_callee_position(&self, node: &AstNode, child_idx: usize) -> bool {
        if child_idx != 0 {
            return false;
        }
        // Java callees are typically Identifier or MemberExpression
        match node.children.get(0).map(|c| &c.kind) {
            Some(AstNodeKind::Identifier { .. }) => true,
            Some(AstNodeKind::MemberExpression { .. }) => true,
            Some(AstNodeKind::Other { node_type }) => {
                node_type == "field_access" || node_type == "method_invocation"
            }
            _ => false,
        }
    }

    fn get_argument_list_node_type(&self) -> &'static str {
        "argument_list"
    }

    fn evaluate_literal(&self, node: &AstNode) -> Option<SymbolicValue> {
        match &node.kind {
            AstNodeKind::Literal { value } => match value {
                LiteralValue::Number(n) => n.parse::<i64>().ok().map(SymbolicValue::Concrete),
                LiteralValue::Boolean(b) => Some(SymbolicValue::ConcreteBool(*b)),
                LiteralValue::String(s) => {
                    // Strip outer quotes if present (AST often includes them)
                    let text = s.trim();
                    let content = if (text.starts_with('"') && text.ends_with('"')) ||
                                   (text.starts_with('\'') && text.ends_with('\'')) {
                        text[1..text.len()-1].to_string()
                    } else {
                        text.to_string()
                    };
                    Some(SymbolicValue::ConcreteString(content))
                }
                LiteralValue::Null => Some(SymbolicValue::Null),
                LiteralValue::Undefined => Some(SymbolicValue::Undefined),
            },
            AstNodeKind::Other { node_type } if node_type == "decimal_integer_literal" => {
                node.text.trim().parse::<i64>().ok().map(SymbolicValue::Concrete)
            }
            AstNodeKind::Other { node_type } if node_type == "string_literal" => {
                let text = node.text.trim();
                let content = if text.starts_with('"') && text.ends_with('"') {
                    text[1..text.len()-1].to_string()
                } else {
                    text.to_string()
                };
                Some(SymbolicValue::ConcreteString(content))
            }
            AstNodeKind::Other { node_type } if node_type == "true" => {
                Some(SymbolicValue::ConcreteBool(true))
            }
            AstNodeKind::Other { node_type } if node_type == "false" => {
                Some(SymbolicValue::ConcreteBool(false))
            }
            AstNodeKind::Other { node_type } if node_type == "null_literal" => {
                Some(SymbolicValue::Null)
            }
            _ => None,
        }
    }

    fn evaluate_binary_op(&self, node: &AstNode, sym_state: &SymbolicState) -> Option<SymbolicValue> {
        match &node.kind {
            AstNodeKind::BinaryExpression { operator } => {
                // Java binary expressions: either [left, right] or [left, op, right]
                let (left_idx, right_idx) = if node.children.len() == 3 {
                    (0, 2)
                } else {
                    (0, 1)
                };

                if node.children.len() >= 2 {
                    let left = evaluate_node_symbolic(node.children.get(left_idx)?, sym_state, self);
                    let right = evaluate_node_symbolic(node.children.get(right_idx)?, sym_state, self);

                    let op = match operator.as_str() {
                        "+" => BinaryOperator::Add,
                        "-" => BinaryOperator::Subtract,
                        "*" => BinaryOperator::Multiply,
                        "/" => BinaryOperator::Divide,
                        "%" => BinaryOperator::Modulo,
                        "==" => BinaryOperator::Equal,
                        "!=" => BinaryOperator::NotEqual,
                        "<" => BinaryOperator::LessThan,
                        "<=" => BinaryOperator::LessThanOrEqual,
                        ">" => BinaryOperator::GreaterThan,
                        ">=" => BinaryOperator::GreaterThanOrEqual,
                        "&&" => BinaryOperator::And,
                        "||" => BinaryOperator::Or,
                        _ => return None,
                    };

                    Some(SymbolicValue::binary(op, left, right).simplify())
                } else {
                    None
                }
            }
            _ => None,
        }
    }

    fn evaluate_comparison(&self, node: &AstNode, sym_state: &SymbolicState) -> Option<SymbolicValue> {
        // In Java, comparisons are BinaryExpression with comparison operators
        self.evaluate_binary_op(node, sym_state)
    }

    fn detect_safe_sink_pattern(&self, callee: &str, node: &AstNode) -> SafeSinkPattern {
        let callee_lower = callee.to_lowercase();

        // Check for PreparedStatement usage
        if callee_lower.contains("preparedstatement") ||
           callee_lower.contains("preparestatement") ||
           callee_lower.contains("preparequery") {
            return SafeSinkPattern::PreparedStatement;
        }

        // Check for parameterized query via method name patterns
        if self.is_prepared_statement_usage(node) {
            return SafeSinkPattern::PreparedStatement;
        }

        // Check for compiled XPath
        if callee_lower.contains("xpath") && callee_lower.contains("compile") {
            return SafeSinkPattern::CompiledXPath;
        }

        SafeSinkPattern::None
    }

    fn get_sources(&self) -> Vec<TaintSource> {
        use crate::taint::TaintSourceKind;
        vec![
            // Servlet
            TaintSource { name: "request.getParameter".into(), kind: TaintSourceKind::UserInput, node_id: 0 },
            TaintSource { name: "request.getParameterValues".into(), kind: TaintSourceKind::UserInput, node_id: 0 },
            TaintSource { name: "request.getHeader".into(), kind: TaintSourceKind::UserInput, node_id: 0 },
            TaintSource { name: "request.getCookies".into(), kind: TaintSourceKind::UserInput, node_id: 0 },
            TaintSource { name: "request.getInputStream".into(), kind: TaintSourceKind::UserInput, node_id: 0 },
            TaintSource { name: "request.getReader".into(), kind: TaintSourceKind::UserInput, node_id: 0 },
            TaintSource { name: "request.getQueryString".into(), kind: TaintSourceKind::UserInput, node_id: 0 },
            // Spring
            TaintSource { name: "@RequestParam".into(), kind: TaintSourceKind::UserInput, node_id: 0 },
            TaintSource { name: "@RequestBody".into(), kind: TaintSourceKind::UserInput, node_id: 0 },
            TaintSource { name: "@PathVariable".into(), kind: TaintSourceKind::UserInput, node_id: 0 },
            // Environment
            TaintSource { name: "System.getenv".into(), kind: TaintSourceKind::EnvironmentVariable, node_id: 0 },
            TaintSource { name: "System.getProperty".into(), kind: TaintSourceKind::EnvironmentVariable, node_id: 0 },
        ]
    }

    fn get_sinks(&self) -> Vec<TaintSink> {
        use crate::taint::TaintSinkKind;
        vec![
            // SQL
            TaintSink { name: "executeQuery".into(), kind: TaintSinkKind::SqlQuery, node_id: 0 },
            TaintSink { name: "executeUpdate".into(), kind: TaintSinkKind::SqlQuery, node_id: 0 },
            TaintSink { name: "execute".into(), kind: TaintSinkKind::SqlQuery, node_id: 0 },
            TaintSink { name: "createStatement".into(), kind: TaintSinkKind::SqlQuery, node_id: 0 },
            // Command execution
            TaintSink { name: "Runtime.exec".into(), kind: TaintSinkKind::CommandExecution, node_id: 0 },
            TaintSink { name: "ProcessBuilder".into(), kind: TaintSinkKind::CommandExecution, node_id: 0 },
            // XPath (uses CodeEval as it's code injection)
            TaintSink { name: "xpath.evaluate".into(), kind: TaintSinkKind::CodeEval, node_id: 0 },
            // LDAP (uses SqlQuery as it's query injection)
            TaintSink { name: "search".into(), kind: TaintSinkKind::SqlQuery, node_id: 0 },
        ]
    }

    fn get_sanitizers(&self) -> Vec<String> {
        vec![
            "escapeHtml".into(),
            "escapeSql".into(),
            "escapeXml".into(),
            "StringEscapeUtils.escapeHtml".into(),
            "ESAPI.encoder".into(),
            "Encode.forHtml".into(),
            "PreparedStatement".into(),
        ]
    }
}

impl JavaTaintHandler {
    /// Check if the call uses PreparedStatement pattern
    fn is_prepared_statement_usage(&self, node: &AstNode) -> bool {
        // Check if the receiver is a PreparedStatement
        if let Some(first_child) = node.children.get(0) {
            let text = first_child.text.to_lowercase();
            if text.contains("prepared") || text.contains("stmt") || text.contains("pstmt") {
                return true;
            }
        }

        // Check if the SQL string contains ? placeholders
        for child in &node.children {
            if child.text.contains("?") && !child.text.contains("??") {
                return true;
            }
        }

        false
    }
}

// ============================================================================
// Generic Handler (fallback)
// ============================================================================

/// Generic handler for languages without specific implementations
pub struct GenericTaintHandler {
    language: Language,
}

impl GenericTaintHandler {
    pub fn new(language: Language) -> Self {
        Self { language }
    }
}

impl LanguageTaintHandler for GenericTaintHandler {
    fn language(&self) -> Language {
        self.language
    }

    fn get_conditional_indices(&self, node: &AstNode) -> ConditionalIndices {
        // Try to detect based on AST structure
        // Default to Java/C style unless we see Python-style "if" keyword
        let is_python_style = node.children.get(1).map_or(false, |c| {
            matches!(&c.kind, AstNodeKind::Other { node_type } if node_type == "if")
        });

        if is_python_style {
            ConditionalIndices { condition: 2, true_branch: 0, false_branch: 4 }
        } else {
            ConditionalIndices { condition: 0, true_branch: 2, false_branch: 4 }
        }
    }

    fn is_callee_position(&self, node: &AstNode, child_idx: usize) -> bool {
        if child_idx != 0 {
            return false;
        }
        match node.children.get(0).map(|c| &c.kind) {
            Some(AstNodeKind::Identifier { .. }) => true,
            Some(AstNodeKind::MemberExpression { .. }) => true,
            Some(AstNodeKind::Other { node_type }) => {
                node_type == "attribute" || node_type == "identifier" ||
                node_type == "field_access" || node_type == "method_invocation"
            }
            _ => false,
        }
    }

    fn get_argument_list_node_type(&self) -> &'static str {
        "argument_list"
    }

    fn evaluate_literal(&self, node: &AstNode) -> Option<SymbolicValue> {
        match &node.kind {
            AstNodeKind::Literal { value } => match value {
                LiteralValue::Number(n) => n.parse::<i64>().ok().map(SymbolicValue::Concrete),
                LiteralValue::Boolean(b) => Some(SymbolicValue::ConcreteBool(*b)),
                LiteralValue::String(s) => Some(SymbolicValue::ConcreteString(s.clone())),
                LiteralValue::Null => Some(SymbolicValue::Null),
                LiteralValue::Undefined => Some(SymbolicValue::Undefined),
            },
            _ => None,
        }
    }

    fn evaluate_binary_op(&self, _node: &AstNode, _sym_state: &SymbolicState) -> Option<SymbolicValue> {
        None
    }

    fn evaluate_comparison(&self, _node: &AstNode, _sym_state: &SymbolicState) -> Option<SymbolicValue> {
        None
    }

    fn detect_safe_sink_pattern(&self, _callee: &str, _node: &AstNode) -> SafeSinkPattern {
        SafeSinkPattern::None
    }

    fn get_sources(&self) -> Vec<TaintSource> {
        Vec::new()
    }

    fn get_sinks(&self) -> Vec<TaintSink> {
        Vec::new()
    }

    fn get_sanitizers(&self) -> Vec<String> {
        Vec::new()
    }
}

// ============================================================================
// Helper Functions
// ============================================================================

/// Evaluate a node to a symbolic value using the language handler
pub fn evaluate_node_symbolic(
    node: &AstNode,
    sym_state: &SymbolicState,
    handler: &dyn LanguageTaintHandler,
) -> SymbolicValue {
    // Try handler-specific literal evaluation first
    if let Some(value) = handler.evaluate_literal(node) {
        return value;
    }

    // Try binary operator evaluation
    if let Some(value) = handler.evaluate_binary_op(node, sym_state) {
        return value;
    }

    // Try comparison evaluation
    if let Some(value) = handler.evaluate_comparison(node, sym_state) {
        return value;
    }

    // Handle identifiers
    if let AstNodeKind::Identifier { name } = &node.kind {
        return sym_state.get(name);
    }

    // Default
    SymbolicValue::Unknown
}
