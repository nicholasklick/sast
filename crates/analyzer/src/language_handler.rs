//! Language-specific taint analysis handlers
//!
//! This module defines the `LanguageTaintHandler` trait that abstracts
//! language-specific behavior in taint analysis, enabling isolated handling
//! of Python vs Java vs other languages without cross-contamination.
//!
//! ## New Abstractions (Phase 3 Refactoring)
//!
//! The trait now includes methods for language-specific patterns that were
//! previously hardcoded in the interprocedural taint analysis:
//!
//! - `is_constructor_sink()` - Java ProcessBuilder, Python subprocess.Popen
//! - `is_collection_initialization()` - Java `new ArrayList<>()`, Python `[]`
//! - `get_multi_return_pattern()` - Go `val, err := fn()`, Python `a, b = fn()`
//! - `is_web_handler()` - Flask @app.route, Spring @GetMapping
//! - `detect_trust_boundary_assignment()` - session['key'] = value
//! - `detect_validation_guard()` - `if '../' in var: return`

use crate::symbolic::{SymbolicValue, SymbolicState, BinaryOperator};
use crate::taint::{TaintSink, TaintSource, TaintSinkKind};
use gittera_parser::ast::{AstNode, AstNodeKind, LiteralValue};
use gittera_parser::language::Language;
use std::collections::HashSet;

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

// ============================================================================
// New Types for Language-Specific Abstractions (Phase 3)
// ============================================================================

/// Result of checking if a constructor is a sink
#[derive(Debug, Clone)]
pub struct ConstructorSinkInfo {
    /// The sink kind (e.g., CommandExecution, PathTraversal)
    pub sink_kind: TaintSinkKind,
    /// Which argument indices are dangerous (0-based)
    pub dangerous_arg_indices: Vec<usize>,
    /// Human-readable description
    pub description: &'static str,
}

/// Multi-return/tuple unpacking pattern information
#[derive(Debug, Clone)]
pub struct MultiReturnPattern {
    /// Variable names being assigned
    pub variables: Vec<String>,
    /// Strategy for taint propagation
    pub taint_strategy: MultiReturnTaintStrategy,
}

/// How to propagate taint in multi-return assignments
#[derive(Debug, Clone, Copy, PartialEq)]
pub enum MultiReturnTaintStrategy {
    /// All variables get tainted if any return value is tainted (conservative)
    TaintAll,
    /// Only taint the first variable (e.g., Go's `val, err := fn()` where err is not tainted)
    TaintFirst,
    /// Only taint specific indices (e.g., Python's `a, _, c = fn()`)
    TaintByIndex,
}

/// Trust boundary violation information
#[derive(Debug, Clone)]
pub struct TrustBoundaryViolation {
    /// The type of trust boundary crossed
    pub boundary_type: TrustBoundaryType,
    /// The key/property being assigned to
    pub key: String,
    /// Human-readable description
    pub description: String,
}

/// Types of trust boundaries that can be violated
#[derive(Debug, Clone, Copy, PartialEq)]
pub enum TrustBoundaryType {
    /// Session storage (session['key'] = tainted)
    Session,
    /// Cookie storage (response.set_cookie with tainted value)
    Cookie,
    /// Database write (storing tainted data without validation)
    Database,
    /// Cache storage
    Cache,
}

/// Validation guard detection result
#[derive(Debug, Clone)]
pub struct ValidationGuard {
    /// The variable being validated
    pub validated_variable: String,
    /// What the variable is validated against
    pub validation_type: ValidationType,
}

/// Types of validation patterns
#[derive(Debug, Clone, PartialEq)]
pub enum ValidationType {
    /// Path traversal check (e.g., '../' not in var)
    PathTraversal,
    /// Allowlist check (e.g., var in allowed_list)
    Allowlist,
    /// Type check (e.g., isinstance(var, int))
    TypeCheck,
    /// Length check (e.g., len(var) < MAX)
    LengthCheck,
    /// Pattern match (e.g., regex validation)
    PatternMatch,
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

    // ========== Language-Specific Patterns (Phase 3) ==========

    /// Check if a constructor/class instantiation is a sink
    ///
    /// Examples:
    /// - Java: `new ProcessBuilder(cmd)` → CommandExecution
    /// - Java: `new FileInputStream(path)` → PathTraversal
    /// - Python: `subprocess.Popen(cmd)` → CommandExecution
    ///
    /// Returns None if not a sink, or ConstructorSinkInfo with details
    fn is_constructor_sink(&self, class_name: &str) -> Option<ConstructorSinkInfo> {
        let _ = class_name;
        None // Default: no constructor sinks
    }

    /// Check if a node represents collection initialization
    ///
    /// Examples:
    /// - Java: `new ArrayList<>()`, `new HashMap<>()`
    /// - Python: `[]`, `{}`, `list()`, `dict()`
    /// - Go: `make([]string, 0)`, `map[string]int{}`
    ///
    /// Used to reset taint when a collection is re-initialized
    fn is_collection_initialization(&self, node: &AstNode) -> bool {
        let _ = node;
        false // Default: not collection initialization
    }

    /// Check if a node is a multi-return/tuple unpacking pattern
    ///
    /// Examples:
    /// - Go: `val, err := someFunc()` → TaintFirst (val tainted, err not)
    /// - Python: `a, b = func()` → TaintAll (both tainted)
    /// - Python: `a, _ = func()` → TaintByIndex (only a tainted)
    ///
    /// Returns None if not a multi-return pattern
    fn get_multi_return_pattern(&self, node: &AstNode) -> Option<MultiReturnPattern> {
        let _ = node;
        None // Default: no multi-return pattern
    }

    /// Check if a function/method is a web handler
    ///
    /// Examples:
    /// - Python/Flask: `@app.route('/path')` decorator
    /// - Python/Django: function in views.py with request param
    /// - Java/Spring: `@GetMapping`, `@PostMapping`, `@RequestMapping`
    /// - Ruby/Rails: methods in controllers
    ///
    /// Used for XSS detection (tainted returns from web handlers are vulnerabilities)
    fn is_web_handler(&self, node: &AstNode) -> bool {
        let _ = node;
        false // Default: not a web handler
    }

    /// Detect trust boundary violations in assignments
    ///
    /// Examples:
    /// - Python: `session['user_id'] = user_input` → Session boundary
    /// - JavaScript: `req.session.userId = tainted` → Session boundary
    /// - Python: `response.set_cookie('name', tainted)` → Cookie boundary
    ///
    /// Returns None if not a trust boundary assignment
    fn detect_trust_boundary_assignment(&self, node: &AstNode) -> Option<TrustBoundaryViolation> {
        let _ = node;
        None // Default: no trust boundary violation
    }

    /// Detect validation guard patterns in conditionals
    ///
    /// Examples:
    /// - Python: `if '../' in path: return` → PathTraversal validation
    /// - Java: `if (path.contains("..")) return;` → PathTraversal validation
    /// - Python: `if user_id in allowed_ids:` → Allowlist validation
    ///
    /// Used to track path-sanitized variables after validation guards
    fn detect_validation_guard(
        &self,
        condition: &AstNode,
        then_branch: &AstNode,
    ) -> Option<ValidationGuard> {
        let _ = (condition, then_branch);
        None // Default: no validation guard detected
    }

    /// Get the node types that represent if-statement branches for this language
    ///
    /// Returns (then_branch_index, else_branch_index) within the if-statement children
    /// Different languages structure if-statements differently:
    /// - Python: if_statement has [condition, ":", block, "else", ":", block]
    /// - Java/C: if_statement has [condition, statement, "else", statement]
    fn get_if_branch_indices(&self, node: &AstNode) -> (usize, Option<usize>) {
        let _ = node;
        // Default: Java/C style - then at index 1, else at index 3 (if present)
        (1, Some(3))
    }
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
            // Go uses "int_literal", "float_literal", "rune_literal"
            AstNodeKind::Other { node_type } if node_type == "integer" || node_type == "int_literal" || node_type == "rune_literal" => {
                node.text.trim().parse::<i64>().ok().map(SymbolicValue::Concrete)
            }
            AstNodeKind::Other { node_type } if node_type == "float" || node_type == "float_literal" => {
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

    // ========== Phase 3: Language-Specific Pattern Implementations ==========

    fn is_constructor_sink(&self, class_name: &str) -> Option<ConstructorSinkInfo> {
        match class_name {
            // subprocess.Popen is commonly used with tainted command
            "Popen" | "subprocess.Popen" => Some(ConstructorSinkInfo {
                sink_kind: TaintSinkKind::CommandExecution,
                dangerous_arg_indices: vec![0],
                description: "subprocess.Popen with tainted command",
            }),

            // File operations
            "open" | "io.open" | "builtins.open" => Some(ConstructorSinkInfo {
                sink_kind: TaintSinkKind::PathTraversal,
                dangerous_arg_indices: vec![0],
                description: "open() with tainted file path",
            }),

            _ => None,
        }
    }

    fn is_collection_initialization(&self, node: &AstNode) -> bool {
        // Check for Python collection initializations:
        // - [], {}, set(), list(), dict()
        match &node.kind {
            AstNodeKind::ArrayExpression { .. } => true, // []
            AstNodeKind::ObjectExpression { .. } => true, // {}

            AstNodeKind::Other { node_type } => {
                node_type == "list" || node_type == "dictionary" ||
                node_type == "set" || node_type == "tuple"
            }

            AstNodeKind::CallExpression { callee, .. } => {
                callee == "list" || callee == "dict" || callee == "set" ||
                callee == "tuple" || callee == "frozenset"
            }

            _ => false,
        }
    }

    fn get_multi_return_pattern(&self, node: &AstNode) -> Option<MultiReturnPattern> {
        // Python tuple unpacking: a, b = func()
        // Look for assignment with tuple on left side
        match &node.kind {
            AstNodeKind::AssignmentExpression { .. } => {
                // Check if left side is a pattern_list or tuple_pattern
                if let Some(left) = node.children.first() {
                    match &left.kind {
                        AstNodeKind::Other { node_type }
                            if node_type == "pattern_list" || node_type == "tuple_pattern" =>
                        {
                            let variables: Vec<String> = left.children.iter()
                                .filter_map(|c| {
                                    if let AstNodeKind::Identifier { name } = &c.kind {
                                        if name != "_" { // Skip underscore placeholders
                                            Some(name.clone())
                                        } else {
                                            None
                                        }
                                    } else {
                                        None
                                    }
                                })
                                .collect();

                            if !variables.is_empty() {
                                return Some(MultiReturnPattern {
                                    variables,
                                    taint_strategy: MultiReturnTaintStrategy::TaintAll,
                                });
                            }
                        }
                        _ => {}
                    }
                }
            }
            _ => {}
        }
        None
    }

    fn is_web_handler(&self, node: &AstNode) -> bool {
        // Check for Flask/Django decorators
        let text = &node.text;

        // Flask patterns
        if text.contains("@app.route") || text.contains("@blueprint.route") ||
           text.contains("@bp.route") {
            return true;
        }

        // FastAPI patterns
        if text.contains("@app.get") || text.contains("@app.post") ||
           text.contains("@app.put") || text.contains("@app.delete") ||
           text.contains("@router.get") || text.contains("@router.post") {
            return true;
        }

        // Check for Django view patterns (function with request parameter)
        if let AstNodeKind::FunctionDeclaration { .. } = &node.kind {
            // Check if first parameter is named 'request'
            for child in &node.children {
                if let AstNodeKind::Other { node_type } = &child.kind {
                    if node_type == "parameters" {
                        for param in &child.children {
                            if let AstNodeKind::Identifier { name } = &param.kind {
                                if name == "request" {
                                    return true;
                                }
                            }
                            // Check only first real parameter
                            if !matches!(&param.kind, AstNodeKind::Other { node_type } if node_type == "(" || node_type == ")") {
                                break;
                            }
                        }
                    }
                }
            }
        }

        false
    }

    fn detect_trust_boundary_assignment(&self, node: &AstNode) -> Option<TrustBoundaryViolation> {
        // Check for session['key'] = value pattern
        // Python: session['user_id'] = user_input
        match &node.kind {
            AstNodeKind::AssignmentExpression { .. } => {
                if let Some(left) = node.children.first() {
                    let left_text = &left.text;

                    // Check for session assignment
                    if left_text.contains("session[") {
                        // Extract the key
                        if let Some(start) = left_text.find('[') {
                            if let Some(end) = left_text.find(']') {
                                let key = left_text[start+1..end]
                                    .trim_matches(|c| c == '\'' || c == '"')
                                    .to_string();
                                return Some(TrustBoundaryViolation {
                                    boundary_type: TrustBoundaryType::Session,
                                    key,
                                    description: "Tainted data stored in session".to_string(),
                                });
                            }
                        }
                    }
                }
            }
            _ => {}
        }
        None
    }

    fn detect_validation_guard(
        &self,
        condition: &AstNode,
        then_branch: &AstNode,
    ) -> Option<ValidationGuard> {
        let cond_text = &condition.text;

        // Check for path traversal validation: '../' in path or '..' in path
        if (cond_text.contains("'../'") || cond_text.contains("'..'") ||
            cond_text.contains("\"../\"") || cond_text.contains("\"..\"")) &&
           cond_text.contains(" in ") {
            // Check if then_branch has early return/raise
            if self.has_early_exit(then_branch) {
                // Extract variable name (the one after "in")
                if let Some(var) = self.extract_in_variable(cond_text) {
                    return Some(ValidationGuard {
                        validated_variable: var,
                        validation_type: ValidationType::PathTraversal,
                    });
                }
            }
        }

        // Check for allowlist validation: var in allowed_list
        if cond_text.contains(" in ") && !cond_text.contains("..") {
            // This might be an allowlist check
            // We can't easily distinguish, so we'll skip for now
        }

        None
    }

    fn get_if_branch_indices(&self, _node: &AstNode) -> (usize, Option<usize>) {
        // Python if_statement structure: if condition: block [else: block]
        // Children: ["if", condition, ":", block, "else", ":", block]
        // or ["if", condition, ":", block, elif_clause, ...]
        (3, Some(6))
    }
}

impl PythonTaintHandler {
    /// Check if a branch has an early exit (return, raise)
    fn has_early_exit(&self, node: &AstNode) -> bool {
        match &node.kind {
            AstNodeKind::ReturnStatement => true,
            AstNodeKind::Other { node_type } if node_type == "raise_statement" => true,
            _ => {
                for child in &node.children {
                    if self.has_early_exit(child) {
                        return true;
                    }
                }
                false
            }
        }
    }

    /// Extract the variable from "x in var" pattern
    fn extract_in_variable(&self, text: &str) -> Option<String> {
        // Pattern: 'x' in variable or "x" in variable
        if let Some(in_pos) = text.find(" in ") {
            let after_in = &text[in_pos + 4..];
            // Get the identifier after "in"
            let var = after_in.split(|c: char| !c.is_alphanumeric() && c != '_')
                .next()?
                .trim();
            if !var.is_empty() {
                return Some(var.to_string());
            }
        }
        None
    }

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

        // IMPORTANT: Do NOT unconditionally treat prepareStatement as safe!
        // prepareStatement(sql) is STILL vulnerable if sql was built with tainted concatenation.
        // Example: sql = "SELECT * WHERE id=" + userInput; prepareStatement(sql); // VULNERABLE
        //
        // The safety of prepared statements comes from using parameter placeholders (?)
        // AND not having tainted data concatenated into the SQL string.
        // We cannot determine at this point whether the SQL argument is tainted,
        // so we must NOT skip the taint check for prepareStatement calls.

        // Only check for truly safe patterns where the operation itself is safe
        // regardless of input (like compiling an XPath expression)

        // Check for compiled XPath (compiling an expression is not itself dangerous)
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
            // NOTE: PreparedStatement is NOT a sanitizer!
            // Calling prepareStatement(taintedSQL) is still vulnerable.
            // PreparedStatement only prevents SQL injection when used with
            // parameter placeholders (?) and setString() for actual values.
        ]
    }

    // ========== Phase 3: Language-Specific Pattern Implementations ==========

    fn is_constructor_sink(&self, class_name: &str) -> Option<ConstructorSinkInfo> {
        match class_name {
            // Command execution sinks
            "ProcessBuilder" => Some(ConstructorSinkInfo {
                sink_kind: TaintSinkKind::CommandExecution,
                dangerous_arg_indices: vec![0], // First argument is the command
                description: "ProcessBuilder constructor with tainted command",
            }),

            // Path traversal sinks
            "FileInputStream" | "FileOutputStream" | "FileReader" | "FileWriter"
            | "RandomAccessFile" | "File" => Some(ConstructorSinkInfo {
                sink_kind: TaintSinkKind::PathTraversal,
                dangerous_arg_indices: vec![0], // First argument is the path
                description: "File I/O constructor with tainted path",
            }),

            // URL/SSRF sinks (using NetworkSend as closest match)
            "URL" | "URI" => Some(ConstructorSinkInfo {
                sink_kind: TaintSinkKind::NetworkSend,
                dangerous_arg_indices: vec![0],
                description: "URL/URI constructor with tainted address",
            }),

            // Socket sinks (potential SSRF)
            "Socket" | "ServerSocket" => Some(ConstructorSinkInfo {
                sink_kind: TaintSinkKind::NetworkSend,
                dangerous_arg_indices: vec![0, 1], // Host and port
                description: "Socket constructor with tainted host/port",
            }),

            _ => None,
        }
    }

    fn is_collection_initialization(&self, node: &AstNode) -> bool {
        // Check for Java collection initializations:
        // - new ArrayList<>(), new HashMap<>(), new HashSet<>(), etc.
        // - Arrays.asList(), List.of(), Set.of(), Map.of()
        match &node.kind {
            AstNodeKind::Other { node_type } if node_type == "object_creation_expression" => {
                let text = node.text.to_lowercase();
                text.contains("arraylist") || text.contains("hashmap") ||
                text.contains("hashset") || text.contains("linkedlist") ||
                text.contains("treemap") || text.contains("treeset") ||
                text.contains("concurrenthashmap") || text.contains("vector")
            }
            AstNodeKind::CallExpression { callee, .. } => {
                let callee_lower = callee.to_lowercase();
                callee_lower == "arrays.aslist" || callee_lower == "list.of" ||
                callee_lower == "set.of" || callee_lower == "map.of" ||
                callee_lower == "collections.emptylist" || callee_lower == "collections.emptymap"
            }
            _ => false,
        }
    }

    fn is_web_handler(&self, node: &AstNode) -> bool {
        // Check for Spring annotations: @GetMapping, @PostMapping, @RequestMapping, etc.
        // These are typically in decorators/annotations on the function
        let text = &node.text;

        // Check for Spring web annotations
        if text.contains("@GetMapping") || text.contains("@PostMapping") ||
           text.contains("@PutMapping") || text.contains("@DeleteMapping") ||
           text.contains("@RequestMapping") || text.contains("@PatchMapping") {
            return true;
        }

        // Check for JAX-RS annotations
        if text.contains("@GET") || text.contains("@POST") ||
           text.contains("@PUT") || text.contains("@DELETE") ||
           text.contains("@Path") {
            return true;
        }

        // Check for Servlet patterns (doGet, doPost methods)
        if let AstNodeKind::FunctionDeclaration { name, .. }
            | AstNodeKind::MethodDeclaration { name, .. } = &node.kind {
            let name_lower = name.to_lowercase();
            if name_lower == "doget" || name_lower == "dopost" ||
               name_lower == "doput" || name_lower == "dodelete" ||
               name_lower == "service" {
                return true;
            }
        }

        false
    }

    fn detect_validation_guard(
        &self,
        condition: &AstNode,
        then_branch: &AstNode,
    ) -> Option<ValidationGuard> {
        let cond_text = &condition.text;

        // Check for path traversal validation: path.contains("..")
        if cond_text.contains(".contains") && cond_text.contains("..") {
            // Check if then_branch has early return/throw
            if self.has_early_exit(then_branch) {
                // Extract variable name from condition
                if let Some(var) = self.extract_contains_receiver(cond_text) {
                    return Some(ValidationGuard {
                        validated_variable: var,
                        validation_type: ValidationType::PathTraversal,
                    });
                }
            }
        }

        None
    }

    fn get_if_branch_indices(&self, _node: &AstNode) -> (usize, Option<usize>) {
        // Java if-statement structure: if (condition) statement [else statement]
        // Children: ["if", "(", condition, ")", then_statement, "else", else_statement]
        // Or with blocks: ["if", "(", condition, ")", block, "else", block]
        (4, Some(6))
    }
}

impl JavaTaintHandler {
    /// Check if a branch has an early exit (return, throw)
    fn has_early_exit(&self, node: &AstNode) -> bool {
        match &node.kind {
            AstNodeKind::ReturnStatement | AstNodeKind::ThrowStatement => true,
            _ => {
                // Check children
                for child in &node.children {
                    if self.has_early_exit(child) {
                        return true;
                    }
                }
                false
            }
        }
    }

    /// Extract the receiver variable from a .contains() call
    fn extract_contains_receiver(&self, text: &str) -> Option<String> {
        // Pattern: variable.contains("...")
        if let Some(dot_pos) = text.find(".contains") {
            let before_dot = &text[..dot_pos];
            // Get the last identifier before the dot
            let var = before_dot.split(|c: char| !c.is_alphanumeric() && c != '_')
                .filter(|s| !s.is_empty())
                .last()?;
            return Some(var.to_string());
        }
        None
    }

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
            // Go uses int_literal, float_literal, rune_literal for numeric types
            // Rust uses integer_literal, float_literal
            // Ruby uses integer
            AstNodeKind::Other { node_type }
                if node_type == "int_literal"
                    || node_type == "integer_literal"
                    || node_type == "integer"
                    || node_type == "rune_literal" =>
            {
                node.text.trim().parse::<i64>().ok().map(SymbolicValue::Concrete)
            }
            AstNodeKind::Other { node_type }
                if node_type == "float_literal" || node_type == "float" =>
            {
                node.text.trim().parse::<f64>().ok()
                    .map(|f| SymbolicValue::Concrete(f as i64))
            }
            // Go uses true/false as Other nodes, Ruby uses true/false
            AstNodeKind::Other { node_type } if node_type == "true" => {
                Some(SymbolicValue::ConcreteBool(true))
            }
            AstNodeKind::Other { node_type } if node_type == "false" => {
                Some(SymbolicValue::ConcreteBool(false))
            }
            // Go uses interpreted_string_literal and raw_string_literal
            AstNodeKind::Other { node_type }
                if node_type == "interpreted_string_literal"
                    || node_type == "raw_string_literal" =>
            {
                let text = node.text.trim();
                // Strip outer quotes if present
                let content = if (text.starts_with('"') && text.ends_with('"'))
                    || (text.starts_with('`') && text.ends_with('`')) {
                    text[1..text.len()-1].to_string()
                } else {
                    text.to_string()
                };
                Some(SymbolicValue::ConcreteString(content))
            }
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

    // Handle parenthesized expressions - extract inner expression
    if let AstNodeKind::ParenthesizedExpression = &node.kind {
        // For 3 children: (, expr, ), the expression is at index 1
        // For 1 child: just the expression at index 0
        let inner_idx = if node.children.len() == 3 { 1 } else { 0 };
        if let Some(inner) = node.children.get(inner_idx) {
            return evaluate_node_symbolic(inner, sym_state, handler);
        }
    }

    // Default
    SymbolicValue::Unknown
}
