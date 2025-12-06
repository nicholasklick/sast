//! Query execution engine

use crate::ast::*;
use gittera_analyzer::call_graph::CallGraph;
use gittera_analyzer::cfg::ControlFlowGraph;
use gittera_analyzer::taint::TaintAnalysisResult;
use gittera_parser::ast::{AstNode, AstNodeKind, LiteralValue};
use regex::Regex;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct QueryResult {
    pub findings: Vec<Finding>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Finding {
    pub file_path: String,
    pub line: usize,
    pub column: usize,
    pub message: String,
    pub severity: String,
    pub code_snippet: String,
    pub category: String,  // e.g., "injection", "crypto", "secrets"
    pub rule_id: String,   // e.g., "sql-injection", "weak-crypto"
}

/// Evaluation context for a query
struct EvaluationContext<'a> {
    /// The current AST node being evaluated
    node: &'a AstNode,
    /// Taint analysis results (optional)
    taint_results: Option<&'a TaintAnalysisResult>,
    /// Call graph (optional, for inter-procedural queries)
    call_graph: Option<&'a CallGraph>,
    /// Variable bindings (from FROM clause)
    bindings: HashMap<String, &'a AstNode>,
}

impl<'a> EvaluationContext<'a> {
    fn new(
        node: &'a AstNode,
        taint_results: Option<&'a TaintAnalysisResult>,
        call_graph: Option<&'a CallGraph>,
    ) -> Self {
        Self {
            node,
            taint_results,
            call_graph,
            bindings: HashMap::new(),
        }
    }

    fn with_binding(mut self, name: String, node: &'a AstNode) -> Self {
        self.bindings.insert(name, node);
        self
    }

    fn get_binding(&self, name: &str) -> Option<&'a AstNode> {
        self.bindings.get(name).copied()
    }
}

/// Result of evaluating an expression
#[derive(Debug, Clone, PartialEq)]
enum Value {
    String(String),
    Number(i64),
    Boolean(bool),
    Null,
}

impl Value {
    fn as_string(&self) -> String {
        match self {
            Value::String(s) => s.clone(),
            Value::Number(n) => n.to_string(),
            Value::Boolean(b) => b.to_string(),
            Value::Null => "null".to_string(),
        }
    }

    fn as_bool(&self) -> bool {
        match self {
            Value::Boolean(b) => *b,
            Value::Null => false,
            Value::Number(n) => *n != 0,
            Value::String(s) => !s.is_empty(),
        }
    }
}

pub struct QueryExecutor;

impl QueryExecutor {
    pub fn execute(
        query: &Query,
        ast: &AstNode,
        _cfg: &ControlFlowGraph,
        taint_results: Option<&TaintAnalysisResult>,
    ) -> QueryResult {
        Self::execute_with_call_graph(query, ast, taint_results, None)
    }

    pub fn execute_with_call_graph(
        query: &Query,
        ast: &AstNode,
        taint_results: Option<&TaintAnalysisResult>,
        call_graph: Option<&CallGraph>,
    ) -> QueryResult {
        let mut findings = Vec::new();

        // Execute query on the AST
        Self::execute_on_node(query, ast, &mut findings, taint_results, call_graph);

        QueryResult { findings }
    }

    fn execute_on_node(
        query: &Query,
        node: &AstNode,
        findings: &mut Vec<Finding>,
        taint_results: Option<&TaintAnalysisResult>,
        call_graph: Option<&CallGraph>,
    ) {
        // Check if node matches the FROM clause
        if Self::matches_entity(&query.from.entity, &node.kind) {
            // Create evaluation context with variable binding
            let ctx = EvaluationContext::new(node, taint_results, call_graph)
                .with_binding(query.from.variable.clone(), node);

            // Check WHERE clause if present
            let matches = if let Some(ref where_clause) = query.where_clause {
                Self::evaluate_where(where_clause, &ctx)
            } else {
                true
            };

            if matches {
                // Extract message from SELECT clause
                let message = Self::format_select(&query.select, &ctx);

                findings.push(Finding {
                    file_path: node.location.file_path.clone(),
                    line: node.location.span.start_line,
                    column: node.location.span.start_column,
                    message,
                    severity: "Medium".to_string(),
                    code_snippet: node.text.lines().next().unwrap_or("").to_string(),
                    category: "security".to_string(),
                    rule_id: "unknown".to_string(),
                });
            }
        }

        // Recurse into children
        for child in &node.children {
            Self::execute_on_node(query, child, findings, taint_results, call_graph);
        }
    }

    fn matches_entity(entity: &EntityType, kind: &AstNodeKind) -> bool {
        match (entity, kind) {
            (EntityType::MethodCall, AstNodeKind::CallExpression { .. }) => true,
            (EntityType::CallExpression, AstNodeKind::CallExpression { .. }) => true,
            (EntityType::FunctionDeclaration, AstNodeKind::FunctionDeclaration { .. }) => true,
            (EntityType::VariableDeclaration, AstNodeKind::VariableDeclaration { .. }) => true,
            (EntityType::Assignment, AstNodeKind::AssignmentExpression { .. }) => true,
            (EntityType::BinaryExpression, AstNodeKind::BinaryExpression { .. }) => true,
            (EntityType::Literal, AstNodeKind::Literal { .. }) => true,
            (EntityType::MemberExpression, AstNodeKind::MemberExpression { .. }) => true,
            (EntityType::AnyNode, _) => true,
            _ => false,
        }
    }

    fn evaluate_where(where_clause: &WhereClause, ctx: &EvaluationContext) -> bool {
        // Evaluate all predicates with AND logic
        where_clause
            .predicates
            .iter()
            .all(|pred| Self::evaluate_predicate(pred, ctx))
    }

    fn evaluate_predicate(predicate: &Predicate, ctx: &EvaluationContext) -> bool {
        match predicate {
            Predicate::Comparison { left, operator, right } => {
                let left_val = Self::evaluate_expression(left, ctx);
                let right_val = Self::evaluate_expression(right, ctx);
                Self::compare_values(&left_val, operator, &right_val)
            }

            Predicate::And { left, right } => {
                Self::evaluate_predicate(left, ctx) && Self::evaluate_predicate(right, ctx)
            }

            Predicate::Or { left, right } => {
                Self::evaluate_predicate(left, ctx) || Self::evaluate_predicate(right, ctx)
            }

            Predicate::Not { predicate } => !Self::evaluate_predicate(predicate, ctx),

            Predicate::FunctionCall {
                variable,
                function,
                arguments,
            } => {
                // Handle special functions like isTainted(), calls(), etc.
                Self::evaluate_function_call_with_args(variable, function, arguments, ctx)
            }

            Predicate::MethodName { variable, operator, value } => {
                // Legacy support: variable.method == value
                if let Some(node) = ctx.get_binding(variable) {
                    if let Some(name) = Self::extract_name(node) {
                        let left = Value::String(name);
                        let right = Value::String(value.clone());
                        Self::compare_values(&left, operator, &right)
                    } else {
                        false
                    }
                } else {
                    false
                }
            }

            Predicate::PropertyAccess { variable: _, property: _ } => {
                // This is handled by expression evaluation
                true
            }
        }
    }

    fn evaluate_expression(expr: &Expression, ctx: &EvaluationContext) -> Value {
        match expr {
            Expression::Variable(name) => {
                // Look up the variable in bindings
                if let Some(node) = ctx.get_binding(name) {
                    // Try to extract a meaningful value from the node
                    if let Some(extracted_name) = Self::extract_name(node) {
                        Value::String(extracted_name)
                    } else {
                        Value::String(node.text.clone())
                    }
                } else {
                    Value::Null
                }
            }

            Expression::String(s) => Value::String(s.clone()),
            Expression::Number(n) => Value::Number(*n),
            Expression::Boolean(b) => Value::Boolean(*b),

            Expression::PropertyAccess { object, property } => {
                // Recursively evaluate nested property access
                Self::evaluate_property_access(object, property, ctx)
            }

            Expression::MethodCall {
                object,
                method,
                arguments: _,
            } => {
                // Evaluate method calls
                match object.as_ref() {
                    Expression::Variable(var_name) => {
                        if let Some(_node) = ctx.get_binding(var_name) {
                            Self::call_method(var_name, method, ctx)
                        } else {
                            Value::Null
                        }
                    }
                    _ => Value::Null,
                }
            }
        }
    }

    fn compare_values(left: &Value, operator: &ComparisonOp, right: &Value) -> bool {
        match operator {
            ComparisonOp::Equal => left == right,
            ComparisonOp::NotEqual => left != right,

            ComparisonOp::Contains => {
                let left_str = left.as_string().to_lowercase();
                let right_str = right.as_string().to_lowercase();
                left_str.contains(&right_str)
            }

            ComparisonOp::StartsWith => {
                let left_str = left.as_string().to_lowercase();
                let right_str = right.as_string().to_lowercase();
                left_str.starts_with(&right_str)
            }

            ComparisonOp::EndsWith => {
                let left_str = left.as_string().to_lowercase();
                let right_str = right.as_string().to_lowercase();
                left_str.ends_with(&right_str)
            }

            ComparisonOp::Matches => {
                let pattern = right.as_string();
                let text = left.as_string();
                if let Ok(regex) = Regex::new(&pattern) {
                    regex.is_match(&text)
                } else {
                    false
                }
            }
        }
    }

    /// Evaluate property access, supporting nested properties like a.b.c
    fn evaluate_property_access(
        object: &Expression,
        property: &str,
        ctx: &EvaluationContext,
    ) -> Value {
        match object {
            // Base case: simple variable
            Expression::Variable(var_name) => {
                if let Some(node) = ctx.get_binding(var_name) {
                    Self::get_property_value(node, property)
                } else {
                    Value::Null
                }
            }
            // Recursive case: nested property access (a.b.c)
            Expression::PropertyAccess {
                object: nested_object,
                property: nested_property,
            } => {
                // First evaluate the nested part (a.b), which should give us an AST node
                // Then access the property (c) on that node
                if let Expression::Variable(var_name) = nested_object.as_ref() {
                    if let Some(node) = ctx.get_binding(var_name) {
                        // Navigate to the nested property
                        if let Some(nested_node) =
                            Self::navigate_to_property(node, nested_property)
                        {
                            // Now get the final property from the nested node
                            Self::get_property_value(&nested_node, property)
                        } else {
                            Value::Null
                        }
                    } else {
                        Value::Null
                    }
                } else {
                    // Even deeper nesting - recursively evaluate
                    Value::Null // TODO: Could implement deeper recursion if needed
                }
            }
            _ => Value::Null,
        }
    }

    /// Navigate to a property within an AST node's children
    fn navigate_to_property(node: &AstNode, property: &str) -> Option<AstNode> {
        // Search through children for a node matching the property name
        for child in &node.children {
            if let Some(child_name) = Self::extract_name(child) {
                if child_name == property {
                    return Some(child.clone());
                }
            }

            // Also check if this child is a MemberExpression matching the property
            if let AstNodeKind::MemberExpression {
                property: prop, ..
            } = &child.kind
            {
                if prop == property {
                    return Some(child.clone());
                }
            }

            // Recursively search in children
            if let Some(found) = Self::navigate_to_property(child, property) {
                return Some(found);
            }
        }

        None
    }

    fn get_property_value(node: &AstNode, property: &str) -> Value {
        match property {
            "name" => {
                if let Some(name) = Self::extract_name(node) {
                    Value::String(name)
                } else {
                    Value::Null
                }
            }
            "text" => Value::String(node.text.clone()),
            "line" => Value::Number(node.location.span.start_line as i64),
            "column" => Value::Number(node.location.span.start_column as i64),
            _ => {
                // Try to extract nested properties from the node kind
                Self::extract_kind_property(node, property)
            }
        }
    }

    fn extract_name(node: &AstNode) -> Option<String> {
        match &node.kind {
            AstNodeKind::CallExpression { callee, .. } => Some(callee.clone()),
            AstNodeKind::FunctionDeclaration { name, .. } => Some(name.clone()),
            AstNodeKind::VariableDeclaration { name, .. } => Some(name.clone()),
            AstNodeKind::Identifier { name } => Some(name.clone()),
            AstNodeKind::MethodDeclaration { name, .. } => Some(name.clone()),
            _ => None,
        }
    }

    fn extract_kind_property(node: &AstNode, property: &str) -> Value {
        match (&node.kind, property) {
            (AstNodeKind::CallExpression { callee, .. }, "callee") => {
                Value::String(callee.clone())
            }
            (AstNodeKind::CallExpression { arguments_count, .. }, "argumentsCount") => {
                Value::Number(*arguments_count as i64)
            }
            (AstNodeKind::FunctionDeclaration { name, .. }, "name") => {
                Value::String(name.clone())
            }
            (AstNodeKind::FunctionDeclaration { parameters, .. }, "parameterCount") => {
                Value::Number(parameters.len() as i64)
            }
            (AstNodeKind::VariableDeclaration { name, .. }, "name") => {
                Value::String(name.clone())
            }
            (AstNodeKind::BinaryExpression { operator }, "operator") => {
                Value::String(operator.clone())
            }
            (AstNodeKind::MemberExpression { property, .. }, "property") => {
                Value::String(property.clone())
            }
            (AstNodeKind::MemberExpression { object, .. }, "object") => {
                Value::String(object.clone())
            }
            (AstNodeKind::Literal { value }, "value") => match value {
                LiteralValue::String(s) => Value::String(s.clone()),
                LiteralValue::Number(n) => Value::String(n.clone()),
                LiteralValue::Boolean(b) => Value::Boolean(*b),
                LiteralValue::Null => Value::Null,
                LiteralValue::Undefined => Value::Null,
            },
            _ => Value::Null,
        }
    }

    fn call_method(var_name: &str, method: &str, ctx: &EvaluationContext) -> Value {
        match method {
            "isTainted" => {
                // Check if the node is tainted
                if let Some(taint_results) = ctx.taint_results {
                    // Get the actual AST node bound to this variable
                    let is_tainted = if let Some(node) = ctx.get_binding(var_name) {
                        let node_line = node.location.span.start_line;
                        let node_text = &node.text;

                        // Check if this is a parameterized query pattern (safe from SQL injection)
                        // Pattern: execute(sql, (params,)) or execute(sql, [params])
                        // This is the safe way to use SQL - parameterized queries prevent injection
                        if Self::is_parameterized_query(node_text) {
                            return Value::Boolean(false);
                        }

                        taint_results.vulnerabilities.iter().any(|v| {
                            let tainted_var = &v.tainted_value.variable;
                            node_text.contains(tainted_var)
                                || tainted_var.contains(&node.text)
                                || v.sink.node_id as usize == node_line
                                || tainted_var.split('.').any(|part| node_text.contains(part) && !part.is_empty() && part.len() > 2)
                        })
                    } else {
                        taint_results.vulnerabilities.iter().any(|v| {
                            v.tainted_value.variable == var_name
                                || v.tainted_value.variable.split('.').any(|part| part == var_name)
                        })
                    };
                    Value::Boolean(is_tainted)
                } else {
                    Value::Boolean(false)
                }
            }
            "toString" => {
                if let Some(node) = ctx.get_binding(var_name) {
                    Value::String(node.text.clone())
                } else {
                    Value::Null
                }
            }
            _ => Value::Null,
        }
    }

    /// Check if a function calls another function (inter-procedural)
    fn calls_function(caller: &str, callee: &str, call_graph: Option<&CallGraph>) -> bool {
        if let Some(cg) = call_graph {
            cg.get_callees(caller)
                .iter()
                .any(|edge| edge.to == callee)
        } else {
            false
        }
    }

    /// Check if a function is called by another function (inter-procedural)
    fn called_by_function(callee: &str, caller: &str, call_graph: Option<&CallGraph>) -> bool {
        if let Some(cg) = call_graph {
            cg.get_callers(callee)
                .iter()
                .any(|c| *c == caller)
        } else {
            false
        }
    }

    /// Check if a function is reachable from another function (inter-procedural)
    fn reachable_from(target: &str, source: &str, call_graph: Option<&CallGraph>) -> bool {
        if let Some(cg) = call_graph {
            cg.reachable_from(source).contains(target)
        } else {
            false
        }
    }

    /// Check if a node represents a parameterized query pattern
    /// Parameterized queries are safe from SQL injection because user input is
    /// passed as a separate parameter, not concatenated into the SQL string.
    ///
    /// Patterns detected:
    /// - `execute(sql, (params,))` - tuple parameter
    /// - `execute(sql, [params])` - list parameter
    /// - `execute(sql, params)` - any second argument indicates parameterized
    fn is_parameterized_query(node_text: &str) -> bool {
        let text = node_text.to_lowercase();

        // Check for execute/query calls with multiple arguments (indicating parameterized)
        // Pattern: execute(..., (...)) or execute(..., [...])
        if text.contains("execute") || text.contains("query") {
            // Check if there's a comma followed by a tuple/list argument
            // This indicates parameterized: execute(sql, (param,)) or execute(sql, [param])
            let has_param_tuple = text.contains(", (") || text.contains(",(");
            let has_param_list = text.contains(", [") || text.contains(",[");
            let has_param_dict = text.contains(", {") || text.contains(",{");

            // If we see execute with a tuple/list/dict as second argument, it's parameterized
            // This is a conservative check - better to have false negatives than false positives
            if has_param_tuple || has_param_list || has_param_dict {
                return true;
            }

            // Also check for placeholder patterns in the SQL string if visible
            let has_placeholder = text.contains(" = ?")
                || text.contains("=?")
                || text.contains("= :")
                || text.contains("=:")
                || text.contains("$1")
                || text.contains("$2")
                || text.contains("%s")
                || text.contains("%(");

            if has_placeholder {
                return true;
            }
        }

        false
    }

    fn evaluate_function_call(variable: &str, function: &str, ctx: &EvaluationContext) -> bool {
        Self::evaluate_function_call_with_args(variable, function, &[], ctx)
    }

    fn evaluate_function_call_with_args(
        variable: &str,
        function: &str,
        arguments: &[Expression],
        ctx: &EvaluationContext,
    ) -> bool {
        match function {
            "isTainted" => {
                if let Some(taint_results) = ctx.taint_results {
                    // Get the actual AST node bound to this variable
                    if let Some(node) = ctx.get_binding(variable) {
                        // Check if this node's line/position overlaps with any tainted value
                        let node_line = node.location.span.start_line;
                        let node_text = &node.text;

                        taint_results.vulnerabilities.iter().any(|v| {
                            // Check if the tainted variable appears in this node's text
                            let tainted_var = &v.tainted_value.variable;
                            node_text.contains(tainted_var)
                                || tainted_var.contains(&node.text)
                                // Or check if lines match (sink is on same line as vulnerability)
                                || v.sink.node_id as usize == node_line
                                // Or if the tainted variable is in any part of the node
                                || tainted_var.split('.').any(|part| node_text.contains(part) && !part.is_empty() && part.len() > 2)
                        })
                    } else {
                        // Fallback to original variable name matching
                        taint_results.vulnerabilities.iter().any(|v| {
                            v.tainted_value.variable == variable
                                || v.tainted_value.variable.split('.').any(|part| part == variable)
                        })
                    }
                } else {
                    false
                }
            }
            "calls" => {
                // Check if function calls another function
                // Usage: func.calls("targetFunction")
                if arguments.is_empty() {
                    return false;
                }
                if let Expression::String(target_func) = &arguments[0] {
                    // Get the function name from the bound variable
                    if let Some(node) = ctx.get_binding(variable) {
                        if let Some(func_name) = Self::extract_name(node) {
                            return Self::calls_function(&func_name, target_func, ctx.call_graph);
                        }
                    }
                }
                false
            }
            "calledBy" => {
                // Check if function is called by another function
                // Usage: func.calledBy("callerFunction")
                if arguments.is_empty() {
                    return false;
                }
                if let Expression::String(caller_func) = &arguments[0] {
                    if let Some(node) = ctx.get_binding(variable) {
                        if let Some(func_name) = Self::extract_name(node) {
                            return Self::called_by_function(&func_name, caller_func, ctx.call_graph);
                        }
                    }
                }
                false
            }
            "reachableFrom" => {
                // Check if function is reachable from another function
                // Usage: func.reachableFrom("entryPoint")
                if arguments.is_empty() {
                    return false;
                }
                if let Expression::String(source_func) = &arguments[0] {
                    if let Some(node) = ctx.get_binding(variable) {
                        if let Some(func_name) = Self::extract_name(node) {
                            return Self::reachable_from(&func_name, source_func, ctx.call_graph);
                        }
                    }
                }
                false
            }
            _ => false,
        }
    }

    fn format_select(select: &SelectClause, ctx: &EvaluationContext) -> String {
        select
            .items
            .iter()
            .map(|item| match item {
                SelectItem::Variable(var) => {
                    if let Some(node) = ctx.get_binding(var) {
                        format!("Found: {}", node.kind)
                    } else {
                        format!("Variable: {}", var)
                    }
                }
                SelectItem::Message(msg) => msg.clone(),
                SelectItem::Both { variable: _, message } => message.clone(),
            })
            .collect::<Vec<_>>()
            .join(", ")
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use gittera_parser::ast::{Location, Span};

    fn create_test_node(kind: AstNodeKind, text: &str) -> AstNode {
        AstNode {
            id: 1,
            kind,
            location: Location {
                file_path: "test.js".to_string(),
                span: Span {
                    start_line: 1,
                    start_column: 0,
                    end_line: 1,
                    end_column: 10,
                    start_byte: 0,
                    end_byte: 10,
                },
            },
            children: Vec::new(),
            text: text.to_string(),
        }
    }

    #[test]
    fn test_value_as_string() {
        assert_eq!(Value::String("hello".to_string()).as_string(), "hello");
        assert_eq!(Value::Number(42).as_string(), "42");
        assert_eq!(Value::Boolean(true).as_string(), "true");
        assert_eq!(Value::Null.as_string(), "null");
    }

    #[test]
    fn test_compare_equal() {
        let left = Value::String("eval".to_string());
        let right = Value::String("eval".to_string());
        assert!(QueryExecutor::compare_values(&left, &ComparisonOp::Equal, &right));

        let left = Value::Number(42);
        let right = Value::Number(42);
        assert!(QueryExecutor::compare_values(&left, &ComparisonOp::Equal, &right));
    }

    #[test]
    fn test_compare_not_equal() {
        let left = Value::String("eval".to_string());
        let right = Value::String("safe".to_string());
        assert!(QueryExecutor::compare_values(&left, &ComparisonOp::NotEqual, &right));
    }

    #[test]
    fn test_compare_contains() {
        let left = Value::String("getUserInput".to_string());
        let right = Value::String("input".to_string());
        assert!(QueryExecutor::compare_values(&left, &ComparisonOp::Contains, &right));

        let left = Value::String("safe".to_string());
        let right = Value::String("input".to_string());
        assert!(!QueryExecutor::compare_values(&left, &ComparisonOp::Contains, &right));
    }

    #[test]
    fn test_compare_starts_with() {
        let left = Value::String("getUserInput".to_string());
        let right = Value::String("get".to_string());
        assert!(QueryExecutor::compare_values(&left, &ComparisonOp::StartsWith, &right));

        let left = Value::String("setUserInput".to_string());
        let right = Value::String("get".to_string());
        assert!(!QueryExecutor::compare_values(&left, &ComparisonOp::StartsWith, &right));
    }

    #[test]
    fn test_compare_ends_with() {
        let left = Value::String("getUserInput".to_string());
        let right = Value::String("Input".to_string());
        assert!(QueryExecutor::compare_values(&left, &ComparisonOp::EndsWith, &right));
    }

    #[test]
    fn test_compare_matches() {
        let left = Value::String("eval123".to_string());
        let right = Value::String(r"eval\d+".to_string());
        assert!(QueryExecutor::compare_values(&left, &ComparisonOp::Matches, &right));

        let left = Value::String("safe".to_string());
        let right = Value::String(r"eval\d+".to_string());
        assert!(!QueryExecutor::compare_values(&left, &ComparisonOp::Matches, &right));
    }

    #[test]
    fn test_extract_name() {
        let node = create_test_node(
            AstNodeKind::CallExpression {
                callee: "eval".to_string(),
                arguments_count: 1,
                is_optional_chain: false,
            },
            "eval(x)",
        );
        assert_eq!(QueryExecutor::extract_name(&node), Some("eval".to_string()));

        let node = create_test_node(
            AstNodeKind::FunctionDeclaration {
                name: "myFunc".to_string(),
                parameters: vec![],
                return_type: None,
                is_async: false,
                is_generator: false,
            },
            "function myFunc() {}",
        );
        assert_eq!(QueryExecutor::extract_name(&node), Some("myFunc".to_string()));
    }

    #[test]
    fn test_get_property_value() {
        let node = create_test_node(
            AstNodeKind::CallExpression {
                callee: "eval".to_string(),
                arguments_count: 2,
                is_optional_chain: false,
            },
            "eval(x, y)",
        );

        let name_val = QueryExecutor::get_property_value(&node, "name");
        assert_eq!(name_val, Value::String("eval".to_string()));

        let line_val = QueryExecutor::get_property_value(&node, "line");
        assert_eq!(line_val, Value::Number(1));

        let args_val = QueryExecutor::get_property_value(&node, "argumentsCount");
        assert_eq!(args_val, Value::Number(2));
    }

    #[test]
    fn test_evaluate_expression_variable() {
        let node = create_test_node(
            AstNodeKind::CallExpression {
                callee: "eval".to_string(),
                arguments_count: 1,
                is_optional_chain: false,
            },
            "eval(x)",
        );

        let ctx = EvaluationContext::new(&node, None, None)
            .with_binding("mc".to_string(), &node);

        let expr = Expression::Variable("mc".to_string());
        let result = QueryExecutor::evaluate_expression(&expr, &ctx);
        assert_eq!(result, Value::String("eval".to_string()));
    }

    #[test]
    fn test_evaluate_expression_property_access() {
        let node = create_test_node(
            AstNodeKind::CallExpression {
                callee: "eval".to_string(),
                arguments_count: 1,
                is_optional_chain: false,
            },
            "eval(x)",
        );

        let ctx = EvaluationContext::new(&node, None, None)
            .with_binding("mc".to_string(), &node);

        let expr = Expression::PropertyAccess {
            object: Box::new(Expression::Variable("mc".to_string())),
            property: "name".to_string(),
        };
        let result = QueryExecutor::evaluate_expression(&expr, &ctx);
        assert_eq!(result, Value::String("eval".to_string()));
    }

    #[test]
    fn test_evaluate_predicate_comparison() {
        let node = create_test_node(
            AstNodeKind::CallExpression {
                callee: "eval".to_string(),
                arguments_count: 1,
                is_optional_chain: false,
            },
            "eval(x)",
        );

        let ctx = EvaluationContext::new(&node, None, None)
            .with_binding("mc".to_string(), &node);

        let predicate = Predicate::Comparison {
            left: Expression::PropertyAccess {
                object: Box::new(Expression::Variable("mc".to_string())),
                property: "name".to_string(),
            },
            operator: ComparisonOp::Equal,
            right: Expression::String("eval".to_string()),
        };

        assert!(QueryExecutor::evaluate_predicate(&predicate, &ctx));
    }

    #[test]
    fn test_evaluate_predicate_and() {
        let node = create_test_node(
            AstNodeKind::CallExpression {
                callee: "eval".to_string(),
                arguments_count: 1,
                is_optional_chain: false,
            },
            "eval(x)",
        );

        let ctx = EvaluationContext::new(&node, None, None)
            .with_binding("mc".to_string(), &node);

        let predicate = Predicate::And {
            left: Box::new(Predicate::Comparison {
                left: Expression::PropertyAccess {
                    object: Box::new(Expression::Variable("mc".to_string())),
                    property: "name".to_string(),
                },
                operator: ComparisonOp::Equal,
                right: Expression::String("eval".to_string()),
            }),
            right: Box::new(Predicate::Comparison {
                left: Expression::PropertyAccess {
                    object: Box::new(Expression::Variable("mc".to_string())),
                    property: "argumentsCount".to_string(),
                },
                operator: ComparisonOp::Equal,
                right: Expression::Number(1),
            }),
        };

        assert!(QueryExecutor::evaluate_predicate(&predicate, &ctx));
    }

    #[test]
    fn test_evaluate_predicate_or() {
        let node = create_test_node(
            AstNodeKind::CallExpression {
                callee: "eval".to_string(),
                arguments_count: 1,
                is_optional_chain: false,
            },
            "eval(x)",
        );

        let ctx = EvaluationContext::new(&node, None, None)
            .with_binding("mc".to_string(), &node);

        let predicate = Predicate::Or {
            left: Box::new(Predicate::Comparison {
                left: Expression::PropertyAccess {
                    object: Box::new(Expression::Variable("mc".to_string())),
                    property: "name".to_string(),
                },
                operator: ComparisonOp::Equal,
                right: Expression::String("safe".to_string()),
            }),
            right: Box::new(Predicate::Comparison {
                left: Expression::PropertyAccess {
                    object: Box::new(Expression::Variable("mc".to_string())),
                    property: "name".to_string(),
                },
                operator: ComparisonOp::Equal,
                right: Expression::String("eval".to_string()),
            }),
        };

        assert!(QueryExecutor::evaluate_predicate(&predicate, &ctx));
    }

    #[test]
    fn test_evaluate_predicate_not() {
        let node = create_test_node(
            AstNodeKind::CallExpression {
                callee: "eval".to_string(),
                arguments_count: 1,
                is_optional_chain: false,
            },
            "eval(x)",
        );

        let ctx = EvaluationContext::new(&node, None, None)
            .with_binding("mc".to_string(), &node);

        let predicate = Predicate::Not {
            predicate: Box::new(Predicate::Comparison {
                left: Expression::PropertyAccess {
                    object: Box::new(Expression::Variable("mc".to_string())),
                    property: "name".to_string(),
                },
                operator: ComparisonOp::Equal,
                right: Expression::String("safe".to_string()),
            }),
        };

        assert!(QueryExecutor::evaluate_predicate(&predicate, &ctx));
    }

    #[test]
    fn test_matches_entity() {
        assert!(QueryExecutor::matches_entity(
            &EntityType::MethodCall,
            &AstNodeKind::CallExpression {
                callee: "test".to_string(),
                arguments_count: 0,
                is_optional_chain: false,
            }
        ));

        assert!(QueryExecutor::matches_entity(
            &EntityType::FunctionDeclaration,
            &AstNodeKind::FunctionDeclaration {
                name: "test".to_string(),
                parameters: vec![],
                return_type: None,
                is_async: false,
                is_generator: false,
            }
        ));

        assert!(QueryExecutor::matches_entity(
            &EntityType::AnyNode,
            &AstNodeKind::Literal {
                value: LiteralValue::String("test".to_string())
            }
        ));
    }
}
