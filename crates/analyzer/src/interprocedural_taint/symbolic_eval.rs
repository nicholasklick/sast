//! Symbolic evaluation for constant propagation.
//!
//! This module provides symbolic evaluation of AST expressions to support
//! constant propagation during taint analysis. This enables elimination of
//! infeasible branches and more precise taint tracking.
//!
//! ## Example
//!
//! ```java
//! int num = 106;
//! String bar = (7 * 18) + num > 200 ? "safe" : taintedParam;
//! // Since 126 + 106 = 232 > 200 is ALWAYS TRUE, bar = "safe"
//! sink(bar);  // NOT a vulnerability
//! ```

use crate::interprocedural_taint::InterproceduralTaintAnalysis;
use crate::symbolic::{BinaryOperator, SymbolicState, SymbolicValue, UnaryOperator};
use gittera_parser::ast::{AstNode, AstNodeKind, LiteralValue};

impl InterproceduralTaintAnalysis {
    /// Evaluate an AST node to a symbolic value for constant propagation
    /// Uses language handler for language-specific literal and operator evaluation
    pub(crate) fn evaluate_symbolic(&self, node: &AstNode, sym_state: &SymbolicState) -> SymbolicValue {
        // First try language handler for literals (handles Python integer, float, etc.)
        if let Some(value) = self.language_handler.evaluate_literal(node) {
            return value;
        }

        // Then try language handler for binary operators (Python binary_operator)
        if let Some(value) = self.language_handler.evaluate_binary_op(node, sym_state) {
            return value;
        }

        // Then try language handler for comparisons (Python comparison_operator)
        if let Some(value) = self.language_handler.evaluate_comparison(node, sym_state) {
            return value;
        }

        // Fall back to generic handling
        match &node.kind {
            AstNodeKind::Identifier { name } => {
                // Look up in symbolic state
                sym_state.get(name)
            }

            AstNodeKind::BinaryExpression { operator } => {
                #[cfg(debug_assertions)]
                {
                    eprintln!("[DEBUG] BinaryExpression op='{}' with {} children:", operator, node.children.len());
                    for (i, child) in node.children.iter().enumerate() {
                        eprintln!("[DEBUG]   child[{}]: {:?} = '{}'", i, child.kind, child.text.lines().next().unwrap_or(""));
                    }
                }
                // Handle both 2-child (left, right) and 3-child (left, op, right) formats
                // Java/C often use 3 children: left, operator, right
                let (left_idx, right_idx) = if node.children.len() == 3 {
                    (0, 2) // Skip the operator node in the middle
                } else {
                    (0, 1)
                };
                if node.children.len() >= 2 {
                    let left = self.evaluate_symbolic(&node.children[left_idx], sym_state);
                    let right = self.evaluate_symbolic(&node.children[right_idx], sym_state);
                    #[cfg(debug_assertions)]
                    eprintln!("[DEBUG]   left={:?}, right={:?}", left, right);

                    let op = match operator.as_str() {
                        "+" => BinaryOperator::Add,
                        "-" => BinaryOperator::Subtract,
                        "*" => BinaryOperator::Multiply,
                        "/" => BinaryOperator::Divide,
                        "%" => BinaryOperator::Modulo,
                        "==" | "===" => BinaryOperator::Equal,
                        "!=" | "!==" => BinaryOperator::NotEqual,
                        "<" => BinaryOperator::LessThan,
                        "<=" => BinaryOperator::LessThanOrEqual,
                        ">" => BinaryOperator::GreaterThan,
                        ">=" => BinaryOperator::GreaterThanOrEqual,
                        "&&" => BinaryOperator::And,
                        "||" => BinaryOperator::Or,
                        "&" => BinaryOperator::BitwiseAnd,
                        "|" => BinaryOperator::BitwiseOr,
                        "^" => BinaryOperator::BitwiseXor,
                        "<<" => BinaryOperator::LeftShift,
                        ">>" => BinaryOperator::RightShift,
                        _ => return SymbolicValue::Unknown,
                    };

                    SymbolicValue::binary(op, left, right).simplify()
                } else {
                    SymbolicValue::Unknown
                }
            }

            AstNodeKind::UnaryExpression { operator } => {
                if let Some(operand_node) = node.children.first() {
                    let operand = self.evaluate_symbolic(operand_node, sym_state);

                    let op = match operator.as_str() {
                        "!" => UnaryOperator::Not,
                        "-" => UnaryOperator::Negate,
                        "~" => UnaryOperator::BitwiseNot,
                        _ => return SymbolicValue::Unknown,
                    };

                    SymbolicValue::UnaryOp {
                        operator: op,
                        operand: Box::new(operand),
                    }.simplify()
                } else {
                    SymbolicValue::Unknown
                }
            }

            AstNodeKind::ParenthesizedExpression => {
                #[cfg(debug_assertions)]
                {
                    eprintln!("[DEBUG] ParenthesizedExpression with {} children:", node.children.len());
                    for (i, child) in node.children.iter().enumerate() {
                        eprintln!("[DEBUG]   child[{}]: {:?} = '{}'", i, child.kind, child.text.lines().next().unwrap_or(""));
                    }
                }
                // The inner expression - skip leading ( and trailing )
                // For 3 children: (expr), the expression is at index 1
                // For 1 child: just the expression
                let inner_idx = if node.children.len() == 3 { 1 } else { 0 };
                if let Some(inner) = node.children.get(inner_idx) {
                    self.evaluate_symbolic(inner, sym_state)
                } else {
                    SymbolicValue::Unknown
                }
            }

            // Handle Python/JavaScript/Ruby subscript (string/list indexing): possible[1]
            // This is critical for match statement constant propagation
            // Python: "subscript", JavaScript: "subscript_expression", Ruby: "element_reference"
            AstNodeKind::Other { node_type } if node_type == "subscript" || node_type == "subscript_expression" || node_type == "element_reference" => {
                #[cfg(debug_assertions)]
                {
                    eprintln!("[DEBUG] Subscript with {} children:", node.children.len());
                    for (i, child) in node.children.iter().enumerate() {
                        eprintln!("[DEBUG]   child[{}]: {:?} = '{}'", i, child.kind, child.text.lines().next().unwrap_or(""));
                    }
                }
                // Python subscript structure: base[index]
                // children are typically: [base, "[", index, "]"] or [base, index]
                if let Some(base_node) = node.children.first() {
                    let base_val = self.evaluate_symbolic(base_node, sym_state);

                    // Find the index - skip "[" brackets
                    let index_node = node.children.iter().find(|c| {
                        !matches!(&c.kind, AstNodeKind::Other { node_type }
                            if node_type == "[" || node_type == "]")
                        && c.id != base_node.id
                    });

                    if let Some(idx_node) = index_node {
                        let idx_val = self.evaluate_symbolic(idx_node, sym_state);

                        // If we have a concrete string and concrete index, extract the character
                        if let (SymbolicValue::ConcreteString(s), SymbolicValue::Concrete(idx)) = (&base_val, &idx_val) {
                            let idx = *idx as usize;
                            if idx < s.len() {
                                let ch = s.chars().nth(idx).unwrap_or('\0');
                                #[cfg(debug_assertions)]
                                eprintln!("[DEBUG]   Subscript result: '{}'[{}] = '{}'", s, idx, ch);
                                return SymbolicValue::ConcreteString(ch.to_string());
                            }
                        }
                    }
                }
                SymbolicValue::Unknown
            }

            // Handle Java/C# method calls that can be evaluated symbolically
            // Most importantly: str.charAt(index) -> returns the character at index
            AstNodeKind::CallExpression { callee, .. } => {
                // Handle String.charAt(index) for switch statement constant propagation
                // Pattern: varName.charAt or "literal".charAt
                if callee.ends_with(".charAt") {
                    let receiver_name = callee.strip_suffix(".charAt").unwrap_or("");

                    // Get receiver value from symbolic state or as literal
                    let receiver_val = sym_state.get(receiver_name);

                    // Find the argument (the index)
                    let index_val: Option<i64> = node.children.iter()
                        .find_map(|child| {
                            if matches!(&child.kind, AstNodeKind::Other { node_type } if node_type == "argument_list") {
                                // Find numeric argument
                                for arg in &child.children {
                                    match &arg.kind {
                                        AstNodeKind::Literal { value: LiteralValue::Number(n) } => {
                                            return n.parse::<i64>().ok();
                                        }
                                        _ => {
                                            // Try symbolic evaluation
                                            let arg_val = self.evaluate_symbolic(arg, sym_state);
                                            if let SymbolicValue::Concrete(n) = arg_val {
                                                return Some(n);
                                            }
                                        }
                                    }
                                }
                            }
                            None
                        });

                    if let (SymbolicValue::ConcreteString(s), Some(idx)) = (receiver_val, index_val) {
                        if idx >= 0 && (idx as usize) < s.len() {
                            let ch = s.chars().nth(idx as usize).unwrap_or('\0');
                            #[cfg(debug_assertions)]
                            eprintln!("[DEBUG] charAt: '{}'.charAt({}) = '{}' (code {})", s, idx, ch, ch as i64);
                            // Return as integer for switch comparison (char is compared as int)
                            return SymbolicValue::Concrete(ch as i64);
                        }
                    }
                }
                SymbolicValue::Unknown
            }

            // For other expressions - return Unknown
            _ => SymbolicValue::Unknown,
        }
    }
}
