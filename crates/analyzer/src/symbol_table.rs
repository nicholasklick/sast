//! Symbol table for tracking variable definitions and uses

use kodecd_parser::ast::{NodeId, Span};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SymbolTable {
    scopes: Vec<Scope>,
    current_scope: usize,
}

impl SymbolTable {
    pub fn new() -> Self {
        Self {
            scopes: vec![Scope::new(0, None)],
            current_scope: 0,
        }
    }

    pub fn enter_scope(&mut self) {
        let scope_id = self.scopes.len();
        let new_scope = Scope::new(scope_id, Some(self.current_scope));
        self.scopes.push(new_scope);
        self.current_scope = scope_id;
    }

    pub fn exit_scope(&mut self) {
        if let Some(parent) = self.scopes[self.current_scope].parent {
            self.current_scope = parent;
        }
    }

    pub fn define(&mut self, name: String, symbol: Symbol) {
        self.scopes[self.current_scope].symbols.insert(name, symbol);
    }

    pub fn lookup(&self, name: &str) -> Option<&Symbol> {
        let mut scope_id = self.current_scope;
        loop {
            if let Some(symbol) = self.scopes[scope_id].symbols.get(name) {
                return Some(symbol);
            }

            if let Some(parent) = self.scopes[scope_id].parent {
                scope_id = parent;
            } else {
                return None;
            }
        }
    }

    pub fn current_scope(&self) -> &Scope {
        &self.scopes[self.current_scope]
    }

    /// Get all symbols in the current scope (non-recursive)
    pub fn current_scope_symbols(&self) -> &HashMap<String, Symbol> {
        &self.scopes[self.current_scope].symbols
    }

    /// Get all symbols visible from the current scope (includes parent scopes)
    pub fn visible_symbols(&self) -> HashMap<String, &Symbol> {
        let mut symbols = HashMap::new();
        let mut scope_id = self.current_scope;

        loop {
            for (name, symbol) in &self.scopes[scope_id].symbols {
                // Only add if not already defined in a more local scope
                symbols.entry(name.clone()).or_insert(symbol);
            }

            if let Some(parent) = self.scopes[scope_id].parent {
                scope_id = parent;
            } else {
                break;
            }
        }

        symbols
    }

    /// Lookup a symbol and return its type
    pub fn lookup_type(&self, name: &str) -> Option<String> {
        self.lookup(name).and_then(|s| s.type_info.clone())
    }

    /// Check if a symbol is defined in any visible scope
    pub fn is_defined(&self, name: &str) -> bool {
        self.lookup(name).is_some()
    }

    /// Get all symbols of a specific kind
    pub fn symbols_of_kind(&self, kind: SymbolKind) -> Vec<&Symbol> {
        self.scopes
            .iter()
            .flat_map(|scope| scope.symbols.values())
            .filter(|symbol| symbol.kind == kind)
            .collect()
    }

    /// Get the total number of scopes
    pub fn scope_count(&self) -> usize {
        self.scopes.len()
    }

    /// Get all scopes
    pub fn scopes(&self) -> &[Scope] {
        &self.scopes
    }

    /// Add a reference to a symbol
    pub fn add_reference(&mut self, name: &str, reference_node_id: NodeId) -> bool {
        let mut scope_id = self.current_scope;
        loop {
            if let Some(symbol) = self.scopes[scope_id].symbols.get_mut(name) {
                symbol.references.push(reference_node_id);
                return true;
            }

            if let Some(parent) = self.scopes[scope_id].parent {
                scope_id = parent;
            } else {
                return false;
            }
        }
    }

    /// Get all references to a symbol
    pub fn get_references(&self, name: &str) -> Option<&[NodeId]> {
        self.lookup(name).map(|s| s.references.as_slice())
    }

    /// Resolve a reference to its defining symbol
    /// Returns (symbol, scope_id where defined)
    pub fn resolve_reference(&self, name: &str) -> Option<(&Symbol, usize)> {
        let mut scope_id = self.current_scope;
        loop {
            if let Some(symbol) = self.scopes[scope_id].symbols.get(name) {
                return Some((symbol, scope_id));
            }

            if let Some(parent) = self.scopes[scope_id].parent {
                scope_id = parent;
            } else {
                return None;
            }
        }
    }
}

impl Default for SymbolTable {
    fn default() -> Self {
        Self::new()
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Scope {
    pub id: usize,
    pub parent: Option<usize>,
    pub symbols: HashMap<String, Symbol>,
}

impl Scope {
    pub fn new(id: usize, parent: Option<usize>) -> Self {
        Self {
            id,
            parent,
            symbols: HashMap::new(),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Symbol {
    pub name: String,
    pub kind: SymbolKind,
    pub node_id: NodeId,
    pub span: Span,
    pub type_info: Option<String>,
    /// Node IDs where this symbol is referenced (not defined)
    pub references: Vec<NodeId>,
    /// Scope ID where this symbol is defined
    pub scope_id: usize,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum SymbolKind {
    Variable,
    Function,
    Class,
    Method,
    Parameter,
    Constant,
}

/// Builder for constructing symbol tables from AST
pub struct SymbolTableBuilder {
    table: SymbolTable,
}

impl SymbolTableBuilder {
    pub fn new() -> Self {
        Self {
            table: SymbolTable::new(),
        }
    }

    /// Build symbol table from an AST
    pub fn build(mut self, ast: &kodecd_parser::ast::AstNode) -> SymbolTable {
        self.visit_node(ast);
        self.table
    }

    fn visit_node(&mut self, node: &kodecd_parser::ast::AstNode) {
        use kodecd_parser::ast::AstNodeKind;

        match &node.kind {
            // Function declarations create a new scope
            AstNodeKind::FunctionDeclaration { name, parameters, return_type, .. } => {
                // Define the function in the current scope
                let scope_id = self.table.current_scope;
                self.table.define(name.clone(), Symbol {
                    name: name.clone(),
                    kind: SymbolKind::Function,
                    node_id: node.id,
                    span: node.location.span,
                    type_info: return_type.clone(),
                    references: Vec::new(),
                    scope_id,
                });

                // Enter function scope
                self.table.enter_scope();

                // Add parameters to the function scope
                for param in parameters {
                    let param_scope_id = self.table.current_scope;
                    self.table.define(param.name.clone(), Symbol {
                        name: param.name.clone(),
                        kind: SymbolKind::Parameter,
                        node_id: node.id,
                        span: node.location.span,
                        type_info: param.param_type.clone(),
                        references: Vec::new(),
                        scope_id: param_scope_id,
                    });
                }

                // Visit function body
                for child in &node.children {
                    self.visit_node(child);
                }

                // Exit function scope
                self.table.exit_scope();
            }

            // Method declarations create a new scope
            AstNodeKind::MethodDeclaration { name, parameters, return_type, .. } => {
                // Define the method in the current scope
                let scope_id = self.table.current_scope;
                self.table.define(name.clone(), Symbol {
                    name: name.clone(),
                    kind: SymbolKind::Method,
                    node_id: node.id,
                    span: node.location.span,
                    type_info: return_type.clone(),
                    references: Vec::new(),
                    scope_id,
                });

                // Enter method scope
                self.table.enter_scope();

                // Add parameters
                for param in parameters {
                    let param_scope_id = self.table.current_scope;
                    self.table.define(param.name.clone(), Symbol {
                        name: param.name.clone(),
                        kind: SymbolKind::Parameter,
                        node_id: node.id,
                        span: node.location.span,
                        type_info: param.param_type.clone(),
                        references: Vec::new(),
                        scope_id: param_scope_id,
                    });
                }

                // Visit method body
                for child in &node.children {
                    self.visit_node(child);
                }

                self.table.exit_scope();
            }

            // Class declarations create a new scope
            AstNodeKind::ClassDeclaration { name, .. } => {
                // Define the class in the current scope
                let scope_id = self.table.current_scope;
                self.table.define(name.clone(), Symbol {
                    name: name.clone(),
                    kind: SymbolKind::Class,
                    node_id: node.id,
                    span: node.location.span,
                    type_info: Some(name.clone()),
                    references: Vec::new(),
                    scope_id,
                });

                // Enter class scope
                self.table.enter_scope();

                // Visit class members
                for child in &node.children {
                    self.visit_node(child);
                }

                self.table.exit_scope();
            }

            // Variable declarations
            AstNodeKind::VariableDeclaration { name, var_type, is_const, .. } => {
                let kind = if *is_const {
                    SymbolKind::Constant
                } else {
                    SymbolKind::Variable
                };

                let scope_id = self.table.current_scope;
                self.table.define(name.clone(), Symbol {
                    name: name.clone(),
                    kind,
                    node_id: node.id,
                    span: node.location.span,
                    type_info: var_type.clone(),
                    references: Vec::new(),
                    scope_id,
                });

                // Visit initializer if present
                for child in &node.children {
                    self.visit_node(child);
                }
            }

            // Blocks create a new scope
            AstNodeKind::Block => {
                self.table.enter_scope();

                for child in &node.children {
                    self.visit_node(child);
                }

                self.table.exit_scope();
            }

            // For other nodes, just traverse children
            _ => {
                for child in &node.children {
                    self.visit_node(child);
                }
            }
        }
    }
}

impl Default for SymbolTableBuilder {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use kodecd_parser::ast::{AstNode, AstNodeKind, Location, Span};

    fn create_test_location() -> Location {
        Location {
            file_path: "test.js".to_string(),
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

    fn create_test_symbol(name: &str, kind: SymbolKind, node_id: NodeId, type_info: Option<String>, scope_id: usize) -> Symbol {
        Symbol {
            name: name.to_string(),
            kind,
            node_id,
            span: Span {
                start_line: 1,
                start_column: 0,
                end_line: 1,
                end_column: name.len(),
                start_byte: 0,
                end_byte: name.len(),
            },
            type_info,
            references: Vec::new(),
            scope_id,
        }
    }

    #[test]
    fn test_basic_symbol_table() {
        let mut table = SymbolTable::new();

        // Define a variable
        table.define("x".to_string(), Symbol {
            name: "x".to_string(),
            kind: SymbolKind::Variable,
            node_id: 1,
            span: Span {
                start_line: 1,
                start_column: 0,
                end_line: 1,
                end_column: 1,
                start_byte: 0,
                end_byte: 1,
            },
            type_info: Some("number".to_string()),
            references: Vec::new(),
            scope_id: 0,
        });

        // Lookup the variable
        assert!(table.is_defined("x"));
        assert_eq!(table.lookup_type("x"), Some("number".to_string()));
    }

    #[test]
    fn test_scope_hierarchy() {
        let mut table = SymbolTable::new();

        // Define in global scope
        table.define("global".to_string(), create_test_symbol("global", SymbolKind::Variable, 1, None, 0));

        // Enter nested scope
        table.enter_scope();

        // Define in nested scope
        table.define("local".to_string(), create_test_symbol("local", SymbolKind::Variable, 2, None, 1));

        // Both should be visible in nested scope
        assert!(table.is_defined("global"));
        assert!(table.is_defined("local"));

        // Exit nested scope
        table.exit_scope();

        // Only global should be visible now
        assert!(table.is_defined("global"));
        assert!(!table.is_defined("local"));
    }

    #[test]
    fn test_shadowing() {
        let mut table = SymbolTable::new();

        // Define in global scope
        table.define("x".to_string(), create_test_symbol("x", SymbolKind::Variable, 1, Some("string".to_string()), 0));

        // Enter nested scope
        table.enter_scope();

        // Shadow with different type
        table.define("x".to_string(), create_test_symbol("x", SymbolKind::Variable, 2, Some("number".to_string()), 1));

        // Should resolve to the shadowed version
        assert_eq!(table.lookup_type("x"), Some("number".to_string()));

        // Exit nested scope
        table.exit_scope();

        // Should resolve to the outer version
        assert_eq!(table.lookup_type("x"), Some("string".to_string()));
    }

    #[test]
    fn test_builder_function_scope() {
        // Create AST for: function add(a, b) { let sum = a + b; return sum; }
        let mut func_node = AstNode::new(
            1,
            AstNodeKind::FunctionDeclaration {
                name: "add".to_string(),
                parameters: vec![
                    kodecd_parser::Parameter {
                        name: "a".to_string(),
                        param_type: None,
                        default_value: None,
                        is_optional: false,
                        is_rest: false,
                    },
                    kodecd_parser::Parameter {
                        name: "b".to_string(),
                        param_type: None,
                        default_value: None,
                        is_optional: false,
                        is_rest: false,
                    },
                ],
                return_type: Some("number".to_string()),
                is_async: false,
                is_generator: false,
            },
            create_test_location(),
            "function add(a, b) { ... }".to_string(),
        );

        // Add variable declaration inside function
        let var_node = AstNode::new(
            2,
            AstNodeKind::VariableDeclaration {
                name: "sum".to_string(),
                var_type: Some("number".to_string()),
                is_const: false,
                initializer: None,
            },
            create_test_location(),
            "let sum = a + b".to_string(),
        );
        func_node.add_child(var_node);

        let program = AstNode::new(
            0,
            AstNodeKind::Program,
            create_test_location(),
            "".to_string(),
        );

        let builder = SymbolTableBuilder::new();
        let table = builder.build(&func_node);

        // Function should be defined
        assert!(table.is_defined("add"));
        assert_eq!(table.lookup_type("add"), Some("number".to_string()));

        // Should have multiple scopes (global + function)
        assert!(table.scope_count() >= 2);
    }

    #[test]
    fn test_builder_class_scope() {
        // Create AST for: class MyClass { method() { } }
        let mut class_node = AstNode::new(
            1,
            AstNodeKind::ClassDeclaration {
                name: "MyClass".to_string(),
                extends: None,
                implements: vec![],
                is_abstract: false,
            },
            create_test_location(),
            "class MyClass { ... }".to_string(),
        );

        let method_node = AstNode::new(
            2,
            AstNodeKind::MethodDeclaration {
                name: "method".to_string(),
                parameters: vec![],
                return_type: None,
                visibility: kodecd_parser::ast::Visibility::Public,
                is_static: false,
                is_async: false,
                is_abstract: false,
            },
            create_test_location(),
            "method() { }".to_string(),
        );
        class_node.add_child(method_node);

        let builder = SymbolTableBuilder::new();
        let table = builder.build(&class_node);

        // Class should be defined
        assert!(table.is_defined("MyClass"));
        let class_symbol = table.lookup("MyClass").unwrap();
        assert_eq!(class_symbol.kind, SymbolKind::Class);
    }

    #[test]
    fn test_builder_block_scope() {
        // Create AST with nested blocks
        let mut outer_block = AstNode::new(
            1,
            AstNodeKind::Block,
            create_test_location(),
            "{ }".to_string(),
        );

        let var1 = AstNode::new(
            2,
            AstNodeKind::VariableDeclaration {
                name: "x".to_string(),
                var_type: None,
                is_const: false,
                initializer: Some("1".to_string()),
            },
            create_test_location(),
            "let x = 1".to_string(),
        );
        outer_block.add_child(var1);

        let mut inner_block = AstNode::new(
            3,
            AstNodeKind::Block,
            create_test_location(),
            "{ }".to_string(),
        );

        let var2 = AstNode::new(
            4,
            AstNodeKind::VariableDeclaration {
                name: "y".to_string(),
                var_type: None,
                is_const: false,
                initializer: None,
            },
            create_test_location(),
            "let y = 2".to_string(),
        );
        inner_block.add_child(var2);
        outer_block.add_child(inner_block);

        let builder = SymbolTableBuilder::new();
        let table = builder.build(&outer_block);

        // Should have multiple scopes (global + outer block + inner block)
        assert!(table.scope_count() >= 3);
    }

    #[test]
    fn test_symbols_of_kind() {
        let mut table = SymbolTable::new();

        // Add various symbols
        table.define("func".to_string(), create_test_symbol("func", SymbolKind::Function, 1, None, 0));
        table.define("var".to_string(), create_test_symbol("var", SymbolKind::Variable, 2, None, 0));
        table.define("const".to_string(), create_test_symbol("const", SymbolKind::Constant, 3, None, 0));

        let functions = table.symbols_of_kind(SymbolKind::Function);
        assert_eq!(functions.len(), 1);
        assert_eq!(functions[0].name, "func");

        let variables = table.symbols_of_kind(SymbolKind::Variable);
        assert_eq!(variables.len(), 1);
        assert_eq!(variables[0].name, "var");
    }

    #[test]
    fn test_reference_tracking() {
        let mut table = SymbolTable::new();

        // Define a variable
        table.define("x".to_string(), create_test_symbol("x", SymbolKind::Variable, 1, Some("number".to_string()), 0));

        // Add references
        assert!(table.add_reference("x", 2));
        assert!(table.add_reference("x", 3));
        assert!(table.add_reference("x", 4));

        // Check references
        let refs = table.get_references("x").unwrap();
        assert_eq!(refs.len(), 3);
        assert_eq!(refs, &[2, 3, 4]);

        // Try to add reference to undefined variable
        assert!(!table.add_reference("undefined", 5));
    }

    #[test]
    fn test_reference_resolution() {
        let mut table = SymbolTable::new();

        // Define in outer scope
        table.define("x".to_string(), create_test_symbol("x", SymbolKind::Variable, 1, Some("string".to_string()), 0));

        // Enter nested scope
        table.enter_scope();

        // Resolve reference from nested scope
        let (symbol, scope_id) = table.resolve_reference("x").unwrap();
        assert_eq!(symbol.name, "x");
        assert_eq!(symbol.type_info, Some("string".to_string()));
        assert_eq!(scope_id, 0); // Defined in global scope

        // Define shadowing variable
        table.define("x".to_string(), create_test_symbol("x", SymbolKind::Variable, 2, Some("number".to_string()), 1));

        // Should now resolve to the shadowing variable
        let (symbol, scope_id) = table.resolve_reference("x").unwrap();
        assert_eq!(symbol.type_info, Some("number".to_string()));
        assert_eq!(scope_id, 1); // Defined in nested scope

        table.exit_scope();

        // Back to outer scope, should resolve to original
        let (symbol, scope_id) = table.resolve_reference("x").unwrap();
        assert_eq!(symbol.type_info, Some("string".to_string()));
        assert_eq!(scope_id, 0);
    }

    #[test]
    fn test_cross_scope_references() {
        let mut table = SymbolTable::new();

        // Define in global scope
        table.define("global_var".to_string(), create_test_symbol("global_var", SymbolKind::Variable, 1, None, 0));

        // Enter function scope
        table.enter_scope();

        // Add reference from function scope
        assert!(table.add_reference("global_var", 10));

        // Enter block scope
        table.enter_scope();

        // Add reference from block scope
        assert!(table.add_reference("global_var", 20));

        // Exit to function scope
        table.exit_scope();

        // Add another reference from function scope
        assert!(table.add_reference("global_var", 30));

        // Exit to global scope
        table.exit_scope();

        // Check all references were tracked
        let refs = table.get_references("global_var").unwrap();
        assert_eq!(refs.len(), 3);
        assert!(refs.contains(&10));
        assert!(refs.contains(&20));
        assert!(refs.contains(&30));
    }
}
