//! Call Graph - Represents function and method call relationships
//!
//! This module provides call graph construction for interprocedural analysis.
//! A call graph shows which functions/methods call which other functions/methods.

use gittera_parser::ast::{AstNode, AstNodeKind};
use std::collections::{HashMap, HashSet};

/// Represents a function or method in the call graph
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct CallGraphNode {
    /// Fully qualified name of the function/method
    pub name: String,
    /// The kind of callable (function, method, etc.)
    pub kind: CallableKind,
    /// AST node ID
    pub node_id: usize,
}

/// The kind of callable entity
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum CallableKind {
    /// Standalone function
    Function,
    /// Method on a class/struct
    Method { class_name: String },
    /// Constructor
    Constructor { class_name: String },
    /// Lambda/closure/anonymous function
    Lambda,
}

/// Represents a call relationship between two functions
#[derive(Debug, Clone)]
pub struct CallEdge {
    /// The function making the call (caller)
    pub from: String,
    /// The function being called (callee)
    pub to: String,
    /// Location in source code where the call occurs
    pub call_site_node_id: usize,
}

/// Call graph representing function/method call relationships
#[derive(Debug, Clone)]
pub struct CallGraph {
    /// All functions/methods in the program
    nodes: HashMap<String, CallGraphNode>,
    /// Call relationships: caller -> list of callees
    edges: HashMap<String, Vec<CallEdge>>,
    /// Reverse edges: callee -> list of callers (for backwards analysis)
    reverse_edges: HashMap<String, Vec<String>>,
}

impl CallGraph {
    /// Create a new empty call graph
    pub fn new() -> Self {
        Self {
            nodes: HashMap::new(),
            edges: HashMap::new(),
            reverse_edges: HashMap::new(),
        }
    }

    /// Add a function/method node to the graph
    pub fn add_node(&mut self, node: CallGraphNode) {
        self.nodes.insert(node.name.clone(), node);
    }

    /// Add a call edge between two functions
    pub fn add_edge(&mut self, edge: CallEdge) {
        // Add to forward edges
        self.edges
            .entry(edge.from.clone())
            .or_insert_with(Vec::new)
            .push(edge.clone());

        // Add to reverse edges
        self.reverse_edges
            .entry(edge.to.clone())
            .or_insert_with(Vec::new)
            .push(edge.from.clone());
    }

    /// Get a node by name
    pub fn get_node(&self, name: &str) -> Option<&CallGraphNode> {
        self.nodes.get(name)
    }

    /// Get all functions called by a given function
    pub fn get_callees(&self, caller: &str) -> Vec<&CallEdge> {
        self.edges
            .get(caller)
            .map(|edges| edges.iter().collect())
            .unwrap_or_default()
    }

    /// Get all functions that call a given function
    pub fn get_callers(&self, callee: &str) -> Vec<&str> {
        self.reverse_edges
            .get(callee)
            .map(|callers| callers.iter().map(|s| s.as_str()).collect())
            .unwrap_or_default()
    }

    /// Get all nodes in the call graph
    pub fn nodes(&self) -> impl Iterator<Item = &CallGraphNode> {
        self.nodes.values()
    }

    /// Get all edges in the call graph
    pub fn edges(&self) -> impl Iterator<Item = &CallEdge> {
        self.edges.values().flatten()
    }

    /// Check if a function exists in the graph
    pub fn contains(&self, name: &str) -> bool {
        self.nodes.contains_key(name)
    }

    /// Get the number of nodes in the call graph
    pub fn node_count(&self) -> usize {
        self.nodes.len()
    }

    /// Get the number of call edges in the call graph
    pub fn edge_count(&self) -> usize {
        self.edges.values().map(|v| v.len()).sum()
    }

    /// Perform topological sort to get call order (useful for bottom-up analysis)
    /// Returns functions in bottom-up order: callees before callers
    /// Returns None if there's a cycle
    pub fn topological_sort(&self) -> Option<Vec<String>> {
        let mut in_degree: HashMap<String, usize> = HashMap::new();
        let mut result = Vec::new();
        let mut queue = Vec::new();

        // Calculate in-degrees
        for node_name in self.nodes.keys() {
            in_degree.insert(node_name.clone(), 0);
        }

        for edges in self.edges.values() {
            for edge in edges {
                *in_degree.entry(edge.to.clone()).or_insert(0) += 1;
            }
        }

        // Find all nodes with in-degree 0
        for (name, &degree) in &in_degree {
            if degree == 0 {
                queue.push(name.clone());
            }
        }

        // Process nodes
        while let Some(node_name) = queue.pop() {
            result.push(node_name.clone());

            if let Some(edges) = self.edges.get(&node_name) {
                for edge in edges {
                    let degree = in_degree.get_mut(&edge.to)?;
                    *degree -= 1;
                    if *degree == 0 {
                        queue.push(edge.to.clone());
                    }
                }
            }
        }

        // If we processed all nodes, no cycle exists
        if result.len() == self.nodes.len() {
            // Reverse for bottom-up order (callees before callers)
            result.reverse();
            Some(result)
        } else {
            None // Cycle detected
        }
    }

    /// Find all reachable functions from a given starting function
    pub fn reachable_from(&self, start: &str) -> HashSet<String> {
        let mut visited = HashSet::new();
        let mut stack = vec![start.to_string()];

        while let Some(node_name) = stack.pop() {
            if visited.contains(&node_name) {
                continue;
            }
            visited.insert(node_name.clone());

            if let Some(edges) = self.edges.get(&node_name) {
                for edge in edges {
                    if !visited.contains(&edge.to) {
                        stack.push(edge.to.clone());
                    }
                }
            }
        }

        visited
    }
}

impl Default for CallGraph {
    fn default() -> Self {
        Self::new()
    }
}

/// Builder for constructing a call graph from an AST
pub struct CallGraphBuilder {
    graph: CallGraph,
    /// Stack of current function context (for nested functions)
    function_stack: Vec<String>,
    /// Current class name (for method resolution)
    current_class: Option<String>,
    /// Counter for generating unique lambda names
    lambda_counter: usize,
}

impl CallGraphBuilder {
    /// Create a new call graph builder
    pub fn new() -> Self {
        Self {
            graph: CallGraph::new(),
            function_stack: Vec::new(),
            current_class: None,
            lambda_counter: 0,
        }
    }

    /// Build a call graph from an AST
    pub fn build(mut self, ast: &AstNode) -> CallGraph {
        self.visit_node(ast);
        self.graph
    }

    /// Visit a node and process it
    fn visit_node(&mut self, node: &AstNode) {
        match &node.kind {
            AstNodeKind::FunctionDeclaration { name, .. } => {
                self.process_function_declaration(name, node);
            }

            AstNodeKind::MethodDeclaration { name, .. } => {
                self.process_method_declaration(name, node);
            }

            AstNodeKind::ClassDeclaration { name, .. } => {
                self.process_class_declaration(name, node);
            }

            AstNodeKind::ArrowFunction { .. } => {
                self.process_arrow_function(node);
            }

            AstNodeKind::CallExpression { callee, .. } => {
                self.process_function_call(callee, node);
                // Still visit children for nested calls
                for child in &node.children {
                    self.visit_node(child);
                }
            }

            AstNodeKind::MemberExpression { object, property, .. } => {
                // Check if this is a method call (has a CallExpression parent or is followed by a call)
                // For now, treat member expressions as potential method calls
                self.process_method_call(object, property, node);
                // Still visit children
                for child in &node.children {
                    self.visit_node(child);
                }
            }

            _ => {
                // Recursively visit children
                for child in &node.children {
                    self.visit_node(child);
                }
            }
        }
    }

    /// Process a function declaration
    fn process_function_declaration(&mut self, name: &str, node: &AstNode) {
        let node_def = CallGraphNode {
            name: name.to_string(),
            kind: CallableKind::Function,
            node_id: node.id,
        };

        self.graph.add_node(node_def);

        // Push function onto stack and visit body
        self.function_stack.push(name.to_string());

        for child in &node.children {
            self.visit_node(child);
        }

        self.function_stack.pop();
    }

    /// Process a method declaration
    fn process_method_declaration(&mut self, name: &str, node: &AstNode) {
        let method_name = if let Some(class_name) = &self.current_class {
            format!("{}.{}", class_name, name)
        } else {
            name.to_string()
        };

        let node_def = CallGraphNode {
            name: method_name.clone(),
            kind: CallableKind::Method {
                class_name: self.current_class.clone().unwrap_or_default(),
            },
            node_id: node.id,
        };

        self.graph.add_node(node_def);

        // Push method onto stack and visit body
        self.function_stack.push(method_name);

        for child in &node.children {
            self.visit_node(child);
        }

        self.function_stack.pop();
    }

    /// Process a class declaration
    fn process_class_declaration(&mut self, name: &str, node: &AstNode) {
        let prev_class = self.current_class.clone();
        self.current_class = Some(name.to_string());

        for child in &node.children {
            self.visit_node(child);
        }

        self.current_class = prev_class;
    }

    /// Process an arrow function (anonymous/lambda)
    fn process_arrow_function(&mut self, node: &AstNode) {
        // Generate synthetic name using node id for uniqueness
        let lambda_name = format!("__arrow_{}", node.id);
        self.lambda_counter += 1;

        let node_def = CallGraphNode {
            name: lambda_name.clone(),
            kind: CallableKind::Lambda,
            node_id: node.id,
        };

        self.graph.add_node(node_def);

        // Push lambda onto stack and visit body
        self.function_stack.push(lambda_name);

        for child in &node.children {
            self.visit_node(child);
        }

        self.function_stack.pop();
    }

    /// Process a function call
    fn process_function_call(&mut self, callee: &str, node: &AstNode) {
        if let Some(caller) = self.function_stack.last() {
            let edge = CallEdge {
                from: caller.clone(),
                to: callee.to_string(),
                call_site_node_id: node.id,
            };

            self.graph.add_edge(edge);
        }
    }

    /// Process a method call
    fn process_method_call(&mut self, object: &str, method: &str, node: &AstNode) {
        if let Some(caller) = self.function_stack.last() {
            // Try to resolve the method call
            // For now, just use "object.method" format
            // TODO: Use symbol table to resolve actual type of object
            let callee = format!("{}.{}", object, method);

            let edge = CallEdge {
                from: caller.clone(),
                to: callee,
                call_site_node_id: node.id,
            };

            self.graph.add_edge(edge);
        }
    }
}

impl Default for CallGraphBuilder {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use gittera_parser::ast::{Location, Span};

    // Helper function to create a test location
    fn test_location() -> Location {
        Location {
            file_path: "test.rs".to_string(),
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

    #[test]
    fn test_call_graph_basic() {
        let mut graph = CallGraph::new();

        let node1 = CallGraphNode {
            name: "main".to_string(),
            kind: CallableKind::Function,
            node_id: 1,
        };
        let node2 = CallGraphNode {
            name: "helper".to_string(),
            kind: CallableKind::Function,
            node_id: 2,
        };

        graph.add_node(node1);
        graph.add_node(node2);

        let edge = CallEdge {
            from: "main".to_string(),
            to: "helper".to_string(),
            call_site_node_id: 3,
        };

        graph.add_edge(edge);

        assert_eq!(graph.node_count(), 2);
        assert_eq!(graph.edge_count(), 1);
        assert!(graph.contains("main"));
        assert!(graph.contains("helper"));

        let callees = graph.get_callees("main");
        assert_eq!(callees.len(), 1);
        assert_eq!(callees[0].to, "helper");

        let callers = graph.get_callers("helper");
        assert_eq!(callers.len(), 1);
        assert_eq!(callers[0], "main");
    }

    #[test]
    fn test_reachable_from() {
        let mut graph = CallGraph::new();

        graph.add_node(CallGraphNode {
            name: "a".to_string(),
            kind: CallableKind::Function,
            node_id: 1,
        });
        graph.add_node(CallGraphNode {
            name: "b".to_string(),
            kind: CallableKind::Function,
            node_id: 2,
        });
        graph.add_node(CallGraphNode {
            name: "c".to_string(),
            kind: CallableKind::Function,
            node_id: 3,
        });
        graph.add_node(CallGraphNode {
            name: "d".to_string(),
            kind: CallableKind::Function,
            node_id: 4,
        });

        graph.add_edge(CallEdge {
            from: "a".to_string(),
            to: "b".to_string(),
            call_site_node_id: 10,
        });
        graph.add_edge(CallEdge {
            from: "b".to_string(),
            to: "c".to_string(),
            call_site_node_id: 11,
        });

        let reachable = graph.reachable_from("a");
        assert!(reachable.contains("a"));
        assert!(reachable.contains("b"));
        assert!(reachable.contains("c"));
        assert!(!reachable.contains("d"));
    }

    #[test]
    fn test_topological_sort() {
        let mut graph = CallGraph::new();

        // Create a simple call chain: main -> foo -> bar
        graph.add_node(CallGraphNode {
            name: "main".to_string(),
            kind: CallableKind::Function,
            node_id: 1,
        });
        graph.add_node(CallGraphNode {
            name: "foo".to_string(),
            kind: CallableKind::Function,
            node_id: 2,
        });
        graph.add_node(CallGraphNode {
            name: "bar".to_string(),
            kind: CallableKind::Function,
            node_id: 3,
        });

        graph.add_edge(CallEdge {
            from: "main".to_string(),
            to: "foo".to_string(),
            call_site_node_id: 10,
        });
        graph.add_edge(CallEdge {
            from: "foo".to_string(),
            to: "bar".to_string(),
            call_site_node_id: 11,
        });

        let sorted = graph.topological_sort();
        assert!(sorted.is_some());
        let sorted = sorted.unwrap();

        // Topological sort now returns bottom-up order (callees before callers)
        // So for main -> foo -> bar, we get [bar, foo, main]
        let bar_pos = sorted.iter().position(|s| s == "bar").unwrap();
        let foo_pos = sorted.iter().position(|s| s == "foo").unwrap();
        let main_pos = sorted.iter().position(|s| s == "main").unwrap();

        // Callees should be processed before callers for bottom-up analysis
        assert!(bar_pos < foo_pos);
        assert!(foo_pos < main_pos);
    }

    #[test]
    fn test_builder_simple() {
        // Create a simple AST: main() calls helper()
        let helper_call = AstNode::new(
            1,
            AstNodeKind::CallExpression {
                callee: "helper".to_string(),
                arguments_count: 0,
                is_optional_chain: false,
            },
            test_location(),
            "helper()".to_string(),
        );

        let main_func = AstNode {
            id: 2,
            kind: AstNodeKind::FunctionDeclaration {
                name: "main".to_string(),
                parameters: vec![],
                return_type: None,
                is_async: false,
                is_generator: false,
            },
            location: test_location(),
            children: vec![helper_call],
            text: "fn main() { helper(); }".to_string(),
        };

        let helper_func = AstNode::new(
            3,
            AstNodeKind::FunctionDeclaration {
                name: "helper".to_string(),
                parameters: vec![],
                return_type: None,
                is_async: false,
                is_generator: false,
            },
            test_location(),
            "fn helper() {}".to_string(),
        );

        let program = AstNode {
            id: 0,
            kind: AstNodeKind::Program,
            location: test_location(),
            children: vec![main_func, helper_func],
            text: "program".to_string(),
        };

        let builder = CallGraphBuilder::new();
        let graph = builder.build(&program);

        assert_eq!(graph.node_count(), 2);
        assert!(graph.contains("main"));
        assert!(graph.contains("helper"));

        let callees = graph.get_callees("main");
        assert_eq!(callees.len(), 1);
        assert_eq!(callees[0].to, "helper");
    }

    #[test]
    fn test_builder_with_methods() {
        // Create AST: class Foo { method bar() calls baz() }
        let baz_call = AstNode::new(
            1,
            AstNodeKind::CallExpression {
                callee: "baz".to_string(),
                arguments_count: 0,
                is_optional_chain: false,
            },
            test_location(),
            "baz()".to_string(),
        );

        let bar_method = AstNode {
            id: 2,
            kind: AstNodeKind::MethodDeclaration {
                name: "bar".to_string(),
                parameters: vec![],
                return_type: None,
                visibility: gittera_parser::ast::Visibility::Public,
                is_static: false,
                is_async: false,
                is_abstract: false,
            },
            location: test_location(),
            children: vec![baz_call],
            text: "bar() { baz(); }".to_string(),
        };

        let foo_class = AstNode {
            id: 3,
            kind: AstNodeKind::ClassDeclaration {
                name: "Foo".to_string(),
                extends: None,
                implements: vec![],
                is_abstract: false,
            },
            location: test_location(),
            children: vec![bar_method],
            text: "class Foo {}".to_string(),
        };

        let baz_func = AstNode::new(
            4,
            AstNodeKind::FunctionDeclaration {
                name: "baz".to_string(),
                parameters: vec![],
                return_type: None,
                is_async: false,
                is_generator: false,
            },
            test_location(),
            "fn baz() {}".to_string(),
        );

        let program = AstNode {
            id: 0,
            kind: AstNodeKind::Program,
            location: test_location(),
            children: vec![foo_class, baz_func],
            text: "program".to_string(),
        };

        let builder = CallGraphBuilder::new();
        let graph = builder.build(&program);

        assert_eq!(graph.node_count(), 2);
        assert!(graph.contains("Foo.bar"));
        assert!(graph.contains("baz"));

        let callees = graph.get_callees("Foo.bar");
        assert_eq!(callees.len(), 1);
        assert_eq!(callees[0].to, "baz");
    }

    #[test]
    fn test_builder_nested_calls() {
        // Create AST: main() calls foo() and bar(), foo() calls baz()
        let baz_call = AstNode::new(
            1,
            AstNodeKind::CallExpression {
                callee: "baz".to_string(),
                arguments_count: 0,
                is_optional_chain: false,
            },
            test_location(),
            "baz()".to_string(),
        );

        let foo_func = AstNode {
            id: 2,
            kind: AstNodeKind::FunctionDeclaration {
                name: "foo".to_string(),
                parameters: vec![],
                return_type: None,
                is_async: false,
                is_generator: false,
            },
            location: test_location(),
            children: vec![baz_call],
            text: "fn foo() { baz(); }".to_string(),
        };

        let foo_call = AstNode::new(
            3,
            AstNodeKind::CallExpression {
                callee: "foo".to_string(),
                arguments_count: 0,
                is_optional_chain: false,
            },
            test_location(),
            "foo()".to_string(),
        );

        let bar_call = AstNode::new(
            4,
            AstNodeKind::CallExpression {
                callee: "bar".to_string(),
                arguments_count: 0,
                is_optional_chain: false,
            },
            test_location(),
            "bar()".to_string(),
        );

        let main_func = AstNode {
            id: 5,
            kind: AstNodeKind::FunctionDeclaration {
                name: "main".to_string(),
                parameters: vec![],
                return_type: None,
                is_async: false,
                is_generator: false,
            },
            location: test_location(),
            children: vec![foo_call, bar_call],
            text: "fn main() { foo(); bar(); }".to_string(),
        };

        let bar_func = AstNode::new(
            6,
            AstNodeKind::FunctionDeclaration {
                name: "bar".to_string(),
                parameters: vec![],
                return_type: None,
                is_async: false,
                is_generator: false,
            },
            test_location(),
            "fn bar() {}".to_string(),
        );

        let baz_func = AstNode::new(
            7,
            AstNodeKind::FunctionDeclaration {
                name: "baz".to_string(),
                parameters: vec![],
                return_type: None,
                is_async: false,
                is_generator: false,
            },
            test_location(),
            "fn baz() {}".to_string(),
        );

        let program = AstNode {
            id: 0,
            kind: AstNodeKind::Program,
            location: test_location(),
            children: vec![main_func, foo_func, bar_func, baz_func],
            text: "program".to_string(),
        };

        let builder = CallGraphBuilder::new();
        let graph = builder.build(&program);

        assert_eq!(graph.node_count(), 4);

        let main_callees = graph.get_callees("main");
        assert_eq!(main_callees.len(), 2);

        let foo_callees = graph.get_callees("foo");
        assert_eq!(foo_callees.len(), 1);
        assert_eq!(foo_callees[0].to, "baz");

        // Check reachability from main
        let reachable = graph.reachable_from("main");
        assert_eq!(reachable.len(), 4); // main, foo, bar, baz
    }
}
