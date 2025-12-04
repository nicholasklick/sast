//! Type system integration for enhanced static analysis
//!
//! This module provides type information extraction and type-aware analysis
//! capabilities to improve the precision of taint analysis and points-to analysis.
//!
//! ## Overview
//!
//! The type system integration allows analyses to:
//! - Filter taint propagation based on type compatibility
//! - Refine points-to sets using type information
//! - Distinguish safe types (primitives) from potentially unsafe types (objects, arrays)
//! - Track type narrowing through type guards and assertions
//!
//! ## Example
//!
//! ```rust
//! use gittera_analyzer::type_system::{TypeInfo, TypeContext, TypeCategory};
//! use gittera_parser::ast::{AstNode, AstNodeKind, Location, Span};
//!
//! // Create a simple AST
//! let ast = AstNode::new(0, AstNodeKind::Program,
//!     Location { file_path: "test.ts".to_string(),
//!                span: Span { start_line: 1, start_column: 0,
//!                             end_line: 1, end_column: 10,
//!                             start_byte: 0, end_byte: 10 } },
//!     String::new());
//!
//! // Build type context from AST
//! let type_ctx = TypeContext::from_ast(&ast);
//!
//! // Query type information
//! if let Some(type_info) = type_ctx.get_variable_type("userInput") {
//!     // Check if this could carry tainted data
//!     if type_info.can_carry_taint() {
//!         // Apply taint analysis
//!     }
//! }
//! ```

use gittera_parser::ast::{AstNode, AstNodeKind, NodeId};
use std::collections::HashMap;

/// Represents the category of a type for analysis purposes
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum TypeCategory {
    /// Primitive types (number, boolean, null, undefined) - cannot carry object references
    Primitive,
    /// String type - can carry tainted data but not object references
    String,
    /// Array type - can contain references and tainted data
    Array,
    /// Object type - can contain references and tainted data
    Object,
    /// Function type - can be called, may return tainted data
    Function,
    /// Union type - could be any of several types
    Union(Vec<TypeCategory>),
    /// Unknown type - must be treated conservatively
    Unknown,
    /// Void/Never - cannot carry data
    Void,
    /// Any/unknown in TypeScript - could be anything
    Any,
}

impl TypeCategory {
    /// Check if this type category can carry tainted string data
    pub fn can_carry_taint(&self) -> bool {
        match self {
            TypeCategory::Primitive => false, // numbers/booleans can't be tainted strings
            TypeCategory::String => true,
            TypeCategory::Array => true,  // arrays can contain tainted strings
            TypeCategory::Object => true, // objects can have tainted string properties
            TypeCategory::Function => false, // functions themselves aren't tainted
            TypeCategory::Union(types) => types.iter().any(|t| t.can_carry_taint()),
            TypeCategory::Unknown => true, // conservative: assume yes
            TypeCategory::Void => false,
            TypeCategory::Any => true, // conservative: assume yes
        }
    }

    /// Check if this type can hold object references (for points-to analysis)
    pub fn can_hold_reference(&self) -> bool {
        match self {
            TypeCategory::Primitive => false,
            TypeCategory::String => false, // strings are immutable values
            TypeCategory::Array => true,
            TypeCategory::Object => true,
            TypeCategory::Function => true, // functions are objects
            TypeCategory::Union(types) => types.iter().any(|t| t.can_hold_reference()),
            TypeCategory::Unknown => true,
            TypeCategory::Void => false,
            TypeCategory::Any => true,
        }
    }

    /// Check if two type categories could be compatible (for assignment/aliasing)
    pub fn is_compatible_with(&self, other: &TypeCategory) -> bool {
        match (self, other) {
            // Same category is always compatible
            (a, b) if a == b => true,

            // Any/Unknown is compatible with everything
            (TypeCategory::Any, _) | (_, TypeCategory::Any) => true,
            (TypeCategory::Unknown, _) | (_, TypeCategory::Unknown) => true,

            // Void is only compatible with void
            (TypeCategory::Void, TypeCategory::Void) => true,
            (TypeCategory::Void, _) | (_, TypeCategory::Void) => false,

            // Union types check any member
            (TypeCategory::Union(types), other) => {
                types.iter().any(|t| t.is_compatible_with(other))
            }
            (other, TypeCategory::Union(types)) => {
                types.iter().any(|t| other.is_compatible_with(t))
            }

            // Different concrete types are incompatible
            _ => false,
        }
    }
}

/// Detailed type information for a symbol
#[derive(Debug, Clone)]
pub struct TypeInfo {
    /// The raw type string from the source (e.g., "string", "number[]", "User")
    pub type_string: Option<String>,
    /// The inferred category for analysis
    pub category: TypeCategory,
    /// Whether this type is nullable (includes null or undefined)
    pub is_nullable: bool,
    /// Whether this type is a promise (async return)
    pub is_promise: bool,
    /// Generic type arguments if any (e.g., Array<string> -> ["string"])
    pub type_arguments: Vec<String>,
    /// For function types: parameter types
    pub parameter_types: Vec<TypeInfo>,
    /// For function types: return type
    pub return_type: Option<Box<TypeInfo>>,
}

impl TypeInfo {
    /// Create a new TypeInfo with unknown type
    pub fn unknown() -> Self {
        Self {
            type_string: None,
            category: TypeCategory::Unknown,
            is_nullable: true,
            is_promise: false,
            type_arguments: Vec::new(),
            parameter_types: Vec::new(),
            return_type: None,
        }
    }

    /// Create TypeInfo from a type string
    pub fn from_type_string(type_str: &str) -> Self {
        let type_str = type_str.trim();
        let category = Self::categorize_type(type_str);
        let is_nullable = type_str.contains("null")
            || type_str.contains("undefined")
            || type_str.contains('?');
        let is_promise = type_str.starts_with("Promise<") || type_str.contains("Promise<");

        // Extract generic type arguments
        let type_arguments = Self::extract_type_arguments(type_str);

        Self {
            type_string: Some(type_str.to_string()),
            category,
            is_nullable,
            is_promise,
            type_arguments,
            parameter_types: Vec::new(),
            return_type: None,
        }
    }

    /// Categorize a type string into a TypeCategory
    fn categorize_type(type_str: &str) -> TypeCategory {
        let type_str = type_str.trim().to_lowercase();

        // Handle union types
        if type_str.contains(" | ") {
            let parts: Vec<&str> = type_str.split(" | ").collect();
            let categories: Vec<TypeCategory> = parts
                .iter()
                .map(|p| Self::categorize_type(p))
                .collect();
            return TypeCategory::Union(categories);
        }

        // Handle array types
        if type_str.ends_with("[]") || type_str.starts_with("array<") {
            return TypeCategory::Array;
        }

        // Handle primitives
        match type_str.as_str() {
            "number" | "int" | "float" | "double" | "i32" | "i64" | "u32" | "u64"
            | "boolean" | "bool" | "true" | "false" => TypeCategory::Primitive,

            "string" | "str" | "&str" => TypeCategory::String,

            "void" | "never" | "()" | "unit" => TypeCategory::Void,

            "any" | "unknown" => TypeCategory::Any,

            "null" | "undefined" | "nil" => TypeCategory::Void,

            "object" | "record" | "map" => TypeCategory::Object,

            "function" => TypeCategory::Function,

            // Check for function signatures
            _ if type_str.contains("=>") || type_str.starts_with("(") => TypeCategory::Function,

            // Check for object literal types
            _ if type_str.starts_with("{") => TypeCategory::Object,

            // Default to Object for custom types (User, Config, etc.)
            _ => TypeCategory::Object,
        }
    }

    /// Extract generic type arguments from a type string
    fn extract_type_arguments(type_str: &str) -> Vec<String> {
        let mut args = Vec::new();

        if let Some(start) = type_str.find('<') {
            if let Some(end) = type_str.rfind('>') {
                let inner = &type_str[start + 1..end];
                // Simple split by comma (doesn't handle nested generics perfectly)
                for arg in inner.split(',') {
                    args.push(arg.trim().to_string());
                }
            }
        }

        args
    }

    /// Check if this type can carry tainted data
    pub fn can_carry_taint(&self) -> bool {
        self.category.can_carry_taint()
    }

    /// Check if this type can hold object references
    pub fn can_hold_reference(&self) -> bool {
        self.category.can_hold_reference()
    }

    /// Create a primitive type info
    pub fn primitive() -> Self {
        Self {
            type_string: Some("number".to_string()),
            category: TypeCategory::Primitive,
            is_nullable: false,
            is_promise: false,
            type_arguments: Vec::new(),
            parameter_types: Vec::new(),
            return_type: None,
        }
    }

    /// Create a string type info
    pub fn string() -> Self {
        Self {
            type_string: Some("string".to_string()),
            category: TypeCategory::String,
            is_nullable: false,
            is_promise: false,
            type_arguments: Vec::new(),
            parameter_types: Vec::new(),
            return_type: None,
        }
    }

    /// Create an object type info
    pub fn object() -> Self {
        Self {
            type_string: Some("object".to_string()),
            category: TypeCategory::Object,
            is_nullable: false,
            is_promise: false,
            type_arguments: Vec::new(),
            parameter_types: Vec::new(),
            return_type: None,
        }
    }
}

impl Default for TypeInfo {
    fn default() -> Self {
        Self::unknown()
    }
}

/// Context for type information across the program
#[derive(Debug, Default)]
pub struct TypeContext {
    /// Variable name to type mapping
    variable_types: HashMap<String, TypeInfo>,
    /// Function name to return type mapping
    function_return_types: HashMap<String, TypeInfo>,
    /// Function name to parameter types mapping
    function_param_types: HashMap<String, Vec<TypeInfo>>,
    /// Class/interface names and their field types
    class_field_types: HashMap<String, HashMap<String, TypeInfo>>,
    /// Node ID to type info for precise tracking
    node_types: HashMap<NodeId, TypeInfo>,
}

impl TypeContext {
    /// Create a new empty type context
    pub fn new() -> Self {
        Self::default()
    }

    /// Build type context from an AST
    pub fn from_ast(ast: &AstNode) -> Self {
        let mut ctx = Self::new();
        ctx.collect_types(ast);
        ctx
    }

    /// Get the type of a variable by name
    pub fn get_variable_type(&self, name: &str) -> Option<&TypeInfo> {
        self.variable_types.get(name)
    }

    /// Get the return type of a function
    pub fn get_function_return_type(&self, name: &str) -> Option<&TypeInfo> {
        self.function_return_types.get(name)
    }

    /// Get the parameter types of a function
    pub fn get_function_param_types(&self, name: &str) -> Option<&Vec<TypeInfo>> {
        self.function_param_types.get(name)
    }

    /// Get a field type from a class
    pub fn get_field_type(&self, class_name: &str, field_name: &str) -> Option<&TypeInfo> {
        self.class_field_types
            .get(class_name)
            .and_then(|fields| fields.get(field_name))
    }

    /// Get type info for a specific AST node
    pub fn get_node_type(&self, node_id: NodeId) -> Option<&TypeInfo> {
        self.node_types.get(&node_id)
    }

    /// Check if two variables could be aliased based on type compatibility
    pub fn could_alias(&self, var1: &str, var2: &str) -> bool {
        match (self.get_variable_type(var1), self.get_variable_type(var2)) {
            (Some(t1), Some(t2)) => {
                // Must both be reference types and compatible
                t1.can_hold_reference()
                    && t2.can_hold_reference()
                    && t1.category.is_compatible_with(&t2.category)
            }
            // Unknown types - be conservative
            _ => true,
        }
    }

    /// Check if taint can propagate from one variable to another based on types
    pub fn can_propagate_taint(&self, from: &str, to: &str) -> bool {
        let from_type = self.get_variable_type(from);
        let to_type = self.get_variable_type(to);

        match (from_type, to_type) {
            (Some(ft), Some(tt)) => {
                // Source must be able to carry taint
                // Target must be able to receive taint
                ft.can_carry_taint() && tt.can_carry_taint()
            }
            // Unknown types - be conservative
            _ => true,
        }
    }

    /// Set the type for a variable
    pub fn set_variable_type(&mut self, name: String, type_info: TypeInfo) {
        self.variable_types.insert(name, type_info);
    }

    /// Set the return type for a function
    pub fn set_function_return_type(&mut self, name: String, type_info: TypeInfo) {
        self.function_return_types.insert(name, type_info);
    }

    /// Collect type information from the AST
    fn collect_types(&mut self, node: &AstNode) {
        match &node.kind {
            AstNodeKind::VariableDeclaration { name, var_type, .. } => {
                let type_info = var_type
                    .as_ref()
                    .map(|t| TypeInfo::from_type_string(t))
                    .unwrap_or_else(|| self.infer_type_from_initializer(node));

                self.variable_types.insert(name.clone(), type_info.clone());
                self.node_types.insert(node.id, type_info);
            }

            AstNodeKind::FunctionDeclaration {
                name,
                parameters,
                return_type,
                ..
            } => {
                // Record return type
                let ret_type = return_type
                    .as_ref()
                    .map(|t| TypeInfo::from_type_string(t))
                    .unwrap_or_else(TypeInfo::unknown);
                self.function_return_types.insert(name.clone(), ret_type.clone());

                // Record parameter types
                let param_types: Vec<TypeInfo> = parameters
                    .iter()
                    .map(|p| {
                        p.param_type
                            .as_ref()
                            .map(|t| TypeInfo::from_type_string(t))
                            .unwrap_or_else(TypeInfo::unknown)
                    })
                    .collect();
                self.function_param_types.insert(name.clone(), param_types.clone());

                // Also add parameters as variables in scope
                for param in parameters {
                    let type_info = param
                        .param_type
                        .as_ref()
                        .map(|t| TypeInfo::from_type_string(t))
                        .unwrap_or_else(TypeInfo::unknown);
                    self.variable_types.insert(param.name.clone(), type_info);
                }
            }

            AstNodeKind::MethodDeclaration {
                name,
                parameters,
                return_type,
                ..
            } => {
                let ret_type = return_type
                    .as_ref()
                    .map(|t| TypeInfo::from_type_string(t))
                    .unwrap_or_else(TypeInfo::unknown);
                self.function_return_types.insert(name.clone(), ret_type);

                let param_types: Vec<TypeInfo> = parameters
                    .iter()
                    .map(|p| {
                        p.param_type
                            .as_ref()
                            .map(|t| TypeInfo::from_type_string(t))
                            .unwrap_or_else(TypeInfo::unknown)
                    })
                    .collect();
                self.function_param_types.insert(name.clone(), param_types);
            }

            AstNodeKind::ArrowFunction {
                parameters,
                return_type,
                ..
            } => {
                // Arrow functions: add parameters to variable types
                for param in parameters {
                    let type_info = param
                        .param_type
                        .as_ref()
                        .map(|t| TypeInfo::from_type_string(t))
                        .unwrap_or_else(TypeInfo::unknown);
                    self.variable_types.insert(param.name.clone(), type_info);
                }

                // Store return type on the node itself
                if let Some(ret) = return_type {
                    self.node_types.insert(node.id, TypeInfo::from_type_string(ret));
                }
            }

            AstNodeKind::ClassDeclaration { name, .. } => {
                // Collect field types from children
                let mut fields = HashMap::new();
                for child in &node.children {
                    if let AstNodeKind::FieldDeclaration {
                        name: field_name,
                        field_type,
                        ..
                    } = &child.kind
                    {
                        let type_info = field_type
                            .as_ref()
                            .map(|t| TypeInfo::from_type_string(t))
                            .unwrap_or_else(TypeInfo::unknown);
                        fields.insert(field_name.clone(), type_info);
                    }
                }
                self.class_field_types.insert(name.clone(), fields);
            }

            AstNodeKind::FieldDeclaration {
                name, field_type, ..
            } => {
                let type_info = field_type
                    .as_ref()
                    .map(|t| TypeInfo::from_type_string(t))
                    .unwrap_or_else(TypeInfo::unknown);
                self.node_types.insert(node.id, type_info.clone());
                // Also add as variable for simpler lookup
                self.variable_types.insert(name.clone(), type_info);
            }

            AstNodeKind::TypeAnnotation { type_string } => {
                self.node_types
                    .insert(node.id, TypeInfo::from_type_string(type_string));
            }

            AstNodeKind::AsExpression { type_string } => {
                // Type assertion: record the asserted type
                self.node_types
                    .insert(node.id, TypeInfo::from_type_string(type_string));
            }

            AstNodeKind::Identifier { name } => {
                // Look up and cache the type
                if let Some(type_info) = self.variable_types.get(name).cloned() {
                    self.node_types.insert(node.id, type_info);
                }
            }

            AstNodeKind::CallExpression { callee, .. } => {
                // Record the return type of the call
                if let Some(ret_type) = self.function_return_types.get(callee).cloned() {
                    self.node_types.insert(node.id, ret_type);
                }
            }

            AstNodeKind::Literal { value } => {
                // Literals have known types
                use gittera_parser::ast::LiteralValue;
                let type_info = match value {
                    LiteralValue::String(_) => TypeInfo::string(),
                    LiteralValue::Number(_) => TypeInfo::primitive(),
                    LiteralValue::Boolean(_) => TypeInfo::primitive(),
                    LiteralValue::Null | LiteralValue::Undefined => TypeInfo {
                        type_string: Some("null".to_string()),
                        category: TypeCategory::Void,
                        is_nullable: true,
                        is_promise: false,
                        type_arguments: Vec::new(),
                        parameter_types: Vec::new(),
                        return_type: None,
                    },
                };
                self.node_types.insert(node.id, type_info);
            }

            AstNodeKind::ObjectExpression { .. } => {
                self.node_types.insert(node.id, TypeInfo::object());
            }

            AstNodeKind::ArrayExpression { .. } => {
                self.node_types.insert(node.id, TypeInfo {
                    type_string: Some("array".to_string()),
                    category: TypeCategory::Array,
                    is_nullable: false,
                    is_promise: false,
                    type_arguments: Vec::new(),
                    parameter_types: Vec::new(),
                    return_type: None,
                });
            }

            _ => {}
        }

        // Recurse into children
        for child in &node.children {
            self.collect_types(child);
        }
    }

    /// Infer type from initializer expression
    fn infer_type_from_initializer(&self, node: &AstNode) -> TypeInfo {
        // Check first child (initializer)
        if let Some(init) = node.children.first() {
            match &init.kind {
                AstNodeKind::Literal { value } => {
                    use gittera_parser::ast::LiteralValue;
                    match value {
                        LiteralValue::String(_) => return TypeInfo::string(),
                        LiteralValue::Number(_) => return TypeInfo::primitive(),
                        LiteralValue::Boolean(_) => return TypeInfo::primitive(),
                        _ => {}
                    }
                }
                AstNodeKind::ObjectExpression { .. } => return TypeInfo::object(),
                AstNodeKind::ArrayExpression { .. } => {
                    return TypeInfo {
                        type_string: Some("array".to_string()),
                        category: TypeCategory::Array,
                        is_nullable: false,
                        is_promise: false,
                        type_arguments: Vec::new(),
                        parameter_types: Vec::new(),
                        return_type: None,
                    }
                }
                AstNodeKind::CallExpression { callee, .. } => {
                    // Try to get return type of the called function
                    if let Some(ret_type) = self.function_return_types.get(callee) {
                        return ret_type.clone();
                    }
                }
                AstNodeKind::Identifier { name } => {
                    // Copy type from source variable
                    if let Some(type_info) = self.variable_types.get(name) {
                        return type_info.clone();
                    }
                }
                _ => {}
            }
        }
        TypeInfo::unknown()
    }

    /// Get statistics about type coverage
    pub fn stats(&self) -> TypeContextStats {
        let typed_vars = self
            .variable_types
            .values()
            .filter(|t| t.type_string.is_some())
            .count();

        TypeContextStats {
            total_variables: self.variable_types.len(),
            typed_variables: typed_vars,
            total_functions: self.function_return_types.len(),
            typed_functions: self
                .function_return_types
                .values()
                .filter(|t| t.type_string.is_some())
                .count(),
            total_classes: self.class_field_types.len(),
        }
    }
}

/// Statistics about type coverage
#[derive(Debug, Clone)]
pub struct TypeContextStats {
    pub total_variables: usize,
    pub typed_variables: usize,
    pub total_functions: usize,
    pub typed_functions: usize,
    pub total_classes: usize,
}

impl TypeContextStats {
    /// Calculate the percentage of variables with explicit types
    pub fn variable_coverage(&self) -> f64 {
        if self.total_variables == 0 {
            0.0
        } else {
            self.typed_variables as f64 / self.total_variables as f64 * 100.0
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use gittera_parser::ast::{Location, Span, Parameter};

    fn test_location() -> Location {
        Location {
            file_path: "test.ts".to_string(),
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
    fn test_type_category_from_string() {
        assert_eq!(
            TypeInfo::from_type_string("number").category,
            TypeCategory::Primitive
        );
        assert_eq!(
            TypeInfo::from_type_string("string").category,
            TypeCategory::String
        );
        assert_eq!(
            TypeInfo::from_type_string("boolean").category,
            TypeCategory::Primitive
        );
        assert_eq!(
            TypeInfo::from_type_string("string[]").category,
            TypeCategory::Array
        );
        assert_eq!(
            TypeInfo::from_type_string("Array<number>").category,
            TypeCategory::Array
        );
        assert_eq!(
            TypeInfo::from_type_string("object").category,
            TypeCategory::Object
        );
        assert_eq!(
            TypeInfo::from_type_string("void").category,
            TypeCategory::Void
        );
        assert_eq!(
            TypeInfo::from_type_string("any").category,
            TypeCategory::Any
        );
        assert_eq!(
            TypeInfo::from_type_string("User").category,
            TypeCategory::Object
        );
    }

    #[test]
    fn test_union_types() {
        let type_info = TypeInfo::from_type_string("string | number");
        assert!(matches!(type_info.category, TypeCategory::Union(_)));
        assert!(type_info.can_carry_taint()); // string can carry taint
    }

    #[test]
    fn test_nullable_detection() {
        assert!(TypeInfo::from_type_string("string | null").is_nullable);
        assert!(TypeInfo::from_type_string("string | undefined").is_nullable);
        assert!(TypeInfo::from_type_string("string?").is_nullable);
        assert!(!TypeInfo::from_type_string("string").is_nullable);
    }

    #[test]
    fn test_promise_detection() {
        assert!(TypeInfo::from_type_string("Promise<string>").is_promise);
        assert!(!TypeInfo::from_type_string("string").is_promise);
    }

    #[test]
    fn test_type_arguments() {
        let type_info = TypeInfo::from_type_string("Map<string, number>");
        assert_eq!(type_info.type_arguments, vec!["string", "number"]);
    }

    #[test]
    fn test_can_carry_taint() {
        assert!(TypeInfo::string().can_carry_taint());
        assert!(TypeInfo::object().can_carry_taint());
        assert!(!TypeInfo::primitive().can_carry_taint());
    }

    #[test]
    fn test_can_hold_reference() {
        assert!(TypeInfo::object().can_hold_reference());
        assert!(!TypeInfo::primitive().can_hold_reference());
        assert!(!TypeInfo::string().can_hold_reference());
    }

    #[test]
    fn test_type_compatibility() {
        assert!(TypeCategory::Object.is_compatible_with(&TypeCategory::Object));
        assert!(TypeCategory::Any.is_compatible_with(&TypeCategory::String));
        assert!(!TypeCategory::String.is_compatible_with(&TypeCategory::Primitive));
    }

    #[test]
    fn test_type_context_from_ast() {
        // Create a simple AST with typed variable
        let mut program = AstNode::new(0, AstNodeKind::Program, test_location(), String::new());

        let var_decl = AstNode::new(
            1,
            AstNodeKind::VariableDeclaration {
                name: "userName".to_string(),
                var_type: Some("string".to_string()),
                is_const: true,
                initializer: None,
            },
            test_location(),
            "const userName: string".to_string(),
        );

        program.add_child(var_decl);

        let ctx = TypeContext::from_ast(&program);

        let type_info = ctx.get_variable_type("userName");
        assert!(type_info.is_some());
        assert_eq!(type_info.unwrap().category, TypeCategory::String);
    }

    #[test]
    fn test_type_context_function_types() {
        let mut program = AstNode::new(0, AstNodeKind::Program, test_location(), String::new());

        let func_decl = AstNode::new(
            1,
            AstNodeKind::FunctionDeclaration {
                name: "getUser".to_string(),
                parameters: vec![Parameter {
                    name: "id".to_string(),
                    param_type: Some("number".to_string()),
                    default_value: None,
                    is_optional: false,
                    is_rest: false,
                }],
                return_type: Some("User".to_string()),
                is_async: false,
                is_generator: false,
            },
            test_location(),
            "function getUser(id: number): User".to_string(),
        );

        program.add_child(func_decl);

        let ctx = TypeContext::from_ast(&program);

        // Check return type
        let ret_type = ctx.get_function_return_type("getUser");
        assert!(ret_type.is_some());
        assert_eq!(ret_type.unwrap().category, TypeCategory::Object);

        // Check parameter types
        let param_types = ctx.get_function_param_types("getUser");
        assert!(param_types.is_some());
        assert_eq!(param_types.unwrap().len(), 1);
        assert_eq!(param_types.unwrap()[0].category, TypeCategory::Primitive);
    }

    #[test]
    fn test_could_alias() {
        let mut ctx = TypeContext::new();
        ctx.set_variable_type("obj1".to_string(), TypeInfo::object());
        ctx.set_variable_type("obj2".to_string(), TypeInfo::object());
        ctx.set_variable_type("num".to_string(), TypeInfo::primitive());

        // Objects can alias each other
        assert!(ctx.could_alias("obj1", "obj2"));

        // Primitive cannot alias with object
        assert!(!ctx.could_alias("num", "obj1"));

        // Unknown variables conservatively assumed to alias
        assert!(ctx.could_alias("unknown1", "unknown2"));
    }

    #[test]
    fn test_can_propagate_taint() {
        let mut ctx = TypeContext::new();
        ctx.set_variable_type("userInput".to_string(), TypeInfo::string());
        ctx.set_variable_type("count".to_string(), TypeInfo::primitive());
        ctx.set_variable_type("data".to_string(), TypeInfo::object());

        // String -> Object can propagate (object can hold strings)
        assert!(ctx.can_propagate_taint("userInput", "data"));

        // String -> Primitive cannot propagate (primitive can't hold tainted data)
        assert!(!ctx.can_propagate_taint("userInput", "count"));
    }
}
