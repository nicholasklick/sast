//! Abstract Syntax Tree representation
//!
//! Language-agnostic AST nodes that can represent code from any supported language.

use serde::{Deserialize, Serialize};
use std::fmt;

/// Unique identifier for AST nodes
pub type NodeId = usize;

/// Represents a function/method parameter
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Parameter {
    pub name: String,
    pub param_type: Option<String>,
    pub default_value: Option<String>,
    pub is_optional: bool,
    pub is_rest: bool,  // ...args
}

/// Represents an import specifier (import { X as Y } from 'module')
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ImportSpecifier {
    pub imported: String,  // Original name in module
    pub local: String,     // Local name in current file
    pub is_namespace: bool, // import * as X
    pub is_default: bool,   // import X
}

/// Represents a location in source code
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Location {
    pub file_path: String,
    pub span: Span,
}

/// Represents a span (range) in source code
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct Span {
    pub start_line: usize,
    pub start_column: usize,
    pub end_line: usize,
    pub end_column: usize,
    pub start_byte: usize,
    pub end_byte: usize,
}

impl Span {
    pub fn contains(&self, other: &Span) -> bool {
        self.start_byte <= other.start_byte && self.end_byte >= other.end_byte
    }

    pub fn overlaps(&self, other: &Span) -> bool {
        self.start_byte <= other.end_byte && self.end_byte >= other.start_byte
    }
}

/// An AST node representing a code construct
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AstNode {
    pub id: NodeId,
    pub kind: AstNodeKind,
    pub location: Location,
    pub children: Vec<AstNode>,
    pub text: String,
}

impl AstNode {
    pub fn new(id: NodeId, kind: AstNodeKind, location: Location, text: String) -> Self {
        Self {
            id,
            kind,
            location,
            children: Vec::new(),
            text,
        }
    }

    pub fn add_child(&mut self, child: AstNode) {
        self.children.push(child);
    }

    /// Find all descendant nodes matching a predicate
    pub fn find_descendants<F>(&self, predicate: F) -> Vec<AstNode>
    where
        F: Fn(&AstNode) -> bool,
    {
        let mut results = Vec::new();
        self.visit_descendants_internal(&predicate, &mut results);
        results
    }

    fn visit_descendants_internal<F>(&self, predicate: &F, results: &mut Vec<AstNode>)
    where
        F: Fn(&AstNode) -> bool,
    {
        for child in &self.children {
            if predicate(child) {
                results.push(child.clone());
            }
            child.visit_descendants_internal(predicate, results);
        }
    }

    /// Visit all descendant nodes with a callback
    pub fn visit_descendants<F>(&self, callback: &mut F)
    where
        F: FnMut(&AstNode),
    {
        for child in &self.children {
            callback(child);
            child.visit_descendants(callback);
        }
    }
}

/// The kind/type of an AST node
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum AstNodeKind {
    // Program structure
    Program,
    Module,
    Package,

    // Declarations
    FunctionDeclaration {
        name: String,
        parameters: Vec<Parameter>,
        return_type: Option<String>,
        is_async: bool,
        is_generator: bool,
    },
    ClassDeclaration {
        name: String,
        extends: Option<String>,
        implements: Vec<String>,
        is_abstract: bool,
    },
    MethodDeclaration {
        name: String,
        parameters: Vec<Parameter>,
        return_type: Option<String>,
        visibility: Visibility,
        is_static: bool,
        is_async: bool,
        is_abstract: bool,
    },
    VariableDeclaration {
        name: String,
        var_type: Option<String>,
        is_const: bool,
        initializer: Option<String>,
    },
    InterfaceDeclaration {
        name: String,
        extends: Vec<String>,
    },
    TypeAlias {
        name: String,
        type_definition: String,
    },
    EnumDeclaration {
        name: String,
        members: Vec<String>,
    },

    // Statements
    ExpressionStatement,
    ReturnStatement,
    IfStatement,
    WhileStatement,
    ForStatement,
    DoWhileStatement,
    TryStatement,
    CatchClause,
    FinallyClause,
    ThrowStatement,
    Block,

    // Control flow
    SwitchStatement {
        discriminant: String,
        cases_count: usize,
    },
    SwitchCase {
        test: Option<String>,  // None for default case
        consequent_count: usize,
    },
    BreakStatement {
        label: Option<String>,
    },
    ContinueStatement {
        label: Option<String>,
    },
    LabeledStatement {
        label: String,
    },
    WithStatement {
        object: String,
    },

    // Expressions
    BinaryExpression {
        operator: String,
    },
    UnaryExpression {
        operator: String,
    },
    CallExpression {
        callee: String,
        arguments_count: usize,
        is_optional_chain: bool,  // obj?.method()
    },
    MemberExpression {
        object: String,
        property: String,
        is_computed: bool,        // obj[prop] vs obj.prop
        is_optional: bool,        // obj?.prop
    },
    Identifier {
        name: String,
    },
    Literal {
        value: LiteralValue,
    },
    AssignmentExpression {
        operator: String,
    },
    ArrowFunction {
        parameters: Vec<Parameter>,
        return_type: Option<String>,
        is_async: bool,
    },
    ObjectExpression {
        properties: Vec<String>,
    },
    ArrayExpression {
        elements_count: usize,
    },
    AwaitExpression,
    YieldExpression {
        is_delegate: bool,  // yield*
    },
    TemplateString {
        has_expressions: bool,
    },
    ConditionalExpression {
        test: String,
    },
    UpdateExpression {
        operator: String,  // ++, --
        prefix: bool,      // ++i vs i++
    },
    SequenceExpression {
        expressions_count: usize,
    },
    NewExpression {
        callee: String,
        arguments_count: usize,
    },
    ThisExpression,
    SuperExpression,
    SpreadElement,
    RestElement {
        is_parameter: bool,  // In function params vs array/object
    },
    ParenthesizedExpression,
    TaggedTemplateExpression {
        tag: String,
    },
    FunctionExpression {
        name: Option<String>,
        parameters: Vec<Parameter>,
        return_type: Option<String>,
        is_async: bool,
        is_generator: bool,
    },
    ClassExpression {
        name: Option<String>,
    },

    // Patterns (destructuring)
    ArrayPattern {
        elements_count: usize,
        has_rest: bool,
    },
    ObjectPattern {
        properties_count: usize,
        has_rest: bool,
    },
    AssignmentPattern {
        has_default: bool,
    },
    RestPattern {
        is_array: bool,  // true for array rest, false for object rest
    },

    // Object/Array Details
    Property {
        key: String,
        value: Option<String>,
        is_computed: bool,   // obj[key] vs obj.key
        is_shorthand: bool,  // {x} vs {x: x}
        is_method: bool,     // {foo() {}} vs {foo: function() {}}
    },
    ComputedPropertyName {
        expression: String,
    },
    MethodDefinition {
        name: String,
        kind: MethodKind,  // method, get, set, constructor
        is_static: bool,
    },

    // Special constructs
    ImportDeclaration {
        source: String,
        imported_names: Vec<ImportSpecifier>,
        is_type_only: bool,
    },
    ExportDeclaration {
        exported_names: Vec<String>,
        is_default: bool,
        is_type_only: bool,
    },

    // Module System Details (Phase 5)
    ImportSpecifierNode {
        imported: String,  // Original name in module
        local: String,     // Local name in current file
        is_default: bool,  // import X from 'mod'
    },
    ImportNamespaceSpecifier {
        local: String,     // import * as X
    },
    ExportSpecifierNode {
        exported: String,  // Name being exported
        local: String,     // Local name (may differ if renamed)
    },
    ExportAllDeclaration {
        source: String,    // export * from 'module'
        exported: Option<String>,  // export * as X from 'module'
    },
    ReExportDeclaration {
        source: String,           // Re-export from another module
        specifiers: Vec<String>,  // Names being re-exported
    },

    Decorator {
        name: String,
        arguments: Vec<String>,
    },
    Comment {
        is_multiline: bool,
    },

    // TypeScript Support (Phase 6)
    TypeAnnotation {
        type_string: String,
    },
    TypeArguments {
        types: Vec<String>,
    },
    TypeParameters {
        parameters: Vec<String>,
    },
    AsExpression {
        type_string: String,
    },
    SatisfiesExpression {
        type_string: String,
    },
    NonNullAssertion,
    TypePredicate {
        parameter_name: String,
        type_name: String,
    },

    // Fallback for unsupported constructs
    Other {
        node_type: String,
    },
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum LiteralValue {
    String(String),
    Number(String),
    Boolean(bool),
    Null,
    Undefined,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum Visibility {
    Public,
    Private,
    Protected,
    Internal,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum MethodKind {
    Method,      // Regular method
    Get,         // Getter
    Set,         // Setter
    Constructor, // Constructor
}

impl fmt::Display for AstNodeKind {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            AstNodeKind::Program => write!(f, "Program"),
            AstNodeKind::FunctionDeclaration { name, .. } => {
                write!(f, "FunctionDeclaration({})", name)
            }
            AstNodeKind::CallExpression { callee, .. } => write!(f, "CallExpression({})", callee),
            AstNodeKind::Identifier { name } => write!(f, "Identifier({})", name),
            _ => write!(f, "{:?}", self),
        }
    }
}
