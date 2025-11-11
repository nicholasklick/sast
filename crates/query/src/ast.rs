//! KQL Abstract Syntax Tree

use serde::{Deserialize, Serialize};

/// A complete KQL query
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Query {
    pub from: FromClause,
    pub where_clause: Option<WhereClause>,
    pub select: SelectClause,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FromClause {
    pub entity: EntityType,
    pub variable: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum EntityType {
    MethodCall,
    FunctionDeclaration,
    VariableDeclaration,
    Assignment,
    Literal,
    BinaryExpression,
    CallExpression,
    MemberExpression,
    AnyNode,
}

impl EntityType {
    pub fn from_str(s: &str) -> Option<Self> {
        match s {
            "MethodCall" => Some(EntityType::MethodCall),
            "FunctionDeclaration" => Some(EntityType::FunctionDeclaration),
            "VariableDeclaration" => Some(EntityType::VariableDeclaration),
            "Assignment" => Some(EntityType::Assignment),
            "Literal" => Some(EntityType::Literal),
            "BinaryExpression" => Some(EntityType::BinaryExpression),
            "CallExpression" => Some(EntityType::CallExpression),
            "MemberExpression" => Some(EntityType::MemberExpression),
            "AnyNode" => Some(EntityType::AnyNode),
            _ => None,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WhereClause {
    pub predicates: Vec<Predicate>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum Predicate {
    MethodName {
        variable: String,
        operator: ComparisonOp,
        value: String,
    },
    PropertyAccess {
        variable: String,
        property: String,
    },
    FunctionCall {
        variable: String,
        function: String,
        arguments: Vec<Expression>,
    },
    Comparison {
        left: Expression,
        operator: ComparisonOp,
        right: Expression,
    },
    And {
        left: Box<Predicate>,
        right: Box<Predicate>,
    },
    Or {
        left: Box<Predicate>,
        right: Box<Predicate>,
    },
    Not {
        predicate: Box<Predicate>,
    },
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum ComparisonOp {
    Equal,
    NotEqual,
    Contains,
    StartsWith,
    EndsWith,
    Matches, // Regex match
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum Expression {
    Variable(String),
    String(String),
    Number(i64),
    Boolean(bool),
    PropertyAccess {
        object: Box<Expression>,
        property: String,
    },
    MethodCall {
        object: Box<Expression>,
        method: String,
        arguments: Vec<Expression>,
    },
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SelectClause {
    pub items: Vec<SelectItem>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum SelectItem {
    Variable(String),
    Message(String),
    Both {
        variable: String,
        message: String,
    },
}

/// The complete AST for a KQL query
pub type QueryAst = Query;

impl Query {
    pub fn new(from: FromClause, where_clause: Option<WhereClause>, select: SelectClause) -> Self {
        Self {
            from,
            where_clause,
            select,
        }
    }
}

impl FromClause {
    pub fn new(entity: EntityType, variable: String) -> Self {
        Self { entity, variable }
    }
}

impl WhereClause {
    pub fn new(predicates: Vec<Predicate>) -> Self {
        Self { predicates }
    }
}

impl SelectClause {
    pub fn new(items: Vec<SelectItem>) -> Self {
        Self { items }
    }
}
