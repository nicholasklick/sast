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
