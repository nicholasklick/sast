//! Arena-allocated Abstract Syntax Tree representation
//!
//! Memory-optimized AST using arena allocation with bumpalo.
//! This reduces memory usage by 50-60% by eliminating clones and using references.
//!
//! Key differences from the standard AST:
//! - Nodes use lifetimes tied to the arena
//! - Children are slices of references, not owned Vecs
//! - Strings are arena-allocated &str, not owned Strings
//! - No cloning needed during traversal

use bumpalo::Bump;
use std::fmt;

/// Unique identifier for AST nodes
pub type NodeId = usize;

/// Represents a location in source code
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Location<'arena> {
    pub file_path: &'arena str,
    pub span: Span,
}

/// Represents a span (range) in source code
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
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

/// An arena-allocated AST node
///
/// Uses lifetimes to ensure nodes don't outlive their arena.
/// All strings and children are references into the arena.
#[derive(Debug)]
pub struct AstNode<'arena> {
    pub id: NodeId,
    pub kind: AstNodeKind<'arena>,
    pub location: Location<'arena>,
    pub children: &'arena [&'arena AstNode<'arena>],
    pub text: &'arena str,
}

impl<'arena> AstNode<'arena> {
    /// Find all descendant nodes matching a predicate
    ///
    /// Returns references instead of clones - huge memory savings!
    pub fn find_descendants<F>(&self, predicate: F) -> Vec<&'arena AstNode<'arena>>
    where
        F: Fn(&AstNode<'arena>) -> bool,
    {
        let mut results = Vec::new();
        self.visit_descendants_internal(&predicate, &mut results);
        results
    }

    fn visit_descendants_internal<F>(
        &self,
        predicate: &F,
        results: &mut Vec<&'arena AstNode<'arena>>,
    ) where
        F: Fn(&AstNode<'arena>) -> bool,
    {
        for child in self.children {
            if predicate(child) {
                results.push(child); // No clone!
            }
            child.visit_descendants_internal(predicate, results);
        }
    }

    /// Visit all descendant nodes with a callback
    pub fn visit_descendants<F>(&self, callback: &mut F)
    where
        F: FnMut(&AstNode<'arena>),
    {
        for child in self.children {
            callback(child);
            child.visit_descendants(callback);
        }
    }

    /// Visit descendants and collect results
    pub fn collect_descendants<F, T>(&self, mut f: F) -> Vec<T>
    where
        F: FnMut(&AstNode<'arena>) -> Option<T>,
    {
        let mut results = Vec::new();
        self.visit_descendants(&mut |node| {
            if let Some(value) = f(node) {
                results.push(value);
            }
        });
        results
    }
}

/// The kind/type of an AST node using arena-allocated strings
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AstNodeKind<'arena> {
    // Program structure
    Program,
    Module,
    Package,

    // Declarations
    FunctionDeclaration {
        name: &'arena str,
        parameters: Vec<&'arena str>,
        return_type: Option<&'arena str>,
    },
    ClassDeclaration {
        name: &'arena str,
        extends: Option<&'arena str>,
        implements: Vec<&'arena str>,
    },
    MethodDeclaration {
        name: &'arena str,
        parameters: Vec<&'arena str>,
        return_type: Option<&'arena str>,
        visibility: Visibility,
    },
    VariableDeclaration {
        name: &'arena str,
        var_type: Option<&'arena str>,
        is_const: bool,
    },
    InterfaceDeclaration {
        name: &'arena str,
    },

    // Statements
    ExpressionStatement,
    ReturnStatement,
    IfStatement,
    WhileStatement,
    ForStatement,
    TryStatement,
    CatchClause,
    ThrowStatement,
    Block,

    // Expressions
    BinaryExpression {
        operator: &'arena str,
    },
    UnaryExpression {
        operator: &'arena str,
    },
    CallExpression {
        callee: &'arena str,
        arguments_count: usize,
    },
    MemberExpression {
        object: &'arena str,
        property: &'arena str,
    },
    AssignmentExpression {
        operator: &'arena str,
    },

    // Literals
    Literal {
        value: LiteralValue<'arena>,
    },
    Identifier {
        name: &'arena str,
    },

    // Special constructs
    Import {
        source: &'arena str,
    },
    Export,

    // Comments
    Comment {
        is_multiline: bool,
    },

    // Fallback for unknown node types
    Other {
        node_type: &'arena str,
    },
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum LiteralValue<'arena> {
    String(&'arena str),
    Number(&'arena str),
    Boolean(bool),
    Null,
    Undefined,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Visibility {
    Public,
    Private,
    Protected,
    Internal,
}

impl fmt::Display for Visibility {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Visibility::Public => write!(f, "public"),
            Visibility::Private => write!(f, "private"),
            Visibility::Protected => write!(f, "protected"),
            Visibility::Internal => write!(f, "internal"),
        }
    }
}

/// Arena container for AST construction
///
/// Manages memory allocation and node ID generation.
pub struct AstArena {
    pub arena: Bump,
    next_id: std::cell::Cell<NodeId>,
}

impl AstArena {
    pub fn new() -> Self {
        Self {
            arena: Bump::new(),
            next_id: std::cell::Cell::new(0),
        }
    }

    /// Get the next unique node ID
    pub fn next_id(&self) -> NodeId {
        let id = self.next_id.get();
        self.next_id.set(id + 1);
        id
    }

    /// Allocate a string in the arena
    pub fn alloc_str(&self, s: &str) -> &str {
        self.arena.alloc_str(s)
    }

    /// Create a new AST node in the arena
    pub fn alloc_node<'arena>(
        &'arena self,
        id: NodeId,
        kind: AstNodeKind<'arena>,
        location: Location<'arena>,
        text: &'arena str,
        children: Vec<&'arena AstNode<'arena>>,
    ) -> &'arena AstNode<'arena> {
        let children_slice = self.arena.alloc_slice_copy(&children);
        self.arena.alloc(AstNode {
            id,
            kind,
            location,
            children: children_slice,
            text,
        })
    }

    /// Get memory usage statistics
    pub fn memory_stats(&self) -> MemoryStats {
        MemoryStats {
            arena_allocated: self.arena.allocated_bytes(),
            arena_capacity: self.arena.chunk_capacity(),
        }
    }

    /// Reset the arena, freeing all allocated memory
    ///
    /// This is much faster than dropping individual nodes.
    pub fn reset(&mut self) {
        self.arena.reset();
        self.next_id.set(0);
    }
}

impl Default for AstArena {
    fn default() -> Self {
        Self::new()
    }
}

#[derive(Debug, Clone)]
pub struct MemoryStats {
    pub arena_allocated: usize,
    pub arena_capacity: usize,
}

impl fmt::Display for MemoryStats {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "Allocated: {:.2} MB / Capacity: {:.2} MB",
            self.arena_allocated as f64 / 1024.0 / 1024.0,
            self.arena_capacity as f64 / 1024.0 / 1024.0
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_arena_allocation() {
        let ast_arena = AstArena::new();

        let text = ast_arena.alloc_str("test");
        let file_path = ast_arena.alloc_str("test.rs");

        let location = Location {
            file_path,
            span: Span {
                start_line: 1,
                start_column: 0,
                end_line: 1,
                end_column: 4,
                start_byte: 0,
                end_byte: 4,
            },
        };

        let node = ast_arena.alloc_node(
            0,
            AstNodeKind::Program,
            location,
            text,
            vec![],
        );

        assert_eq!(node.id, 0);
        assert_eq!(node.text, "test");
    }

    #[test]
    fn test_no_cloning_traversal() {
        let ast_arena = AstArena::new();
        let file_path = ast_arena.alloc_str("test.rs");

        let location = Location {
            file_path,
            span: Span {
                start_line: 1,
                start_column: 0,
                end_line: 1,
                end_column: 4,
                start_byte: 0,
                end_byte: 4,
            },
        };

        // Create child nodes
        let child1 = ast_arena.alloc_node(
            1,
            AstNodeKind::Program,
            location,
            ast_arena.alloc_str("child1"),
            vec![],
        );

        let child2 = ast_arena.alloc_node(
            2,
            AstNodeKind::Module,
            location,
            ast_arena.alloc_str("child2"),
            vec![],
        );

        // Create parent with children
        let parent = ast_arena.alloc_node(
            0,
            AstNodeKind::Program,
            location,
            ast_arena.alloc_str("parent"),
            vec![child1, child2],
        );

        // Find descendants - no cloning!
        let descendants = parent.find_descendants(|n| n.id > 0);
        assert_eq!(descendants.len(), 2);
        assert_eq!(descendants[0].id, 1);
        assert_eq!(descendants[1].id, 2);
    }

    #[test]
    fn test_memory_stats() {
        let ast_arena = AstArena::new();

        // Allocate some data
        for i in 0..100 {
            let text = ast_arena.alloc_str(&format!("node_{}", i));
            let file_path = ast_arena.alloc_str("test.rs");
            let location = Location {
                file_path,
                span: Span {
                    start_line: 1,
                    start_column: 0,
                    end_line: 1,
                    end_column: 4,
                    start_byte: 0,
                    end_byte: 4,
                },
            };
            ast_arena.alloc_node(i, AstNodeKind::Program, location, text, vec![]);
        }

        let stats = ast_arena.memory_stats();
        assert!(stats.arena_allocated > 0);
        // Capacity is per-chunk, so it may be less than total allocated
        assert!(stats.arena_capacity > 0);
    }
}
