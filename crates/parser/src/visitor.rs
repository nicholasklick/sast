//! AST visitor pattern for traversing and analyzing AST nodes

use crate::ast::AstNode;

pub type VisitorResult = Result<(), Box<dyn std::error::Error>>;

/// Trait for visiting AST nodes
pub trait AstVisitor {
    /// Called when entering a node (pre-order)
    fn visit_enter(&mut self, _node: &AstNode) -> VisitorResult {
        Ok(())
    }

    /// Called when leaving a node (post-order)
    fn visit_exit(&mut self, _node: &AstNode) -> VisitorResult {
        Ok(())
    }

    /// Walk the entire AST
    fn walk(&mut self, node: &AstNode) -> VisitorResult {
        self.visit_enter(node)?;
        for child in &node.children {
            self.walk(child)?;
        }
        self.visit_exit(node)?;
        Ok(())
    }
}

/// A simple visitor that collects nodes matching a predicate
pub struct CollectingVisitor<F>
where
    F: Fn(&AstNode) -> bool,
{
    predicate: F,
    pub collected: Vec<AstNode>,
}

impl<F> CollectingVisitor<F>
where
    F: Fn(&AstNode) -> bool,
{
    pub fn new(predicate: F) -> Self {
        Self {
            predicate,
            collected: Vec::new(),
        }
    }
}

impl<F> AstVisitor for CollectingVisitor<F>
where
    F: Fn(&AstNode) -> bool,
{
    fn visit_enter(&mut self, node: &AstNode) -> VisitorResult {
        if (self.predicate)(node) {
            self.collected.push(node.clone());
        }
        Ok(())
    }
}
