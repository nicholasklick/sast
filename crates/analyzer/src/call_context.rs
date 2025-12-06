//! Call Context Sensitivity (k-CFA) for Inter-procedural Analysis
//!
//! This module provides call context tracking for context-sensitive analysis.
//! Context sensitivity distinguishes calls to the same function from different
//! call sites, improving precision by not merging taint from unrelated callers.
//!
//! ## Why Context Sensitivity Matters
//!
//! Consider:
//! ```ignore
//! function helper(x) { return x; }
//!
//! let a = helper(tainted);  // tainted flows to 'a'
//! let b = helper(clean);    // clean flows to 'b'
//! ```
//!
//! Without context sensitivity, both `a` and `b` would be marked tainted because
//! the summary of `helper` would merge taint from all callers.
//!
//! With k=1 context sensitivity, each call site gets its own summary:
//! - helper@call1: tainted -> return
//! - helper@call2: clean -> return
//!
//! ## Implementation
//!
//! We use k-CFA (k-limited call-strings) where:
//! - k=0: Context-insensitive (single summary per function)
//! - k=1: Last call site tracked (most common, good balance)
//! - k=2: Last two call sites tracked (more precise, more expensive)

use gittera_parser::ast::NodeId;
use serde::{Deserialize, Serialize};
use std::fmt;

/// Maximum call context depth (k in k-CFA)
pub const MAX_CONTEXT_DEPTH: usize = 1;

/// A call context represents the calling history leading to a function.
///
/// This enables context-sensitive analysis where the same function
/// can have different behavior depending on how it was called.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum CallContext {
    /// Empty context (top-level call or context-insensitive)
    Empty,
    /// Single call site context (k=1 CFA)
    Call {
        /// The node ID of the call site
        call_id: NodeId,
    },
    /// Chain of call sites (k>1 CFA)
    CallChain {
        /// Call sites, most recent last
        calls: Vec<NodeId>,
        /// Maximum depth to maintain
        k: usize,
    },
}

impl Default for CallContext {
    fn default() -> Self {
        CallContext::Empty
    }
}

impl CallContext {
    /// Create an empty context
    pub fn empty() -> Self {
        CallContext::Empty
    }

    /// Create a context for a single call site (k=1)
    pub fn from_call(call_id: NodeId) -> Self {
        CallContext::Call { call_id }
    }

    /// Create a new context by pushing a call onto this one.
    ///
    /// For k=1: Simply replaces the context with the new call.
    /// For k>1: Adds the call to the chain, dropping oldest if needed.
    pub fn push_call(&self, call_id: NodeId) -> Self {
        match self {
            CallContext::Empty => CallContext::Call { call_id },
            CallContext::Call { call_id: _old } => {
                // k=1: just replace with new call
                // For k=2+, we would create a CallChain here
                CallContext::Call { call_id }
            }
            CallContext::CallChain { calls, k } => {
                let mut new_calls = calls.clone();
                new_calls.push(call_id);
                if new_calls.len() > *k {
                    new_calls.remove(0); // Remove oldest
                }
                CallContext::CallChain { calls: new_calls, k: *k }
            }
        }
    }

    /// Create a new context by pushing a call, with explicit k limit.
    pub fn push_call_with_k(&self, call_id: NodeId, k: usize) -> Self {
        if k == 0 {
            return CallContext::Empty;
        }
        if k == 1 {
            return CallContext::Call { call_id };
        }

        match self {
            CallContext::Empty => CallContext::Call { call_id },
            CallContext::Call { call_id: old } => {
                CallContext::CallChain {
                    calls: vec![*old, call_id],
                    k,
                }
            }
            CallContext::CallChain { calls, k: _ } => {
                let mut new_calls = calls.clone();
                new_calls.push(call_id);
                if new_calls.len() > k {
                    new_calls.remove(0);
                }
                CallContext::CallChain { calls: new_calls, k }
            }
        }
    }

    /// Pop a call from the context (for return from function)
    pub fn pop_call(&self) -> Self {
        match self {
            CallContext::Empty => CallContext::Empty,
            CallContext::Call { .. } => CallContext::Empty,
            CallContext::CallChain { calls, k } => {
                if calls.len() <= 1 {
                    CallContext::Empty
                } else {
                    let mut new_calls = calls.clone();
                    new_calls.pop();
                    if new_calls.len() == 1 {
                        CallContext::Call { call_id: new_calls[0] }
                    } else {
                        CallContext::CallChain { calls: new_calls, k: *k }
                    }
                }
            }
        }
    }

    /// Check if a return is valid for this context.
    ///
    /// A return is valid if it matches the most recent call site in the context.
    pub fn is_valid_return(&self, call_id: NodeId) -> bool {
        match self {
            CallContext::Empty => true, // Accept any return from empty context
            CallContext::Call { call_id: ctx_call } => *ctx_call == call_id,
            CallContext::CallChain { calls, .. } => {
                calls.last().map_or(true, |&last| last == call_id)
            }
        }
    }

    /// Get the most recent call site in this context
    pub fn current_call(&self) -> Option<NodeId> {
        match self {
            CallContext::Empty => None,
            CallContext::Call { call_id } => Some(*call_id),
            CallContext::CallChain { calls, .. } => calls.last().copied(),
        }
    }

    /// Get the depth of this context
    pub fn depth(&self) -> usize {
        match self {
            CallContext::Empty => 0,
            CallContext::Call { .. } => 1,
            CallContext::CallChain { calls, .. } => calls.len(),
        }
    }

    /// Check if this is an empty context
    pub fn is_empty(&self) -> bool {
        matches!(self, CallContext::Empty)
    }

    /// Create a unique key for this context (for use in maps)
    pub fn to_key(&self) -> String {
        match self {
            CallContext::Empty => "[]".to_string(),
            CallContext::Call { call_id } => format!("[{}]", call_id),
            CallContext::CallChain { calls, .. } => {
                let ids: Vec<String> = calls.iter().map(|id| id.to_string()).collect();
                format!("[{}]", ids.join(","))
            }
        }
    }
}

impl fmt::Display for CallContext {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            CallContext::Empty => write!(f, "⟨⟩"),
            CallContext::Call { call_id } => write!(f, "⟨{}⟩", call_id),
            CallContext::CallChain { calls, .. } => {
                write!(f, "⟨")?;
                for (i, call) in calls.iter().enumerate() {
                    if i > 0 {
                        write!(f, " → ")?;
                    }
                    write!(f, "{}", call)?;
                }
                write!(f, "⟩")
            }
        }
    }
}

/// A function identity combined with a call context.
///
/// This is used as a key in context-sensitive analysis to distinguish
/// different "versions" of the same function based on calling context.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct ContextualFunction {
    /// The function name or identifier
    pub function: String,
    /// The calling context
    pub context: CallContext,
}

impl ContextualFunction {
    /// Create a new contextual function reference
    pub fn new(function: impl Into<String>, context: CallContext) -> Self {
        Self {
            function: function.into(),
            context,
        }
    }

    /// Create a contextual function with empty context
    pub fn with_empty_context(function: impl Into<String>) -> Self {
        Self::new(function, CallContext::Empty)
    }

    /// Create a unique key for this function+context
    pub fn to_key(&self) -> String {
        format!("{}@{}", self.function, self.context.to_key())
    }
}

impl fmt::Display for ContextualFunction {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}@{}", self.function, self.context)
    }
}

/// Configuration for context sensitivity
#[derive(Debug, Clone)]
pub struct ContextConfig {
    /// The k value for k-CFA (0 = context-insensitive, 1 = default)
    pub k: usize,
    /// Maximum number of contexts to track per function before widening
    pub max_contexts_per_function: usize,
    /// Whether to use object sensitivity in addition to call sensitivity
    pub use_object_sensitivity: bool,
}

impl Default for ContextConfig {
    fn default() -> Self {
        Self {
            k: MAX_CONTEXT_DEPTH,
            max_contexts_per_function: 100,
            use_object_sensitivity: false,
        }
    }
}

impl ContextConfig {
    /// Create context-insensitive configuration
    pub fn insensitive() -> Self {
        Self {
            k: 0,
            ..Default::default()
        }
    }

    /// Create configuration with k=1
    pub fn k1() -> Self {
        Self::default()
    }

    /// Create configuration with k=2
    pub fn k2() -> Self {
        Self {
            k: 2,
            ..Default::default()
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_empty_context() {
        let ctx = CallContext::empty();
        assert!(ctx.is_empty());
        assert_eq!(ctx.depth(), 0);
        assert_eq!(ctx.current_call(), None);
    }

    #[test]
    fn test_push_call() {
        let ctx = CallContext::empty();
        let ctx1 = ctx.push_call(42);
        assert!(!ctx1.is_empty());
        assert_eq!(ctx1.depth(), 1);
        assert_eq!(ctx1.current_call(), Some(42));
    }

    #[test]
    fn test_push_replaces_with_k1() {
        let ctx = CallContext::from_call(10);
        let ctx2 = ctx.push_call(20);

        // With k=1, pushing a new call replaces the old one
        assert_eq!(ctx2.depth(), 1);
        assert_eq!(ctx2.current_call(), Some(20));
    }

    #[test]
    fn test_push_with_k2() {
        let ctx = CallContext::from_call(10);
        let ctx2 = ctx.push_call_with_k(20, 2);

        // With k=2, we maintain both calls
        assert_eq!(ctx2.depth(), 2);
        assert_eq!(ctx2.current_call(), Some(20));

        match ctx2 {
            CallContext::CallChain { calls, .. } => {
                assert_eq!(calls, vec![10, 20]);
            }
            _ => panic!("Expected CallChain"),
        }
    }

    #[test]
    fn test_pop_call() {
        let ctx = CallContext::from_call(42);
        let popped = ctx.pop_call();
        assert!(popped.is_empty());
    }

    #[test]
    fn test_is_valid_return() {
        let ctx = CallContext::from_call(42);
        assert!(ctx.is_valid_return(42));
        assert!(!ctx.is_valid_return(99));

        // Empty context accepts any return
        assert!(CallContext::empty().is_valid_return(123));
    }

    #[test]
    fn test_contextual_function() {
        let cf = ContextualFunction::new("foo", CallContext::from_call(10));
        assert_eq!(cf.function, "foo");
        assert_eq!(cf.to_key(), "foo@[10]");
    }

    #[test]
    fn test_context_display() {
        assert_eq!(format!("{}", CallContext::empty()), "⟨⟩");
        assert_eq!(format!("{}", CallContext::from_call(42)), "⟨42⟩");
    }

    #[test]
    fn test_context_key() {
        let ctx1 = CallContext::from_call(10);
        let ctx2 = CallContext::from_call(10);
        let ctx3 = CallContext::from_call(20);

        assert_eq!(ctx1.to_key(), ctx2.to_key());
        assert_ne!(ctx1.to_key(), ctx3.to_key());
    }

    #[test]
    fn test_k_limits_chain_length() {
        let mut ctx = CallContext::empty();
        ctx = ctx.push_call_with_k(1, 2);
        ctx = ctx.push_call_with_k(2, 2);
        ctx = ctx.push_call_with_k(3, 2);

        // With k=2, only last 2 calls are kept
        assert_eq!(ctx.depth(), 2);
        match ctx {
            CallContext::CallChain { calls, .. } => {
                assert_eq!(calls, vec![2, 3]);
            }
            _ => panic!("Expected CallChain"),
        }
    }

    #[test]
    fn test_context_config() {
        let default_cfg = ContextConfig::default();
        assert_eq!(default_cfg.k, 1);

        let insensitive = ContextConfig::insensitive();
        assert_eq!(insensitive.k, 0);

        let k2 = ContextConfig::k2();
        assert_eq!(k2.k, 2);
    }
}
