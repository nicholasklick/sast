//! Access Path Model for Field-Sensitive Taint Analysis
//!
//! This module provides access paths for tracking data through nested structures.
//! An access path represents a chain of content accesses like `obj.field1.field2[0]`.
//!
//! Key concepts:
//! - AccessPath: A chain of content accesses from a base variable
//! - AccessPathFront: The first content in an access path
//!
//! Access paths have a maximum depth (default 5, matching CodeQL) to prevent
//! infinite expansion while still providing precise tracking for common patterns.

use crate::content::Content;
use serde::{Deserialize, Serialize};
use std::fmt;
use std::hash::Hash;

/// Maximum length of an access path
///
/// This matches CodeQL's default and provides good precision for most code patterns
/// while preventing unbounded growth.
pub const MAX_ACCESS_PATH_LENGTH: usize = 5;

/// An access path represents a chain of content accesses
///
/// Example paths:
/// - `x` (just a variable)
/// - `x.field` (field access)
/// - `x.field1.field2` (nested field access)
/// - `x[0].field` (array element then field)
/// - `obj.map.get(key)` (map value access)
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct AccessPath {
    /// The base variable name
    pub base: String,
    /// Chain of content accesses (limited to MAX_ACCESS_PATH_LENGTH)
    pub path: Vec<Content>,
}

impl AccessPath {
    /// Create an access path for just a variable (no content access)
    pub fn variable(name: impl Into<String>) -> Self {
        Self {
            base: name.into(),
            path: Vec::new(),
        }
    }

    /// Create an access path with a base and initial content
    pub fn with_content(base: impl Into<String>, content: Content) -> Self {
        Self {
            base: base.into(),
            path: vec![content],
        }
    }

    /// Create an access path from a base and a chain of content
    pub fn from_chain(base: impl Into<String>, chain: Vec<Content>) -> Self {
        let mut path = chain;
        if path.len() > MAX_ACCESS_PATH_LENGTH {
            path.truncate(MAX_ACCESS_PATH_LENGTH);
        }
        Self {
            base: base.into(),
            path,
        }
    }

    /// Extend this access path with additional content
    ///
    /// Returns None if the path would exceed MAX_ACCESS_PATH_LENGTH.
    /// This prevents unbounded path growth.
    pub fn push(&self, content: Content) -> Option<Self> {
        if self.path.len() >= MAX_ACCESS_PATH_LENGTH {
            return None;
        }
        let mut new_path = self.path.clone();
        new_path.push(content);
        Some(Self {
            base: self.base.clone(),
            path: new_path,
        })
    }

    /// Extend this access path, widening if necessary
    ///
    /// Unlike push(), this always succeeds by collapsing the path
    /// to the base if it would exceed MAX_ACCESS_PATH_LENGTH.
    pub fn push_or_widen(&self, content: Content) -> Self {
        if self.path.len() >= MAX_ACCESS_PATH_LENGTH {
            // Widen: collapse to just the base
            Self {
                base: self.base.clone(),
                path: Vec::new(),
            }
        } else {
            let mut new_path = self.path.clone();
            new_path.push(content);
            Self {
                base: self.base.clone(),
                path: new_path,
            }
        }
    }

    /// Pop the last content from the path
    ///
    /// Returns the popped content and the remaining path.
    pub fn pop(&self) -> (Option<Content>, Self) {
        if self.path.is_empty() {
            (None, self.clone())
        } else {
            let mut new_path = self.path.clone();
            let content = new_path.pop();
            (
                content,
                Self {
                    base: self.base.clone(),
                    path: new_path,
                },
            )
        }
    }

    /// Get the first content in the path (if any)
    pub fn front(&self) -> Option<&Content> {
        self.path.first()
    }

    /// Get the last content in the path (if any)
    pub fn back(&self) -> Option<&Content> {
        self.path.last()
    }

    /// Check if this is just a variable (no content access)
    pub fn is_variable(&self) -> bool {
        self.path.is_empty()
    }

    /// Get the depth of the access path
    pub fn depth(&self) -> usize {
        self.path.len()
    }

    /// Check if this path may alias with another
    ///
    /// Two paths may alias if:
    /// 1. They have the same base
    /// 2. One is a prefix of the other, or they diverge at a may-match content
    pub fn may_alias(&self, other: &AccessPath) -> bool {
        // Different bases never alias
        if self.base != other.base {
            return false;
        }

        // Same base - check the path
        let min_len = self.path.len().min(other.path.len());
        for i in 0..min_len {
            if !self.path[i].may_match(&other.path[i]) {
                return false;
            }
        }

        // If we got here, one path is a prefix of the other (or they're equal)
        // which means they may alias
        true
    }

    /// Check if this path definitely matches another
    pub fn definitely_matches(&self, other: &AccessPath) -> bool {
        if self.base != other.base {
            return false;
        }
        if self.path.len() != other.path.len() {
            return false;
        }
        self.path.iter().zip(&other.path).all(|(a, b)| a.definitely_matches(b))
    }

    /// Check if this path is a prefix of another
    pub fn is_prefix_of(&self, other: &AccessPath) -> bool {
        if self.base != other.base {
            return false;
        }
        if self.path.len() > other.path.len() {
            return false;
        }
        self.path.iter().zip(&other.path).all(|(a, b)| a.definitely_matches(b))
    }

    /// Create a field access path: `base.field`
    pub fn field(base: impl Into<String>, field: impl Into<String>) -> Self {
        Self::with_content(base, Content::field(field))
    }

    /// Create an array access path: `base[index]`
    pub fn array(base: impl Into<String>, index: i64) -> Self {
        Self::with_content(base, Content::array_at(index))
    }

    /// Create an array access path with unknown index: `base[*]`
    pub fn array_any(base: impl Into<String>) -> Self {
        Self::with_content(base, Content::array_any())
    }

    /// Extend with a field access: `path.field`
    pub fn then_field(&self, field: impl Into<String>) -> Option<Self> {
        self.push(Content::field(field))
    }

    /// Extend with an array access: `path[index]`
    pub fn then_array(&self, index: i64) -> Option<Self> {
        self.push(Content::array_at(index))
    }

    /// Convert to a string representation suitable for use as a taint variable name
    pub fn to_taint_key(&self) -> String {
        self.to_string()
    }
}

impl fmt::Display for AccessPath {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.base)?;
        for content in &self.path {
            match content {
                Content::FieldContent { field_name } => write!(f, ".{}", field_name)?,
                Content::ArrayContent { index: Some(i) } => write!(f, "[{}]", i)?,
                Content::ArrayContent { index: None } => write!(f, "[*]")?,
                Content::CollectionContent => write!(f, ".element")?,
                Content::MapKeyContent => write!(f, ".key")?,
                Content::MapValueContent => write!(f, ".value")?,
                Content::SyntheticContent { name } => write!(f, ".${}", name)?,
                Content::Wildcard => write!(f, ".*")?,
            }
        }
        Ok(())
    }
}

/// A short access path with just the front content
///
/// Used for efficient matching in flow summaries.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct AccessPathFront {
    pub base: String,
    pub front: Option<Content>,
}

impl AccessPathFront {
    pub fn from_access_path(path: &AccessPath) -> Self {
        Self {
            base: path.base.clone(),
            front: path.front().cloned(),
        }
    }

    pub fn variable(name: impl Into<String>) -> Self {
        Self {
            base: name.into(),
            front: None,
        }
    }

    pub fn with_content(base: impl Into<String>, content: Content) -> Self {
        Self {
            base: base.into(),
            front: Some(content),
        }
    }
}

impl fmt::Display for AccessPathFront {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.base)?;
        if let Some(ref content) = self.front {
            match content {
                Content::FieldContent { field_name } => write!(f, ".{}", field_name)?,
                Content::ArrayContent { index: Some(i) } => write!(f, "[{}]", i)?,
                Content::ArrayContent { index: None } => write!(f, "[*]")?,
                _ => write!(f, ".{}", content)?,
            }
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_variable_path() {
        let path = AccessPath::variable("x");
        assert!(path.is_variable());
        assert_eq!(path.depth(), 0);
        assert_eq!(path.to_string(), "x");
    }

    #[test]
    fn test_field_access() {
        let path = AccessPath::field("obj", "name");
        assert!(!path.is_variable());
        assert_eq!(path.depth(), 1);
        assert_eq!(path.to_string(), "obj.name");
    }

    #[test]
    fn test_nested_access() {
        let path = AccessPath::field("obj", "data")
            .then_field("name")
            .unwrap();
        assert_eq!(path.depth(), 2);
        assert_eq!(path.to_string(), "obj.data.name");
    }

    #[test]
    fn test_array_access() {
        let path = AccessPath::array("arr", 0);
        assert_eq!(path.to_string(), "arr[0]");

        let any = AccessPath::array_any("arr");
        assert_eq!(any.to_string(), "arr[*]");
    }

    #[test]
    fn test_max_depth() {
        let mut path = AccessPath::variable("x");
        for i in 0..MAX_ACCESS_PATH_LENGTH {
            path = path.push(Content::field(format!("f{}", i))).unwrap();
        }
        assert_eq!(path.depth(), MAX_ACCESS_PATH_LENGTH);

        // Cannot push beyond max
        assert!(path.push(Content::field("extra")).is_none());
    }

    #[test]
    fn test_push_or_widen() {
        let mut path = AccessPath::variable("x");
        for _ in 0..MAX_ACCESS_PATH_LENGTH {
            path = path.push_or_widen(Content::field("f"));
        }

        // Next push_or_widen should widen to base
        let widened = path.push_or_widen(Content::field("extra"));
        assert!(widened.is_variable());
        assert_eq!(widened.base, "x");
    }

    #[test]
    fn test_may_alias_same_path() {
        let p1 = AccessPath::field("obj", "name");
        let p2 = AccessPath::field("obj", "name");
        assert!(p1.may_alias(&p2));
        assert!(p1.definitely_matches(&p2));
    }

    #[test]
    fn test_may_alias_different_fields() {
        let p1 = AccessPath::field("obj", "name");
        let p2 = AccessPath::field("obj", "other");
        assert!(!p1.may_alias(&p2));
    }

    #[test]
    fn test_may_alias_prefix() {
        let p1 = AccessPath::variable("obj");
        let p2 = AccessPath::field("obj", "name");
        assert!(p1.may_alias(&p2)); // obj may alias obj.name
        assert!(p1.is_prefix_of(&p2));
    }

    #[test]
    fn test_may_alias_different_base() {
        let p1 = AccessPath::field("obj1", "name");
        let p2 = AccessPath::field("obj2", "name");
        assert!(!p1.may_alias(&p2));
    }

    #[test]
    fn test_pop() {
        let path = AccessPath::field("obj", "data")
            .then_field("name")
            .unwrap();

        let (content, remaining) = path.pop();
        assert_eq!(content, Some(Content::field("name")));
        assert_eq!(remaining.to_string(), "obj.data");
    }

    #[test]
    fn test_access_path_front() {
        let path = AccessPath::field("obj", "name")
            .then_field("value")
            .unwrap();
        let front = AccessPathFront::from_access_path(&path);

        assert_eq!(front.base, "obj");
        assert_eq!(front.front, Some(Content::field("name")));
    }
}
