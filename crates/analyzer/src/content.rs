//! Content Model for Field-Sensitive Taint Analysis
//!
//! This module provides a CodeQL-inspired content abstraction for tracking
//! data through object fields, array elements, and collection contents.
//!
//! Key concepts:
//! - Content: A single piece of content (field, array element, etc.)
//! - ContentSet: A set of content that can be read/written together
//!
//! This enables field-sensitive analysis where `obj.safe` and `obj.tainted`
//! are tracked separately, reducing false positives.

use serde::{Deserialize, Serialize};
use std::fmt;
use std::hash::Hash;

/// Represents a piece of content (field, array element, etc.)
///
/// Content describes WHERE data is stored within an object or container.
/// This is the foundation for field-sensitive analysis.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum Content {
    /// Object field: `obj.fieldName`
    FieldContent {
        field_name: String,
    },

    /// Array element: `arr[i]`
    /// The index is optional - None means "any element"
    ArrayContent {
        index: Option<i64>,
    },

    /// Collection element (List, Set, etc.): `list.get(i)`
    CollectionContent,

    /// Map key: `map.keySet()` or the key part of `map.get(k)`
    MapKeyContent,

    /// Map value: `map.get(k)` (the value part)
    MapValueContent,

    /// Synthetic content for taint inheritance
    /// Used when we want to mark that all contents inherit taint from a container
    SyntheticContent {
        name: String,
    },

    /// Wildcard: matches any content
    /// Used for conservative analysis when we don't know the specific content
    Wildcard,
}

impl Content {
    /// Create a field content
    pub fn field(name: impl Into<String>) -> Self {
        Content::FieldContent {
            field_name: name.into(),
        }
    }

    /// Create an array content with known index
    pub fn array_at(index: i64) -> Self {
        Content::ArrayContent { index: Some(index) }
    }

    /// Create an array content with unknown index (any element)
    pub fn array_any() -> Self {
        Content::ArrayContent { index: None }
    }

    /// Create collection content
    pub fn collection() -> Self {
        Content::CollectionContent
    }

    /// Create map key content
    pub fn map_key() -> Self {
        Content::MapKeyContent
    }

    /// Create map value content
    pub fn map_value() -> Self {
        Content::MapValueContent
    }

    /// Create a wildcard content
    pub fn wildcard() -> Self {
        Content::Wildcard
    }

    /// Check if this content may match another content
    ///
    /// Used for determining if a read/store operation might affect data
    pub fn may_match(&self, other: &Content) -> bool {
        match (self, other) {
            // Wildcards match everything
            (Content::Wildcard, _) | (_, Content::Wildcard) => true,

            // Field contents match if names are the same
            (Content::FieldContent { field_name: a }, Content::FieldContent { field_name: b }) => {
                a == b
            }

            // Array contents match if indices overlap
            (Content::ArrayContent { index: a }, Content::ArrayContent { index: b }) => {
                match (a, b) {
                    (None, _) | (_, None) => true, // Unknown index matches any
                    (Some(i), Some(j)) => i == j,
                }
            }

            // Collection/Map contents match by type
            (Content::CollectionContent, Content::CollectionContent) => true,
            (Content::MapKeyContent, Content::MapKeyContent) => true,
            (Content::MapValueContent, Content::MapValueContent) => true,

            // Synthetic contents match by name
            (Content::SyntheticContent { name: a }, Content::SyntheticContent { name: b }) => {
                a == b
            }

            // Different types don't match
            _ => false,
        }
    }

    /// Check if this content definitely matches another (not just may-match)
    pub fn definitely_matches(&self, other: &Content) -> bool {
        match (self, other) {
            // Wildcards don't definitely match anything specific
            (Content::Wildcard, _) | (_, Content::Wildcard) => false,

            // Field contents definitely match if names are the same
            (Content::FieldContent { field_name: a }, Content::FieldContent { field_name: b }) => {
                a == b
            }

            // Array contents definitely match only with known equal indices
            (Content::ArrayContent { index: Some(a) }, Content::ArrayContent { index: Some(b) }) => {
                a == b
            }

            // Collection/Map contents definitely match by type
            (Content::CollectionContent, Content::CollectionContent) => true,
            (Content::MapKeyContent, Content::MapKeyContent) => true,
            (Content::MapValueContent, Content::MapValueContent) => true,

            // Synthetic contents definitely match by name
            (Content::SyntheticContent { name: a }, Content::SyntheticContent { name: b }) => {
                a == b
            }

            _ => false,
        }
    }
}

impl fmt::Display for Content {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Content::FieldContent { field_name } => write!(f, "Field[{}]", field_name),
            Content::ArrayContent { index: Some(i) } => write!(f, "Array[{}]", i),
            Content::ArrayContent { index: None } => write!(f, "Array[*]"),
            Content::CollectionContent => write!(f, "Element"),
            Content::MapKeyContent => write!(f, "MapKey"),
            Content::MapValueContent => write!(f, "MapValue"),
            Content::SyntheticContent { name } => write!(f, "Synthetic[{}]", name),
            Content::Wildcard => write!(f, "*"),
        }
    }
}

/// A set of content that can be read/written together
///
/// ContentSet allows specifying multiple content locations that
/// might be affected by a single operation.
#[derive(Debug, Clone, Default)]
pub struct ContentSet {
    contents: Vec<Content>,
}

impl ContentSet {
    /// Create an empty content set
    pub fn new() -> Self {
        Self { contents: Vec::new() }
    }

    /// Create a content set with a single content
    pub fn single(content: Content) -> Self {
        Self { contents: vec![content] }
    }

    /// Create a content set from multiple contents
    pub fn from_contents(contents: Vec<Content>) -> Self {
        Self { contents }
    }

    /// Add content to the set
    pub fn add(&mut self, content: Content) {
        if !self.contents.contains(&content) {
            self.contents.push(content);
        }
    }

    /// Check if this set includes a specific content
    pub fn includes(&self, content: &Content) -> bool {
        self.contents.iter().any(|c| c.may_match(content))
    }

    /// Check if this set definitely includes a specific content
    pub fn definitely_includes(&self, content: &Content) -> bool {
        self.contents.iter().any(|c| c.definitely_matches(content))
    }

    /// Get contents for store operations
    ///
    /// When storing data, we need the specific content locations
    pub fn get_store_content(&self) -> impl Iterator<Item = &Content> {
        self.contents.iter()
    }

    /// Get contents for read operations
    ///
    /// When reading data, we need all content locations that might provide data
    pub fn get_read_content(&self) -> impl Iterator<Item = &Content> {
        self.contents.iter()
    }

    /// Check if the set is empty
    pub fn is_empty(&self) -> bool {
        self.contents.is_empty()
    }

    /// Get the number of contents in the set
    pub fn len(&self) -> usize {
        self.contents.len()
    }

    /// Iterate over all contents
    pub fn iter(&self) -> impl Iterator<Item = &Content> {
        self.contents.iter()
    }
}

impl FromIterator<Content> for ContentSet {
    fn from_iter<I: IntoIterator<Item = Content>>(iter: I) -> Self {
        Self {
            contents: iter.into_iter().collect(),
        }
    }
}

impl fmt::Display for ContentSet {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        if self.contents.is_empty() {
            write!(f, "{{}}")
        } else {
            write!(f, "{{")?;
            for (i, c) in self.contents.iter().enumerate() {
                if i > 0 {
                    write!(f, ", ")?;
                }
                write!(f, "{}", c)?;
            }
            write!(f, "}}")
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_field_content() {
        let f1 = Content::field("name");
        let f2 = Content::field("name");
        let f3 = Content::field("other");

        assert!(f1.may_match(&f2));
        assert!(f1.definitely_matches(&f2));
        assert!(!f1.may_match(&f3));
    }

    #[test]
    fn test_array_content() {
        let a1 = Content::array_at(0);
        let a2 = Content::array_at(0);
        let a3 = Content::array_at(1);
        let any = Content::array_any();

        assert!(a1.may_match(&a2));
        assert!(a1.definitely_matches(&a2));
        assert!(!a1.may_match(&a3));

        // Any index matches everything
        assert!(any.may_match(&a1));
        assert!(any.may_match(&a3));
        assert!(!any.definitely_matches(&a1)); // But doesn't definitely match
    }

    #[test]
    fn test_wildcard() {
        let wildcard = Content::wildcard();
        let field = Content::field("x");
        let array = Content::array_at(0);

        assert!(wildcard.may_match(&field));
        assert!(wildcard.may_match(&array));
        assert!(!wildcard.definitely_matches(&field)); // Wildcard doesn't definitely match
    }

    #[test]
    fn test_content_set() {
        let mut set = ContentSet::new();
        set.add(Content::field("name"));
        set.add(Content::field("value"));

        assert!(set.includes(&Content::field("name")));
        assert!(set.includes(&Content::field("value")));
        assert!(!set.includes(&Content::field("other")));

        assert_eq!(set.len(), 2);
    }

    #[test]
    fn test_content_display() {
        assert_eq!(Content::field("x").to_string(), "Field[x]");
        assert_eq!(Content::array_at(5).to_string(), "Array[5]");
        assert_eq!(Content::array_any().to_string(), "Array[*]");
        assert_eq!(Content::collection().to_string(), "Element");
    }
}
