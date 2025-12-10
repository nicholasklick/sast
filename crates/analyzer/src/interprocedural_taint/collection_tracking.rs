//! Collection Index Tracking State
//!
//! Manages state for index-precise taint tracking through collections (lists, maps).
//! This tracks which indices/keys in collections contain tainted data.

use std::collections::{HashMap, HashSet};
use gittera_parser::ast::AstNode;

/// Maximum size for tracked collections before resetting.
/// Prevents unbounded state growth during duplicate analysis passes.
pub const MAX_TRACKED_LIST_SIZE: usize = 3;

/// State for tracking collection indices and taint
#[derive(Debug, Clone)]
pub struct CollectionTrackingState {
    /// Map of collection variable name to current list size
    pub list_sizes: HashMap<String, usize>,
    /// Set of tainted collection keys (e.g., "varName@0", "varName[key]")
    pub tainted_keys: HashSet<String>,
}

impl CollectionTrackingState {
    pub fn new() -> Self {
        Self {
            list_sizes: HashMap::new(),
            tainted_keys: HashSet::new(),
        }
    }

    /// Reset state for a specific collection (used when new collection is created)
    pub fn reset_collection(&mut self, collection_var: &str) {
        self.list_sizes.insert(collection_var.to_string(), 0);
        let prefix = format!("{}@", collection_var);
        self.tainted_keys.retain(|k| !k.starts_with(&prefix));
    }

    /// Get current size of a tracked list
    pub fn get_list_size(&self, collection_var: &str) -> usize {
        self.list_sizes.get(collection_var).copied().unwrap_or(0)
    }

    /// Set size for a tracked list
    pub fn set_list_size(&mut self, collection_var: &str, size: usize) {
        self.list_sizes.insert(collection_var.to_string(), size);
    }

    /// Check if a taint key exists in the tracking state
    pub fn is_key_tainted(&self, key: &str) -> bool {
        self.tainted_keys.contains(key)
    }

    /// Add a tainted key
    pub fn add_tainted_key(&mut self, key: String) {
        self.tainted_keys.insert(key);
    }

    /// Remove a tainted key
    pub fn remove_tainted_key(&mut self, key: &str) {
        self.tainted_keys.remove(key);
    }

    /// Shift indices after a remove operation
    /// When an element is removed at index, all higher indices shift down
    pub fn shift_indices_down(&mut self, collection_var: &str, removed_idx: usize) {
        let prefix = format!("{}@", collection_var);

        // Collect indices that need to be shifted
        let mut indices_to_remove: Vec<usize> = Vec::new();
        let mut indices_to_add: Vec<usize> = Vec::new();

        for key in &self.tainted_keys {
            if key.starts_with(&prefix) {
                if let Ok(idx) = key[prefix.len()..].parse::<usize>() {
                    if idx > removed_idx {
                        indices_to_remove.push(idx);
                        indices_to_add.push(idx - 1);
                    } else if idx == removed_idx {
                        // The removed index is no longer tainted
                        indices_to_remove.push(idx);
                    }
                }
            }
        }

        // Apply the shifts
        for idx in indices_to_remove {
            self.tainted_keys.remove(&format!("{}@{}", collection_var, idx));
        }
        for idx in indices_to_add {
            self.tainted_keys.insert(format!("{}@{}", collection_var, idx));
        }
    }

    /// Shift indices up after an insert operation
    /// When an element is inserted at index, all indices at or after shift up
    pub fn shift_indices_up(&mut self, collection_var: &str, insert_idx: usize) {
        let prefix = format!("{}@", collection_var);

        // Collect indices that need to be shifted (process highest first)
        let mut indices_to_shift: Vec<usize> = Vec::new();

        for key in &self.tainted_keys {
            if key.starts_with(&prefix) {
                if let Ok(idx) = key[prefix.len()..].parse::<usize>() {
                    if idx >= insert_idx {
                        indices_to_shift.push(idx);
                    }
                }
            }
        }

        // Sort descending to process highest indices first
        indices_to_shift.sort_by(|a, b| b.cmp(a));

        // Apply the shifts
        for idx in indices_to_shift {
            self.tainted_keys.remove(&format!("{}@{}", collection_var, idx));
            self.tainted_keys.insert(format!("{}@{}", collection_var, idx + 1));
        }
    }
}

impl Default for CollectionTrackingState {
    fn default() -> Self {
        Self::new()
    }
}

/// Check if a node represents collection initialization
/// e.g., new ArrayList<>(), [], {}
pub fn is_collection_initialization(node: &AstNode) -> bool {
    let text = node.text.trim();

    // Java collection patterns - handle both simple and fully-qualified names
    let collection_types = [
        "ArrayList", "LinkedList", "Vector", "Stack", "ArrayDeque",
        "PriorityQueue", "CopyOnWriteArrayList", "HashSet", "TreeSet",
        "HashMap", "TreeMap", "LinkedHashMap", "Hashtable",
    ];

    // Check for "new" followed by collection type
    if text.contains("new ") {
        for ctype in collection_types {
            // Match "new ArrayList", "new java.util.ArrayList", etc.
            if text.contains(&format!("new {}", ctype))
                || text.contains(&format!(".{}<", ctype))
                || text.contains(&format!(".{}(", ctype))
                || text.ends_with(&format!(".{}", ctype))
            {
                return true;
            }
        }
    }

    // Python list/dict patterns
    if text == "[]" || text == "{}" || text.starts_with('[') || text.starts_with('{') {
        return true;
    }

    // Recursive check in children
    for child in &node.children {
        if is_collection_initialization(child) {
            return true;
        }
    }

    false
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_shift_indices_down() {
        let mut state = CollectionTrackingState::new();
        state.add_tainted_key("list@0".to_string());
        state.add_tainted_key("list@1".to_string());
        state.add_tainted_key("list@2".to_string());
        state.set_list_size("list", 3);

        // Remove element at index 1
        state.shift_indices_down("list", 1);

        // Index 0 unchanged, index 1 removed, index 2 -> index 1
        assert!(state.is_key_tainted("list@0"));
        assert!(state.is_key_tainted("list@1")); // was index 2
        assert!(!state.is_key_tainted("list@2")); // shifted down
    }

    #[test]
    fn test_shift_indices_up() {
        let mut state = CollectionTrackingState::new();
        state.add_tainted_key("list@1".to_string());
        state.add_tainted_key("list@2".to_string());
        state.set_list_size("list", 3);

        // Insert at index 1
        state.shift_indices_up("list", 1);

        // Index 0 unchanged, index 1 -> 2, index 2 -> 3
        assert!(!state.is_key_tainted("list@1")); // shifted up
        assert!(state.is_key_tainted("list@2")); // was index 1
        assert!(state.is_key_tainted("list@3")); // was index 2
    }

    #[test]
    fn test_reset_collection() {
        let mut state = CollectionTrackingState::new();
        state.add_tainted_key("list@0".to_string());
        state.add_tainted_key("list@1".to_string());
        state.add_tainted_key("other@0".to_string());
        state.set_list_size("list", 2);
        state.set_list_size("other", 1);

        state.reset_collection("list");

        assert!(!state.is_key_tainted("list@0"));
        assert!(!state.is_key_tainted("list@1"));
        assert!(state.is_key_tainted("other@0"));
        assert_eq!(state.get_list_size("list"), 0);
        assert_eq!(state.get_list_size("other"), 1);
    }
}
