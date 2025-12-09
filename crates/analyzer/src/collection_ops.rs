//! Collection Operations for Language-Agnostic Taint Tracking
//!
//! This module provides a unified abstraction for collection operations across
//! languages (Java, Python, JavaScript, etc.), enabling index-precise taint
//! tracking through lists, arrays, and maps.
//!
//! ## Language Mappings
//!
//! | Operation      | Java              | Python           | JavaScript       |
//! |---------------|-------------------|------------------|------------------|
//! | ListAppend    | list.add(val)     | list.append(val) | arr.push(val)    |
//! | ListInsert    | list.add(i, val)  | list.insert(i,v) | arr.splice(i,0,v)|
//! | ListGet       | list.get(i)       | list[i]          | arr[i]           |
//! | ListSet       | list.set(i, val)  | list[i] = val    | arr[i] = val     |
//! | ListRemoveLast| -                 | list.pop()       | arr.pop()        |
//! | ListRemoveAt  | list.remove(i)    | list.pop(i)      | arr.splice(i,1)  |
//! | ListRemoveFirst| -               | -                | arr.shift()      |
//! | MapPut        | map.put(k, v)     | dict[k] = v      | obj[k] = v       |
//! | MapGet        | map.get(k)        | dict[k]/dict.get | obj[k]           |

use gittera_parser::ast::{AstNode, AstNodeKind, LiteralValue};
use gittera_parser::language::Language;

/// Represents a collection operation detected from AST
#[derive(Debug, Clone, PartialEq)]
pub enum CollectionOperation {
    /// Append to end of list: list.add(val), list.append(val), arr.push(val)
    ListAppend {
        collection_var: String,
        value_node_idx: usize,
    },

    /// Insert at specific index: list.add(i, val), list.insert(i, val)
    ListInsert {
        collection_var: String,
        index: Option<usize>,
        value_node_idx: usize,
    },

    /// Get element at index: list.get(i), list[i], arr[i]
    ListGet {
        collection_var: String,
        index: Option<usize>,
    },

    /// Set element at index: list.set(i, val), list[i] = val
    ListSet {
        collection_var: String,
        index: Option<usize>,
        value_node_idx: usize,
    },

    /// Remove and return last element: list.pop(), arr.pop()
    ListRemoveLast {
        collection_var: String,
    },

    /// Remove element at specific index: list.remove(i), list.pop(i), arr.splice(i, 1)
    ListRemoveAt {
        collection_var: String,
        index: Option<usize>,
    },

    /// Remove and return first element: arr.shift()
    ListRemoveFirst {
        collection_var: String,
    },

    /// Insert at beginning: arr.unshift(val)
    ListPrepend {
        collection_var: String,
        value_node_idx: usize,
    },

    /// Put key-value pair: map.put(k, v), dict[k] = v, obj[k] = v
    MapPut {
        collection_var: String,
        key: Option<String>,
        value_node_idx: usize,
    },

    /// Get value by key: map.get(k), dict[k], obj[k]
    MapGet {
        collection_var: String,
        key: Option<String>,
    },

    /// Remove key: map.remove(k), del dict[k], delete obj[k]
    MapRemove {
        collection_var: String,
        key: Option<String>,
    },
}

impl CollectionOperation {
    /// Get the collection variable name
    pub fn collection_var(&self) -> &str {
        match self {
            CollectionOperation::ListAppend { collection_var, .. } |
            CollectionOperation::ListInsert { collection_var, .. } |
            CollectionOperation::ListGet { collection_var, .. } |
            CollectionOperation::ListSet { collection_var, .. } |
            CollectionOperation::ListRemoveLast { collection_var } |
            CollectionOperation::ListRemoveAt { collection_var, .. } |
            CollectionOperation::ListRemoveFirst { collection_var } |
            CollectionOperation::ListPrepend { collection_var, .. } |
            CollectionOperation::MapPut { collection_var, .. } |
            CollectionOperation::MapGet { collection_var, .. } |
            CollectionOperation::MapRemove { collection_var, .. } => collection_var,
        }
    }

    /// Check if this is a list operation
    pub fn is_list_operation(&self) -> bool {
        matches!(self,
            CollectionOperation::ListAppend { .. } |
            CollectionOperation::ListInsert { .. } |
            CollectionOperation::ListGet { .. } |
            CollectionOperation::ListSet { .. } |
            CollectionOperation::ListRemoveLast { .. } |
            CollectionOperation::ListRemoveAt { .. } |
            CollectionOperation::ListRemoveFirst { .. } |
            CollectionOperation::ListPrepend { .. }
        )
    }

    /// Check if this is a map operation
    pub fn is_map_operation(&self) -> bool {
        matches!(self,
            CollectionOperation::MapPut { .. } |
            CollectionOperation::MapGet { .. } |
            CollectionOperation::MapRemove { .. }
        )
    }

    /// Check if this operation modifies the collection
    pub fn is_mutating(&self) -> bool {
        !matches!(self,
            CollectionOperation::ListGet { .. } |
            CollectionOperation::MapGet { .. }
        )
    }
}

/// Detect collection operation from a CallExpression node
pub fn detect_collection_op_from_call(
    callee: &str,
    node: &AstNode,
    language: Language,
) -> Option<CollectionOperation> {
    #[cfg(debug_assertions)]
    if callee.contains("append") || callee.contains("insert") || callee.contains("push") {
        eprintln!("[DEBUG] detect_collection_op_from_call: callee='{}' language={:?}", callee, language);
    }
    match language {
        Language::Java | Language::Kotlin | Language::Scala => detect_java_collection_op(callee, node),
        Language::Python => detect_python_collection_op(callee, node),
        Language::JavaScript | Language::TypeScript => detect_js_collection_op(callee, node),
        _ => None,
    }
}

/// Detect Java collection operations
fn detect_java_collection_op(callee: &str, node: &AstNode) -> Option<CollectionOperation> {
    // Extract receiver variable: "list.add" -> "list"
    let parts: Vec<&str> = callee.rsplitn(2, '.').collect();
    if parts.len() != 2 {
        return None;
    }
    let method = parts[0];
    let collection_var = parts[1].to_string();

    // Get argument count
    let args = get_call_arguments(node);
    let arg_count = args.len();

    match method {
        "add" => {
            if arg_count == 1 {
                // list.add(value) - append
                Some(CollectionOperation::ListAppend {
                    collection_var,
                    value_node_idx: 0,
                })
            } else if arg_count == 2 {
                // list.add(index, value) - insert at index
                let index = extract_index_from_arg(&args, 0);
                Some(CollectionOperation::ListInsert {
                    collection_var,
                    index,
                    value_node_idx: 1,
                })
            } else {
                None
            }
        }
        "get" => {
            if arg_count >= 1 {
                let index = extract_index_from_arg(&args, 0);
                let key = extract_string_key_from_arg(&args, 0);
                // Could be list.get(i) or map.get(k)
                if key.is_some() {
                    Some(CollectionOperation::MapGet {
                        collection_var,
                        key,
                    })
                } else {
                    Some(CollectionOperation::ListGet {
                        collection_var,
                        index,
                    })
                }
            } else {
                None
            }
        }
        "set" => {
            if arg_count >= 2 {
                let index = extract_index_from_arg(&args, 0);
                Some(CollectionOperation::ListSet {
                    collection_var,
                    index,
                    value_node_idx: 1,
                })
            } else {
                None
            }
        }
        "remove" => {
            if arg_count >= 1 {
                let index = extract_index_from_arg(&args, 0);
                let key = extract_string_key_from_arg(&args, 0);
                if key.is_some() {
                    Some(CollectionOperation::MapRemove {
                        collection_var,
                        key,
                    })
                } else {
                    Some(CollectionOperation::ListRemoveAt {
                        collection_var,
                        index,
                    })
                }
            } else {
                None
            }
        }
        "put" => {
            if arg_count >= 2 {
                let key = extract_string_key_from_arg(&args, 0);
                Some(CollectionOperation::MapPut {
                    collection_var,
                    key,
                    value_node_idx: 1,
                })
            } else {
                None
            }
        }
        _ => None,
    }
}

/// Detect Python collection operations
fn detect_python_collection_op(callee: &str, node: &AstNode) -> Option<CollectionOperation> {
    let parts: Vec<&str> = callee.rsplitn(2, '.').collect();
    if parts.len() != 2 {
        return None;
    }
    let method = parts[0];
    let collection_var = parts[1].to_string();

    let args = get_call_arguments(node);
    let arg_count = args.len();

    #[cfg(debug_assertions)]
    if method == "append" || method == "insert" {
        eprintln!("[DEBUG] detect_python_collection_op: callee='{}' method='{}' arg_count={}", callee, method, arg_count);
    }

    match method {
        "append" => {
            if arg_count >= 1 {
                Some(CollectionOperation::ListAppend {
                    collection_var,
                    value_node_idx: 0,
                })
            } else {
                None
            }
        }
        "insert" => {
            if arg_count >= 2 {
                let index = extract_index_from_arg(&args, 0);
                Some(CollectionOperation::ListInsert {
                    collection_var,
                    index,
                    value_node_idx: 1,
                })
            } else {
                None
            }
        }
        "pop" => {
            if arg_count == 0 {
                Some(CollectionOperation::ListRemoveLast {
                    collection_var,
                })
            } else {
                let index = extract_index_from_arg(&args, 0);
                Some(CollectionOperation::ListRemoveAt {
                    collection_var,
                    index,
                })
            }
        }
        "get" => {
            // dict.get(key) or dict.get(key, default)
            if arg_count >= 1 {
                let key = extract_string_key_from_arg(&args, 0);
                Some(CollectionOperation::MapGet {
                    collection_var,
                    key,
                })
            } else {
                None
            }
        }
        "extend" => {
            // list.extend(iterable) - treated as append for now
            if arg_count >= 1 {
                Some(CollectionOperation::ListAppend {
                    collection_var,
                    value_node_idx: 0,
                })
            } else {
                None
            }
        }
        _ => None,
    }
}

/// Detect JavaScript collection operations
fn detect_js_collection_op(callee: &str, node: &AstNode) -> Option<CollectionOperation> {
    let parts: Vec<&str> = callee.rsplitn(2, '.').collect();
    if parts.len() != 2 {
        return None;
    }
    let method = parts[0];
    let collection_var = parts[1].to_string();

    let args = get_call_arguments(node);
    let arg_count = args.len();

    match method {
        "push" => {
            if arg_count >= 1 {
                Some(CollectionOperation::ListAppend {
                    collection_var,
                    value_node_idx: 0,
                })
            } else {
                None
            }
        }
        "pop" => {
            Some(CollectionOperation::ListRemoveLast {
                collection_var,
            })
        }
        "shift" => {
            Some(CollectionOperation::ListRemoveFirst {
                collection_var,
            })
        }
        "unshift" => {
            if arg_count >= 1 {
                Some(CollectionOperation::ListPrepend {
                    collection_var,
                    value_node_idx: 0,
                })
            } else {
                None
            }
        }
        "splice" => {
            // arr.splice(start, deleteCount, ...items)
            // Complex operation - handle common cases
            if arg_count >= 2 {
                let index = extract_index_from_arg(&args, 0);
                let delete_count = extract_index_from_arg(&args, 1);

                if delete_count == Some(0) && arg_count >= 3 {
                    // splice(i, 0, item) = insert at index
                    Some(CollectionOperation::ListInsert {
                        collection_var,
                        index,
                        value_node_idx: 2,
                    })
                } else if arg_count == 2 {
                    // splice(i, n) = remove n elements at index
                    Some(CollectionOperation::ListRemoveAt {
                        collection_var,
                        index,
                    })
                } else {
                    // Complex splice - treat conservatively as remove + insert
                    Some(CollectionOperation::ListRemoveAt {
                        collection_var,
                        index,
                    })
                }
            } else {
                None
            }
        }
        _ => None,
    }
}

/// Detect collection operation from subscript/index access
pub fn detect_collection_op_from_subscript(
    base_var: &str,
    key_or_index: &AstNode,
    is_assignment: bool,
    language: Language,
) -> Option<CollectionOperation> {
    let collection_var = base_var.to_string();

    // Try to extract string key (for maps/dicts)
    let key = extract_string_from_node(key_or_index);

    // Try to extract numeric index (for arrays/lists)
    let index = extract_index_from_node(key_or_index);

    if is_assignment {
        if key.is_some() {
            Some(CollectionOperation::MapPut {
                collection_var,
                key,
                value_node_idx: 0, // Will be set by caller
            })
        } else {
            Some(CollectionOperation::ListSet {
                collection_var,
                index,
                value_node_idx: 0, // Will be set by caller
            })
        }
    } else {
        if key.is_some() {
            Some(CollectionOperation::MapGet {
                collection_var,
                key,
            })
        } else {
            Some(CollectionOperation::ListGet {
                collection_var,
                index,
            })
        }
    }
}

/// Generate the taint tracking key for a collection element
///
/// Lists use `@` notation: `list@0`, `list@1`
/// Maps use bracket notation: `map[keyA]`, `map[keyB]`
pub fn make_taint_key(collection_var: &str, op: &CollectionOperation, current_size: usize) -> Option<String> {
    match op {
        CollectionOperation::ListAppend { .. } => {
            // Append adds at current size
            Some(format!("{}@{}", collection_var, current_size))
        }
        CollectionOperation::ListInsert { index, .. } => {
            index.map(|i| format!("{}@{}", collection_var, i))
        }
        CollectionOperation::ListGet { index, .. } |
        CollectionOperation::ListSet { index, .. } |
        CollectionOperation::ListRemoveAt { index, .. } => {
            index.map(|i| format!("{}@{}", collection_var, i))
        }
        CollectionOperation::ListPrepend { .. } => {
            Some(format!("{}@0", collection_var))
        }
        CollectionOperation::ListRemoveLast { .. } => {
            if current_size > 0 {
                Some(format!("{}@{}", collection_var, current_size - 1))
            } else {
                None
            }
        }
        CollectionOperation::ListRemoveFirst { .. } => {
            Some(format!("{}@0", collection_var))
        }
        CollectionOperation::MapPut { key, .. } |
        CollectionOperation::MapGet { key, .. } |
        CollectionOperation::MapRemove { key, .. } => {
            key.as_ref().map(|k| format!("{}[{}]", collection_var, k))
        }
    }
}

// Helper functions

fn get_call_arguments(node: &AstNode) -> Vec<&AstNode> {
    for child in &node.children {
        if matches!(&child.kind, AstNodeKind::Other { node_type }
            if node_type == "argument_list" || node_type == "arguments")
        {
            return child.children.iter()
                .filter(|c| !matches!(&c.kind, AstNodeKind::Other { node_type }
                    if node_type == "(" || node_type == ")" || node_type == ","))
                .collect();
        }
    }
    Vec::new()
}

fn extract_index_from_arg(args: &[&AstNode], idx: usize) -> Option<usize> {
    args.get(idx).and_then(|n| extract_index_from_node(n))
}

fn extract_index_from_node(node: &AstNode) -> Option<usize> {
    match &node.kind {
        AstNodeKind::Literal { value: LiteralValue::Number(n) } => {
            n.parse::<usize>().ok()
        }
        AstNodeKind::Other { node_type } if node_type == "integer" || node_type == "number" => {
            node.text.trim().parse::<usize>().ok()
        }
        _ => {
            // Try parsing from text
            node.text.trim().parse::<usize>().ok()
        }
    }
}

fn extract_string_key_from_arg(args: &[&AstNode], idx: usize) -> Option<String> {
    args.get(idx).and_then(|n| extract_string_from_node(n))
}

fn extract_string_from_node(node: &AstNode) -> Option<String> {
    match &node.kind {
        AstNodeKind::Literal { value: LiteralValue::String(s) } => {
            Some(s.trim_matches(|c| c == '"' || c == '\'').to_string())
        }
        AstNodeKind::Other { node_type } if node_type == "string" || node_type == "string_literal" => {
            let text = node.text.trim();
            if (text.starts_with('"') && text.ends_with('"')) ||
               (text.starts_with('\'') && text.ends_with('\'')) {
                Some(text[1..text.len()-1].to_string())
            } else {
                None
            }
        }
        _ => {
            // Try to extract quoted string from text
            let text = node.text.trim();
            if (text.starts_with('"') && text.ends_with('"')) ||
               (text.starts_with('\'') && text.ends_with('\'')) {
                Some(text[1..text.len()-1].to_string())
            } else {
                None
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_make_taint_key_list_append() {
        let op = CollectionOperation::ListAppend {
            collection_var: "myList".to_string(),
            value_node_idx: 0,
        };
        assert_eq!(make_taint_key("myList", &op, 0), Some("myList@0".to_string()));
        assert_eq!(make_taint_key("myList", &op, 3), Some("myList@3".to_string()));
    }

    #[test]
    fn test_make_taint_key_list_get() {
        let op = CollectionOperation::ListGet {
            collection_var: "arr".to_string(),
            index: Some(5),
        };
        assert_eq!(make_taint_key("arr", &op, 10), Some("arr@5".to_string()));
    }

    #[test]
    fn test_make_taint_key_map_put() {
        let op = CollectionOperation::MapPut {
            collection_var: "config".to_string(),
            key: Some("apiKey".to_string()),
            value_node_idx: 1,
        };
        assert_eq!(make_taint_key("config", &op, 0), Some("config[apiKey]".to_string()));
    }

    #[test]
    fn test_is_mutating() {
        let get = CollectionOperation::ListGet {
            collection_var: "x".to_string(),
            index: Some(0),
        };
        assert!(!get.is_mutating());

        let append = CollectionOperation::ListAppend {
            collection_var: "x".to_string(),
            value_node_idx: 0,
        };
        assert!(append.is_mutating());
    }
}
