//! Source and Sink Detection for Taint Analysis
//!
//! Functions to detect taint sources (user input) and sinks (dangerous operations).

use super::InterproceduralTaintAnalysis;
use crate::taint::TaintSink;

impl InterproceduralTaintAnalysis {
    /// Check if a function/method name represents a taint source
    pub(super) fn is_source_function(&self, name: &str) -> bool {
        // Check flow registry first
        if let Some(summary) = self.flow_registry.get(name) {
            if summary.is_source {
                return true;
            }
        }
        // Also check by just the method name (e.g., "getParameter" from "request.getParameter")
        let method_name = name.split('.').last().unwrap_or(name);
        if let Some(summary) = self.flow_registry.get(method_name) {
            if summary.is_source {
                return true;
            }
        }

        // Check for cookie method calls that return user input
        let name_lower = name.to_lowercase();
        let method_lower = method_name.to_lowercase();

        // Match .getValue()/.getName() only if receiver looks like a cookie variable
        if method_lower == "getvalue" || method_lower == "getname" || method_lower == "getcomment" {
            let receiver = name.rsplitn(2, '.').nth(1).unwrap_or("");
            let receiver_lower = receiver.to_lowercase();
            if receiver_lower.contains("cookie")
                || receiver_lower == "c"
                || (receiver_lower.starts_with("the") && receiver_lower.contains("cook"))
            {
                #[cfg(debug_assertions)]
                eprintln!("[DEBUG] is_source_function: '{}' matched as cookie method (receiver='{}')", name, receiver);
                return true;
            }
        }

        // Match headers.nextElement() patterns
        if method_lower == "nextelement" {
            let receiver = name.rsplitn(2, '.').nth(1).unwrap_or("");
            let receiver_lower = receiver.to_lowercase();
            if receiver_lower.contains("header") {
                #[cfg(debug_assertions)]
                eprintln!("[DEBUG] is_source_function: '{}' matched as headers enumeration", name);
                return true;
            }
        }

        // Match helper class methods that wrap request.getParameter
        let is_getter = method_lower.starts_with("get") || method_lower.starts_with("read")
            || method_lower.starts_with("fetch") || method_lower.starts_with("retrieve");

        if is_getter && (method_lower.contains("parameter") || method_lower.contains("param")) {
            #[cfg(debug_assertions)]
            eprintln!("[DEBUG] is_source_function: '{}' matched as parameter getter method", name);
            return true;
        }
        if is_getter && method_lower.contains("header") {
            #[cfg(debug_assertions)]
            eprintln!("[DEBUG] is_source_function: '{}' matched as header getter method", name);
            return true;
        }
        if is_getter && method_lower.contains("cookie") {
            #[cfg(debug_assertions)]
            eprintln!("[DEBUG] is_source_function: '{}' matched as cookie getter method", name);
            return true;
        }
        if is_getter && (method_lower.contains("body") || method_lower.contains("input") || method_lower.contains("data")) {
            #[cfg(debug_assertions)]
            eprintln!("[DEBUG] is_source_function: '{}' matched as body/input getter method", name);
            return true;
        }
        if is_getter && method_lower.contains("content")
            && !method_lower.contains("textcontent")
            && !method_lower.contains("nodecontent")
            && (method_lower.contains("request") || name_lower.contains("request") || name_lower.contains("req."))
        {
            #[cfg(debug_assertions)]
            eprintln!("[DEBUG] is_source_function: '{}' matched as request content getter method", name);
            return true;
        }

        // Fall back to legacy sources
        self.sources.iter().any(|s| {
            let source_lower = s.name.to_lowercase();
            let matches = name_lower.contains(&source_lower) || source_lower.contains(&name_lower);
            #[cfg(debug_assertions)]
            if matches {
                eprintln!("[DEBUG] is_source_function: '{}' matched source '{}' (name_contains_src={}, src_contains_name={})",
                    name, s.name, name_lower.contains(&source_lower), source_lower.contains(&name_lower));
            }
            matches
        })
    }

    /// Check if a member expression path matches a source pattern
    /// Handles patterns like "req.body", "request.query", "req.body.code"
    pub(super) fn is_source_expression(&self, path: &str) -> bool {
        // Check flow registry
        if let Some(summary) = self.flow_registry.get(path) {
            if summary.is_source {
                return true;
            }
        }

        let path_lower = path.to_lowercase();
        self.sources.iter().any(|s| {
            let source_lower = s.name.to_lowercase();
            path_lower.starts_with(&source_lower)
                || path_lower.contains(&source_lower)
                || source_lower.contains(&path_lower)
        })
    }

    /// Check if a function/method name represents a taint sink
    pub(super) fn is_sink_function(&self, name: &str) -> bool {
        // Check flow registry first
        if let Some(summary) = self.flow_registry.get(name) {
            if summary.is_sink.is_some() {
                return true;
            }
        }
        let method_name = name.split('.').last().unwrap_or(name);
        if let Some(summary) = self.flow_registry.get(method_name) {
            if summary.is_sink.is_some() {
                return true;
            }
        }

        // Common method names that should NOT match by method name alone
        let common_methods = [
            "get", "set", "put", "add", "remove", "contains", "size", "length",
            "open", "close", "read", "write", "run", "call", "send", "recv",
            "parse", "format", "str", "int", "float", "list", "dict",
            "append",
            "query", "update", "insert", "delete", "select",
        ];
        let method_name_lower = method_name.to_lowercase();
        let name_lower = name.to_lowercase();

        // Special case: format/printf on HTTP response writers
        let is_response_writer_output = (method_name_lower == "format" || method_name_lower == "printf")
            && (name_lower.contains("getwriter") || name_lower.contains("printwriter")
                || name_lower.contains("out.") || name_lower.contains("writer."));
        if is_response_writer_output {
            return true;
        }

        // Special case: setAttribute/putValue on session objects
        let is_session_set_attribute = (method_name_lower == "setattribute" || method_name_lower == "putvalue")
            && (name_lower.contains("getsession") || name_lower.contains("session."));
        if is_session_set_attribute {
            return true;
        }

        // Special case: Spring JdbcTemplate SQL methods
        let is_jdbc_template_sink = (method_name_lower == "query"
            || method_name_lower == "queryforobject"
            || method_name_lower == "queryforlist"
            || method_name_lower == "queryformap"
            || method_name_lower == "update"
            || method_name_lower == "batchupdate"
            || method_name_lower == "execute")
            && (name_lower.contains("jdbctemplate") || name_lower.contains("namedparameterjdbctemplate"));
        if is_jdbc_template_sink {
            return true;
        }

        // Special case: EntityManager JPA methods
        let is_entity_manager_sink = (method_name_lower == "createquery"
            || method_name_lower == "createnativequery"
            || method_name_lower == "nativequery")
            && name_lower.contains("entitymanager");
        if is_entity_manager_sink {
            return true;
        }

        let is_common_method = common_methods.contains(&method_name_lower.as_str());

        // Safe variants that should NOT be considered sinks even if they match a sink pattern
        // e.g., yaml.safe_load should NOT match yaml.load as a deserialization sink
        let safe_method_prefixes = ["safe_", "safe"];
        let is_safe_variant = safe_method_prefixes.iter().any(|prefix| method_name_lower.starts_with(prefix));
        if is_safe_variant {
            return false;
        }

        // Fall back to legacy sinks
        self.sinks.iter().any(|s| {
            let sink_lower = s.name.to_lowercase();
            let sink_method = s.name.split('.').last().unwrap_or(&s.name).to_lowercase();

            // Exact match
            if name_lower == sink_lower {
                return true;
            }

            // Match by method name ending/starting with sink method
            if !is_common_method && sink_method.len() >= 4 {
                let sink_class = s.name.split('.').next().unwrap_or("");
                let caller_class = name.split('.').rev().nth(1).unwrap_or("");
                let class_matches = sink_class.is_empty()
                    || sink_class.to_lowercase() == caller_class.to_lowercase()
                    || name_lower.contains(&sink_class.to_lowercase());

                if class_matches {
                    if method_name_lower.ends_with(&sink_method) {
                        return true;
                    }
                    if method_name_lower.starts_with(&sink_method) {
                        return true;
                    }
                }
            }

            // Match by method name only if not common
            if !is_common_method && method_name_lower == sink_method {
                return true;
            }

            false
        })
    }

    /// Find a sink by name from the configured sinks list
    pub(super) fn find_sink_by_name(&self, name: &str) -> Option<&TaintSink> {
        let name_lower = name.to_lowercase();
        let method_name = name.split('.').last().unwrap_or(name).to_lowercase();

        // Safe variants should NOT be treated as sinks
        let safe_method_prefixes = ["safe_", "safe"];
        if safe_method_prefixes.iter().any(|prefix| method_name.starts_with(prefix)) {
            return None;
        }

        // First try exact match
        if let Some(sink) = self.sinks.iter().find(|s| s.name.to_lowercase() == name_lower) {
            return Some(sink);
        }

        // Then try method name match
        self.sinks.iter().find(|s| {
            let sink_method = s.name.split('.').last().unwrap_or(&s.name).to_lowercase();
            method_name == sink_method
                || method_name.ends_with(&sink_method)
                || method_name.starts_with(&sink_method)
        })
    }
}
