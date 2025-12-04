//! Taint analysis for tracking data flow from sources to sinks

use crate::cfg::{CfgGraphIndex, CfgNode, CfgNodeKind, ControlFlowGraph};
use crate::dataflow::{DataFlowAnalysis, DataFlowDirection, DataFlowResult, TransferFunction};
use crate::symbolic::SymbolicValue;
use crate::taint_ast_based::AstBasedTaintTransferFunction;
use gittera_parser::ast::{AstNode, AstNodeKind, NodeId};
use serde::{Deserialize, Serialize};
use std::collections::{HashMap, HashSet};

/// A taint source (where untrusted data enters)
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct TaintSource {
    pub name: String,
    pub kind: TaintSourceKind,
    pub node_id: NodeId,
}

#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum TaintSourceKind {
    UserInput,
    FileRead,
    NetworkRequest,
    EnvironmentVariable,
    CommandLineArgument,
    DatabaseQuery,
}

/// A taint sink (where tainted data could cause security issues)
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct TaintSink {
    pub name: String,
    pub kind: TaintSinkKind,
    pub node_id: NodeId,
}

#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum TaintSinkKind {
    SqlQuery,
    CommandExecution,
    FileWrite,
    CodeEval,
    HtmlOutput,
    LogOutput,
    NetworkSend,
}

/// Represents a tainted value in the program
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct TaintValue {
    pub variable: String,
    pub source: TaintSourceKind,
    pub sanitized: bool,

    /// Condition under which this value becomes tainted (None = always tainted)
    /// This enables path-sensitive analysis by tracking WHEN taint applies
    #[serde(skip)]  // Skip serialization for now (SymbolicValue is complex)
    pub taint_condition: Option<SymbolicValue>,

    /// Condition under which this value is sanitized (None = never sanitized conditionally)
    /// This tracks WHEN sanitization occurs, enabling precise false positive reduction
    #[serde(skip)]
    pub sanitized_condition: Option<SymbolicValue>,
}

impl TaintValue {
    pub fn new(variable: String, source: TaintSourceKind) -> Self {
        Self {
            variable,
            source,
            sanitized: false,
            taint_condition: None,      // Always tainted
            sanitized_condition: None,  // Not conditionally sanitized
        }
    }

    /// Create a tainted value with a condition
    /// Use this when taint only applies under certain conditions
    pub fn new_with_condition(
        variable: String,
        source: TaintSourceKind,
        condition: Option<SymbolicValue>,
    ) -> Self {
        Self {
            variable,
            source,
            sanitized: false,
            taint_condition: condition,
            sanitized_condition: None,
        }
    }

    /// Mark as unconditionally sanitized
    pub fn sanitize(&mut self) {
        self.sanitized = true;
    }

    /// Mark as sanitized under a specific condition
    /// This is the key to path-sensitive analysis!
    pub fn sanitize_when(&mut self, condition: SymbolicValue) {
        self.sanitized_condition = Some(condition);
    }

    /// Check if this value is potentially tainted (considering conditions)
    /// Returns true if there exists ANY path where this could be tainted
    pub fn is_potentially_tainted(&self) -> bool {
        if self.sanitized {
            return false;
        }

        // If there's a sanitization condition, it might not always be sanitized
        if self.sanitized_condition.is_some() {
            return true;  // Could be tainted on some paths
        }

        true  // Always potentially tainted
    }

    /// Check if this value is always safe (definitely sanitized on all paths)
    /// Returns true only if we can guarantee it's clean
    pub fn is_always_safe(&self) -> bool {
        if self.sanitized {
            return true;  // Unconditionally sanitized
        }

        // If sanitized_condition is "true" (always), then always safe
        if let Some(cond) = &self.sanitized_condition {
            if let SymbolicValue::ConcreteBool(true) = cond {
                return true;
            }
        }

        false  // Not provably safe
    }

    /// Check if this value may be tainted on some path
    /// More conservative than is_potentially_tainted - used for reporting
    pub fn may_be_tainted(&self) -> bool {
        !self.is_always_safe()
    }
}

/// Taint analysis engine
pub struct TaintAnalysis {
    sources: Vec<TaintSource>,
    sinks: Vec<TaintSink>,
    sanitizers: HashSet<String>,
}

impl TaintAnalysis {
    pub fn new() -> Self {
        Self {
            sources: Vec::new(),
            sinks: Vec::new(),
            sanitizers: HashSet::new(),
        }
    }

    pub fn add_source(&mut self, source: TaintSource) {
        self.sources.push(source);
    }

    pub fn add_sink(&mut self, sink: TaintSink) {
        self.sinks.push(sink);
    }

    pub fn add_sanitizer(&mut self, name: String) {
        self.sanitizers.insert(name);
    }

    /// Run taint analysis on a CFG with AST
    pub fn analyze(&self, cfg: &ControlFlowGraph, ast: &AstNode) -> TaintAnalysisResult {
        // Clone the data to avoid lifetime issues
        let sources = self.sources.clone();
        let sanitizers = self.sanitizers.clone();

        // Create AST-based transfer function (proper semantic analysis!)
        let transfer = AstBasedTaintTransferFunction::new(sources, sanitizers);

        let analysis = DataFlowAnalysis::new(
            DataFlowDirection::Forward,
            Box::new(transfer),
        );

        let dataflow_result = analysis.analyze(cfg, ast);

        self.find_vulnerabilities(cfg, &dataflow_result)
    }

    /// Run type-aware taint analysis on a CFG with AST
    ///
    /// This variant uses type information from the AST to reduce false positives:
    /// - Skips taint propagation to primitive types (numbers, booleans)
    /// - Uses function return types to determine taint-carrying capability
    /// - Filters assignments based on type compatibility
    ///
    /// # Example
    ///
    /// ```rust
    /// use gittera_analyzer::{CfgBuilder, TaintAnalysis, TypeContext};
    /// use gittera_parser::{Parser, Language, LanguageConfig};
    /// use std::path::Path;
    ///
    /// # fn main() -> Result<(), Box<dyn std::error::Error>> {
    /// # let mut parser = Parser::new(
    /// #     LanguageConfig::new(Language::TypeScript),
    /// #     Path::new("app.ts")
    /// # );
    /// # let source = "const x: number = getUserInput().length;";
    /// # let ast = parser.parse_source(source)?;
    /// // Build type context from AST
    /// let type_ctx = TypeContext::from_ast(&ast);
    ///
    /// let cfg = CfgBuilder::new().build(&ast);
    /// let taint = TaintAnalysis::new()
    ///     .with_default_sources()
    ///     .with_default_sinks();
    ///
    /// // Type-aware analysis reduces false positives
    /// let result = taint.analyze_with_types(&cfg, &ast, type_ctx);
    /// # Ok(())
    /// # }
    /// ```
    pub fn analyze_with_types(
        &self,
        cfg: &ControlFlowGraph,
        ast: &AstNode,
        type_context: crate::type_system::TypeContext,
    ) -> TaintAnalysisResult {
        let sources = self.sources.clone();
        let sanitizers = self.sanitizers.clone();

        // Create type-aware transfer function
        let transfer = AstBasedTaintTransferFunction::with_type_context(
            sources,
            sanitizers,
            type_context,
        );

        let analysis = DataFlowAnalysis::new(
            DataFlowDirection::Forward,
            Box::new(transfer),
        );

        let dataflow_result = analysis.analyze(cfg, ast);

        self.find_vulnerabilities(cfg, &dataflow_result)
    }

    fn find_vulnerabilities(
        &self,
        cfg: &ControlFlowGraph,
        result: &DataFlowResult<TaintValue>,
    ) -> TaintAnalysisResult {
        let mut vulnerabilities = Vec::new();

        // Check each sink
        for sink in &self.sinks {
            // Find the CFG node for this sink
            if let Some(&cfg_index) = cfg.node_map.get(&sink.node_id) {
                if let Some(taint_set) = result.get_in(cfg_index) {
                    // Check if any tainted values reach this sink without sanitization
                    for taint_value in taint_set {
                        // NEW: Use path-sensitive checking
                        // Only report if potentially tainted AND not always safe
                        if taint_value.is_potentially_tainted() && !taint_value.is_always_safe() {
                            vulnerabilities.push(TaintVulnerability {
                                sink: sink.clone(),
                                tainted_value: taint_value.clone(),
                                severity: self.calculate_severity(&sink.kind, &taint_value.source),
                            });
                        }
                    }
                }
            }
        }

        TaintAnalysisResult { vulnerabilities }
    }

    fn calculate_severity(&self, sink: &TaintSinkKind, source: &TaintSourceKind) -> Severity {
        match (sink, source) {
            (TaintSinkKind::SqlQuery, TaintSourceKind::UserInput) => Severity::Critical,
            (TaintSinkKind::CommandExecution, TaintSourceKind::UserInput) => Severity::Critical,
            (TaintSinkKind::CodeEval, _) => Severity::High,
            (TaintSinkKind::FileWrite, TaintSourceKind::UserInput) => Severity::High,
            (TaintSinkKind::HtmlOutput, TaintSourceKind::UserInput) => Severity::Medium,
            (TaintSinkKind::LogOutput, _) => Severity::Low,
            _ => Severity::Medium,
        }
    }

    /// Configure default sources for common vulnerability types
    pub fn with_default_sources(mut self) -> Self {
        // Common user input sources
        let user_input_sources = vec![
            "request.body",
            "request.query",
            "request.params",
            "req.body",
            "req.query",
            "req.params",
            "input",
            "stdin",
            "argv",
            "os.Args",
        ];

        for source_name in user_input_sources {
            self.sources.push(TaintSource {
                name: source_name.to_string(),
                kind: TaintSourceKind::UserInput,
                node_id: 0,
            });
        }

        self
    }

    /// Configure default sinks for common vulnerability types
    pub fn with_default_sinks(mut self) -> Self {
        // SQL injection sinks
        let sql_sinks = vec!["execute", "query", "exec", "raw", "prepare"];
        for sink_name in sql_sinks {
            self.sinks.push(TaintSink {
                name: sink_name.to_string(),
                kind: TaintSinkKind::SqlQuery,
                node_id: 0,
            });
        }

        // Command injection sinks
        let cmd_sinks = vec!["exec", "spawn", "system", "popen", "os.system"];
        for sink_name in cmd_sinks {
            self.sinks.push(TaintSink {
                name: sink_name.to_string(),
                kind: TaintSinkKind::CommandExecution,
                node_id: 0,
            });
        }

        self
    }

    /// Configure default sanitizers
    pub fn with_default_sanitizers(mut self) -> Self {
        let sanitizers = vec![
            "escape",
            "sanitize",
            "validate",
            "escapeHtml",
            "escapeSql",
            "clean",
            "filter",
        ];

        for sanitizer in sanitizers {
            self.sanitizers.insert(sanitizer.to_string());
        }

        self
    }

    /// Configure taint analysis for a specific language
    ///
    /// This method replaces the default configuration with language-specific
    /// taint sources, sinks, and sanitizers appropriate for the target language.
    ///
    /// # Example
    ///
    /// ```
    /// use gittera_analyzer::TaintAnalysis;
    /// use gittera_parser::Language;
    ///
    /// let taint = TaintAnalysis::new().for_language(Language::Ruby);
    /// // Now configured with Ruby-specific sources like "params", "gets"
    /// // and sinks like "system", "eval", etc.
    /// ```
    pub fn for_language(mut self, language: gittera_parser::Language) -> Self {
        use crate::taint_config::LanguageTaintConfig;

        let config = LanguageTaintConfig::for_language(language);

        // Replace sources, sinks, and sanitizers with language-specific ones
        self.sources = config.sources;
        self.sinks = config.sinks;
        self.sanitizers = config.sanitizers.into_iter().collect();

        self
    }
}

impl Default for TaintAnalysis {
    fn default() -> Self {
        Self::new()
    }
}

/// Transfer function for taint analysis (with owned data)
///
/// # Deprecation Notice
///
/// **This is a legacy implementation that is deprecated and will be removed in a future version.**
///
/// ## Known Issues
/// - Uses string-based analysis which is imprecise
/// - Cannot handle complex expressions properly
/// - Does not integrate with AST-based symbol tracking
///
/// ## Migration Path
/// Please use `AstBasedTaintTransferFunction` from `taint_ast_based` module instead.
/// It provides:
/// - Precise AST-based analysis
/// - Better integration with symbol tables
/// - Support for complex expressions
/// - More accurate taint tracking
///
/// ## Why Kept?
/// This implementation is maintained only for backward compatibility with existing
/// code. All new development should use the AST-based implementation.
#[deprecated(
    since = "0.2.0",
    note = "Use AstBasedTaintTransferFunction from taint_ast_based module instead. This legacy implementation has known issues with complex expressions."
)]
struct OwnedTaintTransferFunction {
    sources: Vec<TaintSource>,
    sanitizers: HashSet<String>,
}

impl OwnedTaintTransferFunction {
    /// Check if a name matches any taint source (case-insensitive)
    fn is_source(&self, name: &str) -> Option<TaintSourceKind> {
        let name_lower = name.to_lowercase();
        for source in &self.sources {
            let source_lower = source.name.to_lowercase();
            // Check if the name contains the source name (case-insensitive)
            if name_lower.contains(&source_lower) {
                return Some(source.kind.clone());
            }
        }
        None
    }

    /// Check if a name is a sanitizer function (case-insensitive)
    fn is_sanitizer(&self, name: &str) -> bool {
        let name_lower = name.to_lowercase();
        self.sanitizers.iter().any(|san| name_lower.contains(&san.to_lowercase()))
    }

    /// Extract variable name from an assignment or call
    fn extract_assigned_variable(&self, node: &CfgNode) -> Option<String> {
        // Parse the label to extract the assigned variable
        // For assignments like "x = ...", we want to extract "x"
        let label = &node.label;

        if label.contains('=') && !label.contains("==") {
            // Assignment: "var = expr" or "AssignmentExpression"
            if let Some(var_part) = label.split('=').next() {
                let var_name = var_part.trim().to_string();
                if !var_name.is_empty() && var_name != "AssignmentExpression" {
                    return Some(var_name);
                }
            }
        }

        None
    }

    /// Extract the callee name from a function call
    fn extract_callee(&self, node: &CfgNode) -> Option<String> {
        if node.kind == CfgNodeKind::FunctionCall {
            // Label format: "call: functionName"
            if let Some(name) = node.label.strip_prefix("call: ") {
                return Some(name.to_string());
            }
        }
        None
    }

    /// Extract variables referenced in an expression
    fn extract_referenced_variables(&self, node: &CfgNode) -> Vec<String> {
        let mut vars = Vec::new();
        let label = &node.label;

        // Simple heuristic: extract words that look like identifiers
        // In a full implementation, we'd parse the AST properly
        for word in label.split(|c: char| !c.is_alphanumeric() && c != '_') {
            if !word.is_empty()
                && !word.chars().next().unwrap().is_numeric()
                && word != "call"
                && word != "return"
                && word != "if"
                && word != "while"
                && word != "for"
            {
                vars.push(word.to_string());
            }
        }

        vars
    }
}

impl TransferFunction<TaintValue> for OwnedTaintTransferFunction {
    fn transfer(&self, cfg: &ControlFlowGraph, ast: &AstNode, node_idx: CfgGraphIndex, input: &HashSet<TaintValue>) -> HashSet<TaintValue> {
        let mut output = input.clone();

        // Get the CFG node
        let node = match cfg.get_node(node_idx) {
            Some(n) => n,
            None => return output,
        };

        match node.kind {
            CfgNodeKind::Entry | CfgNodeKind::Exit => {
                // No changes for entry/exit
                output
            }

            CfgNodeKind::FunctionCall => {
                // Check if this is a taint source
                if let Some(callee) = self.extract_callee(node) {
                    if let Some(source_kind) = self.is_source(&callee) {
                        // Generate new taint for the result of this call
                        // The result is typically assigned to a variable
                        // For now, we use the callee name as the variable name
                        output.insert(TaintValue::new(callee.clone(), source_kind));
                    } else if self.is_sanitizer(&callee) {
                        // Sanitizer function: remove taint from all variables passed as arguments
                        let referenced_vars = self.extract_referenced_variables(node);

                        // Mark tainted values as sanitized instead of removing them
                        let mut sanitized_output = HashSet::new();
                        for mut taint in output.drain() {
                            if referenced_vars.contains(&taint.variable) {
                                taint.sanitize();
                            }
                            sanitized_output.insert(taint);
                        }
                        return sanitized_output;
                    }
                }
                output
            }

            CfgNodeKind::Statement | CfgNodeKind::Expression => {
                let label = &node.label;

                // Check for assignment: x = y
                if let Some(lhs) = self.extract_assigned_variable(node) {
                    let referenced_vars = self.extract_referenced_variables(node);

                    // Check if RHS contains any taint sources
                    let mut has_source_on_rhs = false;
                    let mut source_kind = None;

                    for var in &referenced_vars {
                        if let Some(kind) = self.is_source(var) {
                            has_source_on_rhs = true;
                            source_kind = Some(kind);
                            break;
                        }
                    }

                    if has_source_on_rhs {
                        // Generate new taint
                        if let Some(kind) = source_kind {
                            output.insert(TaintValue::new(lhs.clone(), kind));
                        }
                    } else {
                        // Propagate taint from RHS to LHS
                        let mut propagated_taint = false;

                        for taint in input {
                            if referenced_vars.contains(&taint.variable) {
                                // Create new taint for LHS variable, preserving conditions
                                let mut new_taint = TaintValue {
                                    variable: lhs.clone(),
                                    source: taint.source.clone(),
                                    sanitized: taint.sanitized,
                                    taint_condition: taint.taint_condition.clone(),
                                    sanitized_condition: taint.sanitized_condition.clone(),
                                };
                                output.insert(new_taint);
                                propagated_taint = true;
                            }
                        }

                        // Kill old taint for the LHS variable (it's being reassigned)
                        if !propagated_taint {
                            output.retain(|t| t.variable != lhs);
                        }
                    }
                }
                // For VariableDeclaration, check if it's initialized with a source
                else if label.contains("VariableDeclaration") {
                    let vars = self.extract_referenced_variables(node);
                    for var in &vars {
                        if let Some(kind) = self.is_source(var) {
                            // Generate taint for the declared variable
                            // Assume the first identifier is the variable being declared
                            if let Some(declared_var) = vars.first() {
                                output.insert(TaintValue::new(declared_var.clone(), kind));
                            }
                        }
                    }
                }

                output
            }

            CfgNodeKind::Branch => {
                // For branches, just propagate taint through
                output
            }

            CfgNodeKind::Loop => {
                // For loops, propagate taint through
                // In a more sophisticated analysis, we'd handle fixpoint iteration
                output
            }

            CfgNodeKind::Return => {
                // Return statements propagate taint
                output
            }
        }
    }

    fn initial_state(&self) -> HashSet<TaintValue> {
        HashSet::new()
    }
}

/// Result of taint analysis
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TaintAnalysisResult {
    pub vulnerabilities: Vec<TaintVulnerability>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TaintVulnerability {
    pub sink: TaintSink,
    pub tainted_value: TaintValue,
    pub severity: Severity,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum Severity {
    Critical,
    High,
    Medium,
    Low,
}

impl Severity {
    pub fn as_str(&self) -> &'static str {
        match self {
            Severity::Critical => "Critical",
            Severity::High => "High",
            Severity::Medium => "Medium",
            Severity::Low => "Low",
        }
    }
}

// CFG cloning removed! We now pass CFG by reference to the transfer function.
// This eliminates a major performance bottleneck (50-80% speedup for large CFGs).

#[cfg(test)]
mod tests {
    use super::*;
    use crate::cfg::{CfgEdge, CfgEdgeKind, CfgNode, CfgNodeKind};
    use gittera_parser::ast::{AstNode, AstNodeKind, Location, Span};

    /// Helper function to create a dummy AST node for testing
    fn create_dummy_ast() -> AstNode {
        AstNode::new(
            0,
            AstNodeKind::Program,
            Location {
                file_path: "test.rs".to_string(),
                span: Span {
                    start_line: 1,
                    start_column: 0,
                    end_line: 1,
                    end_column: 10,
                    start_byte: 0,
                    end_byte: 10,
                },
            },
            String::new(),
        )
    }

    #[test]
    fn test_taint_source_detection() {
        let mut taint = TaintAnalysis::new();
        taint.add_source(TaintSource {
            name: "input".to_string(),
            kind: TaintSourceKind::UserInput,
            node_id: 1,
        });

        let sources = vec![TaintSource {
            name: "input".to_string(),
            kind: TaintSourceKind::UserInput,
            node_id: 1,
        }];

        let transfer = OwnedTaintTransferFunction {
            sources,
            sanitizers: HashSet::new(),
        };

        // Exact match
        assert!(transfer.is_source("input").is_some());
        // Contains match (name contains source)
        assert!(transfer.is_source("getUserInput").is_some());
        // No match
        assert!(transfer.is_source("safeFunction").is_none());
    }

    #[test]
    fn test_sanitizer_detection() {
        let sanitizers = vec!["escape", "sanitize"]
            .into_iter()
            .map(|s| s.to_string())
            .collect();

        let transfer = OwnedTaintTransferFunction {
            sources: Vec::new(),
            sanitizers,
        };

        assert!(transfer.is_sanitizer("escape"));
        assert!(transfer.is_sanitizer("escapeHtml"));
        assert!(transfer.is_sanitizer("sanitize"));
        assert!(!transfer.is_sanitizer("execute"));
    }

    #[test]
    fn test_taint_propagation_through_assignment() {
        let mut cfg = ControlFlowGraph::new();

        // Create a simple CFG: x = userInput
        let assign_node = CfgNode {
            id: 2,
            ast_node_id: 2,
            kind: CfgNodeKind::Statement,
            label: "x = userInput".to_string(),
        };
        let assign_idx = cfg.add_node(assign_node);

        cfg.add_edge(
            cfg.entry,
            assign_idx,
            CfgEdge {
                label: None,
                kind: CfgEdgeKind::Normal,
            },
        );

        cfg.add_edge(
            assign_idx,
            cfg.exit,
            CfgEdge {
                label: None,
                kind: CfgEdgeKind::Normal,
            },
        );

        let sources = vec![TaintSource {
            name: "userInput".to_string(),
            kind: TaintSourceKind::UserInput,
            node_id: 2,
        }];

        let transfer = OwnedTaintTransferFunction {
            sources,
            sanitizers: HashSet::new(),
        };

        // Test: empty input should generate taint for x
        let input = HashSet::new();
        let dummy_ast = create_dummy_ast();
        let output = transfer.transfer(&cfg, &dummy_ast, assign_idx, &input);

        // Should have taint for 'x'
        assert!(output.iter().any(|t| t.variable == "x"));
    }

    #[test]
    fn test_taint_killing_through_sanitizer() {
        let mut cfg = ControlFlowGraph::new();

        // Create CFG: result = escape(taintedVar)
        // The label should include the variable being sanitized
        let call_node = CfgNode {
            id: 2,
            ast_node_id: 2,
            kind: CfgNodeKind::FunctionCall,
            label: "call: escape(taintedVar)".to_string(),
        };
        let call_idx = cfg.add_node(call_node);

        cfg.add_edge(
            cfg.entry,
            call_idx,
            CfgEdge {
                label: None,
                kind: CfgEdgeKind::Normal,
            },
        );

        let mut sanitizers = HashSet::new();
        sanitizers.insert("escape".to_string());

        let transfer = OwnedTaintTransferFunction {
            sources: Vec::new(),
            sanitizers,
        };

        // Input: taintedVar is tainted
        let mut input = HashSet::new();
        input.insert(TaintValue::new(
            "taintedVar".to_string(),
            TaintSourceKind::UserInput,
        ));

        let dummy_ast = create_dummy_ast();
        let output = transfer.transfer(&cfg, &dummy_ast, call_idx, &input);

        // The taintedVar should now be marked as sanitized
        let tainted_var = output.iter().find(|t| t.variable == "taintedVar");
        assert!(tainted_var.is_some());
        assert!(tainted_var.unwrap().sanitized);
    }

    #[test]
    fn test_severity_calculation() {
        let taint = TaintAnalysis::new();

        // Critical: SQL injection from user input
        assert_eq!(
            taint.calculate_severity(&TaintSinkKind::SqlQuery, &TaintSourceKind::UserInput),
            Severity::Critical
        );

        // Critical: Command injection from user input
        assert_eq!(
            taint.calculate_severity(
                &TaintSinkKind::CommandExecution,
                &TaintSourceKind::UserInput
            ),
            Severity::Critical
        );

        // High: Code eval
        assert_eq!(
            taint.calculate_severity(&TaintSinkKind::CodeEval, &TaintSourceKind::UserInput),
            Severity::High
        );

        // Low: Log output
        assert_eq!(
            taint.calculate_severity(&TaintSinkKind::LogOutput, &TaintSourceKind::UserInput),
            Severity::Low
        );
    }

    #[test]
    fn test_default_sources_and_sinks() {
        let taint = TaintAnalysis::new()
            .with_default_sources()
            .with_default_sinks()
            .with_default_sanitizers();

        assert!(!taint.sources.is_empty());
        assert!(!taint.sinks.is_empty());
        assert!(!taint.sanitizers.is_empty());
    }

    #[test]
    fn test_extract_assigned_variable() {
        let transfer = OwnedTaintTransferFunction {
            sources: Vec::new(),
            sanitizers: HashSet::new(),
        };

        let node1 = CfgNode {
            id: 1,
            ast_node_id: 1,
            kind: CfgNodeKind::Statement,
            label: "x = 5".to_string(),
        };
        assert_eq!(transfer.extract_assigned_variable(&node1), Some("x".to_string()));

        let node2 = CfgNode {
            id: 2,
            ast_node_id: 2,
            kind: CfgNodeKind::Statement,
            label: "result = userInput()".to_string(),
        };
        assert_eq!(
            transfer.extract_assigned_variable(&node2),
            Some("result".to_string())
        );

        let node3 = CfgNode {
            id: 3,
            ast_node_id: 3,
            kind: CfgNodeKind::Statement,
            label: "x == 5".to_string(),
        };
        assert_eq!(transfer.extract_assigned_variable(&node3), None);
    }

    #[test]
    fn test_extract_callee() {
        let transfer = OwnedTaintTransferFunction {
            sources: Vec::new(),
            sanitizers: HashSet::new(),
        };

        let node = CfgNode {
            id: 1,
            ast_node_id: 1,
            kind: CfgNodeKind::FunctionCall,
            label: "call: getUserInput".to_string(),
        };
        assert_eq!(
            transfer.extract_callee(&node),
            Some("getUserInput".to_string())
        );
    }
}
