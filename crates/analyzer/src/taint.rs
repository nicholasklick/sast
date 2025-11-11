//! Taint analysis for tracking data flow from sources to sinks

use crate::cfg::{CfgGraphIndex, ControlFlowGraph};
use crate::dataflow::{DataFlowAnalysis, DataFlowDirection, DataFlowResult, TransferFunction};
use kodecd_parser::ast::NodeId;
use serde::{Deserialize, Serialize};
use std::collections::HashSet;

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
}

impl TaintValue {
    pub fn new(variable: String, source: TaintSourceKind) -> Self {
        Self {
            variable,
            source,
            sanitized: false,
        }
    }

    pub fn sanitize(&mut self) {
        self.sanitized = true;
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

    /// Run taint analysis on a CFG
    pub fn analyze(&self, cfg: &ControlFlowGraph) -> TaintAnalysisResult {
        // Clone the data to avoid lifetime issues
        let sources = self.sources.clone();
        let sinks = self.sinks.clone();
        let sanitizers = self.sanitizers.clone();

        let transfer = OwnedTaintTransferFunction {
            sources,
            sanitizers,
        };

        let analysis = DataFlowAnalysis::new(
            DataFlowDirection::Forward,
            Box::new(transfer),
        );

        let dataflow_result = analysis.analyze(cfg);

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
                        if !taint_value.sanitized {
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
}

impl Default for TaintAnalysis {
    fn default() -> Self {
        Self::new()
    }
}

/// Transfer function for taint analysis (with owned data)
struct OwnedTaintTransferFunction {
    sources: Vec<TaintSource>,
    sanitizers: HashSet<String>,
}

impl TransferFunction<TaintValue> for OwnedTaintTransferFunction {
    fn transfer(&self, _node: CfgGraphIndex, input: &HashSet<TaintValue>) -> HashSet<TaintValue> {
        let mut output = input.clone();

        // For now, just pass through the taint values
        // In a full implementation, we would check the CFG node
        // and add new taints or sanitize existing ones

        output
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
