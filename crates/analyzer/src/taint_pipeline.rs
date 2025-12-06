//! Staged Taint Analysis Pipeline
//!
//! This module provides a multi-stage analysis pipeline for improved performance
//! and precision. Each stage builds on the previous, allowing early pruning of
//! irrelevant paths and focused analysis on potential vulnerabilities.
//!
//! ## Pipeline Stages
//!
//! 1. **Local Flow Stage**: Fast intra-procedural flow analysis
//! 2. **Pruning Stage**: Eliminate unreachable paths and false candidates
//! 3. **Global Flow Stage**: Inter-procedural analysis with access paths
//! 4. **Verification Stage**: Path reconstruction and validation
//!
//! ## Performance Benefits
//!
//! - Early elimination of false positives reduces work in later stages
//! - Context-sensitive analysis only where needed
//! - Parallelizable stages for large codebases

use crate::access_path::AccessPath;
use crate::call_context::CallContext;
use crate::call_graph::CallGraph;
use crate::cfg::ControlFlowGraph;
use crate::flow_summary::FlowSummaryRegistry;
use crate::taint::{FlowState, TaintSink, TaintSource, TaintSourceKind, TaintValue, TaintVulnerability, Severity};
use gittera_parser::ast::{AstNode, NodeId};
use std::collections::{HashMap, HashSet};

/// A candidate vulnerability found during local analysis
#[derive(Debug, Clone)]
pub struct VulnerabilityCandidate {
    /// Source of the taint
    pub source: TaintSource,
    /// Sink where taint flows
    pub sink: TaintSink,
    /// Variables involved in the flow
    pub flow_path: Vec<String>,
    /// Whether this candidate has been verified by global analysis
    pub verified: bool,
    /// Confidence score (0.0 - 1.0)
    pub confidence: f64,
}

impl VulnerabilityCandidate {
    /// Create a new vulnerability candidate
    pub fn new(source: TaintSource, sink: TaintSink) -> Self {
        Self {
            source,
            sink,
            flow_path: Vec::new(),
            verified: false,
            confidence: 0.5, // Default confidence
        }
    }

    /// Add a variable to the flow path
    pub fn add_to_path(&mut self, variable: String) {
        self.flow_path.push(variable);
    }

    /// Mark as verified with a confidence score
    pub fn verify(&mut self, confidence: f64) {
        self.verified = true;
        self.confidence = confidence;
    }
}

/// Configuration for the analysis pipeline
#[derive(Debug, Clone)]
pub struct PipelineConfig {
    /// Enable local flow analysis
    pub enable_local_flow: bool,
    /// Enable pruning stage
    pub enable_pruning: bool,
    /// Enable global flow analysis
    pub enable_global_flow: bool,
    /// Enable verification stage
    pub enable_verification: bool,
    /// Maximum path depth for local analysis
    pub max_local_depth: usize,
    /// Maximum call depth for global analysis
    pub max_call_depth: usize,
    /// Minimum confidence to report a vulnerability
    pub min_confidence: f64,
    /// Use flow summaries for library calls
    pub use_flow_summaries: bool,
}

impl Default for PipelineConfig {
    fn default() -> Self {
        Self {
            enable_local_flow: true,
            enable_pruning: true,
            enable_global_flow: true,
            enable_verification: true,
            max_local_depth: 50,
            max_call_depth: 10,
            min_confidence: 0.5,
            use_flow_summaries: true,
        }
    }
}

impl PipelineConfig {
    /// Create a fast configuration (less precise but faster)
    pub fn fast() -> Self {
        Self {
            enable_local_flow: true,
            enable_pruning: true,
            enable_global_flow: false,
            enable_verification: false,
            max_local_depth: 20,
            max_call_depth: 3,
            min_confidence: 0.3,
            use_flow_summaries: true,
        }
    }

    /// Create a thorough configuration (more precise but slower)
    pub fn thorough() -> Self {
        Self {
            enable_local_flow: true,
            enable_pruning: true,
            enable_global_flow: true,
            enable_verification: true,
            max_local_depth: 100,
            max_call_depth: 15,
            min_confidence: 0.7,
            use_flow_summaries: true,
        }
    }
}

/// Result from a pipeline stage
#[derive(Debug, Clone)]
pub struct StageResult {
    /// Candidates that passed this stage
    pub candidates: Vec<VulnerabilityCandidate>,
    /// Statistics about this stage
    pub stats: StageStats,
}

/// Statistics for a pipeline stage
#[derive(Debug, Clone, Default)]
pub struct StageStats {
    /// Number of candidates entering this stage
    pub input_count: usize,
    /// Number of candidates exiting this stage
    pub output_count: usize,
    /// Number filtered out
    pub filtered_count: usize,
    /// Time taken (milliseconds)
    pub duration_ms: u64,
}

/// The complete analysis pipeline
pub struct TaintAnalysisPipeline {
    config: PipelineConfig,
    sources: Vec<TaintSource>,
    sinks: Vec<TaintSink>,
    flow_summaries: FlowSummaryRegistry,
}

impl TaintAnalysisPipeline {
    /// Create a new analysis pipeline with default configuration
    pub fn new() -> Self {
        Self {
            config: PipelineConfig::default(),
            sources: Vec::new(),
            sinks: Vec::new(),
            flow_summaries: FlowSummaryRegistry::new(),
        }
    }

    /// Create a pipeline with custom configuration
    pub fn with_config(config: PipelineConfig) -> Self {
        Self {
            config,
            sources: Vec::new(),
            sinks: Vec::new(),
            flow_summaries: FlowSummaryRegistry::new(),
        }
    }

    /// Add a taint source
    pub fn add_source(&mut self, source: TaintSource) {
        self.sources.push(source);
    }

    /// Add a taint sink
    pub fn add_sink(&mut self, sink: TaintSink) {
        self.sinks.push(sink);
    }

    /// Set flow summaries for library analysis
    pub fn with_flow_summaries(mut self, summaries: FlowSummaryRegistry) -> Self {
        self.flow_summaries = summaries;
        self
    }

    /// Run the complete analysis pipeline
    pub fn analyze(
        &self,
        ast: &AstNode,
        _cfg: &ControlFlowGraph,
        _call_graph: Option<&CallGraph>,
    ) -> PipelineResult {
        let start_time = std::time::Instant::now();
        let mut result = PipelineResult::new();

        // Stage 1: Local Flow Analysis
        let local_result = if self.config.enable_local_flow {
            self.run_local_flow_stage(ast)
        } else {
            StageResult {
                candidates: self.create_initial_candidates(),
                stats: StageStats::default(),
            }
        };
        result.local_flow_stats = local_result.stats.clone();
        let mut candidates = local_result.candidates;

        // Stage 2: Pruning
        if self.config.enable_pruning {
            let pruning_result = self.run_pruning_stage(candidates, ast);
            result.pruning_stats = pruning_result.stats.clone();
            candidates = pruning_result.candidates;
        }

        // Stage 3: Global Flow Analysis (if enabled and call graph available)
        if self.config.enable_global_flow {
            let global_result = self.run_global_flow_stage(candidates, ast);
            result.global_flow_stats = global_result.stats.clone();
            candidates = global_result.candidates;
        }

        // Stage 4: Verification
        if self.config.enable_verification {
            let verification_result = self.run_verification_stage(candidates);
            result.verification_stats = verification_result.stats.clone();
            candidates = verification_result.candidates;
        }

        // Convert candidates to vulnerabilities
        for candidate in candidates {
            if candidate.confidence >= self.config.min_confidence {
                result.vulnerabilities.push(TaintVulnerability {
                    sink: candidate.sink.clone(),
                    tainted_value: TaintValue::new(
                        candidate.flow_path.first().cloned().unwrap_or_default(),
                        candidate.source.kind.clone(),
                    ),
                    severity: self.calculate_severity(&candidate),
                });
            }
        }

        result.total_duration_ms = start_time.elapsed().as_millis() as u64;
        result
    }

    /// Stage 1: Local Flow Analysis
    fn run_local_flow_stage(&self, _ast: &AstNode) -> StageResult {
        let candidates = self.create_initial_candidates();
        let input_count = candidates.len();

        StageResult {
            candidates,
            stats: StageStats {
                input_count,
                output_count: input_count,
                filtered_count: 0,
                duration_ms: 0,
            },
        }
    }

    /// Stage 2: Pruning - eliminate obviously unreachable paths
    fn run_pruning_stage(&self, candidates: Vec<VulnerabilityCandidate>, _ast: &AstNode) -> StageResult {
        let input_count = candidates.len();

        // For now, keep all candidates
        // In full implementation, would check:
        // - Reachability between source and sink
        // - Type compatibility
        // - Basic must-not-alias analysis
        let output = candidates;

        StageResult {
            candidates: output.clone(),
            stats: StageStats {
                input_count,
                output_count: output.len(),
                filtered_count: input_count - output.len(),
                duration_ms: 0,
            },
        }
    }

    /// Stage 3: Global Flow Analysis
    fn run_global_flow_stage(&self, candidates: Vec<VulnerabilityCandidate>, _ast: &AstNode) -> StageResult {
        let input_count = candidates.len();

        // In full implementation, would:
        // - Track taint across function boundaries
        // - Use call context sensitivity
        // - Apply flow summaries for library calls
        let mut verified_candidates = Vec::new();
        for mut candidate in candidates {
            // Mark as verified with moderate confidence
            candidate.verify(0.7);
            verified_candidates.push(candidate);
        }

        StageResult {
            candidates: verified_candidates.clone(),
            stats: StageStats {
                input_count,
                output_count: verified_candidates.len(),
                filtered_count: 0,
                duration_ms: 0,
            },
        }
    }

    /// Stage 4: Verification - reconstruct and validate paths
    fn run_verification_stage(&self, candidates: Vec<VulnerabilityCandidate>) -> StageResult {
        let input_count = candidates.len();

        // In full implementation, would:
        // - Reconstruct actual data flow paths
        // - Verify sanitizers are properly applied
        // - Check for context-specific sanitization
        let verified: Vec<_> = candidates
            .into_iter()
            .filter(|c| c.verified && c.confidence >= self.config.min_confidence)
            .collect();

        StageResult {
            candidates: verified.clone(),
            stats: StageStats {
                input_count,
                output_count: verified.len(),
                filtered_count: input_count - verified.len(),
                duration_ms: 0,
            },
        }
    }

    /// Create initial vulnerability candidates from sources and sinks
    fn create_initial_candidates(&self) -> Vec<VulnerabilityCandidate> {
        let mut candidates = Vec::new();

        // Create candidates for all source-sink pairs
        for source in &self.sources {
            for sink in &self.sinks {
                let mut candidate = VulnerabilityCandidate::new(source.clone(), sink.clone());
                candidate.add_to_path(source.name.clone());
                candidates.push(candidate);
            }
        }

        candidates
    }

    /// Calculate severity for a candidate
    fn calculate_severity(&self, candidate: &VulnerabilityCandidate) -> Severity {
        use crate::taint::TaintSinkKind;

        match (&candidate.sink.kind, &candidate.source.kind) {
            (TaintSinkKind::SqlQuery, TaintSourceKind::UserInput) => Severity::Critical,
            (TaintSinkKind::CommandExecution, TaintSourceKind::UserInput) => Severity::Critical,
            (TaintSinkKind::CodeEval, _) => Severity::High,
            (TaintSinkKind::FileWrite, TaintSourceKind::UserInput) => Severity::High,
            (TaintSinkKind::HtmlOutput, TaintSourceKind::UserInput) => Severity::Medium,
            (TaintSinkKind::LogOutput, _) => Severity::Low,
            _ => Severity::Medium,
        }
    }
}

impl Default for TaintAnalysisPipeline {
    fn default() -> Self {
        Self::new()
    }
}

/// Result of running the complete pipeline
#[derive(Debug, Clone)]
pub struct PipelineResult {
    /// Verified vulnerabilities
    pub vulnerabilities: Vec<TaintVulnerability>,
    /// Statistics from local flow stage
    pub local_flow_stats: StageStats,
    /// Statistics from pruning stage
    pub pruning_stats: StageStats,
    /// Statistics from global flow stage
    pub global_flow_stats: StageStats,
    /// Statistics from verification stage
    pub verification_stats: StageStats,
    /// Total duration in milliseconds
    pub total_duration_ms: u64,
}

impl PipelineResult {
    fn new() -> Self {
        Self {
            vulnerabilities: Vec::new(),
            local_flow_stats: StageStats::default(),
            pruning_stats: StageStats::default(),
            global_flow_stats: StageStats::default(),
            verification_stats: StageStats::default(),
            total_duration_ms: 0,
        }
    }

    /// Get summary statistics
    pub fn summary(&self) -> String {
        format!(
            "Pipeline completed in {}ms\n\
             Local Flow: {} -> {} candidates\n\
             Pruning: {} filtered\n\
             Global Flow: {} verified\n\
             Final: {} vulnerabilities",
            self.total_duration_ms,
            self.local_flow_stats.input_count,
            self.local_flow_stats.output_count,
            self.pruning_stats.filtered_count,
            self.global_flow_stats.output_count,
            self.vulnerabilities.len()
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::taint::TaintSinkKind;

    #[test]
    fn test_pipeline_config_default() {
        let config = PipelineConfig::default();
        assert!(config.enable_local_flow);
        assert!(config.enable_pruning);
        assert!(config.enable_global_flow);
        assert!(config.enable_verification);
    }

    #[test]
    fn test_pipeline_config_fast() {
        let config = PipelineConfig::fast();
        assert!(config.enable_local_flow);
        assert!(!config.enable_global_flow);
        assert!(!config.enable_verification);
        assert_eq!(config.max_local_depth, 20);
    }

    #[test]
    fn test_pipeline_config_thorough() {
        let config = PipelineConfig::thorough();
        assert!(config.enable_global_flow);
        assert!(config.enable_verification);
        assert_eq!(config.max_call_depth, 15);
    }

    #[test]
    fn test_vulnerability_candidate() {
        let source = TaintSource {
            name: "getParameter".to_string(),
            kind: TaintSourceKind::UserInput,
            node_id: 1,
        };
        let sink = TaintSink {
            name: "executeQuery".to_string(),
            kind: TaintSinkKind::SqlQuery,
            node_id: 2,
        };

        let mut candidate = VulnerabilityCandidate::new(source, sink);
        candidate.add_to_path("param".to_string());
        candidate.add_to_path("query".to_string());

        assert!(!candidate.verified);
        assert_eq!(candidate.flow_path.len(), 2);

        candidate.verify(0.9);
        assert!(candidate.verified);
        assert!((candidate.confidence - 0.9).abs() < 0.01);
    }

    #[test]
    fn test_pipeline_creation() {
        let pipeline = TaintAnalysisPipeline::new();
        assert!(pipeline.sources.is_empty());
        assert!(pipeline.sinks.is_empty());
    }

    #[test]
    fn test_stage_stats() {
        let stats = StageStats {
            input_count: 100,
            output_count: 80,
            filtered_count: 20,
            duration_ms: 50,
        };

        assert_eq!(stats.input_count, 100);
        assert_eq!(stats.filtered_count, 20);
    }

    #[test]
    fn test_pipeline_result_summary() {
        let result = PipelineResult {
            vulnerabilities: vec![],
            local_flow_stats: StageStats {
                input_count: 10,
                output_count: 10,
                filtered_count: 0,
                duration_ms: 5,
            },
            pruning_stats: StageStats {
                input_count: 10,
                output_count: 8,
                filtered_count: 2,
                duration_ms: 3,
            },
            global_flow_stats: StageStats {
                input_count: 8,
                output_count: 5,
                filtered_count: 3,
                duration_ms: 10,
            },
            verification_stats: StageStats::default(),
            total_duration_ms: 20,
        };

        let summary = result.summary();
        assert!(summary.contains("20ms"));
        assert!(summary.contains("10 -> 10"));
    }
}
