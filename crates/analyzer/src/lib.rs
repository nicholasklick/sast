//! Gittera Analyzer - Data flow and control flow analysis
//!
//! This crate provides control flow graph generation, data flow analysis,
//! and taint tracking capabilities for security analysis.
//!
//! ## Features
//!
//! - **Control Flow Graphs (CFG)**: Build control flow graphs from ASTs
//! - **Data Flow Analysis**: Generic framework for forward/backward analysis
//! - **Taint Analysis**: Track untrusted data from sources to sinks
//! - **Inter-procedural Analysis**: Cross-function taint tracking
//! - **Call Graph**: Function call relationship tracking
//! - **Symbol Table**: Scope-aware symbol tracking
//! - **Points-to Analysis**: Determine what memory locations pointers may reference
//! - **Symbolic Execution**: Path-sensitive analysis with constraint solving
//!
//! ## Quick Start
//!
//! ### Taint Analysis
//!
//! ```rust
//! use gittera_analyzer::{CfgBuilder, TaintAnalysis};
//! use gittera_parser::{Parser, Language, LanguageConfig};
//! use std::path::Path;
//!
//! # fn main() -> Result<(), Box<dyn std::error::Error>> {
//! // Parse source code
//! let mut parser = Parser::new(
//!     LanguageConfig::new(Language::TypeScript),
//!     Path::new("app.ts")
//! );
//! let source = "const x = getUserInput(); execute(x);";
//! let ast = parser.parse_source(source)?;
//!
//! // Build control flow graph
//! let cfg = CfgBuilder::new().build(&ast);
//!
//! // Run taint analysis
//! let taint = TaintAnalysis::new()
//!     .with_default_sources()
//!     .with_default_sinks()
//!     .with_default_sanitizers();
//!
//! let result = taint.analyze(&cfg, &ast);
//!
//! // Process vulnerabilities
//! for vuln in &result.vulnerabilities {
//!     println!(
//!         "[{}] {} flows to {}",
//!         vuln.severity.as_str(),
//!         vuln.tainted_value.variable,
//!         vuln.sink.name
//!     );
//! }
//! # Ok(())
//! # }
//! ```
//!
//! ### Inter-procedural Taint Analysis
//!
//! ```rust
//! use gittera_analyzer::{CallGraphBuilder, InterproceduralTaintAnalysis};
//! # use gittera_parser::{Parser, Language, LanguageConfig};
//! # use std::path::Path;
//!
//! # fn main() -> Result<(), Box<dyn std::error::Error>> {
//! # let mut parser = Parser::new(
//! #     LanguageConfig::new(Language::TypeScript),
//! #     Path::new("app.ts")
//! # );
//! # let source = "const x = 10;";
//! # let ast = parser.parse_source(source)?;
//! // Build call graph
//! let call_graph = CallGraphBuilder::new().build(&ast);
//!
//! // Run inter-procedural analysis
//! let mut analysis = InterproceduralTaintAnalysis::new()
//!     .with_default_sources()
//!     .with_default_sinks()
//!     .with_default_sanitizers();
//!
//! let result = analysis.analyze(&ast, &call_graph);
//!
//! // Detects vulnerabilities across function boundaries
//! for vuln in &result.vulnerabilities {
//!     println!("Cross-function vulnerability: {}", vuln.sink.name);
//! }
//! # Ok(())
//! # }
//! ```
//!
//! ### Call Graph Analysis
//!
//! ```rust
//! use gittera_analyzer::CallGraphBuilder;
//! # use gittera_parser::{Parser, Language, LanguageConfig};
//! # use std::path::Path;
//!
//! # fn main() -> Result<(), Box<dyn std::error::Error>> {
//! # let mut parser = Parser::new(
//! #     LanguageConfig::new(Language::TypeScript),
//! #     Path::new("app.ts")
//! # );
//! # let source = "const x = 10;";
//! # let ast = parser.parse_source(source)?;
//! let call_graph = CallGraphBuilder::new().build(&ast);
//!
//! // Query the graph
//! for edge in call_graph.get_callees("main") {
//!     println!("main() calls {}", edge.to);
//! }
//!
//! // Find reachable functions
//! let reachable = call_graph.reachable_from("main");
//! println!("Reachable functions: {:?}", reachable);
//!
//! // Topological sort for bottom-up analysis
//! if let Some(sorted) = call_graph.topological_sort() {
//!     println!("Analysis order: {:?}", sorted);
//! }
//! # Ok(())
//! # }
//! ```
//!
//! ### Points-to Analysis
//!
//! ```rust
//! use gittera_analyzer::PointsToAnalysisBuilder;
//! # use gittera_parser::{Parser, Language, LanguageConfig};
//! # use std::path::Path;
//!
//! # fn main() -> Result<(), Box<dyn std::error::Error>> {
//! # let mut parser = Parser::new(
//! #     LanguageConfig::new(Language::JavaScript),
//! #     Path::new("app.js")
//! # );
//! # let source = "let obj = { value: 1 }; let ptr = obj;";
//! # let ast = parser.parse_source(source)?;
//! // Build points-to analysis
//! let pts = PointsToAnalysisBuilder::new().build(&ast);
//!
//! // Query what a variable points to
//! let targets = pts.points_to("ptr");
//! println!("ptr may point to: {:?}", targets);
//!
//! // Check if two variables may alias
//! let may_alias = pts.may_alias("ptr1", "ptr2");
//! if may_alias {
//!     println!("ptr1 and ptr2 may point to the same location");
//! }
//!
//! // Get analysis statistics
//! let stats = pts.stats();
//! println!("Analyzed {} locations with {} constraints",
//!     stats.num_locations, stats.num_constraints);
//! # Ok(())
//! # }
//! ```
//!
//! ### Symbolic Execution
//!
//! ```rust
//! use gittera_analyzer::SymbolicExecutorBuilder;
//! # use gittera_parser::{AstNode, AstNodeKind, Location, Span};
//!
//! # fn main() -> Result<(), Box<dyn std::error::Error>> {
//! # let program = AstNode {
//! #     id: 0,
//! #     kind: AstNodeKind::Program,
//! #     location: Location {
//! #         file_path: "test.js".to_string(),
//! #         span: Span {
//! #             start_line: 1, start_column: 0,
//! #             end_line: 1, end_column: 10,
//! #             start_byte: 0, end_byte: 10,
//! #         },
//! #     },
//! #     children: Vec::new(),
//! #     text: String::new(),
//! # };
//! // Execute program symbolically
//! let executor = SymbolicExecutorBuilder::new()
//!     .with_max_depth(50)
//!     .with_max_paths(100)
//!     .build();
//!
//! let result = executor.execute(&program);
//!
//! // Analyze explored paths
//! println!("Explored {} paths", result.paths.len());
//! for path in &result.paths {
//!     println!("Path has {} constraints", path.constraints.len());
//! }
//!
//! // Get statistics
//! println!("Completed: {}/{} paths",
//!     result.stats.completed_paths,
//!     result.stats.total_paths);
//! # Ok(())
//! # }
//! ```
//!
//! ## Architecture
//!
//! The analyzer is built on several core components:
//!
//! ### Control Flow Graph (CFG)
//!
//! Represents the flow of execution through a program:
//! - **Nodes**: Statements and expressions
//! - **Edges**: Control flow (sequential, conditional, loops)
//! - **Analysis**: Foundation for data flow analysis
//!
//! ### Data Flow Analysis Framework
//!
//! Generic framework for analyzing how data flows through the program:
//! - **Forward Analysis**: Propagate from entry to exit
//! - **Backward Analysis**: Propagate from exit to entry
//! - **Transfer Functions**: Define how data changes at each node
//! - **Meet Operations**: Combine data from multiple paths
//!
//! ### Taint Analysis
//!
//! Tracks untrusted data from sources to sinks:
//! - **Sources**: User input, files, network, environment variables
//! - **Propagation**: Assignment, operations, function calls
//! - **Sanitizers**: Validation, escaping, filtering
//! - **Sinks**: SQL queries, command execution, file writes, eval
//!
//! ### Inter-procedural Analysis
//!
//! Tracks data across function boundaries:
//! - **Call Graph**: Function call relationships
//! - **Function Summaries**: Pre-computed taint behavior
//! - **Bottom-up Analysis**: Analyze callees before callers
//! - **Cross-function Taint**: Detect vulnerabilities spanning functions
//!
//! ### Points-to Analysis
//!
//! Determines what memory locations pointers may reference:
//! - **Andersen-style**: Flow-insensitive, context-insensitive analysis
//! - **Constraint-based**: Address-of, copy, load, store constraints
//! - **Alias Analysis**: Determine if two pointers may point to same location
//! - **Applications**: Improves taint analysis, call graph refinement
//!
//! ### Symbolic Execution
//!
//! Explores program paths by treating inputs as symbolic values:
//! - **Path Exploration**: Systematic exploration of execution paths
//! - **Constraint Generation**: Tracks path conditions as symbolic constraints
//! - **Constant Folding**: Simplifies concrete symbolic expressions
//! - **Applications**: Test generation, bug finding, vulnerability discovery
//!
//! ## Default Configurations
//!
//! ### Taint Sources
//!
//! ```text
//! UserInput:        request.body, request.query, getUserInput()
//! FileRead:         readFile(), fs.read
//! NetworkRequest:   fetch(), axios
//! EnvironmentVar:   process.env, os.Getenv
//! CommandLineArg:   argv, os.Args
//! DatabaseQuery:    db.query
//! ```
//!
//! ### Taint Sinks
//!
//! ```text
//! SqlQuery:          execute(), query(), raw()
//! CommandExecution:  exec(), spawn(), system()
//! FileWrite:         writeFile(), fs.write
//! CodeEval:          eval(), Function()
//! HtmlOutput:        innerHTML, document.write
//! LogOutput:         console.log (info disclosure)
//! NetworkSend:       http.send(), socket.write
//! ```
//!
//! ### Sanitizers
//!
//! ```text
//! escape, sanitize, validate
//! escapeHtml, escapeSql
//! clean, filter
//! ```
//!
//! ## Performance
//!
//! - **CFG Construction**: O(n) where n = AST nodes
//! - **Taint Analysis**: O(n × t) where t = taint values
//! - **Inter-procedural**: O(f × (n + t)) where f = functions
//! - **Call Graph**: O(n + e) where e = call edges
//!
//! **Scalability**:
//! - Handles 10,000+ line files
//! - Inter-procedural analysis with 500+ functions
//! - Deep call chains (15+ levels)
//!
//! ## Examples
//!
//! ### Custom Taint Sources and Sinks
//!
//! ```rust
//! use gittera_analyzer::{TaintAnalysis, TaintSource, TaintSink};
//! use gittera_analyzer::{TaintSourceKind, TaintSinkKind};
//!
//! let mut taint = TaintAnalysis::new();
//!
//! // Add custom source
//! taint.add_source(TaintSource {
//!     name: "getCustomInput".to_string(),
//!     kind: TaintSourceKind::UserInput,
//!     node_id: 0,
//! });
//!
//! // Add custom sink
//! taint.add_sink(TaintSink {
//!     name: "dangerousFunction".to_string(),
//!     kind: TaintSinkKind::SqlQuery,
//!     node_id: 0,
//! });
//! ```
//!
//! ## Testing
//!
//! Run the analyzer test suite:
//!
//! ```bash
//! cargo test -p gittera-analyzer
//! ```
//!
//! Test specific modules:
//!
//! ```bash
//! cargo test -p gittera-analyzer cfg
//! cargo test -p gittera-analyzer taint
//! cargo test -p gittera-analyzer call_graph
//! ```

pub mod cfg;
pub mod dataflow;
pub mod dataflow_node;    // CodeQL-inspired data flow node abstraction
pub mod content;          // Content model for field-sensitive analysis
pub mod access_path;      // Access path tracking (depth 5)
pub mod flow_summary;     // Flow summaries (Models as Data) for library functions
pub mod taint;
pub mod taint_ast_based;  // New: AST-based taint analysis with proper expression evaluation
pub mod taint_config;     // Language-specific taint configurations
pub mod yaml_config;      // YAML-based taint configuration (MaD format)
pub mod taint_pipeline;   // Multi-stage analysis pipeline for performance
pub mod language_handler; // Language-specific taint analysis handlers
pub mod symbol_table;
pub mod call_graph;
pub mod call_context;      // k-CFA context sensitivity for inter-procedural analysis
pub mod interprocedural_taint;
pub mod points_to;
pub mod symbolic;
pub mod type_system;      // Type system integration for enhanced analysis precision
pub mod collection_ops;   // Language-agnostic collection operation tracking

pub use cfg::{ControlFlowGraph, CfgNode, CfgEdge, CfgBuilder};
pub use dataflow::{DataFlowAnalysis, DataFlowDirection, TransferFunction};
pub use dataflow_node::{DataFlowNode, ArgumentPosition, ReturnKind, LocalFlowStep, ClearedNodes};
pub use content::{Content, ContentSet};
pub use access_path::{AccessPath, AccessPathFront, MAX_ACCESS_PATH_LENGTH};
pub use flow_summary::{FlowSummaryRegistry, SummarizedCallable, FlowPropagation, SummaryComponent, FlowKind, ArgumentSpec, Provenance};
pub use taint::{TaintAnalysis, TaintSource, TaintSink, TaintValue, TaintAnalysisResult, Severity, TaintSinkKind, TaintSourceKind, FlowState, Sanitizer, TaintVulnerability, TaintPath, TaintNode, TaintNodeType, allows_implicit_read};
pub use taint_config::{LanguageTaintConfig, init_yaml_configs};
pub use yaml_config::{TaintConfigYaml, TaintConfigRegistry, SourceConfig, SinkConfig, SanitizerConfig, SummaryConfig, SourceKind, SinkKind, SanitizeKind, SummaryKind, YamlConfigError};
pub use language_handler::{LanguageTaintHandler, ConditionalIndices, SafeSinkPattern, get_handler_for_language, PythonTaintHandler, JavaTaintHandler, GenericTaintHandler, evaluate_node_symbolic};
pub use taint_pipeline::{TaintAnalysisPipeline, PipelineConfig, PipelineResult, VulnerabilityCandidate, StageStats};
pub use symbol_table::{SymbolTable, SymbolTableBuilder, Symbol, SymbolKind};
pub use call_graph::{CallGraph, CallGraphBuilder, CallGraphNode, CallEdge, CallableKind};
pub use call_context::{CallContext, ContextualFunction, ContextConfig, MAX_CONTEXT_DEPTH};
pub use interprocedural_taint::{InterproceduralTaintAnalysis, FunctionTaintSummary};
pub use points_to::{PointsToAnalysis, PointsToAnalysisBuilder, AbstractLocation, PointsToConstraint, PointsToStats};
pub use symbolic::{SymbolicExecutor, SymbolicExecutorBuilder, SymbolicValue, SymbolicState, ExecutionPath, SymbolicExecutionResult, Constraint, BinaryOperator, UnaryOperator};
pub use type_system::{TypeContext, TypeInfo, TypeCategory, TypeContextStats};
pub use collection_ops::{CollectionOperation, detect_collection_op_from_call, detect_collection_op_from_subscript, make_taint_key};
