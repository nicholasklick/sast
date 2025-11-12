//! KodeCD Analyzer - Data flow and control flow analysis
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
//!
//! ## Quick Start
//!
//! ### Taint Analysis
//!
//! ```rust
//! use kodecd_analyzer::{CfgBuilder, TaintAnalysis};
//! use kodecd_parser::{Parser, Language, LanguageConfig};
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
//! let result = taint.analyze(&cfg);
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
//! use kodecd_analyzer::{CallGraphBuilder, InterproceduralTaintAnalysis};
//! # use kodecd_parser::{Parser, Language, LanguageConfig};
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
//! use kodecd_analyzer::CallGraphBuilder;
//! # use kodecd_parser::{Parser, Language, LanguageConfig};
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
//! use kodecd_analyzer::{TaintAnalysis, TaintSource, TaintSink};
//! use kodecd_analyzer::{TaintSourceKind, TaintSinkKind};
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
//! cargo test -p kodecd-analyzer
//! ```
//!
//! Test specific modules:
//!
//! ```bash
//! cargo test -p kodecd-analyzer cfg
//! cargo test -p kodecd-analyzer taint
//! cargo test -p kodecd-analyzer call_graph
//! ```

pub mod cfg;
pub mod dataflow;
pub mod taint;
pub mod symbol_table;
pub mod call_graph;
pub mod interprocedural_taint;

pub use cfg::{ControlFlowGraph, CfgNode, CfgEdge, CfgBuilder};
pub use dataflow::{DataFlowAnalysis, DataFlowDirection, TransferFunction};
pub use taint::{TaintAnalysis, TaintSource, TaintSink, TaintValue, TaintAnalysisResult, Severity, TaintSinkKind, TaintSourceKind};
pub use symbol_table::{SymbolTable, SymbolTableBuilder, Symbol, SymbolKind};
pub use call_graph::{CallGraph, CallGraphBuilder, CallGraphNode, CallEdge, CallableKind};
pub use interprocedural_taint::{InterproceduralTaintAnalysis, FunctionTaintSummary};
