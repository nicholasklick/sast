//! KodeCD Analyzer - Data flow and control flow analysis
//!
//! This crate provides control flow graph generation, data flow analysis,
//! and taint tracking capabilities for security analysis.

pub mod cfg;
pub mod dataflow;
pub mod taint;
pub mod symbol_table;

pub use cfg::{ControlFlowGraph, CfgNode, CfgEdge, CfgBuilder};
pub use dataflow::{DataFlowAnalysis, DataFlowDirection, TransferFunction};
pub use taint::{TaintAnalysis, TaintSource, TaintSink, TaintValue};
pub use symbol_table::{SymbolTable, SymbolTableBuilder, Symbol, SymbolKind};
