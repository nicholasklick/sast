#![no_main]

use libfuzzer_sys::fuzz_target;
use kodecd_parser::{Parser, Language, LanguageConfig};
use kodecd_analyzer::{CfgBuilder, TaintAnalysis};
use std::path::Path;

fuzz_target!(|data: &[u8]| {
    // Convert bytes to string
    if let Ok(code) = std::str::from_utf8(data) {
        // Parse the code
        let config = LanguageConfig::new(Language::TypeScript);
        let parser = Parser::new(config, Path::new("fuzz.ts"));

        if let Ok(ast) = parser.parse_source(code) {
            // Build CFG
            let cfg = CfgBuilder::new().build(&ast);

            // Run taint analysis - should never panic
            let taint = TaintAnalysis::new()
                .with_default_sources()
                .with_default_sinks()
                .with_default_sanitizers();

            let _ = taint.analyze(&cfg, &ast);
        }
    }
});
