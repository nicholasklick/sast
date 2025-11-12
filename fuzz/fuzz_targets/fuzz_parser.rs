#![no_main]

use libfuzzer_sys::fuzz_target;
use kodecd_parser::{Parser, Language, LanguageConfig};
use std::path::Path;

fuzz_target!(|data: &[u8]| {
    // Convert bytes to string, allowing invalid UTF-8
    if let Ok(code) = std::str::from_utf8(data) {
        // Test TypeScript parser (most complex)
        let config = LanguageConfig::new(Language::TypeScript);
        let parser = Parser::new(config, Path::new("fuzz.ts"));

        // Parse should never panic
        let _ = parser.parse_source(code);
    }

    // Also test with potentially invalid UTF-8 using lossy conversion
    let code_lossy = String::from_utf8_lossy(data);
    let config = LanguageConfig::new(Language::JavaScript);
    let parser = Parser::new(config, Path::new("fuzz.js"));
    let _ = parser.parse_source(&code_lossy);
});
