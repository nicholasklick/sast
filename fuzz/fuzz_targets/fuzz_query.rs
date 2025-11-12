#![no_main]

use libfuzzer_sys::fuzz_target;
use kodecd_query::QueryParser;

fuzz_target!(|data: &[u8]| {
    // Convert bytes to string
    if let Ok(query_str) = std::str::from_utf8(data) {
        // Query parser should never panic, even on invalid input
        let _ = QueryParser::parse(query_str);
    }

    // Also test with lossy UTF-8 conversion
    let query_str_lossy = String::from_utf8_lossy(data);
    let _ = QueryParser::parse(&query_str_lossy);
});
