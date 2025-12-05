// ReDoS (Regular Expression Denial of Service) Test Cases

use regex::Regex;

// Test 1: Catastrophic backtracking with nested quantifiers
fn validate_email(email: &str) -> bool {
    // VULNERABLE: (a+)+ causes exponential backtracking
    let pattern = Regex::new(r"^([a-zA-Z0-9]+)+@[a-zA-Z0-9]+\.[a-z]+$").unwrap();
    pattern.is_match(email)
}

// Test 2: Multiple overlapping quantifiers
fn validate_input(input: &str) -> bool {
    // VULNERABLE: (a*)*b pattern can cause ReDoS
    let pattern = Regex::new(r"(a*)*b").unwrap();
    pattern.is_match(input)
}

// Test 3: Alternation with overlapping patterns
fn match_pattern(text: &str) -> bool {
    // VULNERABLE: (a|a)* causes catastrophic backtracking
    let pattern = Regex::new(r"(a|a)*c").unwrap();
    pattern.is_match(text)
}

// Test 4: Complex pattern with nested groups
fn validate_username(username: &str) -> bool {
    // VULNERABLE: (x+x+)+ causes exponential time complexity
    let pattern = Regex::new(r"^(x+x+)+y$").unwrap();
    pattern.is_match(username)
}

// Test 5: Greedy quantifiers with backtracking
fn extract_data(data: &str) -> bool {
    // VULNERABLE: Multiple greedy quantifiers can cause ReDoS
    let pattern = Regex::new(r"(.*,)*(.*)$").unwrap();
    pattern.is_match(data)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_redos() {
        let _ = validate_email("test@example.com");
        let _ = validate_input("aaaaa");
    }
}
