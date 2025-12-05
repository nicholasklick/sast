// XPath Injection Test Cases

// Test 1: XPath query with unsanitized user input
fn find_user_by_name(username: &str) -> String {
    // VULNERABLE: username could contain XPath injection like ' or '1'='1
    format!("//users/user[username/text()='{}']", username)
}

// Test 2: Authentication using XPath
fn authenticate_xpath(user: &str, pass: &str) -> String {
    // VULNERABLE: user could be "admin' or '1'='1" to bypass authentication
    format!("//user[username='{}' and password='{}']", user, pass)
}

// Test 3: XPath query with multiple user inputs
fn search_products(category: &str, min_price: &str) -> String {
    // VULNERABLE: Both category and min_price are unsanitized
    format!("//products/product[category='{}' and price>={}]", category, min_price)
}

// Test 4: XPath contains function with user input
fn search_by_partial_match(search_term: &str) -> String {
    // VULNERABLE: search_term could break out of the contains function
    format!("//item[contains(name, '{}')]", search_term)
}

// Test 5: Complex XPath with user-controlled predicate
fn custom_xpath_query(field: &str, value: &str) -> String {
    // VULNERABLE: field and value allow arbitrary XPath construction
    format!("//{}[text()='{}']", field, value)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_xpath_injection() {
        let query = find_user_by_name("admin");
        assert!(query.contains("admin"));
    }
}
