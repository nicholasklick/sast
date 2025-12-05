// LDAP Injection Test Cases

// Test 1: LDAP search filter with unsanitized user input
fn search_user_by_username(username: &str) -> String {
    // VULNERABLE: username could contain LDAP special characters like *, (, ), \, etc.
    format!("(uid={})", username)
}

// Test 2: LDAP authentication filter
fn create_auth_filter(username: &str, password: &str) -> String {
    // VULNERABLE: username could be "admin)(&(1=1" to bypass auth
    format!("(&(uid={})(password={}))", username, password)
}

// Test 3: Complex LDAP filter with user input
fn find_users_filter(search_term: &str, department: &str) -> String {
    // VULNERABLE: Both searchTerm and department are unsanitized
    format!("(&(cn=*{}*)(department={}))", search_term, department)
}

// Test 4: LDAP DN construction
fn get_user_dn(username: &str, domain: &str) -> String {
    // VULNERABLE: username could contain DN special characters
    format!("cn={},dc={},dc=com", username, domain)
}

// Test 5: LDAP group membership filter
fn check_group_membership(username: &str, group: &str) -> String {
    // VULNERABLE: Both parameters unsanitized
    format!("(&(member=uid={},ou=users,dc=example,dc=com)(cn={}))", username, group)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_ldap_injection() {
        let filter = search_user_by_username("admin");
        assert!(filter.contains("admin"));
    }
}
