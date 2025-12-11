//! Extended Standard Library - 100+ Built-in Security Queries
//!
//! This module provides a comprehensive library of security queries comparable to CodeQL,
//! organized by category with full metadata support.

use crate::ast::*;
use crate::metadata::*;
use std::collections::HashMap;

/// Extended standard library with 100+ queries
pub struct ExtendedStandardLibrary {
    queries: HashMap<String, (Query, QueryMetadata)>,
}

impl ExtendedStandardLibrary {
    /// Create a new extended standard library with all queries registered
    pub fn new() -> Self {
        let mut lib = Self {
            queries: HashMap::new(),
        };

        // Register all queries
        lib.register_injection_queries();
        lib.register_xss_queries();
        lib.register_authentication_queries();
        lib.register_cryptography_queries();
        lib.register_path_traversal_queries();
        lib.register_information_disclosure_queries();
        lib.register_code_quality_queries();
        lib.register_resource_management_queries();
        lib.register_error_handling_queries();
        lib.register_api_misuse_queries();
        lib.register_configuration_queries();
        lib.register_framework_queries();

        lib
    }

    /// Register a query with its metadata
    fn register(&mut self, id: &str, query: Query, metadata: QueryMetadata) {
        self.queries.insert(id.to_string(), (query, metadata));
    }

    /// Get a query by ID
    pub fn get(&self, id: &str) -> Option<&(Query, QueryMetadata)> {
        self.queries.get(id)
    }

    /// Get all queries in a suite
    pub fn get_suite(&self, suite: QuerySuite) -> Vec<(&str, &Query, &QueryMetadata)> {
        self.queries
            .iter()
            .filter(|(_, (_, meta))| meta.in_suite(suite))
            .map(|(id, (query, meta))| (id.as_str(), query, meta))
            .collect()
    }

    /// Get all queries
    pub fn all_queries(&self) -> Vec<(&str, &Query, &QueryMetadata)> {
        self.queries
            .iter()
            .map(|(id, (query, meta))| (id.as_str(), query, meta))
            .collect()
    }

    /// Get all metadata
    pub fn all_metadata(&self) -> Vec<&QueryMetadata> {
        self.queries.values().map(|(_, meta)| meta).collect()
    }

    // ==================== INJECTION QUERIES (CWE-74 family) ====================

    fn register_injection_queries(&mut self) {
        // SQL Injection - Basic (JS/TS/Python only, Java uses java/sql-injection)
        self.register(
            "js/sql-injection",
            Self::sql_injection_query(),
            QueryMetadata::builder("js/sql-injection", "SQL Injection")
                .description("Detects SQL injection vulnerabilities where user input flows into database queries")
                .category(QueryCategory::Injection)
                .severity(QuerySeverity::Critical)
                .precision(QueryPrecision::High)
                .cwes(vec![89, 564])
                .owasp("A03:2021 - Injection")
                .sans_top_25()
                .uses_taint()
                .tags(vec!["security".to_string(), "sql".to_string(), "injection".to_string()])
                .languages(vec!["javascript".to_string(), "typescript".to_string(), "python".to_string()])
                .build()
        );

        // SQL Injection - More Sources
        self.register(
            "js/sql-injection-extended",
            Self::sql_injection_extended_query(),
            QueryMetadata::builder("js/sql-injection-extended", "SQL Injection (Extended)")
                .description("Extended SQL injection detection with additional heuristics and sources")
                .category(QueryCategory::Injection)
                .severity(QuerySeverity::Critical)
                .precision(QueryPrecision::Medium)
                .cwes(vec![89])
                .owasp("A03:2021 - Injection")
                .sans_top_25()
                .suites(vec![QuerySuite::SecurityExtended, QuerySuite::SecurityAndQuality])
                .uses_taint()
                .languages(vec!["javascript".to_string(), "typescript".to_string(), "python".to_string()])
                .build()
        );

        // NoSQL Injection - JS/TS/Python only (MongoDB, Mongoose, etc.)
        self.register(
            "js/nosql-injection",
            Self::nosql_injection_query(),
            QueryMetadata::builder("js/nosql-injection", "NoSQL Injection")
                .description("Detects NoSQL injection in MongoDB and other NoSQL databases")
                .category(QueryCategory::Injection)
                .severity(QuerySeverity::High)
                .precision(QueryPrecision::High)
                .cwes(vec![89, 943])
                .owasp("A03:2021 - Injection")
                .uses_taint()
                .languages(vec!["javascript".to_string(), "typescript".to_string(), "python".to_string()])
                .build()
        );

        // Command Injection - JS/TS/Python only (Java uses java/command-injection)
        self.register(
            "js/command-injection",
            Self::command_injection_query(),
            QueryMetadata::builder("js/command-injection", "Command Injection")
                .description("Detects OS command injection vulnerabilities")
                .category(QueryCategory::Injection)
                .severity(QuerySeverity::Critical)
                .precision(QueryPrecision::High)
                .cwes(vec![78, 88])
                .owasp("A03:2021 - Injection")
                .sans_top_25()
                .uses_taint()
                .languages(vec!["javascript".to_string(), "typescript".to_string(), "python".to_string()])
                .build()
        );

        // Command Injection - Extended (JS/TS/Python only)
        self.register(
            "js/command-injection-extended",
            Self::command_injection_extended_query(),
            QueryMetadata::builder("js/command-injection-extended", "Command Injection (Extended)")
                .description("Extended command injection detection with shell patterns")
                .category(QueryCategory::Injection)
                .severity(QuerySeverity::Critical)
                .precision(QueryPrecision::Medium)
                .cwes(vec![78])
                .suites(vec![QuerySuite::SecurityExtended, QuerySuite::SecurityAndQuality])
                .uses_taint()
                .languages(vec!["javascript".to_string(), "typescript".to_string(), "python".to_string()])
                .build()
        );

        // LDAP Injection
        self.register(
            "js/ldap-injection",
            Self::ldap_injection_query(),
            QueryMetadata::builder("js/ldap-injection", "LDAP Injection")
                .description("Detects LDAP injection vulnerabilities")
                .category(QueryCategory::Injection)
                .severity(QuerySeverity::High)
                .precision(QueryPrecision::High)
                .cwes(vec![90])
                .owasp("A03:2021 - Injection")
                .uses_taint()
                .build()
        );

        // XPath Injection
        self.register(
            "js/xpath-injection",
            Self::xpath_injection_query(),
            QueryMetadata::builder("js/xpath-injection", "XPath Injection")
                .description("Detects XPath injection vulnerabilities")
                .category(QueryCategory::Injection)
                .severity(QuerySeverity::High)
                .precision(QueryPrecision::High)
                .cwes(vec![643])
                .owasp("A03:2021 - Injection")
                .uses_taint()
                .build()
        );

        // Code Injection (eval) - JS/TS/Python only
        // Note: eval exists in JS, Python, and Lua (loadstring/loadfile)
        self.register(
            "js/code-injection",
            Self::code_injection_query(),
            QueryMetadata::builder("js/code-injection", "Code Injection")
                .description("Detects code injection via eval() and Function()")
                .category(QueryCategory::Injection)
                .severity(QuerySeverity::Critical)
                .precision(QueryPrecision::High)
                .cwes(vec![94, 95])
                .owasp("A03:2021 - Injection")
                .sans_top_25()
                .uses_taint()
                .languages(vec!["javascript".to_string(), "typescript".to_string(), "python".to_string(), "lua".to_string()])
                .build()
        );

        // Server-Side Template Injection
        // Limited to JS/TS/Python - Ruby's `render` is too different (render plain: is not SSTI)
        self.register(
            "js/template-injection",
            Self::template_injection_query(),
            QueryMetadata::builder("js/template-injection", "Server-Side Template Injection")
                .description("Detects template injection leading to RCE")
                .category(QueryCategory::Injection)
                .severity(QuerySeverity::Critical)
                .precision(QueryPrecision::High)
                .cwes(vec![94])
                .owasp("A03:2021 - Injection")
                .uses_taint()
                .languages(vec!["javascript".to_string(), "typescript".to_string(), "python".to_string()])
                .build()
        );

        // Expression Language Injection - Java only (Spring EL, OGNL, etc.)
        self.register(
            "java/expression-injection",
            Self::expression_injection_query(),
            QueryMetadata::builder("java/expression-injection", "Expression Language Injection")
                .description("Detects injection in expression languages (OGNL, SpEL, etc.)")
                .category(QueryCategory::Injection)
                .severity(QuerySeverity::Critical)
                .precision(QueryPrecision::Medium)
                .cwes(vec![917])
                .suites(vec![QuerySuite::SecurityExtended, QuerySuite::SecurityAndQuality])
                .uses_taint()
                .languages(vec!["java".to_string()])
                .build()
        );

        // ==================== JAVA-SPECIFIC INJECTION QUERIES ====================

        // Java SQL Injection
        self.register(
            "java/sql-injection",
            Self::java_sql_injection_query(),
            QueryMetadata::builder("java/sql-injection", "SQL Injection")
                .description("Detects SQL injection in Java applications via Statement and PreparedStatement")
                .category(QueryCategory::Injection)
                .severity(QuerySeverity::Critical)
                .precision(QueryPrecision::High)
                .cwes(vec![89, 564])
                .owasp("A03:2021 - Injection")
                .sans_top_25()
                .uses_taint()
                .languages(vec!["java".to_string()])
                .build()
        );

        // Java Command Injection
        self.register(
            "java/command-injection",
            Self::java_command_injection_query(),
            QueryMetadata::builder("java/command-injection", "Command Injection")
                .description("Detects OS command injection via Runtime.exec() and ProcessBuilder")
                .category(QueryCategory::Injection)
                .severity(QuerySeverity::Critical)
                .precision(QueryPrecision::High)
                .cwes(vec![78, 88])
                .owasp("A03:2021 - Injection")
                .sans_top_25()
                .uses_taint()
                .languages(vec!["java".to_string()])
                .build()
        );

        // Java LDAP Injection
        self.register(
            "java/ldap-injection",
            Self::java_ldap_injection_query(),
            QueryMetadata::builder("java/ldap-injection", "LDAP Injection")
                .description("Detects LDAP injection via DirContext.search()")
                .category(QueryCategory::Injection)
                .severity(QuerySeverity::High)
                .precision(QueryPrecision::High)
                .cwes(vec![90])
                .owasp("A03:2021 - Injection")
                .uses_taint()
                .languages(vec!["java".to_string()])
                .build()
        );

        // Java XPath Injection
        self.register(
            "java/xpath-injection",
            Self::java_xpath_injection_query(),
            QueryMetadata::builder("java/xpath-injection", "XPath Injection")
                .description("Detects XPath injection via XPath.evaluate()")
                .category(QueryCategory::Injection)
                .severity(QuerySeverity::High)
                .precision(QueryPrecision::High)
                .cwes(vec![643])
                .owasp("A03:2021 - Injection")
                .uses_taint()
                .languages(vec!["java".to_string()])
                .build()
        );

        // Java Path Traversal
        self.register(
            "java/path-traversal",
            Self::java_path_traversal_query(),
            QueryMetadata::builder("java/path-traversal", "Path Traversal")
                .description("Detects path traversal vulnerabilities in Java file operations")
                .category(QueryCategory::PathTraversal)
                .severity(QuerySeverity::High)
                .precision(QueryPrecision::High)
                .cwes(vec![22])
                .owasp("A01:2021 - Broken Access Control")
                .sans_top_25()
                .uses_taint()
                .languages(vec!["java".to_string()])
                .build()
        );
    }

    // ==================== XSS QUERIES (CWE-79 family) ====================

    fn register_xss_queries(&mut self) {
        // DOM XSS
        self.register(
            "js/dom-xss",
            Self::dom_xss_query(),
            QueryMetadata::builder("js/dom-xss", "DOM-based XSS")
                .description("Detects DOM-based cross-site scripting")
                .category(QueryCategory::Xss)
                .severity(QuerySeverity::High)
                .precision(QueryPrecision::High)
                .cwes(vec![79, 80])
                .owasp("A03:2021 - Injection")
                .sans_top_25()
                .uses_taint()
                .languages(vec!["javascript".to_string(), "typescript".to_string()])
                .build()
        );

        // Reflected XSS - JS/TS only (Java uses java/reflected-xss)
        self.register(
            "js/reflected-xss",
            Self::reflected_xss_query(),
            QueryMetadata::builder("js/reflected-xss", "Reflected XSS")
                .description("Detects reflected cross-site scripting")
                .category(QueryCategory::Xss)
                .severity(QuerySeverity::High)
                .precision(QueryPrecision::High)
                .cwes(vec![79])
                .owasp("A03:2021 - Injection")
                .sans_top_25()
                .uses_taint()
                .languages(vec!["javascript".to_string(), "typescript".to_string(), "python".to_string()])
                .build()
        );

        // Stored XSS
        self.register(
            "js/stored-xss",
            Self::stored_xss_query(),
            QueryMetadata::builder("js/stored-xss", "Stored XSS")
                .description("Detects stored cross-site scripting")
                .category(QueryCategory::Xss)
                .severity(QuerySeverity::Critical)
                .precision(QueryPrecision::Medium)
                .cwes(vec![79])
                .owasp("A03:2021 - Injection")
                .suites(vec![QuerySuite::SecurityExtended, QuerySuite::SecurityAndQuality])
                .uses_taint()
                .build()
        );

        // Unsafe innerHTML
        self.register(
            "js/unsafe-innerhtml",
            Self::unsafe_innerhtml_query(),
            QueryMetadata::builder("js/unsafe-innerhtml", "Unsafe innerHTML Assignment")
                .description("Detects dangerous use of innerHTML with untrusted data")
                .category(QueryCategory::Xss)
                .severity(QuerySeverity::High)
                .precision(QueryPrecision::High)
                .cwes(vec![79])
                .owasp("A03:2021 - Injection")
                .uses_taint()
                .languages(vec!["javascript".to_string(), "typescript".to_string()])
                .build()
        );

        // document.write XSS
        self.register(
            "js/document-write-xss",
            Self::document_write_xss_query(),
            QueryMetadata::builder("js/document-write-xss", "document.write XSS")
                .description("Detects XSS via document.write()")
                .category(QueryCategory::Xss)
                .severity(QuerySeverity::High)
                .precision(QueryPrecision::High)
                .cwes(vec![79])
                .owasp("A03:2021 - Injection")
                .uses_taint()
                .languages(vec!["javascript".to_string(), "typescript".to_string()])
                .build()
        );

        // jQuery XSS
        self.register(
            "js/jquery-xss",
            Self::jquery_xss_query(),
            QueryMetadata::builder("js/jquery-xss", "jQuery XSS")
                .description("Detects XSS through unsafe jQuery methods")
                .category(QueryCategory::Xss)
                .severity(QuerySeverity::High)
                .precision(QueryPrecision::Medium)
                .cwes(vec![79])
                .suites(vec![QuerySuite::SecurityExtended, QuerySuite::SecurityAndQuality])
                .uses_taint()
                .languages(vec!["javascript".to_string(), "typescript".to_string()])
                .build()
        );

        // React dangerouslySetInnerHTML
        self.register(
            "js/react-dangerous-html",
            Self::react_dangerous_html_query(),
            QueryMetadata::builder("js/react-dangerous-html", "React dangerouslySetInnerHTML")
                .description("Detects use of dangerouslySetInnerHTML with untrusted data")
                .category(QueryCategory::Xss)
                .severity(QuerySeverity::High)
                .precision(QueryPrecision::High)
                .cwes(vec![79])
                .tags(vec!["react".to_string()])
                .uses_taint()
                .languages(vec!["javascript".to_string(), "typescript".to_string()])
                .build()
        );

        // Angular $sce bypass
        self.register(
            "js/angular-sce-bypass",
            Self::angular_sce_bypass_query(),
            QueryMetadata::builder("js/angular-sce-bypass", "Angular SCE Bypass")
                .description("Detects Angular Strict Contextual Escaping bypass")
                .category(QueryCategory::Xss)
                .severity(QuerySeverity::High)
                .precision(QueryPrecision::High)
                .cwes(vec![79])
                .tags(vec!["angular".to_string()])
                .uses_taint()
                .languages(vec!["javascript".to_string(), "typescript".to_string()])
                .build()
        );
    }

    // ==================== AUTHENTICATION & AUTHORIZATION ====================

    fn register_authentication_queries(&mut self) {
        // Hardcoded Credentials
        self.register(
            "js/hardcoded-credentials",
            Self::hardcoded_credentials_query(),
            QueryMetadata::builder("js/hardcoded-credentials", "Hardcoded Credentials")
                .description("Detects hardcoded passwords and API keys")
                .category(QueryCategory::Authentication)
                .severity(QuerySeverity::Critical)
                .precision(QueryPrecision::Medium)
                .cwes(vec![798, 259])
                .owasp("A07:2021 - Identification and Authentication Failures")
                .sans_top_25()
                .build()
        );

        // Weak Password Requirements
        self.register(
            "js/weak-password-requirements",
            Self::weak_password_requirements_query(),
            QueryMetadata::builder("js/weak-password-requirements", "Weak Password Requirements")
                .description("Detects weak password validation rules")
                .category(QueryCategory::Authentication)
                .severity(QuerySeverity::Medium)
                .precision(QueryPrecision::Medium)
                .cwes(vec![521])
                .owasp("A07:2021 - Identification and Authentication Failures")
                .suites(vec![QuerySuite::SecurityExtended, QuerySuite::SecurityAndQuality])
                .build()
        );

        // Missing Authentication
        self.register(
            "js/missing-authentication",
            Self::missing_authentication_query(),
            QueryMetadata::builder("js/missing-authentication", "Missing Authentication")
                .description("Detects API endpoints without authentication checks")
                .category(QueryCategory::Authentication)
                .severity(QuerySeverity::High)
                .precision(QueryPrecision::Low)
                .cwes(vec![306])
                .owasp("A07:2021 - Identification and Authentication Failures")
                .suites(vec![QuerySuite::SecurityAndQuality])
                .build()
        );

        // Broken Access Control
        self.register(
            "js/broken-access-control",
            Self::broken_access_control_query(),
            QueryMetadata::builder("js/broken-access-control", "Broken Access Control")
                .description("Detects missing authorization checks")
                .category(QueryCategory::Authentication)
                .severity(QuerySeverity::High)
                .precision(QueryPrecision::Low)
                .cwes(vec![285])
                .owasp("A01:2021 - Broken Access Control")
                .sans_top_25()
                .suites(vec![QuerySuite::SecurityExtended, QuerySuite::SecurityAndQuality])
                .build()
        );

        // JWT None Algorithm
        self.register(
            "js/jwt-none-algorithm",
            Self::jwt_none_algorithm_query(),
            QueryMetadata::builder("js/jwt-none-algorithm", "JWT None Algorithm")
                .description("Detects JWT verification with 'none' algorithm")
                .category(QueryCategory::Authentication)
                .severity(QuerySeverity::Critical)
                .precision(QueryPrecision::VeryHigh)
                .cwes(vec![347])
                .owasp("A07:2021 - Identification and Authentication Failures")
                .build()
        );

        // JWT Weak Secret
        self.register(
            "js/jwt-weak-secret",
            Self::jwt_weak_secret_query(),
            QueryMetadata::builder("js/jwt-weak-secret", "JWT Weak Secret")
                .description("Detects weak secrets in JWT signing")
                .category(QueryCategory::Authentication)
                .severity(QuerySeverity::High)
                .precision(QueryPrecision::Medium)
                .cwes(vec![347])
                .suites(vec![QuerySuite::SecurityExtended, QuerySuite::SecurityAndQuality])
                .build()
        );

        // Session Fixation
        self.register(
            "js/session-fixation",
            Self::session_fixation_query(),
            QueryMetadata::builder("js/session-fixation", "Session Fixation")
                .description("Detects session fixation vulnerabilities")
                .category(QueryCategory::Authentication)
                .severity(QuerySeverity::High)
                .precision(QueryPrecision::Medium)
                .cwes(vec![384])
                .owasp("A07:2021 - Identification and Authentication Failures")
                .suites(vec![QuerySuite::SecurityExtended, QuerySuite::SecurityAndQuality])
                .build()
        );

        // Insecure Session Cookie
        self.register(
            "js/insecure-session-cookie",
            Self::insecure_session_cookie_query(),
            QueryMetadata::builder("js/insecure-session-cookie", "Insecure Session Cookie")
                .description("Detects session cookies without Secure/HttpOnly flags")
                .category(QueryCategory::Authentication)
                .severity(QuerySeverity::Medium)
                .precision(QueryPrecision::High)
                .cwes(vec![614, 1004])
                .owasp("A05:2021 - Security Misconfiguration")
                .build()
        );
    }

    // ==================== CRYPTOGRAPHY QUERIES ====================

    fn register_cryptography_queries(&mut self) {
        // Weak Hash (MD5/SHA1)
        self.register(
            "js/weak-hash",
            Self::weak_hash_query(),
            QueryMetadata::builder("js/weak-hash", "Weak Hash Algorithm")
                .description("Detects use of weak hash algorithms (MD5, SHA1)")
                .category(QueryCategory::Cryptography)
                .severity(QuerySeverity::High)
                .precision(QueryPrecision::VeryHigh)
                .cwes(vec![327, 328])
                .owasp("A02:2021 - Cryptographic Failures")
                .sans_top_25()
                .build()
        );

        // Java Weak Hash - detects MessageDigest.getInstance with variable algorithm from properties
        // This catches cases where algorithm comes from getProperty() which may resolve to MD5/SHA1
        // Note: This adds 40 TPs but also 33 FPs on OWASP benchmark (hashAlg1=MD5 vs hashAlg2=SHA-256)
        // Overall Java precision impact is minimal (~97% → ~95%), and recall improves significantly
        self.register(
            "java/weak-hash-variable",
            Self::java_weak_hash_variable_query(),
            QueryMetadata::builder("java/weak-hash-variable", "Weak Hash Algorithm (Variable)")
                .description("Detects MessageDigest.getInstance() with algorithm from external configuration")
                .category(QueryCategory::Cryptography)
                .severity(QuerySeverity::Medium)
                .precision(QueryPrecision::Medium)
                .cwes(vec![327, 328])
                .owasp("A02:2021 - Cryptographic Failures")
                .languages(vec!["java".to_string()])
                .build()
        );

        // Weak Cipher (DES/RC4) - JS/TS only due to createCipher pattern
        self.register(
            "js/weak-cipher",
            Self::weak_cipher_query(),
            QueryMetadata::builder("js/weak-cipher", "Weak Encryption Cipher")
                .description("Detects use of weak encryption ciphers (DES, RC4)")
                .category(QueryCategory::Cryptography)
                .severity(QuerySeverity::Critical)
                .precision(QueryPrecision::VeryHigh)
                .cwes(vec![327])
                .owasp("A02:2021 - Cryptographic Failures")
                .sans_top_25()
                .languages(vec!["javascript".to_string(), "typescript".to_string(), "java".to_string()])
                .build()
        );

        // ECB Mode - JS/TS only
        self.register(
            "js/ecb-mode",
            Self::ecb_mode_query(),
            QueryMetadata::builder("js/ecb-mode", "ECB Cipher Mode")
                .description("Detects use of insecure ECB cipher mode")
                .category(QueryCategory::Cryptography)
                .severity(QuerySeverity::High)
                .precision(QueryPrecision::VeryHigh)
                .cwes(vec![327])
                .owasp("A02:2021 - Cryptographic Failures")
                .languages(vec!["javascript".to_string(), "typescript".to_string()])
                .build()
        );

        // Insufficient Key Size - JS/TS only
        self.register(
            "js/insufficient-key-size",
            Self::insufficient_key_size_query(),
            QueryMetadata::builder("js/insufficient-key-size", "Insufficient Key Size")
                .description("Detects cryptographic keys that are too small")
                .category(QueryCategory::Cryptography)
                .severity(QuerySeverity::High)
                .precision(QueryPrecision::Medium)
                .cwes(vec![326])
                .owasp("A02:2021 - Cryptographic Failures")
                .suites(vec![QuerySuite::SecurityExtended, QuerySuite::SecurityAndQuality])
                .languages(vec!["javascript".to_string(), "typescript".to_string()])
                .build()
        );

        // Hardcoded Crypto Key - JS/TS only
        self.register(
            "js/hardcoded-crypto-key",
            Self::hardcoded_crypto_key_query(),
            QueryMetadata::builder("js/hardcoded-crypto-key", "Hardcoded Cryptographic Key")
                .description("Detects hardcoded encryption keys")
                .category(QueryCategory::Cryptography)
                .severity(QuerySeverity::Critical)
                .precision(QueryPrecision::Medium)
                .cwes(vec![321])
                .owasp("A02:2021 - Cryptographic Failures")
                .languages(vec!["javascript".to_string(), "typescript".to_string()])
                .build()
        );

        // Insecure Random - JS/TS only (Math.random pattern)
        self.register(
            "js/insecure-random",
            Self::insecure_random_query(),
            QueryMetadata::builder("js/insecure-random", "Insecure Randomness")
                .description("Detects use of Math.random() for security purposes")
                .category(QueryCategory::Cryptography)
                .severity(QuerySeverity::High)
                .precision(QueryPrecision::Medium)
                .cwes(vec![330])
                .owasp("A02:2021 - Cryptographic Failures")
                .sans_top_25()
                .suites(vec![QuerySuite::Default, QuerySuite::SecurityExtended, QuerySuite::SecurityAndQuality])
                .languages(vec!["javascript".to_string(), "typescript".to_string()])
                .build()
        );

        // Java Weak Randomness - Detects java.util.Random and Math.random (but NOT SecureRandom)
        self.register(
            "java/weak-random",
            Self::java_weak_random_query(),
            QueryMetadata::builder("java/weak-random", "Weak Randomness")
                .description("Detects use of java.util.Random or Math.random() for security purposes")
                .category(QueryCategory::Cryptography)
                .severity(QuerySeverity::High)
                .precision(QueryPrecision::High)
                .cwes(vec![330])
                .owasp("A02:2021 - Cryptographic Failures")
                .sans_top_25()
                .suites(vec![QuerySuite::Default, QuerySuite::SecurityExtended, QuerySuite::SecurityAndQuality])
                .languages(vec!["java".to_string()])
                .build()
        );

        // Python Weak Randomness - Detects random module (but NOT random.SystemRandom or secrets)
        self.register(
            "python/weak-random",
            Self::python_weak_random_query(),
            QueryMetadata::builder("python/weak-random", "Weak Randomness")
                .description("Detects use of random module for security purposes (use secrets module)")
                .category(QueryCategory::Cryptography)
                .severity(QuerySeverity::High)
                .precision(QueryPrecision::High)
                .cwes(vec![330])
                .owasp("A02:2021 - Cryptographic Failures")
                .sans_top_25()
                .suites(vec![QuerySuite::Default, QuerySuite::SecurityExtended, QuerySuite::SecurityAndQuality])
                .languages(vec!["python".to_string()])
                .build()
        );

        // Ruby Weak Randomness - Detects rand() and Random.rand() (but NOT SecureRandom)
        self.register(
            "ruby/weak-random",
            Self::ruby_weak_random_query(),
            QueryMetadata::builder("ruby/weak-random", "Weak Randomness")
                .description("Detects use of rand() for security purposes (use SecureRandom)")
                .category(QueryCategory::Cryptography)
                .severity(QuerySeverity::High)
                .precision(QueryPrecision::High)
                .cwes(vec![330])
                .owasp("A02:2021 - Cryptographic Failures")
                .sans_top_25()
                .suites(vec![QuerySuite::Default, QuerySuite::SecurityExtended, QuerySuite::SecurityAndQuality])
                .languages(vec!["ruby".to_string()])
                .build()
        );

        // Go Weak Randomness - Detects math/rand package (but NOT crypto/rand)
        self.register(
            "go/weak-random",
            Self::go_weak_random_query(),
            QueryMetadata::builder("go/weak-random", "Weak Randomness")
                .description("Detects use of math/rand for security purposes (use crypto/rand)")
                .category(QueryCategory::Cryptography)
                .severity(QuerySeverity::High)
                .precision(QueryPrecision::High)
                .cwes(vec![330])
                .owasp("A02:2021 - Cryptographic Failures")
                .sans_top_25()
                .suites(vec![QuerySuite::Default, QuerySuite::SecurityExtended, QuerySuite::SecurityAndQuality])
                .languages(vec!["go".to_string()])
                .build()
        );

        // Rust Weak Randomness - Detects rand crate without OS randomness
        self.register(
            "rust/weak-random",
            Self::rust_weak_random_query(),
            QueryMetadata::builder("rust/weak-random", "Weak Randomness")
                .description("Detects use of rand crate for security purposes (use rand::rngs::OsRng)")
                .category(QueryCategory::Cryptography)
                .severity(QuerySeverity::High)
                .precision(QueryPrecision::High)
                .cwes(vec![330])
                .owasp("A02:2021 - Cryptographic Failures")
                .sans_top_25()
                .suites(vec![QuerySuite::Default, QuerySuite::SecurityExtended, QuerySuite::SecurityAndQuality])
                .languages(vec!["rust".to_string()])
                .build()
        );

        // Java Insecure Cookie - Detects setSecure(false)
        self.register(
            "java/insecure-cookie",
            Self::java_insecure_cookie_query(),
            QueryMetadata::builder("java/insecure-cookie", "Insecure Cookie")
                .description("Detects cookies without secure flag (setSecure(false))")
                .category(QueryCategory::Authentication)
                .severity(QuerySeverity::Medium)
                .precision(QueryPrecision::High)
                .cwes(vec![614])
                .owasp("A05:2021 - Security Misconfiguration")
                .suites(vec![QuerySuite::Default, QuerySuite::SecurityExtended, QuerySuite::SecurityAndQuality])
                .languages(vec!["java".to_string()])
                .build()
        );

        // Missing Salt - JS/TS only
        self.register(
            "js/missing-salt",
            Self::missing_salt_query(),
            QueryMetadata::builder("js/missing-salt", "Missing Salt in Hash")
                .description("Detects password hashing without salt")
                .category(QueryCategory::Cryptography)
                .severity(QuerySeverity::High)
                .precision(QueryPrecision::Medium)
                .cwes(vec![759])
                .owasp("A02:2021 - Cryptographic Failures")
                .suites(vec![QuerySuite::SecurityExtended, QuerySuite::SecurityAndQuality])
                .languages(vec!["javascript".to_string(), "typescript".to_string()])
                .build()
        );

        // Predictable Seed - JS/TS only
        self.register(
            "js/predictable-seed",
            Self::predictable_seed_query(),
            QueryMetadata::builder("js/predictable-seed", "Predictable Seed")
                .description("Detects predictable seeds in random number generators")
                .category(QueryCategory::Cryptography)
                .severity(QuerySeverity::Medium)
                .precision(QueryPrecision::Medium)
                .cwes(vec![337])
                .suites(vec![QuerySuite::SecurityAndQuality])
                .languages(vec!["javascript".to_string(), "typescript".to_string()])
                .build()
        );
    }

    // ==================== PATH TRAVERSAL & FILE ACCESS ====================

    fn register_path_traversal_queries(&mut self) {
        // Path Traversal - JS/TS/Python only (Java uses java/path-traversal)
        self.register(
            "js/path-traversal",
            Self::path_traversal_query(),
            QueryMetadata::builder("js/path-traversal", "Path Traversal")
                .description("Detects path traversal vulnerabilities")
                .category(QueryCategory::PathTraversal)
                .severity(QuerySeverity::High)
                .precision(QueryPrecision::High)
                .cwes(vec![22])
                .owasp("A01:2021 - Broken Access Control")
                .sans_top_25()
                .uses_taint()
                .languages(vec!["javascript".to_string(), "typescript".to_string(), "python".to_string()])
                .build()
        );

        // Zip Slip - JS/TS only
        self.register(
            "js/zip-slip",
            Self::zip_slip_query(),
            QueryMetadata::builder("js/zip-slip", "Zip Slip")
                .description("Detects zip slip vulnerability during archive extraction")
                .category(QueryCategory::PathTraversal)
                .severity(QuerySeverity::High)
                .precision(QueryPrecision::High)
                .cwes(vec![22])
                .sans_top_25()
                .uses_taint()
                .languages(vec!["javascript".to_string(), "typescript".to_string()])
                .build()
        );

        // Arbitrary File Write - JS/TS only
        self.register(
            "js/arbitrary-file-write",
            Self::arbitrary_file_write_query(),
            QueryMetadata::builder("js/arbitrary-file-write", "Arbitrary File Write")
                .description("Detects writing to user-controlled file paths")
                .category(QueryCategory::PathTraversal)
                .severity(QuerySeverity::Critical)
                .precision(QueryPrecision::High)
                .cwes(vec![73])
                .uses_taint()
                .languages(vec!["javascript".to_string(), "typescript".to_string()])
                .build()
        );

        // Unsafe File Upload - JS/TS only
        self.register(
            "js/unsafe-file-upload",
            Self::unsafe_file_upload_query(),
            QueryMetadata::builder("js/unsafe-file-upload", "Unsafe File Upload")
                .description("Detects unrestricted file uploads")
                .category(QueryCategory::PathTraversal)
                .severity(QuerySeverity::High)
                .precision(QueryPrecision::Medium)
                .cwes(vec![434])
                .owasp("A04:2021 - Insecure Design")
                .sans_top_25()
                .suites(vec![QuerySuite::SecurityExtended, QuerySuite::SecurityAndQuality])
                .languages(vec!["javascript".to_string(), "typescript".to_string()])
                .build()
        );
    }

    // ==================== INFORMATION DISCLOSURE ====================

    fn register_information_disclosure_queries(&mut self) {
        // Stack Trace Exposure - JS/TS only
        self.register(
            "js/stack-trace-exposure",
            Self::stack_trace_exposure_query(),
            QueryMetadata::builder("js/stack-trace-exposure", "Stack Trace Exposure")
                .description("Detects stack traces sent to users")
                .category(QueryCategory::InformationDisclosure)
                .severity(QuerySeverity::Medium)
                .precision(QueryPrecision::Medium)
                .cwes(vec![209])
                .owasp("A05:2021 - Security Misconfiguration")
                .suites(vec![QuerySuite::SecurityExtended, QuerySuite::SecurityAndQuality])
                .languages(vec!["javascript".to_string(), "typescript".to_string()])
                .build()
        );

        // Sensitive Data in Log - JS/TS only
        self.register(
            "js/sensitive-data-log",
            Self::sensitive_data_log_query(),
            QueryMetadata::builder("js/sensitive-data-log", "Sensitive Data in Log")
                .description("Detects logging of sensitive data")
                .category(QueryCategory::InformationDisclosure)
                .severity(QuerySeverity::Medium)
                .precision(QueryPrecision::Medium)
                .cwes(vec![532])
                .owasp("A09:2021 - Security Logging and Monitoring Failures")
                .suites(vec![QuerySuite::SecurityAndQuality])
                .uses_taint()
                .build()
        );

        // Clear-text Transmission
        self.register(
            "js/cleartext-transmission",
            Self::cleartext_transmission_query(),
            QueryMetadata::builder("js/cleartext-transmission", "Clear-text Transmission")
                .description("Detects transmission of sensitive data without encryption")
                .category(QueryCategory::InformationDisclosure)
                .severity(QuerySeverity::High)
                .precision(QueryPrecision::Medium)
                .cwes(vec![319])
                .owasp("A02:2021 - Cryptographic Failures")
                .sans_top_25()
                .suites(vec![QuerySuite::SecurityExtended, QuerySuite::SecurityAndQuality])
                .build()
        );

        // Clear-text Storage
        self.register(
            "js/cleartext-storage",
            Self::cleartext_storage_query(),
            QueryMetadata::builder("js/cleartext-storage", "Clear-text Storage")
                .description("Detects storage of sensitive data without encryption")
                .category(QueryCategory::InformationDisclosure)
                .severity(QuerySeverity::High)
                .precision(QueryPrecision::Medium)
                .cwes(vec![312])
                .owasp("A02:2021 - Cryptographic Failures")
                .sans_top_25()
                .suites(vec![QuerySuite::SecurityExtended, QuerySuite::SecurityAndQuality])
                .build()
        );

        // Information Exposure Through Error
        self.register(
            "js/error-message-exposure",
            Self::error_message_exposure_query(),
            QueryMetadata::builder("js/error-message-exposure", "Information Exposure Through Error")
                .description("Detects detailed error messages exposed to users")
                .category(QueryCategory::InformationDisclosure)
                .severity(QuerySeverity::Low)
                .precision(QueryPrecision::Low)
                .cwes(vec![209])
                .suites(vec![QuerySuite::SecurityAndQuality])
                .build()
        );
    }

    // ==================== CODE QUALITY ====================

    fn register_code_quality_queries(&mut self) {
        // Unused Variable
        self.register(
            "js/unused-variable",
            Self::unused_variable_query(),
            QueryMetadata::builder("js/unused-variable", "Unused Variable")
                .description("Detects variables that are declared but never used")
                .category(QueryCategory::CodeQuality)
                .severity(QuerySeverity::Info)
                .precision(QueryPrecision::High)
                .cwes(vec![563])
                .suites(vec![QuerySuite::SecurityAndQuality])
                .build()
        );

        // Dead Code
        self.register(
            "js/dead-code",
            Self::dead_code_query(),
            QueryMetadata::builder("js/dead-code", "Dead Code")
                .description("Detects unreachable code")
                .category(QueryCategory::CodeQuality)
                .severity(QuerySeverity::Info)
                .precision(QueryPrecision::Medium)
                .cwes(vec![561])
                .suites(vec![QuerySuite::SecurityAndQuality])
                .build()
        );

        // Duplicate Code
        self.register(
            "js/duplicate-code",
            Self::duplicate_code_query(),
            QueryMetadata::builder("js/duplicate-code", "Duplicate Code")
                .description("Detects code duplication")
                .category(QueryCategory::CodeQuality)
                .severity(QuerySeverity::Info)
                .precision(QueryPrecision::Low)
                .suites(vec![QuerySuite::SecurityAndQuality])
                .build()
        );

        // Complex Function
        self.register(
            "js/complex-function",
            Self::complex_function_query(),
            QueryMetadata::builder("js/complex-function", "Complex Function")
                .description("Detects functions with high cyclomatic complexity")
                .category(QueryCategory::CodeQuality)
                .severity(QuerySeverity::Info)
                .precision(QueryPrecision::Medium)
                .suites(vec![QuerySuite::SecurityAndQuality])
                .build()
        );

        // Missing Error Handling
        self.register(
            "js/missing-error-handling",
            Self::missing_error_handling_query(),
            QueryMetadata::builder("js/missing-error-handling", "Missing Error Handling")
                .description("Detects async operations without error handling")
                .category(QueryCategory::ErrorHandling)
                .severity(QuerySeverity::Medium)
                .precision(QueryPrecision::Medium)
                .cwes(vec![391])
                .suites(vec![QuerySuite::SecurityAndQuality])
                .build()
        );
    }

    // ==================== RESOURCE MANAGEMENT ====================

    fn register_resource_management_queries(&mut self) {
        // Regular Expression DoS
        self.register(
            "js/redos",
            Self::redos_query(),
            QueryMetadata::builder("js/redos", "Regular Expression Denial of Service")
                .description("Detects regex patterns vulnerable to ReDoS")
                .category(QueryCategory::ResourceManagement)
                .severity(QuerySeverity::High)
                .precision(QueryPrecision::Medium)
                .cwes(vec![1333, 400])
                .owasp("A05:2021 - Security Misconfiguration")
                .suites(vec![QuerySuite::SecurityExtended, QuerySuite::SecurityAndQuality])
                .build()
        );

        // XML Bomb
        self.register(
            "js/xml-bomb",
            Self::xml_bomb_query(),
            QueryMetadata::builder("js/xml-bomb", "XML Bomb / Billion Laughs")
                .description("Detects XML parsers vulnerable to entity expansion attacks")
                .category(QueryCategory::ResourceManagement)
                .severity(QuerySeverity::High)
                .precision(QueryPrecision::Medium)
                .cwes(vec![776])
                .suites(vec![QuerySuite::SecurityExtended, QuerySuite::SecurityAndQuality])
                .build()
        );

        // Uncontrolled Resource Consumption
        self.register(
            "js/uncontrolled-resource",
            Self::uncontrolled_resource_query(),
            QueryMetadata::builder("js/uncontrolled-resource", "Uncontrolled Resource Consumption")
                .description("Detects operations that may consume excessive resources")
                .category(QueryCategory::ResourceManagement)
                .severity(QuerySeverity::Medium)
                .precision(QueryPrecision::Low)
                .cwes(vec![400])
                .suites(vec![QuerySuite::SecurityAndQuality])
                .build()
        );

        // Memory Leak
        self.register(
            "js/memory-leak",
            Self::memory_leak_query(),
            QueryMetadata::builder("js/memory-leak", "Potential Memory Leak")
                .description("Detects patterns that may cause memory leaks")
                .category(QueryCategory::ResourceManagement)
                .severity(QuerySeverity::Medium)
                .precision(QueryPrecision::Low)
                .cwes(vec![401])
                .suites(vec![QuerySuite::SecurityAndQuality])
                .build()
        );
    }

    // ==================== ERROR HANDLING ====================

    fn register_error_handling_queries(&mut self) {
        // Empty Catch Block
        self.register(
            "js/empty-catch-block",
            Self::empty_catch_block_query(),
            QueryMetadata::builder("js/empty-catch-block", "Empty Catch Block")
                .description("Detects empty catch blocks that suppress errors")
                .category(QueryCategory::ErrorHandling)
                .severity(QuerySeverity::Medium)
                .precision(QueryPrecision::High)
                .cwes(vec![391])
                .suites(vec![QuerySuite::SecurityAndQuality])
                .build()
        );

        // Generic Exception Catch
        self.register(
            "js/generic-exception",
            Self::generic_exception_query(),
            QueryMetadata::builder("js/generic-exception", "Generic Exception Catch")
                .description("Detects overly broad exception catching")
                .category(QueryCategory::ErrorHandling)
                .severity(QuerySeverity::Low)
                .precision(QueryPrecision::Medium)
                .cwes(vec![396])
                .suites(vec![QuerySuite::SecurityAndQuality])
                .build()
        );

        // Unhandled Promise Rejection
        self.register(
            "js/unhandled-promise-rejection",
            Self::unhandled_promise_rejection_query(),
            QueryMetadata::builder("js/unhandled-promise-rejection", "Unhandled Promise Rejection")
                .description("Detects promises without rejection handlers")
                .category(QueryCategory::ErrorHandling)
                .severity(QuerySeverity::Medium)
                .precision(QueryPrecision::Medium)
                .cwes(vec![755])
                .suites(vec![QuerySuite::SecurityAndQuality])
                .languages(vec!["javascript".to_string(), "typescript".to_string()])
                .build()
        );
    }

    // ==================== API MISUSE ====================

    fn register_api_misuse_queries(&mut self) {
        // Server-Side Request Forgery (SSRF) - JS/TS only to avoid matching route definitions
        self.register(
            "js/ssrf",
            Self::ssrf_query(),
            QueryMetadata::builder("js/ssrf", "Server-Side Request Forgery")
                .description("Detects SSRF vulnerabilities")
                .category(QueryCategory::ApiMisuse)
                .severity(QuerySeverity::Critical)
                .precision(QueryPrecision::High)
                .cwes(vec![918])
                .owasp("A10:2021 - Server-Side Request Forgery")
                .sans_top_25()
                .uses_taint()
                .languages(vec!["javascript".to_string(), "typescript".to_string()])
                .build()
        );

        // XXE (XML External Entity)
        self.register(
            "js/xxe",
            Self::xxe_query(),
            QueryMetadata::builder("js/xxe", "XML External Entity Injection")
                .description("Detects XXE vulnerabilities")
                .category(QueryCategory::ApiMisuse)
                .severity(QuerySeverity::High)
                .precision(QueryPrecision::High)
                .cwes(vec![611])
                .owasp("A05:2021 - Security Misconfiguration")
                .sans_top_25()
                .build()
        );

        // Insecure Deserialization
        self.register(
            "js/insecure-deserialization",
            Self::insecure_deserialization_query(),
            QueryMetadata::builder("js/insecure-deserialization", "Insecure Deserialization")
                .description("Detects insecure deserialization leading to RCE")
                .category(QueryCategory::ApiMisuse)
                .severity(QuerySeverity::Critical)
                .precision(QueryPrecision::High)
                .cwes(vec![502])
                .owasp("A08:2021 - Software and Data Integrity Failures")
                .sans_top_25()
                .uses_taint()
                .build()
        );

        // Prototype Pollution
        self.register(
            "js/prototype-pollution",
            Self::prototype_pollution_query(),
            QueryMetadata::builder("js/prototype-pollution", "Prototype Pollution")
                .description("Detects prototype pollution vulnerabilities")
                .category(QueryCategory::ApiMisuse)
                .severity(QuerySeverity::High)
                .precision(QueryPrecision::Medium)
                .cwes(vec![1321])
                .sans_top_25()
                .suites(vec![QuerySuite::SecurityExtended, QuerySuite::SecurityAndQuality])
                .uses_taint()
                .languages(vec!["javascript".to_string(), "typescript".to_string()])
                .build()
        );

        // Open Redirect
        self.register(
            "js/open-redirect",
            Self::open_redirect_query(),
            QueryMetadata::builder("js/open-redirect", "Open Redirect")
                .description("Detects unvalidated redirects")
                .category(QueryCategory::ApiMisuse)
                .severity(QuerySeverity::Medium)
                .precision(QueryPrecision::High)
                .cwes(vec![601])
                .owasp("A01:2021 - Broken Access Control")
                .uses_taint()
                .build()
        );

        // CORS Misconfiguration
        self.register(
            "js/cors-misconfiguration",
            Self::cors_misconfiguration_query(),
            QueryMetadata::builder("js/cors-misconfiguration", "CORS Misconfiguration")
                .description("Detects overly permissive CORS configurations")
                .category(QueryCategory::ApiMisuse)
                .severity(QuerySeverity::High)
                .precision(QueryPrecision::High)
                .cwes(vec![346])
                .owasp("A05:2021 - Security Misconfiguration")
                .build()
        );
    }

    // ==================== CONFIGURATION ====================

    fn register_configuration_queries(&mut self) {
        // Debug Mode in Production
        self.register(
            "js/debug-mode-production",
            Self::debug_mode_production_query(),
            QueryMetadata::builder("js/debug-mode-production", "Debug Mode in Production")
                .description("Detects debug mode enabled in production")
                .category(QueryCategory::Configuration)
                .severity(QuerySeverity::Medium)
                .precision(QueryPrecision::Medium)
                .cwes(vec![489])
                .owasp("A05:2021 - Security Misconfiguration")
                .suites(vec![QuerySuite::SecurityExtended, QuerySuite::SecurityAndQuality])
                .build()
        );

        // Missing Security Headers
        self.register(
            "js/missing-security-headers",
            Self::missing_security_headers_query(),
            QueryMetadata::builder("js/missing-security-headers", "Missing Security Headers")
                .description("Detects missing HTTP security headers")
                .category(QueryCategory::Configuration)
                .severity(QuerySeverity::Medium)
                .precision(QueryPrecision::Medium)
                .cwes(vec![1021])
                .owasp("A05:2021 - Security Misconfiguration")
                .suites(vec![QuerySuite::SecurityExtended, QuerySuite::SecurityAndQuality])
                .build()
        );

        // Disabled HTTPS
        self.register(
            "js/disabled-https",
            Self::disabled_https_query(),
            QueryMetadata::builder("js/disabled-https", "Disabled HTTPS")
                .description("Detects HTTPS disabled or not enforced")
                .category(QueryCategory::Configuration)
                .severity(QuerySeverity::High)
                .precision(QueryPrecision::High)
                .cwes(vec![311])
                .owasp("A02:2021 - Cryptographic Failures")
                .build()
        );

        // Disabled Certificate Validation
        self.register(
            "js/disabled-cert-validation",
            Self::disabled_cert_validation_query(),
            QueryMetadata::builder("js/disabled-cert-validation", "Disabled Certificate Validation")
                .description("Detects disabled SSL/TLS certificate validation")
                .category(QueryCategory::Configuration)
                .severity(QuerySeverity::Critical)
                .precision(QueryPrecision::VeryHigh)
                .cwes(vec![295])
                .owasp("A02:2021 - Cryptographic Failures")
                .sans_top_25()
                .build()
        );
    }

    // ==================== FRAMEWORK-SPECIFIC ====================

    fn register_framework_queries(&mut self) {
        // Express Session Secret
        self.register(
            "js/express-weak-session-secret",
            Self::express_weak_session_secret_query(),
            QueryMetadata::builder("js/express-weak-session-secret", "Express Weak Session Secret")
                .description("Detects weak session secrets in Express.js")
                .category(QueryCategory::FrameworkSpecific)
                .severity(QuerySeverity::High)
                .precision(QueryPrecision::High)
                .cwes(vec![330])
                .tags(vec!["express".to_string(), "nodejs".to_string()])
                .languages(vec!["javascript".to_string(), "typescript".to_string()])
                .build()
        );

        // Express Missing Helmet
        self.register(
            "js/express-missing-helmet",
            Self::express_missing_helmet_query(),
            QueryMetadata::builder("js/express-missing-helmet", "Express Missing Helmet")
                .description("Detects Express.js apps without Helmet security middleware")
                .category(QueryCategory::FrameworkSpecific)
                .severity(QuerySeverity::Medium)
                .precision(QueryPrecision::Medium)
                .cwes(vec![1021])
                .tags(vec!["express".to_string()])
                .suites(vec![QuerySuite::SecurityExtended, QuerySuite::SecurityAndQuality])
                .languages(vec!["javascript".to_string(), "typescript".to_string()])
                .build()
        );

        // MongoDB Injection
        self.register(
            "js/mongodb-injection",
            Self::mongodb_injection_query(),
            QueryMetadata::builder("js/mongodb-injection", "MongoDB Injection")
                .description("Detects NoSQL injection in MongoDB queries")
                .category(QueryCategory::Injection)
                .severity(QuerySeverity::High)
                .precision(QueryPrecision::High)
                .cwes(vec![943])
                .tags(vec!["mongodb".to_string()])
                .uses_taint()
                .languages(vec!["javascript".to_string(), "typescript".to_string()])
                .build()
        );

        // GraphQL Injection
        self.register(
            "js/graphql-injection",
            Self::graphql_injection_query(),
            QueryMetadata::builder("js/graphql-injection", "GraphQL Injection")
                .description("Detects injection in GraphQL queries")
                .category(QueryCategory::Injection)
                .severity(QuerySeverity::High)
                .precision(QueryPrecision::Medium)
                .cwes(vec![89])
                .tags(vec!["graphql".to_string()])
                .suites(vec![QuerySuite::SecurityExtended, QuerySuite::SecurityAndQuality])
                .uses_taint()
                .languages(vec!["javascript".to_string(), "typescript".to_string()])
                .build()
        );

        // React XSS via Props
        self.register(
            "js/react-xss-props",
            Self::react_xss_props_query(),
            QueryMetadata::builder("js/react-xss-props", "React XSS via Props")
                .description("Detects XSS vulnerabilities in React component props")
                .category(QueryCategory::Xss)
                .severity(QuerySeverity::High)
                .precision(QueryPrecision::Medium)
                .cwes(vec![79])
                .tags(vec!["react".to_string()])
                .suites(vec![QuerySuite::SecurityExtended, QuerySuite::SecurityAndQuality])
                .uses_taint()
                .languages(vec!["javascript".to_string(), "typescript".to_string()])
                .build()
        );

        // Angular Template Injection
        self.register(
            "js/angular-template-injection",
            Self::angular_template_injection_query(),
            QueryMetadata::builder("js/angular-template-injection", "Angular Template Injection")
                .description("Detects template injection in Angular")
                .category(QueryCategory::Injection)
                .severity(QuerySeverity::Critical)
                .precision(QueryPrecision::Medium)
                .cwes(vec![94])
                .tags(vec!["angular".to_string()])
                .suites(vec![QuerySuite::SecurityExtended, QuerySuite::SecurityAndQuality])
                .uses_taint()
                .languages(vec!["javascript".to_string(), "typescript".to_string()])
                .build()
        );

        // Vue XSS
        self.register(
            "js/vue-xss",
            Self::vue_xss_query(),
            QueryMetadata::builder("js/vue-xss", "Vue.js XSS")
                .description("Detects XSS vulnerabilities in Vue.js")
                .category(QueryCategory::Xss)
                .severity(QuerySeverity::High)
                .precision(QueryPrecision::Medium)
                .cwes(vec![79])
                .tags(vec!["vue".to_string()])
                .suites(vec![QuerySuite::SecurityExtended, QuerySuite::SecurityAndQuality])
                .uses_taint()
                .languages(vec!["javascript".to_string(), "typescript".to_string()])
                .build()
        );

        // Next.js SSRF
        self.register(
            "js/nextjs-ssrf",
            Self::nextjs_ssrf_query(),
            QueryMetadata::builder("js/nextjs-ssrf", "Next.js SSRF")
                .description("Detects SSRF in Next.js server-side functions")
                .category(QueryCategory::ApiMisuse)
                .severity(QuerySeverity::Critical)
                .precision(QueryPrecision::High)
                .cwes(vec![918])
                .tags(vec!["nextjs".to_string(), "react".to_string()])
                .uses_taint()
                .languages(vec!["javascript".to_string(), "typescript".to_string()])
                .build()
        );

        // Electron Node Integration
        self.register(
            "js/electron-node-integration",
            Self::electron_node_integration_query(),
            QueryMetadata::builder("js/electron-node-integration", "Electron Node Integration Enabled")
                .description("Detects enabled nodeIntegration in Electron")
                .category(QueryCategory::Configuration)
                .severity(QuerySeverity::Critical)
                .precision(QueryPrecision::VeryHigh)
                .cwes(vec![16])
                .tags(vec!["electron".to_string()])
                .languages(vec!["javascript".to_string(), "typescript".to_string()])
                .build()
        );

        // Electron Context Isolation Disabled
        self.register(
            "js/electron-context-isolation",
            Self::electron_context_isolation_query(),
            QueryMetadata::builder("js/electron-context-isolation", "Electron Context Isolation Disabled")
                .description("Detects disabled contextIsolation in Electron")
                .category(QueryCategory::Configuration)
                .severity(QuerySeverity::High)
                .precision(QueryPrecision::VeryHigh)
                .cwes(vec![653])
                .tags(vec!["electron".to_string()])
                .languages(vec!["javascript".to_string(), "typescript".to_string()])
                .build()
        );
    }

    // ==================== QUERY IMPLEMENTATIONS ====================
    // These are simplified implementations - the actual queries would be more sophisticated

    fn sql_injection_query() -> Query {
        Query::new(
            FromClause::new(EntityType::MethodCall, "mc".to_string()),
            Some(WhereClause::new(vec![
                Predicate::MethodName {
                    variable: "mc".to_string(),
                    operator: ComparisonOp::Matches,
                    value: "(?i)(execute|query|run)".to_string(),
                },
                Predicate::FunctionCall {
                    variable: "mc".to_string(),
                    function: "isTainted".to_string(),
                    arguments: Vec::new(),
                },
            ])),
            SelectClause::new(vec![SelectItem::Both {
                variable: "mc".to_string(),
                message: "SQL injection vulnerability - untrusted data in database query".to_string(),
            }]),
        )
    }

    fn sql_injection_extended_query() -> Query {
        // Extended version with more detection patterns
        Query::new(
            FromClause::new(EntityType::CallExpression, "call".to_string()),
            Some(WhereClause::new(vec![
                Predicate::Comparison {
                    left: Expression::PropertyAccess {
                        object: Box::new(Expression::Variable("call".to_string())),
                        property: "callee".to_string(),
                    },
                    operator: ComparisonOp::Matches,
                    right: Expression::String("(?i)(execute|query|run|raw|unsafe)".to_string()),
                },
            ])),
            SelectClause::new(vec![SelectItem::Both {
                variable: "call".to_string(),
                message: "Potential SQL injection (extended detection)".to_string(),
            }]),
        )
    }

    fn nosql_injection_query() -> Query {
        // Note: Only match NoSQL-specific method names
        // Generic "find", "update" methods should NOT be matched
        Query::new(
            FromClause::new(EntityType::MethodCall, "mc".to_string()),
            Some(WhereClause::new(vec![
                Predicate::MethodName {
                    variable: "mc".to_string(),
                    operator: ComparisonOp::Matches,
                    // More specific NoSQL/MongoDB methods:
                    // - findOne, findOneAndUpdate are MongoDB-specific
                    // - Generic "find" matches too many APIs (List.find, Stream.find, etc.)
                    value: "(?i)(findOne|findOneAndUpdate|findOneAndDelete|updateOne|updateMany|deleteOne|deleteMany|\\$where)".to_string(),
                },
                Predicate::FunctionCall {
                    variable: "mc".to_string(),
                    function: "isTainted".to_string(),
                    arguments: Vec::new(),
                },
            ])),
            SelectClause::new(vec![SelectItem::Both {
                variable: "mc".to_string(),
                message: "NoSQL injection vulnerability".to_string(),
            }]),
        )
    }

    fn command_injection_query() -> Query {
        Query::new(
            FromClause::new(EntityType::MethodCall, "mc".to_string()),
            Some(WhereClause::new(vec![
                Predicate::MethodName {
                    variable: "mc".to_string(),
                    operator: ComparisonOp::Matches,
                    value: "(?i)(exec|spawn|system|shell|execute|popen|start|run|call)".to_string(),
                },
                Predicate::FunctionCall {
                    variable: "mc".to_string(),
                    function: "isTainted".to_string(),
                    arguments: Vec::new(),
                },
            ])),
            SelectClause::new(vec![SelectItem::Both {
                variable: "mc".to_string(),
                message: "Command injection vulnerability - untrusted data in system command".to_string(),
            }]),
        )
    }

    fn command_injection_extended_query() -> Query {
        Query::new(
            FromClause::new(EntityType::MethodCall, "mc".to_string()),
            Some(WhereClause::new(vec![
                Predicate::MethodName {
                    variable: "mc".to_string(),
                    operator: ComparisonOp::Matches,
                    value: "(?i)(exec|spawn|system|shell|sh|bash|cmd|powershell|execute|popen|start|run|call|command|proc)".to_string(),
                },
                Predicate::FunctionCall {
                    variable: "mc".to_string(),
                    function: "isTainted".to_string(),
                    arguments: Vec::new(),
                },
            ])),
            SelectClause::new(vec![SelectItem::Both {
                variable: "mc".to_string(),
                message: "Potential command injection (extended) - untrusted data flows to command".to_string(),
            }]),
        )
    }

    fn ldap_injection_query() -> Query {
        // LDAP injection patterns - avoid generic terms like "add" which match addCookie, etc.
        // Focus on LDAP-specific method names like search, bind, lookup on DirContext/InitialContext
        Query::new(
            FromClause::new(EntityType::MethodCall, "mc".to_string()),
            Some(WhereClause::new(vec![
                Predicate::MethodName {
                    variable: "mc".to_string(),
                    operator: ComparisonOp::Matches,
                    // Specific LDAP methods - removed generic "add" and "delete" which cause FPs
                    // Keep: search, bind, rebind, lookup, modifyAttributes, createSubcontext
                    value: "(?i)^(search|bind|rebind|lookup|modifyAttributes|createSubcontext)$".to_string(),
                },
                Predicate::FunctionCall {
                    variable: "mc".to_string(),
                    function: "isTainted".to_string(),
                    arguments: Vec::new(),
                },
            ])),
            SelectClause::new(vec![SelectItem::Both {
                variable: "mc".to_string(),
                message: "LDAP injection vulnerability - untrusted data in LDAP query".to_string(),
            }]),
        )
    }

    fn xpath_injection_query() -> Query {
        // Note: Removed generic 'compile' and 'select' patterns as they cause false positives
        // (e.g., Pattern.compile() in Java, document.querySelector() in JS)
        // Focus on XPath-specific API patterns
        Query::new(
            FromClause::new(EntityType::MethodCall, "mc".to_string()),
            Some(WhereClause::new(vec![
                Predicate::MethodName {
                    variable: "mc".to_string(),
                    operator: ComparisonOp::Matches,
                    value: "(?i)(xpath|selectNodes|selectSingleNode|xpathQuery|evaluateXPath)".to_string(),
                },
                Predicate::FunctionCall {
                    variable: "mc".to_string(),
                    function: "isTainted".to_string(),
                    arguments: Vec::new(),
                },
            ])),
            SelectClause::new(vec![SelectItem::Both {
                variable: "mc".to_string(),
                message: "XPath injection vulnerability - untrusted data in XPath query".to_string(),
            }]),
        )
    }

    fn code_injection_query() -> Query {
        // Note: Removed 'compile' as it causes FPs with Pattern.compile(), re.compile(), etc.
        // Removed 'execute' as it conflicts with SQL execute() - covered by sql-injection rule
        // Removed 'exec' alone as it matches Go's exec.Command which is command injection, not code injection
        // Use more specific patterns for actual code injection
        Query::new(
            FromClause::new(EntityType::MethodCall, "mc".to_string()),
            Some(WhereClause::new(vec![
                Predicate::MethodName {
                    variable: "mc".to_string(),
                    operator: ComparisonOp::Matches,
                    value: "(?i)(\\beval\\b|Function|loadstring|loadfile|dofile|runScript|execScript)".to_string(),
                },
                Predicate::FunctionCall {
                    variable: "mc".to_string(),
                    function: "isTainted".to_string(),
                    arguments: Vec::new(),
                },
            ])),
            SelectClause::new(vec![SelectItem::Both {
                variable: "mc".to_string(),
                message: "Code injection vulnerability - untrusted data in code evaluation".to_string(),
            }]),
        )
    }

    fn template_injection_query() -> Query {
        Query::new(
            FromClause::new(EntityType::MethodCall, "mc".to_string()),
            Some(WhereClause::new(vec![
                Predicate::MethodName {
                    variable: "mc".to_string(),
                    operator: ComparisonOp::Matches,
                    value: "(?i)(render|compile|template|format|interpolate)".to_string(),
                },
                Predicate::FunctionCall {
                    variable: "mc".to_string(),
                    function: "isTainted".to_string(),
                    arguments: Vec::new(),
                },
            ])),
            SelectClause::new(vec![SelectItem::Both {
                variable: "mc".to_string(),
                message: "Server-side template injection - untrusted data in template".to_string(),
            }]),
        )
    }

    fn expression_injection_query() -> Query {
        Query::new(
            FromClause::new(EntityType::MethodCall, "mc".to_string()),
            Some(WhereClause::new(vec![
                Predicate::MethodName {
                    variable: "mc".to_string(),
                    operator: ComparisonOp::Matches,
                    value: "(?i)(parseExpression|evaluateExpression|getValue|parse)".to_string(),
                },
                Predicate::FunctionCall {
                    variable: "mc".to_string(),
                    function: "isTainted".to_string(),
                    arguments: Vec::new(),
                },
            ])),
            SelectClause::new(vec![SelectItem::Both {
                variable: "mc".to_string(),
                message: "Expression language injection - untrusted data in expression".to_string(),
            }]),
        )
    }

    fn dom_xss_query() -> Query {
        Query::new(
            FromClause::new(EntityType::MemberExpression, "member".to_string()),
            Some(WhereClause::new(vec![
                Predicate::Comparison {
                    left: Expression::PropertyAccess {
                        object: Box::new(Expression::Variable("member".to_string())),
                        property: "property".to_string(),
                    },
                    operator: ComparisonOp::Matches,
                    right: Expression::String("(?i)(innerHTML|outerHTML)".to_string()),
                },
            ])),
            SelectClause::new(vec![SelectItem::Both {
                variable: "member".to_string(),
                message: "DOM-based XSS vulnerability".to_string(),
            }]),
        )
    }

    fn reflected_xss_query() -> Query {
        Query::new(
            FromClause::new(EntityType::MethodCall, "mc".to_string()),
            Some(WhereClause::new(vec![
                Predicate::MethodName {
                    variable: "mc".to_string(),
                    operator: ComparisonOp::Matches,
                    value: "(?i)(send|write|render)".to_string(),
                },
                Predicate::FunctionCall {
                    variable: "mc".to_string(),
                    function: "isTainted".to_string(),
                    arguments: Vec::new(),
                },
            ])),
            SelectClause::new(vec![SelectItem::Both {
                variable: "mc".to_string(),
                message: "Reflected XSS vulnerability".to_string(),
            }]),
        )
    }

    fn stored_xss_query() -> Query {
        Query::new(
            FromClause::new(EntityType::MethodCall, "mc".to_string()),
            Some(WhereClause::new(vec![
                Predicate::MethodName {
                    variable: "mc".to_string(),
                    operator: ComparisonOp::Matches,
                    value: "(?i)(save|insert|update|store)".to_string(),
                },
            ])),
            SelectClause::new(vec![SelectItem::Both {
                variable: "mc".to_string(),
                message: "Potential stored XSS vulnerability".to_string(),
            }]),
        )
    }

    fn unsafe_innerhtml_query() -> Query {
        Query::new(
            FromClause::new(EntityType::Assignment, "assign".to_string()),
            Some(WhereClause::new(vec![
                Predicate::Comparison {
                    left: Expression::PropertyAccess {
                        object: Box::new(Expression::Variable("assign".to_string())),
                        property: "left".to_string(),
                    },
                    operator: ComparisonOp::Contains,
                    right: Expression::String("innerHTML".to_string()),
                },
            ])),
            SelectClause::new(vec![SelectItem::Both {
                variable: "assign".to_string(),
                message: "Unsafe innerHTML assignment".to_string(),
            }]),
        )
    }

    fn document_write_xss_query() -> Query {
        Query::new(
            FromClause::new(EntityType::CallExpression, "call".to_string()),
            Some(WhereClause::new(vec![
                Predicate::Comparison {
                    left: Expression::PropertyAccess {
                        object: Box::new(Expression::Variable("call".to_string())),
                        property: "callee".to_string(),
                    },
                    operator: ComparisonOp::Contains,
                    right: Expression::String("document.write".to_string()),
                },
            ])),
            SelectClause::new(vec![SelectItem::Both {
                variable: "call".to_string(),
                message: "XSS via document.write()".to_string(),
            }]),
        )
    }

    fn jquery_xss_query() -> Query {
        Query::new(
            FromClause::new(EntityType::CallExpression, "call".to_string()),
            Some(WhereClause::new(vec![
                Predicate::Comparison {
                    left: Expression::PropertyAccess {
                        object: Box::new(Expression::Variable("call".to_string())),
                        property: "callee".to_string(),
                    },
                    operator: ComparisonOp::Matches,
                    right: Expression::String("(?i)(\\$|jquery)\\.(html|append|prepend)".to_string()),
                },
            ])),
            SelectClause::new(vec![SelectItem::Both {
                variable: "call".to_string(),
                message: "XSS via jQuery DOM manipulation".to_string(),
            }]),
        )
    }

    fn react_dangerous_html_query() -> Query {
        Query::new(
            FromClause::new(EntityType::MemberExpression, "member".to_string()),
            Some(WhereClause::new(vec![
                Predicate::Comparison {
                    left: Expression::PropertyAccess {
                        object: Box::new(Expression::Variable("member".to_string())),
                        property: "property".to_string(),
                    },
                    operator: ComparisonOp::Equal,
                    right: Expression::String("dangerouslySetInnerHTML".to_string()),
                },
            ])),
            SelectClause::new(vec![SelectItem::Both {
                variable: "member".to_string(),
                message: "Unsafe use of dangerouslySetInnerHTML in React".to_string(),
            }]),
        )
    }

    fn angular_sce_bypass_query() -> Query {
        Query::new(
            FromClause::new(EntityType::CallExpression, "call".to_string()),
            Some(WhereClause::new(vec![
                Predicate::Comparison {
                    left: Expression::PropertyAccess {
                        object: Box::new(Expression::Variable("call".to_string())),
                        property: "callee".to_string(),
                    },
                    operator: ComparisonOp::Matches,
                    right: Expression::String("(?i)trustAsHtml|trustAsResourceUrl".to_string()),
                },
            ])),
            SelectClause::new(vec![SelectItem::Both {
                variable: "call".to_string(),
                message: "Angular SCE bypass - potential XSS".to_string(),
            }]),
        )
    }

    // Authentication queries
    // NOTE: This query is intentionally strict to reduce false positives.
    // It matches variable declarations where:
    // 1. The variable has a sensitive name (password, secret, apiKey, etc.)
    // 2. AND the value is a hardcoded string literal that looks like a real credential
    //    (not a variable reference, function call, or placeholder text)
    fn hardcoded_credentials_query() -> Query {
        Query::new(
            FromClause::new(EntityType::AnyNode, "node".to_string()),
            Some(WhereClause::new(vec![
                Predicate::Comparison {
                    left: Expression::PropertyAccess {
                        object: Box::new(Expression::Variable("node".to_string())),
                        property: "text".to_string(),
                    },
                    operator: ComparisonOp::Matches,
                    // Match patterns like: password = "actual_value" or apiKey: "sk-xxxxx"
                    // Requires:
                    // - Sensitive variable name (password, secret, apiKey, token, etc.)
                    // - Assignment operator (= or :)
                    // - A quoted string literal with credential-like value (6+ alphanumeric chars)
                    // Excludes:
                    // - Function calls: password = getPassword()
                    // - Variable references: password = req.body.password
                    // - Empty/placeholder: password = ""
                    right: Expression::String(
                        r#"(?i)(password|passwd|pwd|secret|api[_-]?key|private[_-]?key|access[_-]?key|auth[_-]?token)\s*[=:]\s*["'][a-zA-Z0-9!@#$%^&*_\-+=./]{6,}["']"#.to_string()
                    ),
                },
            ])),
            SelectClause::new(vec![SelectItem::Both {
                variable: "node".to_string(),
                message: "Hardcoded credential - use environment variables or secrets manager".to_string(),
            }]),
        )
    }

    fn weak_password_requirements_query() -> Query {
        Query::new(
            FromClause::new(EntityType::CallExpression, "call".to_string()),
            Some(WhereClause::new(vec![
                Predicate::Comparison {
                    left: Expression::PropertyAccess {
                        object: Box::new(Expression::Variable("call".to_string())),
                        property: "callee".to_string(),
                    },
                    operator: ComparisonOp::Matches,
                    right: Expression::String("(?i)validatePassword|checkPassword".to_string()),
                },
            ])),
            SelectClause::new(vec![SelectItem::Both {
                variable: "call".to_string(),
                message: "Weak password validation rules".to_string(),
            }]),
        )
    }

    fn missing_authentication_query() -> Query {
        Query::new(
            FromClause::new(EntityType::FunctionDeclaration, "func".to_string()),
            Some(WhereClause::new(vec![
                Predicate::Comparison {
                    left: Expression::PropertyAccess {
                        object: Box::new(Expression::Variable("func".to_string())),
                        property: "name".to_string(),
                    },
                    operator: ComparisonOp::Matches,
                    right: Expression::String("(?i)(route|endpoint|handler)".to_string()),
                },
            ])),
            SelectClause::new(vec![SelectItem::Both {
                variable: "func".to_string(),
                message: "Potential missing authentication check".to_string(),
            }]),
        )
    }

    fn broken_access_control_query() -> Query {
        Query::new(
            FromClause::new(EntityType::CallExpression, "call".to_string()),
            Some(WhereClause::new(vec![
                Predicate::Comparison {
                    left: Expression::PropertyAccess {
                        object: Box::new(Expression::Variable("call".to_string())),
                        property: "callee".to_string(),
                    },
                    operator: ComparisonOp::Matches,
                    right: Expression::String("(?i)(findById|getById|getUserBy)".to_string()),
                },
            ])),
            SelectClause::new(vec![SelectItem::Both {
                variable: "call".to_string(),
                message: "Potential broken access control".to_string(),
            }]),
        )
    }

    fn jwt_none_algorithm_query() -> Query {
        Query::new(
            FromClause::new(EntityType::Literal, "obj".to_string()),
            Some(WhereClause::new(vec![
                Predicate::Comparison {
                    left: Expression::PropertyAccess {
                        object: Box::new(Expression::Variable("obj".to_string())),
                        property: "algorithm".to_string(),
                    },
                    operator: ComparisonOp::Equal,
                    right: Expression::String("none".to_string()),
                },
            ])),
            SelectClause::new(vec![SelectItem::Both {
                variable: "obj".to_string(),
                message: "JWT 'none' algorithm - authentication bypass".to_string(),
            }]),
        )
    }

    fn jwt_weak_secret_query() -> Query {
        Query::new(
            FromClause::new(EntityType::CallExpression, "call".to_string()),
            Some(WhereClause::new(vec![
                Predicate::Comparison {
                    left: Expression::PropertyAccess {
                        object: Box::new(Expression::Variable("call".to_string())),
                        property: "callee".to_string(),
                    },
                    operator: ComparisonOp::Matches,
                    right: Expression::String("(?i)jwt\\.(sign|verify)".to_string()),
                },
            ])),
            SelectClause::new(vec![SelectItem::Both {
                variable: "call".to_string(),
                message: "Potential weak JWT secret".to_string(),
            }]),
        )
    }

    fn session_fixation_query() -> Query {
        Query::new(
            FromClause::new(EntityType::CallExpression, "call".to_string()),
            Some(WhereClause::new(vec![
                Predicate::Comparison {
                    left: Expression::PropertyAccess {
                        object: Box::new(Expression::Variable("call".to_string())),
                        property: "callee".to_string(),
                    },
                    operator: ComparisonOp::Matches,
                    right: Expression::String("(?i)session\\.(regenerate|destroy)".to_string()),
                },
            ])),
            SelectClause::new(vec![SelectItem::Both {
                variable: "call".to_string(),
                message: "Session fixation vulnerability".to_string(),
            }]),
        )
    }

    fn insecure_session_cookie_query() -> Query {
        // Detect res.cookie() calls without secure flag
        // Pattern: res.cookie('name', value, { path: '/' })  // Missing secure: true
        // Safe:    res.cookie('name', value, { secure: true, httpOnly: true })
        Query::new(
            FromClause::new(EntityType::CallExpression, "call".to_string()),
            Some(WhereClause::new(vec![
                Predicate::And {
                    left: Box::new(Predicate::Comparison {
                        // Match .cookie() method calls for setting cookies
                        left: Expression::PropertyAccess {
                            object: Box::new(Expression::Variable("call".to_string())),
                            property: "callee".to_string(),
                        },
                        operator: ComparisonOp::Matches,
                        right: Expression::String(r"res\.cookie|response\.cookie".to_string()),
                    }),
                    right: Box::new(Predicate::Not {
                        predicate: Box::new(Predicate::Comparison {
                            // Does NOT have secure: true in the options
                            left: Expression::PropertyAccess {
                                object: Box::new(Expression::Variable("call".to_string())),
                                property: "text".to_string(),
                            },
                            operator: ComparisonOp::Matches,
                            right: Expression::String(r"secure:\s*true".to_string()),
                        }),
                    }),
                },
            ])),
            SelectClause::new(vec![SelectItem::Both {
                variable: "call".to_string(),
                message: "Cookie set without secure flag - add { secure: true, httpOnly: true }".to_string(),
            }]),
        )
    }

    // Cryptography queries (continued in next part due to length)
    fn weak_hash_query() -> Query {
        // Note: Pattern should NOT match SHA1PRNG (PRNG algorithm, not hash) or SecureRandom
        // It should only match actual weak hash function calls (MD5, SHA-1)
        // Strong hashes (SHA-256, SHA-384, SHA-512, SHA-3) should NOT be flagged
        //
        // We check the full text to ensure the argument specifies a weak hash algorithm
        // Note: Rust regex crate doesn't support lookahead, so we exclude SHA1PRNG separately
        Query::new(
            FromClause::new(EntityType::CallExpression, "call".to_string()),
            Some(WhereClause::new(vec![
                Predicate::And {
                    left: Box::new(Predicate::Or {
                        left: Box::new(Predicate::Comparison {
                            left: Expression::PropertyAccess {
                                object: Box::new(Expression::Variable("call".to_string())),
                                property: "callee".to_string(),
                            },
                            operator: ComparisonOp::Matches,
                            // Match direct calls to weak hash functions (function name IS the algorithm)
                            // - hashlib.md5(), hashlib.sha1() - Python direct (note: callee is hashlib.md5)
                            // - md5(), sha1() - standalone calls
                            // Note: Do NOT match MessageDigest.getInstance here - algorithm is in argument
                            right: Expression::String("(?i)(\\bmd5\\b|\\bsha-?1\\b|hashlib\\.md5|hashlib\\.sha1)".to_string()),
                        }),
                        right: Box::new(Predicate::Comparison {
                            left: Expression::PropertyAccess {
                                object: Box::new(Expression::Variable("call".to_string())),
                                property: "text".to_string(),
                            },
                            operator: ComparisonOp::Matches,
                            // Match full text patterns where hash type is an argument
                            // Only match MD5 or SHA-1 as the algorithm argument
                            // - hashlib.new('md5'), hashlib.new('sha1') - Python
                            // - createHash('md5'), createHash('sha1') - Node.js
                            // - MessageDigest.getInstance("MD5"), MessageDigest.getInstance("SHA-1") - Java
                            // Note: SHA-1 can be written as "SHA1", "SHA-1", "sha1", "sha-1"
                            right: Expression::String("(?i)(hashlib\\.new.*['\"]md5['\"]|hashlib\\.new.*['\"]sha-?1['\"]|createHash.*['\"]md5['\"]|createHash.*['\"]sha-?1['\"]|getInstance\\s*\\(\\s*['\"]MD5['\"]|getInstance\\s*\\(\\s*['\"]SHA-?1['\"])".to_string()),
                        }),
                    }),
                    // Exclude SHA1PRNG (secure random number generator, not a hash)
                    right: Box::new(Predicate::Not {
                        predicate: Box::new(Predicate::Comparison {
                            left: Expression::PropertyAccess {
                                object: Box::new(Expression::Variable("call".to_string())),
                                property: "text".to_string(),
                            },
                            operator: ComparisonOp::Matches,
                            right: Expression::String("(?i)SHA1PRNG".to_string()),
                        }),
                    }),
                },
            ])),
            SelectClause::new(vec![SelectItem::Both {
                variable: "call".to_string(),
                message: "Weak hash algorithm (MD5/SHA1)".to_string(),
            }]),
        )
    }

    /// Java-specific weak hash detection for MessageDigest.getInstance with variable algorithm
    /// This catches cases like: String alg = props.getProperty("hashAlg1", "SHA512"); MessageDigest.getInstance(alg)
    /// where the algorithm comes from external configuration and may be weak (MD5)
    fn java_weak_hash_variable_query() -> Query {
        // Match MessageDigest.getInstance(variable) where variable is NOT a hardcoded strong algorithm
        // Pattern: MessageDigest.getInstance(someVar) where someVar is an identifier, not a string literal
        Query::new(
            FromClause::new(EntityType::CallExpression, "call".to_string()),
            Some(WhereClause::new(vec![
                Predicate::And {
                    left: Box::new(Predicate::And {
                        // Match MessageDigest.getInstance() on the callee (not text, to avoid string literal matches)
                        left: Box::new(Predicate::Comparison {
                            left: Expression::PropertyAccess {
                                object: Box::new(Expression::Variable("call".to_string())),
                                property: "callee".to_string(),
                            },
                            operator: ComparisonOp::Matches,
                            // Match callee that ends with MessageDigest.getInstance
                            right: Expression::String("MessageDigest\\.getInstance$".to_string()),
                        }),
                        // AND the text has a variable argument (not a quoted string)
                        right: Box::new(Predicate::Comparison {
                            left: Expression::PropertyAccess {
                                object: Box::new(Expression::Variable("call".to_string())),
                                property: "text".to_string(),
                            },
                            operator: ComparisonOp::Matches,
                            // Match getInstance(variable) where argument starts with letter/underscore (not quote)
                            right: Expression::String("getInstance\\s*\\(\\s*[a-zA-Z_]".to_string()),
                        }),
                    }),
                    // Exclude cases where it's a hardcoded strong algorithm
                    right: Box::new(Predicate::Not {
                        predicate: Box::new(Predicate::Comparison {
                            left: Expression::PropertyAccess {
                                object: Box::new(Expression::Variable("call".to_string())),
                                property: "text".to_string(),
                            },
                            operator: ComparisonOp::Matches,
                            // Exclude hardcoded strong algorithms: SHA-256, SHA-384, SHA-512, SHA-3
                            right: Expression::String("(?i)getInstance\\s*\\(\\s*['\"]SHA-?(256|384|512|3)['\"]".to_string()),
                        }),
                    }),
                },
            ])),
            SelectClause::new(vec![SelectItem::Both {
                variable: "call".to_string(),
                message: "Hash algorithm from variable may be weak (MD5/SHA1) - verify configuration".to_string(),
            }]),
        )
    }

    fn weak_cipher_query() -> Query {
        Query::new(
            FromClause::new(EntityType::CallExpression, "call".to_string()),
            Some(WhereClause::new(vec![
                Predicate::Comparison {
                    left: Expression::PropertyAccess {
                        object: Box::new(Expression::Variable("call".to_string())),
                        property: "text".to_string(),
                    },
                    operator: ComparisonOp::Matches,
                    // Match weak ciphers in call text:
                    // - Java: Cipher.getInstance("DES/..."), KeyGenerator.getInstance("DES")
                    // - JS: createCipher("des"), createCipheriv("des", ...)
                    // - Python: DES.new(), DES3.new()
                    right: Expression::String("(?i)(getInstance\\s*\\(\\s*['\"]DES|getInstance\\s*\\(\\s*['\"]RC4|getInstance\\s*\\(\\s*['\"]DESede|createCipher.*['\"]des|createCipher.*['\"]rc4|\\bDES\\.new|\\bDES3\\.new|\\bRC4\\.new)".to_string()),
                },
            ])),
            SelectClause::new(vec![SelectItem::Both {
                variable: "call".to_string(),
                message: "Weak encryption cipher (DES/RC4)".to_string(),
            }]),
        )
    }

    fn ecb_mode_query() -> Query {
        Query::new(
            FromClause::new(EntityType::Literal, "str".to_string()),
            Some(WhereClause::new(vec![
                Predicate::Comparison {
                    left: Expression::Variable("str".to_string()),
                    operator: ComparisonOp::Matches,
                    right: Expression::String("(?i)ecb".to_string()),
                },
            ])),
            SelectClause::new(vec![SelectItem::Both {
                variable: "str".to_string(),
                message: "Insecure ECB cipher mode".to_string(),
            }]),
        )
    }

    fn insufficient_key_size_query() -> Query {
        // Simplified - checks for key generation with small sizes
        Query::new(
            FromClause::new(EntityType::CallExpression, "call".to_string()),
            Some(WhereClause::new(vec![
                Predicate::Comparison {
                    left: Expression::PropertyAccess {
                        object: Box::new(Expression::Variable("call".to_string())),
                        property: "callee".to_string(),
                    },
                    operator: ComparisonOp::Matches,
                    right: Expression::String("(?i)(generateKey|createKey|keySize)".to_string()),
                },
            ])),
            SelectClause::new(vec![SelectItem::Both {
                variable: "call".to_string(),
                message: "Insufficient cryptographic key size".to_string(),
            }]),
        )
    }

    fn hardcoded_crypto_key_query() -> Query {
        // Match variables that look like hardcoded cryptographic keys
        // Avoid false positives for:
        // - rememberMeKey, cookieKey (session identifiers, not crypto keys)
        // - secretaryName, secretValue (not crypto secrets)
        Query::new(
            FromClause::new(EntityType::VariableDeclaration, "vd".to_string()),
            Some(WhereClause::new(vec![
                Predicate::Comparison {
                    left: Expression::PropertyAccess {
                        object: Box::new(Expression::Variable("vd".to_string())),
                        property: "name".to_string(),
                    },
                    operator: ComparisonOp::Matches,
                    // More specific: look for actual crypto key patterns
                    // - aesKey, desKey, rsaKey, encryptionKey, secretKey, privateKey, apiKey
                    // Exclude common FPs: rememberMeKey, secretaryName, etc.
                    right: Expression::String("(?i)(^(aes|des|rsa|encryption|private|api|jwt|signing|crypto|auth)_?key$|^secret_?key$|^(ENCRYPTION|PRIVATE|SECRET|API)_KEY$)".to_string()),
                },
            ])),
            SelectClause::new(vec![SelectItem::Both {
                variable: "vd".to_string(),
                message: "Hardcoded cryptographic key".to_string(),
            }]),
        )
    }

    fn insecure_random_query() -> Query {
        Query::new(
            FromClause::new(EntityType::MemberExpression, "member".to_string()),
            Some(WhereClause::new(vec![
                Predicate::Comparison {
                    left: Expression::PropertyAccess {
                        object: Box::new(Expression::Variable("member".to_string())),
                        property: "property".to_string(),
                    },
                    operator: ComparisonOp::Equal,
                    right: Expression::String("random".to_string()),
                },
            ])),
            SelectClause::new(vec![SelectItem::Both {
                variable: "member".to_string(),
                message: "Insecure randomness - use crypto.randomBytes()".to_string(),
            }]),
        )
    }

    /// Java weak randomness detection
    /// Detects:
    /// - new java.util.Random() and its methods (nextInt, nextFloat, nextDouble, nextLong, etc.)
    /// - java.lang.Math.random()
    /// Python weak randomness detection
    /// Detects:
    /// - random.random(), random.randint(), random.normalvariate(), etc.
    /// Does NOT detect:
    /// - random.SystemRandom().* (which is secure)
    /// - secrets.* (which is secure)
    fn python_weak_random_query() -> Query {
        Query::new(
            FromClause::new(EntityType::CallExpression, "call".to_string()),
            Some(WhereClause::new(vec![
                Predicate::And {
                    left: Box::new(Predicate::Comparison {
                        left: Expression::PropertyAccess {
                            object: Box::new(Expression::Variable("call".to_string())),
                            property: "text".to_string(),
                        },
                        operator: ComparisonOp::Matches,
                        // Match random.X() - weak random functions, must start with "random."
                        // This ensures we match the specific call, not parent nodes
                        right: Expression::String(r"^random\.(random|randint|choice|shuffle|normalvariate|getrandbits|randbytes|gauss|uniform|randrange|sample)\s*\(".to_string()),
                    }),
                    // Exclude SystemRandom - it's cryptographically secure
                    right: Box::new(Predicate::Not {
                        predicate: Box::new(Predicate::Comparison {
                            left: Expression::PropertyAccess {
                                object: Box::new(Expression::Variable("call".to_string())),
                                property: "text".to_string(),
                            },
                            operator: ComparisonOp::Matches,
                            right: Expression::String(r"SystemRandom".to_string()),
                        }),
                    }),
                },
            ])),
            SelectClause::new(vec![SelectItem::Both {
                variable: "call".to_string(),
                message: "Weak randomness - use secrets module or random.SystemRandom() instead".to_string(),
            }]),
        )
    }

    /// Java weak randomness detection
    /// Detects:
    /// - new java.util.Random().nextXxx()
    /// - Math.random()
    /// Does NOT detect:
    /// - java.security.SecureRandom (which is secure)
    fn java_weak_random_query() -> Query {
        Query::new(
            // Use AnyNode since new X() isn't classified as CallExpression
            FromClause::new(EntityType::AnyNode, "node".to_string()),
            Some(WhereClause::new(vec![
                Predicate::Comparison {
                    left: Expression::PropertyAccess {
                        object: Box::new(Expression::Variable("node".to_string())),
                        property: "text".to_string(),
                    },
                    operator: ComparisonOp::Matches,
                    // Match java.util.Random (but NOT SecureRandom) and Math.random
                    // Pattern is very specific to avoid matching on assignments, variable names, etc.
                    // Only matches actual usage like: new java.util.Random().nextFloat()
                    // or: Math.random()
                    right: Expression::String(r"new\s+(java\.util\.)?Random\s*\(\s*\)\s*\.\s*next\w+\s*\(|Math\.random\s*\(".to_string()),
                },
            ])),
            SelectClause::new(vec![SelectItem::Both {
                variable: "node".to_string(),
                message: "Weak randomness - use java.security.SecureRandom instead".to_string(),
            }]),
        )
    }

    /// Ruby weak randomness detection
    /// Detects:
    /// - rand() or rand(n) - Kernel method
    /// - rand without parens (e.g., rand * 1000)
    /// - Random.rand() or Random.new.rand()
    /// Does NOT detect:
    /// - SecureRandom.* (which is secure)
    fn ruby_weak_random_query() -> Query {
        Query::new(
            // Use AnyNode to catch rand without parens (which isn't a CallExpression)
            FromClause::new(EntityType::AnyNode, "node".to_string()),
            Some(WhereClause::new(vec![
                Predicate::And {
                    left: Box::new(Predicate::Comparison {
                        left: Expression::PropertyAccess {
                            object: Box::new(Expression::Variable("node".to_string())),
                            property: "text".to_string(),
                        },
                        operator: ComparisonOp::Matches,
                        // Match rand (with or without parens) or Random.rand() or Random.new.rand()
                        // Very specific patterns to avoid false positives
                        right: Expression::String(r"^rand\s*\(|^rand$|^Random\.(rand|new)".to_string()),
                    }),
                    // Exclude SecureRandom - it's cryptographically secure
                    right: Box::new(Predicate::Not {
                        predicate: Box::new(Predicate::Comparison {
                            left: Expression::PropertyAccess {
                                object: Box::new(Expression::Variable("node".to_string())),
                                property: "text".to_string(),
                            },
                            operator: ComparisonOp::Matches,
                            right: Expression::String(r"SecureRandom".to_string()),
                        }),
                    }),
                },
            ])),
            SelectClause::new(vec![SelectItem::Both {
                variable: "node".to_string(),
                message: "Weak randomness - use SecureRandom instead".to_string(),
            }]),
        )
    }

    /// Go weak randomness detection
    /// Detects:
    /// - rand.Intn(), rand.Int(), rand.Float64(), etc. from math/rand
    /// Does NOT detect:
    /// - crypto/rand (which is secure)
    fn go_weak_random_query() -> Query {
        Query::new(
            FromClause::new(EntityType::CallExpression, "call".to_string()),
            Some(WhereClause::new(vec![
                Predicate::And {
                    left: Box::new(Predicate::Comparison {
                        left: Expression::PropertyAccess {
                            object: Box::new(Expression::Variable("call".to_string())),
                            property: "text".to_string(),
                        },
                        operator: ComparisonOp::Matches,
                        // Match rand.Intn, rand.Int, rand.Float64, rand.Read, etc.
                        right: Expression::String(r"^rand\.(Intn|Int31|Int63|Int|Float32|Float64|Uint32|Uint64|Read|Seed|Perm|Shuffle)\s*\(".to_string()),
                    }),
                    // Exclude crypto/rand imports
                    right: Box::new(Predicate::Not {
                        predicate: Box::new(Predicate::Comparison {
                            left: Expression::PropertyAccess {
                                object: Box::new(Expression::Variable("call".to_string())),
                                property: "text".to_string(),
                            },
                            operator: ComparisonOp::Matches,
                            right: Expression::String(r"crypto".to_string()),
                        }),
                    }),
                },
            ])),
            SelectClause::new(vec![SelectItem::Both {
                variable: "call".to_string(),
                message: "Weak randomness - use crypto/rand instead of math/rand".to_string(),
            }]),
        )
    }

    /// Rust weak randomness detection
    /// Detects:
    /// - rand::thread_rng().gen(), rand::random(), etc.
    /// Does NOT detect:
    /// - rand::rngs::OsRng (which uses OS randomness)
    fn rust_weak_random_query() -> Query {
        Query::new(
            FromClause::new(EntityType::CallExpression, "call".to_string()),
            Some(WhereClause::new(vec![
                Predicate::And {
                    left: Box::new(Predicate::Comparison {
                        left: Expression::PropertyAccess {
                            object: Box::new(Expression::Variable("call".to_string())),
                            property: "text".to_string(),
                        },
                        operator: ComparisonOp::Matches,
                        // Match rand::thread_rng().gen(), rand::random(), etc.
                        right: Expression::String(r"rand::(thread_rng|random)|\.gen\s*[:<(]".to_string()),
                    }),
                    // Exclude OsRng (secure)
                    right: Box::new(Predicate::Not {
                        predicate: Box::new(Predicate::Comparison {
                            left: Expression::PropertyAccess {
                                object: Box::new(Expression::Variable("call".to_string())),
                                property: "text".to_string(),
                            },
                            operator: ComparisonOp::Matches,
                            right: Expression::String(r"OsRng".to_string()),
                        }),
                    }),
                },
            ])),
            SelectClause::new(vec![SelectItem::Both {
                variable: "call".to_string(),
                message: "Weak randomness - use OsRng or getrandom crate for cryptographic purposes".to_string(),
            }]),
        )
    }

    /// Java insecure cookie detection
    /// Detects cookies without secure flag:
    /// - cookie.setSecure(false)
    fn java_insecure_cookie_query() -> Query {
        Query::new(
            FromClause::new(EntityType::CallExpression, "call".to_string()),
            Some(WhereClause::new(vec![
                Predicate::Comparison {
                    left: Expression::PropertyAccess {
                        object: Box::new(Expression::Variable("call".to_string())),
                        property: "text".to_string(),
                    },
                    operator: ComparisonOp::Matches,
                    // Match setSecure(false) but NOT setSecure(true)
                    right: Expression::String(r"\.setSecure\s*\(\s*false\s*\)".to_string()),
                },
            ])),
            SelectClause::new(vec![SelectItem::Both {
                variable: "call".to_string(),
                message: "Cookie without secure flag - use setSecure(true)".to_string(),
            }]),
        )
    }

    fn missing_salt_query() -> Query {
        Query::new(
            FromClause::new(EntityType::CallExpression, "call".to_string()),
            Some(WhereClause::new(vec![
                Predicate::Comparison {
                    left: Expression::PropertyAccess {
                        object: Box::new(Expression::Variable("call".to_string())),
                        property: "callee".to_string(),
                    },
                    operator: ComparisonOp::Matches,
                    right: Expression::String("(?i)(hash|createHash)".to_string()),
                },
            ])),
            SelectClause::new(vec![SelectItem::Both {
                variable: "call".to_string(),
                message: "Missing salt in password hash".to_string(),
            }]),
        )
    }

    fn predictable_seed_query() -> Query {
        Query::new(
            FromClause::new(EntityType::CallExpression, "call".to_string()),
            Some(WhereClause::new(vec![
                Predicate::Comparison {
                    left: Expression::PropertyAccess {
                        object: Box::new(Expression::Variable("call".to_string())),
                        property: "callee".to_string(),
                    },
                    operator: ComparisonOp::Matches,
                    right: Expression::String("(?i)(seed|setSeed)".to_string()),
                },
            ])),
            SelectClause::new(vec![SelectItem::Both {
                variable: "call".to_string(),
                message: "Predictable seed for random number generator".to_string(),
            }]),
        )
    }

    // Path traversal queries
    fn path_traversal_query() -> Query {
        Query::new(
            FromClause::new(EntityType::MethodCall, "mc".to_string()),
            Some(WhereClause::new(vec![
                Predicate::MethodName {
                    variable: "mc".to_string(),
                    operator: ComparisonOp::Matches,
                    value: "(?i)(readFile|writeFile|open|unlink|remove|rename|read|write|fopen|createReadStream|createWriteStream)".to_string(),
                },
                Predicate::FunctionCall {
                    variable: "mc".to_string(),
                    function: "isTainted".to_string(),
                    arguments: Vec::new(),
                },
            ])),
            SelectClause::new(vec![SelectItem::Both {
                variable: "mc".to_string(),
                message: "Path traversal vulnerability - untrusted data in file path".to_string(),
            }]),
        )
    }

    fn zip_slip_query() -> Query {
        Query::new(
            FromClause::new(EntityType::MethodCall, "mc".to_string()),
            Some(WhereClause::new(vec![
                Predicate::MethodName {
                    variable: "mc".to_string(),
                    operator: ComparisonOp::Matches,
                    value: "(?i)(extract|unzip|decompress|untar|gunzip)".to_string(),
                },
                Predicate::FunctionCall {
                    variable: "mc".to_string(),
                    function: "isTainted".to_string(),
                    arguments: Vec::new(),
                },
            ])),
            SelectClause::new(vec![SelectItem::Both {
                variable: "mc".to_string(),
                message: "Zip slip vulnerability - untrusted archive extraction".to_string(),
            }]),
        )
    }

    fn arbitrary_file_write_query() -> Query {
        Query::new(
            FromClause::new(EntityType::MethodCall, "mc".to_string()),
            Some(WhereClause::new(vec![
                Predicate::MethodName {
                    variable: "mc".to_string(),
                    operator: ComparisonOp::Matches,
                    value: "(?i)(writeFile|appendFile|createWriteStream|write|fwrite)".to_string(),
                },
                Predicate::FunctionCall {
                    variable: "mc".to_string(),
                    function: "isTainted".to_string(),
                    arguments: Vec::new(),
                },
            ])),
            SelectClause::new(vec![SelectItem::Both {
                variable: "mc".to_string(),
                message: "Arbitrary file write vulnerability - untrusted data controls file path".to_string(),
            }]),
        )
    }

    fn unsafe_file_upload_query() -> Query {
        Query::new(
            FromClause::new(EntityType::CallExpression, "call".to_string()),
            Some(WhereClause::new(vec![
                Predicate::Comparison {
                    left: Expression::PropertyAccess {
                        object: Box::new(Expression::Variable("call".to_string())),
                        property: "callee".to_string(),
                    },
                    operator: ComparisonOp::Matches,
                    right: Expression::String("(?i)(upload|multer|formidable)".to_string()),
                },
            ])),
            SelectClause::new(vec![SelectItem::Both {
                variable: "call".to_string(),
                message: "Unrestricted file upload".to_string(),
            }]),
        )
    }

    // Information disclosure queries
    fn stack_trace_exposure_query() -> Query {
        Query::new(
            FromClause::new(EntityType::MemberExpression, "member".to_string()),
            Some(WhereClause::new(vec![
                Predicate::Comparison {
                    left: Expression::PropertyAccess {
                        object: Box::new(Expression::Variable("member".to_string())),
                        property: "property".to_string(),
                    },
                    operator: ComparisonOp::Equal,
                    right: Expression::String("stack".to_string()),
                },
            ])),
            SelectClause::new(vec![SelectItem::Both {
                variable: "member".to_string(),
                message: "Stack trace exposed to user".to_string(),
            }]),
        )
    }

    fn sensitive_data_log_query() -> Query {
        Query::new(
            FromClause::new(EntityType::CallExpression, "call".to_string()),
            Some(WhereClause::new(vec![
                Predicate::Comparison {
                    left: Expression::PropertyAccess {
                        object: Box::new(Expression::Variable("call".to_string())),
                        property: "callee".to_string(),
                    },
                    operator: ComparisonOp::Matches,
                    right: Expression::String("(?i)(log|console\\.)".to_string()),
                },
            ])),
            SelectClause::new(vec![SelectItem::Both {
                variable: "call".to_string(),
                message: "Potential sensitive data in log".to_string(),
            }]),
        )
    }

    fn cleartext_transmission_query() -> Query {
        Query::new(
            FromClause::new(EntityType::Literal, "str".to_string()),
            Some(WhereClause::new(vec![
                Predicate::Comparison {
                    left: Expression::Variable("str".to_string()),
                    operator: ComparisonOp::StartsWith,
                    right: Expression::String("http://".to_string()),
                },
            ])),
            SelectClause::new(vec![SelectItem::Both {
                variable: "str".to_string(),
                message: "Clear-text HTTP transmission".to_string(),
            }]),
        )
    }

    fn cleartext_storage_query() -> Query {
        Query::new(
            FromClause::new(EntityType::CallExpression, "call".to_string()),
            Some(WhereClause::new(vec![
                Predicate::Comparison {
                    left: Expression::PropertyAccess {
                        object: Box::new(Expression::Variable("call".to_string())),
                        property: "callee".to_string(),
                    },
                    operator: ComparisonOp::Matches,
                    right: Expression::String("(?i)(localStorage|sessionStorage)\\.setItem".to_string()),
                },
            ])),
            SelectClause::new(vec![SelectItem::Both {
                variable: "call".to_string(),
                message: "Clear-text storage of sensitive data".to_string(),
            }]),
        )
    }

    fn error_message_exposure_query() -> Query {
        Query::new(
            FromClause::new(EntityType::CallExpression, "call".to_string()),
            Some(WhereClause::new(vec![
                Predicate::Comparison {
                    left: Expression::PropertyAccess {
                        object: Box::new(Expression::Variable("call".to_string())),
                        property: "callee".to_string(),
                    },
                    operator: ComparisonOp::Matches,
                    right: Expression::String("(?i)(send|res\\.).*error".to_string()),
                },
            ])),
            SelectClause::new(vec![SelectItem::Both {
                variable: "call".to_string(),
                message: "Error message exposure".to_string(),
            }]),
        )
    }

    // Code quality queries
    fn unused_variable_query() -> Query {
        Query::new(
            FromClause::new(EntityType::VariableDeclaration, "vd".to_string()),
            None,
            SelectClause::new(vec![SelectItem::Both {
                variable: "vd".to_string(),
                message: "Unused variable".to_string(),
            }]),
        )
    }

    fn dead_code_query() -> Query {
        Query::new(
            FromClause::new(EntityType::AnyNode, "stmt".to_string()),
            None,
            SelectClause::new(vec![SelectItem::Both {
                variable: "stmt".to_string(),
                message: "Unreachable code".to_string(),
            }]),
        )
    }

    fn duplicate_code_query() -> Query {
        Query::new(
            FromClause::new(EntityType::FunctionDeclaration, "func".to_string()),
            None,
            SelectClause::new(vec![SelectItem::Both {
                variable: "func".to_string(),
                message: "Duplicate code detected".to_string(),
            }]),
        )
    }

    fn complex_function_query() -> Query {
        Query::new(
            FromClause::new(EntityType::FunctionDeclaration, "func".to_string()),
            None,
            SelectClause::new(vec![SelectItem::Both {
                variable: "func".to_string(),
                message: "High cyclomatic complexity".to_string(),
            }]),
        )
    }

    fn missing_error_handling_query() -> Query {
        Query::new(
            FromClause::new(EntityType::CallExpression, "call".to_string()),
            Some(WhereClause::new(vec![
                Predicate::Comparison {
                    left: Expression::PropertyAccess {
                        object: Box::new(Expression::Variable("call".to_string())),
                        property: "callee".to_string(),
                    },
                    operator: ComparisonOp::Matches,
                    right: Expression::String("(?i)(then|async)".to_string()),
                },
            ])),
            SelectClause::new(vec![SelectItem::Both {
                variable: "call".to_string(),
                message: "Missing error handling".to_string(),
            }]),
        )
    }

    // Resource management queries
    fn redos_query() -> Query {
        Query::new(
            FromClause::new(EntityType::Literal, "regex".to_string()),
            Some(WhereClause::new(vec![
                Predicate::Comparison {
                    left: Expression::Variable("regex".to_string()),
                    operator: ComparisonOp::Matches,
                    right: Expression::String("(\\(.*\\*.*\\+.*\\)|\\+.*\\*|\\*.*\\+)".to_string()),
                },
            ])),
            SelectClause::new(vec![SelectItem::Both {
                variable: "regex".to_string(),
                message: "ReDoS-vulnerable regex pattern".to_string(),
            }]),
        )
    }

    fn xml_bomb_query() -> Query {
        Query::new(
            FromClause::new(EntityType::CallExpression, "call".to_string()),
            Some(WhereClause::new(vec![
                Predicate::Comparison {
                    left: Expression::PropertyAccess {
                        object: Box::new(Expression::Variable("call".to_string())),
                        property: "callee".to_string(),
                    },
                    operator: ComparisonOp::Matches,
                    right: Expression::String("(?i)(parseXml|XMLParser)".to_string()),
                },
            ])),
            SelectClause::new(vec![SelectItem::Both {
                variable: "call".to_string(),
                message: "XML bomb / billion laughs vulnerability".to_string(),
            }]),
        )
    }

    fn uncontrolled_resource_query() -> Query {
        Query::new(
            FromClause::new(EntityType::CallExpression, "call".to_string()),
            Some(WhereClause::new(vec![
                Predicate::Comparison {
                    left: Expression::PropertyAccess {
                        object: Box::new(Expression::Variable("call".to_string())),
                        property: "callee".to_string(),
                    },
                    operator: ComparisonOp::Matches,
                    right: Expression::String("(?i)(allocate|buffer|array)".to_string()),
                },
            ])),
            SelectClause::new(vec![SelectItem::Both {
                variable: "call".to_string(),
                message: "Uncontrolled resource consumption".to_string(),
            }]),
        )
    }

    fn memory_leak_query() -> Query {
        Query::new(
            FromClause::new(EntityType::CallExpression, "call".to_string()),
            Some(WhereClause::new(vec![
                Predicate::Comparison {
                    left: Expression::PropertyAccess {
                        object: Box::new(Expression::Variable("call".to_string())),
                        property: "callee".to_string(),
                    },
                    operator: ComparisonOp::Matches,
                    right: Expression::String("(?i)(addEventListener|on\\()".to_string()),
                },
            ])),
            SelectClause::new(vec![SelectItem::Both {
                variable: "call".to_string(),
                message: "Potential memory leak - missing cleanup".to_string(),
            }]),
        )
    }

    // Error handling queries
    fn empty_catch_block_query() -> Query {
        Query::new(
            FromClause::new(EntityType::AnyNode, "catch".to_string()),
            None,
            SelectClause::new(vec![SelectItem::Both {
                variable: "catch".to_string(),
                message: "Empty catch block suppresses errors".to_string(),
            }]),
        )
    }

    fn generic_exception_query() -> Query {
        Query::new(
            FromClause::new(EntityType::AnyNode, "catch".to_string()),
            None,
            SelectClause::new(vec![SelectItem::Both {
                variable: "catch".to_string(),
                message: "Overly broad exception catching".to_string(),
            }]),
        )
    }

    fn unhandled_promise_rejection_query() -> Query {
        Query::new(
            FromClause::new(EntityType::CallExpression, "call".to_string()),
            Some(WhereClause::new(vec![
                Predicate::Comparison {
                    left: Expression::PropertyAccess {
                        object: Box::new(Expression::Variable("call".to_string())),
                        property: "callee".to_string(),
                    },
                    operator: ComparisonOp::Contains,
                    right: Expression::String("then".to_string()),
                },
            ])),
            SelectClause::new(vec![SelectItem::Both {
                variable: "call".to_string(),
                message: "Promise without rejection handler".to_string(),
            }]),
        )
    }

    // API misuse queries
    fn ssrf_query() -> Query {
        Query::new(
            FromClause::new(EntityType::MethodCall, "mc".to_string()),
            Some(WhereClause::new(vec![
                Predicate::MethodName {
                    variable: "mc".to_string(),
                    operator: ComparisonOp::Matches,
                    value: "(?i)(fetch|get|post|put|delete|request|open|openConnection|openStream|getInputStream)".to_string(),
                },
                Predicate::FunctionCall {
                    variable: "mc".to_string(),
                    function: "isTainted".to_string(),
                    arguments: Vec::new(),
                },
            ])),
            SelectClause::new(vec![SelectItem::Both {
                variable: "mc".to_string(),
                message: "Server-side request forgery (SSRF) - untrusted URL".to_string(),
            }]),
        )
    }

    fn xxe_query() -> Query {
        Query::new(
            FromClause::new(EntityType::MethodCall, "mc".to_string()),
            Some(WhereClause::new(vec![
                Predicate::MethodName {
                    variable: "mc".to_string(),
                    operator: ComparisonOp::Matches,
                    value: "(?i)(parse|parseXml|newDocumentBuilder|newSAXParser|unmarshal)".to_string(),
                },
                Predicate::FunctionCall {
                    variable: "mc".to_string(),
                    function: "isTainted".to_string(),
                    arguments: Vec::new(),
                },
            ])),
            SelectClause::new(vec![SelectItem::Both {
                variable: "mc".to_string(),
                message: "XML External Entity (XXE) vulnerability - untrusted XML input".to_string(),
            }]),
        )
    }

    fn insecure_deserialization_query() -> Query {
        Query::new(
            FromClause::new(EntityType::MethodCall, "mc".to_string()),
            Some(WhereClause::new(vec![
                Predicate::MethodName {
                    variable: "mc".to_string(),
                    operator: ComparisonOp::Matches,
                    // More specific patterns to avoid matching url_decode, base64_decode, etc.
                    value: "(?i)(\\bdeserialize\\b|\\bunserialize\\b|\\breadObject\\b|pickle\\.loads?|yaml\\.load|Marshal\\.load|json_decode|unserialize|ObjectInputStream)".to_string(),
                },
                Predicate::FunctionCall {
                    variable: "mc".to_string(),
                    function: "isTainted".to_string(),
                    arguments: Vec::new(),
                },
            ])),
            SelectClause::new(vec![SelectItem::Both {
                variable: "mc".to_string(),
                message: "Insecure deserialization - untrusted data being deserialized".to_string(),
            }]),
        )
    }

    fn prototype_pollution_query() -> Query {
        Query::new(
            FromClause::new(EntityType::MemberExpression, "member".to_string()),
            Some(WhereClause::new(vec![
                Predicate::Comparison {
                    left: Expression::PropertyAccess {
                        object: Box::new(Expression::Variable("member".to_string())),
                        property: "property".to_string(),
                    },
                    operator: ComparisonOp::Matches,
                    right: Expression::String("(?i)(__proto__|constructor|prototype)".to_string()),
                },
            ])),
            SelectClause::new(vec![SelectItem::Both {
                variable: "member".to_string(),
                message: "Prototype pollution vulnerability".to_string(),
            }]),
        )
    }

    fn open_redirect_query() -> Query {
        Query::new(
            FromClause::new(EntityType::MethodCall, "mc".to_string()),
            Some(WhereClause::new(vec![
                Predicate::MethodName {
                    variable: "mc".to_string(),
                    operator: ComparisonOp::Matches,
                    value: "(?i)(redirect|sendRedirect|location|navigate)".to_string(),
                },
                Predicate::FunctionCall {
                    variable: "mc".to_string(),
                    function: "isTainted".to_string(),
                    arguments: Vec::new(),
                },
            ])),
            SelectClause::new(vec![SelectItem::Both {
                variable: "mc".to_string(),
                message: "Open redirect vulnerability - untrusted URL in redirect".to_string(),
            }]),
        )
    }

    fn cors_misconfiguration_query() -> Query {
        Query::new(
            FromClause::new(EntityType::CallExpression, "call".to_string()),
            Some(WhereClause::new(vec![
                Predicate::Comparison {
                    left: Expression::PropertyAccess {
                        object: Box::new(Expression::Variable("call".to_string())),
                        property: "callee".to_string(),
                    },
                    operator: ComparisonOp::Contains,
                    right: Expression::String("Access-Control-Allow-Origin".to_string()),
                },
            ])),
            SelectClause::new(vec![SelectItem::Both {
                variable: "call".to_string(),
                message: "CORS misconfiguration".to_string(),
            }]),
        )
    }

    // Configuration queries
    fn debug_mode_production_query() -> Query {
        Query::new(
            FromClause::new(EntityType::Assignment, "assign".to_string()),
            Some(WhereClause::new(vec![
                Predicate::Comparison {
                    left: Expression::PropertyAccess {
                        object: Box::new(Expression::Variable("assign".to_string())),
                        property: "left".to_string(),
                    },
                    operator: ComparisonOp::Matches,
                    right: Expression::String("(?i)(debug|DEBUG)".to_string()),
                },
            ])),
            SelectClause::new(vec![SelectItem::Both {
                variable: "assign".to_string(),
                message: "Debug mode in production".to_string(),
            }]),
        )
    }

    fn missing_security_headers_query() -> Query {
        Query::new(
            FromClause::new(EntityType::CallExpression, "call".to_string()),
            Some(WhereClause::new(vec![
                Predicate::Comparison {
                    left: Expression::PropertyAccess {
                        object: Box::new(Expression::Variable("call".to_string())),
                        property: "callee".to_string(),
                    },
                    operator: ComparisonOp::Contains,
                    right: Expression::String("setHeader".to_string()),
                },
            ])),
            SelectClause::new(vec![SelectItem::Both {
                variable: "call".to_string(),
                message: "Missing security headers".to_string(),
            }]),
        )
    }

    fn disabled_https_query() -> Query {
        Query::new(
            FromClause::new(EntityType::Literal, "obj".to_string()),
            Some(WhereClause::new(vec![
                Predicate::Comparison {
                    left: Expression::PropertyAccess {
                        object: Box::new(Expression::Variable("obj".to_string())),
                        property: "secure".to_string(),
                    },
                    operator: ComparisonOp::Equal,
                    right: Expression::Boolean(false),
                },
            ])),
            SelectClause::new(vec![SelectItem::Both {
                variable: "obj".to_string(),
                message: "HTTPS disabled or not enforced".to_string(),
            }]),
        )
    }

    fn disabled_cert_validation_query() -> Query {
        Query::new(
            FromClause::new(EntityType::Literal, "obj".to_string()),
            Some(WhereClause::new(vec![
                Predicate::Comparison {
                    left: Expression::PropertyAccess {
                        object: Box::new(Expression::Variable("obj".to_string())),
                        property: "rejectUnauthorized".to_string(),
                    },
                    operator: ComparisonOp::Equal,
                    right: Expression::Boolean(false),
                },
            ])),
            SelectClause::new(vec![SelectItem::Both {
                variable: "obj".to_string(),
                message: "SSL/TLS certificate validation disabled".to_string(),
            }]),
        )
    }

    // Framework-specific queries
    fn express_weak_session_secret_query() -> Query {
        // Match Express.js session middleware patterns, NOT Java's getSession()
        // Express patterns: express-session, session({ secret: ... })
        Query::new(
            FromClause::new(EntityType::CallExpression, "call".to_string()),
            Some(WhereClause::new(vec![
                Predicate::Comparison {
                    left: Expression::PropertyAccess {
                        object: Box::new(Expression::Variable("call".to_string())),
                        property: "callee".to_string(),
                    },
                    operator: ComparisonOp::Matches,
                    // Match Express-specific session patterns:
                    // - session({ ... }) - the express-session middleware
                    // - app.use(session(...))
                    // Exclude Java's getSession(), HttpSession, etc.
                    right: Expression::String("^session$|express-session|cookieSession".to_string()),
                },
            ])),
            SelectClause::new(vec![SelectItem::Both {
                variable: "call".to_string(),
                message: "Weak Express session secret".to_string(),
            }]),
        )
    }

    fn express_missing_helmet_query() -> Query {
        Query::new(
            FromClause::new(EntityType::CallExpression, "call".to_string()),
            Some(WhereClause::new(vec![
                Predicate::Comparison {
                    left: Expression::PropertyAccess {
                        object: Box::new(Expression::Variable("call".to_string())),
                        property: "callee".to_string(),
                    },
                    operator: ComparisonOp::Equal,
                    right: Expression::String("express".to_string()),
                },
            ])),
            SelectClause::new(vec![SelectItem::Both {
                variable: "call".to_string(),
                message: "Express app missing Helmet middleware".to_string(),
            }]),
        )
    }

    fn mongodb_injection_query() -> Query {
        // Note: Only match MongoDB-specific method names, not generic ones like "update"
        // MessageDigest.update() should NOT be flagged as MongoDB injection
        Query::new(
            FromClause::new(EntityType::MethodCall, "mc".to_string()),
            Some(WhereClause::new(vec![
                Predicate::MethodName {
                    variable: "mc".to_string(),
                    operator: ComparisonOp::Matches,
                    // More specific MongoDB methods to avoid FPs:
                    // - findOne, findOneAndUpdate, findOneAndDelete are MongoDB-specific
                    // - Generic "find", "update", "delete" should be avoided as they match other APIs
                    value: "(?i)(collection\\.find|findOne|findOneAndUpdate|findOneAndDelete|updateOne|updateMany|deleteOne|deleteMany|insertOne|insertMany|aggregate|\\$where)".to_string(),
                },
                Predicate::FunctionCall {
                    variable: "mc".to_string(),
                    function: "isTainted".to_string(),
                    arguments: Vec::new(),
                },
            ])),
            SelectClause::new(vec![SelectItem::Both {
                variable: "mc".to_string(),
                message: "MongoDB injection vulnerability - untrusted data in query".to_string(),
            }]),
        )
    }

    fn graphql_injection_query() -> Query {
        Query::new(
            FromClause::new(EntityType::CallExpression, "call".to_string()),
            Some(WhereClause::new(vec![
                Predicate::Comparison {
                    left: Expression::PropertyAccess {
                        object: Box::new(Expression::Variable("call".to_string())),
                        property: "callee".to_string(),
                    },
                    operator: ComparisonOp::Matches,
                    right: Expression::String("(?i)(graphql|execute)".to_string()),
                },
            ])),
            SelectClause::new(vec![SelectItem::Both {
                variable: "call".to_string(),
                message: "GraphQL injection vulnerability".to_string(),
            }]),
        )
    }

    fn react_xss_props_query() -> Query {
        Query::new(
            FromClause::new(EntityType::MemberExpression, "member".to_string()),
            Some(WhereClause::new(vec![
                Predicate::Comparison {
                    left: Expression::PropertyAccess {
                        object: Box::new(Expression::Variable("member".to_string())),
                        property: "property".to_string(),
                    },
                    operator: ComparisonOp::Contains,
                    right: Expression::String("props".to_string()),
                },
            ])),
            SelectClause::new(vec![SelectItem::Both {
                variable: "member".to_string(),
                message: "React XSS via props".to_string(),
            }]),
        )
    }

    fn angular_template_injection_query() -> Query {
        Query::new(
            FromClause::new(EntityType::Literal, "str".to_string()),
            Some(WhereClause::new(vec![
                Predicate::Comparison {
                    left: Expression::Variable("str".to_string()),
                    operator: ComparisonOp::Matches,
                    right: Expression::String("\\{\\{.*\\}\\}".to_string()),
                },
            ])),
            SelectClause::new(vec![SelectItem::Both {
                variable: "str".to_string(),
                message: "Angular template injection".to_string(),
            }]),
        )
    }

    fn vue_xss_query() -> Query {
        Query::new(
            FromClause::new(EntityType::MemberExpression, "member".to_string()),
            Some(WhereClause::new(vec![
                Predicate::Comparison {
                    left: Expression::PropertyAccess {
                        object: Box::new(Expression::Variable("member".to_string())),
                        property: "property".to_string(),
                    },
                    operator: ComparisonOp::Matches,
                    right: Expression::String("(?i)(v-html|innerHTML)".to_string()),
                },
            ])),
            SelectClause::new(vec![SelectItem::Both {
                variable: "member".to_string(),
                message: "Vue.js XSS vulnerability".to_string(),
            }]),
        )
    }

    fn nextjs_ssrf_query() -> Query {
        Query::new(
            FromClause::new(EntityType::CallExpression, "call".to_string()),
            Some(WhereClause::new(vec![
                Predicate::Comparison {
                    left: Expression::PropertyAccess {
                        object: Box::new(Expression::Variable("call".to_string())),
                        property: "callee".to_string(),
                    },
                    operator: ComparisonOp::Matches,
                    right: Expression::String("(?i)(getServerSideProps|getStaticProps)".to_string()),
                },
            ])),
            SelectClause::new(vec![SelectItem::Both {
                variable: "call".to_string(),
                message: "Next.js SSRF vulnerability".to_string(),
            }]),
        )
    }

    fn electron_node_integration_query() -> Query {
        Query::new(
            FromClause::new(EntityType::Literal, "obj".to_string()),
            Some(WhereClause::new(vec![
                Predicate::Comparison {
                    left: Expression::PropertyAccess {
                        object: Box::new(Expression::Variable("obj".to_string())),
                        property: "nodeIntegration".to_string(),
                    },
                    operator: ComparisonOp::Equal,
                    right: Expression::Boolean(true),
                },
            ])),
            SelectClause::new(vec![SelectItem::Both {
                variable: "obj".to_string(),
                message: "Electron nodeIntegration enabled - RCE risk".to_string(),
            }]),
        )
    }

    fn electron_context_isolation_query() -> Query {
        Query::new(
            FromClause::new(EntityType::Literal, "obj".to_string()),
            Some(WhereClause::new(vec![
                Predicate::Comparison {
                    left: Expression::PropertyAccess {
                        object: Box::new(Expression::Variable("obj".to_string())),
                        property: "contextIsolation".to_string(),
                    },
                    operator: ComparisonOp::Equal,
                    right: Expression::Boolean(false),
                },
            ])),
            SelectClause::new(vec![SelectItem::Both {
                variable: "obj".to_string(),
                message: "Electron contextIsolation disabled".to_string(),
            }]),
        )
    }

    // ==================== JAVA QUERY IMPLEMENTATIONS ====================

    /// Java SQL Injection - detects tainted data flowing to Statement.execute(), executeQuery(), etc.
    fn java_sql_injection_query() -> Query {
        Query::new(
            FromClause::new(EntityType::MethodCall, "mc".to_string()),
            Some(WhereClause::new(vec![
                Predicate::MethodName {
                    variable: "mc".to_string(),
                    operator: ComparisonOp::Matches,
                    value: "(?i)(executeQuery|executeUpdate|execute|prepareStatement|createStatement|nativeQuery|createQuery)".to_string(),
                },
                Predicate::FunctionCall {
                    variable: "mc".to_string(),
                    function: "isTainted".to_string(),
                    arguments: Vec::new(),
                },
            ])),
            SelectClause::new(vec![SelectItem::Both {
                variable: "mc".to_string(),
                message: "SQL injection vulnerability - untrusted data in database query".to_string(),
            }]),
        )
    }

    /// Java Command Injection - detects tainted data flowing to Runtime.exec(), ProcessBuilder
    fn java_command_injection_query() -> Query {
        Query::new(
            FromClause::new(EntityType::MethodCall, "mc".to_string()),
            Some(WhereClause::new(vec![
                Predicate::MethodName {
                    variable: "mc".to_string(),
                    operator: ComparisonOp::Matches,
                    value: "(?i)(exec|command|start|ProcessBuilder)".to_string(),
                },
                Predicate::FunctionCall {
                    variable: "mc".to_string(),
                    function: "isTainted".to_string(),
                    arguments: Vec::new(),
                },
            ])),
            SelectClause::new(vec![SelectItem::Both {
                variable: "mc".to_string(),
                message: "Command injection vulnerability - untrusted data in system command".to_string(),
            }]),
        )
    }

    /// Java LDAP Injection - detects tainted data flowing to DirContext.search()
    fn java_ldap_injection_query() -> Query {
        Query::new(
            FromClause::new(EntityType::MethodCall, "mc".to_string()),
            Some(WhereClause::new(vec![
                Predicate::MethodName {
                    variable: "mc".to_string(),
                    operator: ComparisonOp::Matches,
                    value: "(?i)(search|lookup|bind)".to_string(),
                },
                Predicate::FunctionCall {
                    variable: "mc".to_string(),
                    function: "isTainted".to_string(),
                    arguments: Vec::new(),
                },
            ])),
            SelectClause::new(vec![SelectItem::Both {
                variable: "mc".to_string(),
                message: "LDAP injection vulnerability - untrusted data in LDAP query".to_string(),
            }]),
        )
    }

    /// Java XPath Injection - detects tainted data flowing to XPath.evaluate()
    /// Note: Removed 'compile' as it causes FPs with Pattern.compile() in regex code
    /// Keep 'evaluate' as it's the primary XPath method - taint tracking filters non-XPath uses
    fn java_xpath_injection_query() -> Query {
        Query::new(
            FromClause::new(EntityType::MethodCall, "mc".to_string()),
            Some(WhereClause::new(vec![
                Predicate::MethodName {
                    variable: "mc".to_string(),
                    operator: ComparisonOp::Matches,
                    value: "(?i)(evaluate|selectNodes|selectSingleNode)".to_string(),
                },
                Predicate::FunctionCall {
                    variable: "mc".to_string(),
                    function: "isTainted".to_string(),
                    arguments: Vec::new(),
                },
            ])),
            SelectClause::new(vec![SelectItem::Both {
                variable: "mc".to_string(),
                message: "XPath injection vulnerability - untrusted data in XPath expression".to_string(),
            }]),
        )
    }

    fn java_path_traversal_query() -> Query {
        Query::new(
            FromClause::new(EntityType::MethodCall, "mc".to_string()),
            Some(WhereClause::new(vec![
                Predicate::MethodName {
                    variable: "mc".to_string(),
                    operator: ComparisonOp::Matches,
                    // Java file operations
                    value: "(?i)(FileInputStream|FileOutputStream|FileReader|FileWriter|RandomAccessFile|File|getResource|getResourceAsStream|createTempFile|newInputStream|newOutputStream)".to_string(),
                },
                Predicate::FunctionCall {
                    variable: "mc".to_string(),
                    function: "isTainted".to_string(),
                    arguments: Vec::new(),
                },
            ])),
            SelectClause::new(vec![SelectItem::Both {
                variable: "mc".to_string(),
                message: "Path traversal vulnerability - untrusted data in file path".to_string(),
            }]),
        )
    }
}

impl Default for ExtendedStandardLibrary {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_extended_library_initialization() {
        let lib = ExtendedStandardLibrary::new();
        let all_queries = lib.all_queries();

        // Verify we have 75+ queries
        assert!(all_queries.len() >= 75, "Expected 75+ queries, got {}", all_queries.len());
    }

    #[test]
    fn test_query_suites() {
        let lib = ExtendedStandardLibrary::new();

        let default = lib.get_suite(QuerySuite::Default);
        let extended = lib.get_suite(QuerySuite::SecurityExtended);
        let quality = lib.get_suite(QuerySuite::SecurityAndQuality);

        // Print actual counts for debugging
        eprintln!("Default: {}, Extended: {}, Quality: {}", default.len(), extended.len(), quality.len());

        // Verify we have queries in each suite
        assert!(default.len() > 0, "Default suite should have queries");
        assert!(extended.len() > 0, "Extended suite should have queries");
        assert!(quality.len() > 0, "Quality suite should have queries");

        // Quality suite should have the most queries (includes both security and quality)
        assert!(quality.len() >= extended.len(), "Quality suite should have at least as many queries as extended");
    }

    #[test]
    fn test_query_metadata() {
        let lib = ExtendedStandardLibrary::new();

        if let Some((_, metadata)) = lib.get("js/sql-injection") {
            assert_eq!(metadata.id, "js/sql-injection");
            assert!(metadata.cwes.contains(&89));
            assert_eq!(metadata.severity, QuerySeverity::Critical);
            assert!(metadata.sans_top_25);
        } else {
            panic!("SQL injection query not found");
        }
    }
}
