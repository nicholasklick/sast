//! Language-specific taint analysis configurations
//!
//! This module provides taint sources, sinks, and sanitizers for different
//! programming languages. Each language has unique frameworks, APIs, and
//! security-sensitive functions that need to be tracked.
//!
//! ## Configuration Sources
//!
//! Configurations can be loaded from:
//! 1. YAML files in the `models/` directory (MaD format, preferred)
//! 2. Hardcoded configurations in this module (fallback)
//!
//! When a YAML config exists for a language, it takes precedence over hardcoded configs.

use crate::taint::{TaintSink, TaintSinkKind, TaintSource, TaintSourceKind};
use crate::yaml_config::{TaintConfigYaml, TaintConfigRegistry, SinkKind as YamlSinkKind, SourceKind as YamlSourceKind};
use gittera_parser::language::Language;
use std::path::Path;
use std::sync::OnceLock;

/// Global registry for YAML configs (lazily initialized)
static YAML_REGISTRY: OnceLock<Option<TaintConfigRegistry>> = OnceLock::new();

/// Initialize the YAML config registry from the models directory
pub fn init_yaml_configs(models_dir: &Path) -> Result<(), String> {
    let registry = TaintConfigRegistry::load_from_dir(models_dir)
        .map_err(|e| format!("Failed to load YAML configs: {}", e))?;

    // Store the registry (ignore if already initialized)
    let _ = YAML_REGISTRY.set(Some(registry));
    Ok(())
}

/// Get the YAML config registry if initialized
fn get_yaml_registry() -> Option<&'static TaintConfigRegistry> {
    YAML_REGISTRY.get().and_then(|opt| opt.as_ref())
}

/// Get sanitizer flow states from YAML config for a given language and function name.
/// Returns None if the function is not a sanitizer, Some(empty) for universal sanitizers,
/// or Some(states) for context-specific sanitizers.
pub fn get_yaml_sanitizer_flow_states(language: Language, name: &str) -> Option<std::collections::HashSet<crate::taint::FlowState>> {
    let registry = get_yaml_registry()?;
    let lang_name = language_to_string(language);
    let yaml_config = registry.get(&lang_name)?;
    yaml_config.get_sanitizer_flow_states(name)
}

/// Convert Language enum to string for YAML lookup
fn language_to_string(language: Language) -> String {
    match language {
        Language::Ruby => "ruby",
        Language::Php => "php",
        Language::JavaScript => "javascript",
        Language::TypeScript => "typescript",
        Language::Python => "python",
        Language::Java => "java",
        Language::Go => "go",
        Language::CSharp => "csharp",
        Language::Swift => "swift",
        Language::Rust => "rust",
        Language::Lua => "lua",
        Language::Perl => "perl",
        Language::Bash => "bash",
        Language::Dart => "dart",
        Language::C => "c",
        Language::Cpp => "cpp",
        Language::Kotlin => "kotlin",
        Language::Scala => "scala",
        _ => "generic",
    }.to_string()
}

/// Convert YAML source kind to internal source kind
fn convert_source_kind(kind: &YamlSourceKind) -> TaintSourceKind {
    match kind {
        YamlSourceKind::UserInput => TaintSourceKind::UserInput,
        YamlSourceKind::Environment => TaintSourceKind::EnvironmentVariable,
        YamlSourceKind::Database => TaintSourceKind::DatabaseQuery,
        YamlSourceKind::File => TaintSourceKind::FileRead,
        YamlSourceKind::Network => TaintSourceKind::NetworkRequest,
        YamlSourceKind::Config => TaintSourceKind::EnvironmentVariable, // Closest match
    }
}

/// Convert YAML sink kind to internal sink kind
fn convert_sink_kind(kind: &YamlSinkKind) -> TaintSinkKind {
    match kind {
        YamlSinkKind::SqlQuery => TaintSinkKind::SqlQuery,
        YamlSinkKind::CommandExecution => TaintSinkKind::CommandExecution,
        YamlSinkKind::FileWrite => TaintSinkKind::FileWrite,
        YamlSinkKind::CodeEval => TaintSinkKind::CodeEval,
        YamlSinkKind::HtmlOutput => TaintSinkKind::HtmlOutput,
        YamlSinkKind::LogOutput => TaintSinkKind::LogOutput,
        YamlSinkKind::NetworkSend => TaintSinkKind::NetworkSend,
        YamlSinkKind::PathTraversal => TaintSinkKind::PathTraversal,
        YamlSinkKind::Deserialization => TaintSinkKind::Deserialization,
        YamlSinkKind::LdapQuery => TaintSinkKind::LdapQuery,
        YamlSinkKind::XPathQuery => TaintSinkKind::XPathQuery,
        YamlSinkKind::XmlParse => TaintSinkKind::XmlParse,
        YamlSinkKind::TrustBoundary => TaintSinkKind::TrustBoundary,
    }
}

/// Language-specific taint configuration
pub struct LanguageTaintConfig {
    pub language: Language,
    pub sources: Vec<TaintSource>,
    pub sinks: Vec<TaintSink>,
    pub sanitizers: Vec<String>,
}

impl LanguageTaintConfig {
    /// Get taint configuration for a specific language
    ///
    /// This method first checks if a YAML config exists for the language
    /// (requires `init_yaml_configs` to be called first). If no YAML config
    /// is found, it falls back to the hardcoded configuration.
    pub fn for_language(language: Language) -> Self {
        // First, try to load from YAML if the registry is initialized
        if let Some(yaml_config) = Self::try_from_yaml(language) {
            return yaml_config;
        }

        // Fall back to hardcoded configs
        Self::for_language_hardcoded(language)
    }

    /// Try to load configuration from YAML
    fn try_from_yaml(language: Language) -> Option<Self> {
        let registry = get_yaml_registry()?;
        let lang_name = language_to_string(language);
        let yaml_config = registry.get(&lang_name)?;

        Some(Self::from_yaml_config(language, yaml_config))
    }

    /// Convert a YAML config to LanguageTaintConfig
    fn from_yaml_config(language: Language, yaml: &TaintConfigYaml) -> Self {
        let sources = yaml.sources.iter().map(|s| {
            TaintSource {
                name: s.name.clone(),
                kind: convert_source_kind(&s.kind),
                node_id: 0,
            }
        }).collect();

        let sinks = yaml.sinks.iter().map(|s| {
            TaintSink {
                name: s.name.clone(),
                kind: convert_sink_kind(&s.kind),
                node_id: 0,
            }
        }).collect();

        let sanitizers = yaml.sanitizers.iter()
            .map(|s| s.name.clone())
            .collect();

        Self {
            language,
            sources,
            sinks,
            sanitizers,
        }
    }

    /// Get hardcoded taint configuration for a specific language (fallback)
    fn for_language_hardcoded(language: Language) -> Self {
        match language {
            Language::Ruby => Self::ruby_config(),
            Language::Php => Self::php_config(),
            Language::JavaScript => Self::javascript_config(Language::JavaScript),
            Language::TypeScript => Self::javascript_config(Language::TypeScript),
            Language::Python => Self::python_config(),
            Language::Java => Self::java_config(),
            Language::Go => Self::go_config(),
            Language::CSharp => Self::csharp_config(),
            Language::Swift => Self::swift_config(),
            Language::Rust => Self::rust_config(),
            Language::Lua => Self::lua_config(),
            Language::Perl => Self::perl_config(),
            Language::Bash => Self::bash_config(),
            Language::Dart => Self::dart_config(),
            Language::C => Self::c_config(),
            Language::Cpp => Self::cpp_config(),
            Language::Kotlin => Self::kotlin_config(),
            Language::Scala => Self::scala_config(),
            _ => Self::generic_config(language),
        }
    }

    /// Ruby-specific taint configuration
    fn ruby_config() -> Self {
        let mut sources = Vec::new();
        let mut sinks = Vec::new();
        let mut sanitizers = Vec::new();

        // ============ RUBY TAINT SOURCES ============

        // User Input (Rails & Sinatra)
        let user_input_sources = vec![
            "params",           // Rails params hash
            "request.params",   // Explicit params access
            "request.query_string",
            "request.POST",
            "request.GET",
            "request.body",
            "request.env",
            "gets",             // STDIN
            "gets.chomp",
            "readline",
            "readlines",
            "STDIN.read",
            "STDIN.gets",
            "$stdin.read",
            "URI.parse",        // URL parameters
            "CGI.new",
        ];

        for name in user_input_sources {
            sources.push(TaintSource {
                name: name.to_string(),
                kind: TaintSourceKind::UserInput,
                node_id: 0,
            });
        }

        // File Read
        let file_sources = vec![
            "File.read",
            "File.open",
            "File.readlines",
            "IO.read",
            "IO.readlines",
            "open",             // Kernel#open
            "File.binread",
        ];

        for name in file_sources {
            sources.push(TaintSource {
                name: name.to_string(),
                kind: TaintSourceKind::FileRead,
                node_id: 0,
            });
        }

        // Environment Variables
        let env_sources = vec![
            "ENV",
            "ENV.fetch",
            "ENV[]",
        ];

        for name in env_sources {
            sources.push(TaintSource {
                name: name.to_string(),
                kind: TaintSourceKind::EnvironmentVariable,
                node_id: 0,
            });
        }

        // Network/HTTP
        let network_sources = vec![
            "Net::HTTP.get",
            "Net::HTTP.get_response",
            "open-uri",
            "RestClient.get",
            "HTTParty.get",
            "Faraday.get",
        ];

        for name in network_sources {
            sources.push(TaintSource {
                name: name.to_string(),
                kind: TaintSourceKind::NetworkRequest,
                node_id: 0,
            });
        }

        // Database Query Results
        let db_sources = vec![
            "ActiveRecord::Base.connection.execute",
            "ActiveRecord::Base.connection.select_all",
            "execute",
            "select_all",
        ];

        for name in db_sources {
            sources.push(TaintSource {
                name: name.to_string(),
                kind: TaintSourceKind::DatabaseQuery,
                node_id: 0,
            });
        }

        // ============ RUBY TAINT SINKS ============

        // Command Execution
        let cmd_sinks = vec![
            "system",
            "exec",
            "spawn",
            "`",                // Backticks
            "%x",               // %x{} syntax
            "Kernel.system",
            "Kernel.exec",
            "IO.popen",
            "Open3.popen3",
            "Open3.capture3",
            "PTY.spawn",
        ];

        for name in cmd_sinks {
            sinks.push(TaintSink {
                name: name.to_string(),
                kind: TaintSinkKind::CommandExecution,
                node_id: 0,
            });
        }

        // Code Evaluation
        let eval_sinks = vec![
            "eval",
            "instance_eval",
            "class_eval",
            "module_eval",
            "binding.eval",
            "Kernel.eval",
            "send",             // Dynamic method invocation
            "public_send",
            "__send__",
            "method",
            "const_get",        // Constant lookup
            "constantize",      // Rails method
        ];

        for name in eval_sinks {
            sinks.push(TaintSink {
                name: name.to_string(),
                kind: TaintSinkKind::CodeEval,
                node_id: 0,
            });
        }

        // SQL Injection (ActiveRecord & Raw SQL)
        let sql_sinks = vec![
            "execute",
            "execute_raw",      // Custom raw SQL execution
            "exec_query",
            "select_all",
            "select_one",
            "select_value",
            "select_values",
            "find_by_sql",
            "where",            // Can be unsafe with string interpolation
            "connection.execute",
            "ActiveRecord::Base.connection.execute",
        ];

        for name in sql_sinks {
            sinks.push(TaintSink {
                name: name.to_string(),
                kind: TaintSinkKind::SqlQuery,
                node_id: 0,
            });
        }

        // File Write
        let file_write_sinks = vec![
            "File.write",
            "IO.write",
            "File.binwrite",
            "FileUtils.cp",
            "FileUtils.mv",
            "FileUtils.rm",
        ];

        for name in file_write_sinks {
            sinks.push(TaintSink {
                name: name.to_string(),
                kind: TaintSinkKind::FileWrite,
                node_id: 0,
            });
        }

        // Path Traversal (file read with untrusted path)
        let path_traversal_sinks = vec![
            "File.read",
            "File.open",
            "File.readlines",
            "File.binread",
            "IO.read",
            "IO.readlines",
            "File.join",       // Building file paths
            "Pathname.new",
            "File.expand_path",
            "send_file",       // Rails file serving
            "send_data",
        ];

        for name in path_traversal_sinks {
            sinks.push(TaintSink {
                name: name.to_string(),
                kind: TaintSinkKind::PathTraversal,
                node_id: 0,
            });
        }

        // HTML/XSS (Rails)
        // Note: Removed "render" and "render_to_string" as they cause FPs
        // render plain:/json: are safe, only render html: is dangerous
        // Without argument-aware analysis, we can't distinguish these variants
        // Focus on clearly dangerous methods: raw, html_safe
        let html_sinks = vec![
            "html_safe",        // Explicitly marks content as safe HTML (dangerous if untrusted)
            "raw",              // Rails helper that bypasses escaping (dangerous)
            "content_tag",      // Can be dangerous if content is untrusted
            "link_to",          // Can be dangerous if href is untrusted
        ];

        for name in html_sinks {
            sinks.push(TaintSink {
                name: name.to_string(),
                kind: TaintSinkKind::HtmlOutput,
                node_id: 0,
            });
        }

        // Logging
        // Note: Removed "p" as it's a common Ruby debugging method but too short,
        // causing false positives when matching partial method names
        let log_sinks = vec![
            "puts",
            "print",
            "logger.info",
            "logger.debug",
            "logger.warn",
            "logger.error",
            "Rails.logger.info",
        ];

        for name in log_sinks {
            sinks.push(TaintSink {
                name: name.to_string(),
                kind: TaintSinkKind::LogOutput,
                node_id: 0,
            });
        }

        // ============ RUBY SANITIZERS ============

        sanitizers.extend(vec![
            "sanitize".to_string(),
            "escape".to_string(),
            "h".to_string(),                    // Rails HTML escape helper
            "html_escape".to_string(),
            "ERB::Util.html_escape".to_string(),
            "CGI.escapeHTML".to_string(),
            "Rack::Utils.escape_html".to_string(),
            "strip_tags".to_string(),
            "sanitize_sql".to_string(),
            "quote".to_string(),                // SQL quoting
            "Shellwords.escape".to_string(),
            "Shellwords.shellescape".to_string(),
            "validate".to_string(),
            "validates".to_string(),
            "permit".to_string(),               // Strong parameters
            "require".to_string(),
        ]);

        Self {
            language: Language::Ruby,
            sources,
            sinks,
            sanitizers,
        }
    }

    /// PHP-specific taint configuration
    fn php_config() -> Self {
        let mut sources = Vec::new();
        let mut sinks = Vec::new();
        let mut sanitizers = Vec::new();

        // ============ PHP TAINT SOURCES ============

        // User Input (Superglobals)
        let user_input_sources = vec![
            "$_GET",
            "$_POST",
            "$_REQUEST",
            "$_COOKIE",
            "$_SERVER",
            "$_FILES",
            "filter_input",
            "filter_input_array",
            "$HTTP_GET_VARS",
            "$HTTP_POST_VARS",
            "$HTTP_COOKIE_VARS",
        ];

        for name in user_input_sources {
            sources.push(TaintSource {
                name: name.to_string(),
                kind: TaintSourceKind::UserInput,
                node_id: 0,
            });
        }

        // File Read
        let file_sources = vec![
            "file_get_contents",
            "file",
            "readfile",
            "fread",
            "fgets",
            "fgetss",
            "fscanf",
            "parse_ini_file",
            "file_get_contents",
        ];

        for name in file_sources {
            sources.push(TaintSource {
                name: name.to_string(),
                kind: TaintSourceKind::FileRead,
                node_id: 0,
            });
        }

        // Environment Variables
        let env_sources = vec![
            "getenv",
            "apache_getenv",
            "$_ENV",
        ];

        for name in env_sources {
            sources.push(TaintSource {
                name: name.to_string(),
                kind: TaintSourceKind::EnvironmentVariable,
                node_id: 0,
            });
        }

        // Network/HTTP
        let network_sources = vec![
            "file_get_contents",    // With URL
            "fopen",                // With URL
            "curl_exec",
            "stream_get_contents",
        ];

        for name in network_sources {
            sources.push(TaintSource {
                name: name.to_string(),
                kind: TaintSourceKind::NetworkRequest,
                node_id: 0,
            });
        }

        // Database (mysqli, PDO)
        let db_sources = vec![
            "mysqli_query",
            "mysql_query",
            "mysqli_fetch_assoc",
            "mysqli_fetch_array",
            "PDO::query",
            "PDOStatement::fetch",
        ];

        for name in db_sources {
            sources.push(TaintSource {
                name: name.to_string(),
                kind: TaintSourceKind::DatabaseQuery,
                node_id: 0,
            });
        }

        // ============ PHP TAINT SINKS ============

        // Command Execution
        let cmd_sinks = vec![
            "system",
            "exec",
            "shell_exec",
            "passthru",
            "proc_open",
            "popen",
            "`",                // Backticks
            "pcntl_exec",
        ];

        for name in cmd_sinks {
            sinks.push(TaintSink {
                name: name.to_string(),
                kind: TaintSinkKind::CommandExecution,
                node_id: 0,
            });
        }

        // Code Evaluation
        let eval_sinks = vec![
            "eval",
            "assert",
            "create_function",
            "preg_replace",     // With /e modifier (deprecated but dangerous)
            "mb_ereg_replace",  // With 'e' option
            "call_user_func",
            "call_user_func_array",
            "$var",             // Variable functions (indirect)
        ];

        for name in eval_sinks {
            sinks.push(TaintSink {
                name: name.to_string(),
                kind: TaintSinkKind::CodeEval,
                node_id: 0,
            });
        }

        // SQL Injection
        let sql_sinks = vec![
            "mysqli_query",
            "mysql_query",
            "mysqli_multi_query",
            "mysqli_real_query",
            "PDO::query",
            "PDO::exec",
            "pg_query",
            "sqlite_query",
            "mssql_query",
            "oci_execute",
        ];

        for name in sql_sinks {
            sinks.push(TaintSink {
                name: name.to_string(),
                kind: TaintSinkKind::SqlQuery,
                node_id: 0,
            });
        }

        // File Write
        let file_write_sinks = vec![
            "file_put_contents",
            "fwrite",
            "fputs",
            "fputcsv",
            "rename",
            "unlink",
            "rmdir",
            "mkdir",
            "move_uploaded_file",
        ];

        for name in file_write_sinks {
            sinks.push(TaintSink {
                name: name.to_string(),
                kind: TaintSinkKind::FileWrite,
                node_id: 0,
            });
        }

        // HTML/XSS Output
        let html_sinks = vec![
            "echo",
            "print",
            "printf",
            "vprintf",
            "die",
            "exit",
            "trigger_error",
            "user_error",
        ];

        for name in html_sinks {
            sinks.push(TaintSink {
                name: name.to_string(),
                kind: TaintSinkKind::HtmlOutput,
                node_id: 0,
            });
        }

        // Logging
        let log_sinks = vec![
            "error_log",
            "syslog",
            "openlog",
            "trigger_error",
        ];

        for name in log_sinks {
            sinks.push(TaintSink {
                name: name.to_string(),
                kind: TaintSinkKind::LogOutput,
                node_id: 0,
            });
        }

        // ============ PHP SANITIZERS ============

        sanitizers.extend(vec![
            "htmlspecialchars".to_string(),
            "htmlentities".to_string(),
            "strip_tags".to_string(),
            "addslashes".to_string(),
            "mysqli_real_escape_string".to_string(),
            "mysql_real_escape_string".to_string(),
            "pg_escape_string".to_string(),
            "sqlite_escape_string".to_string(),
            "escapeshellarg".to_string(),
            "escapeshellcmd".to_string(),
            "filter_var".to_string(),
            "filter_input".to_string(),
            "intval".to_string(),
            "floatval".to_string(),
            "preg_quote".to_string(),
            "PDO::quote".to_string(),
            "preg_replace_callback".to_string(),  // Safer than preg_replace
        ]);

        Self {
            language: Language::Php,
            sources,
            sinks,
            sanitizers,
        }
    }

    /// JavaScript/TypeScript configuration (existing, but formalized here)
    fn javascript_config(language: Language) -> Self {
        let mut sources = Vec::new();
        let mut sinks = Vec::new();
        let mut sanitizers = Vec::new();

        // User Input
        for name in &[
            "request.body", "request.query", "request.params", "process.argv",
            "req.body", "req.query", "req.params", "req.cookies", "req.headers",  // Express
            "req.get", "req.header",  // Express header getters
            "ctx.request.body", "ctx.request.query", "ctx.cookies",  // Koa
            "event.body", "event.queryStringParameters", "event.headers",  // AWS Lambda
        ] {
            sources.push(TaintSource {
                name: name.to_string(),
                kind: TaintSourceKind::UserInput,
                node_id: 0,
            });
        }

        // Command Execution
        for name in &["exec", "spawn", "execSync", "child_process.exec"] {
            sinks.push(TaintSink {
                name: name.to_string(),
                kind: TaintSinkKind::CommandExecution,
                node_id: 0,
            });
        }

        // Code Eval
        for name in &["eval", "Function", "setTimeout", "setInterval"] {
            sinks.push(TaintSink {
                name: name.to_string(),
                kind: TaintSinkKind::CodeEval,
                node_id: 0,
            });
        }

        // XSS - Express response methods
        for name in &[
            "res.send", "res.write", "res.end", "res.json",
            "response.send", "response.write", "response.end",
            "ctx.body",  // Koa
            "document.write", "document.writeln",
            "innerHTML", "outerHTML",
        ] {
            sinks.push(TaintSink {
                name: name.to_string(),
                kind: TaintSinkKind::HtmlOutput,
                node_id: 0,
            });
        }

        // SQL Injection
        for name in &[
            "query", "execute", "raw",
            "executeRaw", "db.executeRaw",  // OWASP BenchmarkJS helper
            "sequelize.query", "sequelize.literal", "knex.raw",
            "connection.query", "pool.query",
            "prisma.$queryRaw", "prisma.$executeRaw",  // Prisma ORM
        ] {
            sinks.push(TaintSink {
                name: name.to_string(),
                kind: TaintSinkKind::SqlQuery,
                node_id: 0,
            });
        }

        // Path Traversal
        for name in &[
            "readFile", "readFileSync", "writeFile", "writeFileSync",
            "fs.readFile", "fs.readFileSync", "fs.writeFile", "fs.writeFileSync",
            "fs.open", "fs.openSync", "fs.createReadStream", "fs.createWriteStream",
            "path.join", "path.resolve",
        ] {
            sinks.push(TaintSink {
                name: name.to_string(),
                kind: TaintSinkKind::PathTraversal,
                node_id: 0,
            });
        }

        // Open Redirect (using NetworkSend as closest match)
        for name in &[
            "res.redirect", "response.redirect",
            "ctx.redirect",  // Koa
        ] {
            sinks.push(TaintSink {
                name: name.to_string(),
                kind: TaintSinkKind::NetworkSend,
                node_id: 0,
            });
        }

        // XPath Injection
        for name in &[
            "xpath.select", "xpath.select1", "xpath.evaluate",
            "xpath.useNamespaces",
            "document.evaluate",  // DOM XPath
        ] {
            sinks.push(TaintSink {
                name: name.to_string(),
                kind: TaintSinkKind::XPathQuery,
                node_id: 0,
            });
        }

        // Deserialization
        for name in &[
            "unserialize", "serialize.unserialize",
            "node-serialize.unserialize",  // node-serialize module
            "JSON.parse",  // Can be dangerous with reviver
            "yaml.load", "yaml.safeLoad",
            "pickle.loads",
            "js-yaml.load",  // js-yaml module
        ] {
            sinks.push(TaintSink {
                name: name.to_string(),
                kind: TaintSinkKind::Deserialization,
                node_id: 0,
            });
        }

        // LDAP Injection
        for name in &[
            "ldap.search", "ldap.bind", "ldap.add", "ldap.modify",
            "ldapjs.search", "client.search",
        ] {
            sinks.push(TaintSink {
                name: name.to_string(),
                kind: TaintSinkKind::LdapQuery,
                node_id: 0,
            });
        }

        // XML Parsing - XXE sinks
        for name in &[
            "parseFromString",           // DOMParser.parseFromString
            "parser.parseFromString",    // xmldom DOMParser
            "DOMParser.parseFromString",
            "parseXml",
            "parseXmlString",            // libxmljs
            "xml2js.parseString",
            "xml2js.Parser.parseString",
        ] {
            sinks.push(TaintSink {
                name: name.to_string(),
                kind: TaintSinkKind::XmlParse,
                node_id: 0,
            });
        }

        // MongoDB / NoSQL Injection
        for name in &[
            "$where",                    // MongoDB $where operator
            "collection.find",
            "collection.findOne",
            "db.collection.find",
            "Model.find",                // Mongoose
            "Model.findOne",
            "Model.findById",
            "Model.aggregate",
        ] {
            sinks.push(TaintSink {
                name: name.to_string(),
                kind: TaintSinkKind::SqlQuery,  // Using SqlQuery as closest match for NoSQL
                node_id: 0,
            });
        }

        // Regular Expression Injection (ReDoS)
        for name in &[
            "RegExp",                    // new RegExp(userInput)
            "new RegExp",
        ] {
            sinks.push(TaintSink {
                name: name.to_string(),
                kind: TaintSinkKind::CodeEval,  // Using CodeEval as closest match
                node_id: 0,
            });
        }

        sanitizers.extend(vec![
            "escape".to_string(),
            "sanitize".to_string(),
            "validator.escape".to_string(),
            "escapeHtml".to_string(),
            "utils.escapeForHtml".to_string(),
        ]);

        Self {
            language,
            sources,
            sinks,
            sanitizers,
        }
    }

    /// Python configuration (comprehensive - Flask, Django, FastAPI)
    fn python_config() -> Self {
        let mut sources = Vec::new();
        let mut sinks = Vec::new();
        let mut sanitizers = Vec::new();

        // ===== TAINT SOURCES =====

        // User Input - Flask
        for name in &[
            "request.args",
            "request.args.get",
            "request.form",
            "request.form.get",
            "request.form.getlist",
            "request.cookies",
            "request.cookies.get",
            "request.headers",
            "request.headers.get",
            "request.data",
            "request.json",
            "request.values",
            "request.values.get",
            "request.query_string",
            "request.path",
            "request.url",
            "request.files",
        ] {
            sources.push(TaintSource {
                name: name.to_string(),
                kind: TaintSourceKind::UserInput,
                node_id: 0,
            });
        }

        // User Input - Django
        for name in &[
            "request.GET",
            "request.GET.get",
            "request.POST",
            "request.POST.get",
            "request.COOKIES",
            "request.META",
            "request.body",
        ] {
            sources.push(TaintSource {
                name: name.to_string(),
                kind: TaintSourceKind::UserInput,
                node_id: 0,
            });
        }

        // User Input - FastAPI/Starlette
        for name in &[
            "Query",
            "Path",
            "Body",
            "Form",
            "Header",
            "Cookie",
        ] {
            sources.push(TaintSource {
                name: name.to_string(),
                kind: TaintSourceKind::UserInput,
                node_id: 0,
            });
        }

        // User Input - Standard library
        for name in &[
            "input",
            "raw_input",
            "sys.argv",
            "sys.stdin",
            "sys.stdin.read",
            "sys.stdin.readline",
        ] {
            sources.push(TaintSource {
                name: name.to_string(),
                kind: TaintSourceKind::UserInput,
                node_id: 0,
            });
        }

        // File Read
        for name in &[
            "open",
            "read",
            "readline",
            "readlines",
            "file.read",
            "Path.read_text",
            "Path.read_bytes",
        ] {
            sources.push(TaintSource {
                name: name.to_string(),
                kind: TaintSourceKind::FileRead,
                node_id: 0,
            });
        }

        // Environment Variables
        for name in &[
            "os.environ",
            "os.environ.get",
            "os.getenv",
        ] {
            sources.push(TaintSource {
                name: name.to_string(),
                kind: TaintSourceKind::EnvironmentVariable,
                node_id: 0,
            });
        }

        // Network/HTTP
        for name in &[
            "requests.get",
            "requests.post",
            "urllib.request.urlopen",
            "httpx.get",
        ] {
            sources.push(TaintSource {
                name: name.to_string(),
                kind: TaintSourceKind::NetworkRequest,
                node_id: 0,
            });
        }

        // ===== TAINT SINKS =====

        // SQL Injection (Critical)
        for name in &[
            "execute",
            "executemany",
            "cur.execute",
            "cursor.execute",
            "conn.execute",
            "connection.execute",
            "db.execute",
            "session.execute",
            "engine.execute",
            "raw",
            "RawSQL",
            "text",
        ] {
            sinks.push(TaintSink {
                name: name.to_string(),
                kind: TaintSinkKind::SqlQuery,
                node_id: 0,
            });
        }

        // Command Execution (Critical)
        for name in &[
            "os.system",
            "os.popen",
            "os.spawn",
            "os.spawnl",
            "os.spawnle",
            "os.spawnlp",
            "os.spawnlpe",
            "os.spawnv",
            "os.spawnve",
            "os.spawnvp",
            "os.spawnvpe",
            "os.execl",
            "os.execle",
            "os.execlp",
            "os.execlpe",
            "os.execv",
            "os.execve",
            "os.execvp",
            "os.execvpe",
            "subprocess.call",
            "subprocess.run",
            "subprocess.Popen",
            "subprocess.check_call",
            "subprocess.check_output",
            "commands.getoutput",
            "commands.getstatusoutput",
            "popen",
            "popen2",
            "popen3",
            "popen4",
        ] {
            sinks.push(TaintSink {
                name: name.to_string(),
                kind: TaintSinkKind::CommandExecution,
                node_id: 0,
            });
        }

        // Code Evaluation (Critical)
        for name in &[
            "eval",
            "exec",
            "compile",
            "__import__",
            "importlib.import_module",
        ] {
            sinks.push(TaintSink {
                name: name.to_string(),
                kind: TaintSinkKind::CodeEval,
                node_id: 0,
            });
        }

        // File Operations (Path Traversal)
        for name in &[
            "open",
            "file",
            "os.open",
            "io.open",
            "codecs.open",
            "Path",
            "pathlib.Path",
            "os.path.join",
            "os.makedirs",
            "os.mkdir",
            "os.remove",
            "os.unlink",
            "os.rename",
            "shutil.copy",
            "shutil.move",
            "shutil.rmtree",
        ] {
            sinks.push(TaintSink {
                name: name.to_string(),
                kind: TaintSinkKind::FileWrite,
                node_id: 0,
            });
        }

        // XSS/HTML Output
        // Note: Markup is NOT a sink - markupsafe.escape() returns Markup which is safe
        // mark_safe is a Django function that marks untrusted input as safe WITHOUT escaping
        for name in &[
            "render_template_string",
            "mark_safe",
            "format_html",
            "innerHTML",
            "write",
            "response.write",
        ] {
            sinks.push(TaintSink {
                name: name.to_string(),
                kind: TaintSinkKind::HtmlOutput,
                node_id: 0,
            });
        }

        // LDAP Injection
        for name in &[
            "search_s",
            "search",
            "search_ext",
            "ldap.search",
            "connection.search",
        ] {
            sinks.push(TaintSink {
                name: name.to_string(),
                kind: TaintSinkKind::CodeEval,  // Using CodeEval as closest match
                node_id: 0,
            });
        }

        // XPath Injection
        for name in &[
            "xpath",
            "find",
            "findall",
            "findtext",
            "iterfind",
            "lxml.etree.XPath",
            "etree.xpath",
            "root.xpath",
        ] {
            sinks.push(TaintSink {
                name: name.to_string(),
                kind: TaintSinkKind::CodeEval,  // Using CodeEval as closest match
                node_id: 0,
            });
        }

        // Deserialization (Critical)
        for name in &[
            "pickle.loads",
            "pickle.load",
            "cPickle.loads",
            "cPickle.load",
            "yaml.load",
            "yaml.unsafe_load",
            "marshal.loads",
            "shelve.open",
        ] {
            sinks.push(TaintSink {
                name: name.to_string(),
                kind: TaintSinkKind::CodeEval,
                node_id: 0,
            });
        }

        // Network/SSRF
        for name in &[
            "urllib.request.urlopen",
            "requests.get",
            "requests.post",
            "requests.put",
            "requests.delete",
            "httpx.get",
            "aiohttp.ClientSession.get",
        ] {
            sinks.push(TaintSink {
                name: name.to_string(),
                kind: TaintSinkKind::NetworkSend,
                node_id: 0,
            });
        }

        // Logging (Information Disclosure)
        for name in &[
            "print",
            "logging.info",
            "logging.debug",
            "logging.warning",
            "logging.error",
            "logger.info",
            "logger.debug",
        ] {
            sinks.push(TaintSink {
                name: name.to_string(),
                kind: TaintSinkKind::LogOutput,
                node_id: 0,
            });
        }

        // ===== SANITIZERS =====
        sanitizers.extend(vec![
            // HTML Escaping
            "escape".to_string(),
            "html.escape".to_string(),
            "cgi.escape".to_string(),
            "markupsafe.escape".to_string(),
            "bleach.clean".to_string(),
            // Shell Escaping
            "shlex.quote".to_string(),
            "pipes.quote".to_string(),
            // SQL Parameterization indicators
            "?".to_string(),
            "%s".to_string(),
            // Type Coercion
            "int".to_string(),
            "float".to_string(),
            "str".to_string(),
            // Validation
            "validate".to_string(),
            "is_safe".to_string(),
        ]);

        Self {
            language: Language::Python,
            sources,
            sinks,
            sanitizers,
        }
    }

    /// Java configuration (comprehensive)
    fn java_config() -> Self {
        let mut sources = Vec::new();
        let mut sinks = Vec::new();
        let mut sanitizers = Vec::new();

        // ===== TAINT SOURCES (40+) =====

        // User Input - Servlet API (javax.servlet.ServletRequest)
        for name in &[
            // Core parameter methods
            "getParameter",
            "getParameterValues",
            "getParameterMap",
            "getParameterNames",
            "request.getParameter",
            "request.getParameterValues",
            "request.getParameterMap",
            "request.getParameterNames",
            // Request body
            "getInputStream",
            "getReader",
            "request.getInputStream",
            "request.getReader",
            // ServletRequest qualified names
            "ServletRequest.getParameter",
            "ServletRequest.getParameterValues",
            "ServletRequest.getParameterMap",
            "ServletRequest.getParameterNames",
            "ServletRequest.getInputStream",
            "ServletRequest.getReader",
        ] {
            sources.push(TaintSource {
                name: name.to_string(),
                kind: TaintSourceKind::UserInput,
                node_id: 0,
            });
        }

        // User Input - HTTP Servlet API (javax.servlet.http.HttpServletRequest)
        for name in &[
            // Headers
            "getHeader",
            "getHeaders",
            "getHeaderNames",
            "request.getHeader",
            "request.getHeaders",
            "request.getHeaderNames",
            "HttpServletRequest.getHeader",
            "HttpServletRequest.getHeaders",
            "HttpServletRequest.getHeaderNames",
            // URL/Path
            "getQueryString",
            "getPathInfo",
            "getRequestURI",
            "getRequestURL",
            "getServletPath",
            "request.getQueryString",
            "request.getPathInfo",
            "request.getRequestURI",
            "request.getRequestURL",
            "HttpServletRequest.getQueryString",
            "HttpServletRequest.getPathInfo",
            "HttpServletRequest.getRequestURI",
            "HttpServletRequest.getRequestURL",
            // User info
            "getRemoteUser",
            "request.getRemoteUser",
            "HttpServletRequest.getRemoteUser",
        ] {
            sources.push(TaintSource {
                name: name.to_string(),
                kind: TaintSourceKind::UserInput,
                node_id: 0,
            });
        }

        // User Input - Cookies (javax.servlet.http.Cookie)
        for name in &[
            "Cookie.getValue",
            "Cookie.getName",
            "Cookie.getComment",
            "cookie.getValue",
            "cookie.getName",
            "getCookies",
            "request.getCookies",
        ] {
            sources.push(TaintSource {
                name: name.to_string(),
                kind: TaintSourceKind::UserInput,
                node_id: 0,
            });
        }

        // User Input - Spring Framework
        for name in &[
            "@RequestParam",
            "@PathVariable",
            "@RequestBody",
            "@RequestHeader",
            "RequestParam",
            "PathVariable",
        ] {
            sources.push(TaintSource {
                name: name.to_string(),
                kind: TaintSourceKind::UserInput,
                node_id: 0,
            });
        }

        // File Read - only match read operations, not constructors
        // FileInputStream and FileReader constructors are SINKS (for path traversal),
        // while their read operations are SOURCES (for file read vulnerabilities)
        for name in &[
            "Files.readString",
            "Files.readAllLines",
            "Files.readAllBytes",
            "BufferedReader.readLine",
            "Scanner.nextLine",
            "FileInputStream.read",   // Actual read operation
            "FileReader.read",        // Actual read operation
            "InputStreamReader.read", // Actual read operation
        ] {
            sources.push(TaintSource {
                name: name.to_string(),
                kind: TaintSourceKind::FileRead,
                node_id: 0,
            });
        }

        // Environment Variables (note: System.getProperty returns system-controlled
        // properties like "user.dir", "os.name", etc. which are NOT user input)
        for name in &["System.getenv"] {
            sources.push(TaintSource {
                name: name.to_string(),
                kind: TaintSourceKind::EnvironmentVariable,
                node_id: 0,
            });
        }

        // Network/HTTP
        for name in &[
            "URL.openStream",
            "HttpURLConnection.getInputStream",
            "HttpClient.send",
        ] {
            sources.push(TaintSource {
                name: name.to_string(),
                kind: TaintSourceKind::NetworkRequest,
                node_id: 0,
            });
        }

        // Database Query Results
        for name in &["ResultSet.getString", "ResultSet.getObject"] {
            sources.push(TaintSource {
                name: name.to_string(),
                kind: TaintSourceKind::DatabaseQuery,
                node_id: 0,
            });
        }

        // ===== TAINT SINKS (25+) =====

        // Command Execution
        for name in &[
            // java.lang.Runtime
            "Runtime.exec",
            "Runtime.getRuntime().exec",
            "runtime.exec",
            "getRuntime().exec",
            // java.lang.ProcessBuilder
            "ProcessBuilder",
            "ProcessBuilder.command",
            "ProcessBuilder.start",
            "new ProcessBuilder",
            "processBuilder.command",
            // Apache Commons Exec
            "CommandLine.parse",
            "CommandLine.addArguments",
            "Executor.execute",
            "DefaultExecutor.execute",
            // Spring ProcessBuilder
            "ProcessBuilder.directory",
        ] {
            sinks.push(TaintSink {
                name: name.to_string(),
                kind: TaintSinkKind::CommandExecution,
                node_id: 0,
            });
        }

        // Code Evaluation (Reflection)
        for name in &[
            "Class.forName",
            "Method.invoke",
            "Constructor.newInstance",
            "ScriptEngine.eval",
            "ScriptEngineManager.eval",
        ] {
            sinks.push(TaintSink {
                name: name.to_string(),
                kind: TaintSinkKind::CodeEval,
                node_id: 0,
            });
        }

        // XPath Injection (javax.xml.xpath)
        for name in &[
            // XPath compilation and evaluation
            "XPath.compile",
            "XPath.evaluate",
            "xp.compile",
            "xp.evaluate",
            "xpath.compile",
            "xpath.evaluate",
            "XPathExpression.evaluate",
            // XPath factory
            "XPathFactory.newXPath",
        ] {
            sinks.push(TaintSink {
                name: name.to_string(),
                kind: TaintSinkKind::CodeEval, // Using CodeEval as closest match
                node_id: 0,
            });
        }

        // LDAP Injection (javax.naming)
        for name in &[
            "DirContext.search",
            "InitialDirContext.search",
            "LdapContext.search",
            "ctx.search",
            "dirContext.search",
        ] {
            sinks.push(TaintSink {
                name: name.to_string(),
                kind: TaintSinkKind::CodeEval, // Using CodeEval as closest match
                node_id: 0,
            });
        }

        // SQL Injection
        for name in &[
            // java.sql.Statement (all execute methods)
            "Statement.execute",
            "Statement.executeQuery",
            "Statement.executeUpdate",
            "Statement.executeLargeUpdate",
            "Statement.addBatch",
            "execute",
            "executeQuery",
            "executeUpdate",
            "executeLargeUpdate",
            "addBatch",
            // java.sql.Connection (prepared statement creation)
            "Connection.prepareStatement",
            "Connection.prepareCall",
            "Connection.createStatement",
            "Connection.nativeSQL",
            "prepareStatement",
            "prepareCall",
            "createStatement",
            "nativeSQL",
            "conn.prepareStatement",
            "conn.prepareCall",
            // Spring JdbcTemplate
            "JdbcTemplate.execute",
            "JdbcTemplate.query",
            "JdbcTemplate.queryForObject",
            "JdbcTemplate.queryForList",
            "JdbcTemplate.queryForMap",
            "JdbcTemplate.update",
            "JdbcTemplate.batchUpdate",
            // JPA/Hibernate EntityManager
            "EntityManager.createQuery",
            "EntityManager.createNativeQuery",
            "createQuery",
            "createNativeQuery",
            // MyBatis
            "SqlSession.selectOne",
            "SqlSession.selectList",
            "SqlSession.selectMap",
            "SqlSession.insert",
            "SqlSession.update",
            "SqlSession.delete",
        ] {
            sinks.push(TaintSink {
                name: name.to_string(),
                kind: TaintSinkKind::SqlQuery,
                node_id: 0,
            });
        }

        // File Write
        for name in &[
            "Files.write",
            "Files.writeString",
            "FileOutputStream.write",
            "FileWriter.write",
            "PrintWriter.write",
            "BufferedWriter.write",
        ] {
            sinks.push(TaintSink {
                name: name.to_string(),
                kind: TaintSinkKind::FileWrite,
                node_id: 0,
            });
        }

        // Path Traversal - file operations with user-controlled paths
        for name in &[
            // java.io.File constructors and methods
            "new File",
            "File",
            "java.io.File",
            "new java.io.File",
            // java.io streams (when path is tainted)
            "FileInputStream",
            "new FileInputStream",
            "java.io.FileInputStream",
            "new java.io.FileInputStream",
            "FileOutputStream",
            "new FileOutputStream",
            "java.io.FileOutputStream",
            "new java.io.FileOutputStream",
            "FileReader",
            "new FileReader",
            "java.io.FileReader",
            "FileWriter",
            "new FileWriter",
            "java.io.FileWriter",
            "RandomAccessFile",
            "new RandomAccessFile",
            // java.nio.file operations
            "Paths.get",
            "Path.of",
            "Files.readAllBytes",
            "Files.readAllLines",
            "Files.readString",
            "Files.newInputStream",
            "Files.newOutputStream",
            "Files.newBufferedReader",
            "Files.newBufferedWriter",
            "Files.copy",
            "Files.move",
            "Files.delete",
            "Files.createFile",
            "Files.createDirectory",
            "Files.createDirectories",
            "Files.exists",
            "Files.isReadable",
            "Files.isWritable",
            "Files.list",
            "Files.walk",
            // Apache Commons IO
            "FileUtils.readFileToString",
            "FileUtils.readLines",
            "FileUtils.writeStringToFile",
            "FileUtils.copyFile",
            // Spring ResourceLoader
            "getResource",
            "ResourceLoader.getResource",
        ] {
            sinks.push(TaintSink {
                name: name.to_string(),
                kind: TaintSinkKind::PathTraversal,
                node_id: 0,
            });
        }

        // HTML/XSS Output
        for name in &[
            "response.getWriter().write",
            "PrintWriter.println",
            "ServletOutputStream.print",
            "HttpServletResponse.getWriter",
        ] {
            sinks.push(TaintSink {
                name: name.to_string(),
                kind: TaintSinkKind::HtmlOutput,
                node_id: 0,
            });
        }

        // Logging (Information Disclosure)
        for name in &[
            "System.out.println",
            "logger.info",
            "logger.debug",
            "logger.error",
            "log.info",
        ] {
            sinks.push(TaintSink {
                name: name.to_string(),
                kind: TaintSinkKind::LogOutput,
                node_id: 0,
            });
        }

        // XSS/HTML Output (response writers)
        for name in &[
            // HttpServletResponse
            "response.getWriter",
            "getWriter",
            "response.getOutputStream",
            "getOutputStream",
            // PrintWriter methods
            "PrintWriter.print",
            "PrintWriter.println",
            "PrintWriter.write",
            "PrintWriter.format",
            "PrintWriter.printf",
            "PrintWriter.append",
            "writer.print",
            "writer.println",
            "writer.write",
            "writer.format",
            "writer.printf",
            "writer.append",
            // Format methods on response writer
            "format",
            "printf",
            // JSP implicit objects
            "out.print",
            "out.println",
            "out.write",
            "out.format",
            "out.printf",
            // Direct response
            "response.sendRedirect",
            "sendRedirect",
        ] {
            sinks.push(TaintSink {
                name: name.to_string(),
                kind: TaintSinkKind::HtmlOutput,
                node_id: 0,
            });
        }

        // Path Traversal
        for name in &[
            // File operations
            "new File",
            "File",
            "Paths.get",
            "Path.of",
            "FileInputStream",
            "FileOutputStream",
            "FileReader",
            "FileWriter",
            // NIO
            "Files.readAllBytes",
            "Files.readString",
            "Files.write",
            "Files.newInputStream",
            "Files.newOutputStream",
            // Servlet context
            "getResourceAsStream",
            "getRealPath",
        ] {
            sinks.push(TaintSink {
                name: name.to_string(),
                kind: TaintSinkKind::FileWrite, // Using FileWrite as closest match for path traversal
                node_id: 0,
            });
        }

        // Trust Boundary - storing user data in trusted contexts (session, context)
        for name in &[
            // HttpSession methods (Java)
            "HttpSession.setAttribute",
            "session.setAttribute",
            "getSession().setAttribute",
            "request.getSession().setAttribute",
            // HttpSession.putValue (deprecated but still used)
            "HttpSession.putValue",
            "session.putValue",
            "getSession().putValue",
            "request.getSession().putValue",
            // Servlet context
            "ServletContext.setAttribute",
            "context.setAttribute",
            "getServletContext().setAttribute",
            // Portlet session
            "PortletSession.setAttribute",
            // Request attributes (can cross trust boundary)
            "request.setAttribute",
            // Python Flask session (subscript assignment sink)
            "flask.session",
            "session",
            // Django session
            "request.session",
            // Express.js session (Node.js)
            "req.session",
            "res.locals",  // Express locals can cross trust boundary
        ] {
            sinks.push(TaintSink {
                name: name.to_string(),
                kind: TaintSinkKind::TrustBoundary,
                node_id: 0,
            });
        }

        // XML Parsing - XXE sinks (untrusted XML input to parser)
        for name in &[
            // JavaScript/Node.js XML parsing
            "parseFromString",           // DOMParser.parseFromString
            "parser.parseFromString",    // xmldom DOMParser
            "parseXml",                  // various XML libraries
            "parseXmlString",            // libxmljs
            "xml2js.parseString",        // xml2js
            "xml2js.Parser.parseString",
            // Java XML parsing (already have some in Java config)
            "DocumentBuilder.parse",
            "SAXParser.parse",
            "XMLReader.parse",
            "Unmarshaller.unmarshal",
        ] {
            sinks.push(TaintSink {
                name: name.to_string(),
                kind: TaintSinkKind::XmlParse,
                node_id: 0,
            });
        }

        // ===== SANITIZERS (12+) =====
        sanitizers.extend(vec![
            // HTML Escaping
            "StringEscapeUtils.escapeHtml4".to_string(),
            "StringEscapeUtils.escapeHtml".to_string(),
            "HtmlUtils.htmlEscape".to_string(),
            "ESAPI.encoder().encodeForHTML".to_string(),
            // SQL Escaping
            "ESAPI.encoder().encodeForSQL".to_string(),
            "PreparedStatement.setString".to_string(),
            "PreparedStatement.setInt".to_string(),
            // Command Escaping
            "StringEscapeUtils.escapeJava".to_string(),
            // Validation
            "Validator.isValid".to_string(),
            "validate".to_string(),
            // Spring Security
            "HtmlUtils.htmlEscapeDecimal".to_string(),
            "UriUtils.encode".to_string(),
        ]);

        Self {
            language: Language::Java,
            sources,
            sinks,
            sanitizers,
        }
    }

    /// Go configuration (comprehensive)
    fn go_config() -> Self {
        let mut sources = Vec::new();
        let mut sinks = Vec::new();
        let mut sanitizers = Vec::new();

        // ===== TAINT SOURCES (18+) =====

        // User Input - Command Line
        for name in &["os.Args", "flag.String", "flag.Int"] {
            sources.push(TaintSource {
                name: name.to_string(),
                kind: TaintSourceKind::UserInput,
                node_id: 0,
            });
        }

        // User Input - HTTP (net/http)
        for name in &[
            "r.FormValue",
            "r.URL.Query",
            "r.URL.Query().Get",
            "r.PostFormValue",
            "r.Header.Get",
            "r.Cookie",
            "r.Body",
        ] {
            sources.push(TaintSource {
                name: name.to_string(),
                kind: TaintSourceKind::UserInput,
                node_id: 0,
            });
        }

        // User Input - Gin Framework
        for name in &[
            "c.Query",
            "c.Param",
            "c.PostForm",
            "c.GetHeader",
            "c.Cookie",
            "gin.Context.Query",
            "gin.Context.Param",
        ] {
            sources.push(TaintSource {
                name: name.to_string(),
                kind: TaintSourceKind::UserInput,
                node_id: 0,
            });
        }

        // File Read
        for name in &[
            "os.ReadFile",
            "ioutil.ReadFile",
            "os.Open",
            "bufio.NewReader",
        ] {
            sources.push(TaintSource {
                name: name.to_string(),
                kind: TaintSourceKind::FileRead,
                node_id: 0,
            });
        }

        // Environment Variables
        for name in &["os.Getenv", "os.LookupEnv"] {
            sources.push(TaintSource {
                name: name.to_string(),
                kind: TaintSourceKind::EnvironmentVariable,
                node_id: 0,
            });
        }

        // Network/HTTP
        for name in &["http.Get", "http.Client.Get", "ioutil.ReadAll"] {
            sources.push(TaintSource {
                name: name.to_string(),
                kind: TaintSourceKind::NetworkRequest,
                node_id: 0,
            });
        }

        // ===== TAINT SINKS (20+) =====

        // Command Execution
        for name in &[
            "exec.Command",
            "exec.CommandContext",
            "os/exec.Command",
            "syscall.Exec",
        ] {
            sinks.push(TaintSink {
                name: name.to_string(),
                kind: TaintSinkKind::CommandExecution,
                node_id: 0,
            });
        }

        // SQL Injection
        for name in &[
            "db.Exec",
            "db.Query",
            "db.QueryRow",
            "tx.Exec",
            "tx.Query",
            "database/sql.DB.Exec",
            "database/sql.DB.Query",
        ] {
            sinks.push(TaintSink {
                name: name.to_string(),
                kind: TaintSinkKind::SqlQuery,
                node_id: 0,
            });
        }

        // File Write
        for name in &[
            "os.WriteFile",
            "ioutil.WriteFile",
            "os.Create",
            "os.OpenFile",
            "fmt.Fprintf",
        ] {
            sinks.push(TaintSink {
                name: name.to_string(),
                kind: TaintSinkKind::FileWrite,
                node_id: 0,
            });
        }

        // HTML/XSS Output
        for name in &[
            "fmt.Fprintf",
            "w.Write",
            "io.WriteString",
            "c.String",
            "c.HTML",
            "gin.Context.String",
        ] {
            sinks.push(TaintSink {
                name: name.to_string(),
                kind: TaintSinkKind::HtmlOutput,
                node_id: 0,
            });
        }

        // Logging (Information Disclosure)
        for name in &[
            "log.Println",
            "log.Printf",
            "fmt.Println",
            "fmt.Printf",
        ] {
            sinks.push(TaintSink {
                name: name.to_string(),
                kind: TaintSinkKind::LogOutput,
                node_id: 0,
            });
        }

        // ===== SANITIZERS (11+) =====
        sanitizers.extend(vec![
            // HTML Escaping
            "html.EscapeString".to_string(),
            "template.HTMLEscapeString".to_string(),
            "template.JSEscapeString".to_string(),
            "template.URLQueryEscaper".to_string(),
            // SQL Escaping (use prepared statements)
            "db.Prepare".to_string(),
            "sql.DB.Prepare".to_string(),
            // Command Escaping
            "shellescape.Quote".to_string(),
            // Validation
            "strconv.Atoi".to_string(),
            "strconv.ParseInt".to_string(),
            "strconv.ParseFloat".to_string(),
            // URL Encoding
            "url.QueryEscape".to_string(),
        ]);

        Self {
            language: Language::Go,
            sources,
            sinks,
            sanitizers,
        }
    }

    /// C# configuration
    fn csharp_config() -> Self {
        let mut sources = Vec::new();
        let mut sinks = Vec::new();
        let mut sanitizers = Vec::new();

        // User Input
        for name in &["Request.QueryString", "Request.Form", "Console.ReadLine"] {
            sources.push(TaintSource {
                name: name.to_string(),
                kind: TaintSourceKind::UserInput,
                node_id: 0,
            });
        }

        // Command Execution
        for name in &["Process.Start", "System.Diagnostics.Process.Start"] {
            sinks.push(TaintSink {
                name: name.to_string(),
                kind: TaintSinkKind::CommandExecution,
                node_id: 0,
            });
        }

        sanitizers.extend(vec![
            "HttpUtility.HtmlEncode".to_string(),
            "AntiXssEncoder.HtmlEncode".to_string(),
        ]);

        Self {
            language: Language::CSharp,
            sources,
            sinks,
            sanitizers,
        }
    }

    /// Swift configuration (comprehensive)
    fn swift_config() -> Self {
        let mut sources = Vec::new();
        let mut sinks = Vec::new();
        let mut sanitizers = Vec::new();

        // ===== TAINT SOURCES (17+) =====

        // User Input - Command Line
        for name in &["CommandLine.arguments", "ProcessInfo.processInfo.arguments"] {
            sources.push(TaintSource {
                name: name.to_string(),
                kind: TaintSourceKind::UserInput,
                node_id: 0,
            });
        }

        // User Input - Network (URLSession, Alamofire)
        for name in &[
            "URLRequest",
            "URLComponents.queryItems",
            "URLSession.dataTask",
            "request.url",
            "request.allHTTPHeaderFields",
        ] {
            sources.push(TaintSource {
                name: name.to_string(),
                kind: TaintSourceKind::UserInput,
                node_id: 0,
            });
        }

        // File Read
        for name in &[
            "String(contentsOfFile:)",
            "String(contentsOf:)",
            "Data(contentsOf:)",
            "FileManager.contents",
            "FileHandle.readDataToEndOfFile",
            "try String(contentsOfFile:)",
        ] {
            sources.push(TaintSource {
                name: name.to_string(),
                kind: TaintSourceKind::FileRead,
                node_id: 0,
            });
        }

        // Environment Variables
        for name in &[
            "ProcessInfo.processInfo.environment",
            "getenv",
            "ProcessInfo.environment",
        ] {
            sources.push(TaintSource {
                name: name.to_string(),
                kind: TaintSourceKind::EnvironmentVariable,
                node_id: 0,
            });
        }

        // User Defaults (can be manipulated)
        for name in &["UserDefaults.standard.string", "UserDefaults.standard.object"] {
            sources.push(TaintSource {
                name: name.to_string(),
                kind: TaintSourceKind::UserInput,
                node_id: 0,
            });
        }

        // Database (CoreData, SQLite)
        for name in &["sqlite3_column_text", "NSFetchRequest.execute"] {
            sources.push(TaintSource {
                name: name.to_string(),
                kind: TaintSourceKind::DatabaseQuery,
                node_id: 0,
            });
        }

        // ===== TAINT SINKS (18+) =====

        // Command Execution
        for name in &[
            "Process",
            "NSTask",
            "Process.launch",
            "Process.run",
            "system",
            "popen",
        ] {
            sinks.push(TaintSink {
                name: name.to_string(),
                kind: TaintSinkKind::CommandExecution,
                node_id: 0,
            });
        }

        // SQL Injection
        for name in &[
            "sqlite3_exec",
            "sqlite3_prepare",
            "sqlite3_prepare_v2",
            "executeQuery",
            "executeUpdate",
        ] {
            sinks.push(TaintSink {
                name: name.to_string(),
                kind: TaintSinkKind::SqlQuery,
                node_id: 0,
            });
        }

        // File Write
        for name in &[
            "write(to:)",
            "write(toFile:)",
            "FileManager.createFile",
            "Data.write",
            "String.write",
        ] {
            sinks.push(TaintSink {
                name: name.to_string(),
                kind: TaintSinkKind::FileWrite,
                node_id: 0,
            });
        }

        // HTML/XSS Output (WKWebView, UIWebView)
        for name in &[
            "WKWebView.loadHTMLString",
            "UIWebView.loadHTMLString",
            "webView.loadHTMLString",
            "evaluateJavaScript",
        ] {
            sinks.push(TaintSink {
                name: name.to_string(),
                kind: TaintSinkKind::HtmlOutput,
                node_id: 0,
            });
        }

        // Logging (Information Disclosure)
        for name in &["print", "NSLog", "os_log", "Logger.log"] {
            sinks.push(TaintSink {
                name: name.to_string(),
                kind: TaintSinkKind::LogOutput,
                node_id: 0,
            });
        }

        // ===== SANITIZERS (10+) =====
        sanitizers.extend(vec![
            // HTML Escaping
            "addingPercentEncoding".to_string(),
            "stringByAddingPercentEncoding".to_string(),
            // SQL Escaping (use prepared statements)
            "sqlite3_bind_text".to_string(),
            "sqlite3_bind_int".to_string(),
            // Validation
            "Int()".to_string(),
            "Double()".to_string(),
            "UUID(uuidString:)".to_string(),
            // URL Encoding
            "URLComponents".to_string(),
            "CharacterSet.urlQueryAllowed".to_string(),
            "escapedString".to_string(),
        ]);

        Self {
            language: Language::Swift,
            sources,
            sinks,
            sanitizers,
        }
    }

    /// Rust configuration (comprehensive)
    fn rust_config() -> Self {
        let mut sources = Vec::new();
        let mut sinks = Vec::new();
        let mut sanitizers = Vec::new();

        // ===== TAINT SOURCES (15+) =====

        // User Input - Command Line
        for name in &[
            "std::env::args",
            "std::env::args_os",
            "env::args",
            "args",
        ] {
            sources.push(TaintSource {
                name: name.to_string(),
                kind: TaintSourceKind::UserInput,
                node_id: 0,
            });
        }

        // User Input - HTTP (actix-web, rocket, warp)
        for name in &[
            "HttpRequest.query_string",
            "HttpRequest.match_info",
            "req.param",
            "req.query",
            "Query",
            "Path",
            "Form",
        ] {
            sources.push(TaintSource {
                name: name.to_string(),
                kind: TaintSourceKind::UserInput,
                node_id: 0,
            });
        }

        // File Read
        for name in &[
            "std::fs::read_to_string",
            "std::fs::read",
            "File::open",
            "read_to_string",
            "read_line",
        ] {
            sources.push(TaintSource {
                name: name.to_string(),
                kind: TaintSourceKind::FileRead,
                node_id: 0,
            });
        }

        // Environment Variables
        for name in &["std::env::var", "std::env::var_os", "env::var"] {
            sources.push(TaintSource {
                name: name.to_string(),
                kind: TaintSourceKind::EnvironmentVariable,
                node_id: 0,
            });
        }

        // Network/HTTP
        for name in &[
            "reqwest::get",
            "reqwest::Client::get",
            "hyper::Client::get",
        ] {
            sources.push(TaintSource {
                name: name.to_string(),
                kind: TaintSourceKind::NetworkRequest,
                node_id: 0,
            });
        }

        // Standard Input
        for name in &["std::io::stdin", "stdin", "io::stdin().read_line"] {
            sources.push(TaintSource {
                name: name.to_string(),
                kind: TaintSourceKind::UserInput,
                node_id: 0,
            });
        }

        // ===== TAINT SINKS (16+) =====

        // Command Execution
        for name in &[
            "std::process::Command",
            "Command::new",
            "Command.spawn",
            "Command.output",
            "process::Command",
        ] {
            sinks.push(TaintSink {
                name: name.to_string(),
                kind: TaintSinkKind::CommandExecution,
                node_id: 0,
            });
        }

        // SQL Injection (rusqlite, diesel, sqlx)
        for name in &[
            "rusqlite::Connection::execute",
            "Connection::execute",
            "execute",
            "query",
            "sqlx::query",
            "diesel::sql_query",
        ] {
            sinks.push(TaintSink {
                name: name.to_string(),
                kind: TaintSinkKind::SqlQuery,
                node_id: 0,
            });
        }

        // File Write
        for name in &[
            "std::fs::write",
            "File::create",
            "OpenOptions::new",
            "write_all",
            "write",
        ] {
            sinks.push(TaintSink {
                name: name.to_string(),
                kind: TaintSinkKind::FileWrite,
                node_id: 0,
            });
        }

        // Logging (Information Disclosure)
        for name in &["println!", "eprintln!", "log::info", "log::debug"] {
            sinks.push(TaintSink {
                name: name.to_string(),
                kind: TaintSinkKind::LogOutput,
                node_id: 0,
            });
        }

        // ===== SANITIZERS (10+) =====
        sanitizers.extend(vec![
            // HTML Escaping
            "html_escape::encode_text".to_string(),
            "askama::escape".to_string(),
            // SQL Escaping (use prepared statements)
            "execute_named".to_string(),
            "query_as".to_string(),
            "sqlx::query!".to_string(),
            // Validation
            "str::parse".to_string(),
            "from_str".to_string(),
            "String::from_utf8".to_string(),
            // Path sanitization
            "Path::new".to_string(),
            "PathBuf::from".to_string(),
        ]);

        Self {
            language: Language::Rust,
            sources,
            sinks,
            sanitizers,
        }
    }

    /// Lua configuration (comprehensive)
    fn lua_config() -> Self {
        let mut sources = Vec::new();
        let mut sinks = Vec::new();
        let mut sanitizers = Vec::new();

        // ===== TAINT SOURCES (20+) =====

        // User Input - Command Line & Standard Input
        for name in &[
            "arg",              // Command line arguments table
            "io.read",          // Read from stdin
            "io.stdin:read",
            "io.input():read",
        ] {
            sources.push(TaintSource {
                name: name.to_string(),
                kind: TaintSourceKind::UserInput,
                node_id: 0,
            });
        }

        // User Input - HTTP/Web (OpenResty, Lapis, Lua-Resty)
        for name in &[
            "ngx.req.get_uri_args",
            "ngx.req.get_post_args",
            "ngx.req.get_headers",
            "ngx.req.get_body_data",
            "ngx.req.read_body",
            "ngx.var",
            "request.params",
            "self.params",
        ] {
            sources.push(TaintSource {
                name: name.to_string(),
                kind: TaintSourceKind::UserInput,
                node_id: 0,
            });
        }

        // File Read
        for name in &[
            "io.open",
            "io.input",
            "io.lines",
            "file:read",
            "file:lines",
            "io.read",
        ] {
            sources.push(TaintSource {
                name: name.to_string(),
                kind: TaintSourceKind::FileRead,
                node_id: 0,
            });
        }

        // Environment Variables
        for name in &[
            "os.getenv",
        ] {
            sources.push(TaintSource {
                name: name.to_string(),
                kind: TaintSourceKind::EnvironmentVariable,
                node_id: 0,
            });
        }

        // Network/HTTP (LuaSocket, lua-resty-http)
        for name in &[
            "socket.http.request",
            "http.request",
            "httpc:request_uri",
            "ngx.location.capture",
            "ngx.socket.tcp",
        ] {
            sources.push(TaintSource {
                name: name.to_string(),
                kind: TaintSourceKind::NetworkRequest,
                node_id: 0,
            });
        }

        // Database Query Results (LuaSQL, pgmoon, lua-resty-mysql)
        for name in &[
            "cursor:fetch",
            "conn:execute",
            "db:query",
            "mysql:query",
            "pg:query",
            "redis:get",
        ] {
            sources.push(TaintSource {
                name: name.to_string(),
                kind: TaintSourceKind::DatabaseQuery,
                node_id: 0,
            });
        }

        // Debug/Reflection (dangerous sources)
        for name in &[
            "debug.getlocal",
            "debug.getupvalue",
            "debug.getinfo",
            "debug.getregistry",
        ] {
            sources.push(TaintSource {
                name: name.to_string(),
                kind: TaintSourceKind::UserInput,
                node_id: 0,
            });
        }

        // ===== TAINT SINKS (25+) =====

        // Command Execution
        for name in &[
            "os.execute",
            "io.popen",
            "os.spawn",
        ] {
            sinks.push(TaintSink {
                name: name.to_string(),
                kind: TaintSinkKind::CommandExecution,
                node_id: 0,
            });
        }

        // Code Evaluation (Critical - Lua's most dangerous functions)
        for name in &[
            "load",
            "loadstring",
            "loadfile",
            "dofile",
            "require",          // Can load arbitrary modules
            "package.loadlib",
            "setfenv",
            "rawset",
            "rawget",
            "setmetatable",     // Can override behavior
            "debug.setlocal",
            "debug.setupvalue",
            "debug.sethook",
            "debug.setmetatable",
        ] {
            sinks.push(TaintSink {
                name: name.to_string(),
                kind: TaintSinkKind::CodeEval,
                node_id: 0,
            });
        }

        // SQL Injection (LuaSQL, pgmoon, lua-resty-mysql)
        for name in &[
            "conn:execute",
            "cursor:execute",
            "db:query",
            "mysql:query",
            "pg:query",
            "ngx.quote_sql_str",
        ] {
            sinks.push(TaintSink {
                name: name.to_string(),
                kind: TaintSinkKind::SqlQuery,
                node_id: 0,
            });
        }

        // File Write
        for name in &[
            "io.open",          // With write mode
            "io.output",
            "file:write",
            "io.write",
            "os.rename",
            "os.remove",
        ] {
            sinks.push(TaintSink {
                name: name.to_string(),
                kind: TaintSinkKind::FileWrite,
                node_id: 0,
            });
        }

        // HTML/XSS Output (OpenResty/nginx-lua)
        for name in &[
            "ngx.say",
            "ngx.print",
            "ngx.header",
            "ngx.redirect",
            "io.write",
            "print",
        ] {
            sinks.push(TaintSink {
                name: name.to_string(),
                kind: TaintSinkKind::HtmlOutput,
                node_id: 0,
            });
        }

        // Logging (Information Disclosure)
        for name in &[
            "print",
            "io.write",
            "ngx.log",
            "ngx.ERR",
            "ngx.WARN",
        ] {
            sinks.push(TaintSink {
                name: name.to_string(),
                kind: TaintSinkKind::LogOutput,
                node_id: 0,
            });
        }

        // ===== SANITIZERS (12+) =====
        sanitizers.extend(vec![
            // HTML/URL Escaping
            "ngx.escape_uri".to_string(),
            "ngx.unescape_uri".to_string(),
            "ngx.encode_base64".to_string(),
            "ngx.quote_sql_str".to_string(),
            // String validation
            "tonumber".to_string(),
            "tostring".to_string(),
            "string.match".to_string(),     // When used for validation
            "string.gsub".to_string(),      // When used for sanitization
            // Type checking
            "type".to_string(),
            "assert".to_string(),
            // Custom sanitizers
            "escape".to_string(),
            "sanitize".to_string(),
            "validate".to_string(),
            "encode".to_string(),
        ]);

        Self {
            language: Language::Lua,
            sources,
            sinks,
            sanitizers,
        }
    }

    /// Perl-specific taint configuration
    fn perl_config() -> Self {
        let mut sources = Vec::new();
        let mut sinks = Vec::new();
        let mut sanitizers = Vec::new();

        // ============ PERL TAINT SOURCES ============

        // CGI/Web Input
        for name in &[
            "param",            // CGI.pm param()
            "Vars",             // CGI->Vars()
            "url_param",        // CGI url_param()
            "query_string",
            "path_info",
            "cookie",           // CGI cookie()
            "header",
            "request_uri",
            "remote_host",
            "remote_addr",
            "user_agent",
            "referer",
        ] {
            sources.push(TaintSource {
                name: name.to_string(),
                kind: TaintSourceKind::UserInput,
                node_id: 0,
            });
        }

        // Standard Input/File
        for name in &[
            "<STDIN>",
            "<>",               // Diamond operator
            "readline",
            "getc",
            "read",
            "<ARGV>",
            "readdir",
        ] {
            sources.push(TaintSource {
                name: name.to_string(),
                kind: TaintSourceKind::UserInput,
                node_id: 0,
            });
        }

        // Environment
        for name in &[
            "%ENV",
            "$ENV",
            "getenv",
        ] {
            sources.push(TaintSource {
                name: name.to_string(),
                kind: TaintSourceKind::EnvironmentVariable,
                node_id: 0,
            });
        }

        // Database Results (DBI)
        for name in &[
            "fetchrow_array",
            "fetchrow_arrayref",
            "fetchrow_hashref",
            "fetchall_arrayref",
            "fetchall_hashref",
            "selectrow_array",
            "selectrow_arrayref",
            "selectrow_hashref",
            "selectall_arrayref",
            "selectall_hashref",
            "selectcol_arrayref",
        ] {
            sources.push(TaintSource {
                name: name.to_string(),
                kind: TaintSourceKind::DatabaseQuery,
                node_id: 0,
            });
        }

        // HTTP Clients (LWP, HTTP::Tiny, Mojo)
        for name in &[
            "get",              // LWP::Simple get()
            "getprint",
            "getstore",
            "request",          // HTTP::Request
            "decoded_content",
            "content",
        ] {
            sources.push(TaintSource {
                name: name.to_string(),
                kind: TaintSourceKind::NetworkRequest,
                node_id: 0,
            });
        }

        // ============ PERL TAINT SINKS ============

        // Command Execution (Critical)
        for name in &[
            "system",
            "exec",
            "qx",               // Backticks equivalent
            "`",                // Backticks
            "open",             // Pipe open
            "open2",
            "open3",
            "IPC::Open2::open2",
            "IPC::Open3::open3",
            "readpipe",
        ] {
            sinks.push(TaintSink {
                name: name.to_string(),
                kind: TaintSinkKind::CommandExecution,
                node_id: 0,
            });
        }

        // Code Evaluation (Critical)
        for name in &[
            "eval",
            "do",               // do FILE
            "require",
            "use",
            "BEGIN",
            "INIT",
            "CHECK",
            "UNITCHECK",
            "END",
        ] {
            sinks.push(TaintSink {
                name: name.to_string(),
                kind: TaintSinkKind::CodeEval,
                node_id: 0,
            });
        }

        // SQL Injection (DBI)
        for name in &[
            "prepare",
            "do",               // DBI do()
            "execute",
            "selectrow_array",
            "selectrow_arrayref",
            "selectrow_hashref",
            "selectall_arrayref",
            "selectall_hashref",
            "selectcol_arrayref",
        ] {
            sinks.push(TaintSink {
                name: name.to_string(),
                kind: TaintSinkKind::SqlQuery,
                node_id: 0,
            });
        }

        // File Operations
        for name in &[
            "open",
            "sysopen",
            "unlink",
            "rmdir",
            "mkdir",
            "rename",
            "link",
            "symlink",
            "chmod",
            "chown",
            "truncate",
        ] {
            sinks.push(TaintSink {
                name: name.to_string(),
                kind: TaintSinkKind::FileWrite,
                node_id: 0,
            });
        }

        // XSS/HTML Output
        for name in &[
            "print",
            "say",
            "printf",
            "sprintf",
            "write",
            "header",           // CGI header
            "start_html",
            "end_html",
        ] {
            sinks.push(TaintSink {
                name: name.to_string(),
                kind: TaintSinkKind::HtmlOutput,
                node_id: 0,
            });
        }

        // Network/SSRF
        for name in &[
            "get",              // LWP::Simple
            "getprint",
            "getstore",
            "request",
            "IO::Socket::INET->new",
            "IO::Socket::SSL->new",
        ] {
            sinks.push(TaintSink {
                name: name.to_string(),
                kind: TaintSinkKind::NetworkSend,
                node_id: 0,
            });
        }

        // Deserialization (use CodeEval since it can lead to code execution)
        for name in &[
            "thaw",             // Storable
            "retrieve",         // Storable
            "fd_retrieve",
            "YAML::Load",
            "YAML::LoadFile",
            "JSON::decode_json",
            "decode_json",
            "from_json",
            "XMLin",            // XML::Simple
            "Data::Dumper",
        ] {
            sinks.push(TaintSink {
                name: name.to_string(),
                kind: TaintSinkKind::CodeEval,
                node_id: 0,
            });
        }

        // Log Injection
        for name in &[
            "warn",
            "die",
            "carp",
            "croak",
            "cluck",
            "confess",
        ] {
            sinks.push(TaintSink {
                name: name.to_string(),
                kind: TaintSinkKind::LogOutput,
                node_id: 0,
            });
        }

        // ============ PERL SANITIZERS ============

        sanitizers.extend(vec![
            // Taint-mode untainting
            "untaint".to_string(),
            // HTML/URL encoding
            "escapeHTML".to_string(),
            "escape".to_string(),
            "encode_entities".to_string(),
            "uri_escape".to_string(),
            "url_encode".to_string(),
            "CGI::escape".to_string(),
            "HTML::Entities::encode_entities".to_string(),
            "URI::Escape::uri_escape".to_string(),
            // SQL
            "quote".to_string(),        // DBI quote()
            "quote_identifier".to_string(),
            "placeholder".to_string(),
            // Validation
            "looks_like_number".to_string(),
            "defined".to_string(),
            "length".to_string(),
            // Type coercion
            "int".to_string(),
            "sprintf".to_string(),      // When used for type coercion
            // Path validation
            "abs_path".to_string(),
            "canonpath".to_string(),
            "File::Spec->canonpath".to_string(),
            "File::Spec->rel2abs".to_string(),
        ]);

        Self {
            language: Language::Perl,
            sources,
            sinks,
            sanitizers,
        }
    }

    /// Dart-specific taint configuration
    fn dart_config() -> Self {
        let mut sources = Vec::new();
        let mut sinks = Vec::new();
        let mut sanitizers = Vec::new();

        // ============ DART TAINT SOURCES ============

        // User Input - HTTP/Web (shelf, dio, http package)
        for name in &[
            "request.url",
            "request.uri",
            "request.headers",
            "request.requestedUri",
            "request.method",
            "request.read",
            "request.readAsString",
            "Uri.queryParameters",
            "Uri.queryParametersAll",
            "Uri.pathSegments",
        ] {
            sources.push(TaintSource {
                name: name.to_string(),
                kind: TaintSourceKind::UserInput,
                node_id: 0,
            });
        }

        // User Input - Flutter/Mobile
        for name in &[
            "TextEditingController.text",
            "TextField.controller",
            "TextFormField.controller",
            "FormFieldState.value",
            "SharedPreferences.getString",
            "SharedPreferences.get",
        ] {
            sources.push(TaintSource {
                name: name.to_string(),
                kind: TaintSourceKind::UserInput,
                node_id: 0,
            });
        }

        // Command Line Arguments
        for name in &[
            "args",             // main(List<String> args)
            "arguments",
        ] {
            sources.push(TaintSource {
                name: name.to_string(),
                kind: TaintSourceKind::CommandLineArgument,
                node_id: 0,
            });
        }

        // File Read
        for name in &[
            "File.readAsString",
            "File.readAsStringSync",
            "File.readAsBytes",
            "File.readAsBytesSync",
            "File.readAsLines",
            "File.readAsLinesSync",
            "File.openRead",
            "stdin.readLineSync",
            "stdin.readByteSync",
        ] {
            sources.push(TaintSource {
                name: name.to_string(),
                kind: TaintSourceKind::FileRead,
                node_id: 0,
            });
        }

        // Environment Variables
        for name in &[
            "Platform.environment",
            "Platform.environment[]",
            "String.fromEnvironment",
            "int.fromEnvironment",
            "bool.fromEnvironment",
        ] {
            sources.push(TaintSource {
                name: name.to_string(),
                kind: TaintSourceKind::EnvironmentVariable,
                node_id: 0,
            });
        }

        // Network/HTTP (dio, http package)
        for name in &[
            "http.get",
            "http.post",
            "http.read",
            "http.readBytes",
            "Dio.get",
            "Dio.post",
            "HttpClient.getUrl",
            "HttpClient.postUrl",
            "Response.body",
            "Response.bodyBytes",
        ] {
            sources.push(TaintSource {
                name: name.to_string(),
                kind: TaintSourceKind::NetworkRequest,
                node_id: 0,
            });
        }

        // Database Query Results
        for name in &[
            "Database.query",
            "Database.rawQuery",
            "sqflite.query",
            "sqflite.rawQuery",
        ] {
            sources.push(TaintSource {
                name: name.to_string(),
                kind: TaintSourceKind::DatabaseQuery,
                node_id: 0,
            });
        }

        // ============ DART TAINT SINKS ============

        // Command Execution
        for name in &[
            "Process.run",
            "Process.runSync",
            "Process.start",
            "shell",
        ] {
            sinks.push(TaintSink {
                name: name.to_string(),
                kind: TaintSinkKind::CommandExecution,
                node_id: 0,
            });
        }

        // Code Evaluation (Dart doesn't have eval, but mirrors/reflection)
        for name in &[
            "Function.apply",
            "InstanceMirror.invoke",
            "ClassMirror.invoke",
            "noSuchMethod",
        ] {
            sinks.push(TaintSink {
                name: name.to_string(),
                kind: TaintSinkKind::CodeEval,
                node_id: 0,
            });
        }

        // SQL Injection (sqflite, moor/drift)
        for name in &[
            "Database.execute",
            "Database.rawInsert",
            "Database.rawUpdate",
            "Database.rawDelete",
            "Database.rawQuery",
            "rawQuery",
            "execute",
        ] {
            sinks.push(TaintSink {
                name: name.to_string(),
                kind: TaintSinkKind::SqlQuery,
                node_id: 0,
            });
        }

        // File Write
        for name in &[
            "File.writeAsString",
            "File.writeAsStringSync",
            "File.writeAsBytes",
            "File.writeAsBytesSync",
            "File.openWrite",
            "IOSink.write",
            "IOSink.writeln",
            "File.create",
            "File.delete",
            "Directory.create",
            "Directory.delete",
        ] {
            sinks.push(TaintSink {
                name: name.to_string(),
                kind: TaintSinkKind::FileWrite,
                node_id: 0,
            });
        }

        // HTML/XSS Output (Flutter WebView, shelf responses)
        for name in &[
            "Response",
            "shelf.Response",
            "WebViewController.loadHtmlString",
            "WebView.initialUrl",
            "Html.data",
            "HtmlWidget",
            "InAppWebViewController.loadData",
        ] {
            sinks.push(TaintSink {
                name: name.to_string(),
                kind: TaintSinkKind::HtmlOutput,
                node_id: 0,
            });
        }

        // Logging (Information Disclosure)
        for name in &[
            "print",
            "debugPrint",
            "log",
            "Logger.info",
            "Logger.warning",
            "Logger.severe",
            "stdout.write",
            "stdout.writeln",
            "stderr.write",
            "stderr.writeln",
        ] {
            sinks.push(TaintSink {
                name: name.to_string(),
                kind: TaintSinkKind::LogOutput,
                node_id: 0,
            });
        }

        // Network (SSRF potential)
        for name in &[
            "http.get",
            "http.post",
            "http.put",
            "http.delete",
            "Dio.get",
            "Dio.post",
            "HttpClient.getUrl",
            "HttpClient.postUrl",
            "HttpClient.openUrl",
            "Socket.connect",
            "WebSocket.connect",
        ] {
            sinks.push(TaintSink {
                name: name.to_string(),
                kind: TaintSinkKind::NetworkSend,
                node_id: 0,
            });
        }

        // URL/Redirect (using NetworkSend as closest match)
        for name in &[
            "Uri.parse",
            "launchUrl",
            "launch",              // url_launcher
            "openUrl",
            "redirect",
        ] {
            sinks.push(TaintSink {
                name: name.to_string(),
                kind: TaintSinkKind::NetworkSend,
                node_id: 0,
            });
        }

        // ============ DART SANITIZERS ============

        sanitizers.extend(vec![
            // HTML Escaping
            "htmlEscape".to_string(),
            "HtmlEscape".to_string(),
            "escape".to_string(),
            // URL Encoding
            "Uri.encodeComponent".to_string(),
            "Uri.encodeQueryComponent".to_string(),
            "Uri.encodeFull".to_string(),
            // Validation
            "int.parse".to_string(),
            "int.tryParse".to_string(),
            "double.parse".to_string(),
            "double.tryParse".to_string(),
            "num.parse".to_string(),
            "num.tryParse".to_string(),
            // Regex validation
            "RegExp.hasMatch".to_string(),
            // Path validation
            "path.normalize".to_string(),
            "path.canonicalize".to_string(),
            // Type checking
            "is".to_string(),
            // SQL parameterization
            "Database.query".to_string(),  // With positional args
        ]);

        Self {
            language: Language::Dart,
            sources,
            sinks,
            sanitizers,
        }
    }

    /// C configuration (comprehensive)
    fn c_config() -> Self {
        let mut sources = Vec::new();
        let mut sinks = Vec::new();
        let mut sanitizers = Vec::new();

        // ===== TAINT SOURCES =====

        // User Input / Network
        for name in &[
            "recv",
            "recvfrom",
            "recvmsg",
            "read",
            "fread",
            "fgets",
            "gets",
            "scanf",
            "fscanf",
            "sscanf",
            "getenv",
            "getchar",
            "fgetc",
            "getc",
            "readline",
            "accept",
            "listen",
        ] {
            sources.push(TaintSource {
                name: name.to_string(),
                kind: TaintSourceKind::UserInput,
                node_id: 0,
            });
        }

        // Environment Variables
        for name in &["getenv", "secure_getenv"] {
            sources.push(TaintSource {
                name: name.to_string(),
                kind: TaintSourceKind::EnvironmentVariable,
                node_id: 0,
            });
        }

        // File Read
        for name in &["fread", "read", "fgets", "fgetc", "getc"] {
            sources.push(TaintSource {
                name: name.to_string(),
                kind: TaintSourceKind::FileRead,
                node_id: 0,
            });
        }

        // ===== TAINT SINKS =====

        // Command Execution (Critical)
        for name in &[
            "system",
            "popen",
            "execl",
            "execlp",
            "execle",
            "execv",
            "execvp",
            "execvpe",
            "execve",
            "fork",
            "vfork",
            "spawn",
            "spawnl",
            "spawnle",
            "spawnlp",
            "spawnlpe",
            "spawnv",
            "spawnve",
            "spawnvp",
            "spawnvpe",
            "_execl",
            "_execv",
            "_system",
            "_popen",
            "ShellExecute",
            "ShellExecuteEx",
            "CreateProcess",
            "WinExec",
        ] {
            sinks.push(TaintSink {
                name: name.to_string(),
                kind: TaintSinkKind::CommandExecution,
                node_id: 0,
            });
        }

        // Format String (Critical)
        for name in &[
            "printf",
            "fprintf",
            "sprintf",
            "snprintf",
            "vprintf",
            "vfprintf",
            "vsprintf",
            "vsnprintf",
            "syslog",
            "wprintf",
            "fwprintf",
            "swprintf",
        ] {
            sinks.push(TaintSink {
                name: name.to_string(),
                kind: TaintSinkKind::LogOutput,  // Format string vulnerabilities
                node_id: 0,
            });
        }

        // Memory Operations (Buffer Overflow)
        for name in &[
            "strcpy",
            "strncpy",
            "strcat",
            "strncat",
            "memcpy",
            "memmove",
            "memset",
            "bcopy",
            "gets",
            "sprintf",
            "vsprintf",
        ] {
            sinks.push(TaintSink {
                name: name.to_string(),
                kind: TaintSinkKind::FileWrite,  // Using FileWrite for memory corruption
                node_id: 0,
            });
        }

        // File Operations (Path Traversal)
        for name in &[
            "fopen",
            "freopen",
            "open",
            "creat",
            "openat",
            "rename",
            "remove",
            "unlink",
            "rmdir",
            "mkdir",
            "chdir",
            "chmod",
            "chown",
            "link",
            "symlink",
        ] {
            sinks.push(TaintSink {
                name: name.to_string(),
                kind: TaintSinkKind::FileWrite,
                node_id: 0,
            });
        }

        // Network Send
        for name in &["send", "sendto", "sendmsg", "write"] {
            sinks.push(TaintSink {
                name: name.to_string(),
                kind: TaintSinkKind::NetworkSend,
                node_id: 0,
            });
        }

        // ===== SANITIZERS =====
        sanitizers.extend(vec![
            "snprintf".to_string(),  // Safe with proper size
            "strncpy".to_string(),   // Safe with proper size
            "strncat".to_string(),   // Safe with proper size
            "escape".to_string(),
            "sanitize".to_string(),
            "validate".to_string(),
        ]);

        Self {
            language: Language::C,
            sources,
            sinks,
            sanitizers,
        }
    }

    /// C++ configuration (extends C config)
    fn cpp_config() -> Self {
        // Start with C config
        let c_config = Self::c_config();
        let mut sources = c_config.sources;
        let mut sinks = c_config.sinks;
        let mut sanitizers = c_config.sanitizers;

        // Add C++ specific sources
        for name in &[
            "cin",
            "std::cin",
            "getline",
            "std::getline",
            "ifstream.read",
            "ifstream.getline",
        ] {
            sources.push(TaintSource {
                name: name.to_string(),
                kind: TaintSourceKind::UserInput,
                node_id: 0,
            });
        }

        // Add C++ specific sinks
        for name in &[
            "cout",
            "std::cout",
            "cerr",
            "std::cerr",
            "ofstream.write",
            "std::system",
        ] {
            sinks.push(TaintSink {
                name: name.to_string(),
                kind: TaintSinkKind::LogOutput,
                node_id: 0,
            });
        }

        Self {
            language: Language::Cpp,
            sources,
            sinks,
            sanitizers,
        }
    }

    /// Kotlin configuration (similar to Java)
    fn kotlin_config() -> Self {
        // Kotlin uses Java-like APIs, so start with Java config
        let java_config = Self::java_config();
        let mut sources = java_config.sources;
        let mut sinks = java_config.sinks;
        let mut sanitizers = java_config.sanitizers;

        // Add Kotlin-specific patterns
        for name in &[
            "readLine",
            "readln",
            "System.console",
        ] {
            sources.push(TaintSource {
                name: name.to_string(),
                kind: TaintSourceKind::UserInput,
                node_id: 0,
            });
        }

        Self {
            language: Language::Kotlin,
            sources,
            sinks,
            sanitizers,
        }
    }

    /// Scala configuration (similar to Java)
    fn scala_config() -> Self {
        // Scala uses Java-like APIs
        let java_config = Self::java_config();
        let mut sources = java_config.sources;
        let mut sinks = java_config.sinks;
        let mut sanitizers = java_config.sanitizers;

        // Add Scala-specific patterns
        for name in &[
            "scala.io.StdIn.readLine",
            "StdIn.readLine",
            "Source.fromFile",
            "Source.fromURL",
        ] {
            sources.push(TaintSource {
                name: name.to_string(),
                kind: TaintSourceKind::UserInput,
                node_id: 0,
            });
        }

        Self {
            language: Language::Scala,
            sources,
            sinks,
            sanitizers,
        }
    }

    /// Generic configuration for unsupported languages
    fn generic_config(language: Language) -> Self {
        Self {
            language,
            sources: Vec::new(),
            sinks: Vec::new(),
            sanitizers: Vec::new(),
        }
    }

    /// Bash/Shell-specific taint configuration
    fn bash_config() -> Self {
        let mut sources = Vec::new();
        let mut sinks = Vec::new();
        let mut sanitizers = Vec::new();

        // ============ BASH TAINT SOURCES ============

        // User Input / Arguments
        for name in &[
            "$1", "$2", "$3", "$4", "$5", "$6", "$7", "$8", "$9",
            "$@",           // All positional parameters
            "$*",           // All positional parameters as single string
            "$#",           // Number of arguments
            "read",         // Read from stdin
            "REPLY",        // Default read variable
        ] {
            sources.push(TaintSource {
                name: name.to_string(),
                kind: TaintSourceKind::CommandLineArgument,
                node_id: 0,
            });
        }

        // Environment Variables
        for name in &[
            "$ENV",
            "$HOME",
            "$USER",
            "$PATH",
            "$PWD",
            "$SHELL",
            "$TERM",
            "$LANG",
            "$HTTP_PROXY",
            "$HTTPS_PROXY",
            "$NO_PROXY",
            "printenv",
            "env",
        ] {
            sources.push(TaintSource {
                name: name.to_string(),
                kind: TaintSourceKind::EnvironmentVariable,
                node_id: 0,
            });
        }

        // File/Network Input
        for name in &[
            "cat",
            "head",
            "tail",
            "less",
            "more",
            "curl",
            "wget",
            "nc",
            "netcat",
        ] {
            sources.push(TaintSource {
                name: name.to_string(),
                kind: TaintSourceKind::FileRead,
                node_id: 0,
            });
        }

        // ============ BASH TAINT SINKS ============

        // Command Execution (Critical)
        for name in &[
            "eval",
            "exec",
            "source",
            ".",              // source alias
            "bash",
            "sh",
            "zsh",
            "ksh",
            "csh",
            "tcsh",
            "dash",
            "xargs",
            "nohup",
            "sudo",
            "su",
            "ssh",
            "sshpass",
        ] {
            sinks.push(TaintSink {
                name: name.to_string(),
                kind: TaintSinkKind::CommandExecution,
                node_id: 0,
            });
        }

        // File Operations
        for name in &[
            "rm",
            "rmdir",
            "mv",
            "cp",
            "ln",
            "chmod",
            "chown",
            "chgrp",
            "touch",
            "mkdir",
            "mktemp",
            "tee",
            "dd",
            "install",
            "shred",
        ] {
            sinks.push(TaintSink {
                name: name.to_string(),
                kind: TaintSinkKind::FileWrite,
                node_id: 0,
            });
        }

        // Network Operations (SSRF potential)
        for name in &[
            "curl",
            "wget",
            "nc",
            "netcat",
            "socat",
            "telnet",
            "ftp",
            "sftp",
            "scp",
            "rsync",
            "ping",
            "nmap",
        ] {
            sinks.push(TaintSink {
                name: name.to_string(),
                kind: TaintSinkKind::NetworkSend,
                node_id: 0,
            });
        }

        // Output (potential information disclosure)
        for name in &[
            "echo",
            "printf",
            "cat",
            "logger",
            "wall",
            "write",
        ] {
            sinks.push(TaintSink {
                name: name.to_string(),
                kind: TaintSinkKind::LogOutput,
                node_id: 0,
            });
        }

        // SQL/Database
        for name in &[
            "mysql",
            "psql",
            "sqlite3",
            "mongosh",
            "redis-cli",
        ] {
            sinks.push(TaintSink {
                name: name.to_string(),
                kind: TaintSinkKind::SqlQuery,
                node_id: 0,
            });
        }

        // ============ BASH SANITIZERS ============

        sanitizers.extend(vec![
            // Quoting
            "printf '%q'".to_string(),
            // Validation
            "[[ -f".to_string(),
            "[[ -d".to_string(),
            "[[ -e".to_string(),
            "[[ -r".to_string(),
            "[[ -w".to_string(),
            "test".to_string(),
            // Path normalization
            "realpath".to_string(),
            "readlink".to_string(),
            "basename".to_string(),
            "dirname".to_string(),
            // Type checking
            "declare -i".to_string(),
            // Escaping
            "sed 's/[^a-zA-Z0-9]//g'".to_string(),
        ]);

        Self {
            language: Language::Bash,
            sources,
            sinks,
            sanitizers,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_ruby_config() {
        let config = LanguageTaintConfig::for_language(Language::Ruby);
        assert!(config.sources.len() > 0, "Ruby should have taint sources");
        assert!(config.sinks.len() > 0, "Ruby should have taint sinks");
        assert!(config.sanitizers.len() > 0, "Ruby should have sanitizers");

        // Check for specific Ruby sources
        assert!(
            config.sources.iter().any(|s| s.name == "params"),
            "Ruby should have 'params' as source"
        );
        assert!(
            config.sources.iter().any(|s| s.name == "gets"),
            "Ruby should have 'gets' as source"
        );

        // Check for specific Ruby sinks
        assert!(
            config.sinks.iter().any(|s| s.name == "system"),
            "Ruby should have 'system' as sink"
        );
        assert!(
            config.sinks.iter().any(|s| s.name == "eval"),
            "Ruby should have 'eval' as sink"
        );

        // Check for specific Ruby sanitizers
        assert!(
            config.sanitizers.contains(&"sanitize".to_string()),
            "Ruby should have 'sanitize' as sanitizer"
        );
    }

    #[test]
    fn test_php_config() {
        let config = LanguageTaintConfig::for_language(Language::Php);
        assert!(config.sources.len() > 0, "PHP should have taint sources");
        assert!(config.sinks.len() > 0, "PHP should have taint sinks");
        assert!(config.sanitizers.len() > 0, "PHP should have sanitizers");

        // Check for specific PHP sources
        assert!(
            config.sources.iter().any(|s| s.name == "$_GET"),
            "PHP should have '$_GET' as source"
        );
        assert!(
            config.sources.iter().any(|s| s.name == "$_POST"),
            "PHP should have '$_POST' as source"
        );

        // Check for specific PHP sinks
        assert!(
            config.sinks.iter().any(|s| s.name == "mysqli_query"),
            "PHP should have 'mysqli_query' as sink"
        );
        assert!(
            config.sinks.iter().any(|s| s.name == "eval"),
            "PHP should have 'eval' as sink"
        );

        // Check for specific PHP sanitizers
        assert!(
            config.sanitizers.contains(&"htmlspecialchars".to_string()),
            "PHP should have 'htmlspecialchars' as sanitizer"
        );
    }

    #[test]
    fn test_all_languages_have_config() {
        for lang in &[
            Language::Ruby,
            Language::Php,
            Language::JavaScript,
            Language::TypeScript,
            Language::Python,
            Language::Java,
            Language::Go,
            Language::CSharp,
        ] {
            let config = LanguageTaintConfig::for_language(*lang);
            assert_eq!(config.language, *lang);
        }
    }
}
