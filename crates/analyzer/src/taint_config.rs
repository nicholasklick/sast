//! Language-specific taint analysis configurations
//!
//! This module provides taint sources, sinks, and sanitizers for different
//! programming languages. Each language has unique frameworks, APIs, and
//! security-sensitive functions that need to be tracked.

use crate::taint::{TaintSink, TaintSinkKind, TaintSource, TaintSourceKind};
use gittera_parser::language::Language;

/// Language-specific taint configuration
pub struct LanguageTaintConfig {
    pub language: Language,
    pub sources: Vec<TaintSource>,
    pub sinks: Vec<TaintSink>,
    pub sanitizers: Vec<String>,
}

impl LanguageTaintConfig {
    /// Get taint configuration for a specific language
    pub fn for_language(language: Language) -> Self {
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
            "File.open",        // With 'w' mode
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

        // HTML/XSS (Rails)
        let html_sinks = vec![
            "html_safe",
            "raw",              // Rails helper
            "render",
            "render_to_string",
            "content_tag",
            "link_to",
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
            "puts",
            "print",
            "p",
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
        for name in &["request.body", "request.query", "request.params", "process.argv"] {
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

        sanitizers.extend(vec![
            "escape".to_string(),
            "sanitize".to_string(),
            "validator.escape".to_string(),
        ]);

        Self {
            language,
            sources,
            sinks,
            sanitizers,
        }
    }

    /// Python configuration
    fn python_config() -> Self {
        let mut sources = Vec::new();
        let mut sinks = Vec::new();
        let mut sanitizers = Vec::new();

        // User Input
        for name in &["input", "raw_input", "sys.argv", "request.args", "request.form"] {
            sources.push(TaintSource {
                name: name.to_string(),
                kind: TaintSourceKind::UserInput,
                node_id: 0,
            });
        }

        // Command Execution
        for name in &["os.system", "subprocess.call", "subprocess.run", "eval", "exec"] {
            sinks.push(TaintSink {
                name: name.to_string(),
                kind: TaintSinkKind::CommandExecution,
                node_id: 0,
            });
        }

        sanitizers.extend(vec![
            "escape".to_string(),
            "html.escape".to_string(),
            "shlex.quote".to_string(),
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

        // ===== TAINT SOURCES (20+) =====

        // User Input - Servlet API
        for name in &[
            "request.getParameter",
            "request.getParameterValues",
            "request.getHeader",
            "request.getHeaders",
            "request.getQueryString",
            "HttpServletRequest.getParameter",
            "HttpServletRequest.getHeader",
            "ServletRequest.getParameter",
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

        // File Read
        for name in &[
            "Files.readString",
            "Files.readAllLines",
            "Files.readAllBytes",
            "FileInputStream",
            "FileReader",
            "BufferedReader.readLine",
            "Scanner.nextLine",
        ] {
            sources.push(TaintSource {
                name: name.to_string(),
                kind: TaintSourceKind::FileRead,
                node_id: 0,
            });
        }

        // Environment Variables
        for name in &["System.getenv", "System.getProperty"] {
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
            "Runtime.exec",
            "Runtime.getRuntime().exec",
            "ProcessBuilder.start",
            "ProcessBuilder.command",
            "Process.start",
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

        // SQL Injection
        for name in &[
            "Statement.execute",
            "Statement.executeQuery",
            "Statement.executeUpdate",
            "Connection.createStatement",
            "JdbcTemplate.execute",
            "JdbcTemplate.query",
            "JdbcTemplate.update",
            "EntityManager.createNativeQuery",
            "Query.executeUpdate",
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

    /// Generic configuration for unsupported languages
    fn generic_config(language: Language) -> Self {
        Self {
            language,
            sources: Vec::new(),
            sinks: Vec::new(),
            sanitizers: Vec::new(),
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
