# Language Support

**Status**: ✅ Complete
**Supported Languages**: 9 languages with full taint analysis
**Last Updated**: 2025-11-19

---

## Overview

Gittera SAST provides comprehensive security analysis for 9 programming languages with full taint analysis support, language-specific sources/sinks/sanitizers, and framework coverage.

### Language Summary

| Language | Sources | Sinks | Sanitizers | Status | Frameworks |
|----------|---------|-------|------------|--------|------------|
| **JavaScript** | 10+ | 15+ | 5+ | ✅ Full | Express, Node.js |
| **TypeScript** | 10+ | 15+ | 5+ | ✅ Full | Express, NestJS |
| **Python** | 10+ | 10+ | 5+ | ✅ Full | Django, Flask |
| **Ruby** | 20+ | 30+ | 10+ | ✅ Full | Rails, Sinatra |
| **PHP** | 15+ | 30+ | 10+ | ✅ Full | Laravel, Symfony |
| **Java** | 25+ | 35+ | 12+ | ✅ Full | Spring, Servlet API |
| **Go** | 18+ | 20+ | 11+ | ✅ Full | Gin, net/http |
| **Swift** | 17+ | 18+ | 10+ | ✅ Full | iOS/macOS frameworks |
| **Rust** | 15+ | 16+ | 10+ | ✅ Full | actix-web, diesel, sqlx |

---

## Quick Start

### Language-Specific Configuration

```rust
use gittera_analyzer::{CfgBuilder, TaintAnalysis};
use gittera_parser::{Parser, Language, LanguageConfig};
use std::path::Path;

// Parse code
let parser = Parser::new(LanguageConfig::new(Language::Java), Path::new("App.java"));
let ast = parser.parse_source(code)?;
let cfg = CfgBuilder::new().build(&ast);

// Configure for specific language
let taint = TaintAnalysis::new().for_language(Language::Java);

// Analyze
let result = taint.analyze(&cfg, &ast);

// Process vulnerabilities
for vuln in &result.vulnerabilities {
    println!("[{}] {} flows to {}",
        vuln.severity.as_str(),
        vuln.tainted_value.variable,
        vuln.sink.name
    );
}
```

---

## Java

### Taint Sources (25+)

#### User Input - Servlet API
```java
request.getParameter
request.getParameterValues
request.getHeader
request.getHeaders
request.getQueryString
HttpServletRequest.getParameter
HttpServletRequest.getHeader
ServletRequest.getParameter
```

#### User Input - Spring Framework
```java
@RequestParam
@PathVariable
@RequestBody
@RequestHeader
RequestParam
PathVariable
```

#### File Read
```java
Files.readString
Files.readAllLines
Files.readAllBytes
FileInputStream
FileReader
BufferedReader.readLine
Scanner.nextLine
```

#### Environment Variables
```java
System.getenv
System.getProperty
```

#### Network/HTTP
```java
URL.openStream
HttpURLConnection.getInputStream
HttpClient.send
```

#### Database Query Results
```java
ResultSet.getString
ResultSet.getObject
```

### Taint Sinks (35+)

#### Command Execution
```java
Runtime.exec
Runtime.getRuntime().exec
ProcessBuilder.start
ProcessBuilder.command
Process.start
```

#### Code Evaluation (Reflection)
```java
Class.forName
Method.invoke
Constructor.newInstance
ScriptEngine.eval
ScriptEngineManager.eval
```

#### SQL Injection
```java
Statement.execute
Statement.executeQuery
Statement.executeUpdate
Connection.createStatement
JdbcTemplate.execute
JdbcTemplate.query
JdbcTemplate.update
EntityManager.createNativeQuery
Query.executeUpdate
```

#### File Write
```java
Files.write
Files.writeString
FileOutputStream.write
FileWriter.write
PrintWriter.write
BufferedWriter.write
```

#### HTML/XSS Output
```java
response.getWriter().write
PrintWriter.println
ServletOutputStream.print
HttpServletResponse.getWriter
```

#### Logging (Information Disclosure)
```java
System.out.println
logger.info
logger.debug
logger.error
log.info
```

### Sanitizers (12+)

```java
// HTML Escaping
StringEscapeUtils.escapeHtml4
StringEscapeUtils.escapeHtml
HtmlUtils.htmlEscape
ESAPI.encoder().encodeForHTML

// SQL Escaping
ESAPI.encoder().encodeForSQL
PreparedStatement.setString
PreparedStatement.setInt

// Command Escaping
StringEscapeUtils.escapeJava

// Validation
Validator.isValid
validate

// Spring Security
HtmlUtils.htmlEscapeDecimal
UriUtils.encode
```

---

## Go

### Taint Sources (18+)

#### User Input - Command Line
```go
os.Args
flag.String
flag.Int
```

#### User Input - HTTP (net/http)
```go
r.FormValue
r.URL.Query
r.URL.Query().Get
r.PostFormValue
r.Header.Get
r.Cookie
r.Body
```

#### User Input - Gin Framework
```go
c.Query
c.Param
c.PostForm
c.GetHeader
c.Cookie
gin.Context.Query
gin.Context.Param
```

#### File Read
```go
os.ReadFile
ioutil.ReadFile
os.Open
bufio.NewReader
```

#### Environment Variables
```go
os.Getenv
os.LookupEnv
```

#### Network/HTTP
```go
http.Get
http.Client.Get
ioutil.ReadAll
```

### Taint Sinks (20+)

#### Command Execution
```go
exec.Command
exec.CommandContext
os/exec.Command
syscall.Exec
```

#### SQL Injection
```go
db.Exec
db.Query
db.QueryRow
tx.Exec
tx.Query
database/sql.DB.Exec
database/sql.DB.Query
```

#### File Write
```go
os.WriteFile
ioutil.WriteFile
os.Create
os.OpenFile
fmt.Fprintf
```

#### HTML/XSS Output
```go
fmt.Fprintf
w.Write
io.WriteString
c.String
c.HTML
gin.Context.String
```

#### Logging
```go
log.Println
log.Printf
fmt.Println
fmt.Printf
```

### Sanitizers (11+)

```go
// HTML Escaping
html.EscapeString
template.HTMLEscapeString
template.JSEscapeString
template.URLQueryEscaper

// SQL Escaping (use prepared statements)
db.Prepare
sql.DB.Prepare

// Command Escaping
shellescape.Quote

// Validation
strconv.Atoi
strconv.ParseInt
strconv.ParseFloat

// URL Encoding
url.QueryEscape
```

---

## Swift

### Taint Sources (17+)

#### User Input - Command Line
```swift
CommandLine.arguments
ProcessInfo.processInfo.arguments
```

#### User Input - Network (URLSession, Alamofire)
```swift
URLRequest
URLComponents.queryItems
URLSession.dataTask
request.url
request.allHTTPHeaderFields
```

#### File Read
```swift
String(contentsOfFile:)
String(contentsOf:)
Data(contentsOf:)
FileManager.contents
FileHandle.readDataToEndOfFile
try String(contentsOfFile:)
```

#### Environment Variables
```swift
ProcessInfo.processInfo.environment
getenv
ProcessInfo.environment
```

#### User Defaults (can be manipulated)
```swift
UserDefaults.standard.string
UserDefaults.standard.object
```

#### Database (CoreData, SQLite)
```swift
sqlite3_column_text
NSFetchRequest.execute
```

### Taint Sinks (18+)

#### Command Execution
```swift
Process
NSTask
Process.launch
Process.run
system
popen
```

#### SQL Injection
```swift
sqlite3_exec
sqlite3_prepare
sqlite3_prepare_v2
executeQuery
executeUpdate
```

#### File Write
```swift
write(to:)
write(toFile:)
FileManager.createFile
Data.write
String.write
```

#### HTML/XSS Output (WKWebView, UIWebView)
```swift
WKWebView.loadHTMLString
UIWebView.loadHTMLString
webView.loadHTMLString
evaluateJavaScript
```

#### Logging
```swift
print
NSLog
os_log
Logger.log
```

### Sanitizers (10+)

```swift
// HTML Escaping
addingPercentEncoding
stringByAddingPercentEncoding

// SQL Escaping (use prepared statements)
sqlite3_bind_text
sqlite3_bind_int

// Validation
Int()
Double()
UUID(uuidString:)

// URL Encoding
URLComponents
CharacterSet.urlQueryAllowed
escapedString
```

---

## Rust

### Taint Sources (15+)

#### User Input - Command Line
```rust
std::env::args
std::env::args_os
env::args
args
```

#### User Input - HTTP (actix-web, rocket, warp)
```rust
HttpRequest.query_string
HttpRequest.match_info
req.param
req.query
Query
Path
Form
```

#### File Read
```rust
std::fs::read_to_string
std::fs::read
File::open
read_to_string
read_line
```

#### Environment Variables
```rust
std::env::var
std::env::var_os
env::var
```

#### Network/HTTP
```rust
reqwest::get
reqwest::Client::get
hyper::Client::get
```

#### Standard Input
```rust
std::io::stdin
stdin
io::stdin().read_line
```

### Taint Sinks (16+)

#### Command Execution
```rust
std::process::Command
Command::new
Command.spawn
Command.output
process::Command
```

#### SQL Injection (rusqlite, diesel, sqlx)
```rust
rusqlite::Connection::execute
Connection::execute
execute
query
sqlx::query
diesel::sql_query
```

#### File Write
```rust
std::fs::write
File::create
OpenOptions::new
write_all
write
```

#### Logging
```rust
println!
eprintln!
log::info
log::debug
```

### Sanitizers (10+)

```rust
// HTML Escaping
html_escape::encode_text
askama::escape

// SQL Escaping (use prepared statements)
execute_named
query_as
sqlx::query!

// Validation
str::parse
from_str
String::from_utf8

// Path sanitization
Path::new
PathBuf::from
```

---

## Ruby

### Taint Sources (20+)

#### User Input (Rails & Sinatra)
```ruby
params                  # Rails params hash
request.params          # Explicit params access
request.query_string
request.POST
request.GET
request.body
request.env
gets                    # STDIN
gets.chomp
readline
readlines
STDIN.read
STDIN.gets
$stdin.read
URI.parse              # URL parameters
CGI.new
```

#### File Read
```ruby
File.read
File.open
File.readlines
IO.read
IO.readlines
open                   # Kernel#open
File.binread
```

#### Environment Variables
```ruby
ENV
ENV.fetch
ENV[]
```

#### Network/HTTP
```ruby
Net::HTTP.get
Net::HTTP.get_response
open-uri
RestClient.get
HTTParty.get
Faraday.get
```

#### Database Query Results
```ruby
ActiveRecord::Base.connection.execute
ActiveRecord::Base.connection.select_all
execute
select_all
```

### Taint Sinks (30+)

#### Command Execution
```ruby
system
exec
spawn
`                      # Backticks
%x                     # %x{} syntax
Kernel.system
Kernel.exec
IO.popen
Open3.popen3
Open3.capture3
PTY.spawn
```

#### Code Evaluation (Dangerous!)
```ruby
eval
instance_eval
class_eval
module_eval
binding.eval
Kernel.eval
send                   # Dynamic method invocation
public_send
__send__
method
const_get             # Constant lookup
constantize           # Rails method
```

#### SQL Injection (ActiveRecord & Raw SQL)
```ruby
execute
exec_query
select_all
select_one
select_value
select_values
find_by_sql
where                 # Can be unsafe with string interpolation
connection.execute
ActiveRecord::Base.connection.execute
```

#### File Write
```ruby
File.write
File.open             # With 'w' mode
IO.write
File.binwrite
FileUtils.cp
FileUtils.mv
FileUtils.rm
```

#### HTML/XSS (Rails)
```ruby
html_safe
raw                   # Rails helper
render
render_to_string
content_tag
link_to
```

#### Logging (Info Disclosure)
```ruby
puts
print
p
logger.info
logger.debug
logger.warn
logger.error
Rails.logger.info
```

### Sanitizers (10+)

```ruby
sanitize
escape
h                      # Rails HTML escape helper
html_escape
ERB::Util.html_escape
CGI.escapeHTML
Rack::Utils.escape_html
strip_tags
sanitize_sql
quote                  # SQL quoting
Shellwords.escape
Shellwords.shellescape
validate
validates
permit                 # Strong parameters
require
```

---

## PHP

### Taint Sources (15+)

#### User Input (Superglobals)
```php
$_GET
$_POST
$_REQUEST
$_COOKIE
$_SERVER
$_FILES
filter_input
filter_input_array
$HTTP_GET_VARS         # Deprecated but still dangerous
$HTTP_POST_VARS
$HTTP_COOKIE_VARS
```

#### File Read
```php
file_get_contents
file
readfile
fread
fgets
fgetss
fscanf
parse_ini_file
```

#### Environment Variables
```php
getenv
apache_getenv
$_ENV
```

#### Network/HTTP
```php
file_get_contents      # With URL
fopen                  # With URL
curl_exec
stream_get_contents
```

#### Database (mysqli, PDO)
```php
mysqli_query
mysql_query
mysqli_fetch_assoc
mysqli_fetch_array
PDO::query
PDOStatement::fetch
```

### Taint Sinks (30+)

#### Command Execution
```php
system
exec
shell_exec
passthru
proc_open
popen
`                      # Backticks
pcntl_exec
```

#### Code Evaluation (Extremely Dangerous!)
```php
eval
assert
create_function
preg_replace           # With /e modifier (deprecated but dangerous)
mb_ereg_replace        # With 'e' option
call_user_func
call_user_func_array
$var                   # Variable functions (indirect)
```

#### SQL Injection
```php
mysqli_query
mysql_query
mysqli_multi_query
mysqli_real_query
PDO::query
PDO::exec
pg_query
sqlite_query
mssql_query
oci_execute
```

#### File Write
```php
file_put_contents
fwrite
fputs
fputcsv
rename
unlink
rmdir
mkdir
move_uploaded_file
```

#### HTML/XSS Output
```php
echo
print
printf
vprintf
die
exit
trigger_error
user_error
```

#### Logging
```php
error_log
syslog
openlog
trigger_error
```

### Sanitizers (10+)

```php
htmlspecialchars
htmlentities
strip_tags
addslashes
mysqli_real_escape_string
mysql_real_escape_string
pg_escape_string
sqlite_escape_string
escapeshellarg
escapeshellcmd
filter_var
filter_input
intval
floatval
preg_quote
PDO::quote
preg_replace_callback   # Safer than preg_replace
```

---

## Security Best Practices

### General Principles

1. **Use Parameterized Queries** - Never concatenate user input into SQL
2. **Validate and Sanitize Input** - Whitelist acceptable values
3. **Escape Output** - Context-aware escaping (HTML, SQL, shell)
4. **Avoid Dynamic Code Execution** - Never use eval() with user input
5. **Use Framework Security Features** - Built-in protections (CSRF tokens, etc.)

### Ruby Best Practices

#### ✅ Safe: Parameterized Queries
```ruby
# Good: Use ActiveRecord query interface
User.where(name: params[:name])

# Good: Use bound parameters
User.where("name = ?", params[:name])
```

#### ❌ Unsafe: String Interpolation in SQL
```ruby
# Bad: String interpolation in SQL
sql = "SELECT * FROM users WHERE name = '#{params[:name]}'"
ActiveRecord::Base.connection.execute(sql)
```

#### ✅ Safe: Command Execution with Arrays
```ruby
# Good: Array form avoids shell interpretation
system("git", "clone", user_repo)
```

#### ❌ Unsafe: String Interpolation in Commands
```ruby
# Bad: Shell injection risk
system("git clone #{user_repo}")
```

### PHP Best Practices

#### ✅ Safe: Prepared Statements
```php
// Good: PDO prepared statements
$stmt = $pdo->prepare("SELECT * FROM users WHERE name = ?");
$stmt->execute([$name]);

// Good: mysqli prepared statements
$stmt = $mysqli->prepare("SELECT * FROM users WHERE name = ?");
$stmt->bind_param("s", $name);
$stmt->execute();
```

#### ❌ Unsafe: String Concatenation in SQL
```php
// Bad: SQL injection risk
$sql = "SELECT * FROM users WHERE name = '$name'";
mysqli_query($conn, $sql);
```

#### ✅ Safe: escapeshellarg()
```php
// Good: Escape shell arguments
$safe_arg = escapeshellarg($user_input);
system("ls $safe_arg");
```

#### ✅ Safe: htmlspecialchars()
```php
// Good: Escape HTML
echo htmlspecialchars($user_input, ENT_QUOTES, 'UTF-8');
```

### Java Best Practices

#### ✅ Safe: PreparedStatement
```java
// Good: Parameterized query
PreparedStatement stmt = conn.prepareStatement("SELECT * FROM users WHERE id = ?");
stmt.setInt(1, userId);
ResultSet rs = stmt.executeQuery();
```

#### ✅ Safe: Spring Security
```java
// Good: Use framework escaping
String safe = HtmlUtils.htmlEscape(userInput);
```

### Go Best Practices

#### ✅ Safe: Prepared Statements
```go
// Good: Use placeholders
stmt, err := db.Prepare("SELECT * FROM users WHERE id = ?")
defer stmt.Close()
row := stmt.QueryRow(userId)
```

#### ✅ Safe: html/template
```go
// Good: Auto-escapes by default
t := template.Must(template.New("page").Parse(tmpl))
t.Execute(w, data)
```

---

## Integration Tests

### Test Coverage Summary

| Language | Test Count | Status |
|----------|-----------|--------|
| Java | 13 tests | ✅ Passing |
| Go | 13 tests | ✅ Passing |
| Swift | 15 tests | ✅ Passing |
| Rust | 14 tests | ✅ Passing |
| Ruby | 12 tests | ✅ Passing |
| PHP | 12 tests | ✅ Passing |
| **Total** | **79 tests** | ✅ **All Passing** |

### Running Tests

```bash
# Run all language tests
cargo test -p gittera-analyzer --test java_taint_test
cargo test -p gittera-analyzer --test go_taint_test
cargo test -p gittera-analyzer --test swift_taint_test
cargo test -p gittera-analyzer --test rust_taint_test
cargo test -p gittera-analyzer --test ruby_taint_test
cargo test -p gittera-analyzer --test php_taint_test

# Run all at once
cargo test -p gittera-analyzer taint_test
```

---

## Architecture

### Language-Specific Configuration Module

**File**: `crates/analyzer/src/taint_config.rs`

```rust
pub struct LanguageTaintConfig {
    pub language: Language,
    pub sources: Vec<TaintSource>,
    pub sinks: Vec<TaintSink>,
    pub sanitizers: Vec<String>,
}

impl LanguageTaintConfig {
    pub fn for_language(language: Language) -> Self {
        match language {
            Language::Java => Self::java_config(),
            Language::Go => Self::go_config(),
            Language::Swift => Self::swift_config(),
            Language::Rust => Self::rust_config(),
            Language::Ruby => Self::ruby_config(),
            Language::Php => Self::php_config(),
            Language::JavaScript => Self::javascript_config(Language::JavaScript),
            Language::TypeScript => Self::javascript_config(Language::TypeScript),
            Language::Python => Self::python_config(),
            Language::CSharp => Self::csharp_config(),
            _ => Self::generic_config(language),
        }
    }
}
```

### TaintAnalysis Integration

```rust
impl TaintAnalysis {
    pub fn for_language(mut self, language: Language) -> Self {
        let config = LanguageTaintConfig::for_language(language);

        self.sources = config.sources;
        self.sinks = config.sinks;
        self.sanitizers = config.sanitizers.into_iter().collect();

        self
    }
}
```

---

## Future Enhancements

### Short Term (1-2 months)
- [ ] Add more framework-specific rules
- [ ] Context-aware taint tracking
- [ ] C# comprehensive coverage
- [ ] C/C++ language support

### Medium Term (3-6 months)
- [ ] Custom sanitizer definitions per-project
- [ ] Framework-specific taint propagation rules
- [ ] Inter-file taint analysis
- [ ] Type-based taint analysis

### Long Term (6-12 months)
- [ ] Whole-program analysis across multiple files
- [ ] Integration with package managers
- [ ] Machine learning for pattern detection
- [ ] IDE integration for real-time analysis

---

## References

### Language Security Guides
- [Java Security](https://www.oracle.com/java/technologies/javase/seccodeguide.html)
- [Go Security](https://go.dev/security/)
- [Swift Security](https://developer.apple.com/security/)
- [Rust Security](https://rustsec.org/)
- [Rails Security Guide](https://guides.rubyonrails.org/security.html)
- [PHP Security](https://www.php.net/manual/en/security.php)

### Security Standards
- [OWASP Top 10](https://owasp.org/Top10/)
- [CWE Database](https://cwe.mitre.org/)
- [SANS Top 25](https://www.sans.org/top25-software-errors/)

---

**Document Version**: 2.0
**Last Updated**: 2025-11-19
**Status**: ✅ Complete

**Consolidates**:
- JAVA_GO_SWIFT_RUST_LANGUAGE_SUPPORT.md
- RUBY_PHP_LANGUAGE_SUPPORT.md
