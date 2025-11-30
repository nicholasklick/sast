# GQL (Gittera Query Language) - Complete Guide

## Overview

GQL is a SQL-like declarative query language for detecting security vulnerabilities and code patterns in source code. It allows security researchers to write custom detection rules without modifying the SAST engine's Rust code.

## Why GQL?

**Traditional Approach** (Hardcoded):
```rust
// Adding a new check requires modifying Rust code
fn check_sql_injection(ast: &AstNode) -> Vec<Finding> {
    // Hundreds of lines of traversal logic...
}
```

**GQL Approach** (Declarative):
```sql
FROM CallExpression AS call
WHERE call.callee MATCHES "(?i)(execute|query|exec)"
SELECT call, "Potential SQL injection"
```

## Query Structure

Every GQL query has three clauses:

```sql
FROM <EntityType> AS <variable>
[WHERE <predicates>]
SELECT <items>
```

### 1. FROM Clause - What to Search For

Specifies the type of AST node to search for:

```sql
FROM CallExpression AS call
FROM FunctionDeclaration AS fn
FROM VariableDeclaration AS vd
FROM MemberExpression AS member
FROM BinaryExpression AS binop
FROM Literal AS lit
FROM Assignment AS assign
FROM AnyNode AS node
```

### 2. WHERE Clause - Filtering (Optional)

Defines conditions that nodes must match:

```sql
WHERE call.callee == "eval"
WHERE fn.name CONTAINS "unsafe"
WHERE vd.name MATCHES "(?i)(password|secret)"
```

### 3. SELECT Clause - What to Report

Specifies what to include in findings:

```sql
SELECT call                              -- Just the node
SELECT call, "Dangerous function"        -- Node + message
SELECT "XSS vulnerability detected"      -- Just message
```

## Operators

### Comparison Operators

| Operator | Description | Example |
|----------|-------------|---------|
| `==` or `=` | Equal | `call.name == "eval"` |
| `!=` | Not equal | `fn.name != "safe"` |
| `CONTAINS` | Contains substring (case-insensitive) | `var.name CONTAINS "password"` |
| `STARTS_WITH` | Starts with prefix | `fn.name STARTS_WITH "unsafe"` |
| `ENDS_WITH` | Ends with suffix | `file.name ENDS_WITH ".js"` |
| `MATCHES` | Regex match | `call.name MATCHES "eval\|exec"` |

### Logical Operators

| Operator | Description | Example |
|----------|-------------|---------|
| `AND` | Logical AND | `call.name == "eval" AND call.argumentsCount > 0` |
| `OR` | Logical OR | `call.name == "eval" OR call.name == "exec"` |
| `NOT` | Logical NOT | `NOT fn.name STARTS_WITH "safe"` |

## Property Access

Access properties of matched nodes:

### Common Properties

```sql
node.name           -- Name of the function/variable/method
node.text           -- Source code text
node.line           -- Line number
node.column         -- Column number
```

### Entity-Specific Properties

**CallExpression / MethodCall:**
```sql
call.callee         -- Function name being called
call.argumentsCount -- Number of arguments
```

**FunctionDeclaration:**
```sql
fn.name             -- Function name
fn.parameterCount   -- Number of parameters
fn.returnType       -- Return type (if available)
```

**VariableDeclaration:**
```sql
vd.name             -- Variable name
vd.type             -- Variable type (if available)
```

**MemberExpression:**
```sql
member.object       -- Object being accessed
member.property     -- Property name
```

**BinaryExpression:**
```sql
binop.operator      -- Operator (e.g., "+", "==", "&&")
```

### Nested Property Access

```sql
WHERE call.callee.name == "eval"
WHERE member.object.property == "document"
```

## Examples

### 1. Find Eval Calls

```sql
FROM CallExpression AS call
WHERE call.callee == "eval"
SELECT call, "Dangerous eval() usage detected"
```

### 2. Command Injection

```sql
FROM CallExpression AS call
WHERE call.callee MATCHES "(?i)(exec|spawn|system|popen)"
SELECT call, "Potential command injection vulnerability"
```

### 3. XSS - innerHTML Usage

```sql
FROM MemberExpression AS member
WHERE member.property MATCHES "(?i)(innerHTML|outerHTML|insertAdjacentHTML)"
SELECT member, "Potential XSS - dangerous HTML manipulation"
```

### 4. Hardcoded Secrets

```sql
FROM VariableDeclaration AS vd
WHERE vd.name MATCHES "(?i)(password|passwd|pwd|secret|api[_-]?key|apikey|token|auth)"
SELECT vd, "Potential hardcoded secret"
```

### 5. SQL Injection Sinks

```sql
FROM CallExpression AS call
WHERE (call.callee CONTAINS "execute" OR call.callee CONTAINS "query")
      AND call.argumentsCount > 0
SELECT call, "Potential SQL injection sink"
```

### 6. Weak Cryptography

```sql
FROM CallExpression AS call
WHERE call.callee MATCHES "(?i)(md5|sha1|des|rc4|ecb)"
SELECT call, "Weak cryptographic algorithm detected"
```

### 7. Complex Multi-Condition

```sql
FROM FunctionDeclaration AS fn
WHERE (fn.name CONTAINS "unsafe" OR fn.name CONTAINS "dangerous")
      AND NOT fn.name STARTS_WITH "test"
      AND fn.parameterCount > 0
SELECT fn, "Potentially unsafe function with parameters"
```

### 8. Path Traversal

```sql
FROM CallExpression AS call
WHERE call.callee MATCHES "(?i)(readFile|writeFile|open|require|import)"
SELECT call, "Potential path traversal - file operation detected"
```

### 9. Insecure Deserialization

```sql
FROM CallExpression AS call
WHERE call.callee MATCHES "(?i)(pickle\\.loads|yaml\\.unsafe_load|unserialize|eval)"
SELECT call, "Insecure deserialization - RCE risk"
```

### 10. SSRF Detection

```sql
FROM CallExpression AS call
WHERE call.callee MATCHES "(?i)(fetch|axios|request|http\\.get|urllib)"
SELECT call, "Potential SSRF vulnerability"
```

## Advanced Features

### Parentheses for Grouping

```sql
WHERE (call.name == "eval" OR call.name == "exec")
      AND NOT call.isSafe == true
```

### Case-Insensitive Keywords

All SQL keywords are case-insensitive:

```sql
from CallExpression as call
where call.callee == "eval"
select call
```

### Multiple Select Items

```sql
SELECT call, "First message", "Second message", var
```

## Regex Patterns

GQL supports Rust regex syntax in `MATCHES` operator:

```sql
-- Case-insensitive: (?i)
WHERE name MATCHES "(?i)password"

-- Alternation: |
WHERE name MATCHES "eval|exec|system"

-- Character classes: [a-z]
WHERE name MATCHES "[A-Z][a-z]+"

-- Quantifiers: +, *, ?
WHERE name MATCHES "get.*Input"

-- Word boundaries: \b
WHERE name MATCHES "\beval\b"
```

## Best Practices

### 1. Be Specific

❌ **Too Broad:**
```sql
FROM CallExpression AS call
SELECT call
```

✅ **Specific:**
```sql
FROM CallExpression AS call
WHERE call.callee MATCHES "(?i)(eval|exec|system)"
SELECT call, "Dangerous function call"
```

### 2. Use Regex for Flexibility

❌ **Multiple Queries:**
```sql
WHERE name == "password" OR name == "passwd" OR name == "pwd"
```

✅ **Single Regex:**
```sql
WHERE name MATCHES "(?i)(password|passwd|pwd)"
```

### 3. Combine Conditions

```sql
WHERE call.name MATCHES "execute"
      AND call.argumentsCount > 0
      AND NOT call.text CONTAINS "prepared"
```

### 4. Provide Clear Messages

❌ **Vague:**
```sql
SELECT call, "Issue found"
```

✅ **Descriptive:**
```sql
SELECT call, "SQL injection: unsanitized user input in database query"
```

## Integration with SAST Engine

### Programmatic Usage

```rust
use gittera_query::{QueryParser, QueryExecutor};
use gittera_parser::{Parser, Language, LanguageConfig};
use gittera_analyzer::cfg::CfgBuilder;

// Parse source code
let parser = Parser::new(
    LanguageConfig::new(Language::TypeScript),
    Path::new("file.ts")
);
let ast = parser.parse_file()?;

// Build CFG
let cfg = CfgBuilder::new().build(&ast);

// Parse query
let query = QueryParser::parse(r#"
    FROM CallExpression AS call
    WHERE call.callee == "eval"
    SELECT call, "Dangerous eval() detected"
"#)?;

// Execute query
let results = QueryExecutor::execute(&query, &ast, &cfg, None);

// Process findings
for finding in results.findings {
    println!("{} at {}:{}", finding.message, finding.line, finding.column);
}
```

### Using Standard Library

```rust
use gittera_query::StandardLibrary;

// Get all OWASP Top 10 queries
let queries = StandardLibrary::owasp_queries();

for (rule_id, query) in queries {
    let results = QueryExecutor::execute(&query, &ast, &cfg, None);
    println!("Rule {}: {} findings", rule_id, results.findings.len());
}
```

## Performance Tips

1. **Order Predicates Efficiently**: Put cheap checks first
   ```sql
   WHERE call.argumentsCount > 0        -- Fast check
         AND call.callee MATCHES "..." -- Slower regex check
   ```

2. **Use Specific Entity Types**: Don't use `AnyNode` unless necessary
   ```sql
   FROM CallExpression AS call  -- Specific (fast)
   -- vs --
   FROM AnyNode AS node         -- Generic (slower)
   ```

3. **Limit Regex Complexity**: Simple patterns are faster
   ```sql
   MATCHES "eval|exec"          -- Simple (fast)
   MATCHES "(?i)(eval|exec)"    -- Case-insensitive (slightly slower)
   MATCHES ".*eval.*"           -- Wildcard (slower)
   ```

## Limitations

1. **No Inter-procedural Analysis**: Queries operate on single AST nodes
   - Cannot track data flow across function calls (yet)
   - No call graph traversal

2. **No Quantifiers**: Cannot express "for all" or "exists"
   - Example: "function with at least one eval call"

3. **No Aggregations**: Cannot count or group results
   - Example: "functions with more than 5 SQL queries"

4. **No Subqueries**: Cannot nest queries
   - Example: "calls that reference variables from another query"

## Future Enhancements

### Planned Features

1. **Taint Analysis Integration**
   ```sql
   WHERE call.isTainted() AND call.name == "execute"
   ```

2. **Data Flow Queries**
   ```sql
   FROM Source AS src TO Sink AS sink
   WHERE flowsTo(src, sink)
   ```

3. **Aggregations**
   ```sql
   SELECT fn, COUNT(call) AS call_count
   GROUP BY fn.name
   HAVING call_count > 5
   ```

4. **Subqueries**
   ```sql
   WHERE fn.name IN (
       FROM CallExpression SELECT callee
   )
   ```

## Troubleshooting

### Query Parse Errors

**Error:** "Unexpected token"
```sql
-- ❌ Missing AS keyword
FROM CallExpression call

-- ✅ Correct
FROM CallExpression AS call
```

**Error:** "Invalid entity type"
```sql
-- ❌ Typo
FROM FunctionCall AS fn

-- ✅ Correct entity types
FROM CallExpression AS call
FROM FunctionDeclaration AS fn
```

### No Results Found

1. **Check Entity Type**: Make sure you're searching for the right AST node type
2. **Verify Property Names**: Use correct property names (case-sensitive)
3. **Test Regex**: Test your regex pattern separately
4. **Check Language**: Ensure the parser supports your language

### Performance Issues

1. **Profile with Small Files First**: Test on small files before large codebases
2. **Simplify Regex**: Complex regex can slow down matching
3. **Use Specific Entity Types**: Avoid `AnyNode` when possible

## Summary

GQL provides a powerful, declarative way to detect security vulnerabilities:

- ✅ **SQL-like syntax** - familiar and easy to learn
- ✅ **Language-agnostic** - works across all supported languages
- ✅ **Regex support** - flexible pattern matching
- ✅ **No code changes** - add new rules without recompiling
- ✅ **Composable** - combine conditions with AND/OR/NOT
- ✅ **Extensible** - standard library of OWASP Top 10 queries

**Get Started:**
1. Write a simple query: `FROM CallExpression AS call WHERE call.callee == "eval" SELECT call`
2. Test it on your codebase
3. Refine with additional conditions
4. Add to your security rule library

Happy querying! 🔍
