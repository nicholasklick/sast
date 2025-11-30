# GQL Quick Reference

## Query Structure

```sql
FROM <EntityType> AS <variable>
[WHERE <predicates>]
SELECT <items>
```

## Entity Types

| Type | Description |
|------|-------------|
| `CallExpression` | Function/method calls |
| `FunctionDeclaration` | Function definitions |
| `VariableDeclaration` | Variable declarations |
| `MemberExpression` | Property access (obj.prop) |
| `BinaryExpression` | Binary operations (+, -, ==, etc.) |
| `Literal` | Literal values (strings, numbers) |
| `Assignment` | Assignments (x = y) |
| `AnyNode` | Any AST node |

## Operators

| Operator | Example |
|----------|---------|
| `==` or `=` | `name == "eval"` |
| `!=` | `name != "safe"` |
| `CONTAINS` | `name CONTAINS "password"` |
| `STARTS_WITH` | `name STARTS_WITH "get"` |
| `ENDS_WITH` | `name ENDS_WITH "Input"` |
| `MATCHES` | `name MATCHES "eval\|exec"` |
| `AND` | `a == 1 AND b == 2` |
| `OR` | `a == 1 OR b == 2` |
| `NOT` | `NOT name == "safe"` |

## Common Properties

```sql
node.name           -- Name
node.text           -- Source code text
node.line           -- Line number
node.column         -- Column number
call.callee         -- Function name (CallExpression)
call.argumentsCount -- Argument count (CallExpression)
fn.parameterCount   -- Parameter count (FunctionDeclaration)
member.object       -- Object (MemberExpression)
member.property     -- Property (MemberExpression)
binop.operator      -- Operator (BinaryExpression)
```

## Common Patterns

### Find dangerous function calls
```sql
FROM CallExpression AS call
WHERE call.callee MATCHES "(?i)(eval|exec|system)"
SELECT call, "Dangerous function"
```

### Find secrets
```sql
FROM VariableDeclaration AS vd
WHERE vd.name MATCHES "(?i)(password|secret|api_?key)"
SELECT vd, "Hardcoded secret"
```

### Find XSS sinks
```sql
FROM MemberExpression AS m
WHERE m.property MATCHES "(?i)(innerHTML|outerHTML)"
SELECT m, "XSS vulnerability"
```

### Complex conditions
```sql
FROM FunctionDeclaration AS fn
WHERE (fn.name CONTAINS "unsafe" OR fn.name CONTAINS "exec")
      AND NOT fn.name STARTS_WITH "test"
      AND fn.parameterCount > 0
SELECT fn, "Unsafe function"
```

## Regex Syntax

| Pattern | Description | Example |
|---------|-------------|---------|
| `(?i)` | Case-insensitive | `(?i)password` |
| `\|` | Alternation (OR) | `eval\|exec` |
| `.` | Any character | `get.*` |
| `*` | 0 or more | `a*` |
| `+` | 1 or more | `a+` |
| `?` | 0 or 1 | `a?` |
| `[a-z]` | Character class | `[0-9]+` |
| `\b` | Word boundary | `\beval\b` |
| `^` | Start of string | `^get` |
| `$` | End of string | `Input$` |

## Tips

1. **Use specific entity types** for better performance
2. **Put cheap checks first** in WHERE clause
3. **Use regex for multiple alternatives**: `MATCHES "a\|b\|c"` vs `== "a" OR == "b" OR == "c"`
4. **Add (?i) for case-insensitive** matching
5. **Provide descriptive messages** in SELECT clause
