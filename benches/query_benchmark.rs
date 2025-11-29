use criterion::{black_box, criterion_group, criterion_main, Criterion, BenchmarkId};
use gittera_query::{QueryParser, QueryExecutor};
use gittera_parser::{Parser, Language, LanguageConfig};
use gittera_analyzer::CfgBuilder;
use std::path::Path;

// Sample queries
const SIMPLE_QUERY: &str = r#"
FROM CallExpression AS call
WHERE call.callee == "eval"
SELECT call, "Use of eval()"
"#;

const COMPLEX_QUERY: &str = r#"
FROM CallExpression AS call
WHERE (call.callee MATCHES "(?i)(eval|exec|system|Function)" OR call.callee CONTAINS "execute")
      AND NOT call.callee STARTS_WITH "safe"
SELECT call, "Dangerous function call detected"
"#;

const TAINT_QUERY: &str = r#"
FROM CallExpression AS call
WHERE call.callee MATCHES "(?i)(execute|query)"
      AND call.isTainted()
SELECT call, "SQL injection vulnerability"
"#;

// Sample code to run queries against
const TEST_CODE: &str = r#"
const userInput = getUserInput();
const query = "SELECT * FROM users WHERE id = " + userInput;
database.execute(query);

eval(userInput);
exec(systemCommand);

const safe = sanitize(input);
safeExecute(safe);
"#;

fn bench_query_parsing(c: &mut Criterion) {
    let mut group = c.benchmark_group("query_parsing");

    group.bench_function("simple", |b| {
        b.iter(|| {
            QueryParser::parse(black_box(SIMPLE_QUERY))
        });
    });

    group.bench_function("complex", |b| {
        b.iter(|| {
            QueryParser::parse(black_box(COMPLEX_QUERY))
        });
    });

    group.bench_function("taint", |b| {
        b.iter(|| {
            QueryParser::parse(black_box(TAINT_QUERY))
        });
    });

    group.finish();
}

fn bench_query_execution(c: &mut Criterion) {
    let mut group = c.benchmark_group("query_execution");

    // Prepare AST and CFG once
    let parser = Parser::new(
        LanguageConfig::new(Language::TypeScript),
        Path::new("test.ts")
    );
    let ast = parser.parse_source(TEST_CODE).unwrap();
    let cfg = CfgBuilder::new().build(&ast);

    group.bench_function("simple", |b| {
        let query = QueryParser::parse(SIMPLE_QUERY).unwrap();
        b.iter(|| {
            QueryExecutor::execute(black_box(&query), black_box(&ast), black_box(&cfg), None)
        });
    });

    group.bench_function("complex", |b| {
        let query = QueryParser::parse(COMPLEX_QUERY).unwrap();
        b.iter(|| {
            QueryExecutor::execute(black_box(&query), black_box(&ast), black_box(&cfg), None)
        });
    });

    group.finish();
}

fn bench_query_stdlib(c: &mut Criterion) {
    use gittera_query::StandardLibrary;

    let mut group = c.benchmark_group("query_stdlib");

    let queries = StandardLibrary::owasp_queries();

    // Prepare AST and CFG
    let parser = Parser::new(
        LanguageConfig::new(Language::TypeScript),
        Path::new("test.ts")
    );
    let ast = parser.parse_source(TEST_CODE).unwrap();
    let cfg = CfgBuilder::new().build(&ast);

    // Benchmark all OWASP queries
    for (id, query) in queries.iter().take(5) {  // First 5 for speed
        group.bench_with_input(
            BenchmarkId::from_parameter(id),
            query,
            |b, query| {
                b.iter(|| {
                    QueryExecutor::execute(black_box(query), black_box(&ast), black_box(&cfg), None)
                });
            }
        );
    }

    group.finish();
}

fn bench_query_operators(c: &mut Criterion) {
    let mut group = c.benchmark_group("query_operators");

    let parser = Parser::new(
        LanguageConfig::new(Language::TypeScript),
        Path::new("test.ts")
    );
    let ast = parser.parse_source(TEST_CODE).unwrap();
    let cfg = CfgBuilder::new().build(&ast);

    let operators = vec![
        ("equals", r#"FROM CallExpression AS c WHERE c.callee == "eval" SELECT c, "msg""#),
        ("contains", r#"FROM CallExpression AS c WHERE c.callee CONTAINS "exec" SELECT c, "msg""#),
        ("starts_with", r#"FROM CallExpression AS c WHERE c.callee STARTS_WITH "eval" SELECT c, "msg""#),
        ("ends_with", r#"FROM CallExpression AS c WHERE c.callee ENDS_WITH "Sync" SELECT c, "msg""#),
        ("matches", r#"FROM CallExpression AS c WHERE c.callee MATCHES "(?i)eval" SELECT c, "msg""#),
    ];

    for (name, query_str) in operators {
        group.bench_function(name, |b| {
            let query = QueryParser::parse(query_str).unwrap();
            b.iter(|| {
                QueryExecutor::execute(black_box(&query), black_box(&ast), black_box(&cfg), None)
            });
        });
    }

    group.finish();
}

criterion_group!(
    benches,
    bench_query_parsing,
    bench_query_execution,
    bench_query_stdlib,
    bench_query_operators
);
criterion_main!(benches);
