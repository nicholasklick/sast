//! Benchmarks for analyzer components
//!
//! Tests performance of:
//! - Symbol table construction
//! - Call graph construction
//! - Points-to analysis
//! - Interprocedural taint analysis

use criterion::{black_box, criterion_group, criterion_main, Criterion, BenchmarkId, Throughput};
use gittera_analyzer::{
    SymbolTableBuilder, CallGraphBuilder, PointsToAnalysisBuilder, InterproceduralTaintAnalysis,
    TaintAnalysis, CfgBuilder,
};
use gittera_parser::{Language, LanguageConfig, Parser};
use std::path::Path;

// Test programs of varying complexity

const SIMPLE_PROGRAM: &str = r#"
function greet(name) {
    const message = "Hello, " + name;
    console.log(message);
}

const user = "Alice";
greet(user);
"#;

const MEDIUM_PROGRAM: &str = r#"
class User {
    constructor(name, email) {
        this.name = name;
        this.email = email;
    }

    getName() {
        return this.name;
    }

    setEmail(email) {
        this.email = email;
    }
}

function processUser(user) {
    const name = user.getName();
    console.log("Processing: " + name);
    return name.toUpperCase();
}

const users = [
    new User("Alice", "alice@example.com"),
    new User("Bob", "bob@example.com"),
];

users.forEach(user => {
    const processed = processUser(user);
    console.log(processed);
});
"#;

const COMPLEX_PROGRAM: &str = r#"
class Database {
    private static instance: Database;
    private connection: any;

    static {
        Database.instance = new Database();
    }

    private constructor() {
        this.connection = null;
    }

    static getInstance(): Database {
        return Database.instance;
    }

    connect(): void {
        console.log("Connecting...");
    }

    query(sql: string): any[] {
        return [];
    }
}

class UserRepository {
    private db: Database;

    constructor() {
        this.db = Database.getInstance();
    }

    findById(id: number): User | null {
        const results = this.db.query(`SELECT * FROM users WHERE id = ${id}`);
        if (results.length > 0) {
            return new User(results[0].name, results[0].email);
        }
        return null;
    }

    save(user: User): void {
        const sql = `INSERT INTO users (name, email) VALUES ('${user.name}', '${user.email}')`;
        this.db.query(sql);
    }
}

class UserService {
    private repository: UserRepository;

    constructor() {
        this.repository = new UserRepository();
    }

    createUser(name: string, email: string): User {
        const user = new User(name, email);
        this.repository.save(user);
        return user;
    }

    getUser(id: number): User | null {
        return this.repository.findById(id);
    }
}

class User {
    name: string;
    email: string;

    constructor(name: string, email: string) {
        this.name = name;
        this.email = email;
    }
}

// Application entry point
const service = new UserService();
const newUser = service.createUser("Alice", "alice@example.com");
const foundUser = service.getUser(1);
"#;

// Benchmark: Symbol Table Construction
fn bench_symbol_table(c: &mut Criterion) {
    let mut group = c.benchmark_group("symbol_table");

    let parser = Parser::new(
        LanguageConfig::new(Language::TypeScript),
        Path::new("test.ts")
    );

    for (name, code) in [
        ("simple", SIMPLE_PROGRAM),
        ("medium", MEDIUM_PROGRAM),
        ("complex", COMPLEX_PROGRAM),
    ] {
        group.throughput(Throughput::Bytes(code.len() as u64));
        group.bench_with_input(BenchmarkId::new("build", name), code, |b, code| {
            let ast = parser.parse_source(code).unwrap();
            b.iter(|| {
                SymbolTableBuilder::new().build(black_box(&ast))
            });
        });
    }

    group.finish();
}

// Benchmark: Call Graph Construction
fn bench_call_graph(c: &mut Criterion) {
    let mut group = c.benchmark_group("call_graph");

    let parser = Parser::new(
        LanguageConfig::new(Language::TypeScript),
        Path::new("test.ts")
    );

    for (name, code) in [
        ("simple", SIMPLE_PROGRAM),
        ("medium", MEDIUM_PROGRAM),
        ("complex", COMPLEX_PROGRAM),
    ] {
        group.throughput(Throughput::Bytes(code.len() as u64));
        group.bench_with_input(BenchmarkId::new("build", name), code, |b, code| {
            let ast = parser.parse_source(code).unwrap();
            b.iter(|| {
                CallGraphBuilder::new().build(black_box(&ast))
            });
        });
    }

    group.finish();
}

// Benchmark: Points-to Analysis
fn bench_points_to(c: &mut Criterion) {
    let mut group = c.benchmark_group("points_to");

    let parser = Parser::new(
        LanguageConfig::new(Language::TypeScript),
        Path::new("test.ts")
    );

    for (name, code) in [
        ("simple", SIMPLE_PROGRAM),
        ("medium", MEDIUM_PROGRAM),
        ("complex", COMPLEX_PROGRAM),
    ] {
        group.throughput(Throughput::Bytes(code.len() as u64));
        group.bench_with_input(BenchmarkId::new("analyze", name), code, |b, code| {
            let ast = parser.parse_source(code).unwrap();
            b.iter(|| {
                PointsToAnalysisBuilder::new().build(black_box(&ast))
            });
        });
    }

    group.finish();
}

// Benchmark: Interprocedural Taint Analysis
fn bench_interprocedural_taint(c: &mut Criterion) {
    let mut group = c.benchmark_group("interprocedural_taint");

    let parser = Parser::new(
        LanguageConfig::new(Language::TypeScript),
        Path::new("test.ts")
    );

    let taint_code = r#"
function getUserInput() {
    return prompt("Enter data:");
}

function sanitize(data) {
    return data.replace(/<script>/g, "");
}

function processData(input) {
    const processed = input.toUpperCase();
    return processed;
}

function displayResult(result) {
    document.getElementById("output").innerHTML = result;
}

// Taint flow: getUserInput -> processData -> displayResult
const userInput = getUserInput();
const processed = processData(userInput);
displayResult(processed);

// Sanitized flow: getUserInput -> sanitize -> displayResult
const raw = getUserInput();
const clean = sanitize(raw);
displayResult(clean);
"#;

    group.throughput(Throughput::Bytes(taint_code.len() as u64));
    group.bench_function("analyze", |b| {
        let ast = parser.parse_source(taint_code).unwrap();
        let call_graph = CallGraphBuilder::new().build(&ast);

        b.iter(|| {
            InterproceduralTaintAnalysis::new()
                .with_default_sources()
                .with_default_sinks()
                .with_default_sanitizers()
                .analyze(black_box(&ast), black_box(&call_graph))
        });
    });

    group.finish();
}

// Benchmark: Full Analysis Pipeline
fn bench_full_pipeline(c: &mut Criterion) {
    let mut group = c.benchmark_group("full_pipeline");
    group.sample_size(20); // Reduce sample size for expensive operation

    let parser = Parser::new(
        LanguageConfig::new(Language::TypeScript),
        Path::new("test.ts")
    );

    for (name, code) in [
        ("simple", SIMPLE_PROGRAM),
        ("medium", MEDIUM_PROGRAM),
        ("complex", COMPLEX_PROGRAM),
    ] {
        group.throughput(Throughput::Bytes(code.len() as u64));
        group.bench_with_input(BenchmarkId::new("all_analyses", name), code, |b, code| {
            b.iter(|| {
                // Parse
                let ast = parser.parse_source(code).unwrap();

                // Symbol table
                let _symbol_table = SymbolTableBuilder::new().build(&ast);

                // Call graph
                let call_graph = CallGraphBuilder::new().build(&ast);

                // Points-to analysis
                let _points_to = PointsToAnalysisBuilder::new().build(&ast);

                // CFG for taint analysis
                let cfg = CfgBuilder::new().build(&ast);

                // Taint analysis
                let _taint = TaintAnalysis::new()
                    .with_default_sources()
                    .with_default_sinks()
                    .with_default_sanitizers()
                    .analyze(&cfg, &ast);

                // Interprocedural taint
                let _interproc = InterproceduralTaintAnalysis::new()
                    .with_default_sources()
                    .with_default_sinks()
                    .with_default_sanitizers()
                    .analyze(&ast, &call_graph);

                black_box(());
            });
        });
    }

    group.finish();
}

// Benchmark: Scaling with Program Size
fn bench_scaling(c: &mut Criterion) {
    let mut group = c.benchmark_group("scaling");
    group.sample_size(20);

    let parser = Parser::new(
        LanguageConfig::new(Language::TypeScript),
        Path::new("test.ts")
    );

    // Generate programs of different sizes
    for num_functions in [10, 50, 100, 200] {
        let mut code = String::new();

        // Generate N simple functions with call chains
        for i in 0..num_functions {
            code.push_str(&format!(
                r#"
function func{}(input) {{
    const processed = input + "_{}";
    {}
    return processed;
}}
"#,
                i,
                i,
                if i > 0 {
                    format!("func{}(processed);", i - 1)
                } else {
                    String::new()
                }
            ));
        }

        // Add entry point
        code.push_str(&format!(
            r#"
const result = func{}("start");
console.log(result);
"#,
            num_functions - 1
        ));

        group.throughput(Throughput::Elements(num_functions as u64));
        group.bench_with_input(
            BenchmarkId::new("full_pipeline", num_functions),
            &code,
            |b, code| {
                b.iter(|| {
                    let ast = parser.parse_source(code).unwrap();
                    let _symbol_table = SymbolTableBuilder::new().build(&ast);
                    let _call_graph = CallGraphBuilder::new().build(&ast);
                    let cfg = CfgBuilder::new().build(&ast);
                    let _taint = TaintAnalysis::new()
                        .with_default_sources()
                        .with_default_sinks()
                        .with_default_sanitizers()
                        .analyze(&cfg, &ast);
                    black_box(());
                });
            },
        );
    }

    group.finish();
}

criterion_group!(
    benches,
    bench_symbol_table,
    bench_call_graph,
    bench_points_to,
    bench_interprocedural_taint,
    bench_full_pipeline,
    bench_scaling,
);
criterion_main!(benches);
