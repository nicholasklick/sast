use criterion::{black_box, criterion_group, criterion_main, Criterion, BenchmarkId, Throughput};
use kodecd_parser::{Parser, Language, LanguageConfig};
use kodecd_analyzer::{CfgBuilder, TaintAnalysis};
use std::path::Path;

const SIMPLE_TAINT: &str = r#"
const userInput = getUserInput();
database.execute(userInput);
"#;

const MEDIUM_TAINT: &str = r#"
function processRequest(req) {
    const userInput = req.query.id;
    const sanitized = sanitize(userInput);

    if (isValid(userInput)) {
        const query = "SELECT * FROM users WHERE id = " + userInput;
        database.execute(query);
    }

    const safe = escape(sanitized);
    return safe;
}
"#;

const COMPLEX_TAINT: &str = r#"
class UserController {
    async handleRequest(req, res) {
        const userId = req.params.id;
        const email = req.body.email;
        const name = req.body.name;

        // Vulnerable path
        const query1 = `SELECT * FROM users WHERE id = ${userId}`;
        await database.execute(query1);

        // Sanitized path
        const sanitizedEmail = validator.escape(email);
        const query2 = `SELECT * FROM users WHERE email = '${sanitizedEmail}'`;
        await database.execute(query2);

        // Safe parameterized query
        await database.query('SELECT * FROM users WHERE name = ?', [name]);

        // Command injection
        const command = `ls -la ${req.query.path}`;
        exec(command);

        // XSS vulnerability
        res.send(`<div>Hello ${userId}</div>`);

        return res.json({ success: true });
    }

    async updateUser(userId, data) {
        const updates = [];
        for (const [key, value] of Object.entries(data)) {
            updates.push(`${key} = '${value}'`);
        }
        const query = `UPDATE users SET ${updates.join(', ')} WHERE id = ${userId}`;
        return database.execute(query);
    }
}
"#;

fn bench_cfg_build(c: &mut Criterion) {
    let mut group = c.benchmark_group("cfg_build");

    let parser = Parser::new(
        LanguageConfig::new(Language::TypeScript),
        Path::new("test.ts")
    );

    group.bench_function("simple", |b| {
        let ast = parser.parse_source(SIMPLE_TAINT).unwrap();
        b.iter(|| {
            CfgBuilder::new().build(black_box(&ast))
        });
    });

    group.bench_function("medium", |b| {
        let ast = parser.parse_source(MEDIUM_TAINT).unwrap();
        b.iter(|| {
            CfgBuilder::new().build(black_box(&ast))
        });
    });

    group.bench_function("complex", |b| {
        let ast = parser.parse_source(COMPLEX_TAINT).unwrap();
        b.iter(|| {
            CfgBuilder::new().build(black_box(&ast))
        });
    });

    group.finish();
}

fn bench_taint_analysis(c: &mut Criterion) {
    let mut group = c.benchmark_group("taint_analysis");

    let parser = Parser::new(
        LanguageConfig::new(Language::TypeScript),
        Path::new("test.ts")
    );

    let taint = TaintAnalysis::new()
        .with_default_sources()
        .with_default_sinks()
        .with_default_sanitizers();

    group.bench_function("simple", |b| {
        let ast = parser.parse_source(SIMPLE_TAINT).unwrap();
        let cfg = CfgBuilder::new().build(&ast);
        b.iter(|| {
            taint.analyze(black_box(&cfg), black_box(&ast))
        });
    });

    group.bench_function("medium", |b| {
        let ast = parser.parse_source(MEDIUM_TAINT).unwrap();
        let cfg = CfgBuilder::new().build(&ast);
        b.iter(|| {
            taint.analyze(black_box(&cfg), black_box(&ast))
        });
    });

    group.bench_function("complex", |b| {
        let ast = parser.parse_source(COMPLEX_TAINT).unwrap();
        let cfg = CfgBuilder::new().build(&ast);
        b.iter(|| {
            taint.analyze(black_box(&cfg), black_box(&ast))
        });
    });

    group.finish();
}

fn bench_taint_analysis_config(c: &mut Criterion) {
    let mut group = c.benchmark_group("taint_analysis_config");

    let parser = Parser::new(
        LanguageConfig::new(Language::TypeScript),
        Path::new("test.ts")
    );
    let ast = parser.parse_source(COMPLEX_TAINT).unwrap();
    let cfg = CfgBuilder::new().build(&ast);

    group.bench_function("default", |b| {
        let taint = TaintAnalysis::new()
            .with_default_sources()
            .with_default_sinks()
            .with_default_sanitizers();
        b.iter(|| {
            taint.analyze(black_box(&cfg), black_box(&ast))
        });
    });

    group.bench_function("sources_only", |b| {
        let taint = TaintAnalysis::new()
            .with_default_sources();
        b.iter(|| {
            taint.analyze(black_box(&cfg), black_box(&ast))
        });
    });

    group.bench_function("no_sanitizers", |b| {
        let taint = TaintAnalysis::new()
            .with_default_sources()
            .with_default_sinks();
        b.iter(|| {
            taint.analyze(black_box(&cfg), black_box(&ast))
        });
    });

    group.finish();
}

fn bench_full_pipeline(c: &mut Criterion) {
    let mut group = c.benchmark_group("full_pipeline");
    group.throughput(Throughput::Bytes(COMPLEX_TAINT.len() as u64));

    let taint = TaintAnalysis::new()
        .with_default_sources()
        .with_default_sinks()
        .with_default_sanitizers();

    group.bench_function("parse_cfg_taint", |b| {
        b.iter(|| {
            let parser = Parser::new(
                LanguageConfig::new(Language::TypeScript),
                Path::new("test.ts")
            );
            let ast = parser.parse_source(black_box(COMPLEX_TAINT)).unwrap();
            let cfg = CfgBuilder::new().build(&ast);
            taint.analyze(&cfg, &ast)
        });
    });

    group.finish();
}

fn bench_taint_scaling(c: &mut Criterion) {
    let mut group = c.benchmark_group("taint_scaling");

    let taint = TaintAnalysis::new()
        .with_default_sources()
        .with_default_sinks()
        .with_default_sanitizers();

    // Test with different numbers of taint flows
    for count in &[1, 5, 10, 20] {
        let code = format!(
            "{}",
            (0..*count)
                .map(|i| format!(
                    "const input{} = getUserInput();\ndatabase.execute(input{});\n",
                    i, i
                ))
                .collect::<String>()
        );

        group.throughput(Throughput::Elements(*count as u64));

        group.bench_with_input(BenchmarkId::from_parameter(count), &code, |b, code| {
            let parser = Parser::new(
                LanguageConfig::new(Language::TypeScript),
                Path::new("test.ts")
            );
            let ast = parser.parse_source(code).unwrap();
            let cfg = CfgBuilder::new().build(&ast);

            b.iter(|| {
                taint.analyze(black_box(&cfg), black_box(&ast))
            });
        });
    }

    group.finish();
}

criterion_group!(
    benches,
    bench_cfg_build,
    bench_taint_analysis,
    bench_taint_analysis_config,
    bench_full_pipeline,
    bench_taint_scaling
);
criterion_main!(benches);
