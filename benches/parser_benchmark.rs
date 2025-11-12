use criterion::{black_box, criterion_group, criterion_main, Criterion, BenchmarkId, Throughput};
use kodecd_parser::{Parser, Language, LanguageConfig};
use std::path::Path;

// Sample TypeScript code of varying complexity
const SIMPLE_CODE: &str = r#"
const x = 42;
const y = "hello";
"#;

const MEDIUM_CODE: &str = r#"
function fibonacci(n: number): number {
    if (n <= 1) return n;
    return fibonacci(n - 1) + fibonacci(n - 2);
}

class Calculator {
    add(a: number, b: number): number {
        return a + b;
    }

    multiply(a: number, b: number): number {
        return a * b;
    }
}

const calc = new Calculator();
const result = calc.add(10, 20);
"#;

const COMPLEX_CODE: &str = r#"
import { Router } from 'express';
import { UserController } from './controllers/UserController';
import { AuthMiddleware } from './middleware/AuthMiddleware';

interface User {
    id: number;
    name: string;
    email: string;
    role: 'admin' | 'user' | 'guest';
}

class UserService {
    private users: Map<number, User> = new Map();

    async createUser(name: string, email: string, role: User['role']): Promise<User> {
        const id = this.users.size + 1;
        const user: User = { id, name, email, role };
        this.users.set(id, user);
        return user;
    }

    async getUser(id: number): Promise<User | undefined> {
        return this.users.get(id);
    }

    async updateUser(id: number, updates: Partial<User>): Promise<User | undefined> {
        const user = this.users.get(id);
        if (!user) return undefined;
        const updated = { ...user, ...updates };
        this.users.set(id, updated);
        return updated;
    }

    async deleteUser(id: number): Promise<boolean> {
        return this.users.delete(id);
    }

    async listUsers(): Promise<User[]> {
        return Array.from(this.users.values());
    }
}

const router = Router();
const userController = new UserController(new UserService());

router.get('/users', AuthMiddleware, userController.list);
router.get('/users/:id', AuthMiddleware, userController.get);
router.post('/users', AuthMiddleware, userController.create);
router.put('/users/:id', AuthMiddleware, userController.update);
router.delete('/users/:id', AuthMiddleware, userController.delete);

export default router;
"#;

fn bench_parser_simple(c: &mut Criterion) {
    let mut group = c.benchmark_group("parser_simple");
    group.throughput(Throughput::Bytes(SIMPLE_CODE.len() as u64));

    let config = LanguageConfig::new(Language::TypeScript);

    group.bench_function("standard", |b| {
        b.iter(|| {
            let parser = Parser::new(config.clone(), Path::new("bench.ts"));
            parser.parse_source(black_box(SIMPLE_CODE))
        });
    });

    group.finish();
}

fn bench_parser_medium(c: &mut Criterion) {
    let mut group = c.benchmark_group("parser_medium");
    group.throughput(Throughput::Bytes(MEDIUM_CODE.len() as u64));

    let config = LanguageConfig::new(Language::TypeScript);

    group.bench_function("standard", |b| {
        b.iter(|| {
            let parser = Parser::new(config.clone(), Path::new("bench.ts"));
            parser.parse_source(black_box(MEDIUM_CODE))
        });
    });

    group.finish();
}

fn bench_parser_complex(c: &mut Criterion) {
    let mut group = c.benchmark_group("parser_complex");
    group.throughput(Throughput::Bytes(COMPLEX_CODE.len() as u64));

    let config = LanguageConfig::new(Language::TypeScript);

    group.bench_function("standard", |b| {
        b.iter(|| {
            let parser = Parser::new(config.clone(), Path::new("bench.ts"));
            parser.parse_source(black_box(COMPLEX_CODE))
        });
    });

    group.finish();
}

fn bench_parser_languages(c: &mut Criterion) {
    let mut group = c.benchmark_group("parser_languages");

    let code = "const x = 42;\nfunction foo() { return 1; }";
    group.throughput(Throughput::Bytes(code.len() as u64));

    for lang in &[
        Language::TypeScript,
        Language::JavaScript,
        Language::Python,
        Language::Rust,
        Language::Java,
        Language::Go,
    ] {
        group.bench_with_input(BenchmarkId::from_parameter(format!("{:?}", lang)), lang, |b, &lang| {
            let config = LanguageConfig::new(lang);
            b.iter(|| {
                let parser = Parser::new(config.clone(), Path::new("bench"));
                parser.parse_source(black_box(code))
            });
        });
    }

    group.finish();
}

fn bench_parser_scaling(c: &mut Criterion) {
    let mut group = c.benchmark_group("parser_scaling");

    // Test parser performance with different input sizes
    for size in &[100, 500, 1000, 5000, 10000] {
        let code = format!("const x = 42;\n").repeat(*size);
        group.throughput(Throughput::Bytes(code.len() as u64));

        group.bench_with_input(BenchmarkId::from_parameter(size), &code, |b, code| {
            let config = LanguageConfig::new(Language::TypeScript);
            b.iter(|| {
                let parser = Parser::new(config.clone(), Path::new("bench.ts"));
                parser.parse_source(black_box(code))
            });
        });
    }

    group.finish();
}

criterion_group!(
    benches,
    bench_parser_simple,
    bench_parser_medium,
    bench_parser_complex,
    bench_parser_languages,
    bench_parser_scaling
);
criterion_main!(benches);
