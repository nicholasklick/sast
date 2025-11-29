use gittera_query::parser::QueryParser;

fn main() {
    let query = r#"
        FROM MethodCall AS mc
        WHERE mc.getName() == "eval"
        SELECT mc
    "#;
    
    match QueryParser::parse(query) {
        Ok(q) => {
            println!("Success!");
            println!("{:#?}", q);
        }
        Err(e) => {
            println!("Error: {}", e);
        }
    }

    // Test simpler query
    let simple = r#"FROM MethodCall AS mc WHERE mc.name == "eval" SELECT mc"#;
    match QueryParser::parse(simple) {
        Ok(q) => println!("Simple query works!"),
        Err(e) => println!("Simple query failed: {}", e),
    }
}
