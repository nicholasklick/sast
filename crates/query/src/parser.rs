//! Parser for GQL queries using nom

use crate::ast::*;
use nom::{
    branch::alt,
    bytes::complete::{tag, tag_no_case, take_while1},
    character::complete::{alpha1, alphanumeric1, char, multispace0, digit1},
    combinator::{map, opt, recognize, value},
    multi::{many0, separated_list0, separated_list1},
    sequence::{delimited, pair, preceded, tuple},
    IResult,
};
use thiserror::Error;

#[derive(Error, Debug)]
pub enum ParseError {
    #[error("Unexpected token: {0}")]
    UnexpectedToken(String),
    #[error("Expected {0}, found {1}")]
    Expected(String, String),
    #[error("Invalid query syntax: {0}")]
    InvalidSyntax(String),
    #[error("Parse error: {0}")]
    Nom(String),
}

pub struct QueryParser;

impl QueryParser {
    pub fn parse(source: &str) -> Result<Query, ParseError> {
        match parse_query(source) {
            Ok((remaining, query)) => {
                let remaining = remaining.trim();
                if !remaining.is_empty() {
                    return Err(ParseError::InvalidSyntax(format!(
                        "Unexpected input after query: {}",
                        remaining
                    )));
                }
                Ok(query)
            }
            Err(e) => Err(ParseError::Nom(format!("{}", e))),
        }
    }
}

// Helper: parse whitespace
fn ws<'a, F, O>(inner: F) -> impl FnMut(&'a str) -> IResult<&'a str, O>
where
    F: FnMut(&'a str) -> IResult<&'a str, O>,
{
    delimited(multispace0, inner, multispace0)
}

// Parse identifier: starts with letter or underscore, followed by alphanumeric or underscore
fn identifier(input: &str) -> IResult<&str, String> {
    map(
        recognize(pair(
            alt((alpha1, tag("_"))),
            many0(alt((alphanumeric1, tag("_")))),
        )),
        |s: &str| s.to_string(),
    )(input)
}

// Parse string literal: "..." or '...'
fn string_literal(input: &str) -> IResult<&str, String> {
    alt((
        delimited(
            char('"'),
            map(
                take_while1(|c| c != '"'),
                |s: &str| s.to_string(),
            ),
            char('"'),
        ),
        delimited(
            char('\''),
            map(
                take_while1(|c| c != '\''),
                |s: &str| s.to_string(),
            ),
            char('\''),
        ),
    ))(input)
}

// Parse number literal
fn number_literal(input: &str) -> IResult<&str, i64> {
    map(
        recognize(pair(opt(char('-')), digit1)),
        |s: &str| s.parse::<i64>().unwrap(),
    )(input)
}

// Parse boolean literal
fn boolean_literal(input: &str) -> IResult<&str, bool> {
    alt((
        value(true, tag_no_case("true")),
        value(false, tag_no_case("false")),
    ))(input)
}

// Parse entity type
fn entity_type(input: &str) -> IResult<&str, EntityType> {
    alt((
        value(EntityType::MethodCall, tag_no_case("MethodCall")),
        value(EntityType::FunctionDeclaration, tag_no_case("FunctionDeclaration")),
        value(EntityType::VariableDeclaration, tag_no_case("VariableDeclaration")),
        value(EntityType::Assignment, tag_no_case("Assignment")),
        value(EntityType::Literal, tag_no_case("Literal")),
        value(EntityType::BinaryExpression, tag_no_case("BinaryExpression")),
        value(EntityType::CallExpression, tag_no_case("CallExpression")),
        value(EntityType::MemberExpression, tag_no_case("MemberExpression")),
        value(EntityType::AnyNode, tag_no_case("AnyNode")),
    ))(input)
}

// Parse FROM clause: FROM EntityType AS variable
fn from_clause(input: &str) -> IResult<&str, FromClause> {
    map(
        tuple((
            ws(tag_no_case("FROM")),
            ws(entity_type),
            ws(tag_no_case("AS")),
            ws(identifier),
        )),
        |(_, entity, _, variable)| FromClause::new(entity, variable),
    )(input)
}

// Parse comparison operators
fn comparison_op(input: &str) -> IResult<&str, ComparisonOp> {
    alt((
        value(ComparisonOp::NotEqual, ws(tag("!="))),
        value(ComparisonOp::Equal, ws(tag("=="))),
        value(ComparisonOp::Equal, ws(tag("="))),
        value(ComparisonOp::Contains, ws(tag_no_case("CONTAINS"))),
        value(ComparisonOp::StartsWith, ws(tag_no_case("STARTS_WITH"))),
        value(ComparisonOp::EndsWith, ws(tag_no_case("ENDS_WITH"))),
        value(ComparisonOp::Matches, ws(tag_no_case("MATCHES"))),
    ))(input)
}

// Parse primary expression (variable, string, number, boolean, or parenthesized expression)
fn primary_expression(input: &str) -> IResult<&str, Expression> {
    alt((
        // Parenthesized expression
        delimited(ws(char('(')), expression, ws(char(')'))),
        // Literals
        map(boolean_literal, Expression::Boolean),
        map(number_literal, Expression::Number),
        map(string_literal, Expression::String),
        // Variable
        map(identifier, Expression::Variable),
    ))(input)
}

// Parse postfix expression: handles property access and method calls
fn postfix_expression(input: &str) -> IResult<&str, Expression> {
    let (mut remaining, mut expr) = primary_expression(input)?;

    loop {
        // Save current position
        let checkpoint = remaining;

        // Try to parse a dot for property access or method call
        match ws(char('.'))(remaining) {
            Ok((after_dot, _)) => {
                // Parse the identifier after the dot
                match ws(identifier)(after_dot) {
                    Ok((after_id, property)) => {
                        // Check if it's a method call (followed by parentheses)
                        match ws(char('('))(after_id) {
                            Ok((after_paren, _)) => {
                                // Method call: obj.method(args)
                                match separated_list0(ws(char(',')), expression)(after_paren) {
                                    Ok((after_args, args)) => {
                                        match ws(char(')'))(after_args) {
                                            Ok((after_close, _)) => {
                                                expr = Expression::MethodCall {
                                                    object: Box::new(expr),
                                                    method: property,
                                                    arguments: args,
                                                };
                                                remaining = after_close;
                                            }
                                            Err(_) => {
                                                // Not a valid method call, restore and break
                                                remaining = checkpoint;
                                                break;
                                            }
                                        }
                                    }
                                    Err(_) => {
                                        remaining = checkpoint;
                                        break;
                                    }
                                }
                            }
                            Err(_) => {
                                // Property access: obj.prop
                                expr = Expression::PropertyAccess {
                                    object: Box::new(expr),
                                    property,
                                };
                                remaining = after_id;
                            }
                        }
                    }
                    Err(_) => {
                        remaining = checkpoint;
                        break;
                    }
                }
            }
            Err(_) => {
                // No more postfix operations
                break;
            }
        }
    }

    Ok((remaining, expr))
}

// Parse expression
fn expression(input: &str) -> IResult<&str, Expression> {
    postfix_expression(input)
}

// Parse comparison predicate: expr op expr
fn comparison_predicate(input: &str) -> IResult<&str, Predicate> {
    map(
        tuple((
            ws(expression),
            ws(comparison_op),
            ws(expression),
        )),
        |(left, operator, right)| Predicate::Comparison { left, operator, right },
    )(input)
}

// Parse primary predicate
fn primary_predicate(input: &str) -> IResult<&str, Predicate> {
    alt((
        // Parenthesized predicate
        delimited(ws(char('(')), predicate, ws(char(')'))),
        // NOT predicate
        map(
            preceded(ws(tag_no_case("NOT")), primary_predicate),
            |pred| Predicate::Not { predicate: Box::new(pred) },
        ),
        // Comparison predicate (handles all expressions including method calls)
        comparison_predicate,
    ))(input)
}

// Parse AND predicate
fn and_predicate(input: &str) -> IResult<&str, Predicate> {
    let (input, first) = primary_predicate(input)?;
    let (input, rest) = many0(preceded(
        ws(tag_no_case("AND")),
        primary_predicate,
    ))(input)?;

    Ok((input, rest.into_iter().fold(first, |acc, pred| {
        Predicate::And {
            left: Box::new(acc),
            right: Box::new(pred),
        }
    })))
}

// Parse OR predicate (lowest precedence)
fn predicate(input: &str) -> IResult<&str, Predicate> {
    let (input, first) = and_predicate(input)?;
    let (input, rest) = many0(preceded(
        ws(tag_no_case("OR")),
        and_predicate,
    ))(input)?;

    Ok((input, rest.into_iter().fold(first, |acc, pred| {
        Predicate::Or {
            left: Box::new(acc),
            right: Box::new(pred),
        }
    })))
}

// Parse WHERE clause
fn where_clause(input: &str) -> IResult<&str, WhereClause> {
    map(
        preceded(
            ws(tag_no_case("WHERE")),
            separated_list1(ws(tag_no_case("AND")), predicate),
        ),
        |predicates| WhereClause::new(predicates),
    )(input)
}

// Parse select item (individual item without comma parsing)
fn select_item_inner(input: &str) -> IResult<&str, SelectItem> {
    alt((
        // Just message: "message"
        map(string_literal, SelectItem::Message),
        // Just variable: variable
        map(identifier, SelectItem::Variable),
    ))(input)
}

// Parse SELECT clause
fn select_clause(input: &str) -> IResult<&str, SelectClause> {
    map(
        preceded(
            ws(tag_no_case("SELECT")),
            separated_list1(ws(char(',')), ws(select_item_inner)),
        ),
        |items| {
            // Check if we have a pattern of variable followed by message
            if items.len() == 2 {
                if let (SelectItem::Variable(var), SelectItem::Message(msg)) = (&items[0], &items[1]) {
                    return SelectClause::new(vec![SelectItem::Both {
                        variable: var.clone(),
                        message: msg.clone(),
                    }]);
                }
            }
            SelectClause::new(items)
        },
    )(input)
}

// Parse complete query
fn parse_query(input: &str) -> IResult<&str, Query> {
    map(
        tuple((
            ws(from_clause),
            opt(ws(where_clause)),
            ws(select_clause),
        )),
        |(from, where_clause, select)| Query::new(from, where_clause, select),
    )(input)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_simple_query() {
        let query = "FROM MethodCall AS mc SELECT mc";
        let result = QueryParser::parse(query);
        assert!(result.is_ok());
        let q = result.unwrap();
        assert_eq!(q.from.variable, "mc");
        assert!(matches!(q.from.entity, EntityType::MethodCall));
        assert!(q.where_clause.is_none());
    }

    #[test]
    fn test_query_with_where() {
        let query = r#"
            FROM MethodCall AS mc
            WHERE mc.name == "eval"
            SELECT mc
        "#;
        let result = QueryParser::parse(query);
        assert!(result.is_ok());
        let q = result.unwrap();
        assert!(q.where_clause.is_some());
    }

    #[test]
    fn test_query_with_and_or() {
        let query = r#"
            FROM MethodCall AS mc
            WHERE mc.name == "eval" OR mc.name == "exec" AND mc.isTainted == true
            SELECT mc
        "#;
        let result = QueryParser::parse(query);
        assert!(result.is_ok());
    }

    #[test]
    fn test_select_with_message() {
        let query = r#"
            FROM MethodCall AS mc
            SELECT mc, "Dangerous eval call detected"
        "#;
        let result = QueryParser::parse(query);
        assert!(result.is_ok());
        let q = result.unwrap();
        assert_eq!(q.select.items.len(), 1);
        match &q.select.items[0] {
            SelectItem::Both { variable, message } => {
                assert_eq!(variable, "mc");
                assert_eq!(message, "Dangerous eval call detected");
            }
            _ => panic!("Expected Both variant"),
        }
    }

    #[test]
    fn test_property_access() {
        let query = r#"
            FROM MethodCall AS mc
            WHERE mc.name.value == "eval"
            SELECT mc
        "#;
        let result = QueryParser::parse(query);
        assert!(result.is_ok());
    }

    #[test]
    fn test_not_predicate() {
        let query = r#"
            FROM MethodCall AS mc
            WHERE NOT mc.name == "safe"
            SELECT mc
        "#;
        let result = QueryParser::parse(query);
        assert!(result.is_ok());
    }

    #[test]
    fn test_comparison_operators() {
        let tests = vec![
            (r#"WHERE mc.name == "eval""#, ComparisonOp::Equal),
            (r#"WHERE mc.name != "safe""#, ComparisonOp::NotEqual),
            (r#"WHERE mc.name CONTAINS "eval""#, ComparisonOp::Contains),
            (r#"WHERE mc.name STARTS_WITH "ev""#, ComparisonOp::StartsWith),
            (r#"WHERE mc.name ENDS_WITH "al""#, ComparisonOp::EndsWith),
            (r#"WHERE mc.name MATCHES "ev.*""#, ComparisonOp::Matches),
        ];

        for (input, _expected_op) in tests {
            let result = where_clause(input);
            assert!(result.is_ok(), "Failed to parse: {}", input);
        }
    }

    #[test]
    fn test_complex_nested_predicates() {
        let query = r#"
            FROM MethodCall AS mc
            WHERE (mc.name == "eval" OR mc.name == "exec")
                AND NOT mc.isSafe == true
            SELECT mc
        "#;
        let result = QueryParser::parse(query);
        assert!(result.is_ok(), "Failed to parse complex nested predicates");
    }

    #[test]
    fn test_method_call_in_expression() {
        let query = r#"
            FROM MethodCall AS mc
            WHERE mc.getName() == "eval"
            SELECT mc
        "#;
        let result = QueryParser::parse(query);
        assert!(result.is_ok(), "Failed to parse method call in expression");
    }

    #[test]
    fn test_multiple_select_items() {
        let query = r#"
            FROM MethodCall AS mc
            WHERE mc.name == "eval"
            SELECT mc, "Dangerous eval call", "High severity"
        "#;
        let result = QueryParser::parse(query);
        assert!(result.is_ok(), "Failed to parse multiple select items");
        let q = result.unwrap();
        assert_eq!(q.select.items.len(), 3);
    }

    #[test]
    fn test_number_and_boolean_in_predicates() {
        let query = r#"
            FROM MethodCall AS mc
            WHERE mc.lineNumber == 42 AND mc.isTainted == true
            SELECT mc
        "#;
        let result = QueryParser::parse(query);
        assert!(result.is_ok(), "Failed to parse numbers and booleans");
    }

    #[test]
    fn test_nested_property_access() {
        let query = r#"
            FROM MethodCall AS mc
            WHERE mc.callee.name == "eval"
            SELECT mc
        "#;
        let result = QueryParser::parse(query);
        assert!(result.is_ok(), "Failed to parse nested property access");
    }

    #[test]
    fn test_all_entity_types() {
        let entity_types = vec![
            "MethodCall",
            "FunctionDeclaration",
            "VariableDeclaration",
            "Assignment",
            "Literal",
            "BinaryExpression",
            "CallExpression",
            "AnyNode",
        ];

        for entity in entity_types {
            let query = format!("FROM {} AS x SELECT x", entity);
            let result = QueryParser::parse(&query);
            assert!(result.is_ok(), "Failed to parse entity type: {}", entity);
        }
    }

    #[test]
    fn test_case_insensitive_keywords() {
        let query = "from MethodCall as mc where mc.name == \"eval\" select mc";
        let result = QueryParser::parse(query);
        assert!(result.is_ok(), "Failed to parse case-insensitive keywords");
    }

    #[test]
    fn test_invalid_query_syntax() {
        // Missing SELECT
        let query1 = "FROM MethodCall AS mc WHERE mc.name == \"eval\"";
        assert!(QueryParser::parse(query1).is_err());

        // Missing FROM
        let query2 = "SELECT mc";
        assert!(QueryParser::parse(query2).is_err());

        // Invalid entity type
        let query3 = "FROM InvalidType AS x SELECT x";
        assert!(QueryParser::parse(query3).is_err());
    }
}
