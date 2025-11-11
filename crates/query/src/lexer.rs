//! Lexer for KQL

use logos::Logos;

#[derive(Logos, Debug, Clone, PartialEq)]
#[logos(skip r"[ \t\n\f]+")]
pub enum Token {
    #[token("from")]
    From,

    #[token("where")]
    Where,

    #[token("select")]
    Select,

    #[token("and")]
    And,

    #[token("or")]
    Or,

    #[token("not")]
    Not,

    #[token("=")]
    Equal,

    #[token("!=")]
    NotEqual,

    #[token("(")]
    LParen,

    #[token(")")]
    RParen,

    #[token(",")]
    Comma,

    #[token(".")]
    Dot,

    #[regex(r#""([^"\\]|\\.)*""#)]
    String,

    #[regex(r"[0-9]+")]
    Number,

    #[regex(r"[a-zA-Z_][a-zA-Z0-9_]*")]
    Identifier,

    #[token("//")]
    Comment,
}

pub struct Lexer<'source> {
    inner: logos::Lexer<'source, Token>,
}

impl<'source> Lexer<'source> {
    pub fn new(source: &'source str) -> Self {
        Self {
            inner: Token::lexer(source),
        }
    }
}

impl<'source> Iterator for Lexer<'source> {
    type Item = (Token, &'source str);

    fn next(&mut self) -> Option<Self::Item> {
        self.inner.next().map(|result| {
            let token = result.unwrap_or(Token::Identifier);
            let slice = self.inner.slice();
            (token, slice)
        })
    }
}
