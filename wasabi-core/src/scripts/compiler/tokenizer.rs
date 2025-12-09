use crate::scripts::compiler::context::CompilationContext;
use crate::scripts::compiler::span::ByteSpan;
use logos::{Lexer, Logos};
use std::fmt::{Display, Formatter};

#[derive(Logos, Debug, PartialEq, Clone)]
#[logos(skip r"([ \t\n\f]+|//[^\n]*\n)")]
pub enum Token {
    #[token("if")]
    KeywordIf,
    #[token("else")]
    KeywordElse,
    #[token("fn")]
    KeywordFn,
    #[token("true")]
    KeywordTrue,
    #[token("false")]
    KeywordFalse,

    #[regex(r"[a-zA-Z_][a-zA-Z0-9_\-]*(::[a-zA-Z0-9_\-]+)*")]
    Ident,
    #[regex(r"[0-9][0-9_]*(\.[0-9]+)?")]
    Number,
    #[regex(r#""([^"\\]|\\.)*""#)]
    String,

    #[token("(")]
    LParen,
    #[token(")")]
    RParen,
    #[token("{")]
    LCurly,
    #[token("}")]
    RCurly,
    #[token(",")]
    Comma,
    #[token(";")]
    Semicolon,
    #[token(".")]
    Dot,
    #[token(":")]
    Colon,
    #[token("!")]
    Exclamation,
    #[token("+")]
    Add,
    #[token("-")]
    Subtract,
    #[token("*")]
    Multiply,
    #[token("/")]
    Divide,
    #[token(":=")]
    Assign,
    #[token("==")]
    Eq,
    #[token("<=")]
    LtEq,
    #[token(">=")]
    GtEq,
    #[token("<")]
    Lt,
    #[token(">")]
    Gt,
    #[token("!=")]
    Ne,
    #[token("&&")]
    And,
    #[token("||")]
    Or,

    Eof,
}

impl Display for Token {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        match self {
            Token::KeywordIf => write!(f, "if"),
            Token::KeywordElse => write!(f, "else"),
            Token::KeywordFn => write!(f, "fn"),
            Token::KeywordTrue => write!(f, "true"),
            Token::KeywordFalse => write!(f, "false"),
            Token::Ident => write!(f, "Identifier"),
            Token::Number => write!(f, "Number"),
            Token::String => write!(f, "String"),
            Token::LParen => write!(f, "("),
            Token::RParen => write!(f, ")"),
            Token::LCurly => write!(f, "{{"),
            Token::RCurly => write!(f, "}}"),
            Token::Comma => write!(f, ","),
            Token::Semicolon => write!(f, ";"),
            Token::Dot => write!(f, "."),
            Token::Colon => write!(f, ":"),
            Token::Exclamation => write!(f, "!"),
            Token::Add => write!(f, "+"),
            Token::Subtract => write!(f, "-"),
            Token::Multiply => write!(f, "*"),
            Token::Divide => write!(f, "/"),
            Token::Assign => write!(f, ":="),
            Token::Eq => write!(f, "=="),
            Token::LtEq => write!(f, "<="),
            Token::GtEq => write!(f, ">="),
            Token::Lt => write!(f, "<"),
            Token::Gt => write!(f, ">"),
            Token::Ne => write!(f, "!="),
            Token::And => write!(f, "&&"),
            Token::Or => write!(f, "||"),
            Token::Eof => write!(f, "EOF"),
        }
    }
}

pub struct Tokenizer {
    tokens: Vec<(ByteSpan, Token)>,
    position: usize,
    input: String,
}

impl Tokenizer {
    pub fn new(source: &str, context: &mut CompilationContext) -> Tokenizer {
        let mut lexer: Lexer<Token> = Lexer::new(source);
        let mut tokens = vec![];

        while let Some(token) = lexer.next() {
            match token {
                Ok(token) => {
                    let span = lexer.span();
                    tokens.push((span, token));
                }
                Err(_) => context.error(&lexer.span(), "Invalid token"),
            }
        }

        Self {
            tokens,
            position: 0,
            input: source.to_string(),
        }
    }

    pub fn is_at_end(&self) -> bool {
        self.position >= self.tokens.len()
    }

    pub fn current_token(&self) -> Token {
        if self.is_at_end() {
            Token::Eof
        } else {
            self.tokens[self.position].1.clone()
        }
    }

    pub fn current_span(&self) -> ByteSpan {
        if self.is_at_end() {
            self.input.len()..self.input.len()
        } else {
            self.tokens[self.position].0.clone()
        }
    }

    pub fn str(&self, span: &ByteSpan) -> &str {
        if span.start < self.input.len() {
            &self.input[span.start..span.end]
        } else {
            ""
        }
    }
    pub fn current_str(&self) -> &str {
        self.str(&self.current_span())
    }

    pub fn consume(&mut self) {
        if self.position < self.input.len() {
            self.position += 1;
        }
    }
}

#[cfg(test)]
mod tests {
    use crate::scripts::compiler::context::CompilationContext;
    use crate::scripts::compiler::tokenizer::{Token, Tokenizer};

    #[test]
    fn test_basic_tokenizing() {
        let mut context = CompilationContext::new("");
        let tokenizer = Tokenizer::new("if", &mut context);

        assert_eq!(tokenizer.current_token(), Token::KeywordIf);
    }
}
