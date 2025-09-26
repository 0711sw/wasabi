use crate::scripts::compiler::context::CompilationContext;
use crate::scripts::compiler::parser::Parser;
use crate::scripts::compiler::span::CharSpan;
use crate::scripts::compiler::tokenizer::Tokenizer;
use crate::scripts::compiler::transformer::Transformer;
use crate::scripts::env::engine::Engine;
use crate::scripts::eval::Script;

mod ast;
mod context;
mod parser;
pub mod span;
mod tokenizer;
mod transformer;

#[derive(Debug)]
pub struct Message {
    pub severity: Severity,
    pub span: CharSpan,
    pub message: String,
}

#[derive(PartialEq, Debug)]
pub enum Severity {
    Info,
    Warning,
    Error,
}

#[derive(Debug)]
pub enum CompilationResult {
    Ok(Script, Vec<Message>),
    Err(Vec<Message>),
}

pub fn compile(source: &str, engine: Engine) -> CompilationResult {
    let mut context = CompilationContext::new(source);
    let tokenizer = Tokenizer::new(source, &mut context);
    let parser = Parser::new(tokenizer, &mut context);
    let ast = parser.parse();
    let transformer = Transformer::new(engine, &mut context);
    let script = transformer.transform(ast);

    if context.is_ok() {
        CompilationResult::Ok(script, context.messages())
    } else {
        CompilationResult::Err(context.messages())
    }
}

#[cfg(test)]
mod tests {
    use crate::scripts::compiler::{compile, CompilationResult};
    use crate::scripts::env::engine::EngineBuilder;
    use crate::scripts::value::Value;
    use crate::web::auth::user::User;
    use rust_decimal::Decimal;
    use std::collections::BTreeMap;

    #[test]
    fn test_compiler() {
        let engine = EngineBuilder::new().build();
        let result = compile(
            r#"
        fn test(x: Number) {
            y := 5.add(6);
            if (x < 2) {
                1 + 1
            } else {
                "Hallo"
            }
        }
        "#,
            engine,
        );

        let mut claims = BTreeMap::new();
        claims.insert("sub".to_string(),serde_json::Value::String("AAA".to_string()));
            let u = User { claims };

        match result {
            CompilationResult::Ok(script, msg) => {
                let x = script
                    .find_function("test")
                    .unwrap()
                    .eval_sync(vec![Value::Number(Decimal::from(9))], vec![Box::new(u.clone())]);
                dbg!(msg);
                dbg!(x);
            }
            CompilationResult::Err(msg) => {
                dbg!(msg);
            }
        }
    }
}
