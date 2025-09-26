use crate::scripts::compiler::ast::{
    Ast, AstNode, AstNodeContent, FunctionArg, FunctionDefinition,
};
use crate::scripts::compiler::context::CompilationContext;
use crate::scripts::compiler::span::ByteSpan;
use crate::scripts::compiler::tokenizer::{Token, Tokenizer};
use crate::scripts::value::core::TYPE_NULL;
use crate::scripts::value::Value;
use rust_decimal::Decimal;
use std::str::FromStr;

pub struct Parser<'c> {
    tokenizer: Tokenizer,
    currently_failing: bool,
    last_fallthrough: usize,
    functions: Vec<FunctionDefinition>,
    context: &'c mut CompilationContext,
}

impl<'c> Parser<'c> {
    pub fn new(tokenizer: Tokenizer, context: &'c mut CompilationContext) -> Self {
        Self {
            tokenizer,
            functions: vec![],
            currently_failing: false,
            last_fallthrough: 0,
            context,
        }
    }

    fn consume_identifier(&mut self, error_message: &str, fallback: &str) -> String {
        if self.tokenizer.current_token() == Token::Ident {
            let ident = self.tokenizer.current_str().to_owned();
            self.tokenizer.consume();
            self.currently_failing = false;

            ident
        } else {
            self.context
                .error(&self.tokenizer.current_span(), error_message);
            self.currently_failing = true;

            fallback.to_owned()
        }
    }

    fn consume_expected_token(&mut self, expected_token: Token) {
        if self.tokenizer.current_token() == expected_token {
            self.tokenizer.consume();
            self.currently_failing = false;
        } else if self.tokenizer.is_at_end() {
            self.context.error(
                &self.tokenizer.current_span(),
                format!(
                    "Expected token '{}' but found '{}'",
                    expected_token,
                    self.tokenizer.current_str()
                ),
            );

            self.currently_failing = true;
        } else {
            self.context.error(
                &self.tokenizer.current_span(),
                format!("Expected token '{}'", expected_token),
            );

            self.currently_failing = true;
        }
    }

    pub fn parse(mut self) -> Ast {
        while !self.tokenizer.is_at_end() {
            self.parse_function()
        }

        Ast {
            functions: self.functions,
        }
    }

    fn parse_function(&mut self) {
        self.consume_expected_token(Token::KeywordFn);
        let name = self.consume_identifier("Expected function name", "");

        self.consume_expected_token(Token::LParen);

        let mut args = vec![];
        while self.tokenizer.current_token() == Token::Ident {
            let start = self.tokenizer.current_span();
            let arg_name = self.tokenizer.current_str().to_owned();
            self.tokenizer.consume();
            self.consume_expected_token(Token::Colon);
            let end = self.tokenizer.current_span();
            let type_name = self.consume_identifier("Expected argument type", TYPE_NULL);
            if arg_name != "" {
                args.push(FunctionArg {
                    name: arg_name,
                    type_name,
                    span: start.start..end.end,
                });
            }

            if self.tokenizer.current_token() != Token::RParen {
                self.consume_expected_token(Token::Comma);
            }

            while !self.tokenizer.is_at_end()
                && self.tokenizer.current_token() != Token::RParen
                && self.tokenizer.current_token() != Token::Ident
                && self.tokenizer.current_token() != Token::LCurly
            {
                self.context.error(
                    &self.tokenizer.current_span(),
                    format!("Unexpected token '{}'", self.tokenizer.current_str()),
                );
                self.tokenizer.consume();
            }
        }

        self.consume_expected_token(Token::RParen);

        let root = self.parse_block();

        self.functions.push(FunctionDefinition { name, args, root });
    }

    fn parse_block(&mut self) -> AstNode {
        let start = self.tokenizer.current_span();
        let mut statements = vec![];
        self.consume_expected_token(Token::LCurly);
        while !self.tokenizer.is_at_end() && self.tokenizer.current_token() != Token::RCurly {
            statements.push(self.parse_statement());
            if self.tokenizer.current_token() != Token::RCurly {
                self.consume_expected_token(Token::Semicolon);
            }
        }
        let end = self.tokenizer.current_span();
        self.consume_expected_token(Token::RCurly);

        AstNode {
            span: start.start..end.end,
            content: AstNodeContent::Block(statements),
        }
    }

    fn parse_statement(&mut self) -> AstNode {
        let expr = self.parse_expression();
        if self.tokenizer.current_token() == Token::Assign {
            let assign_span = self.tokenizer.current_span();
            self.tokenizer.consume();
            let value = self.parse_expression();
            if let AstNodeContent::ReadVariable(var) = &expr.content {
                AstNode {
                    span: expr.span.start..value.span.end,
                    content: AstNodeContent::Assignment {
                        variable: var.clone(),
                        value: Box::new(value),
                    },
                }
            } else {
                self.context
                    .error(&assign_span, "Can only assign to variables");
                value
            }
        } else {
            expr
        }
    }

    fn parse_expression(&mut self) -> AstNode {
        self.parse_boolean_or()
    }

    fn parse_binary_operation<F>(&mut self, mut parse_operand: F, operators: &[Token]) -> AstNode
    where
        F: FnMut(&mut Self) -> AstNode,
    {
        let mut left = parse_operand(self);

        while operators.contains(&self.tokenizer.current_token()) {
            let operation = self.tokenizer.current_token();
            self.tokenizer.consume();
            let right = parse_operand(self);
            let span = left.span.start..right.span.end;
            left = AstNode {
                span,
                content: AstNodeContent::BinaryOperation {
                    operation,
                    left: Box::new(left),
                    right: Box::new(right),
                },
            };
        }

        left
    }

    fn parse_boolean_or(&mut self) -> AstNode {
        self.parse_binary_operation(|s| s.parse_boolean_and(), &[Token::Or])
    }

    fn parse_boolean_and(&mut self) -> AstNode {
        self.parse_binary_operation(|s| s.parse_relational_operation(), &[Token::And])
    }

    fn parse_relational_operation(&mut self) -> AstNode {
        self.parse_binary_operation(
            |s| s.parse_add_sub(),
            &[
                Token::Lt,
                Token::LtEq,
                Token::Eq,
                Token::GtEq,
                Token::Gt,
                Token::Ne,
            ],
        )
    }

    fn parse_add_sub(&mut self) -> AstNode {
        self.parse_binary_operation(|s| s.parse_mul_div(), &[Token::Add, Token::Subtract])
    }

    fn parse_mul_div(&mut self) -> AstNode {
        self.parse_binary_operation(
            |s| s.parse_method_chain(),
            &[Token::Multiply, Token::Divide],
        )
    }

    fn parse_method_chain(&mut self) -> AstNode {
        let mut this = self.parse_atom();

        while self.tokenizer.current_token() == Token::Dot {
            self.tokenizer.consume();
            let function = self.consume_identifier("Expected method node", "");
            self.consume_expected_token(Token::LParen);
            let arguments = self.parse_fn_arguments();
            let end = self.tokenizer.current_span();
            self.consume_expected_token(Token::RParen);

            let span = this.span.start..end.end;
            this = AstNode {
                span,
                content: AstNodeContent::MethodCall {
                    this: Box::new(this),
                    function,
                    arguments,
                },
            }
        }

        this
    }

    fn parse_atom(&mut self) -> AstNode {
        if self.tokenizer.current_token() == Token::LParen {
            self.tokenizer.consume();
            let result = self.parse_expression();
            self.consume_expected_token(Token::RParen);

            result
        } else if self.tokenizer.current_token() == Token::LCurly {
            self.parse_block()
        } else if self.tokenizer.current_token() == Token::KeywordTrue {
            let span = self.tokenizer.current_span();
            self.tokenizer.consume();

            AstNode {
                span,
                content: AstNodeContent::Literal(Value::Boolean(true)),
            }
        } else if self.tokenizer.current_token() == Token::KeywordFalse {
            let span = self.tokenizer.current_span();
            self.tokenizer.consume();

            AstNode {
                span,
                content: AstNodeContent::Literal(Value::Boolean(false)),
            }
        } else if self.tokenizer.current_token() == Token::String {
            let span = self.tokenizer.current_span();
            let string = self
                .tokenizer
                .current_str()
                .strip_prefix('"')
                .and_then(|s| s.strip_suffix('"'))
                .and_then(unescape::unescape)
                .unwrap_or_else(|| self.tokenizer.current_str().to_string());
            let value = Value::string(string);
            self.tokenizer.consume();

            AstNode {
                span,
                content: AstNodeContent::Literal(value),
            }
        } else if self.tokenizer.current_token() == Token::Number {
            let span = self.tokenizer.current_span();
            // TODO graceful error handling
            let number = Decimal::from_str(self.tokenizer.current_str()).unwrap_or_default();
            self.tokenizer.consume();

            AstNode {
                span,
                content: AstNodeContent::Literal(Value::Number(number)),
            }
        } else if self.tokenizer.current_token() == Token::KeywordIf {
            self.parse_if()
        } else if self.tokenizer.current_token() == Token::Ident {
            self.parse_identifier()
        } else {
            let span = self.tokenizer.current_span();
            let current_token = self.tokenizer.current_token();

            self.context.error(
                &span,
                format!("Expected an expression, found '{}'", current_token),
            );
            self.currently_failing = true;

            // TODO explain !!
            if span.start == self.last_fallthrough
                || (current_token != Token::RCurly
                    && current_token != Token::Semicolon
                    && current_token != Token::Comma
                    && current_token != Token::RParen)
            {
                self.tokenizer.consume();
            } else {
                self.last_fallthrough = span.start;
            }

            AstNode {
                span,
                content: AstNodeContent::Literal(Value::Null),
            }
        }
    }

    fn parse_if(&mut self) -> AstNode {
        let start = self.tokenizer.current_span();
        self.tokenizer.consume();

        self.consume_expected_token(Token::LParen);
        let condition = self.parse_expression();
        self.consume_expected_token(Token::RParen);
        let then_branch = self.parse_block();

        let else_branch = if self.tokenizer.current_token() == Token::KeywordElse {
            self.tokenizer.consume();
            Some(self.parse_block())
        } else {
            None
        };

        AstNode {
            span: start.start..else_branch.as_ref().unwrap_or(&then_branch).span.end,
            content: AstNodeContent::IfStatement {
                condition: Box::new(condition),
                then_branch: Box::new(then_branch),
                else_branch: else_branch.map(Box::new),
            },
        }
    }

    fn parse_identifier(&mut self) -> AstNode {
        let span = self.tokenizer.current_span();
        let name = self.tokenizer.current_str().to_owned();
        self.tokenizer.consume();

        if self.tokenizer.current_token() == Token::LParen {
            self.parse_function_call(span, name)
        } else {
            AstNode {
                span,
                content: AstNodeContent::ReadVariable(name),
            }
        }
    }

    fn parse_function_call(&mut self, span: ByteSpan, function: String) -> AstNode {
        self.tokenizer.consume();
        let arguments = self.parse_fn_arguments();
        let end = self.tokenizer.current_span();
        self.consume_expected_token(Token::RParen);

        AstNode {
            span: span.start..end.end,
            content: AstNodeContent::Call {
                function,
                arguments,
            },
        }
    }

    fn parse_fn_arguments(&mut self) -> Vec<AstNode> {
        let mut arguments = vec![];
        while !self.tokenizer.is_at_end() && self.tokenizer.current_token() != Token::RParen {
            arguments.push(self.parse_expression());
            if self.tokenizer.current_token() != Token::RParen {
                self.consume_expected_token(Token::Comma);
            }
        }

        arguments
    }
}

#[cfg(test)]
mod tests {
    use crate::scripts::compiler::context::CompilationContext;
    use crate::scripts::compiler::parser::Parser;
    use crate::scripts::compiler::tokenizer::Tokenizer;

    #[test]
    fn test_basic_sources() {
        let mut context = CompilationContext::new("");
        let tokenizer = Tokenizer::new("fn test(a : String) { a + 2 * 7.test(x) }", &mut context);
        let ast = Parser::new(tokenizer, &mut context).parse();

        dbg!(&ast);
    }
}
