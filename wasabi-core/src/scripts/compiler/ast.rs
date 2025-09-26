use crate::scripts::compiler::span::ByteSpan;
use crate::scripts::compiler::tokenizer::Token;
use crate::scripts::value::Value;
use std::fmt::{Debug, Display, Formatter};

#[derive(Debug)]
pub struct AstNode {
    pub content: AstNodeContent,
    pub span: ByteSpan,
}

#[derive(Debug)]
pub enum AstNodeContent {
    Literal(Value),
    UnaryOperation {
        operation: Token,
        operand: Box<AstNode>,
    },
    BinaryOperation {
        operation: Token,
        left: Box<AstNode>,
        right: Box<AstNode>,
    },
    Call {
        function: String,
        arguments: Vec<AstNode>,
    },
    MethodCall {
        this: Box<AstNode>,
        function: String,
        arguments: Vec<AstNode>,
    },
    ReadVariable(String),
    Assignment {
        variable: String,
        value: Box<AstNode>,
    },
    IfStatement {
        condition: Box<AstNode>,
        then_branch: Box<AstNode>,
        else_branch: Option<Box<AstNode>>,
    },
    Block(Vec<AstNode>),
}

#[derive(Debug)]
pub struct FunctionDefinition {
    pub name: String,
    pub args: Vec<FunctionArg>,
    pub root: AstNode,
}

#[derive(Debug)]
pub struct FunctionArg {
    pub name: String,
    pub type_name: String,
    pub span: ByteSpan,
}

#[derive(Debug)]
pub struct Ast {
    pub functions: Vec<FunctionDefinition>,
}

impl Display for FunctionDefinition {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "fn {}({}){}",
            self.name,
            self.args
                .iter()
                .map(|s| s.to_string())
                .collect::<Vec<_>>()
                .join(", "),
            self.root
        )
    }
}

impl Display for FunctionArg {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}: {}", self.name, self.type_name)
    }
}

impl Display for AstNode {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", &self.content)
    }
}

impl Display for AstNodeContent {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        match &self {
            AstNodeContent::Literal(value) => {
                write!(f, "{}", value)
            }
            AstNodeContent::UnaryOperation { operation, operand } => {
                write!(f, "{operation}{operand}")
            }
            AstNodeContent::BinaryOperation {
                operation,
                left,
                right,
            } => {
                write!(f, "({left} {operation} {right})")
            }
            AstNodeContent::Call {
                function,
                arguments,
            } => {
                write!(
                    f,
                    "{function}({})",
                    arguments
                        .iter()
                        .map(|f| f.to_string())
                        .collect::<Vec<_>>()
                        .join(", ")
                )
            }
            AstNodeContent::MethodCall {
                this,
                function,
                arguments,
            } => {
                write!(
                    f,
                    "{this}.{function}({})",
                    arguments
                        .iter()
                        .map(|f| f.to_string())
                        .collect::<Vec<_>>()
                        .join(", ")
                )
            }
            AstNodeContent::ReadVariable(var) => {
                write!(f, "{var}")
            }
            AstNodeContent::Assignment { variable, value } => {
                write!(f, "{variable} := {value}")
            }
            AstNodeContent::IfStatement {
                condition,
                then_branch,
                else_branch,
            } => {
                if let Some(else_branch) = else_branch {
                    write!(f, "if ({condition}) {then_branch} else {else_branch}")
                } else {
                    write!(f, "if ({condition}) {then_branch}")
                }
            }
            AstNodeContent::Block(stmts) => {
                write!(f, "\n{{\n")?;
                write!(
                    f,
                    "{}",
                    stmts
                        .iter()
                        .map(|f| f.to_string())
                        .collect::<Vec<_>>()
                        .join("\n")
                )?;
                write!(f, "\n}}\n")
            }
        }
    }
}
