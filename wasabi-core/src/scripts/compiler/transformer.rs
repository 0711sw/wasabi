use crate::scripts::compiler::ast::{Ast, AstNode, AstNodeContent, FunctionDefinition};
use crate::scripts::compiler::context::CompilationContext;
use crate::scripts::compiler::span::ByteSpan;
use crate::scripts::compiler::tokenizer::Token;
use crate::scripts::env::engine::Engine;
use crate::scripts::env::function::{Function, FunctionFlags, ScriptFn};
use crate::scripts::eval::node::{Node, NodeContent};
use crate::scripts::eval::{Script, ScriptFunction};
use crate::scripts::value::core::{TYPE_ANY, TYPE_NULL};
use crate::scripts::value::string::TYPE_STRING;
use crate::scripts::value::{TypeName, Value};
use std::collections::HashMap;
use std::sync::Arc;

pub struct Transformer<'c> {
    engine: Engine,
    variables: Vec<HashMap<String, Variable>>,
    num_locals: usize,
    context: &'c mut CompilationContext,
}

struct Variable {
    local_index: usize,
    type_name: TypeName,
}

impl<'c> Transformer<'c> {
    pub fn new(engine: Engine, context: &'c mut CompilationContext) -> Self {
        Self {
            engine,
            variables: vec![],
            num_locals: 0,
            context,
        }
    }

    pub fn transform(mut self, ast: Ast) -> Script {
        let mut functions = HashMap::new();

        for function in ast.functions {
            functions.insert(function.name.clone(), self.transform_function(function));
        }

        Script {
            engine: self.engine,
            line_starts: self.context.line_starts.clone(),
            functions,
        }
    }

    fn transform_function(&mut self, function: FunctionDefinition) -> ScriptFunction {
        self.variables.clear();
        self.begin_context();

        let mut args = vec![];
        for arg in &function.args {
            let type_name = self.engine.find_type(&arg.type_name).unwrap_or_else(|| {
                self.context
                    .error(&arg.span, format!("Unknown type '{}'", arg.type_name));

                TYPE_NULL
            });

            if self.find_variable(&arg.name).is_some() {
                self.context
                    .error(&arg.span, format!("Duplicate argument name '{}'", arg.name));
            }

            self.define_variable(&arg.span, arg.name.clone(), type_name);
            args.push(type_name);
        }

        let root = self.transform_node(function.root.span, function.root.content);
        ScriptFunction {
            name: function.name.clone(),
            args,
            return_type: root.type_name,
            num_locals: self.num_locals,
            root,
        }
    }

    fn begin_context(&mut self) {
        self.variables.push(HashMap::new());
    }

    fn end_context(&mut self) {
        self.variables.pop();
    }

    fn define_variable(&mut self, _span: &ByteSpan, name: String, type_name: TypeName) -> usize {
        let local_index = self.num_locals;
        self.num_locals += 1;

        if let Some(ctx) = self.variables.last_mut() {
            ctx.insert(
                name.clone(),
                Variable {
                    local_index,
                    type_name,
                },
            );
        }

        local_index
    }

    fn find_variable(&self, name: &str) -> Option<&Variable> {
        for variables in self.variables.iter().rev() {
            if let Some(variable) = variables.get(name) {
                return Some(variable);
            }
        }

        None
    }

    fn transform_call_with_args(
        &mut self,
        span: ByteSpan,
        function: String,
        args: Vec<Node>,
        accept_internal: bool,
    ) -> Node {
        if let Some((type_name, ptr, is_async)) =
            self.find_function(span.clone(), &function, &args, accept_internal)
        {
            Node::new(
                span,
                type_name,
                is_async || args.iter().any(Node::is_async),
                NodeContent::Call(ptr, args),
            )
        } else {
            Node::new(span, TYPE_NULL, false, NodeContent::Literal(Value::Null))
        }
    }

    fn find_function(
        &mut self,
        span: ByteSpan,
        function_name: &str,
        args: &[Node],
        accept_internal: bool,
    ) -> Option<(TypeName, Arc<ScriptFn>, bool)> {
        if let Some(function) = self.engine.clone().find_function(function_name) {
            self.check_function(span, function, args, accept_internal);

            Some((
                function.return_type,
                function.script_fn.clone(),
                function.is_async(),
            ))
        } else {
            self.context
                .error(&span, format!("Function '{}' not found", function_name));

            None
        }
    }

    fn find_method(
        &mut self,
        span: ByteSpan,
        type_name: &str,
        function_name: &str,
        args: &[Node],
    ) -> Option<(TypeName, Arc<ScriptFn>, bool)> {
        let engine = self.engine.clone();
        if let Some(function) = engine
            .find_function(&format!("{type_name}::{function_name}"))
            .or_else(|| engine.find_function(&format!("Any::{function_name}")))
        {
            self.check_function(span, function, args, false);

            Some((
                function.return_type,
                function.script_fn.clone(),
                function.is_async(),
            ))
        } else {
            self.context.error(
                &span,
                format!("Method '{function_name}' for type '{type_name}' not found"),
            );
            None
        }
    }

    fn check_function(
        &mut self,
        span: ByteSpan,
        function: &Function,
        args: &[Node],
        accept_internal: bool,
    ) {
        if function.parameters.len() == args.len() {
            if function.flags.contains(FunctionFlags::EXPERIMENTAL) {
                self.context
                    .warning(&span, "This function is marked as experimental.");
            }
            if function.flags.contains(FunctionFlags::DEPRECATED) {
                self.context
                    .warning(&span, "This function is marked as deprecated.");
            }
            if !accept_internal && function.flags.contains(FunctionFlags::INTERNAL) {
                self.context
                    .warning(&span, "This function is intended for internal use.");
            }

            for (i, param) in function.parameters.iter().enumerate() {
                if *param != args[i].type_name && *param != TYPE_ANY {
                    self.context.error(
                        &args[i].span,
                        format!(
                            "Expected argument of type '{}', found '{}'",
                            param, args[i].type_name
                        ),
                    );
                }
            }
        } else {
            self.context.error(
                &span,
                format!(
                    "Expected {} arguments, found {}",
                    function.parameters.len(),
                    args.len()
                ),
            );
        }
    }

    fn transform_node(&mut self, span: ByteSpan, content: AstNodeContent) -> Node {
        match content {
            AstNodeContent::Literal(value) => {
                Node::new(span, value.type_name(), false, NodeContent::Literal(value))
            }
            AstNodeContent::UnaryOperation { operation, operand } => {
                self.transform_unary(span, operation, operand)
            }
            AstNodeContent::BinaryOperation {
                operation,
                left,
                right,
            } => self.transform_binary(span, operation, left, right),
            AstNodeContent::Call {
                function,
                arguments,
            } => self.transform_call(span, function, arguments),
            AstNodeContent::MethodCall {
                this,
                function,
                arguments,
            } => self.transform_method_call(span, this, function, arguments),
            AstNodeContent::ReadVariable(var) => self.transform_read(span, var),
            AstNodeContent::Assignment { variable, value } => {
                self.transform_assignment(span, variable, value)
            }
            AstNodeContent::IfStatement {
                condition,
                then_branch,
                else_branch,
            } => self.transform_if(span, condition, then_branch, else_branch),
            AstNodeContent::Block(statements) => self.transform_block(span, statements),
        }
    }

    fn transform_unary(&mut self, span: ByteSpan, operation: Token, operand: Box<AstNode>) -> Node {
        let operand = self.transform_node(operand.span, operand.content);
        let function_name = format!("{:?}", operation).to_lowercase();

        self.transform_call_with_args(
            span,
            format!("{}::{}", operand.type_name, function_name),
            vec![operand],
            true,
        )
    }

    fn transform_binary(
        &mut self,
        span: ByteSpan,
        operation: Token,
        left: Box<AstNode>,
        right: Box<AstNode>,
    ) -> Node {
        let left = self.transform_node(left.span, left.content);
        let right = self.transform_node(right.span, right.content);
        if operation == Token::Add
            && (left.type_name == TYPE_STRING || right.type_name == TYPE_STRING)
        {
            return self.transform_call_with_args(
                span,
                "String::add".to_owned(),
                vec![left, right],
                true,
            );
        }

        let function_name = format!("{:?}", operation).to_lowercase();
        self.transform_call_with_args(
            span,
            format!("{}::{}", left.type_name, function_name),
            vec![left, right],
            true,
        )
    }

    fn transform_call(&mut self, span: ByteSpan, function: String, args: Vec<AstNode>) -> Node {
        let args = args
            .into_iter()
            .map(|arg| self.transform_node(arg.span, arg.content))
            .collect::<Vec<_>>();

        self.transform_call_with_args(span, function, args, false)
    }

    fn transform_method_call(
        &mut self,
        span: ByteSpan,
        this: Box<AstNode>,
        function: String,
        args: Vec<AstNode>,
    ) -> Node {
        let mut method_args = Vec::with_capacity(args.len() + 1);
        let this = self.transform_node(this.span, this.content);
        let this_type = this.type_name;
        method_args.push(this);

        for arg in args {
            method_args.push(self.transform_node(arg.span, arg.content))
        }

        if let Some((type_name, ptr, is_async)) =
            self.find_method(span.clone(), this_type, &function, &method_args)
        {
            Node::new(
                span,
                type_name,
                is_async || method_args.iter().any(Node::is_async),
                NodeContent::Call(ptr, method_args),
            )
        } else {
            Node::new(span, TYPE_NULL, false, NodeContent::Literal(Value::Null))
        }
    }

    fn transform_read(&mut self, span: ByteSpan, var: String) -> Node {
        if let Some(variable) = self.find_variable(&var) {
            Node::new(
                span,
                variable.type_name,
                false,
                NodeContent::ReadLocal(variable.local_index),
            )
        } else {
            self.context
                .error(&span, format!("Unknown variable '{}'", var));

            Node::new(span, TYPE_NULL, false, NodeContent::Literal(Value::Null))
        }
    }

    fn transform_assignment(
        &mut self,
        span: ByteSpan,
        variable: String,
        value: Box<AstNode>,
    ) -> Node {
        let value = self.transform_node(value.span, value.content);
        let local_index = self.define_variable(&span, variable, value.type_name);

        Node::new(
            span,
            value.type_name,
            value.is_async(),
            NodeContent::WriteLocal(local_index, Box::new(value)),
        )
    }

    fn transform_if(
        &mut self,
        span: ByteSpan,
        condition: Box<AstNode>,
        then_branch: Box<AstNode>,
        else_branch: Option<Box<AstNode>>,
    ) -> Node {
        let condition = self.transform_node(condition.span, condition.content);
        let then_branch = self.transform_node(then_branch.span, then_branch.content);
        let else_branch = match else_branch {
            Some(else_branch) => self.transform_node(else_branch.span, else_branch.content),
            None => Node::new(
                span.clone(),
                TYPE_NULL,
                false,
                NodeContent::Literal(Value::Null),
            ),
        };

        self.transform_call_with_args(
            span,
            "if".to_owned(),
            vec![condition, then_branch, else_branch],
            true,
        )
    }

    fn transform_block(&mut self, span: ByteSpan, statements: Vec<AstNode>) -> Node {
        self.begin_context();
        let statements = statements
            .into_iter()
            .map(|stmt| self.transform_node(stmt.span, stmt.content))
            .collect::<Vec<_>>();
        self.end_context();

        if statements.len() == 1 {
            return statements.into_iter().next().unwrap();
        }

        let type_name = statements
            .last()
            .map(|stmt| stmt.type_name)
            .unwrap_or(TYPE_NULL);

        Node::new(
            span,
            type_name,
            statements.iter().any(|stmt| stmt.is_async()),
            NodeContent::Block(statements),
        )
    }
}
