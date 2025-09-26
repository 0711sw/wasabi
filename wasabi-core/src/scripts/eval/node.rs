use crate::scripts::compiler::span::ByteSpan;
use crate::scripts::env::function::ScriptFn;
use crate::scripts::eval::context::Context;
use crate::scripts::eval::error::{ScriptError, ScriptResult};
use crate::scripts::value::core::TYPE_NULL;
use crate::scripts::value::{TypeName, Value};
use futures_util::future::LocalBoxFuture;
use std::fmt::{Display, Formatter};
use std::sync::Arc;

#[derive(Debug)]
pub struct Node {
    pub span: ByteSpan,
    pub type_name: TypeName,
    pub kind: NodeKind,
}

#[derive(Debug)]
pub enum NodeKind {
    Sync(NodeContent),
    Async(NodeContent),
}

#[derive(Debug)]
pub enum NodeContent {
    Literal(Value),
    Call(Arc<ScriptFn>, Vec<Node>),
    ReadLocal(usize),
    WriteLocal(usize, Box<Node>),
    Block(Vec<Node>),
}

impl Node {
    pub fn new(
        span: ByteSpan,
        type_name: TypeName,
        async_content: bool,
        content: NodeContent,
    ) -> Self {
        Self {
            span,
            type_name,
            kind: if async_content {
                NodeKind::Async(content)
            } else {
                NodeKind::Sync(content)
            },
        }
    }

    pub fn dummy(span: ByteSpan) -> Self {
        Self {
            span,
            type_name: TYPE_NULL,
            kind: NodeKind::Sync(NodeContent::Literal(Value::Null)),
        }
    }

    pub fn eval<'a>(&'a self, context: &'a mut Context) -> LocalBoxFuture<'a, ScriptResult<Value>> {
        Box::pin(async move {
            match &self.kind {
                NodeKind::Sync(content) => content.eval_sync(&self.span, context),
                NodeKind::Async(content) => content.eval(&self.span, context).await,
            }
        })
    }

    pub fn eval_sync(&self, context: &mut Context) -> ScriptResult<Value> {
        match &self.kind {
            NodeKind::Sync(content) => content.eval_sync(&self.span, context),
            NodeKind::Async(_) => {
                Err(ScriptError::async_call_in_sync_context(self.to_string()).at(self.span.clone()))
            }
        }
    }

    pub fn is_async(&self) -> bool {
        matches!(self.kind, NodeKind::Async(_))
    }
}

impl NodeContent {
    fn eval_sync(&self, span: &ByteSpan, context: &mut Context) -> ScriptResult<Value> {
        match self {
            NodeContent::Literal(value) => Ok(value.clone()),
            NodeContent::Call(fun, args) => self.eval_function_sync(span, fun, args, context),
            NodeContent::ReadLocal(index) => context.read(*index).map_err(|err| err.fill_at(span)),
            NodeContent::WriteLocal(index, value_node) => {
                let value = value_node.eval_sync(context)?;
                context
                    .write(*index, value.clone())
                    .map_err(|err| err.fill_at(span))
            }
            NodeContent::Block(nodes) => {
                let mut last_value = Value::Null;
                for node in nodes {
                    last_value = node.eval_sync(context)?;
                }
                Ok(last_value)
            }
        }
    }

    async fn eval(&self, span: &ByteSpan, context: &mut Context) -> ScriptResult<Value> {
        match self {
            NodeContent::Call(fun, args) => {
                self.eval_function(span, fun.as_ref(), args, context).await
            }
            NodeContent::Block(nodes) => {
                let mut last_value = Value::Null;
                for node in nodes {
                    last_value = node.eval(context).await?;
                }
                Ok(last_value)
            }
            NodeContent::WriteLocal(index, value_node) => {
                let value = value_node.eval(context).await?;
                context
                    .write(*index, value.clone())
                    .map_err(|err| err.fill_at(span))
            }
            _ => self.eval_sync(span, context),
        }
    }

    fn eval_function<'a>(
        &'a self,
        span: &'a ByteSpan,
        fun: &'a ScriptFn,
        args: &'a [Node],
        context: &'a mut Context,
    ) -> LocalBoxFuture<'a, ScriptResult<Value>> {
        Box::pin(async move {
            match fun {
                ScriptFn::Simple(fun) => {
                    let args = self.eval_args(args, context).await?;
                    fun(&args, context).await.map_err(|err| err.fill_at(span))
                }
                ScriptFn::SimpleSync(fun) => {
                    let args = self.eval_args(args, context).await?;
                    fun(&args, context).map_err(|err| err.fill_at(span))
                }
                ScriptFn::Lazy { async_fn, .. } => async_fn(args, context)
                    .await
                    .map_err(|err| err.fill_at(span)),
            }
        })
    }

    async fn eval_args(
        &self,
        args: &[Node],
        context: &mut Context,
    ) -> Result<Vec<Value>, ScriptError> {
        let mut evaluated_args = Vec::with_capacity(args.len());
        for arg in args {
            evaluated_args.push(if arg.is_async() {
                arg.eval(context).await?
            } else {
                arg.eval_sync(context)?
            });
        }

        Ok(evaluated_args)
    }

    pub fn eval_function_sync(
        &self,
        span: &ByteSpan,
        fun: &ScriptFn,
        args: &[Node],
        context: &mut Context,
    ) -> ScriptResult<Value> {
        match fun {
            ScriptFn::SimpleSync(f) => {
                let args = self.eval_args_sync(args, context)?;
                f(&args, context).map_err(|err| err.fill_at(span))
            }
            ScriptFn::Lazy { sync_fn, .. } => {
                if let Some(f) = sync_fn {
                    f(&args, context).map_err(|err| err.fill_at(span))
                } else {
                    Err(ScriptError::async_call_in_sync_context(self.to_string()).at(span.clone()))
                }
            }
            _ => Err(ScriptError::async_call_in_sync_context(self.to_string()).at(span.clone())),
        }
    }

    fn eval_args_sync(
        &self,
        args: &[Node],
        context: &mut Context,
    ) -> Result<Vec<Value>, ScriptError> {
        let mut evaluated_args = Vec::with_capacity(args.len());
        for arg in args {
            evaluated_args.push(arg.eval_sync(context)?);
        }

        Ok(evaluated_args)
    }
}

impl Display for Node {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        match &self.kind {
            NodeKind::Sync(content) => write!(f, "{}", content),
            NodeKind::Async(content) => write!(f, "<{}>", content),
        }
    }
}

impl Display for NodeContent {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        match &self {
            NodeContent::Literal(value) => write!(f, "{}", value),
            NodeContent::Call(fun, args) => write!(
                f,
                "#{:?}({})",
                fun,
                args.iter()
                    .map(|a| a.to_string())
                    .collect::<Vec<_>>()
                    .join(", ")
            ),
            NodeContent::ReadLocal(idx) => write!(f, "@{}", idx),
            NodeContent::WriteLocal(idx, value_node) => write!(f, "@{} := {}", idx, value_node),
            NodeContent::Block(nodes) => write!(
                f,
                "\n{{\n{}\n}}\n",
                nodes
                    .iter()
                    .map(|n| n.to_string())
                    .collect::<Vec<_>>()
                    .join("\n")
            ),
        }
    }
}
