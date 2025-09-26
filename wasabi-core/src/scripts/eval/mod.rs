use crate::scripts::compiler::span::LineStarts;
use crate::scripts::env::engine::Engine;
use crate::scripts::eval::context::Context;
use crate::scripts::eval::error::{ScriptError, ScriptResult};
use crate::scripts::eval::node::Node;
use crate::scripts::value::core::TYPE_ANY;
use crate::scripts::value::{TypeName, Value};
use std::any::Any;
use std::collections::HashMap;
use std::fmt::{Debug, Formatter};

pub mod context;
pub mod error;
pub mod node;

pub(crate) struct ScriptFunction {
    pub(crate) name: String,
    pub(crate) args: Vec<TypeName>,
    pub(crate) return_type: TypeName,
    pub(crate) num_locals: usize,
    pub(crate) root: Node,
}

pub struct Script {
    pub(crate) engine: Engine,
    pub(crate) line_starts: LineStarts,
    pub(crate) functions: HashMap<String, ScriptFunction>,
}

pub struct CallableFunction<'a> {
    script: &'a Script,
    function: &'a ScriptFunction,
}

impl Debug for Script {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        write!(f, "{:?}", &self.functions)
    }
}

impl Debug for ScriptFunction {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "fn {}({}) -> {}\n{}",
            self.name,
            self.args.join(", "),
            self.return_type,
            self.root
        )
    }
}

impl Script {
    pub fn find_function(&self, name: &str) -> Option<CallableFunction> {
        if let Some(function) = self.functions.get(name) {
            Some(CallableFunction {
                script: self,
                function,
            })
        } else {
            None
        }
    }
}

impl<'a> CallableFunction<'a> {
    pub async fn eval(&self, args: Vec<Value>, globals: Vec<Box<dyn Any>>) -> ScriptResult<Value> {
        let mut context = self.setup_context(args, globals)?;
        if self.function.root.is_async() {
            let local_set = tokio::task::LocalSet::new();
            local_set
                .run_until(self.function.root.eval(&mut context))
                .await
        } else {
            self.function.root.eval_sync(&mut context)
        }
    }

    pub fn eval_sync(&self, args: Vec<Value>, globals: Vec<Box<dyn Any>>) -> ScriptResult<Value> {
        let mut context = self.setup_context(args, globals)?;
        self.function.root.eval_sync(&mut context)
    }

    fn setup_context(&self, args: Vec<Value>, globals: Vec<Box<dyn Any>>) -> ScriptResult<Context> {
        let mut context = Context::new(self.function.num_locals, globals);
        let _ = ScriptError::enforce_arg_count(self.function.args.len(), args.len())
            .map_err(|err| err.fill_at(&self.function.root.span))?;

        for (index, value) in args.into_iter().enumerate() {
            if self.function.args[index] != value.type_name()
                && self.function.args[index] != TYPE_ANY
            {
                let _ = ScriptError::enforce_arg_type(
                    index,
                    self.function.args[index],
                    value.type_name(),
                )?;
            }

            let _ = context.write(index, value)?;
        }

        Ok(context)
    }

    pub fn is_async(&self) -> bool {
        self.function.root.is_async()
    }

    pub fn args(&self) -> &[TypeName] {
        &self.function.args
    }
}
