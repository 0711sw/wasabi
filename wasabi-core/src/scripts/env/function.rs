use crate::scripts::eval::context::Context;
use crate::scripts::eval::error::{ScriptError, ScriptResult};
use crate::scripts::eval::node::Node;
use crate::scripts::value::{TypeName, Value};
use bitflags::bitflags;
use futures_util::future::LocalBoxFuture;
use std::fmt::{Debug, Formatter};
use std::sync::Arc;

type SyncFn<A> = fn(&[A], &mut Context) -> ScriptResult<Value>;

type AsyncFn<A> = for<'a> fn(&'a [A], &'a mut Context) -> LocalBoxFuture<'a, ScriptResult<Value>>;

pub enum ScriptFn {
    Lazy {
        async_fn: AsyncFn<Node>,
        sync_fn: Option<SyncFn<Node>>,
    },
    Simple(AsyncFn<Value>),
    SimpleSync(SyncFn<Value>),
}

pub trait ArgsExt {
    fn read_value(&self, index: usize) -> ScriptResult<&Value>;
    fn read<'a, T, F>(&'a self, index: usize, converter: F) -> ScriptResult<T>
    where
        T: 'a,
        F: Fn(&'a Value) -> Option<T>;
}

impl ArgsExt for &[Value] {
    fn read_value(&self, index: usize) -> ScriptResult<&Value> {
        self.get(index).ok_or_else(|| {
            ScriptError::engine_err(format!(
                "Argument index ({index}) out of bounds: {}",
                self.len()
            ))
        })
    }
    fn read<'a, T, F>(&'a self, index: usize, converter: F) -> ScriptResult<T>
    where
        T: 'a,
        F: Fn(&'a Value) -> Option<T>,
    {
        let value = self.read_value(index)?;
        converter(value).ok_or_else(|| {
            ScriptError::engine_err(format!("Invalid argument type at index {index}"))
        })
    }
}

impl Debug for ScriptFn {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        match &self {
            ScriptFn::Lazy { .. } => write!(f, "LazyFn"),
            ScriptFn::Simple(_) => write!(f, "SimpleFn"),
            ScriptFn::SimpleSync(_) => write!(f, "SimpleSyncFn"),
        }
    }
}

bitflags! {
    pub struct FunctionFlags: u8 {
        const PURE       = 0b0000_0001;
        const DEPRECATED = 0b0000_0010;
        const INTERNAL   = 0b0000_0100;
        const EXPERIMENTAL = 0b0000_1000;
    }
}

pub(crate) struct Function {
    pub name: &'static str,
    pub parameters: Vec<TypeName>,
    pub return_type: TypeName,
    pub script_fn: Arc<ScriptFn>,
    pub flags: FunctionFlags,
}

impl Function {
    pub fn is_async(&self) -> bool {
        match self.script_fn.as_ref() {
            ScriptFn::Lazy { sync_fn, .. } => sync_fn.is_none(),
            ScriptFn::Simple(_) => true,
            ScriptFn::SimpleSync(_) => false,
        }
    }
}
