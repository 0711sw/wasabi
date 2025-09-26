use crate::scripts::eval::error::{ScriptError, ScriptResult};
use crate::scripts::value::Value;
use std::any::{type_name, Any};

pub struct Context {
    locals: Vec<Value>,
    globals: Vec<Box<dyn Any>>,
}

impl Context {
    pub(crate) fn new(num_locals: usize, globals: Vec<Box<dyn Any>>) -> Self {
        Self {
            locals: vec![Value::Null; num_locals],
            globals,
        }
    }

    pub(crate) fn read(&mut self, index: usize) -> ScriptResult<Value> {
        self.locals.get(index).cloned().ok_or_else(|| {
            ScriptError::engine_err(format!(
                "Invalid local index {index} (num locals: {})",
                self.locals.len()
            ))
        })
    }

    pub(crate) fn write(&mut self, index: usize, value: Value) -> ScriptResult<Value> {
        *self.locals.get_mut(index).ok_or_else(|| {
            ScriptError::engine_err(format!(
                "Invalid local index {index}",
            ))
        })? = value.clone();

        Ok(value)
    }

    pub fn find_global<T: Any>(&self) -> ScriptResult<&T> {
        self.globals
            .iter()
            .find(|x| x.is::<T>())
            .and_then(|a| a.downcast_ref::<T>())
            .ok_or_else(|| ScriptError::engine_err(format!("Missing global: {}", type_name::<T>())))
    }
}
