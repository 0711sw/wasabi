use crate::scripts::compiler::{compile, CompilationResult};
use crate::scripts::env::function::{Function, FunctionFlags, ScriptFn};
use crate::scripts::value::boolean::define_boolean_type;
use crate::scripts::value::core::define_core_types;
use crate::scripts::value::list::define_list_type;
use crate::scripts::value::number::define_number_type;
use crate::scripts::value::string::define_string_type;
use crate::scripts::value::TypeName;
use std::collections::HashMap;
use std::sync::Arc;

#[derive(Clone)]
pub struct Engine {
    inner: Arc<EngineInner>,
}

pub struct EngineBuilder {
    inner: EngineInner,
}

struct EngineInner {
    functions: HashMap<&'static str, Function>,
    types: HashMap<String, TypeName>,
}

impl EngineBuilder {
    pub fn new() -> EngineBuilder {
        let mut result = Self {
            inner: EngineInner {
                functions: HashMap::new(),
                types: HashMap::new(),
            },
        };

        define_core_types(&mut result);
        define_boolean_type(&mut result);
        define_number_type(&mut result);
        define_string_type(&mut result);
        define_list_type(&mut result);

        result
    }

    pub fn register_type(&mut self, type_name: TypeName) {
        self.inner.types.insert(type_name.to_string(), type_name);
    }

    pub fn register_function(
        &mut self,
        name: &'static str,
        parameters: &[&'static str],
        return_type: &'static str,
        flags: FunctionFlags,
        function: ScriptFn,
    ) {
        self.inner.functions.insert(
            name,
            Function {
                name,
                parameters: parameters.to_vec(),
                return_type,
                script_fn: Arc::new(function),
                flags,
            },
        );
    }

    pub fn build(self) -> Engine {
        Engine {
            inner: Arc::new(self.inner),
        }
    }
}

impl Engine {
    pub(crate) fn find_type(&self, type_name: &str) -> Option<TypeName> {
        self.inner.types.get(type_name).cloned()
    }

    pub(crate) fn find_function(&self, name: &str) -> Option<&Function> {
        self.inner.functions.get(name)
    }
    
    pub fn compile(&self, source: impl AsRef<str>) -> CompilationResult {
        compile(source.as_ref(), self.clone())
    }
}
