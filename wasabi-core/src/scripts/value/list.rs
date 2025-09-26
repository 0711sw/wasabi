use crate::scripts::env::engine::EngineBuilder;
use crate::scripts::env::function::{ArgsExt, FunctionFlags, ScriptFn};
use crate::scripts::value::core::TYPE_ANY;
use crate::scripts::value::{Object, TypeName, Value};
use std::cell::RefCell;
use std::fmt::{Debug, Display, Formatter};
use std::rc::Rc;

pub const TYPE_LIST: TypeName = "List";
pub struct List {
    pub items: RefCell<Vec<Value>>,
}

impl Display for List {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        let items: Vec<String> = self.items.borrow().iter().map(|v| format!("{v}")).collect();
        write!(f, "[{}]", items.join(", "))
    }
}

impl Debug for List {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        let items: Vec<String> = self
            .items
            .borrow()
            .iter()
            .map(|v| format!("{v:?}"))
            .collect();
        write!(f, "[{}]", items.join(", "))
    }
}

impl List {
    pub fn into_value(self) -> Value {
        Value::Object(Object {
            value: Rc::new(self),
            type_name: TYPE_LIST,
        })
    }

    pub fn new() -> Self {
        Self {
            items: RefCell::new(Vec::new()),
        }
    }

    pub fn push(&self, value: Value) {
        self.items.borrow_mut().push(value);
    }

    pub fn get(&self, index: usize) -> Option<Value> {
        self.items.borrow().get(index).cloned()
    }

    pub fn len(&self) -> usize {
        self.items.borrow().len()
    }
}

pub(crate) fn define_list_type(engine: &mut EngineBuilder) {
    engine.register_type(TYPE_LIST);

    engine.register_function(
        "newList",
        &[],
        TYPE_LIST,
        FunctionFlags::PURE,
        ScriptFn::SimpleSync(|_, _| Ok(List::new().into_value())),
    );

    engine.register_function(
        "List::push",
        &[TYPE_LIST, TYPE_ANY],
        TYPE_LIST,
        FunctionFlags::PURE,
        ScriptFn::SimpleSync(|mut args, _| {
            let list = args.read(0, Value::as_object::<List>)?;
            let arg = args.read_value(1)?;

            list.items.borrow_mut().push(arg.clone());

            args.read_value(0).cloned()
        }),
    );
}
