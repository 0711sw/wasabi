pub mod boolean;
pub mod core;
pub mod list;
pub mod number;
pub mod string;

use crate::scripts::value::boolean::TYPE_BOOLEAN;
use crate::scripts::value::core::TYPE_NULL;
use crate::scripts::value::number::TYPE_NUMBER;
use crate::scripts::value::string::TYPE_STRING;
use rust_decimal::Decimal;
use std::any::Any;
use std::fmt::{Debug, Display, Formatter};
use std::rc::Rc;
use std::sync::Arc;

pub type TypeName = &'static str;

#[derive(Clone, Debug)]
pub enum Value {
    Null,
    String(Arc<str>),
    Number(Decimal),
    Boolean(bool),
    Object(Object),
}

impl Display for Value {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        match self {
            Value::Null => write!(f, "null"),
            Value::String(s) => write!(f, "{}", s),
            Value::Number(n) => write!(f, "{}", n),
            Value::Boolean(b) => write!(f, "{}", b),
            Value::Object(obj) => write!(f, "{}", obj),
        }
    }
}

impl Value {
    pub fn type_name(&self) -> TypeName {
        match self {
            Value::Null => TYPE_NULL,
            Value::String(_) => TYPE_STRING,
            Value::Number(_) => TYPE_NUMBER,
            Value::Boolean(_) => TYPE_BOOLEAN,
            Value::Object(obj) => obj.type_name,
        }
    }

    pub fn string(s: impl AsRef<str>) -> Self {
        Value::String(s.as_ref().into())
    }

    pub fn is_null(&self) -> bool {
        matches!(self, Value::Null)
    }

    pub fn is_string(&self) -> bool {
        matches!(self, Value::String(_))
    }

    pub fn is_number(&self) -> bool {
        matches!(self, Value::Number(_))
    }

    pub fn is_boolean(&self) -> bool {
        matches!(self, Value::Boolean(_))
    }

    pub fn as_string(&self) -> Option<&str> {
        if let Value::String(s) = self {
            Some(s)
        } else {
            None
        }
    }

    pub fn as_number(&self) -> Option<Decimal> {
        if let Value::Number(n) = self {
            Some(*n)
        } else {
            None
        }
    }

    pub fn as_boolean(&self) -> Option<bool> {
        if let Value::Boolean(b) = self {
            Some(*b)
        } else {
            None
        }
    }

    pub fn as_object<T: ObjectType + 'static>(&self) -> Option<&T> {
        if let Value::Object(obj) = self {
            obj.value.as_ref().as_any().downcast_ref::<T>()
        } else {
            None
        }
    }
}

pub trait ObjectType: Any + Debug + Display {
    fn as_any(&self) -> &dyn Any;
}

impl<T: Any + Debug + Display> ObjectType for T {
    fn as_any(&self) -> &dyn Any {
        self
    }
}

#[derive(Clone)]
pub struct Object {
    value: Rc<dyn ObjectType>,
    type_name: TypeName,
}

impl Debug for Object {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        write!(f, "{:?}", self.value.as_ref())
    }
}

impl Display for Object {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.value)
    }
}
