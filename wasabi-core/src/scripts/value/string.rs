use crate::scripts::env::engine::EngineBuilder;
use crate::scripts::env::function::{ArgsExt, FunctionFlags, ScriptFn};
use crate::scripts::value::core::TYPE_ANY;
use crate::scripts::value::{TypeName, Value};

pub const TYPE_STRING: TypeName = "String";

pub(crate) fn define_string_type(engine: &mut EngineBuilder) {
    engine.register_type(TYPE_STRING);
    engine.register_function(
        "String::add",
        &[TYPE_ANY, TYPE_ANY],
        TYPE_STRING,
        FunctionFlags::PURE | FunctionFlags::INTERNAL,
        ScriptFn::SimpleSync(|args, _| {
            let a = args.read_value(0)?;
            let b = args.read_value(1)?;
            Ok(Value::string(format!("{}{}", a, b)))
        }),
    );
}
