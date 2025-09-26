use crate::scripts::env::engine::EngineBuilder;
use crate::scripts::env::function::{ArgsExt, FunctionFlags, ScriptFn};
use crate::scripts::value::boolean::TYPE_BOOLEAN;
use crate::scripts::value::list::List;
use crate::scripts::value::string::TYPE_STRING;
use crate::scripts::value::{TypeName, Value};
use crate::web::auth::user::User;

pub const TYPE_NULL: TypeName = "Null";
pub const TYPE_ANY: TypeName = "Any";

pub(crate) fn define_core_types(engine: &mut EngineBuilder) {
    engine.register_type(TYPE_NULL);
    engine.register_type(TYPE_ANY);

    engine.register_function(
        "Any::toString",
        &[TYPE_ANY],
        TYPE_STRING,
        FunctionFlags::PURE,
        ScriptFn::SimpleSync(|mut args, _| Ok(Value::string(args.read_value(0)?.to_string()))),
    );

    engine.register_function(
        "Any::isString",
        &[TYPE_ANY],
        TYPE_BOOLEAN,
        FunctionFlags::PURE,
        ScriptFn::SimpleSync(|args, _| Ok(Value::Boolean(args.read_value(0)?.is_string()))),
    );

    engine.register_function(
        "Any::isNumber",
        &[TYPE_ANY],
        TYPE_BOOLEAN,
        FunctionFlags::PURE,
        ScriptFn::SimpleSync(|args, _| Ok(Value::Boolean(args.read_value(0)?.is_number()))),
    );

    engine.register_function(
        "Any::isBoolean",
        &[TYPE_ANY],
        TYPE_BOOLEAN,
        FunctionFlags::PURE,
        ScriptFn::SimpleSync(|args, _| Ok(Value::Boolean(args.read_value(0)?.is_boolean()))),
    );

    engine.register_function(
        "Any::isList",
        &[TYPE_ANY],
        TYPE_BOOLEAN,
        FunctionFlags::PURE,
        ScriptFn::SimpleSync(|args, _| {
            Ok(Value::Boolean(
                args.read_value(0)?.as_object::<List>().is_some(),
            ))
        }),
    );

    engine.register_function(
        "Any::is",
        &[TYPE_ANY, TYPE_STRING],
        TYPE_BOOLEAN,
        FunctionFlags::PURE,
        ScriptFn::SimpleSync(|mut args, _| {
            let this = args.read_value(0)?;
            let type_name = args.read(1, Value::as_string)?;
            Ok(Value::Boolean(this.type_name() == type_name))
        }),
    );
}
