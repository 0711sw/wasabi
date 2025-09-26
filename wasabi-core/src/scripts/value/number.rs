use crate::scripts::env::engine::EngineBuilder;
use crate::scripts::env::function::{ArgsExt, FunctionFlags, ScriptFn};
use crate::scripts::eval::error::ScriptError;
use crate::scripts::value::boolean::TYPE_BOOLEAN;
use crate::scripts::value::{TypeName, Value};
use rust_decimal::Decimal;

pub const TYPE_NUMBER: TypeName = "Number";

pub(crate) fn define_number_type(engine: &mut EngineBuilder) {
    engine.register_type(TYPE_NUMBER);

    engine.register_function(
        "Number::add",
        &[TYPE_NUMBER, TYPE_NUMBER],
        TYPE_NUMBER,
        FunctionFlags::PURE | FunctionFlags::INTERNAL,
        ScriptFn::SimpleSync(|mut args, _| {
            let a = args.read(0, Value::as_number)?;
            let b = args.read(1, Value::as_number)?;
            Ok(Value::Number(a + b))
        }),
    );

    engine.register_function(
        "Number::subtract",
        &[TYPE_NUMBER, TYPE_NUMBER],
        TYPE_NUMBER,
        FunctionFlags::PURE | FunctionFlags::INTERNAL,
        ScriptFn::SimpleSync(|mut args, _| {
            let a = args.read(0, Value::as_number)?;
            let b = args.read(1, Value::as_number)?;
            Ok(Value::Number(a - b))
        }),
    );

    engine.register_function(
        "Number::multiply",
        &[TYPE_NUMBER, TYPE_NUMBER],
        TYPE_NUMBER,
        FunctionFlags::PURE | FunctionFlags::INTERNAL,
        ScriptFn::SimpleSync(|mut args, _| {
            let a = args.read(0, Value::as_number)?;
            let b = args.read(1, Value::as_number)?;
            Ok(Value::Number(a * b))
        }),
    );

    engine.register_function(
        "Number::divide",
        &[TYPE_NUMBER, TYPE_NUMBER],
        TYPE_NUMBER,
        FunctionFlags::PURE | FunctionFlags::INTERNAL,
        ScriptFn::SimpleSync(|mut args, _| {
            let a = args.read(0, Value::as_number)?;
            let b = args.read(1, Value::as_number)?;

            if b == Decimal::ZERO {
                return Err(ScriptError::program_err("Division by zero"));
            }

            Ok(Value::Number(a / b))
        }),
    );

    engine.register_function(
        "Number::lt",
        &[TYPE_NUMBER, TYPE_NUMBER],
        TYPE_BOOLEAN,
        FunctionFlags::PURE | FunctionFlags::INTERNAL,
        ScriptFn::SimpleSync(|mut args, _| {
            let a = args.read(0, Value::as_number)?;
            let b = args.read(1, Value::as_number)?;

            Ok(Value::Boolean(a < b))
        }),
    );
}
