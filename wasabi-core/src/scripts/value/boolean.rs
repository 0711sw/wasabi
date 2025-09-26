use crate::scripts::env::engine::EngineBuilder;
use crate::scripts::env::function::{ArgsExt, FunctionFlags, ScriptFn};
use crate::scripts::eval::error::ScriptError;
use crate::scripts::value::core::TYPE_ANY;
use crate::scripts::value::{TypeName, Value};

pub const TYPE_BOOLEAN: TypeName = "Boolean";

pub(crate) fn define_boolean_type(engine: &mut EngineBuilder) {
    engine.register_type(TYPE_BOOLEAN);

    engine.register_function(
        "Boolean::not",
        &[TYPE_BOOLEAN],
        TYPE_BOOLEAN,
        FunctionFlags::PURE | FunctionFlags::INTERNAL,
        ScriptFn::SimpleSync(|mut args, ctx| {
            let arg = args.read(0, Value::as_boolean)?;
            Ok(Value::Boolean(!arg))
        }),
    );

    engine.register_function(
        "if",
        &[TYPE_BOOLEAN, TYPE_ANY, TYPE_ANY],
        TYPE_ANY,
        FunctionFlags::PURE | FunctionFlags::INTERNAL,
        ScriptFn::Lazy {
            async_fn: |args, ctx| {
                Box::pin(async move {
                    let _ = ScriptError::enforce_arg_count(3, args.len())?;

                    let condition = args[0].eval(ctx).await?.as_boolean().ok_or_else(|| {
                        ScriptError::engine_err("The condition in 'if' needs to be a boolean")
                    })?;

                    if condition {
                        Ok(args[1].eval(ctx).await?)
                    } else {
                        Ok(args[2].eval(ctx).await?)
                    }
                })
            },
            sync_fn: Some(|args, ctx| {
                let _ = ScriptError::enforce_arg_count(3, args.len())?;

                let condition = args[0].eval_sync(ctx)?.as_boolean().ok_or_else(|| {
                    ScriptError::engine_err("The condition in 'if' needs to be a boolean")
                })?;
                if condition {
                    Ok(args[1].eval_sync(ctx)?)
                } else {
                    Ok(args[2].eval_sync(ctx)?)
                }
            }),
        },
    );
}
