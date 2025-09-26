use crate::scripts::compiler::span::ByteSpan;
use crate::scripts::value::core::TYPE_ANY;
use crate::scripts::value::TypeName;

#[derive(Debug)]
pub struct ScriptError {
    span: Option<ByteSpan>,
    kind: ScriptErrorKind,
}

impl ScriptError {}

pub type ScriptResult<T> = Result<T, ScriptError>;

impl ScriptError {
    pub fn engine_err(message: impl ToString) -> Self {
        Self {
            span: None,
            kind: ScriptErrorKind::EngineErr(message.to_string()),
        }
    }

    pub fn program_err(message: impl ToString) -> Self {
        Self {
            span: None,
            kind: ScriptErrorKind::ProgramErr(message.to_string()),
        }
    }

    pub fn user_err(message: impl ToString) -> Self {
        Self {
            span: None,
            kind: ScriptErrorKind::UserErr(message.to_string()),
        }
    }

    pub fn at(mut self, span: ByteSpan) -> Self {
        self.span = Some(span);

        self
    }

    pub fn fill_at(mut self, span: &ByteSpan) -> Self {
        if self.span.is_none() {
            self.span = Some(span.clone());
        }

        self
    }

    pub fn enforce_arg_count(expected_args: usize, given_args: usize) -> ScriptResult<()> {
        if expected_args != given_args {
            Err(Self::engine_err(format!(
                "This function expects {expected_args} but {given_args} were given."
            )))
        } else {
            Ok(())
        }
    }
    pub fn enforce_arg_type(
        index: usize,
        expected_type: TypeName,
        given_type: TypeName,
    ) -> ScriptResult<()> {
        if expected_type != given_type && expected_type != TYPE_ANY {
            Err(Self::engine_err(format!(
                "This function expects {expected_type} as its {}. argument but {given_type} was given.",
                index + 1
            )))
        } else {
            Ok(())
        }
    }

    pub fn async_call_in_sync_context(message: String) -> ScriptError {
        Self::engine_err(format!(
            "An async node was evaluated in a sync context: {message}"
        ))
    }
}

#[derive(Debug)]
pub enum ScriptErrorKind {
    EngineErr(String),
    ProgramErr(String),
    UserErr(String),
}

pub trait ErrorExt {
    fn as_program_err(&self) -> ScriptError;

    fn as_engine_err(&self) -> ScriptError;

    fn as_user_err(&self) -> ScriptError;
}

impl ErrorExt for anyhow::Error {
    fn as_program_err(&self) -> ScriptError {
        ScriptError::program_err(format!("{:#}", self))
    }

    fn as_engine_err(&self) -> ScriptError {
        ScriptError::engine_err(format!("{:#}", self))
    }

    fn as_user_err(&self) -> ScriptError {
        ScriptError::user_err(format!("{}", self))
    }
}
