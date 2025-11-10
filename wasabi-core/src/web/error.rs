use serde::Serialize;
use std::fmt::{Debug, Display, Formatter};
use warp::http::StatusCode;
use warp::reject::Reject;

#[derive(Clone, Serialize, Debug)]
#[serde(rename_all = "camelCase")]
pub struct ApiError {
    #[serde(skip)]
    pub status: StatusCode,
    pub message: String,
}

impl Display for ApiError {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.message)
    }
}

impl Reject for ApiError {}

impl ApiError {
    pub fn new(status: StatusCode, message: impl ToString) -> Self {
        ApiError {
            status,
            message: message.to_string(),
        }
    }
}

pub trait ResultExt<T> {
    fn with_status(self, status: StatusCode) -> Result<T, anyhow::Error>;

    fn mark_client_error(self) -> Result<T, anyhow::Error>;
}

impl<T> ResultExt<T> for Result<T, anyhow::Error> {
    fn with_status(self, status: StatusCode) -> Result<T, anyhow::Error> {
        match self {
            Ok(t) => Ok(t),
            Err(err) => {
                let message = format!("{:#}", err);
                Err(err.context(ApiError { status, message }))
            }
        }
    }

    fn mark_client_error(self) -> Result<T, anyhow::Error> {
        self.with_status(StatusCode::BAD_REQUEST)
    }
}

#[macro_export]
macro_rules! client_bail {
    ($err:expr $(,)?) => {
        return $crate::web::error::ResultExt::mark_client_error(Err(::anyhow::anyhow!($err)))
    };
    ($fmt:expr, $($arg:tt)*) => {
        return $crate::web::error::ResultExt::mark_client_error(Err(::anyhow::anyhow!($fmt, $($arg)*)))
    };
}

#[macro_export]
macro_rules! status_bail {
    ($status:expr, $msg:literal $(,)?) => {
        return $crate::web::error::ResultExt::with_status(Err(::anyhow::anyhow!($msg)), $status)
    };
    ($status:expr, $fmt:literal, $($arg:tt)*) => {
        return $crate::web::error::ResultExt::with_status(Err(::anyhow::anyhow!($fmt, $($arg)*)), $status)
    };
}
