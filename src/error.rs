//! ``traefik-cloudflare-auth``
//!
//! Error module to handle generated errors as HTTP responses.

use axum::{
    http::StatusCode,
    response::{IntoResponse, Response},
};

#[macro_export]
macro_rules! match_error {
    ($v: expr, $e: ident) => {
        match $v {
            Ok(v) => v,
            Err(e) => return Err(AuthError::$e(e.to_string())),
        }
    };
}

/// Collection of error types to convert into HTTP responses.
#[derive(Debug)]
pub enum AuthError {
    // Returns `500` with given error.
    ConvertFailure(String),
    // Returns `401` with given error.
    VerifyFailure(String),
    // Returns `401` with static error.
    MissingData,
}

impl IntoResponse for AuthError {
    fn into_response(self) -> Response {
        // Match each `AuthError` to an appropriate response.
        match self {
            AuthError::ConvertFailure(e) => (StatusCode::INTERNAL_SERVER_ERROR, e),
            AuthError::VerifyFailure(e) => (StatusCode::UNAUTHORIZED, e),
            AuthError::MissingData => (StatusCode::UNAUTHORIZED, "no data provided".into()),
        }
        .into_response()
    }
}
