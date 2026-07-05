//! Application errors.
//!
//! The console surface is browser-facing, so a failure renders the enterprise error page (same
//! app-bar + design tokens). The public `/a/` edge is a byte API for `<img>`/`<script>`, so its
//! handler returns bare status codes rather than HTML (see [`crate::handlers::serve`]).

use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use thiserror::Error;

#[derive(Debug, Error)]
pub enum AppError {
    /// Malformed/rejected request (CSRF mismatch, empty input, oversize asset, bad origin).
    #[error("bad_request: {0}")]
    BadRequest(String),

    /// No such resource (asset path/hash).
    #[error("not_found: {0}")]
    NotFound(String),

    /// Unexpected internal failure (store / blob / origin I/O).
    #[error("server_error: {0}")]
    Internal(String),
}

impl AppError {
    /// Map to `(status, heading, message)` for the rendered error page.
    fn parts(&self) -> (StatusCode, &'static str, String) {
        match self {
            AppError::BadRequest(d) => (StatusCode::BAD_REQUEST, "Request rejected", d.clone()),
            AppError::NotFound(d) => (StatusCode::NOT_FOUND, "Not found", d.clone()),
            AppError::Internal(d) => (
                StatusCode::INTERNAL_SERVER_ERROR,
                "Something went wrong",
                d.clone(),
            ),
        }
    }
}

impl IntoResponse for AppError {
    fn into_response(self) -> Response {
        let (status, heading, message) = self.parts();
        crate::handlers::render_error(status, heading, &message, None).into_response()
    }
}

/// Store failures collapse to a 500 server_error.
impl From<crate::store::StoreError> for AppError {
    fn from(e: crate::store::StoreError) -> Self {
        AppError::Internal(e.to_string())
    }
}

/// Blob failures collapse to their HTTP shape: a missing blob is a 404, everything else a 500.
impl From<crate::blobs::BlobError> for AppError {
    fn from(e: crate::blobs::BlobError) -> Self {
        match e {
            crate::blobs::BlobError::NotFound => {
                AppError::NotFound("cached bytes not found".to_string())
            }
            other => AppError::Internal(other.to_string()),
        }
    }
}
