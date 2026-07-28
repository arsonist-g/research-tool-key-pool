// 统一错误类型 → RFC 9457 Problem Details。
use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use serde::Serialize;

#[derive(Debug, Clone)]
pub struct AppError {
    pub status: StatusCode,
    pub kind: &'static str,
    pub title: &'static str,
    pub detail: String,
}

impl AppError {
    pub fn new(
        status: StatusCode,
        kind: &'static str,
        title: &'static str,
        detail: impl Into<String>,
    ) -> Self {
        Self {
            status,
            kind,
            title,
            detail: detail.into(),
        }
    }
    pub fn bad_request(detail: impl Into<String>) -> Self {
        Self::new(StatusCode::BAD_REQUEST, "bad-request", "Bad Request", detail)
    }
    pub fn unauthorized(detail: impl Into<String>) -> Self {
        Self::new(StatusCode::UNAUTHORIZED, "unauthorized", "Unauthorized", detail)
    }
    pub fn forbidden(detail: impl Into<String>) -> Self {
        Self::new(StatusCode::FORBIDDEN, "forbidden", "Forbidden", detail)
    }
    pub fn not_found(detail: impl Into<String>) -> Self {
        Self::new(StatusCode::NOT_FOUND, "not-found", "Not Found", detail)
    }
    pub fn unavailable(detail: impl Into<String>) -> Self {
        Self::new(
            StatusCode::SERVICE_UNAVAILABLE,
            "no-resource",
            "No Available Resource",
            detail,
        )
    }
    pub fn internal(detail: impl Into<String>) -> Self {
        Self::new(
            StatusCode::INTERNAL_SERVER_ERROR,
            "internal",
            "Internal Error",
            detail,
        )
    }
}

#[derive(Serialize)]
struct ProblemDetails {
    #[serde(rename = "type")]
    typ: String,
    title: String,
    status: u16,
    detail: String,
}

impl IntoResponse for AppError {
    fn into_response(self) -> Response {
        let body = ProblemDetails {
            typ: format!("about:blank#{}", self.kind),
            title: self.title.to_string(),
            status: self.status.as_u16(),
            detail: self.detail,
        };
        (
            self.status,
            [("content-type", "application/problem+json")],
            axum::Json(body),
        )
            .into_response()
    }
}

impl From<sqlx::Error> for AppError {
    fn from(e: sqlx::Error) -> Self {
        match e {
            sqlx::Error::RowNotFound => AppError::not_found("资源不存在"),
            _ => {
                tracing::error!(?e, "db error");
                AppError::internal("数据库错误")
            }
        }
    }
}

impl From<anyhow::Error> for AppError {
    fn from(e: anyhow::Error) -> Self {
        tracing::error!(?e, "internal error");
        AppError::internal(e.to_string())
    }
}

pub type AppResult<T> = Result<T, AppError>;
