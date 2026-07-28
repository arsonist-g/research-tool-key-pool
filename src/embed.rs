// 前端静态资源(rust-embed 编译期内嵌 frontend/)。
use axum::body::Body;
use axum::http::{HeaderValue, StatusCode};
use axum::response::{IntoResponse, Response};
use rust_embed::Embed;

#[derive(Embed)]
#[folder = "frontend/"]
struct Asset;

pub async fn serve(path: &str) -> Response {
    let file = Asset::get(path).or_else(|| Asset::get("index.html"));
    match file {
        Some(f) => {
            let mime = mime_guess::from_path(path)
                .first_or_octet_stream()
                .essence_str()
                .to_string();
            let mut builder = Response::builder().status(StatusCode::OK);
            if let Ok(v) = HeaderValue::from_str(&mime) {
                builder = builder.header("content-type", v);
            }
            builder
                .body(Body::from(f.data.into_owned()))
                .unwrap_or_else(|_| (StatusCode::INTERNAL_SERVER_ERROR, "embed build err").into_response())
        }
        None => (StatusCode::NOT_FOUND, "not found").into_response(),
    }
}
