// 透明转发 handler:校验平台/token 权限 → 调 scheduler → 透传上游响应。
use crate::auth::ForwardAuth;
use crate::error::{AppError, AppResult};
use crate::scheduler::{forward, PlatformCfg};
use crate::state::SharedState;
use axum::body::{to_bytes, Body};
use axum::extract::{Extension, Request, State};
use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};

const BODY_LIMIT: usize = 32 * 1024 * 1024;

pub async fn forward_handler(
    State(st): State<SharedState>,
    Extension(auth): Extension<ForwardAuth>,
    req: Request,
) -> AppResult<Response> {
    let uri = req.uri().clone();
    let method = req.method().clone();
    let (platform, endpoint) = parse_platform_path(uri.path())?;
    let endpoint = match uri.query() {
        Some(q) => format!("{}?{}", endpoint, q),
        None => endpoint,
    };

    let (parts, body) = req.into_parts();
    let bytes = to_bytes(body, BODY_LIMIT)
        .await
        .map_err(|e| AppError::bad_request(format!("读取请求体失败: {e}")))?;
    let headers = parts.headers;

    // 平台启用?
    #[derive(sqlx::FromRow)]
    struct PlatRow {
        enabled: bool,
        max_concurrency: i32,
        same_ip_isolation: bool,
        revoke_codes: String,
        rate_limit_codes: String,
        upstream_timeout_secs: i64,
    }
    let row: Option<PlatRow> = sqlx::query_as(
        "SELECT enabled, max_concurrency, same_ip_isolation, revoke_codes, rate_limit_codes, upstream_timeout_secs FROM platforms WHERE slug=?",
    )
    .bind(&platform)
    .fetch_optional(&st.pools.db)
    .await?;
    let plat = row.ok_or_else(|| AppError::not_found(format!("平台 {platform} 不存在")))?;
    if !plat.enabled {
        return Err(AppError::unavailable("平台已停用"));
    }

    // token 是否允许该平台
    let allowed: Option<i64> =
        sqlx::query_scalar("SELECT 1 FROM token_platforms WHERE token_id=? AND platform_slug=?")
            .bind(auth.token_id)
            .bind(&platform)
            .fetch_optional(&st.pools.db)
            .await?;
    if allowed.is_none() {
        return Err(AppError::forbidden("token 无权访问该平台"));
    }

    st.pools.ensure_platform_permit(&platform, plat.max_concurrency as usize);
    let cfg = PlatformCfg {
        slug: platform.clone(),
        same_ip_isolation: plat.same_ip_isolation,
        status_codes: crate::adapter::StatusCodes::parse(
            &plat.revoke_codes,
            &plat.rate_limit_codes,
        ),
        upstream_timeout_secs: plat.upstream_timeout_secs as u64,
    };

    let result = forward(
        &st.pools,
        &st.registry,
        &st.proxy_clients,
        &cfg,
        &endpoint,
        &method,
        &headers,
        bytes,
        Some(auth.token_id),
    )
    .await?;

    Ok(build_response(result))
}

fn parse_platform_path(path: &str) -> AppResult<(String, String)> {
    let p = path.trim_start_matches('/');
    let mut it = p.splitn(2, '/');
    let platform = it.next().unwrap_or("");
    let rest = it.next().unwrap_or("");
    if !crate::adapter::known_slugs().contains(&platform) {
        return Err(AppError::not_found(format!("未知平台 {platform}")));
    }
    Ok((platform.to_string(), format!("/{}", rest)))
}

fn build_response(r: crate::scheduler::ForwardResult) -> Response {
    let mut builder = Response::builder().status(r.status);
    let h = builder.headers_mut().unwrap();
    // 响应头透传:仅跳过 hop-by-hop 头和 content-length(axum 按最终 body 重设);
    // content-encoding/content-type/其余业务头一律透传(配合 reqwest 关闭 gzip,上游原样字节透传)
    for (k, v) in r.headers.iter() {
        match k.as_str() {
            "content-length" | "transfer-encoding" | "connection" | "keep-alive" => {}
            _ => {
                h.append(k, v.clone());
            }
        }
    }
    builder.body(Body::from(r.body)).unwrap_or_else(|_| {
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            "构建响应失败",
        )
            .into_response()
    })
}
