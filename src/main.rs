// 入口:加载配置 → 初始化 DB → 内存索引 → 后台 worker → 组装路由 → 启动。
mod adapter;
mod api_admin;
mod api_forward;
mod auth;
mod config;
mod crypto;
mod db;
mod embed;
mod error;
mod models;
mod pools;
mod scheduler;
mod state;
mod sync;

use crate::adapter::Registry;
use crate::scheduler::ProxyClientPool;
use crate::state::{AppState, SharedState};
use axum::extract::Path;
use axum::response::Response;
use axum::routing::{any, get, patch, post};
use axum::{middleware, Router};
use std::sync::Arc;
use std::time::Duration;

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    tracing_subscriber::fmt().init();

    let config = config::Config::load()?;
    let pool = db::init_pool(&config.database_url).await?;
    db::migrate(&pool).await?;
    db::seed(
        &pool,
        config.admin_user.as_deref(),
        config.admin_password.as_deref(),
    )
    .await?;

    let aes_key = config.aes_key();
    let pools = Arc::new(pools::Pools::new(pool.clone(), aes_key));
    pools.load_all().await?;
    for slug in adapter::known_slugs() {
        let mc: Option<i32> = sqlx::query_scalar("SELECT max_concurrency FROM platforms WHERE slug=?")
            .bind(slug)
            .fetch_optional(&pool)
            .await?;
        match mc {
            Some(m) => pools.ensure_platform_permit(slug, m as usize),
            None => pools.ensure_platform_permit(slug, 32),
        }
    }

    let registry = Arc::new(Registry::new());
    let proxy_clients = ProxyClientPool::new();
    let http = reqwest::Client::builder()
        .timeout(Duration::from_secs(30))
        .build()?;
    let state: SharedState = Arc::new(AppState {
        config: config.clone(),
        pools: pools.clone(),
        registry: registry.clone(),
        proxy_clients,
        http: http.clone(),
    });

    sync::start_workers(pools.clone(), registry.clone(), http);

    let app = build_router(state);
    let listener = tokio::net::TcpListener::bind(&config.listen).await?;
    tracing::info!(addr = %config.listen, "keypool 服务启动");
    axum::serve(listener, app).await?;
    Ok(())
}

fn build_router(st: SharedState) -> Router<()> {
    // 转发(分发 token 鉴权)
    let fwd: Router<SharedState> = Router::new()
        .route("/{platform}/{*endpoint}", any(api_forward::forward_handler))
        .layer(middleware::from_fn_with_state(st.clone(), auth::require_forward));

    // 管理 API(管理员会话/管理 key 鉴权)
    let admin_authed: Router<SharedState> = Router::new()
        .route("/logout", post(api_admin::logout))
        .route("/me", get(api_admin::me).patch(api_admin::change_password))
        .route("/platforms", get(api_admin::list_platforms))
        .route("/platforms/{slug}", patch(api_admin::patch_platform))
        .route("/platforms/{slug}/enable", post(api_admin::enable_platform))
        .route("/platforms/{slug}/disable", post(api_admin::disable_platform))
        .route("/platforms/{slug}/accounts", post(api_admin::upload_accounts))
        .route("/accounts", get(api_admin::list_accounts))
        .route(
            "/accounts/{id}",
            get(api_admin::get_account)
                .patch(api_admin::patch_account)
                .delete(api_admin::delete_account),
        )
        .route("/accounts/{id}/enable", post(api_admin::enable_account))
        .route("/accounts/{id}/disable", post(api_admin::disable_account))
        .route(
            "/proxy-groups",
            get(api_admin::list_proxy_groups).post(api_admin::create_proxy_group),
        )
        .route(
            "/proxy-groups/{id}",
            patch(api_admin::patch_proxy_group).delete(api_admin::delete_proxy_group),
        )
        .route("/proxy-groups/{id}/sync", post(api_admin::sync_proxy_group))
        .route("/proxies", get(api_admin::list_proxies))
        .route("/proxies/{id}/disable", post(api_admin::disable_proxy))
        .route("/proxies/{id}/enable", post(api_admin::enable_proxy))
        .route("/tokens", get(api_admin::list_tokens).post(api_admin::create_token))
        .route("/tokens/{id}", patch(api_admin::patch_token).delete(api_admin::delete_token))
        .route("/call-logs", get(api_admin::list_call_logs))
        .route("/stats", get(api_admin::stats))
        .route(
            "/settings",
            get(api_admin::get_settings).put(api_admin::update_settings),
        )
        .layer(middleware::from_fn_with_state(st.clone(), auth::require_admin));

    Router::<SharedState>::new()
        .route("/api/v1/admin/login", post(api_admin::login))
        .nest("/api/v1/admin", admin_authed)
        .merge(fwd)
        .route("/static/{*p}", get(serve_static))
        .route("/", get(|| async { embed::serve("index.html").await }))
        .route("/login", get(|| async { embed::serve("login.html").await }))
        .route("/dashboard", get(|| async { embed::serve("dashboard.html").await }))
        .route("/accounts", get(|| async { embed::serve("accounts.html").await }))
        .route("/proxies", get(|| async { embed::serve("proxies.html").await }))
        .route("/tokens", get(|| async { embed::serve("tokens.html").await }))
        .route("/platforms", get(|| async { embed::serve("platforms.html").await }))
        .route("/logs", get(|| async { embed::serve("logs.html").await }))
        .route("/settings", get(|| async { embed::serve("settings.html").await }))
        .fallback(|| async { embed::serve("index.html").await })
        .with_state(st)
}

async fn serve_static(Path(p): Path<String>) -> Response {
    embed::serve(&format!("static/{p}")).await
}
