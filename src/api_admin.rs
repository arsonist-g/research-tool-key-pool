// 管理 API handler(/api/v1/admin/*):登录会话 / 平台 / 号 / 代理组 / 代理 / token / 日志 / 统计。
use crate::auth::{sign_session, AdminUser};
use crate::crypto;
use crate::error::{AppError, AppResult};
use crate::models::{Account, CallLog, IssuedToken, Platform, Proxy, ProxyGroup};
use crate::state::SharedState;
use crate::sync;
use axum::extract::{Extension, Path, Query, State};
use axum::http::StatusCode;
use axum::response::IntoResponse;
use axum::Json;
use chrono::Utc;
use rand::RngCore;
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use std::sync::Arc;
use tokio::sync::Semaphore;

#[derive(Serialize)]
pub struct Paginated<T: Serialize> {
    pub items: Vec<T>,
    pub total: i64,
    pub has_more: bool,
    pub next_cursor: Option<i64>,
}

// —— 登录 / 会话 ——
#[derive(sqlx::FromRow)]
struct LoginRow {
    id: i64,
    password_hash: String,
}

#[derive(Deserialize)]
pub struct LoginReq {
    username: String,
    password: String,
}

pub async fn login(
    State(st): State<SharedState>,
    Json(req): Json<LoginReq>,
) -> AppResult<impl IntoResponse> {
    let row: Option<LoginRow> =
        sqlx::query_as("SELECT id, password_hash FROM admins WHERE username=?")
            .bind(&req.username)
            .fetch_optional(&st.pools.db)
            .await?;
    let lr = row.ok_or_else(|| AppError::unauthorized("用户名或密码错误"))?;
    if !crate::db::verify_password(&req.password, &lr.password_hash) {
        return Err(AppError::unauthorized("用户名或密码错误"));
    }
    let val = sign_session(lr.id, &st.config.session_hmac_key());
    let cookie = format!("kp_session={val}; Path=/; HttpOnly; Max-Age=604800; SameSite=Strict");
    Ok((
        StatusCode::OK,
        [("set-cookie", cookie)],
        Json(json!({"id": lr.id, "username": req.username})),
    ))
}

pub async fn logout() -> impl IntoResponse {
    (
        StatusCode::NO_CONTENT,
        [("set-cookie", "kp_session=; Path=/; Max-Age=0")],
    )
}

pub async fn me(
    State(st): State<SharedState>,
    Extension(u): Extension<AdminUser>,
) -> AppResult<Json<Value>> {
    if u.id == 0 {
        return Ok(Json(json!({"id": 0, "username": "admin (api-key)"})));
    }
    let username: String = sqlx::query_scalar("SELECT username FROM admins WHERE id=?")
        .bind(u.id)
        .fetch_one(&st.pools.db)
        .await?;
    Ok(Json(json!({"id": u.id, "username": username})))
}

#[derive(Deserialize)]
pub struct ChangePassReq {
    old_password: String,
    new_password: String,
}

pub async fn change_password(
    State(st): State<SharedState>,
    Extension(u): Extension<AdminUser>,
    Json(req): Json<ChangePassReq>,
) -> AppResult<StatusCode> {
    if u.id == 0 {
        return Err(AppError::bad_request("api-key 模式不能改密码"));
    }
    let hash: String = sqlx::query_scalar("SELECT password_hash FROM admins WHERE id=?")
        .bind(u.id)
        .fetch_one(&st.pools.db)
        .await?;
    if !crate::db::verify_password(&req.old_password, &hash) {
        return Err(AppError::unauthorized("旧密码错误"));
    }
    let new_hash = crate::db::hash_password(&req.new_password)?;
    sqlx::query("UPDATE admins SET password_hash=? WHERE id=?")
        .bind(new_hash)
        .bind(u.id)
        .execute(&st.pools.db)
        .await?;
    Ok(StatusCode::NO_CONTENT)
}

// —— 平台 ——
pub async fn list_platforms(State(st): State<SharedState>) -> AppResult<Json<Value>> {
    let rows: Vec<Platform> = sqlx::query_as("SELECT * FROM platforms ORDER BY slug")
        .fetch_all(&st.pools.db)
        .await?;
    #[derive(sqlx::FromRow)]
    struct Bind {
        platform_slug: String,
        proxy_group_id: i64,
    }
    let binds: Vec<Bind> =
        sqlx::query_as("SELECT platform_slug, proxy_group_id FROM platform_proxy_groups")
            .fetch_all(&st.pools.db)
            .await?;
    let mut map: std::collections::HashMap<String, Vec<i64>> = std::collections::HashMap::new();
    for b in binds {
        map.entry(b.platform_slug).or_default().push(b.proxy_group_id);
    }
    let out: Vec<Value> = rows
        .into_iter()
        .map(|p| {
            let adapter = st.registry.get(&p.slug);
            let mut v = serde_json::to_value(&p).unwrap_or_else(|_| json!({}));
            let ids = map.remove(&p.slug).unwrap_or_default();
            v["proxy_group_ids"] = json!(ids);
            v["base_url"] = json!(
                adapter
                    .as_ref()
                    .map(|a| a.base_url().to_string())
                    .unwrap_or_default()
            );
            v["supports_balance_query"] =
                json!(adapter.as_ref().map(|a| a.supports_balance_query()).unwrap_or(false));
            v
        })
        .collect();
    Ok(Json(json!(out)))
}

#[derive(Deserialize)]
pub struct PatchPlatform {
    /// 绑定的代理组列表(全量替换);一个平台可绑多个组
    proxy_group_ids: Option<Vec<i64>>,
    max_concurrency: Option<i32>,
    same_ip_isolation: Option<bool>,
    default_quota_limit: Option<Option<i64>>,
    revoke_codes: Option<String>,
    rate_limit_codes: Option<String>,
    upstream_timeout_secs: Option<i64>,
    enabled: Option<bool>,
}

pub async fn patch_platform(
    State(st): State<SharedState>,
    Path(slug): Path<String>,
    Json(req): Json<PatchPlatform>,
) -> AppResult<Json<Value>> {
    let now = Utc::now();
    let mut tx = st.pools.db.begin().await?;
    sqlx::query(
        "UPDATE platforms SET
           max_concurrency=COALESCE(?, max_concurrency),
           same_ip_isolation=COALESCE(?, same_ip_isolation),
           default_quota_limit=COALESCE(?, default_quota_limit),
           revoke_codes=COALESCE(?, revoke_codes),
           rate_limit_codes=COALESCE(?, rate_limit_codes),
           upstream_timeout_secs=COALESCE(?, upstream_timeout_secs),
           enabled=COALESCE(?, enabled),
           updated_at=? WHERE slug=?",
    )
    .bind(req.max_concurrency)
    .bind(req.same_ip_isolation)
    .bind(req.default_quota_limit)
    .bind(req.revoke_codes)
    .bind(req.rate_limit_codes)
    .bind(req.upstream_timeout_secs)
    .bind(req.enabled)
    .bind(now)
    .bind(&slug)
    .execute(&mut *tx)
    .await?;
    if let Some(ids) = &req.proxy_group_ids {
        sqlx::query("DELETE FROM platform_proxy_groups WHERE platform_slug=?")
            .bind(&slug)
            .execute(&mut *tx)
            .await?;
        for gid in ids {
            sqlx::query(
                "INSERT OR IGNORE INTO platform_proxy_groups (platform_slug, proxy_group_id) VALUES (?,?)",
            )
            .bind(&slug)
            .bind(gid)
            .execute(&mut *tx)
            .await?;
        }
    }
    tx.commit().await?;
    if let Some(mc) = req.max_concurrency {
        st.pools.ensure_platform_permit(&slug, mc as usize);
    }
    // 绑组变化时,重新绑定该平台的未绑号(平台现在有代理组可用)
    if req.proxy_group_ids.is_some() {
        let null_ids: Vec<i64> = sqlx::query_scalar(
            "SELECT id FROM accounts WHERE platform_slug=? AND bound_proxy_id IS NULL",
        )
        .bind(&slug)
        .fetch_all(&st.pools.db)
        .await
        .unwrap_or_default();
        for id in null_ids {
            crate::sync::bind_account(&st.pools, id, None).await;
        }
    }
    let row: Platform = sqlx::query_as("SELECT * FROM platforms WHERE slug=?")
        .bind(&slug)
        .fetch_one(&st.pools.db)
        .await?;
    let gids: Vec<i64> =
        sqlx::query_scalar("SELECT proxy_group_id FROM platform_proxy_groups WHERE platform_slug=?")
            .bind(&slug)
            .fetch_all(&st.pools.db)
            .await
            .unwrap_or_default();
    let mut v = serde_json::to_value(&row).map_err(|e| AppError::internal(e.to_string()))?;
    v["proxy_group_ids"] = json!(gids);
    Ok(Json(v))
}

// —— 设置(运行时可调配置,设置页在线改,worker 下次循环即生效)——
pub async fn get_settings(State(st): State<SharedState>) -> AppResult<Json<Value>> {
    let s = crate::sync::read_settings(&st.pools).await;
    Ok(Json(json!({
        "sync_interval_secs": s.sync_interval_secs,
        "log_max_mb": s.log_max_mb,
        "max_retries": s.max_retries,
        "account_concurrency": s.account_concurrency,
        "balance_sync_interval_secs": s.balance_sync_interval_secs,
    })))
}

#[derive(Deserialize)]
pub struct UpdateSettings {
    pub sync_interval_secs: Option<u64>,
    pub log_max_mb: Option<i64>,
    pub max_retries: Option<u32>,
    pub account_concurrency: Option<i64>,
    pub balance_sync_interval_secs: Option<u64>,
}

pub async fn update_settings(
    State(st): State<SharedState>,
    Json(req): Json<UpdateSettings>,
) -> AppResult<Json<Value>> {
    let now = Utc::now();
    let mut tx = st.pools.db.begin().await?;
    let updates: [Option<(&str, String)>; 5] = [
        req.sync_interval_secs
            .map(|v| ("sync_interval_secs", v.to_string())),
        req.log_max_mb.map(|v| ("log_max_mb", v.to_string())),
        req.max_retries.map(|v| ("max_retries", v.to_string())),
        req.account_concurrency
            .map(|v| ("account_concurrency", v.to_string())),
        req.balance_sync_interval_secs
            .map(|v| ("balance_sync_interval_secs", v.to_string())),
    ];
    for opt in updates.into_iter().flatten() {
        let (k, v) = opt;
        sqlx::query(
            "INSERT INTO settings (key, value, updated_at) VALUES (?,?,?)
             ON CONFLICT(key) DO UPDATE SET value=excluded.value, updated_at=excluded.updated_at",
        )
        .bind(k)
        .bind(v)
        .bind(now)
        .execute(&mut *tx)
        .await?;
    }
    tx.commit().await?;
    let s = crate::sync::read_settings(&st.pools).await;
    Ok(Json(json!({
        "sync_interval_secs": s.sync_interval_secs,
        "log_max_mb": s.log_max_mb,
        "max_retries": s.max_retries,
        "account_concurrency": s.account_concurrency,
        "balance_sync_interval_secs": s.balance_sync_interval_secs,
    })))
}

pub async fn enable_platform(
    State(st): State<SharedState>,
    Path(slug): Path<String>,
) -> AppResult<StatusCode> {
    sqlx::query("UPDATE platforms SET enabled=1, updated_at=? WHERE slug=?")
        .bind(Utc::now())
        .bind(&slug)
        .execute(&st.pools.db)
        .await?;
    Ok(StatusCode::NO_CONTENT)
}
pub async fn disable_platform(
    State(st): State<SharedState>,
    Path(slug): Path<String>,
) -> AppResult<StatusCode> {
    sqlx::query("UPDATE platforms SET enabled=0, updated_at=? WHERE slug=?")
        .bind(Utc::now())
        .bind(&slug)
        .execute(&st.pools.db)
        .await?;
    Ok(StatusCode::NO_CONTENT)
}

// —— 号 ——
#[derive(Deserialize)]
pub struct UploadReq {
    accounts: Vec<UploadItem>,
    #[serde(default)]
    default_quota_limit: Option<i64>,
    /// 上传后是否立即对每个号测活(同步:并发探测完才返回,每号经其绑定代理)
    #[serde(default)]
    activate: bool,
}
#[derive(Deserialize)]
pub struct UploadItem {
    api_key: String,
    #[serde(default)]
    registration_ip: Option<String>,
}

pub async fn upload_accounts(
    State(st): State<SharedState>,
    Path(slug): Path<String>,
    Json(req): Json<UploadReq>,
) -> AppResult<Json<Value>> {
    let plat_default: Option<Option<i64>> =
        sqlx::query_scalar("SELECT default_quota_limit FROM platforms WHERE slug=?")
            .bind(&slug)
            .fetch_optional(&st.pools.db)
            .await?;
    let plat_default = match plat_default {
        Some(d) => d,
        None => return Err(AppError::not_found("平台不存在")),
    };
    let aes = st.config.aes_key();
    let now = Utc::now();
    let concur = crate::sync::read_settings(&st.pools).await.account_concurrency;
    let mut created = Vec::new();
    for item in &req.accounts {
        if item.api_key.trim().is_empty() {
            continue;
        }
        let enc = crypto::encrypt(&aes, item.api_key.as_bytes())
            .map_err(|e| AppError::internal(e.to_string()))?;
        let preview = crypto::key_preview(&item.api_key);
        let quota = req.default_quota_limit.or(plat_default);
        let id: i64 = sqlx::query_scalar(
            "INSERT INTO accounts (platform_slug, encrypted_key, key_preview, registration_ip, status, quota_limit, upload_source, created_at, updated_at)
             VALUES (?,?,?,?, 'pending', ?, 'api', ?, ?) RETURNING id",
        )
        .bind(&slug)
        .bind(&enc)
        .bind(&preview)
        .bind(&item.registration_ip)
        .bind(quota)
        .bind(now)
        .bind(now)
        .fetch_one(&st.pools.db)
        .await
        .map_err(|e| AppError::bad_request(format!("入库失败: {e}")))?;
        st.pools
            .acct_permits
            .insert(id, Arc::new(Semaphore::new(concur)));
        st.pools.accounts.insert(
            id,
            crate::models::AccountSlot {
                id,
                platform_slug: slug.clone(),
                decrypted_key: item.api_key.clone(),
                bound_proxy_id: None,
                status: "pending".into(),
                quota_limit: quota,
                quota_used: 0,
                reset_at: None,
                last_called_at: None,
                consecutive_failures: 0,
            },
        );
        sync::bind_account(&st.pools, id, item.registration_ip.as_deref()).await;
        // 上传后测活:经绑定代理探测,按结果设初始状态(healthy / hard_revoked / 保持 pending)
        let status = if req.activate {
            let r = crate::scheduler::probe_account(
                &st.pools,
                &st.registry,
                &st.proxy_clients,
                id,
            )
            .await;
            match r.outcome {
                crate::scheduler::ProbeOutcome::Alive => "healthy",
                crate::scheduler::ProbeOutcome::Revoked => "hard_revoked",
                _ => "pending",
            }
        } else {
            "pending"
        };
        created.push(json!({"id": id, "key_preview": preview, "status": status}));
    }
    Ok(Json(json!({"created": created, "skipped": 0})))
}

#[derive(Deserialize)]
pub struct AcctQuery {
    platform: Option<String>,
    status: Option<String>,
    cursor: Option<i64>,
    limit: Option<i64>,
}

pub async fn list_accounts(
    State(st): State<SharedState>,
    Query(q): Query<AcctQuery>,
) -> AppResult<Json<Paginated<Value>>> {
    let p = q.platform.clone().unwrap_or_default();
    let s = q.status.clone().unwrap_or_default();
    let cur = q.cursor.unwrap_or(0);
    let limit = q.limit.unwrap_or(50).clamp(1, 200);
    let rows: Vec<Account> = sqlx::query_as(
        "SELECT * FROM accounts
         WHERE (?='' OR platform_slug=?) AND (?='' OR status=?) AND (?=0 OR id<?)
         ORDER BY id DESC LIMIT ?",
    )
    .bind(&p)
    .bind(&p)
    .bind(&s)
    .bind(&s)
    .bind(cur)
    .bind(cur)
    .bind(limit)
    .fetch_all(&st.pools.db)
    .await?;
    let total: i64 = sqlx::query_scalar(
        "SELECT COUNT(*) FROM accounts WHERE (?='' OR platform_slug=?) AND (?='' OR status=?)",
    )
    .bind(&p)
    .bind(&p)
    .bind(&s)
    .bind(&s)
    .fetch_one(&st.pools.db)
    .await?;
    let has_more = rows.len() as i64 == limit;
    let next_cursor = rows.last().map(|a| a.id).filter(|_| has_more);
    let items: Vec<Value> = rows
        .into_iter()
        .map(|a| {
            json!({
                "id": a.id, "platform_slug": a.platform_slug, "key_preview": a.key_preview,
                "registration_ip": a.registration_ip, "bound_proxy_id": a.bound_proxy_id,
                "status": a.status, "quota_limit": a.quota_limit, "quota_used": a.quota_used,
                "quota_estimated_remaining": a.quota_estimated_remaining, "reset_at": a.reset_at,
                "last_called_at": a.last_called_at, "consecutive_failures": a.consecutive_failures,
                "upload_source": a.upload_source, "created_at": a.created_at
            })
        })
        .collect();
    Ok(Json(Paginated { items, total, has_more, next_cursor }))
}

pub async fn get_account(
    State(st): State<SharedState>,
    Path(id): Path<i64>,
) -> AppResult<Json<Value>> {
    let a: Account = sqlx::query_as("SELECT * FROM accounts WHERE id=?")
        .bind(id)
        .fetch_one(&st.pools.db)
        .await?;
    let proxy: Option<Proxy> = match a.bound_proxy_id {
        Some(pid) => sqlx::query_as("SELECT * FROM proxies WHERE id=?")
            .bind(pid)
            .fetch_optional(&st.pools.db)
            .await?,
        None => None,
    };
    Ok(Json(json!({
        "account": a,
        "proxy": proxy.map(|p| json!({"id":p.id,"host":p.host,"port":p.port,"country_code":p.country_code,"country_name":p.country_name,"exit_ip":p.exit_ip,"status":p.status}))
    })))
}

#[derive(Deserialize)]
pub struct PatchAccount {
    quota_limit: Option<Option<i64>>,
    bound_proxy_id: Option<Option<i64>>,
    registration_ip: Option<Option<String>>,
}

pub async fn patch_account(
    State(st): State<SharedState>,
    Path(id): Path<i64>,
    Json(req): Json<PatchAccount>,
) -> AppResult<StatusCode> {
    sqlx::query(
        "UPDATE accounts SET quota_limit=COALESCE(?,quota_limit), bound_proxy_id=COALESCE(?,bound_proxy_id), registration_ip=COALESCE(?,registration_ip), updated_at=? WHERE id=?",
    )
    .bind(req.quota_limit)
    .bind(req.bound_proxy_id)
    .bind(req.registration_ip)
    .bind(Utc::now())
    .bind(id)
    .execute(&st.pools.db)
    .await?;
    if let Some(Some(pid)) = req.bound_proxy_id {
        if let Some(mut s) = st.pools.accounts.get_mut(&id) {
            s.bound_proxy_id = Some(pid);
        }
    }
    if let Some(q) = req.quota_limit {
        if let Some(mut s) = st.pools.accounts.get_mut(&id) {
            s.quota_limit = q;
        }
    }
    Ok(StatusCode::NO_CONTENT)
}

pub async fn enable_account(
    State(st): State<SharedState>,
    Path(id): Path<i64>,
) -> AppResult<StatusCode> {
    st.pools.set_status(id, "healthy").await?;
    Ok(StatusCode::NO_CONTENT)
}
pub async fn disable_account(
    State(st): State<SharedState>,
    Path(id): Path<i64>,
) -> AppResult<StatusCode> {
    st.pools.set_status(id, "manual_disabled").await?;
    Ok(StatusCode::NO_CONTENT)
}
pub async fn delete_account(
    State(st): State<SharedState>,
    Path(id): Path<i64>,
) -> AppResult<StatusCode> {
    sqlx::query("DELETE FROM accounts WHERE id=?")
        .bind(id)
        .execute(&st.pools.db)
        .await?;
    st.pools.accounts.remove(&id);
    st.pools.acct_permits.remove(&id);
    Ok(StatusCode::NO_CONTENT)
}

/// 手动测活(激活)单个号:经其绑定代理发探测请求,返回结果并更新状态
pub async fn activate_account(
    State(st): State<SharedState>,
    Path(id): Path<i64>,
) -> AppResult<Json<Value>> {
    let r =
        crate::scheduler::probe_account(&st.pools, &st.registry, &st.proxy_clients, id).await;
    let outcome = match r.outcome {
        crate::scheduler::ProbeOutcome::Alive => "alive",
        crate::scheduler::ProbeOutcome::Revoked => "revoked",
        crate::scheduler::ProbeOutcome::Unknown => "unknown",
        crate::scheduler::ProbeOutcome::Skipped => "skipped",
    };
    Ok(Json(json!({
        "id": id,
        "outcome": outcome,
        "status_code": r.status,
        "reason": r.reason
    })))
}

// —— 代理组 ——
pub async fn list_proxy_groups(State(st): State<SharedState>) -> AppResult<Json<Vec<Value>>> {
    let rows: Vec<ProxyGroup> = sqlx::query_as("SELECT * FROM proxy_groups ORDER BY id")
        .fetch_all(&st.pools.db)
        .await?;
    let mut out = Vec::new();
    for g in rows {
        let cnt: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM proxies WHERE group_id=?")
            .bind(g.id)
            .fetch_one(&st.pools.db)
            .await?;
        out.push(json!({
            "id": g.id, "name": g.name, "subscription_url": g.subscription_url,
            "enabled": g.enabled, "last_synced_at": g.last_synced_at,
            "proxy_count": cnt, "created_at": g.created_at
        }));
    }
    Ok(Json(out))
}

#[derive(Deserialize)]
pub struct CreateGroupReq {
    name: String,
    subscription_url: String,
}

pub async fn create_proxy_group(
    State(st): State<SharedState>,
    Json(req): Json<CreateGroupReq>,
) -> AppResult<Json<Value>> {
    let now = Utc::now();
    let id: i64 = sqlx::query_scalar(
        "INSERT INTO proxy_groups (name, subscription_url, enabled, created_at, updated_at) VALUES (?,?,1,?,?) RETURNING id",
    )
    .bind(&req.name)
    .bind(&req.subscription_url)
    .bind(now)
    .bind(now)
    .fetch_one(&st.pools.db)
    .await
    .map_err(|e| AppError::bad_request(format!("创建失败(名称可能重复): {e}")))?;
    Ok(Json(json!({"id": id})))
}

#[derive(Deserialize)]
pub struct PatchGroupReq {
    name: Option<String>,
    subscription_url: Option<String>,
    enabled: Option<bool>,
}

pub async fn patch_proxy_group(
    State(st): State<SharedState>,
    Path(id): Path<i64>,
    Json(req): Json<PatchGroupReq>,
) -> AppResult<StatusCode> {
    let now = Utc::now();
    sqlx::query(
        "UPDATE proxy_groups SET name=COALESCE(?,name), subscription_url=COALESCE(?,subscription_url), enabled=COALESCE(?,enabled), updated_at=? WHERE id=?",
    )
    .bind(req.name)
    .bind(req.subscription_url)
    .bind(req.enabled)
    .bind(now)
    .bind(id)
    .execute(&st.pools.db)
    .await?;
    Ok(StatusCode::NO_CONTENT)
}

pub async fn delete_proxy_group(
    State(st): State<SharedState>,
    Path(id): Path<i64>,
) -> AppResult<StatusCode> {
    sqlx::query("DELETE FROM proxy_groups WHERE id=?")
        .bind(id)
        .execute(&st.pools.db)
        .await?;
    st.pools.proxies.retain(|_, p| p.group_id != id);
    Ok(StatusCode::NO_CONTENT)
}

pub async fn sync_proxy_group(
    State(st): State<SharedState>,
    Path(id): Path<i64>,
) -> AppResult<Json<Value>> {
    let (n, _) = sync::sync_group(&st.pools, id, &st.http)
        .await
        .map_err(|e| AppError::bad_request(format!("同步失败: {e}")))?;
    Ok(Json(json!({"synced": n})))
}

// —— 代理 ——
#[derive(Deserialize)]
pub struct ProxyQuery {
    group: Option<i64>,
    country: Option<String>,
    status: Option<String>,
    cursor: Option<i64>,
    limit: Option<i64>,
}

pub async fn list_proxies(
    State(st): State<SharedState>,
    Query(q): Query<ProxyQuery>,
) -> AppResult<Json<Paginated<Proxy>>> {
    let g = q.group.unwrap_or(0);
    let c = q.country.clone().unwrap_or_default();
    let s = q.status.clone().unwrap_or_default();
    let cur = q.cursor.unwrap_or(0);
    let limit = q.limit.unwrap_or(50).clamp(1, 500);
    let rows: Vec<Proxy> = sqlx::query_as(
        "SELECT * FROM proxies
         WHERE (?=0 OR group_id=?) AND (?='' OR country_code=?) AND (?='' OR status=?) AND (?=0 OR id<?)
         ORDER BY id DESC LIMIT ?",
    )
    .bind(g)
    .bind(g)
    .bind(&c)
    .bind(&c)
    .bind(&s)
    .bind(&s)
    .bind(cur)
    .bind(cur)
    .bind(limit)
    .fetch_all(&st.pools.db)
    .await?;
    let total: i64 = sqlx::query_scalar(
        "SELECT COUNT(*) FROM proxies WHERE (?=0 OR group_id=?) AND (?='' OR country_code=?) AND (?='' OR status=?)",
    )
    .bind(g)
    .bind(g)
    .bind(&c)
    .bind(&c)
    .bind(&s)
    .bind(&s)
    .fetch_one(&st.pools.db)
    .await?;
    let has_more = rows.len() as i64 == limit;
    let next_cursor = rows.last().map(|p| p.id).filter(|_| has_more);
    Ok(Json(Paginated { items: rows, total, has_more, next_cursor }))
}

pub async fn disable_proxy(
    State(st): State<SharedState>,
    Path(id): Path<i64>,
) -> AppResult<StatusCode> {
    sqlx::query("UPDATE proxies SET status='manual_disabled' WHERE id=?")
        .bind(id)
        .execute(&st.pools.db)
        .await?;
    if let Some(mut p) = st.pools.proxies.get_mut(&id) {
        p.status = "manual_disabled".into();
    }
    Ok(StatusCode::NO_CONTENT)
}
pub async fn enable_proxy(
    State(st): State<SharedState>,
    Path(id): Path<i64>,
) -> AppResult<StatusCode> {
    sqlx::query("UPDATE proxies SET status='available' WHERE id=?")
        .bind(id)
        .execute(&st.pools.db)
        .await?;
    if let Some(mut p) = st.pools.proxies.get_mut(&id) {
        p.status = "available".into();
    }
    Ok(StatusCode::NO_CONTENT)
}

// —— 分发 token ——
pub async fn list_tokens(State(st): State<SharedState>) -> AppResult<Json<Vec<Value>>> {
    let rows: Vec<IssuedToken> = sqlx::query_as("SELECT * FROM issued_tokens ORDER BY id DESC")
        .fetch_all(&st.pools.db)
        .await?;
    let mut out = Vec::new();
    for t in rows {
        let plats: Vec<String> =
            sqlx::query_scalar("SELECT platform_slug FROM token_platforms WHERE token_id=?")
                .bind(t.id)
                .fetch_all(&st.pools.db)
                .await?;
        out.push(json!({
            "id": t.id, "name": t.name, "token_prefix": t.token_prefix,
            "status": t.status, "call_count": t.call_count,
            "platforms": plats, "created_at": t.created_at, "revoked_at": t.revoked_at
        }));
    }
    Ok(Json(out))
}

#[derive(Deserialize)]
pub struct CreateTokenReq {
    name: String,
    platforms: Vec<String>,
}

pub async fn create_token(
    State(st): State<SharedState>,
    Json(req): Json<CreateTokenReq>,
) -> AppResult<Json<Value>> {
    let mut buf = [0u8; 16];
    rand::thread_rng().fill_bytes(&mut buf);
    let raw = format!("pool_{}", hex::encode(buf));
    let hash = crypto::sha256_hex(&raw);
    let prefix: String = raw.chars().take(12).collect();
    let now = Utc::now();
    let id: i64 = sqlx::query_scalar(
        "INSERT INTO issued_tokens (name, token_hash, token_prefix, created_at) VALUES (?,?,?,?) RETURNING id",
    )
    .bind(&req.name)
    .bind(&hash)
    .bind(&prefix)
    .bind(now)
    .fetch_one(&st.pools.db)
    .await?;
    for slug in &req.platforms {
        sqlx::query("INSERT OR IGNORE INTO token_platforms (token_id, platform_slug) VALUES (?,?)")
            .bind(id)
            .bind(slug)
            .execute(&st.pools.db)
            .await?;
    }
    Ok(Json(json!({"id": id, "name": req.name, "token": raw, "platforms": req.platforms})))
}

#[derive(Deserialize)]
pub struct PatchTokenReq {
    name: Option<String>,
    platforms: Option<Vec<String>>,
}

pub async fn patch_token(
    State(st): State<SharedState>,
    Path(id): Path<i64>,
    Json(req): Json<PatchTokenReq>,
) -> AppResult<StatusCode> {
    if let Some(name) = req.name {
        sqlx::query("UPDATE issued_tokens SET name=? WHERE id=?")
            .bind(name)
            .bind(id)
            .execute(&st.pools.db)
            .await?;
    }
    if let Some(plats) = req.platforms {
        sqlx::query("DELETE FROM token_platforms WHERE token_id=?")
            .bind(id)
            .execute(&st.pools.db)
            .await?;
        for slug in plats {
            sqlx::query("INSERT OR IGNORE INTO token_platforms (token_id, platform_slug) VALUES (?,?)")
                .bind(id)
                .bind(slug)
                .execute(&st.pools.db)
                .await?;
        }
    }
    Ok(StatusCode::NO_CONTENT)
}

pub async fn delete_token(
    State(st): State<SharedState>,
    Path(id): Path<i64>,
) -> AppResult<StatusCode> {
    // 硬删除:token 不用了直接删,不保留 revoked 死数据
    // (鉴权上"不存在"与"已吊销"拒绝效果一致;调用日志 token_id ON DELETE SET NULL,日志按 MB 自清理)
    sqlx::query("DELETE FROM issued_tokens WHERE id=?")
        .bind(id)
        .execute(&st.pools.db)
        .await?;
    Ok(StatusCode::NO_CONTENT)
}

// —— 调用日志 ——
#[derive(Deserialize)]
pub struct LogQuery {
    platform: Option<String>,
    account: Option<i64>,
    token: Option<i64>,
    cursor: Option<i64>,
    limit: Option<i64>,
}

pub async fn list_call_logs(
    State(st): State<SharedState>,
    Query(q): Query<LogQuery>,
) -> AppResult<Json<Paginated<CallLog>>> {
    let p = q.platform.clone().unwrap_or_default();
    let a = q.account.unwrap_or(0);
    let t = q.token.unwrap_or(0);
    let cur = q.cursor.unwrap_or(0);
    let limit = q.limit.unwrap_or(50).clamp(1, 200);
    let rows: Vec<CallLog> = sqlx::query_as(
        "SELECT * FROM call_logs
         WHERE (?='' OR platform_slug=?) AND (?=0 OR account_id=?) AND (?=0 OR token_id=?) AND (?=0 OR id<?)
         ORDER BY id DESC LIMIT ?",
    )
    .bind(&p)
    .bind(&p)
    .bind(a)
    .bind(a)
    .bind(t)
    .bind(t)
    .bind(cur)
    .bind(cur)
    .bind(limit)
    .fetch_all(&st.pools.db)
    .await?;
    let total: i64 = sqlx::query_scalar(
        "SELECT COUNT(*) FROM call_logs WHERE (?='' OR platform_slug=?) AND (?=0 OR account_id=?) AND (?=0 OR token_id=?)",
    )
    .bind(&p)
    .bind(&p)
    .bind(a)
    .bind(a)
    .bind(t)
    .bind(t)
    .fetch_one(&st.pools.db)
    .await?;
    let has_more = rows.len() as i64 == limit;
    let next_cursor = rows.last().map(|r| r.id).filter(|_| has_more);
    Ok(Json(Paginated { items: rows, total, has_more, next_cursor }))
}

// —— 统计 ——
#[derive(sqlx::FromRow)]
struct StatRow {
    platform_slug: String,
    healthy: i64,
    disabled: i64,
    hard: i64,
    total: i64,
}

#[derive(sqlx::FromRow)]
struct CallsRow {
    calls: i64,
    succ: i64,
}

pub async fn stats(State(st): State<SharedState>) -> AppResult<Json<Value>> {
    let rows: Vec<StatRow> = sqlx::query_as(
        "SELECT platform_slug AS platform_slug,
           SUM(CASE WHEN status IN('healthy','pending') THEN 1 ELSE 0 END) AS healthy,
           SUM(CASE WHEN status='manual_disabled' THEN 1 ELSE 0 END) AS disabled,
           SUM(CASE WHEN status='hard_revoked' THEN 1 ELSE 0 END) AS hard,
           COUNT(*) AS total
         FROM accounts GROUP BY platform_slug",
    )
    .fetch_all(&st.pools.db)
    .await?;
    let mut platforms = Vec::new();
    let mut calls_today = 0i64;
    let mut success_today = 0i64;
    for r in rows {
        let c: CallsRow = sqlx::query_as(
            "SELECT COUNT(*) AS calls, COALESCE(SUM(CASE WHEN success=1 THEN 1 ELSE 0 END),0) AS succ
             FROM call_logs WHERE platform_slug=? AND date(created_at)=date('now')",
        )
        .bind(&r.platform_slug)
        .fetch_one(&st.pools.db)
        .await
        .unwrap_or(CallsRow { calls: 0, succ: 0 });
        calls_today += c.calls;
        success_today += c.succ;
        platforms.push(json!({
            "slug": r.platform_slug, "total": r.total, "healthy": r.healthy,
            "disabled": r.disabled, "hard_revoked": r.hard, "calls_today": c.calls
        }));
    }
    let success_rate = if calls_today > 0 {
        success_today as f64 / calls_today as f64
    } else {
        0.0
    };
    Ok(Json(json!({
        "platforms": platforms,
        "totals": {"calls_today": calls_today, "success_rate": success_rate}
    })))
}
