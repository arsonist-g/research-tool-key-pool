// 调度引擎:选号选代理 → 改头 → 经代理转发 → 判定(封号永久剔除/限流退避)→ 换号重试 / 降级。
use crate::adapter::{CallOutcome, Registry};
use crate::error::AppError;
use crate::models::{AccountSlot, ProxyEntry};
use crate::pools::Pools;
use axum::http::{HeaderMap, Method, StatusCode};
use bytes::Bytes;
use chrono::{DateTime, Duration as ChDuration, Utc};
use dashmap::DashMap;
use std::time::{Duration, Instant};

/// 平台运行时配置(从 DB 读,传给 scheduler)
#[derive(Clone)]
pub struct PlatformCfg {
    pub slug: String,
    pub same_ip_isolation: bool,
    pub status_codes: crate::adapter::StatusCodes,
    pub upstream_timeout_secs: u64,
}

pub struct ForwardResult {
    pub status: StatusCode,
    pub headers: HeaderMap,
    pub body: Bytes,
}

/// 代理客户端缓存(每代理一个 reqwest Client,内建连接池)
pub struct ProxyClientPool {
    cache: DashMap<String, reqwest::Client>,
}

impl ProxyClientPool {
    pub fn new() -> Self {
        Self {
            cache: DashMap::new(),
        }
    }
    pub fn client_for(&self, proxy: &ProxyEntry, timeout_secs: u64) -> reqwest::Client {
        let user = proxy.username.as_deref().unwrap_or("");
        let pass = proxy.password.as_deref().unwrap_or("");
        let key = format!("{}|{}|{}|{}|{}", proxy.host, proxy.port, user, pass, timeout_secs);
        self.cache
            .entry(key)
            .or_insert_with(|| build_proxy_client(proxy, timeout_secs))
            .clone()
    }
}

fn build_proxy_client(proxy: &ProxyEntry, timeout_secs: u64) -> reqwest::Client {
    let mut builder = reqwest::Client::builder().timeout(Duration::from_secs(timeout_secs));
    let auth = match (&proxy.username, &proxy.password) {
        (Some(u), Some(p)) if !u.is_empty() => format!("{u}:{p}@"),
        _ => String::new(),
    };
    let proxy_url = format!("http://{}{}:{}", auth, proxy.host, proxy.port);
    if let Ok(p) = reqwest::Proxy::http(&proxy_url) {
        builder = builder.proxy(p);
    }
    builder.build().unwrap_or_else(|_| reqwest::Client::new())
}

/// 选号 + 选代理:候选号按其绑定代理的当前占用升序(均衡 + 尽量同IP不连续)
fn select(pools: &Pools, platform: &str, isolation: bool) -> Option<(AccountSlot, ProxyEntry)> {
    let mut cands = pools.candidates(platform);
    if cands.is_empty() {
        return None;
    }
    // 按 proxy busy 计数升序(空闲代理优先 → 自然均衡 + 同IP不连续)
    cands.sort_by_key(|a| {
        a.bound_proxy_id
            .and_then(|pid| pools.get_proxy(pid))
            .and_then(|p| p.exit_ip.clone())
            .and_then(|eip| pools.busy_exit_ips.get(&eip).map(|c| *c as i64))
            .unwrap_or(0)
    });
    // 第一轮:严格隔离(busy==0 或不启用隔离时跳过 busy>0)
    for a in &cands {
        if let Some(p) = a.bound_proxy_id.and_then(|pid| pools.get_proxy(pid)) {
            if p.status != "available" {
                continue;
            }
            if let Some(eip) = &p.exit_ip {
                if isolation && pools.is_exit_ip_busy(eip) {
                    continue;
                }
            }
            return Some((a.clone(), p));
        }
    }
    // 第二轮:放宽隔离,选 busy 最低
    for a in &cands {
        if let Some(p) = a.bound_proxy_id.and_then(|pid| pools.get_proxy(pid)) {
            if p.status == "available" {
                return Some((a.clone(), p));
            }
        }
    }
    None
}

fn parse_retry_after(headers: &HeaderMap) -> DateTime<Utc> {
    let now = Utc::now();
    if let Some(v) = headers.get("retry-after").or_else(|| headers.get("Retry-After")) {
        if let Ok(s) = v.to_str() {
            if let Ok(secs) = s.trim().parse::<i64>() {
                return now + ChDuration::seconds(secs);
            }
        }
    }
    now + ChDuration::seconds(30)
}

/// 选号失败时定位根因,给出可操作的错误信息(而非笼统的"无可用号")。
/// 仅在 select 返回 None 的异常分支调用一次,不影响转发热路径。
async fn diagnose_no_account(pools: &Pools, slug: &str) -> String {
    // 1. 平台是否绑定了代理组(没绑 → 号永远拿不到代理,这是最常见的配置遗漏)
    let bound_groups: i64 = sqlx::query_scalar::<_, i64>(
        "SELECT COUNT(*) FROM platform_proxy_groups WHERE platform_slug=?",
    )
    .bind(slug)
    .fetch_one(&pools.db)
    .await
    .unwrap_or(0);
    if bound_groups == 0 {
        return format!("平台 {slug} 未绑定任何代理组,号无法被调度 —— 请在「平台」页为它关联一个代理组");
    }
    // 2. 候选号情况(走内存索引)
    let cands = pools.candidates(slug);
    if cands.is_empty() {
        let total: i64 = sqlx::query_scalar::<_, i64>(
            "SELECT COUNT(*) FROM accounts WHERE platform_slug=?",
        )
        .bind(slug)
        .fetch_one(&pools.db)
        .await
        .unwrap_or(0);
        if total == 0 {
            return format!("平台 {slug} 还没有上传任何号");
        }
        return format!(
            "平台 {slug} 的号当前都不可用(已停用 / 已失效 / 退避中),请稍后重试或在号池页检查状态"
        );
    }
    // 3. 有候选但都没绑到可用代理
    let unbound = cands.iter().filter(|a| a.bound_proxy_id.is_none()).count();
    if unbound > 0 {
        return format!(
            "平台 {slug} 有 {unbound} 个号未绑定代理 —— 请确认代理组已同步且有可用代理"
        );
    }
    format!("平台 {slug} 候选号绑定的代理当前都不可用,请稍后重试")
}

/// 主转发入口
pub async fn forward(
    pools: &Pools,
    registry: &Registry,
    proxy_clients: &ProxyClientPool,
    cfg: &PlatformCfg,
    endpoint: &str,
    method: &Method,
    headers: &HeaderMap,
    body: Bytes,
    token_id: Option<i64>,
) -> Result<ForwardResult, AppError> {
    let adapter = registry.get(&cfg.slug).ok_or_else(|| {
        AppError::not_found(format!("平台 {} 未注册", cfg.slug))
    })?;

    // 平台并发
    let plat_permit = pools
        .platform_permit(&cfg.slug)
        .ok_or_else(|| AppError::unavailable("平台未就绪"))?;
    let _plat_guard = plat_permit
        .acquire()
        .await
        .map_err(|_| AppError::internal("permit closed"))?;

    let settings = crate::sync::read_settings(pools).await;
    let mut retries = 0u32;
    loop {
        let chosen = select(pools, &cfg.slug, cfg.same_ip_isolation);
        let (acct, proxy) = match chosen {
            Some(x) => x,
            None => {
                // 没选中号:重试无意义(候选号不会在重试间凭空出现),直接诊断根因返回
                let reason = diagnose_no_account(pools, &cfg.slug).await;
                return Err(AppError::unavailable(reason));
            }
        };

        // 同 IP 占用计数
        let exit_ip = proxy.exit_ip.clone();
        if let Some(eip) = &exit_ip {
            pools.inc_exit_ip(eip);
        }
        // 单号并发
        let acct_permit = pools.account_permit(acct.id);
        let _acct_guard = if let Some(p) = acct_permit {
            Some(p.acquire_owned().await.ok())
        } else {
            None
        };

        // 改头 + 拼 URL
        let (url, fwd_headers) = adapter.prepare(headers, endpoint, &acct.decrypted_key);
        let client = proxy_clients.client_for(&proxy, cfg.upstream_timeout_secs);
        let started = Instant::now();
        let send_result = client
            .request(method.clone(), &url)
            .headers(fwd_headers)
            .body(body.clone())
            .send()
            .await;

        let dur = started.elapsed().as_millis() as i64;

        match send_result {
            Ok(resp) => {
                let status = resp.status();
                let rheaders = resp.headers().clone();
                let rbody = resp.bytes().await.unwrap_or_default();
                let outcome = adapter.classify(status, &cfg.status_codes);
                if let Some(eip) = &exit_ip {
                    pools.dec_exit_ip(eip);
                }
                match outcome {
                    CallOutcome::Success => {
                        let _ = pools.record_call(acct.id, true).await;
                        if let Some(t) = token_id {
                            let _ = pools.inc_token_count(t).await;
                        }
                        let _ = pools
                            .write_call_log(
                                token_id,
                                &cfg.slug,
                                endpoint,
                                Some(acct.id),
                                Some(proxy.id),
                                Some(status.as_u16() as i32),
                                Some(dur),
                                retries as i32,
                                true,
                            )
                            .await;
                        return Ok(ForwardResult {
                            status,
                            headers: rheaders,
                            body: rbody,
                        });
                    }
                    CallOutcome::OtherError => {
                        // 调用方请求本身的错误(4xx 非 401/402/429),透传,不重试
                        let _ = pools.record_call(acct.id, false).await;
                        let _ = pools
                            .write_call_log(
                                token_id,
                                &cfg.slug,
                                endpoint,
                                Some(acct.id),
                                Some(proxy.id),
                                Some(status.as_u16() as i32),
                                Some(dur),
                                retries as i32,
                                false,
                            )
                            .await;
                        return Ok(ForwardResult {
                            status,
                            headers: rheaders,
                            body: rbody,
                        });
                    }
                    CallOutcome::HardRevoked => {
                        // 封号码命中:号永久剔除(封号不可恢复)
                        let _ = pools.set_status(acct.id, "hard_revoked").await;
                        let _ = pools
                            .write_call_log(
                                token_id,
                                &cfg.slug,
                                endpoint,
                                Some(acct.id),
                                Some(proxy.id),
                                Some(status.as_u16() as i32),
                                Some(dur),
                                retries as i32,
                                false,
                            )
                            .await;
                        tracing::warn!(account_id = acct.id, status = %status, "封号码命中,号永久剔除");
                    }
                    CallOutcome::RateLimited => {
                        let until = parse_retry_after(&rheaders);
                        pools.mark_rate_limited(acct.id, until);
                        let _ = pools
                            .write_call_log(
                                token_id,
                                &cfg.slug,
                                endpoint,
                                Some(acct.id),
                                Some(proxy.id),
                                Some(status.as_u16() as i32),
                                Some(dur),
                                retries as i32,
                                false,
                            )
                            .await;
                    }
                    CallOutcome::Transient => {
                        let _ = pools
                            .write_call_log(
                                token_id,
                                &cfg.slug,
                                endpoint,
                                Some(acct.id),
                                Some(proxy.id),
                                Some(status.as_u16() as i32),
                                Some(dur),
                                retries as i32,
                                false,
                            )
                            .await;
                    }
                }
            }
            Err(e) => {
                // 网络/代理失败:不是号的错(号没被封),给号换一个代理重绑 + 短暂退避排后,换号重试当前请求
                if let Some(eip) = &exit_ip {
                    pools.dec_exit_ip(eip);
                }
                let _ = pools
                    .write_call_log(
                        token_id,
                        &cfg.slug,
                        endpoint,
                        Some(acct.id),
                        Some(proxy.id),
                        None,
                        Some(dur),
                        retries as i32,
                        false,
                    )
                    .await;
                let _ = crate::sync::bind_account(pools, acct.id, None).await;
                pools.mark_rate_limited(acct.id, Utc::now() + ChDuration::seconds(30));
                tracing::info!(account_id = acct.id, ?e, "代理失败,为号换代理,短暂退避");
            }
        }

        retries += 1;
        if retries > settings.max_retries {
            return Err(AppError::unavailable(format!(
                "平台 {} 重试耗尽,所有候选号均不可用",
                cfg.slug
            )));
        }
    }
}

#[derive(sqlx::FromRow)]
struct ProbeAcctRow {
    platform_slug: String,
    encrypted_key: Vec<u8>,
    bound_proxy_id: Option<i64>,
}

#[derive(sqlx::FromRow)]
struct ProbePlatRow {
    revoke_codes: String,
    rate_limit_codes: String,
    upstream_timeout_secs: i64,
}

/// 测活结果(手动激活 / 上传时激活)
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ProbeOutcome {
    Alive,
    Revoked,
    Unknown,
    Skipped,
}

pub struct ProbeResult {
    pub outcome: ProbeOutcome,
    pub status: Option<u16>,
    pub reason: String,
}

/// 测活(激活):对单个号经其绑定代理发一次最小代价的探测请求,按上游响应码判定 key 是否有效。
/// 走绑定代理(注册 IP 出口,符合同 IP 隔离);未绑代理则先尝试绑定,仍无则跳过(保持原状态)。
/// 判定:2xx→healthy;命中封号码→hard_revoked;其余(限流 / 瞬时 / 网络错误)→ 不动状态。
pub async fn probe_account(
    pools: &Pools,
    registry: &Registry,
    proxy_clients: &ProxyClientPool,
    account_id: i64,
) -> ProbeResult {
    let row: Option<ProbeAcctRow> =
        sqlx::query_as("SELECT platform_slug, encrypted_key, bound_proxy_id FROM accounts WHERE id=?")
            .bind(account_id)
            .fetch_optional(&pools.db)
            .await
            .ok()
            .flatten();
    let row = match row {
        Some(r) => r,
        None => {
            return ProbeResult {
                outcome: ProbeOutcome::Skipped,
                status: None,
                reason: "号不存在".into(),
            }
        }
    };
    let adapter = match registry.get(&row.platform_slug) {
        Some(a) => a,
        None => {
            return ProbeResult {
                outcome: ProbeOutcome::Skipped,
                status: None,
                reason: "平台未注册".into(),
            }
        }
    };
    let key = match crate::crypto::decrypt(&pools.aes_key, &row.encrypted_key)
        .ok()
        .and_then(|b| String::from_utf8(b).ok())
    {
        Some(k) => k,
        None => {
            return ProbeResult {
                outcome: ProbeOutcome::Skipped,
                status: None,
                reason: "key 解密失败".into(),
            }
        }
    };
    // 走绑定代理:未绑则先尝试绑定(吸附注册 IP);仍无代理 → 跳过(保持原状态,不误判)
    let mut bound_proxy_id = row.bound_proxy_id;
    if bound_proxy_id.is_none() {
        crate::sync::bind_account(pools, account_id, None).await;
        bound_proxy_id =
            sqlx::query_scalar::<_, i64>("SELECT bound_proxy_id FROM accounts WHERE id=?")
                .bind(account_id)
                .fetch_optional(&pools.db)
                .await
                .ok()
                .flatten();
    }
    let pid = match bound_proxy_id {
        Some(p) => p,
        None => {
            return ProbeResult {
                outcome: ProbeOutcome::Skipped,
                status: None,
                reason: "未绑定代理,无法测活(请先为平台绑定代理组并同步代理)".into(),
            }
        }
    };
    let proxy = match pools.get_proxy(pid) {
        Some(p) => p,
        None => {
            return ProbeResult {
                outcome: ProbeOutcome::Skipped,
                status: None,
                reason: "绑定的代理不存在".into(),
            }
        }
    };
    let plat: ProbePlatRow = sqlx::query_as(
        "SELECT revoke_codes, rate_limit_codes, upstream_timeout_secs FROM platforms WHERE slug=?",
    )
    .bind(&row.platform_slug)
    .fetch_one(&pools.db)
    .await
    .unwrap_or(ProbePlatRow {
        revoke_codes: "401".into(),
        rate_limit_codes: "429".into(),
        upstream_timeout_secs: 120,
    });
    let codes = crate::adapter::StatusCodes::parse(&plat.revoke_codes, &plat.rate_limit_codes);
    let client = proxy_clients.client_for(&proxy, plat.upstream_timeout_secs as u64);

    match adapter.probe_key(&client, &key).await {
        None => ProbeResult {
            outcome: ProbeOutcome::Unknown,
            status: None,
            reason: "探测请求失败(网络 / 代理错误,未拿到上游响应)".into(),
        },
        Some(status) => {
            let code = status.as_u16();
            match adapter.classify(status, &codes) {
                CallOutcome::Success => {
                    let _ = pools.set_status(account_id, "healthy").await;
                    ProbeResult {
                        outcome: ProbeOutcome::Alive,
                        status: Some(code),
                        reason: format!("探测成功({code}),号已标记健康"),
                    }
                }
                CallOutcome::HardRevoked => {
                    let _ = pools.set_status(account_id, "hard_revoked").await;
                    ProbeResult {
                        outcome: ProbeOutcome::Revoked,
                        status: Some(code),
                        reason: format!("命中封号码({code}),号已标记失效"),
                    }
                }
                _ => ProbeResult {
                    outcome: ProbeOutcome::Unknown,
                    status: Some(code),
                    reason: format!("探测返回 {code}(限流 / 瞬时错误),无法判定,保持原状态"),
                },
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::http::HeaderMap;
    use chrono::Utc;

    #[test]
    fn retry_after_parses_seconds_header() {
        let mut h = HeaderMap::new();
        h.insert("retry-after", "120".parse().unwrap());
        let now = Utc::now();
        let d = (parse_retry_after(&h) - now).num_seconds();
        assert!(d >= 119 && d <= 121, "expected ~120s, got {d}");
    }

    #[test]
    fn retry_after_default_30s_when_missing() {
        let now = Utc::now();
        let d = (parse_retry_after(&HeaderMap::new()) - now).num_seconds();
        assert!(d >= 29 && d <= 31, "expected ~30s default, got {d}");
    }

    #[test]
    fn retry_after_header_case_insensitive() {
        // http HeaderMap 名称大小写不敏感;实现同时兜底 retry-after / Retry-After
        let mut h = HeaderMap::new();
        h.insert("Retry-After", "60".parse().unwrap());
        let now = Utc::now();
        let d = (parse_retry_after(&h) - now).num_seconds();
        assert!(d >= 59 && d <= 61, "expected ~60s, got {d}");
    }
}
