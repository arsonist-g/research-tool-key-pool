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
                if retries >= settings.max_retries {
                    return Err(AppError::unavailable(format!(
                        "平台 {} 无可用号",
                        cfg.slug
                    )));
                }
                return Err(AppError::unavailable(format!("平台 {} 无可用号", cfg.slug)));
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
