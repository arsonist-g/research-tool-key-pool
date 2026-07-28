// 内存索引(AccountPool + ProxyPool)+ 并发信号量 + 同IP占用追踪。
// 热路径(选号/选代理/状态翻转)走内存;变更同步落 SQLite(ADR 0006)。
use crate::crypto;
use crate::models::{AccountSlot, ProxyEntry};
use chrono::{DateTime, Utc};
use dashmap::DashMap;
use sqlx::sqlite::SqlitePool;
use std::sync::Arc;
use tokio::sync::Semaphore;

/// 单号并发上限(防单号高并发,PM 调度约束)
const PER_ACCOUNT_CONCURRENCY: usize = 3;

pub struct Pools {
    pub db: SqlitePool,
    pub aes_key: [u8; 32],
    pub accounts: DashMap<i64, AccountSlot>,
    pub proxies: DashMap<i64, ProxyEntry>,
    pub acct_permits: DashMap<i64, Arc<Semaphore>>,
    pub plat_permits: DashMap<String, Arc<Semaphore>>,
    /// 当前在用的 exit_ip 计数(同 IP 不连续调用约束)
    pub busy_exit_ips: DashMap<String, usize>,
    /// 瞬时退避(429)的解禁时间,内存 only
    pub rate_limited_until: DashMap<i64, DateTime<Utc>>,
}

impl Pools {
    pub fn new(db: SqlitePool, aes_key: [u8; 32]) -> Self {
        Self {
            db,
            aes_key,
            accounts: DashMap::new(),
            proxies: DashMap::new(),
            acct_permits: DashMap::new(),
            plat_permits: DashMap::new(),
            busy_exit_ips: DashMap::new(),
            rate_limited_until: DashMap::new(),
        }
    }

    /// 从 DB 加载号(解密 key)与代理
    pub async fn load_all(&self) -> anyhow::Result<()> {
        let rows: Vec<crate::models::Account> =
            sqlx::query_as("SELECT * FROM accounts")
                .fetch_all(&self.db)
                .await?;
        for a in rows {
            let decrypted_key = match crypto::decrypt(&self.aes_key, &a.encrypted_key) {
                Ok(b) => String::from_utf8_lossy(&b).to_string(),
                Err(e) => {
                    tracing::error!(account_id = a.id, ?e, "decrypt key failed, skip");
                    continue;
                }
            };
            self.acct_permits
                .insert(a.id, Arc::new(Semaphore::new(PER_ACCOUNT_CONCURRENCY)));
            self.accounts.insert(
                a.id,
                AccountSlot {
                    id: a.id,
                    platform_slug: a.platform_slug,
                    decrypted_key,
                    bound_proxy_id: a.bound_proxy_id,
                    status: a.status,
                    quota_limit: a.quota_limit,
                    quota_used: a.quota_used,
                    reset_at: a.reset_at,
                    last_called_at: a.last_called_at,
                    consecutive_failures: a.consecutive_failures,
                },
            );
        }

        let prows: Vec<crate::models::Proxy> =
            sqlx::query_as("SELECT * FROM proxies")
                .fetch_all(&self.db)
                .await?;
        for p in prows {
            self.proxies.insert(
                p.id,
                ProxyEntry {
                    id: p.id,
                    group_id: p.group_id,
                    host: p.host,
                    port: p.port,
                    username: p.username,
                    password: p.password,
                    exit_ip: p.exit_ip,
                    status: p.status,
                },
            );
        }
        Ok(())
    }

    /// 为平台建立并发信号量(按 max_concurrency)
    pub fn ensure_platform_permit(&self, slug: &str, max: usize) {
        self.plat_permits
            .entry(slug.to_string())
            .or_insert_with(|| Arc::new(Semaphore::new(max.max(1))));
    }

    pub fn platform_permit(&self, slug: &str) -> Option<Arc<Semaphore>> {
        self.plat_permits.get(slug).map(|x| x.clone())
    }

    pub fn account_permit(&self, id: i64) -> Option<Arc<Semaphore>> {
        self.acct_permits.get(&id).map(|x| x.clone())
    }

    /// 候选号(healthy/pending,未在退避窗口)
    pub fn candidates(&self, platform: &str) -> Vec<AccountSlot> {
        let now = Utc::now();
        let mut out = Vec::new();
        for entry in self.accounts.iter() {
            let s = entry.value();
            if s.platform_slug != platform {
                continue;
            }
            if s.status != "healthy" && s.status != "pending" {
                continue;
            }
            if let Some(until) = self.rate_limited_until.get(&s.id) {
                if *until > now {
                    continue;
                }
            }
            // 额度估算:有 limit 且已用超限则跳过
            if let Some(limit) = s.quota_limit {
                if s.quota_used >= limit {
                    continue;
                }
            }
            out.push(s.clone());
        }
        out
    }

    pub fn get_proxy(&self, id: i64) -> Option<ProxyEntry> {
        self.proxies.get(&id).map(|p| p.clone())
    }

    /// 选号时:exit_ip 是否当前被占用(同IP不连续)
    pub fn is_exit_ip_busy(&self, exit_ip: &str) -> bool {
        self.busy_exit_ips.get(exit_ip).map(|c| *c > 0).unwrap_or(false)
    }

    pub fn inc_exit_ip(&self, exit_ip: &str) {
        self.busy_exit_ips
            .entry(exit_ip.to_string())
            .and_modify(|c| *c += 1)
            .or_insert(1);
    }

    pub fn dec_exit_ip(&self, exit_ip: &str) {
        if let Some(mut c) = self.busy_exit_ips.get_mut(exit_ip) {
            if *c > 0 {
                *c -= 1;
            }
        }
    }

    /// 标记瞬时退避(429)
    pub fn mark_rate_limited(&self, id: i64, until: DateTime<Utc>) {
        self.rate_limited_until.insert(id, until);
    }

    /// 状态翻转(内存 + DB)
    pub async fn set_status(&self, id: i64, status: &str) -> anyhow::Result<()> {
        if let Some(mut s) = self.accounts.get_mut(&id) {
            s.status = status.to_string();
            s.consecutive_failures = 0;
        }
        let now = Utc::now();
        sqlx::query("UPDATE accounts SET status=?, consecutive_failures=0, updated_at=? WHERE id=?")
            .bind(status)
            .bind(now)
            .bind(id)
            .execute(&self.db)
            .await?;
        Ok(())
    }

    /// 记一次调用结果(内存 + DB)
    pub async fn record_call(
        &self,
        id: i64,
        success: bool,
    ) -> anyhow::Result<()> {
        let now = Utc::now();
        if let Some(mut s) = self.accounts.get_mut(&id) {
            if success {
                s.quota_used += 1;
                s.last_called_at = Some(now);
                s.consecutive_failures = 0;
                if s.status == "pending" {
                    s.status = "healthy".into();
                }
            } else {
                s.consecutive_failures += 1;
                s.last_called_at = Some(now);
            }
        }
        let new_status: Option<String> = self.accounts.get(&id).map(|s| s.status.clone());
        sqlx::query(
            "UPDATE accounts SET quota_used=quota_used+?, last_called_at=?, consecutive_failures=consecutive_failures+?, status=COALESCE(?,status), updated_at=? WHERE id=?",
        )
        .bind(if success { 1_i64 } else { 0 })
        .bind(now)
        .bind(1_i32)
        .bind(new_status)
        .bind(now)
        .bind(id)
        .execute(&self.db)
        .await?;
        Ok(())
    }

    pub async fn inc_token_count(&self, token_id: i64) -> anyhow::Result<()> {
        sqlx::query("UPDATE issued_tokens SET call_count=call_count+1 WHERE id=?")
            .bind(token_id)
            .execute(&self.db)
            .await?;
        Ok(())
    }

    pub async fn write_call_log(
        &self,
        token_id: Option<i64>,
        platform: &str,
        endpoint: &str,
        account_id: Option<i64>,
        proxy_id: Option<i64>,
        status_code: Option<i32>,
        duration_ms: Option<i64>,
        retry_count: i32,
        success: bool,
    ) -> anyhow::Result<()> {
        sqlx::query(
            "INSERT INTO call_logs (created_at, token_id, platform_slug, endpoint, account_id, proxy_id, status_code, duration_ms, retry_count, success) VALUES (?,?,?,?,?,?,?,?,?,?)",
        )
        .bind(Utc::now())
        .bind(token_id)
        .bind(platform)
        .bind(endpoint)
        .bind(account_id)
        .bind(proxy_id)
        .bind(status_code)
        .bind(duration_ms)
        .bind(retry_count)
        .bind(success)
        .execute(&self.db)
        .await?;
        Ok(())
    }
}
