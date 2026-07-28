// 同步器:代理同步(easy_proxies)/ 余额同步 / 额度刷新 / 日志清理 / 号-代理绑定。
use crate::adapter::Registry;
use crate::pools::Pools;
use chrono::{Duration as ChDuration, Utc};
use serde::Deserialize;
use std::collections::HashSet;
use std::sync::Arc;
use std::time::Duration;

// —— easy_proxies /sub 响应 ——
#[derive(Deserialize)]
struct SubResponse {
    proxies: Vec<SubProxy>,
}
#[derive(Deserialize, Clone)]
struct SubProxy {
    name: Option<String>,
    host: String,
    port: i32,
    username: Option<String>,
    password: Option<String>,
    country_code: Option<String>,
    country_name: Option<String>,
    exit_ip: Option<String>,
    latency_ms: Option<i32>,
    availability_rate: Option<f64>,
}

#[derive(sqlx::FromRow)]
struct GroupSubRow {
    subscription_url: String,
}

#[derive(sqlx::FromRow)]
struct ExistingProxyRow {
    host: String,
    port: i32,
    id: i64,
}

#[derive(sqlx::FromRow)]
struct NullAcctRow {
    id: i64,
    registration_ip: Option<String>,
}

/// 同步单个代理组
pub async fn sync_group(
    pools: &Pools,
    group_id: i64,
    http: &reqwest::Client,
) -> anyhow::Result<(usize, usize)> {
    let g: GroupSubRow =
        sqlx::query_as("SELECT subscription_url FROM proxy_groups WHERE id=?")
            .bind(group_id)
            .fetch_one(&pools.db)
            .await?;
    // 订阅地址即完整链接(easy_proxies 端已带 token/过滤参数),直接请求,不再拆分拼接/本地过滤
    let resp = http.get(&g.subscription_url).send().await?;
    let parsed: SubResponse = resp.json().await?;
    let filtered: Vec<SubProxy> = parsed.proxies;
    let total = filtered.len();
    let now = Utc::now();

    let mut present: HashSet<String> = HashSet::new();
    for p in &filtered {
        present.insert(format!("{}:{}", p.host, p.port));
        sqlx::query(
            "INSERT INTO proxies (group_id,name,host,port,username,password,country_code,country_name,exit_ip,latency_ms,availability_rate,status,last_synced_at)
             VALUES (?,?,?,?,?,?,?,?,?,?,?,'available',?)
             ON CONFLICT(group_id,host,port) DO UPDATE SET
               name=excluded.name, username=excluded.username, password=excluded.password,
               country_code=excluded.country_code, country_name=excluded.country_name,
               exit_ip=excluded.exit_ip, latency_ms=excluded.latency_ms,
               availability_rate=excluded.availability_rate, last_synced_at=excluded.last_synced_at",
        )
        .bind(group_id)
        .bind(&p.name)
        .bind(&p.host)
        .bind(p.port)
        .bind(&p.username)
        .bind(&p.password)
        .bind(&p.country_code)
        .bind(&p.country_name)
        .bind(&p.exit_ip)
        .bind(p.latency_ms)
        .bind(p.availability_rate)
        .bind(now)
        .execute(&pools.db)
        .await?;
    }

    let existing: Vec<ExistingProxyRow> =
        sqlx::query_as("SELECT host, port, id FROM proxies WHERE group_id=?")
            .bind(group_id)
            .fetch_all(&pools.db)
            .await?;
    for e in existing {
        let key = format!("{}:{}", e.host, e.port);
        if !present.contains(&key) {
            let _ = sqlx::query("DELETE FROM proxies WHERE id=?")
                .bind(e.id)
                .execute(&pools.db)
                .await;
        }
    }

    sqlx::query("UPDATE proxy_groups SET last_synced_at=? WHERE id=?")
        .bind(now)
        .bind(group_id)
        .execute(&pools.db)
        .await?;

    reload_group_proxies(pools, group_id).await;
    rebind_null_accounts(pools, group_id).await;
    Ok((total, total))
}

pub async fn sync_all_groups(pools: &Pools, http: &reqwest::Client) {
    let groups: Vec<i64> = match sqlx::query_scalar("SELECT id FROM proxy_groups WHERE enabled=1")
        .fetch_all(&pools.db)
        .await
    {
        Ok(x) => x,
        Err(e) => {
            tracing::error!(?e, "list proxy_groups failed");
            return;
        }
    };
    for gid in groups {
        match sync_group(pools, gid, http).await {
            Ok((n, _)) => tracing::info!(group_id = gid, synced = n, "proxy sync ok"),
            Err(e) => tracing::warn!(group_id = gid, ?e, "proxy sync failed"),
        }
    }
}

async fn reload_group_proxies(pools: &Pools, group_id: i64) {
    pools.proxies.retain(|_, p| p.group_id != group_id);
    let rows: Vec<crate::models::Proxy> =
        sqlx::query_as("SELECT * FROM proxies WHERE group_id=?")
            .bind(group_id)
            .fetch_all(&pools.db)
            .await
            .unwrap_or_default();
    for p in rows {
        pools.proxies.insert(
            p.id,
            crate::models::ProxyEntry {
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
}

async fn rebind_null_accounts(pools: &Pools, group_id: i64) {
    // 该组关联的所有平台(通过 platform_proxy_groups M:N),其未绑定号重绑
    let null_accts: Vec<NullAcctRow> = sqlx::query_as(
        "SELECT a.id, a.registration_ip FROM accounts a
         WHERE a.bound_proxy_id IS NULL
           AND a.platform_slug IN (SELECT platform_slug FROM platform_proxy_groups WHERE proxy_group_id=?)",
    )
    .bind(group_id)
    .fetch_all(&pools.db)
    .await
    .unwrap_or_default();
    for a in null_accts {
        bind_account(pools, a.id, a.registration_ip.as_deref()).await;
    }
}

/// 分配代理给号:从平台绑定的所有代理组并集中,优先吸附 registration_ip 的 exit_ip,
/// 否则并集内绑定数最低。一个平台可绑多个组(M:N)。
pub async fn bind_account(pools: &Pools, account_id: i64, registration_ip: Option<&str>) {
    let slug: Option<String> =
        sqlx::query_scalar("SELECT platform_slug FROM accounts WHERE id=?")
            .bind(account_id)
            .fetch_optional(&pools.db)
            .await
            .ok()
            .flatten();
    let slug = match slug {
        Some(s) => s,
        None => return,
    };
    let group_ids: Vec<i64> =
        sqlx::query_scalar("SELECT proxy_group_id FROM platform_proxy_groups WHERE platform_slug=?")
            .bind(&slug)
            .fetch_all(&pools.db)
            .await
            .unwrap_or_default();
    if group_ids.is_empty() {
        return;
    }
    // 优先吸附同 exit_ip(注册 IP == 某代理出口 IP);遍历各组取首个命中
    let mut proxy_id: Option<i64> = None;
    if let Some(reg) = registration_ip {
        for gid in &group_ids {
            proxy_id = sqlx::query_scalar::<_, i64>(
                "SELECT id FROM proxies WHERE group_id=? AND exit_ip=? AND status='available' LIMIT 1",
            )
            .bind(gid)
            .bind(reg)
            .fetch_optional(&pools.db)
            .await
            .ok()
            .flatten();
            if proxy_id.is_some() {
                break;
            }
        }
    }
    // 否则各组内绑定数最低者(均衡)
    if proxy_id.is_none() {
        for gid in &group_ids {
            proxy_id = sqlx::query_scalar::<_, i64>(
                "SELECT p.id FROM proxies p LEFT JOIN accounts a ON a.bound_proxy_id=p.id
                 WHERE p.group_id=? AND p.status='available'
                 GROUP BY p.id ORDER BY COUNT(a.id) ASC LIMIT 1",
            )
            .bind(gid)
            .fetch_optional(&pools.db)
            .await
            .ok()
            .flatten();
            if proxy_id.is_some() {
                break;
            }
        }
    }

    if let Some(pid) = proxy_id {
        let now = Utc::now();
        let _ = sqlx::query("UPDATE accounts SET bound_proxy_id=?, updated_at=? WHERE id=?")
            .bind(pid)
            .bind(now)
            .bind(account_id)
            .execute(&pools.db)
            .await;
        if let Some(mut s) = pools.accounts.get_mut(&account_id) {
            s.bound_proxy_id = Some(pid);
        }
    }
}

/// 余额同步:对可查平台刷新估算剩余
pub async fn refresh_balances(pools: &Pools, registry: &Registry, http: &reqwest::Client) {
    for slug in registry.slugs() {
        let adapter = match registry.get(slug) {
            Some(a) => a,
            None => continue,
        };
        if !adapter.supports_balance_query() {
            continue;
        }
        // 只查近期(24h 内)调用过的号,避免对未调用号无谓查询/撞平台限流
        let cutoff = Utc::now() - ChDuration::hours(24);
        let acct_ids: Vec<i64> = pools
            .accounts
            .iter()
            .filter(|e| {
                let s = e.value();
                s.platform_slug == slug
                    && s.status == "healthy"
                    && s.last_called_at.map(|t| t > cutoff).unwrap_or(false)
            })
            .map(|e| *e.key())
            .collect();
        for id in acct_ids {
            let enc: Option<Vec<u8>> =
                sqlx::query_scalar("SELECT encrypted_key FROM accounts WHERE id=?")
                    .bind(id)
                    .fetch_optional(&pools.db)
                    .await
                    .ok()
                    .flatten();
            let real_key = match enc {
                Some(b) => crate::crypto::decrypt(&pools.aes_key, &b)
                    .ok()
                    .and_then(|x| String::from_utf8(x).ok()),
                None => continue,
            };
            let real_key = match real_key {
                Some(k) => k,
                None => continue,
            };
            if let Some(info) = adapter.query_balance(http, &real_key).await {
                let now = Utc::now();
                let _ = sqlx::query(
                    "UPDATE accounts SET quota_estimated_remaining=?, reset_at=COALESCE(reset_at,?), updated_at=? WHERE id=?",
                )
                .bind(info.remaining)
                .bind(info.reset_at)
                .bind(now)
                .bind(id)
                .execute(&pools.db)
                .await;
            }
        }
    }
}

/// 额度刷新:到 reset_at 的号归零 + 恢复(30 天滚动)
pub async fn reset_quotas(pools: &Pools) {
    let now = Utc::now();
    let next = now + ChDuration::days(30);
    let rows: Vec<i64> = sqlx::query_scalar("SELECT id FROM accounts WHERE reset_at IS NULL OR reset_at <= ?")
        .bind(now)
        .fetch_all(&pools.db)
        .await
        .unwrap_or_default();
    for id in rows {
        let _ = sqlx::query(
            "UPDATE accounts SET quota_used=0, status='healthy', reset_at=?, consecutive_failures=0, updated_at=? WHERE id=?",
        )
        .bind(next)
        .bind(now)
        .bind(id)
        .execute(&pools.db)
        .await;
        if let Some(mut s) = pools.accounts.get_mut(&id) {
            s.quota_used = 0;
            s.status = "healthy".into();
            s.reset_at = Some(next);
            s.consecutive_failures = 0;
        }
    }
}

/// 日志按存储占用防膨胀:每条估算 ~320 字节(字段 + 索引开销),
/// 由 max_mb 反推条数上限,删最旧。SQLite 删除后页可复用,文件不会再涨超过阈值。
pub async fn cleanup_logs(pools: &Pools, max_mb: i64) {
    if max_mb <= 0 {
        return;
    }
    let max_rows = (max_mb * 1024 * 1024) / 320;
    let cur: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM call_logs")
        .fetch_one(&pools.db)
        .await
        .unwrap_or(0);
    if cur > max_rows {
        let del = cur - max_rows;
        let _ = sqlx::query(
            "DELETE FROM call_logs WHERE id IN (SELECT id FROM call_logs ORDER BY id ASC LIMIT ?)",
        )
        .bind(del)
        .execute(&pools.db)
        .await;
    }
}

/// 读 settings 表的一个整数项(缺失或非法用默认)
async fn setting_i64(pools: &Pools, key: &str, default: i64) -> i64 {
    sqlx::query_scalar::<_, String>("SELECT value FROM settings WHERE key=?")
        .bind(key)
        .fetch_optional(&pools.db)
        .await
        .ok()
        .flatten()
        .and_then(|v| v.parse().ok())
        .unwrap_or(default)
}

/// 运行时可调配置(设置页在线改,各 worker / scheduler 动态读)
#[derive(Debug, Clone)]
pub struct RuntimeSettings {
    pub sync_interval_secs: u64,
    pub log_max_mb: i64,
    pub max_retries: u32,
    pub account_concurrency: usize,
    pub balance_sync_interval_secs: u64,
}

pub async fn read_settings(pools: &Pools) -> RuntimeSettings {
    RuntimeSettings {
        sync_interval_secs: setting_i64(pools, "sync_interval_secs", 300).await.max(30) as u64,
        log_max_mb: setting_i64(pools, "log_max_mb", 100).await,
        max_retries: setting_i64(pools, "max_retries", 3).await.max(0) as u32,
        account_concurrency: setting_i64(pools, "account_concurrency", 3).await.max(1) as usize,
        balance_sync_interval_secs: setting_i64(pools, "balance_sync_interval_secs", 900)
            .await
            .max(60) as u64,
    }
}

/// 启动后台周期任务。间隔/阈值从 settings 表动态读(设置页改了下次循环即生效)。
pub fn start_workers(pools: Arc<Pools>, registry: Arc<Registry>, http: reqwest::Client) {
    // 代理同步:启动即同步一次,之后按 sync_interval_secs 循环
    {
        let (p, h) = (pools.clone(), http.clone());
        tokio::spawn(async move {
            sync_all_groups(&p, &h).await;
            loop {
                let s = read_settings(&p).await;
                tokio::time::sleep(Duration::from_secs(s.sync_interval_secs)).await;
                sync_all_groups(&p, &h).await;
            }
        });
    }
    // 余额同步:按 balance_sync_interval_secs 循环(只查近期调用号)
    {
        let (p, h) = (pools.clone(), http.clone());
        tokio::spawn(async move {
            loop {
                let s = read_settings(&p).await;
                tokio::time::sleep(Duration::from_secs(s.balance_sync_interval_secs)).await;
                refresh_balances(&p, &registry, &h).await;
            }
        });
    }
    // 额度刷新 + 日志清理:每小时
    {
        let p = pools.clone();
        tokio::spawn(async move {
            let mut tick = tokio::time::interval(Duration::from_secs(3600));
            tick.tick().await;
            loop {
                tick.tick().await;
                reset_quotas(&p).await;
                let s = read_settings(&p).await;
                cleanup_logs(&p, s.log_max_mb).await;
            }
        });
    }
}

#[cfg(test)]
mod tests {
    use super::*; // bind_account
    use crate::db;
    use crate::models::{AccountSlot, ProxyEntry};
    use crate::pools::Pools;
    use chrono::Utc;
    use sqlx::sqlite::SqlitePoolOptions;

    /// 内存 SQLite + 完整 schema + 一个平台 / 代理组 / 一个代理
    async fn setup() -> Pools {
        let pool = SqlitePoolOptions::new()
            .min_connections(1)
            .max_connections(1)
            .connect("sqlite::memory:")
            .await
            .unwrap();
        db::migrate(&pool).await.unwrap();
        let now = Utc::now();
        sqlx::query(
            "INSERT INTO platforms (slug,display_name,created_at,updated_at) VALUES ('exa','Exa',?,?)",
        )
        .bind(now)
        .bind(now)
        .execute(&pool)
        .await
        .unwrap();
        sqlx::query(
            "INSERT INTO proxy_groups (name,subscription_url,enabled,created_at,updated_at) VALUES ('g','http://x',1,?,?)",
        )
        .bind(now)
        .bind(now)
        .execute(&pool)
        .await
        .unwrap();
        sqlx::query(
            "INSERT INTO proxies (group_id,host,port,exit_ip,status,last_synced_at) VALUES (1,'1.1.1.1',8080,'2.2.2.2','available',?)",
        )
        .bind(now)
        .execute(&pool)
        .await
        .unwrap();
        let pools = Pools::new(pool, [0u8; 32]);
        pools.proxies.insert(
            1,
            ProxyEntry {
                id: 1,
                group_id: 1,
                host: "1.1.1.1".into(),
                port: 8080,
                username: None,
                password: None,
                exit_ip: Some("2.2.2.2".into()),
                status: "available".into(),
            },
        );
        pools
    }

    fn slot(id: i64, bound: Option<i64>) -> AccountSlot {
        AccountSlot {
            id,
            platform_slug: "exa".into(),
            decrypted_key: "k".into(),
            bound_proxy_id: bound,
            status: "pending".into(),
            quota_limit: None,
            quota_used: 0,
            reset_at: None,
            last_called_at: None,
            consecutive_failures: 0,
        }
    }

    async fn insert_account(pools: &Pools, id: i64) {
        let now = Utc::now();
        sqlx::query(
            "INSERT INTO accounts (id,platform_slug,encrypted_key,key_preview,status,upload_source,created_at,updated_at) VALUES (?,?,x'00','prev','pending','api',?,?)",
        )
        .bind(id)
        .bind("exa")
        .bind(now)
        .bind(now)
        .execute(&pools.db)
        .await
        .unwrap();
        pools.accounts.insert(id, slot(id, None));
    }

    /// 回归(用户踩坑根因):平台没绑代理组时,号上传后 bind_account 不绑,保持未绑
    #[tokio::test]
    async fn account_stays_unbound_when_platform_has_no_group() {
        let pools = setup().await;
        insert_account(&pools, 1).await;
        bind_account(&pools, 1, None).await;
        let bound: Option<i64> =
            sqlx::query_scalar("SELECT bound_proxy_id FROM accounts WHERE id=1")
                .fetch_one(&pools.db)
                .await
                .unwrap();
        assert!(bound.is_none(), "平台未绑代理组时,号应保持未绑");
    }

    /// 回归(修复路径):先上传号(无组,未绑)→ 后绑组 → bind_account 重绑到代理 → candidates 选中
    #[tokio::test]
    async fn account_rebinds_after_group_attached_and_becomes_selectable() {
        let pools = setup().await;
        insert_account(&pools, 1).await;
        // 绑组前:未绑
        bind_account(&pools, 1, None).await;
        let before: Option<i64> =
            sqlx::query_scalar("SELECT bound_proxy_id FROM accounts WHERE id=1")
                .fetch_one(&pools.db)
                .await
                .unwrap();
        assert!(before.is_none());
        // 绑组(模拟用户在平台页关联代理组)
        sqlx::query("INSERT INTO platform_proxy_groups (platform_slug,proxy_group_id) VALUES ('exa',1)")
            .execute(&pools.db)
            .await
            .unwrap();
        // 重绑(模拟 patch_platform / sync_group 触发的 rebind_null_accounts)
        bind_account(&pools, 1, None).await;
        let after: Option<i64> =
            sqlx::query_scalar("SELECT bound_proxy_id FROM accounts WHERE id=1")
                .fetch_one(&pools.db)
                .await
                .unwrap();
        assert_eq!(after, Some(1), "绑组后号应被绑到代理 1");
        assert_eq!(pools.accounts.get(&1).unwrap().bound_proxy_id, Some(1));
        let cands = pools.candidates("exa");
        assert!(cands.iter().any(|c| c.id == 1), "绑代理后号应能被 candidates 选中");
    }

    /// 注册 IP 吸附:号的 registration_ip 命中某代理 exit_ip 时优先绑该代理
    #[tokio::test]
    async fn bind_prefers_registration_ip_match() {
        let pools = setup().await;
        let now = Utc::now();
        // 第二个代理,exit_ip=9.9.9.9
        sqlx::query(
            "INSERT INTO proxies (group_id,host,port,exit_ip,status,last_synced_at) VALUES (1,'3.3.3.3',9090,'9.9.9.9','available',?)",
        )
        .bind(now)
        .execute(&pools.db)
        .await
        .unwrap();
        pools.proxies.insert(
            2,
            ProxyEntry {
                id: 2,
                group_id: 1,
                host: "3.3.3.3".into(),
                port: 9090,
                username: None,
                password: None,
                exit_ip: Some("9.9.9.9".into()),
                status: "available".into(),
            },
        );
        sqlx::query("INSERT INTO platform_proxy_groups (platform_slug,proxy_group_id) VALUES ('exa',1)")
            .execute(&pools.db)
            .await
            .unwrap();
        sqlx::query(
            "INSERT INTO accounts (id,platform_slug,encrypted_key,key_preview,registration_ip,status,upload_source,created_at,updated_at) VALUES (?,?,x'00','prev','9.9.9.9','pending','api',?,?)",
        )
        .bind(1)
        .bind("exa")
        .bind(now)
        .bind(now)
        .execute(&pools.db)
        .await
        .unwrap();
        pools.accounts.insert(1, slot(1, None));
        bind_account(&pools, 1, Some("9.9.9.9")).await;
        let bound: i64 = sqlx::query_scalar("SELECT bound_proxy_id FROM accounts WHERE id=1")
            .fetch_one(&pools.db)
            .await
            .unwrap();
        assert_eq!(bound, 2, "号应吸附到 exit_ip 匹配 registration_ip 的代理 2");
    }
}
