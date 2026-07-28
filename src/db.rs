// 数据库:连接池、WAL、建表、初始平台注册、管理员种子、密码哈希。
use anyhow::{anyhow, Result};
use argon2::password_hash::{PasswordHash, PasswordHasher, PasswordVerifier, SaltString};
use argon2::Argon2;
use chrono::Utc;
use rand::rngs::OsRng;
use sqlx::sqlite::{SqlitePool, SqlitePoolOptions};

pub async fn init_pool(db_url: &str) -> Result<SqlitePool> {
    let pool = SqlitePoolOptions::new()
        .max_connections(5)
        .connect(db_url)
        .await?;
    sqlx::query("PRAGMA journal_mode=WAL;")
        .execute(&pool)
        .await?;
    sqlx::query("PRAGMA foreign_keys=ON;")
        .execute(&pool)
        .await?;
    sqlx::query("PRAGMA busy_timeout=5000;")
        .execute(&pool)
        .await?;
    Ok(pool)
}

pub async fn migrate(pool: &SqlitePool) -> Result<()> {
    sqlx::query(SCHEMA).execute(pool).await?;
    Ok(())
}

pub async fn seed(pool: &SqlitePool, admin_user: Option<&str>, admin_pass: Option<&str>) -> Result<()> {
    // 初始平台(adapter 代码注册,这里入库 slug+display_name;运营参数默认值)
    let now = Utc::now();
    for (slug, name, quota) in [
        ("context7", "Context7", Some(1000_i64)),
        ("exa", "Exa", None),
        ("firecrawl", "Firecrawl", Some(1000)),
        ("tavily", "Tavily", Some(1000)),
    ] {
        sqlx::query(
            "INSERT OR IGNORE INTO platforms
             (slug, display_name, default_quota_limit, created_at, updated_at)
             VALUES (?,?,?,?,?)",
        )
        .bind(slug)
        .bind(name)
        .bind(quota)
        .bind(now)
        .bind(now)
        .execute(pool)
        .await?;
    }

    // 管理员凭证:
    // - config 同时配了 admin_user + admin_password → 以 config 为准(最高优先级),每次启动覆盖 DB
    //   (改 config + 重启容器即可改用户名/密码;忘密码去服务器看挂载的 config.toml 即可恢复)
    // - 没配 → 库空时随机生成密码并打印到日志(之后存库,重启不变)
    let (count,): (i64,) = sqlx::query_as("SELECT COUNT(*) FROM admins")
        .fetch_one(pool)
        .await?;
    let cfg_user = admin_user.filter(|s| !s.is_empty());
    let cfg_pass = admin_pass.filter(|s| !s.is_empty());
    match (cfg_user, cfg_pass) {
        (Some(user), Some(pass)) => {
            let hash = hash_password(pass)?;
            if count == 0 {
                sqlx::query("INSERT INTO admins (username, password_hash, created_at) VALUES (?,?,?)")
                    .bind(user)
                    .bind(hash)
                    .bind(now)
                    .execute(pool)
                    .await?;
            } else {
                // config 优先级最高:覆盖现有管理员凭证(单管理员场景)
                sqlx::query("UPDATE admins SET username=?, password_hash=?")
                    .bind(user)
                    .bind(hash)
                    .execute(pool)
                    .await?;
            }
            tracing::info!("管理员凭证已按 config 同步(username={user})");
        }
        _ => {
            if count == 0 {
                let pass = random_password(18);
                let hash = hash_password(&pass)?;
                sqlx::query("INSERT INTO admins (username, password_hash, created_at) VALUES (?,?,?)")
                    .bind("admin")
                    .bind(hash)
                    .bind(now)
                    .execute(pool)
                    .await?;
                tracing::warn!(
                    "首次启动:管理员账号 admin / 初始密码 {pass}(在 config.toml 设 admin_user/admin_password 可固定且可恢复;或登录后修改)"
                );
            }
        }
    }

    // 运行时可调配置默认值(首次写入;设置页可在线改)
    for (k, v) in [
        ("sync_interval_secs", "300"),
        ("log_max_mb", "100"),
        ("max_retries", "3"),
        ("upstream_timeout_secs", "60"),
        ("account_concurrency", "3"),
        ("balance_sync_interval_secs", "900"),
    ] {
        sqlx::query("INSERT OR IGNORE INTO settings (key, value, updated_at) VALUES (?,?,?)")
            .bind(k)
            .bind(v)
            .bind(now)
            .execute(pool)
            .await?;
    }
    Ok(())
}

pub fn hash_password(p: &str) -> Result<String> {
    let mut rng = OsRng;
    let salt = SaltString::generate(&mut rng);
    let h = Argon2::default()
        .hash_password(p.as_bytes(), &salt)
        .map_err(|e| anyhow!("argon2 hash: {e}"))?;
    Ok(h.to_string())
}

/// 随机生成管理员初始密码(去掉易混淆字符 0/O/1/I/l)
fn random_password(n: usize) -> String {
    use rand::Rng;
    const CHARSET: &[u8] = b"ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz23456789";
    let mut rng = rand::thread_rng();
    (0..n).map(|_| CHARSET[rng.gen_range(0..CHARSET.len())] as char).collect()
}

pub fn verify_password(p: &str, hash: &str) -> bool {
    let parsed = match PasswordHash::new(hash) {
        Ok(h) => h,
        Err(_) => return false,
    };
    Argon2::default()
        .verify_password(p.as_bytes(), &parsed)
        .is_ok()
}

const SCHEMA: &str = r#"
CREATE TABLE IF NOT EXISTS admins (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    username TEXT NOT NULL UNIQUE,
    password_hash TEXT NOT NULL,
    created_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS proxy_groups (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    name TEXT NOT NULL UNIQUE,
    subscription_url TEXT NOT NULL,
    enabled INTEGER NOT NULL DEFAULT 1,
    last_synced_at TEXT,
    created_at TEXT NOT NULL,
    updated_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS platforms (
    slug TEXT PRIMARY KEY,
    display_name TEXT NOT NULL,
    max_concurrency INTEGER NOT NULL DEFAULT 32,
    risk_policy TEXT NOT NULL DEFAULT 'strict' CHECK(risk_policy IN('strict','loose')),
    same_ip_isolation INTEGER NOT NULL DEFAULT 1,
    default_quota_limit INTEGER,
    -- 封号策略:封号码(默认 401,命中即永久剔除)/ 限流码(默认 429,退避重试)。逗号分隔多个,不做码表
    revoke_codes TEXT NOT NULL DEFAULT '401',
    rate_limit_codes TEXT NOT NULL DEFAULT '429',
    -- 上游超时(秒,经代理转发到真实平台的最长等待;长任务平台如 Tavily crawl 需调高,各平台不一)
    upstream_timeout_secs INTEGER NOT NULL DEFAULT 120,
    enabled INTEGER NOT NULL DEFAULT 1,
    created_at TEXT NOT NULL,
    updated_at TEXT NOT NULL
);

-- 平台 ↔ 代理组 多对多:一个平台可绑多个组,调度从并集选代理
CREATE TABLE IF NOT EXISTS platform_proxy_groups (
    platform_slug TEXT NOT NULL REFERENCES platforms(slug) ON DELETE CASCADE,
    proxy_group_id INTEGER NOT NULL REFERENCES proxy_groups(id) ON DELETE CASCADE,
    PRIMARY KEY(platform_slug, proxy_group_id)
);

CREATE TABLE IF NOT EXISTS proxies (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    group_id INTEGER NOT NULL REFERENCES proxy_groups(id) ON DELETE CASCADE,
    name TEXT,
    host TEXT NOT NULL,
    port INTEGER NOT NULL,
    username TEXT,
    password TEXT,
    country_code TEXT,
    country_name TEXT,
    exit_ip TEXT,
    latency_ms INTEGER,
    availability_rate REAL,
    status TEXT NOT NULL DEFAULT 'available' CHECK(status IN('available','manual_disabled')),
    last_synced_at TEXT,
    UNIQUE(group_id, host, port)
);
CREATE INDEX IF NOT EXISTS idx_proxies_group ON proxies(group_id);
CREATE INDEX IF NOT EXISTS idx_proxies_exit ON proxies(exit_ip);
CREATE INDEX IF NOT EXISTS idx_proxies_country ON proxies(country_code);

CREATE TABLE IF NOT EXISTS accounts (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    platform_slug TEXT NOT NULL REFERENCES platforms(slug) ON DELETE CASCADE,
    encrypted_key BLOB NOT NULL,
    key_preview TEXT NOT NULL,
    registration_ip TEXT,
    bound_proxy_id INTEGER REFERENCES proxies(id) ON DELETE SET NULL,
    status TEXT NOT NULL DEFAULT 'pending' CHECK(status IN('pending','healthy','manual_disabled','hard_revoked')),
    quota_limit INTEGER,
    quota_used INTEGER NOT NULL DEFAULT 0,
    quota_estimated_remaining INTEGER,
    reset_at TEXT,
    last_called_at TEXT,
    consecutive_failures INTEGER NOT NULL DEFAULT 0,
    upload_source TEXT NOT NULL DEFAULT 'manual' CHECK(upload_source IN('api','manual')),
    created_at TEXT NOT NULL,
    updated_at TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_accounts_platform_status ON accounts(platform_slug, status);
CREATE INDEX IF NOT EXISTS idx_accounts_proxy ON accounts(bound_proxy_id);
CREATE INDEX IF NOT EXISTS idx_accounts_status ON accounts(status);

CREATE TABLE IF NOT EXISTS issued_tokens (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    name TEXT NOT NULL,
    token_hash TEXT NOT NULL UNIQUE,
    token_prefix TEXT NOT NULL,
    status TEXT NOT NULL DEFAULT 'active' CHECK(status IN('active','revoked')),
    call_count INTEGER NOT NULL DEFAULT 0,
    revoked_at TEXT,
    created_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS token_platforms (
    token_id INTEGER NOT NULL REFERENCES issued_tokens(id) ON DELETE CASCADE,
    platform_slug TEXT NOT NULL REFERENCES platforms(slug) ON DELETE CASCADE,
    PRIMARY KEY(token_id, platform_slug)
);

CREATE TABLE IF NOT EXISTS call_logs (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    created_at TEXT NOT NULL,
    token_id INTEGER REFERENCES issued_tokens(id) ON DELETE SET NULL,
    platform_slug TEXT NOT NULL,
    endpoint TEXT,
    account_id INTEGER REFERENCES accounts(id) ON DELETE SET NULL,
    proxy_id INTEGER REFERENCES proxies(id) ON DELETE SET NULL,
    status_code INTEGER,
    duration_ms INTEGER,
    retry_count INTEGER NOT NULL DEFAULT 0,
    success INTEGER NOT NULL DEFAULT 0
);
CREATE INDEX IF NOT EXISTS idx_logs_created ON call_logs(created_at DESC);
CREATE INDEX IF NOT EXISTS idx_logs_token ON call_logs(token_id, created_at DESC);
CREATE INDEX IF NOT EXISTS idx_logs_platform ON call_logs(platform_slug, created_at DESC);
CREATE INDEX IF NOT EXISTS idx_logs_account ON call_logs(account_id, created_at DESC);

-- 运行时可调配置(设置页在线改,worker 动态读)
CREATE TABLE IF NOT EXISTS settings (
    key TEXT PRIMARY KEY,
    value TEXT NOT NULL,
    updated_at TEXT NOT NULL
);
"#;
