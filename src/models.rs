// 数据模型(与 backend-design/key-pool/data-model.md 一致)。敏感字段 skip_serializing。
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use sqlx::FromRow;

#[derive(Debug, Clone, FromRow, Serialize, Deserialize)]
pub struct Platform {
    pub slug: String,
    pub display_name: String,
    pub max_concurrency: i32,
    pub risk_policy: String, // strict | loose
    pub same_ip_isolation: bool,
    pub default_quota_limit: Option<i64>,
    pub revoke_codes: String,
    pub rate_limit_codes: String,
    pub upstream_timeout_secs: i64,
    pub enabled: bool,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

#[derive(Debug, Clone, FromRow, Serialize)]
pub struct Account {
    pub id: i64,
    pub platform_slug: String,
    #[serde(skip_serializing)]
    pub encrypted_key: Vec<u8>,
    pub key_preview: String,
    pub registration_ip: Option<String>,
    pub bound_proxy_id: Option<i64>,
    pub status: String, // pending | healthy | manual_disabled | hard_revoked
    pub quota_limit: Option<i64>,
    pub quota_used: i64,
    pub quota_estimated_remaining: Option<i64>,
    pub reset_at: Option<DateTime<Utc>>,
    pub last_called_at: Option<DateTime<Utc>>,
    pub consecutive_failures: i32,
    pub upload_source: String, // api | manual
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

#[derive(Debug, Clone, FromRow, Serialize, Deserialize)]
pub struct ProxyGroup {
    pub id: i64,
    pub name: String,
    pub subscription_url: String,
    pub enabled: bool,
    pub last_synced_at: Option<DateTime<Utc>>,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

#[derive(Debug, Clone, FromRow, Serialize)]
pub struct Proxy {
    pub id: i64,
    pub group_id: i64,
    pub name: Option<String>,
    pub host: String,
    pub port: i32,
    pub username: Option<String>,
    #[serde(skip_serializing)]
    pub password: Option<String>,
    pub country_code: Option<String>,
    pub country_name: Option<String>,
    pub exit_ip: Option<String>,
    pub latency_ms: Option<i32>,
    pub availability_rate: Option<f64>,
    pub status: String, // available | manual_disabled
    pub last_synced_at: Option<DateTime<Utc>>,
}

#[derive(Debug, Clone, FromRow, Serialize)]
pub struct IssuedToken {
    pub id: i64,
    pub name: String,
    #[serde(skip_serializing)]
    #[allow(dead_code)]
    pub token_hash: String,
    pub token_prefix: String,
    pub status: String, // active | revoked
    pub call_count: i64,
    pub revoked_at: Option<DateTime<Utc>>,
    pub created_at: DateTime<Utc>,
}

#[derive(Debug, Clone, FromRow, Serialize)]
pub struct CallLog {
    pub id: i64,
    pub created_at: DateTime<Utc>,
    pub token_id: Option<i64>,
    pub platform_slug: String,
    pub endpoint: Option<String>,
    pub account_id: Option<i64>,
    pub proxy_id: Option<i64>,
    pub status_code: Option<i32>,
    pub duration_ms: Option<i64>,
    pub retry_count: i32,
    pub success: bool,
}

// —— 便于内存索引的轻量视图 ——
#[derive(Debug, Clone)]
pub struct AccountSlot {
    pub id: i64,
    pub platform_slug: String,
    pub decrypted_key: String,
    pub bound_proxy_id: Option<i64>,
    pub status: String,
    pub quota_limit: Option<i64>,
    pub quota_used: i64,
    pub reset_at: Option<DateTime<Utc>>,
    pub last_called_at: Option<DateTime<Utc>>,
    pub consecutive_failures: i32,
}

#[derive(Debug, Clone)]
pub struct ProxyEntry {
    pub id: i64,
    pub group_id: i64,
    pub host: String,
    pub port: i32,
    pub username: Option<String>,
    pub password: Option<String>,
    pub exit_ip: Option<String>,
    pub status: String,
}
