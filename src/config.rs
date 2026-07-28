// 配置加载:优先 config.toml;不存在则生成默认(随机密钥 + 默认管理员)。
// DB 默认放 data/ 目录,便于 docker 目录挂载(挂 data/ 而非单个 .db 文件)。
use anyhow::Result;
use rand::RngCore;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

#[derive(Deserialize, Serialize, Clone, Debug)]
pub struct Config {
    pub listen: String,
    pub database_url: String,
    pub master_key: String,
    pub session_secret: String,
    pub admin_key: String,
    /// 代理组同步间隔(秒)—— 初始默认;运行时可在设置页调(存 DB settings 表)
    #[serde(default = "default_sync_interval")]
    pub sync_interval_secs: u64,
    /// 调用日志最大占用(MB)—— 超过则删最旧;0 = 不限
    #[serde(default = "default_log_max_mb")]
    pub log_max_mb: i64,
    /// 可选:管理员用户名(config 优先级最高,填了则每次启动覆盖 DB;不填则首次随机生成)
    #[serde(default)]
    pub admin_user: Option<String>,
    /// 可选:管理员密码(同 admin_user,填了则覆盖 DB)
    #[serde(default)]
    pub admin_password: Option<String>,
}

fn default_sync_interval() -> u64 {
    300
}
fn default_log_max_mb() -> i64 {
    100
}

impl Config {
    pub fn load() -> Result<Self> {
        let path = std::path::Path::new("config.toml");
        let cfg = if path.exists() {
            let s = std::fs::read_to_string(path)?;
            toml::from_str(&s)?
        } else {
            let cfg = Self::generate_default();
            std::fs::write(path, toml::to_string_pretty(&cfg)?)?;
            tracing::warn!(
                "已生成默认 config.toml(随机密钥 + 默认管理员 admin/admin123),生产环境请修改"
            );
            cfg
        };
        // DB 在 data/ 下时,确保目录存在(目录挂载友好)
        let lower = cfg.database_url.to_lowercase();
        if lower.contains("data/") || lower.contains("data\\") {
            std::fs::create_dir_all("data")?;
        }
        Ok(cfg)
    }

    fn generate_default() -> Self {
        Self {
            listen: "0.0.0.0:8787".into(),
            database_url: "sqlite:data/keypool.db?mode=rwc".into(),
            master_key: random_hex(32),
            session_secret: random_hex(32),
            admin_key: format!("admin_{}", random_hex(8)),
            sync_interval_secs: 300,
            log_max_mb: 100,
            admin_user: None,
            admin_password: None,
        }
    }

    /// 由 master_key 派生 AES-256 密钥
    pub fn aes_key(&self) -> [u8; 32] {
        let mut h = Sha256::new();
        h.update(self.master_key.as_bytes());
        let mut k = [0u8; 32];
        k.copy_from_slice(&h.finalize());
        k
    }

    /// 由 session_secret 派生 HMAC 密钥
    pub fn session_hmac_key(&self) -> [u8; 32] {
        let mut h = Sha256::new();
        h.update(self.session_secret.as_bytes());
        let mut k = [0u8; 32];
        k.copy_from_slice(&h.finalize());
        k
    }
}

fn random_hex(n: usize) -> String {
    let mut buf = vec![0u8; n];
    rand::thread_rng().fill_bytes(&mut buf);
    hex::encode(buf)
}
