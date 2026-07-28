// 共享应用状态。
use crate::adapter::Registry;
use crate::config::Config;
use crate::pools::Pools;
use crate::scheduler::ProxyClientPool;
use std::sync::Arc;

pub struct AppState {
    pub config: Config,
    pub pools: Arc<Pools>,
    pub registry: Arc<Registry>,
    pub proxy_clients: ProxyClientPool,
    pub http: reqwest::Client,
}

pub type SharedState = Arc<AppState>;
