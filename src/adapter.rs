// 平台适配层:trait + 四平台 impl + Registry。加平台 = 加一个 impl + 注册,不动调度。
// 透明转发:撕分发 token、换真实 key 头,请求体/其余头透传。
// 三档判定:401→硬剔除 / 402·432·433→软 disable / 429→退避(分类对所有平台通用)。
use axum::http::{HeaderMap, HeaderValue, StatusCode};
use chrono::{DateTime, Utc};
use std::collections::HashMap;
use std::sync::Arc;

/// 一次调用的状态分类(三档 + 成功/瞬时/其他)
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CallOutcome {
    Success,
    HardRevoked,
    RateLimited,
    Transient,
    OtherError,
}

/// 每平台可配的判定码(由 platforms 表逗号分隔字符串解析;不做全局码表)
#[derive(Debug, Clone, Default)]
pub struct StatusCodes {
    pub revoke: Vec<u16>,
    pub rate: Vec<u16>,
}

impl StatusCodes {
    pub fn parse(revoke: &str, rate: &str) -> Self {
        fn list(s: &str) -> Vec<u16> {
            s.split(',')
                .filter_map(|t| t.trim().parse::<u16>().ok())
                .collect()
        }
        Self {
            revoke: list(revoke),
            rate: list(rate),
        }
    }
}

#[derive(Debug, Clone, Default)]
pub struct BalanceInfo {
    pub remaining: Option<f64>,
    pub reset_at: Option<DateTime<Utc>>,
}

#[async_trait::async_trait]
pub trait PlatformAdapter: Send + Sync {
    fn base_url(&self) -> &'static str;

    /// 套上真实 key 的认证头(各平台不同)
    fn apply_auth(&self, headers: &mut HeaderMap, real_key: &str);

    /// 拼上游 URL
    fn build_url(&self, endpoint: &str) -> String {
        format!("{}{}", self.base_url(), endpoint)
    }

    /// 从原请求头准备转发头:移除分发 token / host / 连接相关,套真实认证头
    fn prepare(
        &self,
        original: &HeaderMap,
        endpoint: &str,
        real_key: &str,
    ) -> (String, HeaderMap) {
        let url = self.build_url(endpoint);
        let mut h = original.clone();
        // 网关只换认证头,其余一律透传。仅移除:认证头(换真实 key)、host(reqwest 必须自设)、
        // content-length(body 重算)、hop-by-hop 头(RFC 7230 代理必须剥除)。编码/类型等业务头全部保留。
        for hk in [
            "authorization",
            "x-api-key",
            "host",
            "content-length",
            "connection",
            "keep-alive",
            "transfer-encoding",
            "te",
            "trailer",
            "proxy-authorization",
            "upgrade",
        ] {
            h.remove(hk);
        }
        self.apply_auth(&mut h, real_key);
        (url, h)
    }

    /// 状态判定:2xx→成功;5xx→瞬时退避;封号码→永久剔除;限流码→退避重试;其余透传
    fn classify(&self, status: StatusCode, codes: &StatusCodes) -> CallOutcome {
        let code = status.as_u16();
        if status.is_success() {
            CallOutcome::Success
        } else if status.is_server_error() {
            CallOutcome::Transient
        } else if codes.revoke.contains(&code) {
            CallOutcome::HardRevoked
        } else if codes.rate.contains(&code) {
            CallOutcome::RateLimited
        } else {
            CallOutcome::OtherError
        }
    }

    /// 主动余额查询(可查平台:Firecrawl/Tavily;不可查返回 None)
    async fn query_balance(
        &self,
        _client: &reqwest::Client,
        _real_key: &str,
    ) -> Option<BalanceInfo> {
        None
    }

    fn supports_balance_query(&self) -> bool {
        false
    }

    /// 测活:向平台发一个最小代价的探测请求,返回上游 HTTP status。
    /// 返回 None 表示请求未能发出或无响应(网络 / 代理错误);返回 Some 即拿到上游响应,
    /// 由调用方结合平台判定码分类(2xx=活,封号码=失效,其余=未知,不动状态)。
    async fn probe_key(&self, _client: &reqwest::Client, _real_key: &str) -> Option<StatusCode>;
}

// —— 四平台 ——

pub struct Context7;
pub struct Exa;
pub struct Firecrawl;
pub struct Tavily;

fn set_bearer(headers: &mut HeaderMap, key: &str) {
    if let Ok(v) = HeaderValue::from_str(&format!("Bearer {key}")) {
        headers.insert("authorization", v);
    }
}

#[async_trait::async_trait]
impl PlatformAdapter for Context7 {
    fn base_url(&self) -> &'static str {
        "https://context7.com/api/v2"
    }
    fn apply_auth(&self, h: &mut HeaderMap, key: &str) {
        set_bearer(h, key);
    }
    async fn probe_key(&self, client: &reqwest::Client, key: &str) -> Option<StatusCode> {
        let resp = client
            .get("https://context7.com/api/v2/search?query=react")
            .bearer_auth(key)
            .send()
            .await
            .ok()?;
        Some(resp.status())
    }
}

#[async_trait::async_trait]
impl PlatformAdapter for Exa {
    fn base_url(&self) -> &'static str {
        "https://api.exa.ai"
    }
    fn apply_auth(&self, h: &mut HeaderMap, key: &str) {
        if let Ok(v) = HeaderValue::from_str(key) {
            h.insert("x-api-key", v);
        }
    }
    async fn probe_key(&self, client: &reqwest::Client, key: &str) -> Option<StatusCode> {
        // Exa 无免费探测端点;发一次最小 search(numResults=1)验证 key,消耗 1 次搜索额度
        let resp = client
            .post("https://api.exa.ai/search")
            .header("x-api-key", key)
            .json(&serde_json::json!({"query":"exa.ai","numResults":1}))
            .send()
            .await
            .ok()?;
        Some(resp.status())
    }
}

#[async_trait::async_trait]
impl PlatformAdapter for Firecrawl {
    fn base_url(&self) -> &'static str {
        "https://api.firecrawl.dev"
    }
    fn apply_auth(&self, h: &mut HeaderMap, key: &str) {
        set_bearer(h, key);
    }
    async fn probe_key(&self, client: &reqwest::Client, key: &str) -> Option<StatusCode> {
        let resp = client
            .get("https://api.firecrawl.dev/v2/team/credit-usage")
            .bearer_auth(key)
            .send()
            .await
            .ok()?;
        Some(resp.status())
    }
    fn supports_balance_query(&self) -> bool {
        true
    }
    async fn query_balance(&self, client: &reqwest::Client, key: &str) -> Option<BalanceInfo> {
        let resp = client
            .get("https://api.firecrawl.dev/v2/team/credit-usage")
            .bearer_auth(key)
            .send()
            .await
            .ok()?;
        let v: serde_json::Value = resp.json().await.ok()?;
        Some(BalanceInfo {
            remaining: v.get("remainingCredits")?.as_f64(),
            reset_at: v
                .get("billingPeriodEnd")
                .and_then(|s| s.as_str())
                .and_then(parse_iso),
        })
    }
}

#[async_trait::async_trait]
impl PlatformAdapter for Tavily {
    fn base_url(&self) -> &'static str {
        "https://api.tavily.com"
    }
    fn apply_auth(&self, h: &mut HeaderMap, key: &str) {
        set_bearer(h, key);
    }
    async fn probe_key(&self, client: &reqwest::Client, key: &str) -> Option<StatusCode> {
        let resp = client
            .get("https://api.tavily.com/usage")
            .bearer_auth(key)
            .send()
            .await
            .ok()?;
        Some(resp.status())
    }
    fn supports_balance_query(&self) -> bool {
        true
    }
    async fn query_balance(&self, client: &reqwest::Client, key: &str) -> Option<BalanceInfo> {
        let resp = client
            .get("https://api.tavily.com/usage")
            .bearer_auth(key)
            .send()
            .await
            .ok()?;
        let v: serde_json::Value = resp.json().await.ok()?;
        let key_usage = v.get("key").or_else(|| v.get("usage"))?;
        let used = key_usage.get("usage").and_then(|x| x.as_f64());
        let limit = key_usage.get("limit").and_then(|x| x.as_f64());
        Some(BalanceInfo {
            remaining: match (limit, used) {
                (Some(l), Some(u)) => Some(l - u),
                _ => None,
            },
            reset_at: None,
        })
    }
}

fn parse_iso(s: &str) -> Option<DateTime<Utc>> {
    DateTime::parse_from_rfc3339(s).ok().map(|d| d.with_timezone(&Utc))
}

pub struct Registry {
    map: HashMap<&'static str, Arc<dyn PlatformAdapter>>,
}

impl Registry {
    pub fn new() -> Self {
        let mut map: HashMap<&'static str, Arc<dyn PlatformAdapter>> = HashMap::new();
        map.insert("context7", Arc::new(Context7) as Arc<dyn PlatformAdapter>);
        map.insert("exa", Arc::new(Exa) as Arc<dyn PlatformAdapter>);
        map.insert("firecrawl", Arc::new(Firecrawl) as Arc<dyn PlatformAdapter>);
        map.insert("tavily", Arc::new(Tavily) as Arc<dyn PlatformAdapter>);
        Self { map }
    }

    pub fn get(&self, slug: &str) -> Option<Arc<dyn PlatformAdapter>> {
        self.map.get(slug).cloned()
    }

    pub fn slugs(&self) -> Vec<&'static str> {
        self.map.keys().copied().collect()
    }
}

/// 鉴权调用方分发 token,返回绑定的平台 slug 列表校验(由调用方在 handler 做)
pub fn known_slugs() -> &'static [&'static str] {
    &["context7", "exa", "firecrawl", "tavily"]
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::http::StatusCode;

    fn cls(code: u16) -> CallOutcome {
        let codes = StatusCodes::parse("401", "429");
        Context7.classify(StatusCode::from_u16(code).unwrap(), &codes)
    }

    #[test]
    fn classify_2xx_success() {
        for c in [200, 201, 204] {
            assert_eq!(cls(c), CallOutcome::Success, "code {c}");
        }
    }

    #[test]
    fn classify_401_hard_revoked() {
        assert_eq!(cls(401), CallOutcome::HardRevoked);
    }

    #[test]
    fn classify_payment_codes_passthrough_by_default() {
        // 402/432/433 默认不在封号码(401)/限流码(429) → 透传(OtherError);需封号则用户自行加入封号码
        for c in [402, 432, 433] {
            assert_eq!(cls(c), CallOutcome::OtherError, "code {c}");
        }
    }

    #[test]
    fn classify_429_rate_limited() {
        assert_eq!(cls(429), CallOutcome::RateLimited);
    }

    #[test]
    fn classify_5xx_transient() {
        for c in [500, 502, 503] {
            assert_eq!(cls(c), CallOutcome::Transient, "code {c}");
        }
    }

    #[test]
    fn classify_other_4xx_passthrough() {
        // 400/403/404/422:调用方请求本身的错误,透传不重试
        for c in [400, 403, 404, 422] {
            assert_eq!(cls(c), CallOutcome::OtherError, "code {c}");
        }
    }

    #[test]
    fn classify_uniform_across_all_platforms() {
        // 封号/限流判定是 trait 默认实现,对所有平台一致
        let codes = StatusCodes::parse("401", "429");
        let adapters: Vec<Box<dyn PlatformAdapter>> = vec![
            Box::new(Context7),
            Box::new(Exa),
            Box::new(Firecrawl),
            Box::new(Tavily),
        ];
        for a in &adapters {
            assert_eq!(a.classify(StatusCode::OK, &codes), CallOutcome::Success);
            assert_eq!(
                a.classify(StatusCode::UNAUTHORIZED, &codes),
                CallOutcome::HardRevoked
            );
            assert_eq!(
                a.classify(StatusCode::TOO_MANY_REQUESTS, &codes),
                CallOutcome::RateLimited
            );
            assert_eq!(
                a.classify(StatusCode::INTERNAL_SERVER_ERROR, &codes),
                CallOutcome::Transient
            );
        }
    }
}
