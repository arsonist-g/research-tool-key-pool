// 鉴权:管理员会话(签名 cookie)/ 管理 API key(X-Admin-Key)/ 分发 token(Bearer)。
use crate::error::AppError;
use crate::state::SharedState;
use axum::extract::{Request, State};
use axum::http::HeaderMap;
use axum::middleware::Next;
use axum::response::Response;
use chrono::{Duration as ChDuration, Utc};
use hmac::{Hmac, Mac};
use sha2::Sha256;

type HmacSha256 = Hmac<Sha256>;

#[derive(Clone, Copy, Debug)]
pub struct AdminUser {
    pub id: i64,
}

#[derive(Clone, Copy, Debug)]
pub struct ForwardAuth {
    pub token_id: i64,
}

/// 签发会话 cookie 值:`{admin_id}:{exp_unix}.{hmac_hex}`
pub fn sign_session(admin_id: i64, hmac_key: &[u8; 32]) -> String {
    let exp = Utc::now() + ChDuration::days(7);
    let payload = format!("{}:{}", admin_id, exp.timestamp());
    let mut mac = HmacSha256::new_from_slice(hmac_key).expect("hmac key");
    mac.update(payload.as_bytes());
    format!("{}.{}", payload, hex::encode(mac.finalize().into_bytes()))
}

pub fn verify_session(val: &str, hmac_key: &[u8; 32]) -> Option<i64> {
    let (payload, sig_hex) = val.rsplit_once('.')?;
    let mut mac = HmacSha256::new_from_slice(hmac_key).ok()?;
    mac.update(payload.as_bytes());
    let expected = mac.finalize().into_bytes();
    let provided = hex::decode(sig_hex).ok()?;
    if expected.as_slice() != provided.as_slice() {
        return None;
    }
    let (id_s, exp_s) = payload.split_once(':')?;
    let id: i64 = id_s.parse().ok()?;
    let exp: i64 = exp_s.parse().ok()?;
    if Utc::now().timestamp() >= exp {
        return None;
    }
    Some(id)
}

fn find_cookie(headers: &HeaderMap, name: &str) -> Option<String> {
    let cv = headers.get("cookie")?.to_str().ok()?;
    let prefix = format!("{}=", name);
    for pair in cv.split(';') {
        let pair = pair.trim();
        if let Some(v) = pair.strip_prefix(&prefix) {
            return Some(v.to_string());
        }
    }
    None
}

/// 管理员鉴权中间件:接受 X-Admin-Key 或有效会话 cookie
pub async fn require_admin(
    State(st): State<SharedState>,
    req: Request,
    next: Next,
) -> Result<Response, AppError> {
    let (key_opt, sess_opt) = {
        let h = req.headers();
        (
            h.get("x-admin-key")
                .and_then(|v| v.to_str().ok())
                .map(String::from),
            find_cookie(h, "kp_session"),
        )
    };
    if let Some(k) = key_opt {
        if k == st.config.admin_key {
            return Ok(run_with(req, next, AdminUser { id: 0 }).await);
        }
    }
    if let Some(s) = sess_opt {
        if let Some(id) = verify_session(&s, &st.config.session_hmac_key()) {
            return Ok(run_with(req, next, AdminUser { id }).await);
        }
    }
    Err(AppError::unauthorized("需要登录或有效管理 key"))
}

/// 转发鉴权中间件:Authorization: Bearer <分发token>
pub async fn require_forward(
    State(st): State<SharedState>,
    req: Request,
    next: Next,
) -> Result<Response, AppError> {
    let token = {
        let h = req.headers();
        // 统一 Authorization: Bearer;其次兼容 x-api-key(Exa 等原生客户端固定用此头发认证,
        // 把分发 token 作为 x-api-key 传入;网关内部仍会替换为真实平台 key,上游认证不变)
        if let Some(v) = h.get("authorization").and_then(|v| v.to_str().ok()) {
            v.strip_prefix("Bearer ").map(|x| x.trim().to_string())
        } else {
            h.get("x-api-key")
                .and_then(|v| v.to_str().ok())
                .map(|s| s.trim().to_string())
        }
    };
    let token = token.ok_or_else(|| AppError::unauthorized("缺少 Authorization Bearer 或 x-api-key token"))?;
    let hash = crate::crypto::sha256_hex(&token);
    #[derive(sqlx::FromRow)]
    struct TokenRow {
        id: i64,
        status: String,
    }
    let row: Option<TokenRow> =
        sqlx::query_as("SELECT id, status FROM issued_tokens WHERE token_hash=?")
            .bind(&hash)
            .fetch_optional(&st.pools.db)
            .await?;
    let row = row.ok_or_else(|| AppError::unauthorized("token 无效"))?;
    let id = row.id;
    let status = row.status;
    if status != "active" {
        return Err(AppError::unauthorized("token 已吊销"));
    }
    Ok(run_with(req, next, ForwardAuth { token_id: id }).await)
}

async fn run_with<T: Clone + Send + Sync + 'static>(mut req: Request, next: Next, ext: T) -> Response {
    req.extensions_mut().insert(ext);
    next.run(req).await
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn session_roundtrip() {
        let key = [7u8; 32];
        let s = sign_session(42, &key);
        assert_eq!(verify_session(&s, &key), Some(42));
    }

    #[test]
    fn session_tampered_payload_rejected() {
        // 篡改 payload(admin_id 42→43),签名不再匹配 → 拒绝
        let key = [7u8; 32];
        let s = sign_session(42, &key);
        let tampered = format!("43{}", &s[2..]);
        assert_eq!(verify_session(&tampered, &key), None);
    }

    #[test]
    fn session_wrong_key_rejected() {
        let key = [7u8; 32];
        let other = [9u8; 32];
        let s = sign_session(42, &key);
        assert_eq!(verify_session(&s, &other), None);
    }

    #[test]
    fn session_malformed_rejected() {
        let key = [7u8; 32];
        assert_eq!(verify_session("garbage", &key), None);
        // 缺签名段(无 '.')
        assert_eq!(verify_session("1:2", &key), None);
    }

    #[test]
    fn session_distinct_ids() {
        let key = [7u8; 32];
        let a = sign_session(1, &key);
        let b = sign_session(2, &key);
        assert_ne!(a, b);
        assert_eq!(verify_session(&a, &key), Some(1));
        assert_eq!(verify_session(&b, &key), Some(2));
    }
}
