// 加密 / 哈希 / 脱敏。
// - AES-256-GCM 加密真实 key(nonce 前置)
// - SHA-256 哈希分发 token
// - key 脱敏预览
use aes_gcm::aead::{Aead, KeyInit};
use aes_gcm::{Aes256Gcm, Key, Nonce};
use anyhow::{anyhow, Result};
use rand::RngCore;
use sha2::{Digest, Sha256};

#[allow(deprecated)]  // aes-gcm 0.11 的 Array::from_slice 被 hybrid-array 标记弃用;功能等价且为官方示例写法,保留简洁
pub fn encrypt(key: &[u8; 32], plaintext: &[u8]) -> Result<Vec<u8>> {
    let cipher = Aes256Gcm::new(Key::<Aes256Gcm>::from_slice(key));
    let mut nonce = [0u8; 12];
    rand::thread_rng().fill_bytes(&mut nonce);
    let ct = cipher
        .encrypt(Nonce::from_slice(&nonce), plaintext)
        .map_err(|e| anyhow!("encrypt: {e}"))?;
    let mut out = Vec::with_capacity(12 + ct.len());
    out.extend_from_slice(&nonce);
    out.extend_from_slice(&ct);
    Ok(out)
}

#[allow(deprecated)]
pub fn decrypt(key: &[u8; 32], data: &[u8]) -> Result<Vec<u8>> {
    if data.len() < 12 {
        return Err(anyhow!("ciphertext too short"));
    }
    let cipher = Aes256Gcm::new(Key::<Aes256Gcm>::from_slice(key));
    let (nonce, ct) = data.split_at(12);
    cipher
        .decrypt(Nonce::from_slice(nonce), ct)
        .map_err(|e| anyhow!("decrypt: {e}"))
}

pub fn sha256_hex(s: &str) -> String {
    let mut h = Sha256::new();
    h.update(s.as_bytes());
    hex::encode(h.finalize())
}

/// 真实 key 脱敏:保留前缀特征 + 后 4 位,中间省略
pub fn key_preview(plaintext: &str) -> String {
    let chars: Vec<char> = plaintext.chars().collect();
    let n = chars.len();
    if n <= 8 {
        return "•".repeat(n.max(4));
    }
    let prefix: String = chars[..6].iter().collect();
    let suffix: String = chars[n - 4..].iter().collect();
    format!("{prefix}…{suffix}")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn encrypt_decrypt_roundtrip() {
        let key = [42u8; 32];
        let pt = b"sk-test-1234567890abcdef";
        let ct = encrypt(&key, pt).unwrap();
        assert_ne!(ct, pt.to_vec(), "ciphertext must differ from plaintext");
        let back = decrypt(&key, &ct).unwrap();
        assert_eq!(back, pt, "decrypt(encrypt(x)) == x");
    }

    #[test]
    fn encrypt_nonce_is_random() {
        // 同明文两次加密,密文必须不同(nonce 前置且随机)
        let key = [1u8; 32];
        let a = encrypt(&key, b"hello").unwrap();
        let b = encrypt(&key, b"hello").unwrap();
        assert_ne!(a, b);
    }

    #[test]
    fn decrypt_with_wrong_key_fails() {
        let key = [1u8; 32];
        let other = [2u8; 32];
        let ct = encrypt(&key, b"secret").unwrap();
        assert!(decrypt(&other, &ct).is_err());
    }

    #[test]
    fn decrypt_tampered_ciphertext_fails() {
        let key = [1u8; 32];
        let mut ct = encrypt(&key, b"secret").unwrap();
        ct[12] ^= 0xff; // 翻转密文一位(GCM 会校验失败)
        assert!(decrypt(&key, &ct).is_err());
    }

    #[test]
    fn key_preview_long_keeps_prefix_and_suffix() {
        let p = key_preview("ctx7sk-abcdef-1234567890");
        assert!(p.starts_with("ctx7sk"), "preview keeps prefix");
        assert!(p.contains('…'));
    }

    #[test]
    fn key_preview_short_is_masked() {
        let p = key_preview("abc");
        assert!(p.contains('•'), "short key fully masked");
    }

    #[test]
    fn sha256_hex_deterministic_and_known() {
        assert_eq!(sha256_hex("abc"), sha256_hex("abc"));
        assert_ne!(sha256_hex("abc"), sha256_hex("abd"));
        // 已知向量(空串 / "abc")
        assert_eq!(
            sha256_hex("abc"),
            "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
        );
    }
}
