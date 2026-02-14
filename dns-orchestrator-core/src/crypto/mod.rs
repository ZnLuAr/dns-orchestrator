//! 加密模块
//!
//! 提供 AES-256-GCM 加密/解密功能，用于账户导入导出的加密保护。

mod versions;

pub use versions::{get_current_iterations, get_pbkdf2_iterations, CURRENT_FILE_VERSION};

use aes_gcm::{
    aead::{Aead, KeyInit},
    Aes256Gcm, Nonce,
};
use base64::{engine::general_purpose::STANDARD as BASE64, Engine};
use pbkdf2::pbkdf2_hmac_array;
use rand::RngCore;
use sha2::Sha256;

use crate::error::{CoreError, CoreResult};

// 从版本管理自动获取当前版本的迭代次数
const PBKDF2_ITERATIONS: u32 = get_current_iterations();
const SALT_LENGTH: usize = 16;
const NONCE_LENGTH: usize = 12;
const KEY_LENGTH: usize = 32; // AES-256

/// 从密码派生加密密钥（支持自定义迭代次数）
fn derive_key_with_iterations(password: &str, salt: &[u8], iterations: u32) -> [u8; KEY_LENGTH] {
    pbkdf2_hmac_array::<Sha256, KEY_LENGTH>(password.as_bytes(), salt, iterations)
}

/// 从密码派生加密密钥（使用默认迭代次数）
fn derive_key(password: &str, salt: &[u8]) -> [u8; KEY_LENGTH] {
    derive_key_with_iterations(password, salt, PBKDF2_ITERATIONS)
}

/// 加密数据
///
/// # Arguments
/// * `plaintext` - 要加密的明文数据
/// * `password` - 加密密码
///
/// # Returns
/// 返回 (`salt_base64`, `nonce_base64`, `ciphertext_base64`) 元组
pub fn encrypt(plaintext: &[u8], password: &str) -> CoreResult<(String, String, String)> {
    // 生成随机盐和 nonce
    let mut salt = [0u8; SALT_LENGTH];
    let mut nonce_bytes = [0u8; NONCE_LENGTH];
    rand::rng().fill_bytes(&mut salt);
    rand::rng().fill_bytes(&mut nonce_bytes);

    // 派生密钥
    let key = derive_key(password, &salt);

    // 创建加密器
    let cipher = Aes256Gcm::new_from_slice(&key)
        .map_err(|e| CoreError::SerializationError(format!("Failed to create cipher: {e}")))?;
    let nonce = Nonce::from_slice(&nonce_bytes);

    // 加密
    let ciphertext = cipher
        .encrypt(nonce, plaintext)
        .map_err(|e| CoreError::SerializationError(format!("Encryption failed: {e}")))?;

    Ok((
        BASE64.encode(salt),
        BASE64.encode(nonce_bytes),
        BASE64.encode(ciphertext),
    ))
}

/// 解密数据
///
/// # Arguments
/// * `ciphertext_b64` - Base64 编码的密文
/// * `password` - 解密密码
/// * `salt_b64` - Base64 编码的盐值
/// * `nonce_b64` - Base64 编码的 nonce
///
/// # Returns
/// 返回解密后的明文数据
pub fn decrypt(
    ciphertext_b64: &str,
    password: &str,
    salt_b64: &str,
    nonce_b64: &str,
) -> CoreResult<Vec<u8>> {
    decrypt_with_iterations(
        ciphertext_b64,
        password,
        salt_b64,
        nonce_b64,
        PBKDF2_ITERATIONS,
    )
}

/// 使用自定义迭代次数解密数据（用于向后兼容）
///
/// # Arguments
/// * `ciphertext_b64` - Base64 编码的密文
/// * `password` - 解密密码
/// * `salt_b64` - Base64 编码的盐值
/// * `nonce_b64` - Base64 编码的 nonce
/// * `iterations` - PBKDF2 迭代次数
///
/// # Returns
/// 返回解密后的明文数据
pub fn decrypt_with_iterations(
    ciphertext_b64: &str,
    password: &str,
    salt_b64: &str,
    nonce_b64: &str,
    iterations: u32,
) -> CoreResult<Vec<u8>> {
    // 解码 Base64
    let salt = BASE64
        .decode(salt_b64)
        .map_err(|e| CoreError::SerializationError(format!("Invalid salt: {e}")))?;
    let nonce_bytes = BASE64
        .decode(nonce_b64)
        .map_err(|e| CoreError::SerializationError(format!("Invalid nonce: {e}")))?;
    let ciphertext = BASE64
        .decode(ciphertext_b64)
        .map_err(|e| CoreError::SerializationError(format!("Invalid ciphertext: {e}")))?;

    // 使用指定迭代次数派生密钥
    let key = derive_key_with_iterations(password, &salt, iterations);

    // 创建解密器
    let cipher = Aes256Gcm::new_from_slice(&key)
        .map_err(|e| CoreError::SerializationError(format!("Failed to create cipher: {e}")))?;
    let nonce = Nonce::from_slice(&nonce_bytes);

    // 解密
    cipher.decrypt(nonce, ciphertext.as_ref()).map_err(|_| {
        CoreError::SerializationError(
            "Decryption failed: invalid password or corrupted data".to_string(),
        )
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn encrypt_decrypt_roundtrip() {
        let plaintext = b"hello, DNS orchestrator!";
        let password = "strong-password-123";

        let (salt, nonce, ciphertext) = encrypt(plaintext, password).unwrap();
        let decrypted = decrypt(&ciphertext, password, &salt, &nonce).unwrap();

        assert_eq!(decrypted, plaintext);
    }

    #[test]
    fn decrypt_wrong_password_fails() {
        let plaintext = b"secret data";
        let (salt, nonce, ciphertext) = encrypt(plaintext, "correct-password").unwrap();

        let result = decrypt(&ciphertext, "wrong-password", &salt, &nonce);
        assert!(result.is_err());
    }

    #[test]
    fn decrypt_corrupted_ciphertext_fails() {
        let plaintext = b"some data";
        let password = "password";
        let (salt, nonce, _) = encrypt(plaintext, password).unwrap();

        // 构造一个合法 base64 但内容是垃圾的密文
        let corrupted = BASE64.encode(b"this is not valid ciphertext at all!!");
        let result = decrypt(&corrupted, password, &salt, &nonce);
        assert!(result.is_err());
    }

    #[test]
    fn decrypt_invalid_base64_fails() {
        let result = decrypt("not-valid-base64!!!", "password", "also-bad!!!", "bad!!!");
        assert!(result.is_err());
    }

    #[test]
    fn encrypt_produces_different_output() {
        let plaintext = b"same data";
        let password = "same-password";

        let (salt1, nonce1, ct1) = encrypt(plaintext, password).unwrap();
        let (salt2, nonce2, ct2) = encrypt(plaintext, password).unwrap();

        // 随机 salt/nonce 使得输出不同
        assert!(salt1 != salt2 || nonce1 != nonce2 || ct1 != ct2);
    }

    #[test]
    fn decrypt_with_different_iterations() {
        let plaintext = b"version test data";
        let password = "test-password";

        // 用当前版本（v2, 600k 次）加密
        let (salt, nonce, ciphertext) = encrypt(plaintext, password).unwrap();

        // 用 v1 迭代次数（100k）解密 → 密钥不同，必然失败
        let v1_iterations = versions::get_pbkdf2_iterations(1).unwrap();
        let result = decrypt_with_iterations(&ciphertext, password, &salt, &nonce, v1_iterations);
        assert!(result.is_err());
    }
}
