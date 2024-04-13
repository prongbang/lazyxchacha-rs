use std::sync::Arc;
use chacha20poly1305::{
    aead::{Aead, AeadCore, KeyInit, OsRng},
    XChaCha20Poly1305,
};
use chacha20poly1305::aead::generic_array::GenericArray;
use crate::hex;

pub trait Cryptography {
    fn encrypt(&self, plaintext: &str, key: &str) -> String;
    fn decrypt(&self, ciphertext: &str, key: &str) -> String;
}

pub struct LazyXChaCha {}

impl LazyXChaCha {
    pub fn new() -> Arc<dyn Cryptography> {
        Arc::new(LazyXChaCha {})
    }
}

impl Cryptography for LazyXChaCha {
    fn encrypt(&self, plaintext: &str, key: &str) -> String {
        let key = hex::decode(key);
        let key = GenericArray::from_slice(key.as_slice());
        let cipher = XChaCha20Poly1305::new(key);

        let nonce = XChaCha20Poly1305::generate_nonce(&mut OsRng);
        let ciphertext = cipher.encrypt(&nonce, plaintext.as_ref()).unwrap_or(Vec::new());
        let mut combined = Vec::<u8>::with_capacity(nonce.len() + ciphertext.len());
        combined.extend_from_slice(&nonce);
        combined.extend_from_slice(&ciphertext);

        hex::encode(combined)
    }

    fn decrypt(&self, ciphertext: &str, key: &str) -> String {
        let key = hex::decode(key);
        let key = GenericArray::from_slice(key.as_slice());
        let cipher = XChaCha20Poly1305::new(key);

        let ciphertext = hex::decode(ciphertext);
        let nonce = &ciphertext[0..24];
        let nonce = GenericArray::from_slice(nonce);
        let ciphertext = &ciphertext[24..];
        let plaintext = cipher.decrypt(nonce, ciphertext).unwrap_or(Vec::new());

        String::from_utf8(plaintext).unwrap_or("".to_string())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn encrypt() {
        // Given
        let lazyxchacha = LazyXChaCha::new();
        let shared_key = "edf9d004edae8335f095bb8e01975c42cf693ea60322b75cb7c6667dc836fd7e";
        let plaintext = r#"{"token": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxIn0.rTCH8cLoGxAm_xw68z-zXVKi9ie6xJn9tnVWjd_9ftE"}"#;

        // When
        let actual = lazyxchacha.encrypt(plaintext, shared_key);

        // Then
        assert_eq!(actual.is_empty(), false)
    }

    #[test]
    fn decrypt() {
        // Given
        let lazyxchacha = LazyXChaCha::new();
        let shared_key = "e4f7fe3c8b4066490f8ffde56f080c70629ff9731b60838015027c4687303b1d";
        let ciphertext = "c3b89ce0cb7d7349e8c254ebcaa8f347b7b70df2e6d34bde709a75175ddc18402aec0c55ca9d8754359ba5d9624eac7530a149f4befbfcf396fb4edd9af6103065fac4a56fcb5afe95cbaa064c8c8fef3ddeb1219a0a28bd8228699cd4139a2fe9541cfd67ff3ea05002023c1216001709c42fcfebb658e3fd9df1f24b74d19012b92b2c5af8a397fba773a27cc1a08cbb195e0871";
        let plaintext = r#"{"token": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxIn0.rTCH8cLoGxAm_xw68z-zXVKi9ie6xJn9tnVWjd_9ftE"}"#;

        // When
        let actual = lazyxchacha.decrypt(ciphertext, shared_key);

        // Then
        assert_eq!(actual, plaintext)
    }
}
