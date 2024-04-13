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
        let shared_key = "edf9d004edae8335f095bb8e01975c42cf693ea60322b75cb7c6667dc836fd7e";
        let ciphertext = "58b99ca42eaed1949d3d707208b39fc9bd8d8b35d44066c072c4ce44cd004971a66389adbfcb3b59903bc22dd825cf7267c63efda6c86bdb0f62571858ac914af67d7cf92e84738996441afcb141a9f621e795e2d2446e1b75d26ee61187c1680af84b5625c3bc9199f69abfb940dbf90970fd1b53bf51d86524249e3af9132b8fdb09f0cd3303f2e9eeeae8e3333104ebb4463aa7";
        let plaintext = r#"{"token": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxIn0.rTCH8cLoGxAm_xw68z-zXVKi9ie6xJn9tnVWjd_9ftE"}"#;

        // When
        let actual = lazyxchacha.decrypt(ciphertext, shared_key);

        // Then
        assert_eq!(actual, plaintext)
    }
}
