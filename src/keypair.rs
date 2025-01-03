use x25519_dalek::{EphemeralSecret, StaticSecret, PublicKey};
use crate::hex;

pub struct SharedKey {}

impl SharedKey {
    pub fn new(pk: String, sk: EphemeralSecret) -> String {
        let pk_vec = hex::decode(pk.as_str());
        let pk_bytes: [u8; 32] = pk_vec.try_into().unwrap_or([0xFF; 32]);
        let public_key = PublicKey::from(pk_bytes);

        let shared_key = sk.diffie_hellman(&public_key);
        let shared_key_bytes = shared_key.as_bytes();

        hex::encode(shared_key_bytes.to_vec())
    }
}

pub struct StaticSharedKey {}

impl StaticSharedKey {
    pub fn new(pk: String, sk: String) -> String {
        let pk_vec = hex::decode(pk.as_str());
        let pk_bytes: [u8; 32] = pk_vec.try_into().unwrap_or([0xFF; 32]);
        let public_key = PublicKey::from(pk_bytes);

        let sk_vec = hex::decode(sk.as_str());
        let sk_bytes: [u8; 32] = sk_vec.try_into().unwrap_or([0xFF; 32]);
        let secret_key = StaticSecret::from(sk_bytes);

        let shared_key = secret_key.diffie_hellman(&public_key);
        let shared_key_bytes = shared_key.as_bytes();

        hex::encode(shared_key_bytes.to_vec())
    }
}

/// Type alias for an ephemeral key pair.
pub struct KeyPair {
    pub pk: PublicKey,
    pub sk: EphemeralSecret,
}

impl KeyPair {
    pub fn new() -> KeyPair {
        let sk = EphemeralSecret::random();
        let pk = PublicKey::from(&sk);

        Self { pk, sk }
    }

    pub fn pk_string(&self) -> String {
        hex::encode(self.pk.as_bytes().to_vec())
    }
}

pub struct StaticKeyPair {
    pub pk: PublicKey,
    pub sk: StaticSecret,
}

impl StaticKeyPair {
    pub fn new() -> Self {
        let sk = StaticSecret::random();
        let pk = PublicKey::from(&sk);
        Self { pk, sk }
    }

    pub fn pk_string(&self) -> String {
        hex::encode(self.pk.as_bytes().to_vec())
    }

    pub fn sk_string(&self) -> String {
        hex::encode(self.sk.as_bytes().to_vec())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ephemeral_key_exchange() {
        // Given
        let client_kp = KeyPair::new();
        let server_kp = KeyPair::new();
        let server_pk = server_kp.pk_string();
        let client_pk = client_kp.pk_string();

        // When
        let client_shared_key = SharedKey::new(server_pk, client_kp.sk);
        let server_shared_key = SharedKey::new(client_pk, server_kp.sk);

        // Then
        assert_eq!(client_shared_key, server_shared_key);
    }

    #[test]
    fn static_key_exchange() {
        // Given
        let client_kp = StaticKeyPair::new();
        let server_kp = StaticKeyPair::new();
        let server_pk = server_kp.pk_string();
        let server_sk = server_kp.sk_string();
        let client_pk = client_kp.pk_string();
        let client_sk = client_kp.sk_string();

        // When
        let client_shared_key = StaticSharedKey::new(server_pk, client_sk);
        let server_shared_key = StaticSharedKey::new(client_pk, server_sk);

        // Then
        assert_eq!(client_shared_key, server_shared_key);
    }
}
