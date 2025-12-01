use ring::aead::{Aad, LessSafeKey, Nonce, UnboundKey, AES_256_GCM};
use ring::rand::{SecureRandom, SystemRandom};
use argon2::Argon2;
use thiserror::Error;

uniffi::setup_scaffolding!();

#[derive(Debug, Error, uniffi::Error)]
pub enum CryptoError {
    #[error("Invalid key length: expected 32 bytes, got {0}")]
    InvalidKeyLength(u64),
    #[error("Invalid ciphertext: too short to contain nonce")]
    InvalidCiphertext,
    #[error("Encryption failed")]
    EncryptionFailed,
    #[error("Decryption failed: invalid ciphertext or wrong key")]
    DecryptionFailed,
    #[error("Key derivation failed")]
    KeyDerivationFailed,
    #[error("Random generation failed")]
    RandomGenerationFailed,
    #[error("Invalid salt length: expected at least 8 bytes, got {0}")]
    InvalidSaltLength(u64),
}

/// Encrypt plaintext using AES-256-GCM
/// Returns nonce (12 bytes) prepended to ciphertext
#[uniffi::export]
pub fn encrypt(plaintext: Vec<u8>, key: Vec<u8>) -> Result<Vec<u8>, CryptoError> {
    if key.len() != 32 {
        return Err(CryptoError::InvalidKeyLength(key.len() as u64));
    }

    let unbound_key = UnboundKey::new(&AES_256_GCM, &key)
        .map_err(|_| CryptoError::InvalidKeyLength(key.len() as u64))?;
    let less_safe_key = LessSafeKey::new(unbound_key);

    let rng = SystemRandom::new();
    let mut nonce_bytes = [0u8; 12];
    rng.fill(&mut nonce_bytes)
        .map_err(|_| CryptoError::RandomGenerationFailed)?;
    let nonce = Nonce::assume_unique_for_key(nonce_bytes);

    let mut in_out = plaintext;
    less_safe_key
        .seal_in_place_append_tag(nonce, Aad::empty(), &mut in_out)
        .map_err(|_| CryptoError::EncryptionFailed)?;

    let mut result = nonce_bytes.to_vec();
    result.extend(in_out);
    Ok(result)
}

/// Decrypt ciphertext using AES-256-GCM
/// Expects nonce (12 bytes) prepended to ciphertext
#[uniffi::export]
pub fn decrypt(ciphertext: Vec<u8>, key: Vec<u8>) -> Result<Vec<u8>, CryptoError> {
    if key.len() != 32 {
        return Err(CryptoError::InvalidKeyLength(key.len() as u64));
    }
    if ciphertext.len() < 12 {
        return Err(CryptoError::InvalidCiphertext);
    }

    let unbound_key = UnboundKey::new(&AES_256_GCM, &key)
        .map_err(|_| CryptoError::InvalidKeyLength(key.len() as u64))?;
    let less_safe_key = LessSafeKey::new(unbound_key);

    let nonce_bytes: [u8; 12] = ciphertext[..12]
        .try_into()
        .map_err(|_| CryptoError::InvalidCiphertext)?;
    let nonce = Nonce::assume_unique_for_key(nonce_bytes);

    let mut in_out = ciphertext[12..].to_vec();
    let decrypted = less_safe_key
        .open_in_place(nonce, Aad::empty(), &mut in_out)
        .map_err(|_| CryptoError::DecryptionFailed)?;

    Ok(decrypted.to_vec())
}

/// Derive a 32-byte key from password using Argon2id
#[uniffi::export]
pub fn derive_key(password: String, salt: Vec<u8>) -> Result<Vec<u8>, CryptoError> {
    if salt.len() < 8 {
        return Err(CryptoError::InvalidSaltLength(salt.len() as u64));
    }

    let mut output_key = [0u8; 32];
    Argon2::default()
        .hash_password_into(password.as_bytes(), &salt, &mut output_key)
        .map_err(|_| CryptoError::KeyDerivationFailed)?;
    Ok(output_key.to_vec())
}

/// Generate a random 16-byte salt for key derivation
#[uniffi::export]
pub fn generate_salt() -> Result<Vec<u8>, CryptoError> {
    let rng = SystemRandom::new();
    let mut salt = [0u8; 16];
    rng.fill(&mut salt)
        .map_err(|_| CryptoError::RandomGenerationFailed)?;
    Ok(salt.to_vec())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn encrypt_decrypt_roundtrip() {
        let key = vec![0u8; 32];
        let plaintext = b"Hello, Finneo!".to_vec();

        let ciphertext = encrypt(plaintext.clone(), key.clone()).unwrap();
        let decrypted = decrypt(ciphertext, key).unwrap();

        assert_eq!(plaintext, decrypted);
    }

    #[test]
    fn encrypt_produces_different_ciphertext() {
        let key = vec![0u8; 32];
        let plaintext = b"Same message".to_vec();

        let ct1 = encrypt(plaintext.clone(), key.clone()).unwrap();
        let ct2 = encrypt(plaintext, key).unwrap();

        assert_ne!(ct1, ct2);
    }

    #[test]
    fn decrypt_with_wrong_key_fails() {
        let key1 = vec![0u8; 32];
        let key2 = vec![1u8; 32];
        let plaintext = b"Secret".to_vec();

        let ciphertext = encrypt(plaintext, key1).unwrap();
        let result = decrypt(ciphertext, key2);

        assert!(matches!(result, Err(CryptoError::DecryptionFailed)));
    }

    #[test]
    fn invalid_key_length_rejected() {
        let short_key = vec![0u8; 16];
        let plaintext = b"Test".to_vec();

        let result = encrypt(plaintext, short_key);

        assert!(matches!(result, Err(CryptoError::InvalidKeyLength(16))));
    }

    #[test]
    fn derive_key_produces_32_bytes() {
        let salt = generate_salt().unwrap();
        let key = derive_key("password".to_string(), salt).unwrap();

        assert_eq!(key.len(), 32);
    }

    #[test]
    fn derive_key_deterministic() {
        let salt = vec![0u8; 16];
        let key1 = derive_key("password".to_string(), salt.clone()).unwrap();
        let key2 = derive_key("password".to_string(), salt).unwrap();

        assert_eq!(key1, key2);
    }

    #[test]
    fn derive_key_different_passwords() {
        let salt = vec![0u8; 16];
        let key1 = derive_key("password1".to_string(), salt.clone()).unwrap();
        let key2 = derive_key("password2".to_string(), salt).unwrap();

        assert_ne!(key1, key2);
    }

    #[test]
    fn short_salt_rejected() {
        let short_salt = vec![0u8; 4];
        let result = derive_key("password".to_string(), short_salt);

        assert!(matches!(result, Err(CryptoError::InvalidSaltLength(4))));
    }

    #[test]
    fn generate_salt_produces_16_bytes() {
        let salt = generate_salt().unwrap();

        assert_eq!(salt.len(), 16);
    }

    #[test]
    fn generate_salt_is_random() {
        let salt1 = generate_salt().unwrap();
        let salt2 = generate_salt().unwrap();

        assert_ne!(salt1, salt2);
    }
}
