use ring::aead::{Aad, LessSafeKey, Nonce, UnboundKey, AES_256_GCM};
use ring::rand::{SecureRandom, SystemRandom};
use argon2::Argon2;

pub fn encrypt(plaintext: &[u8], key: &[u8]) -> Result<Vec<u8>, String> {
    if key.len() != 32 {
        return Err(format!("Invalid key length: expected 32 bytes, got {}", key.len()));
    }

    let unbound_key = UnboundKey::new(&AES_256_GCM, key)
        .map_err(|_| "Failed to create key".to_string())?;
    let less_safe_key = LessSafeKey::new(unbound_key);

    let rng = SystemRandom::new();
    let mut nonce_bytes = [0u8; 12];
    rng.fill(&mut nonce_bytes)
        .map_err(|_| "Failed to generate nonce".to_string())?;
    let nonce = Nonce::assume_unique_for_key(nonce_bytes);

    let mut in_out = plaintext.to_vec();
    less_safe_key
        .seal_in_place_append_tag(nonce, Aad::empty(), &mut in_out)
        .map_err(|_| "Encryption failed".to_string())?;

    let mut result = nonce_bytes.to_vec();
    result.extend(in_out);
    Ok(result)
}

pub fn decrypt(ciphertext: &[u8], key: &[u8]) -> Result<Vec<u8>, String> {
    if key.len() != 32 {
        return Err(format!("Invalid key length: expected 32 bytes, got {}", key.len()));
    }
    if ciphertext.len() < 12 {
        return Err("Invalid ciphertext".to_string());
    }

    let unbound_key = UnboundKey::new(&AES_256_GCM, key)
        .map_err(|_| "Failed to create key".to_string())?;
    let less_safe_key = LessSafeKey::new(unbound_key);

    let nonce_bytes: [u8; 12] = ciphertext[..12]
        .try_into()
        .map_err(|_| "Invalid nonce".to_string())?;
    let nonce = Nonce::assume_unique_for_key(nonce_bytes);

    let mut in_out = ciphertext[12..].to_vec();
    less_safe_key
        .open_in_place(nonce, Aad::empty(), &mut in_out)
        .map_err(|_| "Decryption failed".to_string())?;

    Ok(in_out)
}

pub fn derive_key(password: &str, salt: &[u8]) -> Result<Vec<u8>, String> {
    let mut output_key = [0u8; 32];
    Argon2::default()
        .hash_password_into(password.as_bytes(), salt, &mut output_key)
        .map_err(|_| "Key derivation failed".to_string())?;
    Ok(output_key.to_vec())
}

pub fn generate_salt() -> Result<Vec<u8>, String> {
    let rng = SystemRandom::new();
    let mut salt = [0u8; 16];
    rng.fill(&mut salt)
        .map_err(|_| "Failed to generate salt".to_string())?;
    Ok(salt.to_vec())
}
