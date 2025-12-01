# Finneo-Crypto

Cross-platform encryption library using AES-256-GCM and Argon2id key derivation.

## Features

- AES-256-GCM authenticated encryption
- Argon2id password-based key derivation
- Secure random salt generation
- Cross-platform support via UniFFI (Kotlin/Swift bindings)

## Installation

```toml
[dependencies]
finneo_crypto = "0.1"
```

## Usage

```rust
use finneo_crypto::{encrypt, decrypt, derive_key, generate_salt};

// Generate a key from password
let salt = generate_salt().unwrap();
let key = derive_key("my-password".to_string(), salt).unwrap();

// Encrypt
let plaintext = b"Hello, World!".to_vec();
let ciphertext = encrypt(plaintext, key.clone()).unwrap();

// Decrypt
let decrypted = decrypt(ciphertext, key).unwrap();
assert_eq!(decrypted, b"Hello, World!");
```

## Kotlin (Android/JVM)

Generate Kotlin bindings:

```bash
cargo build --release
cargo run --bin uniffi-bindgen generate \
    --library target/release/libfinneo_crypto.dylib \
    --language kotlin \
    --out-dir bindings/kotlin
```

```kotlin
import uniffi.finneo_crypto.*

val salt = generateSalt()
val key = deriveKey("my-password", salt)

val ciphertext = encrypt("Hello".toByteArray(), key)
val plaintext = decrypt(ciphertext, key)
```

## Security

- Uses `ring` for cryptographic primitives
- 12-byte random nonce per encryption (prepended to ciphertext)
- 16-byte authentication tag (AES-GCM)
- Argon2id with default parameters for key derivation

## License

MIT License - see [LICENSE](LICENSE) for details.
