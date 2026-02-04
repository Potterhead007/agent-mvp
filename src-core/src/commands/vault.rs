use crate::fs_utils::{atomic_write, atomic_write_secure};
use crate::security::audit;
use crate::state::AppState;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::path::Path;
use std::time::{SystemTime, UNIX_EPOCH};

use aes_gcm::aead::{Aead, KeyInit, OsRng};
use aes_gcm::{Aes256Gcm, Nonce};
use argon2::Argon2;
use rand::RngCore;

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct VaultEntry {
    pub key: String,
    pub provider: String,
    pub created_at: String,
    pub last_rotated: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct UnlockResult {
    pub success: bool,
    pub retry_after_ms: u64,
}

#[derive(Debug, Serialize, Deserialize)]
struct VaultLock {
    #[serde(default = "default_vault_version")]
    version: u8,
    hash: String,
    key_salt: String,
}

fn default_vault_version() -> u8 { 1 }

#[derive(Debug, Serialize, Deserialize)]
pub(crate) struct EncryptedBlob {
    pub nonce: String,
    pub ciphertext: String,
}

const MAX_FREE_ATTEMPTS: u32 = 3;
const MAX_BACKOFF_MS: u64 = 60_000;

fn now_millis() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis() as u64
}

fn required_delay_ms(failed_attempts: u32) -> u64 {
    if failed_attempts < MAX_FREE_ATTEMPTS {
        return 0;
    }
    let exponent = failed_attempts - MAX_FREE_ATTEMPTS;
    let delay = 2000u64.saturating_mul(1u64 << exponent.min(5));
    delay.min(MAX_BACKOFF_MS)
}

fn derive_encryption_key(password: &str, salt: &[u8]) -> Result<[u8; 32], String> {
    let mut key = [0u8; 32];
    Argon2::default()
        .hash_password_into(password.as_bytes(), salt, &mut key)
        .map_err(|e| format!("Key derivation failed: {}", e))?;
    Ok(key)
}

fn encrypt_data(key: &[u8; 32], plaintext: &[u8]) -> Result<EncryptedBlob, String> {
    let cipher = Aes256Gcm::new_from_slice(key)
        .map_err(|e| format!("Cipher init failed: {}", e))?;
    let mut nonce_bytes = [0u8; 12];
    OsRng.fill_bytes(&mut nonce_bytes);
    let nonce = Nonce::from_slice(&nonce_bytes);
    let ciphertext = cipher
        .encrypt(nonce, plaintext)
        .map_err(|e| format!("Encryption failed: {}", e))?;
    Ok(EncryptedBlob {
        nonce: hex::encode(nonce_bytes),
        ciphertext: hex::encode(ciphertext),
    })
}

pub(crate) fn decrypt_data(key: &[u8; 32], blob: &EncryptedBlob) -> Result<Vec<u8>, String> {
    let cipher = Aes256Gcm::new_from_slice(key)
        .map_err(|e| format!("Cipher init failed: {}", e))?;
    let nonce_bytes = hex::decode(&blob.nonce)
        .map_err(|e| format!("Invalid nonce hex: {}", e))?;
    if nonce_bytes.len() != 12 {
        return Err(format!("Invalid nonce length: {} (expected 12)", nonce_bytes.len()));
    }
    let ciphertext = hex::decode(&blob.ciphertext)
        .map_err(|e| format!("Invalid ciphertext hex: {}", e))?;
    let nonce = Nonce::from_slice(&nonce_bytes);
    cipher
        .decrypt(nonce, ciphertext.as_ref())
        .map_err(|_| "Decryption failed — wrong password or corrupted data".to_string())
}

pub(crate) mod hex {
    pub fn encode(bytes: impl AsRef<[u8]>) -> String {
        bytes.as_ref().iter().map(|b| format!("{:02x}", b)).collect()
    }
    pub fn decode(s: &str) -> Result<Vec<u8>, String> {
        if !s.len().is_multiple_of(2) {
            return Err("Odd-length hex string".to_string());
        }
        (0..s.len())
            .step_by(2)
            .map(|i| {
                u8::from_str_radix(&s[i..i + 2], 16)
                    .map_err(|e| format!("Invalid hex at {}: {}", i, e))
            })
            .collect()
    }
}

fn secrets_path(vault_dir: &str) -> String {
    format!("{}/vault_secrets.enc", vault_dir)
}

fn read_secrets(vault_dir: &str, key: &[u8; 32]) -> Result<HashMap<String, String>, String> {
    let path = secrets_path(vault_dir);
    match std::fs::read_to_string(&path) {
        Ok(content) => {
            let blob: EncryptedBlob = serde_json::from_str(&content)
                .map_err(|e| format!("Corrupt secrets file: {}", e))?;
            let plaintext = decrypt_data(key, &blob)?;
            let json = String::from_utf8(plaintext)
                .map_err(|_| "Decrypted data is not valid UTF-8".to_string())?;
            serde_json::from_str(&json).map_err(|e| format!("Invalid secrets JSON: {}", e))
        }
        Err(_) => Ok(HashMap::new()),
    }
}

fn write_secrets(vault_dir: &str, key: &[u8; 32], secrets: &HashMap<String, String>) -> Result<(), String> {
    let json = serde_json::to_string(secrets)
        .map_err(|e| format!("Failed to serialize secrets: {}", e))?;
    let blob = encrypt_data(key, json.as_bytes())?;
    let content = serde_json::to_string(&blob)
        .map_err(|e| format!("Failed to serialize blob: {}", e))?;
    atomic_write_secure(Path::new(&secrets_path(vault_dir)), &content)
        .map_err(|e| format!("Failed to write secrets: {}", e))
}

fn get_encryption_key(state: &AppState) -> Result<[u8; 32], String> {
    let vault = state.vault.lock().map_err(|_| "Vault lock poisoned")?;
    vault
        .encryption_key
        .ok_or_else(|| "Vault is locked — unlock first".to_string())
}

pub fn vault_list(state: &AppState) -> Result<Vec<VaultEntry>, String> {
    let vault_meta_path = format!("{}/vault_meta.json", state.vault_dir);
    match std::fs::read_to_string(&vault_meta_path) {
        Ok(content) => {
            let entries: Vec<VaultEntry> =
                serde_json::from_str(&content).unwrap_or_default();
            Ok(entries)
        }
        Err(_) => Ok(vec![]),
    }
}

pub fn vault_store_secret(
    state: &AppState,
    key: String,
    value: String,
) -> Result<(), String> {
    let enc_key = get_encryption_key(state)?;
    let mut secrets = read_secrets(&state.vault_dir, &enc_key)?;
    secrets.insert(key.clone(), value);
    write_secrets(&state.vault_dir, &enc_key, &secrets)?;
    audit::log_action(
        &state.audit_log_path,
        "VAULT_SECRET_STORE",
        &format!("Stored secret for key: {}", key),
    );
    Ok(())
}

pub fn vault_read_secret(
    state: &AppState,
    key: String,
) -> Result<Option<String>, String> {
    let enc_key = get_encryption_key(state)?;
    let secrets = read_secrets(&state.vault_dir, &enc_key)?;
    Ok(secrets.get(&key).cloned())
}

pub fn vault_unlock(
    state: &AppState,
    password: String,
) -> Result<UnlockResult, String> {
    let lock_path = format!("{}/vault.lock", state.vault_dir);

    // Rate limiting check
    {
        let vault = state.vault.lock().map_err(|_| "Vault lock poisoned")?;
        let delay = required_delay_ms(vault.failed_attempts);
        if delay > 0 {
            let elapsed = now_millis().saturating_sub(vault.last_failed_at);
            if elapsed < delay {
                return Ok(UnlockResult {
                    success: false,
                    retry_after_ms: delay - elapsed,
                });
            }
        }
    }

    if !Path::new(&lock_path).exists() {
        // First time — create vault
        let password_hash = argon2::password_hash::PasswordHasher::hash_password(
            &Argon2::default(),
            password.as_bytes(),
            argon2::password_hash::SaltString::generate(&mut OsRng).as_salt(),
        )
        .map_err(|e| format!("Hash failed: {}", e))?
        .to_string();

        let mut key_salt = [0u8; 32];
        OsRng.fill_bytes(&mut key_salt);

        let lock = VaultLock {
            version: 2,
            hash: password_hash,
            key_salt: hex::encode(key_salt),
        };
        let content = serde_json::to_string_pretty(&lock)
            .map_err(|e| format!("Failed to serialize lock: {}", e))?;
        atomic_write_secure(Path::new(&lock_path), &content)?;

        // Derive encryption key and store in runtime
        let enc_key = derive_encryption_key(&password, &key_salt)?;
        {
            let mut vault = state.vault.lock().map_err(|_| "Vault lock poisoned")?;
            vault.encryption_key = Some(enc_key);
            vault.failed_attempts = 0;
        }

        // Migrate plaintext secrets if they exist
        migrate_plaintext_secrets(state, &enc_key);

        audit::log_action(&state.audit_log_path, "VAULT_CREATED", "New vault initialized with Argon2id + AES-256-GCM");
        return Ok(UnlockResult { success: true, retry_after_ms: 0 });
    }

    // Existing vault — read lock file
    let lock_content = std::fs::read_to_string(&lock_path)
        .map_err(|e| format!("Failed to read vault lock: {}", e))?;

    // Support both new (JSON) and legacy (hex hash) formats
    if let Ok(lock) = serde_json::from_str::<VaultLock>(&lock_content) {
        // New format — Argon2id verification
        let parsed_hash = argon2::password_hash::PasswordHash::new(&lock.hash)
            .map_err(|e| format!("Corrupt password hash: {}", e))?;
        let valid = argon2::password_hash::PasswordVerifier::verify_password(
            &Argon2::default(),
            password.as_bytes(),
            &parsed_hash,
        )
        .is_ok();

        if valid {
            let key_salt = hex::decode(&lock.key_salt)
                .map_err(|e| format!("Corrupt key salt: {}", e))?;
            let enc_key = derive_encryption_key(&password, &key_salt)?;
            let mut vault = state.vault.lock().map_err(|_| "Vault lock poisoned")?;
            vault.encryption_key = Some(enc_key);
            vault.failed_attempts = 0;
            audit::log_action(&state.audit_log_path, "VAULT_UNLOCK", "Vault unlocked");
            Ok(UnlockResult { success: true, retry_after_ms: 0 })
        } else {
            let mut vault = state.vault.lock().map_err(|_| "Vault lock poisoned")?;
            vault.failed_attempts += 1;
            vault.last_failed_at = now_millis();
            let next_delay = required_delay_ms(vault.failed_attempts);
            audit::log_action(&state.audit_log_path, "VAULT_UNLOCK_FAIL", "Invalid master password");
            Ok(UnlockResult { success: false, retry_after_ms: next_delay })
        }
    } else {
        // Legacy format — SHA-256 hex hash. Verify with old method, then upgrade.
        #[allow(deprecated)]
        let valid = legacy_verify(&password, &lock_content);
        if valid {
            // Upgrade to Argon2id
            let password_hash = argon2::password_hash::PasswordHasher::hash_password(
                &Argon2::default(),
                password.as_bytes(),
                argon2::password_hash::SaltString::generate(&mut OsRng).as_salt(),
            )
            .map_err(|e| format!("Hash upgrade failed: {}", e))?
            .to_string();

            let mut key_salt = [0u8; 32];
            OsRng.fill_bytes(&mut key_salt);

            let lock = VaultLock {
                version: 2,
                hash: password_hash,
                key_salt: hex::encode(key_salt),
            };
            let content = serde_json::to_string_pretty(&lock)
                .map_err(|e| format!("Failed to serialize lock: {}", e))?;
            atomic_write_secure(Path::new(&lock_path), &content)?;

            let enc_key = derive_encryption_key(&password, &key_salt)?;

            // Migrate plaintext secrets
            migrate_plaintext_secrets(state, &enc_key);

            let mut vault = state.vault.lock().map_err(|_| "Vault lock poisoned")?;
            vault.encryption_key = Some(enc_key);
            vault.failed_attempts = 0;
            audit::log_action(&state.audit_log_path, "VAULT_UPGRADED", "Migrated from SHA-256 to Argon2id + AES-256-GCM");
            Ok(UnlockResult { success: true, retry_after_ms: 0 })
        } else {
            let mut vault = state.vault.lock().map_err(|_| "Vault lock poisoned")?;
            vault.failed_attempts += 1;
            vault.last_failed_at = now_millis();
            let next_delay = required_delay_ms(vault.failed_attempts);
            audit::log_action(&state.audit_log_path, "VAULT_UNLOCK_FAIL", "Invalid master password");
            Ok(UnlockResult { success: false, retry_after_ms: next_delay })
        }
    }
}

pub fn vault_lock(state: &AppState) -> Result<(), String> {
    let mut vault = state.vault.lock().map_err(|_| "Vault lock poisoned")?;
    vault.encryption_key = None;
    audit::log_action(&state.audit_log_path, "VAULT_LOCK", "Vault locked");
    Ok(())
}

pub fn vault_exists(state: &AppState) -> bool {
    let lock_path = format!("{}/vault.lock", state.vault_dir);
    Path::new(&lock_path).exists()
}

pub fn vault_store_meta(
    state: &AppState,
    entry: VaultEntry,
) -> Result<(), String> {
    let vault_meta_path = format!("{}/vault_meta.json", state.vault_dir);
    let mut entries: Vec<VaultEntry> = match std::fs::read_to_string(&vault_meta_path) {
        Ok(content) => serde_json::from_str(&content).unwrap_or_default(),
        Err(_) => vec![],
    };

    let key_for_log = entry.key.clone();
    if let Some(existing) = entries.iter_mut().find(|e| e.key == entry.key) {
        *existing = entry;
    } else {
        entries.push(entry);
    }

    let content = serde_json::to_string_pretty(&entries)
        .map_err(|e| format!("Failed to serialize: {}", e))?;
    atomic_write(Path::new(&vault_meta_path), &content)
        .map_err(|e| format!("Failed to write vault meta: {}", e))?;

    audit::log_action(
        &state.audit_log_path,
        "VAULT_STORE",
        &format!("Stored credential: {}", key_for_log),
    );
    Ok(())
}

pub fn vault_remove(state: &AppState, key: String) -> Result<(), String> {
    // Remove from metadata
    let vault_meta_path = format!("{}/vault_meta.json", state.vault_dir);
    let mut entries: Vec<VaultEntry> = match std::fs::read_to_string(&vault_meta_path) {
        Ok(content) => serde_json::from_str(&content).unwrap_or_default(),
        Err(_) => vec![],
    };
    entries.retain(|e| e.key != key);
    let content = serde_json::to_string_pretty(&entries)
        .map_err(|e| format!("Failed to serialize: {}", e))?;
    atomic_write(Path::new(&vault_meta_path), &content)
        .map_err(|e| format!("Failed to write vault meta: {}", e))?;

    // Remove from encrypted secrets
    let enc_key = get_encryption_key(state)?;
    let mut secrets = read_secrets(&state.vault_dir, &enc_key)?;
    secrets.remove(&key);
    write_secrets(&state.vault_dir, &enc_key, &secrets)?;

    audit::log_action(
        &state.audit_log_path,
        "VAULT_REMOVE",
        &format!("Removed credential: {}", key),
    );
    Ok(())
}

fn migrate_plaintext_secrets(state: &AppState, enc_key: &[u8; 32]) {
    let plaintext_path = format!("{}/vault_secrets.json", state.vault_dir);
    if let Ok(content) = std::fs::read_to_string(&plaintext_path) {
        if let Ok(secrets) = serde_json::from_str::<HashMap<String, String>>(&content) {
            if !secrets.is_empty() {
                if write_secrets(&state.vault_dir, enc_key, &secrets).is_ok() {
                    let _ = std::fs::remove_file(&plaintext_path);
                    audit::log_action(
                        &state.audit_log_path,
                        "VAULT_MIGRATE",
                        "Migrated plaintext secrets to encrypted storage",
                    );
                }
            } else {
                let _ = std::fs::remove_file(&plaintext_path);
            }
        }
    }
}

#[deprecated(note = "Only for pre-Argon2id vaults")]
fn legacy_verify(password: &str, stored_hash: &str) -> bool {
    use sha2::{Sha256, Digest};
    let salt = b"openclaw-vault-lock-2025";
    let mut hasher = Sha256::new();
    hasher.update(salt);
    hasher.update(password.as_bytes());
    let result = hasher.finalize();
    let computed: String = result.iter().map(|b| format!("{:02x}", b)).collect();
    let expected = stored_hash.trim();
    let computed_bytes = computed.as_bytes();
    let expected_bytes = expected.as_bytes();
    if computed_bytes.len() != expected_bytes.len() {
        return false;
    }
    let mut diff: u8 = 0;
    for (a, b) in computed_bytes.iter().zip(expected_bytes.iter()) {
        diff |= a ^ b;
    }
    diff == 0
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn hex_roundtrip() {
        let data = [0u8, 1, 127, 255, 16, 32];
        let encoded = hex::encode(data);
        let decoded = hex::decode(&encoded).unwrap();
        assert_eq!(&data[..], &decoded[..]);
    }

    #[test]
    fn encrypt_decrypt_roundtrip() {
        let key = [42u8; 32];
        let plaintext = b"secret api key value";
        let blob = encrypt_data(&key, plaintext).unwrap();
        let decrypted = decrypt_data(&key, &blob).unwrap();
        assert_eq!(&decrypted, plaintext);
    }

    #[test]
    fn decrypt_with_wrong_key_fails() {
        let key = [42u8; 32];
        let wrong_key = [99u8; 32];
        let blob = encrypt_data(&key, b"secret").unwrap();
        assert!(decrypt_data(&wrong_key, &blob).is_err());
    }

    #[test]
    fn rate_limiting_free_attempts() {
        assert_eq!(required_delay_ms(0), 0);
        assert_eq!(required_delay_ms(1), 0);
        assert_eq!(required_delay_ms(2), 0);
    }

    #[test]
    fn rate_limiting_exponential_backoff() {
        assert_eq!(required_delay_ms(3), 2000);
        assert_eq!(required_delay_ms(4), 4000);
        assert_eq!(required_delay_ms(5), 8000);
        assert_eq!(required_delay_ms(6), 16000);
        assert_eq!(required_delay_ms(7), 32000);
        assert_eq!(required_delay_ms(8), 60000); // capped
        assert_eq!(required_delay_ms(20), 60000); // still capped
    }

    #[test]
    fn vault_lock_version_defaults_to_1() {
        let json = r#"{"hash": "abc", "key_salt": "def"}"#;
        let lock: VaultLock = serde_json::from_str(json).unwrap();
        assert_eq!(lock.version, 1);
    }

    #[test]
    fn vault_lock_version_2_deserializes() {
        let json = r#"{"version": 2, "hash": "abc", "key_salt": "def"}"#;
        let lock: VaultLock = serde_json::from_str(json).unwrap();
        assert_eq!(lock.version, 2);
    }

    #[test]
    #[allow(deprecated)]
    fn legacy_verify_works() {
        let password = "test123";
        // Compute expected hash with old method
        use sha2::{Sha256, Digest};
        let salt = b"openclaw-vault-lock-2025";
        let mut hasher = Sha256::new();
        hasher.update(salt);
        hasher.update(password.as_bytes());
        let result = hasher.finalize();
        let hash: String = result.iter().map(|b| format!("{:02x}", b)).collect();

        assert!(legacy_verify(password, &hash));
        assert!(!legacy_verify("wrong", &hash));
    }

    #[test]
    fn derive_key_deterministic() {
        let salt = [1u8; 32];
        let key1 = derive_encryption_key("password", &salt).unwrap();
        let key2 = derive_encryption_key("password", &salt).unwrap();
        assert_eq!(key1, key2);
    }

    #[test]
    fn derive_key_different_passwords() {
        let salt = [1u8; 32];
        let key1 = derive_encryption_key("password1", &salt).unwrap();
        let key2 = derive_encryption_key("password2", &salt).unwrap();
        assert_ne!(key1, key2);
    }

    #[test]
    fn write_secrets_roundtrip() {
        let tmp = tempfile::tempdir().unwrap();
        let vault_dir = tmp.path().to_str().unwrap();
        let key = [42u8; 32];
        let mut secrets = HashMap::new();
        secrets.insert("API_KEY".to_string(), "sk-test-123".to_string());
        secrets.insert("TOKEN".to_string(), "tok-abc".to_string());

        write_secrets(vault_dir, &key, &secrets).unwrap();
        let loaded = read_secrets(vault_dir, &key).unwrap();

        assert_eq!(loaded.len(), 2);
        assert_eq!(loaded["API_KEY"], "sk-test-123");
        assert_eq!(loaded["TOKEN"], "tok-abc");
    }

    #[test]
    fn read_secrets_returns_empty_when_no_file() {
        let tmp = tempfile::tempdir().unwrap();
        let vault_dir = tmp.path().to_str().unwrap();
        let key = [42u8; 32];
        let secrets = read_secrets(vault_dir, &key).unwrap();
        assert!(secrets.is_empty());
    }

    #[test]
    fn read_secrets_fails_with_wrong_key() {
        let tmp = tempfile::tempdir().unwrap();
        let vault_dir = tmp.path().to_str().unwrap();
        let key = [42u8; 32];
        let wrong_key = [99u8; 32];
        let mut secrets = HashMap::new();
        secrets.insert("KEY".to_string(), "val".to_string());

        write_secrets(vault_dir, &key, &secrets).unwrap();
        let result = read_secrets(vault_dir, &wrong_key);
        assert!(result.is_err());
    }

    #[test]
    fn hex_decode_empty_string() {
        let result = hex::decode("").unwrap();
        assert!(result.is_empty());
    }

    #[test]
    fn hex_decode_odd_length_fails() {
        let result = hex::decode("abc");
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("Odd-length"));
    }

    #[test]
    fn hex_decode_invalid_chars_fails() {
        let result = hex::decode("zzzz");
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("Invalid hex"));
    }

    #[test]
    fn hex_encode_empty_slice() {
        assert_eq!(hex::encode(&[] as &[u8]), "");
    }

    #[test]
    fn encrypt_decrypt_empty_data() {
        let key = [42u8; 32];
        let blob = encrypt_data(&key, b"").unwrap();
        let decrypted = decrypt_data(&key, &blob).unwrap();
        assert!(decrypted.is_empty());
    }

    #[test]
    fn encrypt_decrypt_large_data() {
        let key = [42u8; 32];
        let data = vec![0xABu8; 1_000_000]; // 1 MB
        let blob = encrypt_data(&key, &data).unwrap();
        let decrypted = decrypt_data(&key, &blob).unwrap();
        assert_eq!(decrypted, data);
    }

    #[test]
    fn decrypt_corrupt_nonce_fails() {
        let key = [42u8; 32];
        let blob = EncryptedBlob {
            nonce: "not_valid_hex!".to_string(),
            ciphertext: "aabb".to_string(),
        };
        assert!(decrypt_data(&key, &blob).is_err());
    }

    #[test]
    fn decrypt_corrupt_ciphertext_fails() {
        let key = [42u8; 32];
        let blob = encrypt_data(&key, b"test").unwrap();
        let corrupt = EncryptedBlob {
            nonce: blob.nonce,
            ciphertext: "00".repeat(blob.ciphertext.len() / 2),
        };
        assert!(decrypt_data(&key, &corrupt).is_err());
    }

    #[test]
    fn decrypt_wrong_nonce_length_fails() {
        let key = [42u8; 32];
        let blob = EncryptedBlob {
            nonce: "aabbccdd".to_string(), // 4 bytes, not 12
            ciphertext: "aabb".to_string(),
        };
        let result = decrypt_data(&key, &blob);
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("Invalid nonce length"));
    }

    #[test]
    fn decrypt_wrong_length_ciphertext_fails() {
        let key = [42u8; 32];
        // Valid 12-byte nonce (24 hex chars) but empty ciphertext
        let blob = EncryptedBlob {
            nonce: "000000000000000000000000".to_string(),
            ciphertext: "".to_string(),
        };
        assert!(decrypt_data(&key, &blob).is_err());
    }

    #[test]
    fn encrypt_produces_different_nonces() {
        let key = [42u8; 32];
        let blob1 = encrypt_data(&key, b"same data").unwrap();
        let blob2 = encrypt_data(&key, b"same data").unwrap();
        // Random nonces should differ
        assert_ne!(blob1.nonce, blob2.nonce);
        // And ciphertexts should differ due to different nonces
        assert_ne!(blob1.ciphertext, blob2.ciphertext);
    }

    #[test]
    fn derive_key_different_salts() {
        let salt1 = [1u8; 32];
        let salt2 = [2u8; 32];
        let key1 = derive_encryption_key("same_password", &salt1).unwrap();
        let key2 = derive_encryption_key("same_password", &salt2).unwrap();
        assert_ne!(key1, key2);
    }

    #[test]
    fn derive_key_empty_password() {
        let salt = [1u8; 32];
        // Empty password should still work (Argon2 accepts it)
        let key = derive_encryption_key("", &salt).unwrap();
        assert_ne!(key, [0u8; 32]); // should produce non-zero key
    }

    #[test]
    fn rate_limiting_at_boundary() {
        // Exactly at MAX_FREE_ATTEMPTS (3) should start backoff
        assert_eq!(required_delay_ms(MAX_FREE_ATTEMPTS), 2000);
        // One below should be free
        assert_eq!(required_delay_ms(MAX_FREE_ATTEMPTS - 1), 0);
    }

    #[test]
    fn rate_limiting_very_large_attempts() {
        // Should not overflow, stays capped at MAX_BACKOFF_MS
        assert_eq!(required_delay_ms(u32::MAX), MAX_BACKOFF_MS);
        assert_eq!(required_delay_ms(1000), MAX_BACKOFF_MS);
    }

    #[test]
    fn write_secrets_empty_map() {
        let tmp = tempfile::tempdir().unwrap();
        let vault_dir = tmp.path().to_str().unwrap();
        let key = [42u8; 32];
        let secrets = HashMap::new();

        write_secrets(vault_dir, &key, &secrets).unwrap();
        let loaded = read_secrets(vault_dir, &key).unwrap();
        assert!(loaded.is_empty());
    }

    #[test]
    fn write_secrets_overwrites_existing() {
        let tmp = tempfile::tempdir().unwrap();
        let vault_dir = tmp.path().to_str().unwrap();
        let key = [42u8; 32];

        let mut secrets1 = HashMap::new();
        secrets1.insert("A".to_string(), "1".to_string());
        write_secrets(vault_dir, &key, &secrets1).unwrap();

        let mut secrets2 = HashMap::new();
        secrets2.insert("B".to_string(), "2".to_string());
        write_secrets(vault_dir, &key, &secrets2).unwrap();

        let loaded = read_secrets(vault_dir, &key).unwrap();
        assert_eq!(loaded.len(), 1);
        assert_eq!(loaded["B"], "2");
        assert!(!loaded.contains_key("A"));
    }

    #[test]
    fn read_secrets_corrupt_json_fails() {
        let tmp = tempfile::tempdir().unwrap();
        let path = tmp.path().join("vault_secrets.enc");
        std::fs::write(&path, "not json at all").unwrap();
        let key = [42u8; 32];
        let result = read_secrets(tmp.path().to_str().unwrap(), &key);
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("Corrupt"));
    }

    fn make_vault_state(tmp: &std::path::Path) -> AppState {
        let vault_dir = tmp.join("vault");
        let _ = std::fs::create_dir_all(&vault_dir);
        let audit_path = tmp.join("audit.log");
        let _ = std::fs::write(&audit_path, "");
        AppState {
            openclaw_dir: tmp.to_str().unwrap().to_string(),
            vault_dir: vault_dir.to_str().unwrap().to_string(),
            audit_log_path: audit_path.to_str().unwrap().to_string(),
            vault: std::sync::Mutex::new(crate::state::VaultRuntime::default()),
        }
    }

    #[test]
    fn vault_unlock_creates_new_vault() {
        let tmp = tempfile::tempdir().unwrap();
        let state = make_vault_state(tmp.path());

        let result = vault_unlock(&state, "master123".to_string()).unwrap();
        assert!(result.success);
        assert_eq!(result.retry_after_ms, 0);

        // vault.lock should exist
        let lock_path = tmp.path().join("vault/vault.lock");
        assert!(lock_path.exists());

        // Lock file should be valid JSON with version 2
        let content = std::fs::read_to_string(&lock_path).unwrap();
        let lock: serde_json::Value = serde_json::from_str(&content).unwrap();
        assert_eq!(lock["version"], 2);
        assert!(lock["hash"].as_str().unwrap().starts_with("$argon2"));
    }

    #[test]
    fn vault_unlock_then_lock_clears_key() {
        let tmp = tempfile::tempdir().unwrap();
        let state = make_vault_state(tmp.path());

        vault_unlock(&state, "master123".to_string()).unwrap();
        // Key should be set
        {
            let vault = state.vault.lock().unwrap();
            assert!(vault.encryption_key.is_some());
        }

        vault_lock(&state).unwrap();
        // Key should be cleared
        {
            let vault = state.vault.lock().unwrap();
            assert!(vault.encryption_key.is_none());
        }
    }

    #[test]
    fn vault_unlock_wrong_password_fails() {
        let tmp = tempfile::tempdir().unwrap();
        let state = make_vault_state(tmp.path());

        // Create vault
        vault_unlock(&state, "correct".to_string()).unwrap();
        vault_lock(&state).unwrap();

        // Try wrong password
        let result = vault_unlock(&state, "wrong".to_string()).unwrap();
        assert!(!result.success);

        // Failed attempts should increment
        let vault = state.vault.lock().unwrap();
        assert_eq!(vault.failed_attempts, 1);
    }

    #[test]
    fn vault_unlock_correct_password_resets_failures() {
        let tmp = tempfile::tempdir().unwrap();
        let state = make_vault_state(tmp.path());

        // Create vault
        vault_unlock(&state, "correct".to_string()).unwrap();
        vault_lock(&state).unwrap();

        // Fail once
        vault_unlock(&state, "wrong".to_string()).unwrap();

        // Succeed
        let result = vault_unlock(&state, "correct".to_string()).unwrap();
        assert!(result.success);

        let vault = state.vault.lock().unwrap();
        assert_eq!(vault.failed_attempts, 0);
    }

    #[test]
    fn vault_store_and_read_secret() {
        let tmp = tempfile::tempdir().unwrap();
        let state = make_vault_state(tmp.path());

        vault_unlock(&state, "password".to_string()).unwrap();

        vault_store_secret(&state, "API_KEY".to_string(), "sk-test-123".to_string()).unwrap();

        let value = vault_read_secret(&state, "API_KEY".to_string()).unwrap();
        assert_eq!(value, Some("sk-test-123".to_string()));

        // Non-existent key
        let missing = vault_read_secret(&state, "NOPE".to_string()).unwrap();
        assert_eq!(missing, None);
    }

    #[test]
    fn vault_store_read_requires_unlock() {
        let tmp = tempfile::tempdir().unwrap();
        let state = make_vault_state(tmp.path());

        // Without unlocking
        let err = vault_store_secret(&state, "K".to_string(), "V".to_string());
        assert!(err.is_err());
        assert!(err.unwrap_err().contains("locked"));

        let err = vault_read_secret(&state, "K".to_string());
        assert!(err.is_err());
        assert!(err.unwrap_err().contains("locked"));
    }

    #[test]
    fn vault_remove_secret() {
        let tmp = tempfile::tempdir().unwrap();
        let state = make_vault_state(tmp.path());

        vault_unlock(&state, "password".to_string()).unwrap();

        vault_store_secret(&state, "DELETE_ME".to_string(), "val".to_string()).unwrap();
        vault_store_secret(&state, "KEEP_ME".to_string(), "val2".to_string()).unwrap();

        vault_remove(&state, "DELETE_ME".to_string()).unwrap();

        let deleted = vault_read_secret(&state, "DELETE_ME".to_string()).unwrap();
        assert_eq!(deleted, None);

        let kept = vault_read_secret(&state, "KEEP_ME".to_string()).unwrap();
        assert_eq!(kept, Some("val2".to_string()));
    }

    #[test]
    fn vault_store_meta_and_list() {
        let tmp = tempfile::tempdir().unwrap();
        let state = make_vault_state(tmp.path());

        vault_store_meta(&state, VaultEntry {
            key: "api-key".to_string(),
            provider: "openai".to_string(),
            created_at: "2024-01-01".to_string(),
            last_rotated: None,
        }).unwrap();

        vault_store_meta(&state, VaultEntry {
            key: "token".to_string(),
            provider: "anthropic".to_string(),
            created_at: "2024-01-02".to_string(),
            last_rotated: Some("2024-06-01".to_string()),
        }).unwrap();

        let entries = vault_list(&state).unwrap();
        assert_eq!(entries.len(), 2);
        assert_eq!(entries[0].key, "api-key");
        assert_eq!(entries[1].provider, "anthropic");
    }

    #[test]
    fn vault_store_meta_updates_existing() {
        let tmp = tempfile::tempdir().unwrap();
        let state = make_vault_state(tmp.path());

        vault_store_meta(&state, VaultEntry {
            key: "api-key".to_string(),
            provider: "openai".to_string(),
            created_at: "2024-01-01".to_string(),
            last_rotated: None,
        }).unwrap();

        // Update same key
        vault_store_meta(&state, VaultEntry {
            key: "api-key".to_string(),
            provider: "anthropic".to_string(),
            created_at: "2024-01-01".to_string(),
            last_rotated: Some("2024-06-01".to_string()),
        }).unwrap();

        let entries = vault_list(&state).unwrap();
        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0].provider, "anthropic");
    }

    #[test]
    fn vault_list_returns_empty_when_no_file() {
        let tmp = tempfile::tempdir().unwrap();
        let state = make_vault_state(tmp.path());
        let entries = vault_list(&state).unwrap();
        assert!(entries.is_empty());
    }

    #[test]
    fn vault_exists_reflects_lock_file() {
        let tmp = tempfile::tempdir().unwrap();
        let state = make_vault_state(tmp.path());

        assert!(!vault_exists(&state));

        vault_unlock(&state, "pw".to_string()).unwrap();
        assert!(vault_exists(&state));
    }

    #[test]
    fn vault_secrets_persist_across_lock_unlock() {
        let tmp = tempfile::tempdir().unwrap();
        let state = make_vault_state(tmp.path());

        vault_unlock(&state, "password".to_string()).unwrap();
        vault_store_secret(&state, "KEY".to_string(), "persistent_value".to_string()).unwrap();
        vault_lock(&state).unwrap();

        // Re-unlock with same password
        vault_unlock(&state, "password".to_string()).unwrap();
        let val = vault_read_secret(&state, "KEY".to_string()).unwrap();
        assert_eq!(val, Some("persistent_value".to_string()));
    }

    #[test]
    fn vault_migrate_plaintext_secrets() {
        let tmp = tempfile::tempdir().unwrap();
        let state = make_vault_state(tmp.path());

        // Place a plaintext secrets file
        let plaintext_path = tmp.path().join("vault/vault_secrets.json");
        std::fs::write(&plaintext_path, r#"{"LEGACY_KEY": "legacy_value"}"#).unwrap();

        vault_unlock(&state, "password".to_string()).unwrap();

        // Plaintext file should be deleted after migration
        assert!(!plaintext_path.exists());

        // Secret should be readable from encrypted store
        let val = vault_read_secret(&state, "LEGACY_KEY".to_string()).unwrap();
        assert_eq!(val, Some("legacy_value".to_string()));
    }

    #[test]
    #[allow(deprecated)]
    fn vault_unlock_upgrades_legacy_hash() {
        let tmp = tempfile::tempdir().unwrap();
        let state = make_vault_state(tmp.path());

        // Create a legacy vault.lock with SHA-256 hash
        use sha2::{Sha256, Digest};
        let salt = b"openclaw-vault-lock-2025";
        let mut hasher = Sha256::new();
        hasher.update(salt);
        hasher.update(b"legacy_password");
        let result = hasher.finalize();
        let hash: String = result.iter().map(|b| format!("{:02x}", b)).collect();

        let lock_path = tmp.path().join("vault/vault.lock");
        std::fs::write(&lock_path, &hash).unwrap();

        // Unlock should work with legacy password
        let result = vault_unlock(&state, "legacy_password".to_string()).unwrap();
        assert!(result.success);

        // Lock file should now be upgraded to JSON format
        let content = std::fs::read_to_string(&lock_path).unwrap();
        let lock: serde_json::Value = serde_json::from_str(&content).unwrap();
        assert_eq!(lock["version"], 2);
        assert!(lock["hash"].as_str().unwrap().starts_with("$argon2"));
    }

    #[test]
    #[allow(deprecated)]
    fn vault_unlock_legacy_wrong_password_fails() {
        let tmp = tempfile::tempdir().unwrap();
        let state = make_vault_state(tmp.path());

        use sha2::{Sha256, Digest};
        let salt = b"openclaw-vault-lock-2025";
        let mut hasher = Sha256::new();
        hasher.update(salt);
        hasher.update(b"correct_pw");
        let result = hasher.finalize();
        let hash: String = result.iter().map(|b| format!("{:02x}", b)).collect();

        let lock_path = tmp.path().join("vault/vault.lock");
        std::fs::write(&lock_path, &hash).unwrap();

        let result = vault_unlock(&state, "wrong_pw".to_string()).unwrap();
        assert!(!result.success);
    }

    #[test]
    fn vault_remove_from_meta_and_secrets() {
        let tmp = tempfile::tempdir().unwrap();
        let state = make_vault_state(tmp.path());

        vault_unlock(&state, "pw".to_string()).unwrap();

        // Store both meta and secret
        vault_store_meta(&state, VaultEntry {
            key: "api-key".to_string(),
            provider: "openai".to_string(),
            created_at: "2024-01-01".to_string(),
            last_rotated: None,
        }).unwrap();
        vault_store_secret(&state, "api-key".to_string(), "sk-123".to_string()).unwrap();

        vault_remove(&state, "api-key".to_string()).unwrap();

        // Both meta and secret should be gone
        let entries = vault_list(&state).unwrap();
        assert!(entries.is_empty());
        let val = vault_read_secret(&state, "api-key".to_string()).unwrap();
        assert_eq!(val, None);
    }

    #[test]
    fn vault_remove_requires_unlock() {
        let tmp = tempfile::tempdir().unwrap();
        let state = make_vault_state(tmp.path());
        let err = vault_remove(&state, "key".to_string());
        assert!(err.is_err());
        assert!(err.unwrap_err().contains("locked"));
    }
}
