use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine;
use ed25519_dalek::{SigningKey, Signer};
use serde::{Deserialize, Serialize};
use std::fs;

use crate::state::AppState;
#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "camelCase")]
struct DeviceIdentityFile {
    #[allow(dead_code)]
    version: u32,
    device_id: String,
    public_key_pem: String,
    private_key_pem: String,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct DeviceAuth {
    pub id: String,
    pub public_key: String,
    pub signature: String,
    pub signed_at: u64,
    pub nonce: Option<String>,
}
fn pem_to_der(pem: &str) -> Result<Vec<u8>, String> {
    let b64: String = pem
        .lines()
        .filter(|l| !l.starts_with("-----"))
        .collect::<Vec<_>>()
        .join("");
    base64::engine::general_purpose::STANDARD
        .decode(&b64)
        .map_err(|e| format!("Failed to decode PEM base64: {}", e))
}

fn parse_ed25519_private_key(pem: &str) -> Result<SigningKey, String> {
    let der = pem_to_der(pem)?;
    // PKCS8 Ed25519 DER: 16-byte header + 32-byte seed = 48 bytes
    if der.len() == 48 {
        let seed: [u8; 32] = der[16..48]
            .try_into()
            .map_err(|_| "Invalid key length".to_string())?;
        return Ok(SigningKey::from_bytes(&seed));
    }
    Err(format!("Unexpected PKCS8 DER length: {} (expected 48)", der.len()))
}

pub fn public_key_raw_base64url(pem: &str) -> Result<String, String> {
    let der = pem_to_der(pem)?;
    // SPKI Ed25519: 12-byte prefix + 32-byte key = 44 bytes
    if der.len() == 44 {
        return Ok(URL_SAFE_NO_PAD.encode(&der[12..44]));
    }
    Err(format!("Unexpected SPKI DER length: {} (expected 44)", der.len()))
}

fn build_device_auth_payload(
    device_id: &str,
    params: &SignDeviceParams,
    signed_at_ms: u64,
) -> String {
    let version = if params.nonce.is_some() { "v2" } else { "v1" };
    let scopes_str = params.scopes.join(",");
    let token = params.token.as_deref().unwrap_or("");
    let mut parts = vec![
        version.to_string(),
        device_id.to_string(),
        params.client_id.to_string(),
        params.client_mode.to_string(),
        params.role.to_string(),
        scopes_str,
        signed_at_ms.to_string(),
        token.to_string(),
    ];
    if version == "v2" {
        parts.push(params.nonce.as_deref().unwrap_or("").to_string());
    }
    parts.join("|")
}
#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct SignDeviceParams {
    pub client_id: String,
    pub client_mode: String,
    pub role: String,
    pub scopes: Vec<String>,
    pub token: Option<String>,
    pub nonce: Option<String>,
}

pub fn sign_device_challenge(
    state: &AppState,
    params: SignDeviceParams,
) -> Result<DeviceAuth, String> {
    let identity_path = std::path::PathBuf::from(&state.openclaw_dir)
        .join("identity")
        .join("device.json");

    // Best-effort permission check. In Docker volume mounts the file may be
    // owned by a different UID, so we only warn rather than fail hard.
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        if let Ok(meta) = fs::metadata(&identity_path) {
            let mode = meta.permissions().mode() & 0o777;
            if mode & 0o077 != 0 {
                // Try to fix permissions; if we can't (volume mount), proceed anyway
                let _ = fs::set_permissions(
                    &identity_path,
                    fs::Permissions::from_mode(0o600),
                );
            }
        }
    }

    let content = fs::read_to_string(&identity_path)
        .map_err(|e| format!("Failed to read device identity: {}", e))?;
    let identity: DeviceIdentityFile =
        serde_json::from_str(&content).map_err(|e| format!("Failed to parse device identity: {}", e))?;

    let signing_key = parse_ed25519_private_key(&identity.private_key_pem)?;
    let public_key_b64url = public_key_raw_base64url(&identity.public_key_pem)?;

    let signed_at_ms = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_err(|e| format!("System time error: {}", e))?
        .as_millis() as u64;

    let payload = build_device_auth_payload(
        &identity.device_id,
        &params,
        signed_at_ms,
    );

    let signature = signing_key.sign(payload.as_bytes());
    let signature_b64url = URL_SAFE_NO_PAD.encode(signature.to_bytes());

    Ok(DeviceAuth {
        id: identity.device_id,
        public_key: public_key_b64url,
        signature: signature_b64url,
        signed_at: signed_at_ms,
        nonce: params.nonce,
    })
}
pub fn generate_device_identity(state: &AppState) -> Result<String, String> {
    let identity_dir = std::path::PathBuf::from(&state.openclaw_dir)
        .join("identity");
    let identity_path = identity_dir.join("device.json");

    // If identity already exists, return the device ID without regenerating
    if identity_path.is_file() {
        let content = fs::read_to_string(&identity_path)
            .map_err(|e| format!("Failed to read existing identity: {}", e))?;
        let existing: serde_json::Value =
            serde_json::from_str(&content).map_err(|e| format!("Invalid identity JSON: {}", e))?;
        if let Some(id) = existing["deviceId"].as_str() {
            return Ok(id.to_string());
        }
    }

    // Generate Ed25519 keypair from random seed
    use ed25519_dalek::SigningKey;
    use rand::RngCore;

    let mut seed = [0u8; 32];
    rand::rngs::OsRng.fill_bytes(&mut seed);
    let signing_key = SigningKey::from_bytes(&seed);
    let verifying_key = signing_key.verifying_key();

    // Encode private key as PKCS8 PEM
    // PKCS8 Ed25519: 16-byte header + 32-byte seed = 48 bytes DER
    let pkcs8_header: [u8; 16] = [
        0x30, 0x2e, 0x02, 0x01, 0x00, 0x30, 0x05, 0x06,
        0x03, 0x2b, 0x65, 0x70, 0x04, 0x22, 0x04, 0x20,
    ];
    let mut pkcs8_der = Vec::with_capacity(48);
    pkcs8_der.extend_from_slice(&pkcs8_header);
    pkcs8_der.extend_from_slice(signing_key.as_bytes());
    let private_b64 = base64::engine::general_purpose::STANDARD.encode(&pkcs8_der);
    let private_pem = format!(
        "-----BEGIN PRIVATE KEY-----\n{}\n-----END PRIVATE KEY-----",
        private_b64
    );

    // Encode public key as SPKI PEM
    // SPKI Ed25519: 12-byte header + 32-byte key = 44 bytes DER
    let spki_header: [u8; 12] = [
        0x30, 0x2a, 0x30, 0x05, 0x06, 0x03, 0x2b, 0x65,
        0x70, 0x03, 0x21, 0x00,
    ];
    let mut spki_der = Vec::with_capacity(44);
    spki_der.extend_from_slice(&spki_header);
    spki_der.extend_from_slice(verifying_key.as_bytes());
    let public_b64 = base64::engine::general_purpose::STANDARD.encode(&spki_der);
    let public_pem = format!(
        "-----BEGIN PUBLIC KEY-----\n{}\n-----END PUBLIC KEY-----",
        public_b64
    );

    // Generate device ID
    let device_id = format!("openclaw-{}", uuid_v4());

    let identity = serde_json::json!({
        "version": 1,
        "deviceId": device_id,
        "publicKeyPem": public_pem,
        "privateKeyPem": private_pem,
    });

    // Write to disk
    fs::create_dir_all(&identity_dir)
        .map_err(|e| format!("Failed to create identity directory: {}", e))?;

    let content = serde_json::to_string_pretty(&identity)
        .map_err(|e| format!("Failed to serialize identity: {}", e))?;
    fs::write(&identity_path, &content)
        .map_err(|e| format!("Failed to write device identity: {}", e))?;

    // Set restrictive permissions (owner-only)
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(&identity_path, fs::Permissions::from_mode(0o600))
            .map_err(|e| format!("Failed to set identity permissions: {}", e))?;
    }

    crate::security::audit::log_action(
        &state.audit_log_path,
        "DEVICE_IDENTITY_CREATE",
        &format!("Generated device identity: {}", device_id),
    );

    Ok(device_id)
}

fn uuid_v4() -> String {
    use rand::RngCore;
    let mut bytes = [0u8; 16];
    rand::rngs::OsRng.fill_bytes(&mut bytes);
    // Set version (4) and variant (RFC 4122)
    bytes[6] = (bytes[6] & 0x0f) | 0x40;
    bytes[8] = (bytes[8] & 0x3f) | 0x80;
    format!(
        "{:02x}{:02x}{:02x}{:02x}-{:02x}{:02x}-{:02x}{:02x}-{:02x}{:02x}-{:02x}{:02x}{:02x}{:02x}{:02x}{:02x}",
        bytes[0], bytes[1], bytes[2], bytes[3],
        bytes[4], bytes[5],
        bytes[6], bytes[7],
        bytes[8], bytes[9],
        bytes[10], bytes[11], bytes[12], bytes[13], bytes[14], bytes[15],
    )
}
#[cfg(test)]
mod tests {
    use super::*;

    fn make_params(client_id: &str, client_mode: &str, role: &str, scopes: &[&str], token: Option<&str>, nonce: Option<&str>) -> SignDeviceParams {
        SignDeviceParams {
            client_id: client_id.into(),
            client_mode: client_mode.into(),
            role: role.into(),
            scopes: scopes.iter().map(|s| s.to_string()).collect(),
            token: token.map(String::from),
            nonce: nonce.map(String::from),
        }
    }

    #[test]
    fn test_build_payload_v1() {
        let params = make_params("client1", "ui", "operator", &["operator.admin"], Some("token123"), None);
        let payload = build_device_auth_payload("device123", &params, 1234567890);
        assert_eq!(payload, "v1|device123|client1|ui|operator|operator.admin|1234567890|token123");
    }

    #[test]
    fn test_build_payload_v2_with_nonce() {
        let params = make_params("client1", "ui", "operator", &["operator.admin"], Some("token123"), Some("nonce456"));
        let payload = build_device_auth_payload("device123", &params, 1234567890);
        assert_eq!(payload, "v2|device123|client1|ui|operator|operator.admin|1234567890|token123|nonce456");
    }

    #[test]
    fn test_build_payload_multiple_scopes() {
        let params = make_params("cli", "api", "admin", &["read", "write", "delete"], Some("tok"), None);
        let payload = build_device_auth_payload("dev1", &params, 999);
        assert_eq!(payload, "v1|dev1|cli|api|admin|read,write,delete|999|tok");
    }

    #[test]
    fn test_build_payload_empty_scopes() {
        let params = make_params("cli", "api", "admin", &[], Some("tok"), None);
        let payload = build_device_auth_payload("dev1", &params, 999);
        assert_eq!(payload, "v1|dev1|cli|api|admin||999|tok");
    }

    #[test]
    fn test_build_payload_empty_token() {
        let params = make_params("cli", "api", "admin", &["scope"], None, None);
        let payload = build_device_auth_payload("dev1", &params, 999);
        assert_eq!(payload, "v1|dev1|cli|api|admin|scope|999|");
    }
    #[test]
    fn uuid_v4_correct_format() {
        let id = uuid_v4();
        // UUID v4 format: 8-4-4-4-12 hex chars
        let parts: Vec<&str> = id.split('-').collect();
        assert_eq!(parts.len(), 5);
        assert_eq!(parts[0].len(), 8);
        assert_eq!(parts[1].len(), 4);
        assert_eq!(parts[2].len(), 4);
        assert_eq!(parts[3].len(), 4);
        assert_eq!(parts[4].len(), 12);
        // All hex chars
        assert!(id.replace('-', "").chars().all(|c| c.is_ascii_hexdigit()));
    }

    #[test]
    fn uuid_v4_version_and_variant_bits() {
        let id = uuid_v4();
        let parts: Vec<&str> = id.split('-').collect();
        // Version nibble (first char of 3rd group) should be '4'
        assert!(parts[2].starts_with('4'));
        // Variant nibble (first char of 4th group) should be 8, 9, a, or b
        let variant_char = parts[3].chars().next().unwrap();
        assert!(
            variant_char == '8' || variant_char == '9'
                || variant_char == 'a' || variant_char == 'b',
            "variant nibble was '{}', expected 8/9/a/b",
            variant_char
        );
    }

    #[test]
    fn uuid_v4_uniqueness() {
        let id1 = uuid_v4();
        let id2 = uuid_v4();
        assert_ne!(id1, id2);
    }
    #[test]
    fn pem_to_der_strips_headers() {
        // Create a known PEM with base64 of [1,2,3,4]
        let b64 = base64::engine::general_purpose::STANDARD.encode([1u8, 2, 3, 4]);
        let pem = format!("-----BEGIN PRIVATE KEY-----\n{}\n-----END PRIVATE KEY-----", b64);
        let der = pem_to_der(&pem).unwrap();
        assert_eq!(der, vec![1, 2, 3, 4]);
    }

    #[test]
    fn pem_to_der_invalid_base64_fails() {
        let pem = "-----BEGIN PRIVATE KEY-----\n!!not_base64!!\n-----END PRIVATE KEY-----";
        assert!(pem_to_der(pem).is_err());
    }

    #[test]
    fn pem_to_der_empty_body() {
        let pem = "-----BEGIN PRIVATE KEY-----\n-----END PRIVATE KEY-----";
        let der = pem_to_der(pem).unwrap();
        assert!(der.is_empty());
    }
    #[test]
    fn parse_ed25519_private_key_wrong_length_fails() {
        // Create a PEM with wrong-length DER (not 48 bytes)
        let fake_der = vec![0u8; 32]; // too short
        let b64 = base64::engine::general_purpose::STANDARD.encode(&fake_der);
        let pem = format!("-----BEGIN PRIVATE KEY-----\n{}\n-----END PRIVATE KEY-----", b64);
        let result = parse_ed25519_private_key(&pem);
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("Unexpected PKCS8 DER length"));
    }

    #[test]
    fn public_key_raw_base64url_wrong_length_fails() {
        let fake_der = vec![0u8; 32]; // need 44 bytes
        let b64 = base64::engine::general_purpose::STANDARD.encode(&fake_der);
        let pem = format!("-----BEGIN PUBLIC KEY-----\n{}\n-----END PUBLIC KEY-----", b64);
        let result = public_key_raw_base64url(&pem);
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("Unexpected SPKI DER length"));
    }
    fn make_device_state(tmp: &std::path::Path) -> crate::state::AppState {
        let audit_path = tmp.join("audit.log");
        let _ = std::fs::write(&audit_path, "");
        crate::state::AppState {
            openclaw_dir: tmp.to_str().unwrap().to_string(),
            vault_dir: String::new(),
            audit_log_path: audit_path.to_str().unwrap().to_string(),
            vault: std::sync::Mutex::new(crate::state::VaultRuntime::default()),
        }
    }

    #[test]
    fn generate_device_identity_creates_keypair() {
        let tmp = tempfile::tempdir().unwrap();
        let state = make_device_state(tmp.path());

        let device_id = generate_device_identity(&state).unwrap();
        assert!(device_id.starts_with("openclaw-"));

        // File should exist
        let path = tmp.path().join("identity/device.json");
        assert!(path.exists());

        // File should be valid JSON with expected fields
        let content = std::fs::read_to_string(&path).unwrap();
        let json: serde_json::Value = serde_json::from_str(&content).unwrap();
        assert_eq!(json["version"], 1);
        assert_eq!(json["deviceId"].as_str().unwrap(), device_id);
        assert!(json["publicKeyPem"].as_str().unwrap().contains("BEGIN PUBLIC KEY"));
        assert!(json["privateKeyPem"].as_str().unwrap().contains("BEGIN PRIVATE KEY"));
    }

    #[test]
    fn generate_device_identity_returns_existing() {
        let tmp = tempfile::tempdir().unwrap();
        let state = make_device_state(tmp.path());

        let id1 = generate_device_identity(&state).unwrap();
        let id2 = generate_device_identity(&state).unwrap();
        assert_eq!(id1, id2);
    }

    #[test]
    fn sign_device_challenge_produces_valid_signature() {
        let tmp = tempfile::tempdir().unwrap();
        let state = make_device_state(tmp.path());

        // Generate identity first
        generate_device_identity(&state).unwrap();

        let params = SignDeviceParams {
            client_id: "test-client".to_string(),
            client_mode: "ui".to_string(),
            role: "operator".to_string(),
            scopes: vec!["admin".to_string()],
            token: Some("tok-123".to_string()),
            nonce: Some("nonce-abc".to_string()),
        };

        let auth = sign_device_challenge(&state, params).unwrap();

        assert!(auth.id.starts_with("openclaw-"));
        assert!(!auth.public_key.is_empty());
        assert!(!auth.signature.is_empty());
        assert!(auth.signed_at > 0);
        assert_eq!(auth.nonce, Some("nonce-abc".to_string()));

        // Verify the signature is valid base64url
        let sig_bytes = URL_SAFE_NO_PAD.decode(&auth.signature).unwrap();
        assert_eq!(sig_bytes.len(), 64); // Ed25519 signature is 64 bytes

        // Verify public key is valid base64url
        let pk_bytes = URL_SAFE_NO_PAD.decode(&auth.public_key).unwrap();
        assert_eq!(pk_bytes.len(), 32); // Ed25519 public key is 32 bytes
    }

    #[test]
    fn sign_device_challenge_without_identity_fails() {
        let tmp = tempfile::tempdir().unwrap();
        let state = make_device_state(tmp.path());

        let params = SignDeviceParams {
            client_id: "test".to_string(),
            client_mode: "ui".to_string(),
            role: "operator".to_string(),
            scopes: vec![],
            token: None,
            nonce: None,
        };

        let result = sign_device_challenge(&state, params);
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("Failed to read"));
    }

    #[test]
    fn sign_device_challenge_v1_no_nonce() {
        let tmp = tempfile::tempdir().unwrap();
        let state = make_device_state(tmp.path());
        generate_device_identity(&state).unwrap();

        let params = SignDeviceParams {
            client_id: "cli".to_string(),
            client_mode: "api".to_string(),
            role: "viewer".to_string(),
            scopes: vec!["read".to_string()],
            token: None,
            nonce: None,
        };

        let auth = sign_device_challenge(&state, params).unwrap();
        assert_eq!(auth.nonce, None);
    }

    #[test]
    fn generated_keypair_signs_and_verifies() {
        let tmp = tempfile::tempdir().unwrap();
        let state = make_device_state(tmp.path());
        generate_device_identity(&state).unwrap();

        // Read back the identity
        let content = std::fs::read_to_string(
            tmp.path().join("identity/device.json")
        ).unwrap();
        let identity: serde_json::Value = serde_json::from_str(&content).unwrap();

        // Parse private key and sign something
        let signing_key = parse_ed25519_private_key(
            identity["privateKeyPem"].as_str().unwrap()
        ).unwrap();

        let message = b"test message";
        let sig = signing_key.sign(message);

        // Parse public key and verify
        let pk_b64url = public_key_raw_base64url(
            identity["publicKeyPem"].as_str().unwrap()
        ).unwrap();
        let pk_bytes = URL_SAFE_NO_PAD.decode(&pk_b64url).unwrap();
        let verifying_key = ed25519_dalek::VerifyingKey::from_bytes(
            pk_bytes.as_slice().try_into().unwrap()
        ).unwrap();

        use ed25519_dalek::Verifier;
        assert!(verifying_key.verify(message, &sig).is_ok());
    }
}
