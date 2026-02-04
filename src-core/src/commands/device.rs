use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine;
use ed25519_dalek::{SigningKey, Signer};
use serde::{Deserialize, Serialize};
use std::fs;

use crate::state::AppState;

// ---------------------------------------------------------------------------
// Types
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "camelCase")]
struct DeviceIdentityFile {
    #[serde(rename = "version")]
    _version: u32,
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

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

/// Decode a PEM block (strip header/footer, base64 decode) into raw DER bytes.
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

/// Parse a PKCS8 PEM private key into the raw 32-byte Ed25519 seed.
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

/// Extract the raw 32-byte public key from SPKI PEM and encode as base64url.
fn public_key_raw_base64url(pem: &str) -> Result<String, String> {
    let der = pem_to_der(pem)?;
    // SPKI Ed25519: 12-byte prefix + 32-byte key = 44 bytes
    if der.len() == 44 {
        return Ok(URL_SAFE_NO_PAD.encode(&der[12..44]));
    }
    Err(format!("Unexpected SPKI DER length: {} (expected 44)", der.len()))
}

/// Build the device auth payload string matching the gateway protocol.
#[allow(clippy::too_many_arguments)]
fn build_device_auth_payload(
    device_id: &str,
    client_id: &str,
    client_mode: &str,
    role: &str,
    scopes: &[String],
    signed_at_ms: u64,
    token: &str,
    nonce: Option<&str>,
) -> String {
    let version = if nonce.is_some() { "v2" } else { "v1" };
    let scopes_str = scopes.join(",");
    let mut parts = vec![
        version.to_string(),
        device_id.to_string(),
        client_id.to_string(),
        client_mode.to_string(),
        role.to_string(),
        scopes_str,
        signed_at_ms.to_string(),
        token.to_string(),
    ];
    if version == "v2" {
        parts.push(nonce.unwrap_or("").to_string());
    }
    parts.join("|")
}

// ---------------------------------------------------------------------------
// Commands
// ---------------------------------------------------------------------------

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

/// Sign a device challenge for gateway v3 protocol authentication.
/// Reads the device identity from {openclaw_dir}/identity/device.json,
/// builds the auth payload, signs it with Ed25519, and returns the device auth object.
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
        &params.client_id,
        &params.client_mode,
        &params.role,
        &params.scopes,
        signed_at_ms,
        params.token.as_deref().unwrap_or(""),
        params.nonce.as_deref(),
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

// ---------------------------------------------------------------------------
// Device identity generation
// ---------------------------------------------------------------------------

/// Generate a device identity (Ed25519 keypair) if one does not already exist.
/// Creates {openclaw_dir}/identity/device.json with:
///   - version: 1
///   - deviceId: "openclaw-<uuid>"
///   - publicKeyPem: SPKI PEM
///   - privateKeyPem: PKCS8 PEM
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

/// Generate a simple UUID v4 using random bytes.
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

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_build_payload_v1() {
        let payload = build_device_auth_payload(
            "device123",
            "client1",
            "ui",
            "operator",
            &["operator.admin".to_string()],
            1234567890,
            "token123",
            None,
        );
        assert_eq!(
            payload,
            "v1|device123|client1|ui|operator|operator.admin|1234567890|token123"
        );
    }

    #[test]
    fn test_build_payload_v2_with_nonce() {
        let payload = build_device_auth_payload(
            "device123",
            "client1",
            "ui",
            "operator",
            &["operator.admin".to_string()],
            1234567890,
            "token123",
            Some("nonce456"),
        );
        assert_eq!(
            payload,
            "v2|device123|client1|ui|operator|operator.admin|1234567890|token123|nonce456"
        );
    }
}
