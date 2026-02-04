use crate::state::AppState;
use serde::{Deserialize, Serialize};
use std::process::Command;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PairingRequest {
    pub code: String,
    pub id: String,
    pub meta: Option<serde_json::Value>,
    #[serde(rename = "createdAt")]
    pub created_at: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct PairingListResponse {
    channel: String,
    requests: Vec<PairingRequest>,
}

/// List pending pairing requests for a channel via the gateway CLI.
pub fn list_pairing_requests(
    state: &AppState,
    channel: String,
) -> Result<Vec<PairingRequest>, String> {
    let channel = channel.trim().to_lowercase();
    if channel.is_empty() || !channel.chars().all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '_') {
        return Err("Invalid channel name".into());
    }

    let docker = crate::commands::docker::find_docker();
    let compose_dir = state.docker_compose_dir();
    crate::commands::docker::validate_compose_dir(&compose_dir)?;

    let output = Command::new(&docker)
        .args([
            "compose", "exec", "-T", "gateway",
            "openclaw", "pairing", "list", &channel, "--json",
        ])
        .current_dir(&compose_dir)
        .output()
        .map_err(|e| format!("Failed to list pairing requests: {}", e))?;

    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        // No pending requests is not an error
        if stderr.contains("No pending") || stderr.contains("no pending") {
            return Ok(vec![]);
        }
        return Err(format!("Pairing list failed: {}", stderr.trim()));
    }

    let stdout = String::from_utf8_lossy(&output.stdout);
    let trimmed = stdout.trim();
    if trimmed.is_empty() {
        return Ok(vec![]);
    }

    // Try parsing as PairingListResponse first, fall back to direct array
    if let Ok(parsed) = serde_json::from_str::<PairingListResponse>(trimmed) {
        return Ok(parsed.requests);
    }
    if let Ok(requests) = serde_json::from_str::<Vec<PairingRequest>>(trimmed) {
        return Ok(requests);
    }

    Err(format!("Failed to parse pairing response: {}", &trimmed[..trimmed.len().min(200)]))
}

/// Approve a pairing request by code for a channel.
pub fn approve_pairing_request(
    state: &AppState,
    channel: String,
    code: String,
) -> Result<String, String> {
    let channel = channel.trim().to_lowercase();
    let code = code.trim().to_uppercase();

    if channel.is_empty() || !channel.chars().all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '_') {
        return Err("Invalid channel name".into());
    }
    if code.is_empty() || code.len() > 20 || !code.chars().all(|c| c.is_ascii_alphanumeric()) {
        return Err("Invalid pairing code".into());
    }

    let docker = crate::commands::docker::find_docker();
    let compose_dir = state.docker_compose_dir();
    crate::commands::docker::validate_compose_dir(&compose_dir)?;

    let output = Command::new(&docker)
        .args([
            "compose", "exec", "-T", "gateway",
            "openclaw", "pairing", "approve", &channel, &code,
        ])
        .current_dir(&compose_dir)
        .output()
        .map_err(|e| format!("Failed to approve pairing: {}", e))?;

    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        return Err(format!("Pairing approval failed: {}", stderr.trim()));
    }

    let stdout = String::from_utf8_lossy(&output.stdout);
    Ok(stdout.trim().to_string())
}

#[cfg(test)]
mod tests {
    use super::*;

    // We can't test the Docker-dependent code paths without Docker running,
    // but we CAN test all input validation before Docker is reached.

    fn make_state(tmp: &std::path::Path) -> AppState {
        let audit = tmp.join("audit.log");
        let _ = std::fs::write(&audit, "");
        AppState {
            openclaw_dir: tmp.to_str().unwrap().to_string(),
            vault_dir: String::new(),
            audit_log_path: audit.to_str().unwrap().to_string(),
            vault: std::sync::Mutex::new(crate::state::VaultRuntime::default()),
        }
    }

    #[test]
    fn list_pairing_rejects_empty_channel() {
        let tmp = tempfile::tempdir().unwrap();
        let state = make_state(tmp.path());
        let result = list_pairing_requests(&state, "".to_string());
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("Invalid channel"));
    }

    #[test]
    fn list_pairing_rejects_special_chars_in_channel() {
        let tmp = tempfile::tempdir().unwrap();
        let state = make_state(tmp.path());
        let result = list_pairing_requests(&state, "../etc/passwd".to_string());
        assert!(result.is_err());
    }

    #[test]
    fn list_pairing_normalizes_channel() {
        let tmp = tempfile::tempdir().unwrap();
        let state = make_state(tmp.path());
        // Valid channel with spaces/uppercase — should pass validation
        // but fail at Docker (which we can't test here)
        // Just verify it doesn't reject valid-looking names
        let result = list_pairing_requests(&state, " Telegram ".to_string());
        // Will fail at validate_compose_dir (no docker-compose.yml in temp dir)
        assert!(result.is_err());
        // But the error should NOT be "Invalid channel"
        assert!(!result.unwrap_err().contains("Invalid channel"));
    }

    #[test]
    fn approve_pairing_rejects_empty_channel() {
        let tmp = tempfile::tempdir().unwrap();
        let state = make_state(tmp.path());
        let result = approve_pairing_request(&state, "".to_string(), "ABC".to_string());
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("Invalid channel"));
    }

    #[test]
    fn approve_pairing_rejects_empty_code() {
        let tmp = tempfile::tempdir().unwrap();
        let state = make_state(tmp.path());
        let result = approve_pairing_request(&state, "telegram".to_string(), "".to_string());
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("Invalid pairing code"));
    }

    #[test]
    fn approve_pairing_rejects_too_long_code() {
        let tmp = tempfile::tempdir().unwrap();
        let state = make_state(tmp.path());
        let long_code = "A".repeat(21);
        let result = approve_pairing_request(&state, "telegram".to_string(), long_code);
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("Invalid pairing code"));
    }

    #[test]
    fn approve_pairing_rejects_special_chars_in_code() {
        let tmp = tempfile::tempdir().unwrap();
        let state = make_state(tmp.path());
        let result = approve_pairing_request(&state, "telegram".to_string(), "AB!@#".to_string());
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("Invalid pairing code"));
    }

    #[test]
    fn approve_pairing_normalizes_code_to_uppercase() {
        let tmp = tempfile::tempdir().unwrap();
        let state = make_state(tmp.path());
        // Valid code "abc" should pass validation (gets uppercased to "ABC")
        // Will fail at Docker step, not validation
        let result = approve_pairing_request(&state, "telegram".to_string(), "abc123".to_string());
        assert!(result.is_err());
        assert!(!result.unwrap_err().contains("Invalid pairing code"));
    }

    #[test]
    fn approve_pairing_rejects_channel_with_spaces() {
        let tmp = tempfile::tempdir().unwrap();
        let state = make_state(tmp.path());
        let result = approve_pairing_request(&state, "my channel".to_string(), "ABC".to_string());
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("Invalid channel"));
    }

    #[test]
    fn list_pairing_allows_hyphens_underscores() {
        let tmp = tempfile::tempdir().unwrap();
        let state = make_state(tmp.path());
        // Hyphens and underscores should be valid
        let result = list_pairing_requests(&state, "my-channel_1".to_string());
        // Should fail at Docker, not validation
        assert!(result.is_err());
        assert!(!result.unwrap_err().contains("Invalid channel"));
    }
}
