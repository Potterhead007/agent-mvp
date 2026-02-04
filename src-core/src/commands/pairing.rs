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
