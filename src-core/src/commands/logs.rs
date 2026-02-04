use crate::security::audit;
use crate::state::AppState;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::fs;

pub fn read_audit_log(
    state: &AppState,
    limit: Option<usize>,
) -> Result<Vec<String>, String> {
    let content = fs::read_to_string(&state.audit_log_path).unwrap_or_default();
    let lines: Vec<String> = content.lines().rev().map(|s| s.to_string()).collect();
    let limit = limit.unwrap_or(100);
    Ok(lines.into_iter().take(limit).collect())
}

pub fn read_gateway_logs(
    state: &AppState,
    limit: Option<usize>,
) -> Result<Vec<String>, String> {
    let clamped_limit = limit.unwrap_or(100).min(10_000);
    let docker = super::docker::find_docker();
    let output = std::process::Command::new(&docker)
        .args([
            "compose",
            "logs",
            "--tail",
            &clamped_limit.to_string(),
            "gateway",
        ])
        .current_dir(state.docker_compose_dir())
        .output()
        .map_err(|e| format!("Failed to read gateway logs: {}", e))?;

    let stdout = String::from_utf8_lossy(&output.stdout);
    Ok(stdout.lines().map(|s| s.to_string()).collect())
}

pub fn search_logs(
    state: &AppState,
    query: String,
    limit: Option<usize>,
) -> Result<Vec<String>, String> {
    let max_results = limit.unwrap_or(500).min(10_000);
    let content = fs::read_to_string(&state.audit_log_path).unwrap_or_default();
    let query_lower = query.to_lowercase();
    let matches: Vec<String> = content
        .lines()
        .filter(|line| line.to_lowercase().contains(&query_lower))
        .take(max_results)
        .map(|s| s.to_string())
        .collect();
    Ok(matches)
}

/// Find the largest byte index <= `max_bytes` that sits on a UTF-8 char boundary.
fn truncate_at_char_boundary(s: &str, max_bytes: usize) -> usize {
    if max_bytes >= s.len() {
        return s.len();
    }
    let mut i = max_bytes;
    while i > 0 && !s.is_char_boundary(i) {
        i -= 1;
    }
    i
}

pub fn log_frontend_error(
    state: &AppState,
    severity: String,
    message: String,
    component: Option<String>,
    stack: Option<String>,
) -> Result<(), String> {
    // Truncate to prevent log flooding (max 2KB per field).
    // Use floor_char_boundary to avoid panicking on multi-byte UTF-8.
    let safe_msg = &message[..truncate_at_char_boundary(&message, 2048)];
    let location = component.as_deref().unwrap_or("unknown");
    let detail = match &stack {
        Some(s) => {
            let safe_stack = &s[..truncate_at_char_boundary(s, 2048)];
            format!("[{}] {} in {} | stack: {}", severity, safe_msg, location, safe_stack)
        }
        None => format!("[{}] {} in {}", severity, safe_msg, location),
    };

    audit::log_action(&state.audit_log_path, "FRONTEND_ERROR", &detail);
    Ok(())
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct UsageStats {
    pub total_actions: usize,
    pub actions_by_type: HashMap<String, usize>,
    pub actions_by_day: HashMap<String, usize>,
    pub error_count: usize,
}

pub fn get_usage_stats(state: &AppState) -> Result<UsageStats, String> {
    let content = fs::read_to_string(&state.audit_log_path).unwrap_or_default();
    let lines: Vec<&str> = content.lines().filter(|l| !l.trim().is_empty()).collect();

    let mut actions_by_type: HashMap<String, usize> = HashMap::new();
    let mut actions_by_day: HashMap<String, usize> = HashMap::new();
    let mut error_count = 0;

    for line in &lines {
        // Parse format: [timestamp] ACTION | details
        if let Some(rest) = line.strip_prefix('[') {
            if let Some(bracket_end) = rest.find(']') {
                let timestamp = &rest[..bracket_end];
                let day = if timestamp.len() >= 10 {
                    &timestamp[..10]
                } else {
                    timestamp
                };
                *actions_by_day.entry(day.to_string()).or_insert(0) += 1;

                let after = rest[bracket_end + 1..].trim();
                if let Some(pipe_pos) = after.find('|') {
                    let action = after[..pipe_pos].trim().to_string();
                    *actions_by_type.entry(action).or_insert(0) += 1;
                }
            }
        }

        let lower = line.to_lowercase();
        if lower.contains("error") || lower.contains("fail") {
            error_count += 1;
        }
    }

    Ok(UsageStats {
        total_actions: lines.len(),
        actions_by_type,
        actions_by_day,
        error_count,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;

    fn make_state(tmp: &std::path::Path) -> AppState {
        let audit_path = tmp.join("audit.log");
        let _ = fs::write(&audit_path, "");
        AppState {
            openclaw_dir: tmp.to_str().unwrap().to_string(),
            vault_dir: String::new(),
            audit_log_path: audit_path.to_str().unwrap().to_string(),
            vault: std::sync::Mutex::new(crate::state::VaultRuntime::default()),
        }
    }
    #[test]
    fn read_audit_log_returns_lines_in_reverse() {
        let tmp = tempfile::tempdir().unwrap();
        let state = make_state(tmp.path());
        fs::write(&state.audit_log_path, "line1\nline2\nline3\n").unwrap();

        let lines = read_audit_log(&state, None).unwrap();
        // Last non-empty line comes first
        assert_eq!(lines[0], "line3");
        assert_eq!(lines[1], "line2");
        assert_eq!(lines[2], "line1");
    }

    #[test]
    fn read_audit_log_respects_limit() {
        let tmp = tempfile::tempdir().unwrap();
        let state = make_state(tmp.path());
        fs::write(&state.audit_log_path, "a\nb\nc\nd\ne\n").unwrap();

        let lines = read_audit_log(&state, Some(2)).unwrap();
        assert_eq!(lines.len(), 2);
    }

    #[test]
    fn read_audit_log_empty_file() {
        let tmp = tempfile::tempdir().unwrap();
        let state = make_state(tmp.path());

        let lines = read_audit_log(&state, None).unwrap();
        // Empty file -> one empty string from lines().rev()
        assert!(lines.is_empty() || lines.iter().all(|l| l.is_empty()));
    }

    #[test]
    fn read_audit_log_missing_file() {
        let tmp = tempfile::tempdir().unwrap();
        let state = AppState {
            openclaw_dir: tmp.path().to_str().unwrap().to_string(),
            vault_dir: String::new(),
            audit_log_path: tmp.path().join("nonexistent.log").to_str().unwrap().to_string(),
            vault: std::sync::Mutex::new(crate::state::VaultRuntime::default()),
        };

        // Should return empty, not error (uses unwrap_or_default)
        let lines = read_audit_log(&state, None).unwrap();
        assert!(lines.is_empty() || lines[0].is_empty());
    }
    #[test]
    fn search_logs_finds_matching_lines() {
        let tmp = tempfile::tempdir().unwrap();
        let state = make_state(tmp.path());
        fs::write(&state.audit_log_path, "[2024-01-01] AGENT_CREATE | created bot\n[2024-01-02] CONFIG_UPDATE | changed setting\n[2024-01-03] AGENT_DELETE | removed bot\n").unwrap();

        let results = search_logs(&state, "AGENT".to_string(), None).unwrap();
        assert_eq!(results.len(), 2);
    }

    #[test]
    fn search_logs_case_insensitive() {
        let tmp = tempfile::tempdir().unwrap();
        let state = make_state(tmp.path());
        fs::write(&state.audit_log_path, "Error happened\nwarning issued\nINFO ok\n").unwrap();

        let results = search_logs(&state, "error".to_string(), None).unwrap();
        assert_eq!(results.len(), 1);
        assert!(results[0].contains("Error"));
    }

    #[test]
    fn search_logs_respects_limit() {
        let tmp = tempfile::tempdir().unwrap();
        let state = make_state(tmp.path());
        fs::write(&state.audit_log_path, "match1\nmatch2\nmatch3\nmatch4\nmatch5\n").unwrap();

        let results = search_logs(&state, "match".to_string(), Some(3)).unwrap();
        assert_eq!(results.len(), 3);
    }

    #[test]
    fn search_logs_no_matches() {
        let tmp = tempfile::tempdir().unwrap();
        let state = make_state(tmp.path());
        fs::write(&state.audit_log_path, "nothing relevant here\n").unwrap();

        let results = search_logs(&state, "ZZZZZ".to_string(), None).unwrap();
        assert!(results.is_empty());
    }
    #[test]
    fn log_frontend_error_writes_to_audit_log() {
        let tmp = tempfile::tempdir().unwrap();
        let state = make_state(tmp.path());

        log_frontend_error(
            &state,
            "error".to_string(),
            "Something broke".to_string(),
            Some("ChatView".to_string()),
            Some("at ChatView:42".to_string()),
        ).unwrap();

        let content = fs::read_to_string(&state.audit_log_path).unwrap();
        assert!(content.contains("FRONTEND_ERROR"));
        assert!(content.contains("Something broke"));
        assert!(content.contains("ChatView"));
    }

    #[test]
    fn log_frontend_error_truncates_long_message() {
        let tmp = tempfile::tempdir().unwrap();
        let state = make_state(tmp.path());

        let long_msg = "x".repeat(5000);
        log_frontend_error(&state, "error".to_string(), long_msg, None, None).unwrap();

        // Should not panic and should write something
        let content = fs::read_to_string(&state.audit_log_path).unwrap();
        assert!(content.contains("FRONTEND_ERROR"));
    }

    #[test]
    fn log_frontend_error_without_optional_fields() {
        let tmp = tempfile::tempdir().unwrap();
        let state = make_state(tmp.path());

        log_frontend_error(&state, "warn".to_string(), "minor issue".to_string(), None, None).unwrap();

        let content = fs::read_to_string(&state.audit_log_path).unwrap();
        assert!(content.contains("unknown"));
        assert!(content.contains("minor issue"));
    }
    #[test]
    fn get_usage_stats_counts_actions() {
        let tmp = tempfile::tempdir().unwrap();
        let state = make_state(tmp.path());
        fs::write(&state.audit_log_path, "\
[2024-01-15T10:00:00Z] AGENT_CREATE | created bot
[2024-01-15T11:00:00Z] AGENT_CREATE | created another
[2024-01-15T12:00:00Z] CONFIG_UPDATE | changed config
[2024-01-16T09:00:00Z] AGENT_DELETE | removed bot
").unwrap();

        let stats = get_usage_stats(&state).unwrap();
        assert_eq!(stats.total_actions, 4);
        assert_eq!(stats.actions_by_type["AGENT_CREATE"], 2);
        assert_eq!(stats.actions_by_type["CONFIG_UPDATE"], 1);
        assert_eq!(stats.actions_by_type["AGENT_DELETE"], 1);
        assert_eq!(stats.actions_by_day["2024-01-15"], 3);
        assert_eq!(stats.actions_by_day["2024-01-16"], 1);
    }

    #[test]
    fn get_usage_stats_counts_errors() {
        let tmp = tempfile::tempdir().unwrap();
        let state = make_state(tmp.path());
        fs::write(&state.audit_log_path, "\
[2024-01-15T10:00:00Z] AGENT_CREATE | ok
[2024-01-15T11:00:00Z] FRONTEND_ERROR | something failed
[2024-01-15T12:00:00Z] SYNC_WARN | Gateway sync after create failed: timeout
").unwrap();

        let stats = get_usage_stats(&state).unwrap();
        assert_eq!(stats.total_actions, 3);
        assert_eq!(stats.error_count, 2); // "error" and "failed" both match
    }

    #[test]
    fn get_usage_stats_empty_log() {
        let tmp = tempfile::tempdir().unwrap();
        let state = make_state(tmp.path());

        let stats = get_usage_stats(&state).unwrap();
        // Empty file has one empty line or zero lines
        assert!(stats.actions_by_type.is_empty());
        assert_eq!(stats.error_count, 0);
    }
}
