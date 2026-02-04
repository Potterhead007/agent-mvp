use crate::fs_utils::atomic_write;
use crate::security::audit::log_action;
use crate::security::sanitize::truncate_str;
use crate::state::AppState;
use chrono::Utc;
use rand::Rng;
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::fmt::Write as FmtWrite;
use std::fs;
use std::path::Path;

// ---------------------------------------------------------------------------
// Data model
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct CronJob {
    pub id: String,
    pub name: String,
    pub schedule: CronSchedule,
    pub session_target: String,
    pub wake_mode: String,
    pub payload: CronPayload,
    pub enabled: bool,
    pub last_run: Option<String>,
    pub next_run: Option<String>,
    pub status: String,
    pub last_error: Option<String>,
    pub created_at: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct CronSchedule {
    pub kind: String,
    pub expr: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct CronPayload {
    pub kind: String,
    pub message: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct CronStore {
    version: u32,
    jobs: Vec<CronJob>,
}

const MAX_NAME_BYTES: usize = 200;
const MAX_MESSAGE_BYTES: usize = 4000;

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

fn store_path(state: &AppState) -> String {
    format!("{}/cron/jobs.json", state.openclaw_dir)
}

fn read_store(state: &AppState) -> Result<CronStore, String> {
    let path = store_path(state);
    if !Path::new(&path).exists() {
        // Ensure directory exists and create default store
        let dir = format!("{}/cron", state.openclaw_dir);
        fs::create_dir_all(&dir).map_err(|e| format!("Failed to create cron dir: {}", e))?;
        let store = CronStore {
            version: 1,
            jobs: vec![],
        };
        let json =
            serde_json::to_string_pretty(&store).map_err(|e| format!("Serialize error: {}", e))?;
        atomic_write(Path::new(&path), &json)?;
        return Ok(store);
    }

    let content =
        fs::read_to_string(&path).map_err(|e| format!("Failed to read {}: {}", path, e))?;
    serde_json::from_str(&content).map_err(|e| format!("Failed to parse jobs.json: {}", e))
}

fn write_store(state: &AppState, store: &CronStore) -> Result<(), String> {
    let path = store_path(state);
    let dir = format!("{}/cron", state.openclaw_dir);
    fs::create_dir_all(&dir).map_err(|e| format!("Failed to create cron dir: {}", e))?;
    let json =
        serde_json::to_string_pretty(store).map_err(|e| format!("Serialize error: {}", e))?;
    atomic_write(Path::new(&path), &json)
}

fn generate_uuid() -> String {
    let mut rng = rand::thread_rng();
    let bytes: [u8; 16] = rng.gen();
    let mut buf = String::with_capacity(36);
    for (i, b) in bytes.iter().enumerate() {
        if i == 4 || i == 6 || i == 8 || i == 10 {
            buf.push('-');
        }
        let _ = write!(buf, "{:02x}", b);
    }
    buf
}

/// Basic 5-field cron expression validation.
/// Accepts `"* * * * *"` style (minute hour dom month dow).
pub fn validate_cron_expr(expr: &str) -> Result<(), String> {
    let fields: Vec<&str> = expr.split_whitespace().collect();
    if fields.len() != 5 {
        return Err(format!(
            "Cron expression must have 5 fields, got {}",
            fields.len()
        ));
    }
    // Each field must contain only digits, *, /, -, and ,
    for (i, field) in fields.iter().enumerate() {
        if field.is_empty() {
            return Err(format!("Cron field {} is empty", i));
        }
        for ch in field.chars() {
            if !ch.is_ascii_digit() && ch != '*' && ch != '/' && ch != '-' && ch != ',' {
                return Err(format!(
                    "Invalid character '{}' in cron field {} ('{}')",
                    ch, i, field
                ));
            }
        }
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// Commands
// ---------------------------------------------------------------------------

pub fn cron_list(state: &AppState) -> Result<Value, String> {
    let store = read_store(state)?;
    serde_json::to_value(store.jobs).map_err(|e| e.to_string())
}

pub fn cron_add(state: &AppState, args: Value) -> Result<Value, String> {
    let name = args
        .get("name")
        .and_then(|v| v.as_str())
        .ok_or("name required")?;
    let name = truncate_str(name, MAX_NAME_BYTES).to_string();

    let schedule_val = args.get("schedule").ok_or("schedule required")?;
    let schedule: CronSchedule = serde_json::from_value(schedule_val.clone())
        .map_err(|e| format!("Invalid schedule: {}", e))?;
    validate_cron_expr(&schedule.expr)?;

    let session_target = args
        .get("sessionTarget")
        .and_then(|v| v.as_str())
        .unwrap_or("main")
        .to_string();

    let wake_mode = args
        .get("wakeMode")
        .and_then(|v| v.as_str())
        .unwrap_or("now")
        .to_string();

    let payload_val = args.get("payload").ok_or("payload required")?;
    let mut payload: CronPayload = serde_json::from_value(payload_val.clone())
        .map_err(|e| format!("Invalid payload: {}", e))?;
    payload.message = truncate_str(&payload.message, MAX_MESSAGE_BYTES).to_string();

    let enabled = args
        .get("enabled")
        .and_then(|v| v.as_bool())
        .unwrap_or(true);

    let job = CronJob {
        id: generate_uuid(),
        name,
        schedule,
        session_target,
        wake_mode,
        payload,
        enabled,
        last_run: None,
        next_run: None,
        status: "pending".to_string(),
        last_error: None,
        created_at: Utc::now().to_rfc3339(),
    };

    let mut store = read_store(state)?;
    store.jobs.push(job.clone());
    write_store(state, &store)?;

    log_action(
        &state.audit_log_path,
        "CRON_ADD",
        &format!("id={} name={}", job.id, job.name),
    );

    serde_json::to_value(job).map_err(|e| e.to_string())
}

pub fn cron_remove(state: &AppState, id: &str) -> Result<(), String> {
    let mut store = read_store(state)?;
    let before = store.jobs.len();
    store.jobs.retain(|j| j.id != id);
    if store.jobs.len() == before {
        return Err(format!("Cron job not found: {}", id));
    }
    write_store(state, &store)?;

    log_action(&state.audit_log_path, "CRON_REMOVE", &format!("id={}", id));

    Ok(())
}

pub fn cron_update(state: &AppState, id: &str, patch: Value) -> Result<Value, String> {
    let mut store = read_store(state)?;
    let job = store
        .jobs
        .iter_mut()
        .find(|j| j.id == id)
        .ok_or_else(|| format!("Cron job not found: {}", id))?;

    if let Some(name) = patch.get("name").and_then(|v| v.as_str()) {
        job.name = truncate_str(name, MAX_NAME_BYTES).to_string();
    }
    if let Some(schedule_val) = patch.get("schedule") {
        let schedule: CronSchedule = serde_json::from_value(schedule_val.clone())
            .map_err(|e| format!("Invalid schedule: {}", e))?;
        validate_cron_expr(&schedule.expr)?;
        job.schedule = schedule;
    }
    if let Some(s) = patch.get("sessionTarget").and_then(|v| v.as_str()) {
        job.session_target = s.to_string();
    }
    if let Some(s) = patch.get("wakeMode").and_then(|v| v.as_str()) {
        job.wake_mode = s.to_string();
    }
    if let Some(payload_val) = patch.get("payload") {
        let mut payload: CronPayload = serde_json::from_value(payload_val.clone())
            .map_err(|e| format!("Invalid payload: {}", e))?;
        payload.message = truncate_str(&payload.message, MAX_MESSAGE_BYTES).to_string();
        job.payload = payload;
    }
    if let Some(enabled) = patch.get("enabled").and_then(|v| v.as_bool()) {
        job.enabled = enabled;
    }

    let updated = job.clone();
    write_store(state, &store)?;

    log_action(
        &state.audit_log_path,
        "CRON_UPDATE",
        &format!("id={}", id),
    );

    serde_json::to_value(updated).map_err(|e| e.to_string())
}

pub fn cron_run(state: &AppState, id: &str) -> Result<String, String> {
    let store = read_store(state)?;
    let _job = store
        .jobs
        .iter()
        .find(|j| j.id == id)
        .ok_or_else(|| format!("Cron job not found: {}", id))?;

    log_action(&state.audit_log_path, "CRON_RUN", &format!("id={}", id));

    Ok("triggered".to_string())
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use crate::state::{AppState, VaultRuntime};
    use std::sync::Mutex;

    fn test_state(dir: &str) -> AppState {
        let audit = format!("{}/audit.log", dir);
        AppState {
            openclaw_dir: dir.to_string(),
            vault_dir: String::new(),
            audit_log_path: audit,
            vault: Mutex::new(VaultRuntime::default()),
        }
    }

    fn add_args(name: &str, expr: &str, message: &str) -> Value {
        serde_json::json!({
            "name": name,
            "schedule": { "kind": "cron", "expr": expr },
            "sessionTarget": "main",
            "wakeMode": "now",
            "payload": { "kind": "agentTurn", "message": message },
            "enabled": true,
        })
    }

    #[test]
    fn list_empty() {
        let tmp = tempfile::tempdir().unwrap();
        let state = test_state(tmp.path().to_str().unwrap());
        let result = cron_list(&state).unwrap();
        let arr = result.as_array().unwrap();
        assert!(arr.is_empty());
    }

    #[test]
    fn add_and_list() {
        let tmp = tempfile::tempdir().unwrap();
        let state = test_state(tmp.path().to_str().unwrap());

        let job_val = cron_add(&state, add_args("Daily check", "0 9 * * *", "run check")).unwrap();
        let job: CronJob = serde_json::from_value(job_val).unwrap();
        assert_eq!(job.name, "Daily check");
        assert_eq!(job.status, "pending");
        assert!(!job.id.is_empty());

        let list = cron_list(&state).unwrap();
        let arr = list.as_array().unwrap();
        assert_eq!(arr.len(), 1);
    }

    #[test]
    fn remove_existing() {
        let tmp = tempfile::tempdir().unwrap();
        let state = test_state(tmp.path().to_str().unwrap());

        let job_val = cron_add(&state, add_args("test", "* * * * *", "msg")).unwrap();
        let id = job_val["id"].as_str().unwrap().to_string();

        cron_remove(&state, &id).unwrap();

        let list = cron_list(&state).unwrap();
        assert!(list.as_array().unwrap().is_empty());
    }

    #[test]
    fn remove_nonexistent_fails() {
        let tmp = tempfile::tempdir().unwrap();
        let state = test_state(tmp.path().to_str().unwrap());
        let result = cron_remove(&state, "no-such-id");
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("not found"));
    }

    #[test]
    fn update_existing() {
        let tmp = tempfile::tempdir().unwrap();
        let state = test_state(tmp.path().to_str().unwrap());

        let job_val = cron_add(&state, add_args("old name", "0 9 * * *", "msg")).unwrap();
        let id = job_val["id"].as_str().unwrap().to_string();

        let patch = serde_json::json!({ "name": "new name", "enabled": false });
        let updated = cron_update(&state, &id, patch).unwrap();
        assert_eq!(updated["name"].as_str().unwrap(), "new name");
        assert!(!updated["enabled"].as_bool().unwrap());
    }

    #[test]
    fn update_nonexistent_fails() {
        let tmp = tempfile::tempdir().unwrap();
        let state = test_state(tmp.path().to_str().unwrap());
        let result = cron_update(&state, "no-such-id", serde_json::json!({}));
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("not found"));
    }

    #[test]
    fn validate_cron_expr_valid() {
        assert!(validate_cron_expr("* * * * *").is_ok());
        assert!(validate_cron_expr("0 15 * * 1-5").is_ok());
        assert!(validate_cron_expr("*/5 0 1,15 * *").is_ok());
    }

    #[test]
    fn validate_cron_expr_wrong_field_count() {
        assert!(validate_cron_expr("* * *").is_err());
        assert!(validate_cron_expr("* * * * * *").is_err());
        assert!(validate_cron_expr("").is_err());
    }

    #[test]
    fn validate_cron_expr_bad_chars() {
        assert!(validate_cron_expr("* * * * abc").is_err());
        assert!(validate_cron_expr("0 0 ? * MON").is_err());
    }

    #[test]
    fn name_truncation() {
        let tmp = tempfile::tempdir().unwrap();
        let state = test_state(tmp.path().to_str().unwrap());

        let long_name = "a".repeat(500);
        let job_val = cron_add(&state, add_args(&long_name, "* * * * *", "msg")).unwrap();
        let name = job_val["name"].as_str().unwrap();
        assert!(name.len() <= MAX_NAME_BYTES);
    }

    #[test]
    fn cron_run_existing() {
        let tmp = tempfile::tempdir().unwrap();
        let state = test_state(tmp.path().to_str().unwrap());

        let job_val = cron_add(&state, add_args("test", "* * * * *", "msg")).unwrap();
        let id = job_val["id"].as_str().unwrap().to_string();

        let status = cron_run(&state, &id).unwrap();
        assert_eq!(status, "triggered");
    }

    #[test]
    fn cron_run_nonexistent_fails() {
        let tmp = tempfile::tempdir().unwrap();
        let state = test_state(tmp.path().to_str().unwrap());
        let result = cron_run(&state, "no-such-id");
        assert!(result.is_err());
    }
}
