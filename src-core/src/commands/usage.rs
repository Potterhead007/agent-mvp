use crate::security::{audit, sanitize};
use crate::state::AppState;
use chrono::{NaiveDate, Utc};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::fs;

// ── Data structures ────────────────────────────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct UserUsage {
    pub user_id: String,
    pub channel: String,
    pub display_name: Option<String>,
    /// Map of "YYYY-MM-DD" → message count for that day.
    pub daily_counts: HashMap<String, u64>,
    pub total_messages: u64,
    pub last_message_at: Option<String>,
    /// Per-user quota override: null = use default, 0 = blocked, -1 = unlimited.
    pub daily_quota: Option<i64>,
    pub created_at: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct QuotaCheck {
    pub allowed: bool,
    pub used: u64,
    pub limit: i64,
    pub resets_at: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct UserSummary {
    pub user_id: String,
    pub channel: String,
    pub display_name: Option<String>,
    pub today_count: u64,
    pub total_messages: u64,
    pub daily_quota: Option<i64>,
    pub last_message_at: Option<String>,
}

// ── Helpers ────────────────────────────────────────────────────────

fn usage_dir(openclaw_dir: &str, channel: &str) -> String {
    format!("{}/usage/{}", openclaw_dir, channel)
}

fn usage_path(openclaw_dir: &str, channel: &str, user_id: &str) -> String {
    format!("{}/usage/{}/{}.json", openclaw_dir, channel, user_id)
}

fn today_key() -> String {
    Utc::now().format("%Y-%m-%d").to_string()
}

fn next_midnight_utc() -> String {
    let tomorrow = Utc::now().date_naive().succ_opt().unwrap_or(Utc::now().date_naive());
    format!("{}T00:00:00Z", tomorrow)
}

fn read_usage(openclaw_dir: &str, channel: &str, user_id: &str) -> Option<UserUsage> {
    let path = usage_path(openclaw_dir, channel, user_id);
    let content = fs::read_to_string(&path).ok()?;
    serde_json::from_str(&content).ok()
}

fn write_usage(openclaw_dir: &str, channel: &str, usage: &UserUsage) -> Result<(), String> {
    let dir = usage_dir(openclaw_dir, channel);
    fs::create_dir_all(&dir).map_err(|e| format!("Failed to create usage dir: {}", e))?;

    let content = serde_json::to_string_pretty(usage)
        .map_err(|e| format!("Failed to serialize usage: {}", e))?;

    let final_path = usage_path(openclaw_dir, channel, &usage.user_id);
    let tmp_path = format!("{}.tmp", final_path);
    fs::write(&tmp_path, &content).map_err(|e| format!("Failed to write usage: {}", e))?;
    fs::rename(&tmp_path, &final_path).map_err(|e| format!("Failed to finalize usage: {}", e))?;
    Ok(())
}

/// Prune daily_counts entries older than 90 days.
fn prune_old_entries(usage: &mut UserUsage) {
    let cutoff = Utc::now()
        .date_naive()
        .checked_sub_days(chrono::Days::new(90));
    if let Some(cutoff_date) = cutoff {
        usage
            .daily_counts
            .retain(|key, _| match NaiveDate::parse_from_str(key, "%Y-%m-%d") {
                Ok(d) => d >= cutoff_date,
                Err(_) => false,
            });
    }
}

fn get_default_quota(openclaw_dir: &str) -> i64 {
    let config_path = format!("{}/openclaw.json", openclaw_dir);
    if let Ok(content) = fs::read_to_string(&config_path) {
        if let Ok(config) = serde_json::from_str::<serde_json::Value>(&content) {
            if let Some(q) = config
                .pointer("/settings/quotas/defaultDaily")
                .and_then(|v| v.as_i64())
            {
                return q;
            }
        }
    }
    100
}

fn compute_quota_check(usage: &UserUsage, default_quota: i64) -> QuotaCheck {
    let today = today_key();
    let used = usage.daily_counts.get(&today).copied().unwrap_or(0);
    let limit = usage.daily_quota.unwrap_or(default_quota);
    let allowed = match limit {
        -1 => true,  // unlimited
        0 => false,  // blocked
        n => (used as i64) < n,
    };
    QuotaCheck {
        allowed,
        used,
        limit,
        resets_at: next_midnight_utc(),
    }
}

// ── Commands ───────────────────────────────────────────────────────

pub fn get_user_usage(
    state: &AppState,
    channel: String,
    user_id: String,
) -> Result<UserUsage, String> {
    sanitize::validate_id(&channel)?;
    sanitize::validate_id(&user_id)?;

    read_usage(&state.openclaw_dir, &channel, &user_id)
        .ok_or_else(|| format!("No usage record for {}/{}", channel, user_id))
}

pub fn list_channel_users(
    state: &AppState,
    channel: String,
) -> Result<Vec<UserSummary>, String> {
    sanitize::validate_id(&channel)?;

    let dir = usage_dir(&state.openclaw_dir, &channel);
    let entries = match fs::read_dir(&dir) {
        Ok(e) => e,
        Err(_) => return Ok(vec![]),
    };

    let today = today_key();
    let mut users: Vec<UserSummary> = Vec::new();

    for entry in entries.flatten() {
        let path = entry.path();
        if path.extension().and_then(|e| e.to_str()) != Some("json") {
            continue;
        }
        if let Ok(content) = fs::read_to_string(&path) {
            if let Ok(usage) = serde_json::from_str::<UserUsage>(&content) {
                users.push(UserSummary {
                    user_id: usage.user_id,
                    channel: usage.channel,
                    display_name: usage.display_name,
                    today_count: usage.daily_counts.get(&today).copied().unwrap_or(0),
                    total_messages: usage.total_messages,
                    daily_quota: usage.daily_quota,
                    last_message_at: usage.last_message_at,
                });
            }
        }
    }

    users.sort_by(|a, b| b.total_messages.cmp(&a.total_messages));
    Ok(users)
}

pub fn set_user_quota(
    state: &AppState,
    channel: String,
    user_id: String,
    daily_quota: Option<i64>,
) -> Result<(), String> {
    sanitize::validate_id(&channel)?;
    sanitize::validate_id(&user_id)?;

    let mut usage = read_usage(&state.openclaw_dir, &channel, &user_id)
        .ok_or_else(|| format!("No usage record for {}/{}", channel, user_id))?;

    let old = usage.daily_quota;
    usage.daily_quota = daily_quota;
    write_usage(&state.openclaw_dir, &channel, &usage)?;

    audit::log_action(
        &state.audit_log_path,
        "QUOTA_SET",
        &format!(
            "channel={} user={} old={:?} new={:?}",
            channel, user_id, old, daily_quota
        ),
    );
    Ok(())
}

pub fn set_default_quota(
    state: &AppState,
    daily_quota: i64,
) -> Result<(), String> {
    let config_path = format!("{}/openclaw.json", state.openclaw_dir);
    let content = fs::read_to_string(&config_path)
        .map_err(|e| format!("Failed to read config: {}", e))?;
    let mut config: serde_json::Value =
        serde_json::from_str(&content).map_err(|e| format!("Invalid config JSON: {}", e))?;

    // Ensure settings.quotas exists
    let settings = config
        .as_object_mut()
        .ok_or("Config is not an object")?
        .entry("settings")
        .or_insert_with(|| serde_json::json!({}));
    let quotas = settings
        .as_object_mut()
        .ok_or("settings is not an object")?
        .entry("quotas")
        .or_insert_with(|| serde_json::json!({}));
    quotas
        .as_object_mut()
        .ok_or("quotas is not an object")?
        .insert("defaultDaily".to_string(), serde_json::json!(daily_quota));

    // Atomic write with backup
    let serialized = serde_json::to_string_pretty(&config)
        .map_err(|e| format!("Failed to serialize config: {}", e))?;

    let backup_path = format!("{}/openclaw.json.bak", state.openclaw_dir);
    let _ = fs::copy(&config_path, &backup_path);

    let tmp_path = format!("{}/openclaw.json.tmp", state.openclaw_dir);
    fs::write(&tmp_path, &serialized)
        .map_err(|e| format!("Failed to write temp config: {}", e))?;
    fs::rename(&tmp_path, &config_path)
        .map_err(|e| format!("Failed to finalize config: {}", e))?;

    audit::log_action(
        &state.audit_log_path,
        "DEFAULT_QUOTA_SET",
        &format!("defaultDaily={}", daily_quota),
    );
    Ok(())
}

pub fn record_usage(
    state: &AppState,
    channel: String,
    user_id: String,
    display_name: Option<String>,
) -> Result<QuotaCheck, String> {
    sanitize::validate_id(&channel)?;
    sanitize::validate_id(&user_id)?;

    let now = Utc::now().to_rfc3339();
    let today = today_key();
    let default_quota = get_default_quota(&state.openclaw_dir);

    let mut usage = read_usage(&state.openclaw_dir, &channel, &user_id).unwrap_or_else(|| {
        UserUsage {
            user_id: user_id.clone(),
            channel: channel.clone(),
            display_name: display_name.clone(),
            daily_counts: HashMap::new(),
            total_messages: 0,
            last_message_at: None,
            daily_quota: None,
            created_at: now.clone(),
        }
    });

    // Update display name if provided
    if display_name.is_some() {
        usage.display_name = display_name;
    }

    // Check quota before incrementing
    let check = compute_quota_check(&usage, default_quota);
    if !check.allowed {
        return Ok(check);
    }

    // Increment
    *usage.daily_counts.entry(today).or_insert(0) += 1;
    usage.total_messages += 1;
    usage.last_message_at = Some(now);

    // Prune old entries
    prune_old_entries(&mut usage);

    write_usage(&state.openclaw_dir, &channel, &usage)?;

    // Return updated check
    Ok(compute_quota_check(&usage, default_quota))
}

pub fn check_quota(
    state: &AppState,
    channel: String,
    user_id: String,
) -> Result<QuotaCheck, String> {
    sanitize::validate_id(&channel)?;
    sanitize::validate_id(&user_id)?;

    let default_quota = get_default_quota(&state.openclaw_dir);

    let usage = read_usage(&state.openclaw_dir, &channel, &user_id).unwrap_or_else(|| {
        UserUsage {
            user_id: user_id.clone(),
            channel: channel.clone(),
            display_name: None,
            daily_counts: HashMap::new(),
            total_messages: 0,
            last_message_at: None,
            daily_quota: None,
            created_at: Utc::now().to_rfc3339(),
        }
    });

    Ok(compute_quota_check(&usage, default_quota))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_usage(user_id: &str, channel: &str) -> UserUsage {
        UserUsage {
            user_id: user_id.to_string(),
            channel: channel.to_string(),
            display_name: Some("Test User".to_string()),
            daily_counts: HashMap::new(),
            total_messages: 0,
            last_message_at: None,
            daily_quota: None,
            created_at: Utc::now().to_rfc3339(),
        }
    }

    #[test]
    fn write_and_read_usage() {
        let tmp = tempfile::tempdir().unwrap();
        let dir = tmp.path().to_str().unwrap();

        let mut usage = make_usage("user1", "telegram");
        usage.daily_counts.insert(today_key(), 5);
        usage.total_messages = 5;

        write_usage(dir, "telegram", &usage).unwrap();
        let loaded = read_usage(dir, "telegram", "user1").unwrap();
        assert_eq!(loaded.total_messages, 5);
        assert_eq!(loaded.daily_counts.get(&today_key()), Some(&5));
    }

    #[test]
    fn compute_quota_check_default() {
        let usage = make_usage("user1", "telegram");
        let check = compute_quota_check(&usage, 100);
        assert!(check.allowed);
        assert_eq!(check.used, 0);
        assert_eq!(check.limit, 100);
    }

    #[test]
    fn compute_quota_check_blocked() {
        let mut usage = make_usage("user1", "telegram");
        usage.daily_quota = Some(0);
        let check = compute_quota_check(&usage, 100);
        assert!(!check.allowed);
        assert_eq!(check.limit, 0);
    }

    #[test]
    fn compute_quota_check_unlimited() {
        let mut usage = make_usage("user1", "telegram");
        usage.daily_quota = Some(-1);
        usage.daily_counts.insert(today_key(), 9999);
        let check = compute_quota_check(&usage, 100);
        assert!(check.allowed);
        assert_eq!(check.limit, -1);
    }

    #[test]
    fn compute_quota_check_at_limit() {
        let mut usage = make_usage("user1", "telegram");
        usage.daily_counts.insert(today_key(), 100);
        let check = compute_quota_check(&usage, 100);
        assert!(!check.allowed);
        assert_eq!(check.used, 100);
    }

    #[test]
    fn prune_removes_old_entries() {
        let mut usage = make_usage("user1", "telegram");
        usage.daily_counts.insert("2020-01-01".to_string(), 50);
        usage.daily_counts.insert(today_key(), 10);
        prune_old_entries(&mut usage);
        assert!(!usage.daily_counts.contains_key("2020-01-01"));
        assert!(usage.daily_counts.contains_key(&today_key()));
    }

    #[test]
    fn get_default_quota_returns_100_when_missing() {
        let tmp = tempfile::tempdir().unwrap();
        assert_eq!(get_default_quota(tmp.path().to_str().unwrap()), 100);
    }

    #[test]
    fn get_default_quota_reads_from_config() {
        let tmp = tempfile::tempdir().unwrap();
        let config = serde_json::json!({
            "settings": { "quotas": { "defaultDaily": 50 } }
        });
        fs::write(
            tmp.path().join("openclaw.json"),
            serde_json::to_string(&config).unwrap(),
        )
        .unwrap();
        assert_eq!(get_default_quota(tmp.path().to_str().unwrap()), 50);
    }
}
