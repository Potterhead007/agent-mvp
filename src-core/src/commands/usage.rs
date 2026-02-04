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

    #[test]
    fn get_default_quota_ignores_malformed_json() {
        let tmp = tempfile::tempdir().unwrap();
        fs::write(tmp.path().join("openclaw.json"), "not json").unwrap();
        assert_eq!(get_default_quota(tmp.path().to_str().unwrap()), 100);
    }

    #[test]
    fn get_default_quota_ignores_missing_quotas_key() {
        let tmp = tempfile::tempdir().unwrap();
        let config = serde_json::json!({ "settings": {} });
        fs::write(
            tmp.path().join("openclaw.json"),
            serde_json::to_string(&config).unwrap(),
        ).unwrap();
        assert_eq!(get_default_quota(tmp.path().to_str().unwrap()), 100);
    }

    // -----------------------------------------------------------------------
    // compute_quota_check boundary cases
    // -----------------------------------------------------------------------

    #[test]
    fn compute_quota_check_one_below_limit() {
        let mut usage = make_usage("user1", "telegram");
        usage.daily_counts.insert(today_key(), 99);
        let check = compute_quota_check(&usage, 100);
        assert!(check.allowed);
        assert_eq!(check.used, 99);
    }

    #[test]
    fn compute_quota_check_per_user_quota_overrides_default() {
        let mut usage = make_usage("user1", "telegram");
        usage.daily_quota = Some(10);
        usage.daily_counts.insert(today_key(), 10);
        let check = compute_quota_check(&usage, 100);
        assert!(!check.allowed);
        assert_eq!(check.limit, 10);
    }

    #[test]
    fn compute_quota_check_negative_one_is_unlimited() {
        let mut usage = make_usage("user1", "telegram");
        usage.daily_quota = Some(-1);
        usage.daily_counts.insert(today_key(), u64::MAX);
        let check = compute_quota_check(&usage, 100);
        assert!(check.allowed);
    }

    #[test]
    fn compute_quota_check_zero_is_blocked_even_with_no_usage() {
        let mut usage = make_usage("user1", "telegram");
        usage.daily_quota = Some(0);
        let check = compute_quota_check(&usage, 100);
        assert!(!check.allowed);
        assert_eq!(check.used, 0);
    }

    // -----------------------------------------------------------------------
    // prune_old_entries edge cases
    // -----------------------------------------------------------------------

    #[test]
    fn prune_removes_malformed_date_keys() {
        let mut usage = make_usage("user1", "telegram");
        usage.daily_counts.insert("not-a-date".to_string(), 5);
        usage.daily_counts.insert(today_key(), 10);
        prune_old_entries(&mut usage);
        assert!(!usage.daily_counts.contains_key("not-a-date"));
        assert!(usage.daily_counts.contains_key(&today_key()));
    }

    #[test]
    fn prune_keeps_recent_entries() {
        let mut usage = make_usage("user1", "telegram");
        let yesterday = (chrono::Utc::now() - chrono::Duration::days(1))
            .format("%Y-%m-%d").to_string();
        usage.daily_counts.insert(yesterday.clone(), 5);
        usage.daily_counts.insert(today_key(), 10);
        prune_old_entries(&mut usage);
        assert!(usage.daily_counts.contains_key(&yesterday));
        assert!(usage.daily_counts.contains_key(&today_key()));
    }

    #[test]
    fn prune_removes_exactly_at_90_day_boundary() {
        let mut usage = make_usage("user1", "telegram");
        let exactly_90 = (chrono::Utc::now() - chrono::Duration::days(90))
            .format("%Y-%m-%d").to_string();
        let day_91 = (chrono::Utc::now() - chrono::Duration::days(91))
            .format("%Y-%m-%d").to_string();
        usage.daily_counts.insert(exactly_90.clone(), 5);
        usage.daily_counts.insert(day_91.clone(), 3);
        usage.daily_counts.insert(today_key(), 10);
        prune_old_entries(&mut usage);
        // 90 days ago should be kept (>= cutoff)
        assert!(usage.daily_counts.contains_key(&exactly_90));
        // 91 days ago should be pruned
        assert!(!usage.daily_counts.contains_key(&day_91));
    }

    // -----------------------------------------------------------------------
    // record_usage integration
    // -----------------------------------------------------------------------

    fn make_test_state(tmp: &std::path::Path) -> crate::state::AppState {
        let audit = tmp.join("audit.log");
        let _ = fs::write(&audit, "");
        crate::state::AppState {
            openclaw_dir: tmp.to_str().unwrap().to_string(),
            vault_dir: String::new(),
            audit_log_path: audit.to_str().unwrap().to_string(),
            vault: std::sync::Mutex::new(crate::state::VaultRuntime::default()),
        }
    }

    #[test]
    fn record_usage_creates_new_user() {
        let tmp = tempfile::tempdir().unwrap();
        let state = make_test_state(tmp.path());

        let check = record_usage(
            &state,
            "telegram".to_string(),
            "user1".to_string(),
            Some("Alice".to_string()),
        ).unwrap();

        assert!(check.allowed);
        assert_eq!(check.used, 1);
        assert_eq!(check.limit, 100); // default quota

        // Verify file was written
        let usage = read_usage(tmp.path().to_str().unwrap(), "telegram", "user1").unwrap();
        assert_eq!(usage.total_messages, 1);
        assert_eq!(usage.display_name, Some("Alice".to_string()));
    }

    #[test]
    fn record_usage_increments_existing() {
        let tmp = tempfile::tempdir().unwrap();
        let state = make_test_state(tmp.path());

        record_usage(&state, "telegram".to_string(), "user1".to_string(), None).unwrap();
        record_usage(&state, "telegram".to_string(), "user1".to_string(), None).unwrap();
        let check = record_usage(&state, "telegram".to_string(), "user1".to_string(), None).unwrap();

        assert_eq!(check.used, 3);

        let usage = read_usage(tmp.path().to_str().unwrap(), "telegram", "user1").unwrap();
        assert_eq!(usage.total_messages, 3);
    }

    #[test]
    fn record_usage_stops_at_quota() {
        let tmp = tempfile::tempdir().unwrap();
        let state = make_test_state(tmp.path());

        // Set low default quota
        let config = serde_json::json!({
            "settings": { "quotas": { "defaultDaily": 2 } }
        });
        fs::write(
            tmp.path().join("openclaw.json"),
            serde_json::to_string(&config).unwrap(),
        ).unwrap();

        // Quota check happens BEFORE increment, but the RETURNED check is
        // computed AFTER increment. So:
        // Call 1: pre-check used=0 < 2 → allowed, increments to 1
        //   Returned: allowed=true (1 < 2), used=1
        let c1 = record_usage(&state, "telegram".to_string(), "user1".to_string(), None).unwrap();
        assert!(c1.allowed);
        assert_eq!(c1.used, 1);

        // Call 2: pre-check used=1 < 2 → allowed, increments to 2
        //   Returned: allowed=false (2 is NOT < 2), used=2
        //   The message WAS recorded, but the returned check signals "quota exhausted"
        let c2 = record_usage(&state, "telegram".to_string(), "user1".to_string(), None).unwrap();
        assert_eq!(c2.used, 2);
        // c2.allowed is false because returned check is post-increment

        // Call 3: pre-check used=2 >= 2 → rejected, count stays at 2
        let c3 = record_usage(&state, "telegram".to_string(), "user1".to_string(), None).unwrap();
        assert!(!c3.allowed);
        assert_eq!(c3.used, 2);

        // Verify total: exactly 2 messages were actually recorded
        let usage = read_usage(tmp.path().to_str().unwrap(), "telegram", "user1").unwrap();
        assert_eq!(usage.total_messages, 2);
    }

    #[test]
    fn record_usage_updates_display_name() {
        let tmp = tempfile::tempdir().unwrap();
        let state = make_test_state(tmp.path());

        record_usage(&state, "telegram".to_string(), "user1".to_string(), Some("Old".to_string())).unwrap();
        record_usage(&state, "telegram".to_string(), "user1".to_string(), Some("New".to_string())).unwrap();

        let usage = read_usage(tmp.path().to_str().unwrap(), "telegram", "user1").unwrap();
        assert_eq!(usage.display_name, Some("New".to_string()));
    }

    #[test]
    fn record_usage_rejects_invalid_channel() {
        let tmp = tempfile::tempdir().unwrap();
        let state = make_test_state(tmp.path());
        let result = record_usage(&state, "../escape".to_string(), "user1".to_string(), None);
        assert!(result.is_err());
    }

    #[test]
    fn record_usage_rejects_invalid_user_id() {
        let tmp = tempfile::tempdir().unwrap();
        let state = make_test_state(tmp.path());
        let result = record_usage(&state, "telegram".to_string(), "../../etc".to_string(), None);
        assert!(result.is_err());
    }

    // -----------------------------------------------------------------------
    // check_quota
    // -----------------------------------------------------------------------

    #[test]
    fn check_quota_new_user_allowed() {
        let tmp = tempfile::tempdir().unwrap();
        let state = make_test_state(tmp.path());

        let check = check_quota(&state, "telegram".to_string(), "newuser".to_string()).unwrap();
        assert!(check.allowed);
        assert_eq!(check.used, 0);
        assert_eq!(check.limit, 100);
    }

    #[test]
    fn check_quota_rejects_invalid_ids() {
        let tmp = tempfile::tempdir().unwrap();
        let state = make_test_state(tmp.path());
        assert!(check_quota(&state, "".to_string(), "user".to_string()).is_err());
        assert!(check_quota(&state, "ch".to_string(), "".to_string()).is_err());
    }

    // -----------------------------------------------------------------------
    // get_user_usage
    // -----------------------------------------------------------------------

    #[test]
    fn get_user_usage_returns_error_for_missing_user() {
        let tmp = tempfile::tempdir().unwrap();
        let state = make_test_state(tmp.path());
        let result = get_user_usage(&state, "telegram".to_string(), "nobody".to_string());
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("No usage record"));
    }

    #[test]
    fn get_user_usage_returns_existing_user() {
        let tmp = tempfile::tempdir().unwrap();
        let state = make_test_state(tmp.path());

        record_usage(&state, "telegram".to_string(), "user1".to_string(), None).unwrap();
        let usage = get_user_usage(&state, "telegram".to_string(), "user1".to_string()).unwrap();
        assert_eq!(usage.total_messages, 1);
    }

    // -----------------------------------------------------------------------
    // list_channel_users
    // -----------------------------------------------------------------------

    #[test]
    fn list_channel_users_empty_channel() {
        let tmp = tempfile::tempdir().unwrap();
        let state = make_test_state(tmp.path());
        let users = list_channel_users(&state, "telegram".to_string()).unwrap();
        assert!(users.is_empty());
    }

    #[test]
    fn list_channel_users_returns_sorted_by_messages() {
        let tmp = tempfile::tempdir().unwrap();
        let state = make_test_state(tmp.path());

        // user1: 1 message, user2: 3 messages
        record_usage(&state, "telegram".to_string(), "user1".to_string(), Some("Alice".to_string())).unwrap();
        record_usage(&state, "telegram".to_string(), "user2".to_string(), Some("Bob".to_string())).unwrap();
        record_usage(&state, "telegram".to_string(), "user2".to_string(), None).unwrap();
        record_usage(&state, "telegram".to_string(), "user2".to_string(), None).unwrap();

        let users = list_channel_users(&state, "telegram".to_string()).unwrap();
        assert_eq!(users.len(), 2);
        // user2 (3 msgs) should be first
        assert_eq!(users[0].user_id, "user2");
        assert_eq!(users[0].total_messages, 3);
        assert_eq!(users[1].user_id, "user1");
        assert_eq!(users[1].total_messages, 1);
    }

    #[test]
    fn list_channel_users_rejects_invalid_channel() {
        let tmp = tempfile::tempdir().unwrap();
        let state = make_test_state(tmp.path());
        assert!(list_channel_users(&state, "../escape".to_string()).is_err());
    }

    // -----------------------------------------------------------------------
    // set_user_quota
    // -----------------------------------------------------------------------

    #[test]
    fn set_user_quota_overrides_default() {
        let tmp = tempfile::tempdir().unwrap();
        let state = make_test_state(tmp.path());

        record_usage(&state, "telegram".to_string(), "user1".to_string(), None).unwrap();
        set_user_quota(&state, "telegram".to_string(), "user1".to_string(), Some(5)).unwrap();

        let check = check_quota(&state, "telegram".to_string(), "user1".to_string()).unwrap();
        assert_eq!(check.limit, 5);
    }

    #[test]
    fn set_user_quota_none_reverts_to_default() {
        let tmp = tempfile::tempdir().unwrap();
        let state = make_test_state(tmp.path());

        record_usage(&state, "telegram".to_string(), "user1".to_string(), None).unwrap();
        set_user_quota(&state, "telegram".to_string(), "user1".to_string(), Some(5)).unwrap();
        set_user_quota(&state, "telegram".to_string(), "user1".to_string(), None).unwrap();

        let check = check_quota(&state, "telegram".to_string(), "user1".to_string()).unwrap();
        assert_eq!(check.limit, 100); // default
    }

    #[test]
    fn set_user_quota_fails_for_missing_user() {
        let tmp = tempfile::tempdir().unwrap();
        let state = make_test_state(tmp.path());
        let result = set_user_quota(&state, "telegram".to_string(), "nobody".to_string(), Some(10));
        assert!(result.is_err());
    }

    // -----------------------------------------------------------------------
    // set_default_quota
    // -----------------------------------------------------------------------

    #[test]
    fn set_default_quota_writes_to_config() {
        let tmp = tempfile::tempdir().unwrap();
        let state = make_test_state(tmp.path());

        // Create minimal config
        fs::write(tmp.path().join("openclaw.json"), "{}").unwrap();

        set_default_quota(&state, 42).unwrap();

        let content = fs::read_to_string(tmp.path().join("openclaw.json")).unwrap();
        let config: serde_json::Value = serde_json::from_str(&content).unwrap();
        assert_eq!(config["settings"]["quotas"]["defaultDaily"], 42);
    }

    #[test]
    fn set_default_quota_preserves_existing_settings() {
        let tmp = tempfile::tempdir().unwrap();
        let state = make_test_state(tmp.path());

        let config = serde_json::json!({
            "settings": {
                "gateway": { "port": 18790 },
                "quotas": { "otherField": true }
            }
        });
        fs::write(
            tmp.path().join("openclaw.json"),
            serde_json::to_string(&config).unwrap(),
        ).unwrap();

        set_default_quota(&state, 200).unwrap();

        let content = fs::read_to_string(tmp.path().join("openclaw.json")).unwrap();
        let result: serde_json::Value = serde_json::from_str(&content).unwrap();
        assert_eq!(result["settings"]["gateway"]["port"], 18790);
        assert_eq!(result["settings"]["quotas"]["otherField"], true);
        assert_eq!(result["settings"]["quotas"]["defaultDaily"], 200);
    }

    #[test]
    fn set_default_quota_creates_backup() {
        let tmp = tempfile::tempdir().unwrap();
        let state = make_test_state(tmp.path());

        fs::write(tmp.path().join("openclaw.json"), r#"{"original": true}"#).unwrap();
        set_default_quota(&state, 50).unwrap();

        let backup = fs::read_to_string(tmp.path().join("openclaw.json.bak")).unwrap();
        assert!(backup.contains("original"));
    }

    #[test]
    fn set_default_quota_fails_without_config() {
        let tmp = tempfile::tempdir().unwrap();
        let state = make_test_state(tmp.path());
        let result = set_default_quota(&state, 50);
        assert!(result.is_err());
    }
}
