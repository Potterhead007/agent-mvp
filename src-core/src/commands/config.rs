use crate::security::audit;
use crate::state::AppState;
use serde_json::Value;
use std::fs;

pub fn read_config(state: &AppState) -> Result<Value, String> {
    let config_path = state.desktop_config_path();
    match fs::read_to_string(&config_path) {
        Ok(content) => {
            let config: Value =
                serde_json::from_str(&content).map_err(|e| format!("Invalid JSON: {}", e))?;
            Ok(config)
        }
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
            // Config doesn't exist yet — create default and return it
            ensure_desktop_config(state)?;
            let content = fs::read_to_string(&config_path)
                .map_err(|e| format!("Failed to read config after creating default: {}", e))?;
            let config: Value =
                serde_json::from_str(&content).map_err(|e| format!("Invalid JSON: {}", e))?;
            Ok(config)
        }
        Err(e) => Err(format!("Failed to read config: {}", e)),
    }
}

pub fn write_config(state: &AppState, config: Value) -> Result<(), String> {
    let config_path = state.desktop_config_path();
    let content = serde_json::to_string_pretty(&config)
        .map_err(|e| format!("Failed to serialize config: {}", e))?;

    if std::path::Path::new(&config_path).exists() {
        let backup_path = format!("{}.bak", config_path);
        fs::copy(&config_path, &backup_path)
            .map_err(|e| format!("Failed to create config backup: {}", e))?;
    }

    let tmp_path = format!("{}.tmp", config_path);
    fs::write(&tmp_path, &content)
        .map_err(|e| format!("Failed to write temp config: {}", e))?;
    fs::rename(&tmp_path, &config_path)
        .map_err(|e| format!("Failed to finalize config write: {}", e))?;

    audit::log_action(&state.audit_log_path, "CONFIG_WRITE", "desktop config updated");
    Ok(())
}

pub fn validate_config(config: Value) -> Result<String, String> {
    let agents = config
        .get("agents")
        .ok_or_else(|| "Missing required key: agents".to_string())?;
    if !agents.is_object() {
        return Err("agents must be an object".to_string());
    }
    match agents.get("list") {
        Some(v) if v.is_array() => {}
        Some(_) => return Err("agents.list must be an array".to_string()),
        None => return Err("agents.list is required".to_string()),
    }
    match agents.get("defaults") {
        Some(v) if v.is_object() => {}
        Some(_) => return Err("agents.defaults must be an object".to_string()),
        None => return Err("agents.defaults is required".to_string()),
    }

    let settings = config
        .get("settings")
        .ok_or_else(|| "Missing required key: settings".to_string())?;
    if !settings.is_object() {
        return Err("settings must be an object".to_string());
    }

    let gateway = settings
        .get("gateway")
        .ok_or_else(|| "settings.gateway is required".to_string())?;
    if !gateway.is_object() {
        return Err("settings.gateway must be an object".to_string());
    }
    for key in ["url", "port", "wsUrl"] {
        if gateway.get(key).is_none() {
            return Err(format!("settings.gateway.{} is required", key));
        }
    }

    if let Some(url) = gateway["url"].as_str() {
        if !url.starts_with("http://") && !url.starts_with("https://") {
            return Err("settings.gateway.url must start with http:// or https://".to_string());
        }
    }
    if let Some(ws_url) = gateway["wsUrl"].as_str() {
        if !ws_url.starts_with("ws://") && !ws_url.starts_with("wss://") {
            return Err("settings.gateway.wsUrl must start with ws:// or wss://".to_string());
        }
    }

    if let Some(port) = gateway.get("port") {
        match port.as_u64() {
            Some(p) if (1..=65535).contains(&p) => {}
            _ => return Err("settings.gateway.port must be a number between 1 and 65535".to_string()),
        }
    }

    let security = settings
        .get("security")
        .ok_or_else(|| "settings.security is required".to_string())?;
    if !security.is_object() {
        return Err("settings.security must be an object".to_string());
    }
    for key in ["sandboxMode", "networkIsolation", "auditLogging"] {
        if security.get(key).is_none() {
            return Err(format!("settings.security.{} is required", key));
        }
    }

    if let Some(services) = settings.get("services") {
        if let Some(pg_port) = services.get("postgresPort") {
            match pg_port.as_u64() {
                Some(p) if (1..=65535).contains(&p) => {}
                _ => return Err("settings.services.postgresPort must be a number between 1 and 65535".to_string()),
            }
        }
        if let Some(redis_port) = services.get("redisPort") {
            match redis_port.as_u64() {
                Some(p) if (1..=65535).contains(&p) => {}
                _ => return Err("settings.services.redisPort must be a number between 1 and 65535".to_string()),
            }
        }
    }

    Ok("valid".to_string())
}

pub fn get_openclaw_dir(state: &AppState) -> String {
    state.openclaw_dir.clone()
}

pub fn restore_config_backup(state: &AppState) -> Result<(), String> {
    let config_path = state.desktop_config_path();
    let backup_path = format!("{}.bak", config_path);

    if !std::path::Path::new(&backup_path).exists() {
        return Err("No config backup found".to_string());
    }

    let backup_content = fs::read_to_string(&backup_path)
        .map_err(|e| format!("Failed to read backup: {}", e))?;
    let backup_json: Value = serde_json::from_str(&backup_content)
        .map_err(|e| format!("Backup is not valid JSON: {}", e))?;
    if backup_json.get("agents").is_none() || backup_json.get("settings").is_none() {
        return Err("Backup is missing required keys (agents, settings)".to_string());
    }

    fs::copy(&backup_path, &config_path)
        .map_err(|e| format!("Failed to restore config: {}", e))?;

    audit::log_action(
        &state.audit_log_path,
        "CONFIG_RESTORE",
        "Restored config from backup",
    );
    Ok(())
}

pub fn ensure_desktop_config(state: &AppState) -> Result<(), String> {
    let config_path = state.desktop_config_path();
    if std::path::Path::new(&config_path).exists() {
        return Ok(());
    }

    // In non-bridge mode, just delegate to the existing default config logic.
    if !crate::commands::health::is_bridge_mode() {
        return ensure_default_config(&state.openclaw_dir);
    }

    // Bridge mode: create a desktop-format config seeded from the gateway config
    // if available, otherwise create a fresh default.
    let gw_config_path = format!("{}/openclaw.json", state.openclaw_dir);
    let desktop_config = if let Ok(content) = fs::read_to_string(&gw_config_path) {
        if let Ok(gw) = serde_json::from_str::<serde_json::Value>(&content) {
            // Seed desktop config from gateway config data
            let agents_list = gw.get("agents")
                .and_then(|a| a.get("list"))
                .cloned()
                .unwrap_or_else(|| serde_json::json!([]));

            let channels = gw.get("channels").cloned().unwrap_or_else(|| serde_json::json!({
                "telegram": { "enabled": false },
                "slack": { "enabled": false },
                "discord": { "enabled": false },
            }));

            let gw_port = gw.get("gateway")
                .and_then(|g| g.get("port"))
                .and_then(|p| p.as_u64())
                .unwrap_or(crate::constants::DEFAULT_GATEWAY_PORT as u64);

            serde_json::json!({
                "agents": {
                    "list": agents_list,
                    "defaults": gw.get("agents").and_then(|a| a.get("defaults")).cloned()
                        .unwrap_or_else(|| serde_json::json!({
                            "model": "claude-sonnet-4-20250514",
                            "sandbox": { "mode": "docker", "timeout": 30000, "memoryLimit": "512m" }
                        }))
                },
                "settings": {
                    "gateway": {
                        "url": format!("http://localhost:{}", gw_port),
                        "port": gw_port,
                        "wsUrl": format!("ws://localhost:{}", gw_port),
                    },
                    "security": { "sandboxMode": "docker", "networkIsolation": true, "auditLogging": true },
                    "services": { "postgresPort": 5433, "redisPort": 6380 },
                    "desktop": { "dockerComposePath": "~/agent-mvp", "healthCheckIntervalMs": 10000 },
                    "channels": channels,
                },
                "automation": { "cron": [], "webhooks": [] },
            })
        } else {
            default_desktop_config()
        }
    } else {
        default_desktop_config()
    };

    let content = serde_json::to_string_pretty(&desktop_config)
        .map_err(|e| format!("Failed to serialize desktop config: {}", e))?;
    fs::write(&config_path, content)
        .map_err(|e| format!("Failed to write desktop config: {}", e))?;
    Ok(())
}

fn default_desktop_config() -> serde_json::Value {
    serde_json::json!({
        "agents": {
            "list": [],
            "defaults": {
                "model": "claude-sonnet-4-20250514",
                "sandbox": { "mode": "docker", "timeout": 30000, "memoryLimit": "512m" }
            }
        },
        "settings": {
            "gateway": {
                "url": format!("http://localhost:{}", crate::constants::DEFAULT_GATEWAY_PORT),
                "port": crate::constants::DEFAULT_GATEWAY_PORT,
                "wsUrl": format!("ws://localhost:{}", crate::constants::DEFAULT_GATEWAY_PORT),
            },
            "security": { "sandboxMode": "docker", "networkIsolation": true, "auditLogging": true },
            "services": { "postgresPort": 5433, "redisPort": 6380 },
            "desktop": { "dockerComposePath": "~/agent-mvp", "healthCheckIntervalMs": 10000 },
            "channels": {
                "telegram": { "enabled": false, "allowDMs": true, "allowGroups": false },
                "slack": { "enabled": false },
                "discord": { "enabled": false }
            }
        },
        "automation": { "cron": [], "webhooks": [] }
    })
}

pub fn ensure_default_config(openclaw_dir: &str) -> Result<(), String> {
    let config_path = format!("{}/openclaw.json", openclaw_dir);
    if std::path::Path::new(&config_path).exists() {
        return Ok(());
    }

    for d in [
        openclaw_dir.to_string(),
        format!("{}/agents", openclaw_dir),
        format!("{}/skills", openclaw_dir),
    ] {
        fs::create_dir_all(&d)
            .map_err(|e| format!("Failed to create directory {}: {}", d, e))?;
    }

    let content = serde_json::to_string_pretty(&default_desktop_config())
        .map_err(|e| format!("Failed to serialize default config: {}", e))?;
    fs::write(&config_path, content)
        .map_err(|e| format!("Failed to write default config: {}", e))?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ensure_default_config_creates_valid_json() {
        let tmp = tempfile::tempdir().unwrap();
        let dir = tmp.path().join("openclaw");
        let dir_str = dir.to_str().unwrap();
        ensure_default_config(dir_str).unwrap();
        let config_path = dir.join("openclaw.json");
        assert!(config_path.exists());
        let content = fs::read_to_string(&config_path).unwrap();
        let config: serde_json::Value = serde_json::from_str(&content).unwrap();
        assert!(config.get("agents").is_some());
        assert!(config.get("settings").is_some());
    }

    #[test]
    fn ensure_default_config_does_not_overwrite_existing() {
        let tmp = tempfile::tempdir().unwrap();
        let dir = tmp.path().join("openclaw");
        fs::create_dir_all(&dir).unwrap();
        let config_path = dir.join("openclaw.json");
        fs::write(&config_path, r#"{"custom": true}"#).unwrap();
        ensure_default_config(dir.to_str().unwrap()).unwrap();
        let content = fs::read_to_string(&config_path).unwrap();
        assert!(content.contains("custom"));
    }

    #[test]
    fn validate_config_accepts_valid_config() {
        let config = serde_json::json!({
            "agents": { "list": [], "defaults": {} },
            "settings": {
                "gateway": { "url": "http://localhost:18790", "port": 18790, "wsUrl": "ws://localhost:18790" },
                "security": { "sandboxMode": "docker", "networkIsolation": true, "auditLogging": true }
            }
        });
        assert!(validate_config(config).is_ok());
    }

    #[test]
    fn validate_config_rejects_bad_gateway_url() {
        let config = serde_json::json!({
            "agents": { "list": [], "defaults": {} },
            "settings": {
                "gateway": { "url": "ftp://bad", "port": 18790, "wsUrl": "ws://ok" },
                "security": { "sandboxMode": "docker", "networkIsolation": true, "auditLogging": true }
            }
        });
        assert!(validate_config(config).is_err());
    }

    #[test]
    fn validate_config_rejects_bad_ws_url() {
        let config = serde_json::json!({
            "agents": { "list": [], "defaults": {} },
            "settings": {
                "gateway": { "url": "http://ok", "port": 18790, "wsUrl": "http://wrong-scheme" },
                "security": { "sandboxMode": "docker", "networkIsolation": true, "auditLogging": true }
            }
        });
        let err = validate_config(config).unwrap_err();
        assert!(err.contains("ws://"), "error should mention ws:// requirement: {}", err);
    }

    #[test]
    fn validate_config_rejects_port_zero() {
        let config = serde_json::json!({
            "agents": { "list": [], "defaults": {} },
            "settings": {
                "gateway": { "url": "http://ok", "port": 0, "wsUrl": "ws://ok" },
                "security": { "sandboxMode": "docker", "networkIsolation": true, "auditLogging": true }
            }
        });
        assert!(validate_config(config).is_err());
    }

    #[test]
    fn validate_config_rejects_port_too_high() {
        let config = serde_json::json!({
            "agents": { "list": [], "defaults": {} },
            "settings": {
                "gateway": { "url": "http://ok", "port": 70000, "wsUrl": "ws://ok" },
                "security": { "sandboxMode": "docker", "networkIsolation": true, "auditLogging": true }
            }
        });
        assert!(validate_config(config).is_err());
    }

    #[test]
    fn validate_config_rejects_missing_security() {
        let config = serde_json::json!({
            "agents": { "list": [], "defaults": {} },
            "settings": {
                "gateway": { "url": "http://ok", "port": 18790, "wsUrl": "ws://ok" }
            }
        });
        let err = validate_config(config).unwrap_err();
        assert!(err.contains("security"), "should reject missing security: {}", err);
    }

    #[test]
    fn validate_config_rejects_missing_agents_list() {
        let config = serde_json::json!({
            "agents": { "defaults": {} },
            "settings": {
                "gateway": { "url": "http://ok", "port": 18790, "wsUrl": "ws://ok" },
                "security": { "sandboxMode": "docker", "networkIsolation": true, "auditLogging": true }
            }
        });
        let err = validate_config(config).unwrap_err();
        assert!(err.contains("agents.list"), "should reject missing agents.list: {}", err);
    }

    #[test]
    fn validate_config_rejects_agents_list_not_array() {
        let config = serde_json::json!({
            "agents": { "list": "not-an-array", "defaults": {} },
            "settings": {
                "gateway": { "url": "http://ok", "port": 18790, "wsUrl": "ws://ok" },
                "security": { "sandboxMode": "docker", "networkIsolation": true, "auditLogging": true }
            }
        });
        assert!(validate_config(config).is_err());
    }

    #[test]
    fn validate_config_rejects_bad_postgres_port() {
        let config = serde_json::json!({
            "agents": { "list": [], "defaults": {} },
            "settings": {
                "gateway": { "url": "http://ok", "port": 18790, "wsUrl": "ws://ok" },
                "security": { "sandboxMode": "docker", "networkIsolation": true, "auditLogging": true },
                "services": { "postgresPort": 99999 }
            }
        });
        assert!(validate_config(config).is_err());
    }

    #[test]
    fn validate_config_rejects_bad_redis_port() {
        let config = serde_json::json!({
            "agents": { "list": [], "defaults": {} },
            "settings": {
                "gateway": { "url": "http://ok", "port": 18790, "wsUrl": "ws://ok" },
                "security": { "sandboxMode": "docker", "networkIsolation": true, "auditLogging": true },
                "services": { "redisPort": 0 }
            }
        });
        assert!(validate_config(config).is_err());
    }

    fn make_test_state(dir: &str) -> AppState {
        AppState {
            openclaw_dir: dir.to_string(),
            vault_dir: String::new(),
            audit_log_path: String::new(),
            vault: std::sync::Mutex::new(crate::state::VaultRuntime::default()),
        }
    }

    #[test]
    fn write_config_creates_backup() {
        let tmp = tempfile::tempdir().unwrap();
        let dir = tmp.path().to_str().unwrap();
        // In non-bridge mode, desktop_config_path = openclaw_dir/openclaw.json
        if crate::commands::health::is_bridge_mode() {
            return; // Skip in bridge mode — different paths
        }

        let config_path = format!("{}/openclaw.json", dir);
        let original = serde_json::json!({"agents":{"list":[],"defaults":{}},"settings":{"gateway":{"url":"http://x","port":1,"wsUrl":"ws://x"},"security":{"sandboxMode":"docker","networkIsolation":true,"auditLogging":true}}});
        fs::write(&config_path, serde_json::to_string_pretty(&original).unwrap()).unwrap();

        let state = make_test_state(dir);
        let new_config = serde_json::json!({"agents":{"list":[],"defaults":{}},"settings":{"gateway":{"url":"http://y","port":2,"wsUrl":"ws://y"},"security":{"sandboxMode":"docker","networkIsolation":true,"auditLogging":true}},"_test":true});
        write_config(&state, new_config).unwrap();

        // Backup should exist with original content
        let backup = fs::read_to_string(format!("{}.bak", config_path)).unwrap();
        assert!(backup.contains("http://x"));

        // Config should have new content
        let current = fs::read_to_string(&config_path).unwrap();
        assert!(current.contains("http://y"));
        assert!(current.contains("_test"));
    }

    #[test]
    fn restore_config_backup_rejects_invalid_backup() {
        let tmp = tempfile::tempdir().unwrap();
        let dir = tmp.path().to_str().unwrap();
        if crate::commands::health::is_bridge_mode() {
            return;
        }

        let config_path = format!("{}/openclaw.json", dir);
        fs::write(&config_path, "{}").unwrap();
        // Write a backup that's missing required keys
        fs::write(format!("{}.bak", config_path), r#"{"only_agents": true}"#).unwrap();

        let state = make_test_state(dir);
        let result = restore_config_backup(&state);
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("missing required keys"));
    }

    #[test]
    fn restore_config_backup_fails_when_no_backup() {
        let tmp = tempfile::tempdir().unwrap();
        let dir = tmp.path().to_str().unwrap();
        if crate::commands::health::is_bridge_mode() {
            return;
        }

        let state = make_test_state(dir);
        let result = restore_config_backup(&state);
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("No config backup"));
    }

    #[test]
    fn read_config_creates_default_when_missing() {
        let tmp = tempfile::tempdir().unwrap();
        let dir = tmp.path().to_str().unwrap();
        if crate::commands::health::is_bridge_mode() {
            return;
        }

        let state = make_test_state(dir);
        let config = read_config(&state).unwrap();
        assert!(config.get("agents").is_some());
        assert!(config.get("settings").is_some());

        // File should now exist
        let config_path = format!("{}/openclaw.json", dir);
        assert!(std::path::Path::new(&config_path).exists());
    }
}
