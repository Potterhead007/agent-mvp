use crate::fs_utils::atomic_write;
use crate::security::audit;
use crate::state::AppState;
use serde::{Deserialize, Serialize};
use std::fs;
use std::path::Path;

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct PluginInfo {
    pub id: String,
    pub enabled: bool,
}

/// Read gateway config and return the plugin list.
pub fn list_gateway_plugins(state: &AppState) -> Result<Vec<PluginInfo>, String> {
    let compose_dir = state.docker_compose_dir();
    let gw_config_path = format!("{}/.openclaw/openclaw.json", compose_dir);

    let content = fs::read_to_string(&gw_config_path)
        .map_err(|e| format!("Failed to read gateway config: {}", e))?;
    let config: serde_json::Value =
        serde_json::from_str(&content).map_err(|e| format!("Invalid gateway JSON: {}", e))?;

    let mut plugins = Vec::new();

    // Read plugins.allow[] for the allow list
    let allow_list: Vec<String> = config
        .get("plugins")
        .and_then(|p| p.get("allow"))
        .and_then(|a| a.as_array())
        .map(|arr| {
            arr.iter()
                .filter_map(|v| v.as_str().map(|s| s.to_string()))
                .collect()
        })
        .unwrap_or_default();

    // Read plugins.entries for per-plugin config
    let entries = config
        .get("plugins")
        .and_then(|p| p.get("entries"))
        .cloned()
        .unwrap_or_else(|| serde_json::json!({}));

    // Build a combined list from allow list + entries
    let mut seen = std::collections::HashSet::new();

    for plugin_id in &allow_list {
        seen.insert(plugin_id.clone());
        let entry_enabled = entries
            .get(plugin_id)
            .and_then(|e| e.get("enabled"))
            .and_then(|v| v.as_bool())
            .unwrap_or(true);
        plugins.push(PluginInfo {
            id: plugin_id.clone(),
            enabled: entry_enabled,
        });
    }

    // Also include entries that aren't in the allow list (disabled ones)
    if let Some(obj) = entries.as_object() {
        for (key, val) in obj {
            if !seen.contains(key) {
                let enabled = val
                    .get("enabled")
                    .and_then(|v| v.as_bool())
                    .unwrap_or(false);
                plugins.push(PluginInfo {
                    id: key.clone(),
                    enabled,
                });
            }
        }
    }

    // If no plugins found at all, return recommended defaults as disabled
    if plugins.is_empty() {
        plugins.push(PluginInfo {
            id: "memory-core".to_string(),
            enabled: false,
        });
        plugins.push(PluginInfo {
            id: "telegram".to_string(),
            enabled: false,
        });
    }

    Ok(plugins)
}

/// Toggle a gateway plugin on or off.
pub fn toggle_gateway_plugin(
    state: &AppState,
    plugin_id: String,
    enabled: bool,
) -> Result<(), String> {
    let compose_dir = state.docker_compose_dir();
    let gw_config_path = format!("{}/.openclaw/openclaw.json", compose_dir);

    let content = fs::read_to_string(&gw_config_path)
        .map_err(|e| format!("Failed to read gateway config: {}", e))?;
    let mut config: serde_json::Value =
        serde_json::from_str(&content).map_err(|e| format!("Invalid gateway JSON: {}", e))?;

    // Ensure plugins object exists
    if config.get("plugins").is_none() {
        config["plugins"] = serde_json::json!({ "allow": [], "entries": {} });
    }
    if config["plugins"].get("allow").is_none() {
        config["plugins"]["allow"] = serde_json::json!([]);
    }
    if config["plugins"].get("entries").is_none() {
        config["plugins"]["entries"] = serde_json::json!({});
    }

    // Update allow list
    if let Some(allow) = config["plugins"]["allow"].as_array_mut() {
        let plugin_val = serde_json::Value::String(plugin_id.clone());
        if enabled {
            if !allow.contains(&plugin_val) {
                allow.push(plugin_val);
            }
        } else {
            allow.retain(|v| v.as_str() != Some(&plugin_id));
        }
    }

    // Update entries
    config["plugins"]["entries"][&plugin_id] = serde_json::json!({ "enabled": enabled });

    let updated = serde_json::to_string_pretty(&config)
        .map_err(|e| format!("Failed to serialize: {}", e))?;
    atomic_write(Path::new(&gw_config_path), &updated)?;

    audit::log_action(
        &state.audit_log_path,
        "PLUGIN_TOGGLE",
        &format!(
            "Plugin '{}' {}",
            plugin_id,
            if enabled { "enabled" } else { "disabled" }
        ),
    );

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;

    fn make_state(tmp: &std::path::Path) -> crate::state::AppState {
        let audit_path = tmp.join("audit.log");
        let _ = fs::write(&audit_path, "");
        // Create the compose/.openclaw directory for gateway config
        let compose_dir = tmp.join("compose");
        let _ = fs::create_dir_all(compose_dir.join(".openclaw"));
        // Write a config pointing docker_compose_dir to compose/
        let oc_json = tmp.join("openclaw.json");
        let _ = fs::write(
            &oc_json,
            serde_json::json!({
                "settings": { "desktop": { "dockerComposePath": compose_dir.to_str().unwrap() } }
            }).to_string(),
        );
        crate::state::AppState {
            openclaw_dir: tmp.to_str().unwrap().to_string(),
            vault_dir: String::new(),
            audit_log_path: audit_path.to_str().unwrap().to_string(),
            vault: std::sync::Mutex::new(crate::state::VaultRuntime::default()),
        }
    }

    fn write_gw_config(tmp: &std::path::Path, config: serde_json::Value) {
        let gw_path = tmp.join("compose/.openclaw/openclaw.json");
        fs::write(&gw_path, config.to_string()).unwrap();
    }

    // -----------------------------------------------------------------------
    // list_gateway_plugins
    // -----------------------------------------------------------------------

    #[test]
    fn list_plugins_from_allow_list() {
        let tmp = tempfile::tempdir().unwrap();
        let state = make_state(tmp.path());
        write_gw_config(tmp.path(), serde_json::json!({
            "plugins": {
                "allow": ["memory-core", "telegram"],
                "entries": {}
            }
        }));

        let plugins = list_gateway_plugins(&state).unwrap();
        assert_eq!(plugins.len(), 2);
        assert!(plugins.iter().all(|p| p.enabled));
        let ids: Vec<&str> = plugins.iter().map(|p| p.id.as_str()).collect();
        assert!(ids.contains(&"memory-core"));
        assert!(ids.contains(&"telegram"));
    }

    #[test]
    fn list_plugins_entries_override_enabled() {
        let tmp = tempfile::tempdir().unwrap();
        let state = make_state(tmp.path());
        write_gw_config(tmp.path(), serde_json::json!({
            "plugins": {
                "allow": ["memory-core"],
                "entries": {
                    "memory-core": { "enabled": false }
                }
            }
        }));

        let plugins = list_gateway_plugins(&state).unwrap();
        assert_eq!(plugins.len(), 1);
        assert!(!plugins[0].enabled);
    }

    #[test]
    fn list_plugins_includes_entries_not_in_allow() {
        let tmp = tempfile::tempdir().unwrap();
        let state = make_state(tmp.path());
        write_gw_config(tmp.path(), serde_json::json!({
            "plugins": {
                "allow": ["memory-core"],
                "entries": {
                    "hidden-plugin": { "enabled": false }
                }
            }
        }));

        let plugins = list_gateway_plugins(&state).unwrap();
        assert_eq!(plugins.len(), 2);
        let hidden = plugins.iter().find(|p| p.id == "hidden-plugin").unwrap();
        assert!(!hidden.enabled);
    }

    #[test]
    fn list_plugins_returns_defaults_when_empty() {
        let tmp = tempfile::tempdir().unwrap();
        let state = make_state(tmp.path());
        write_gw_config(tmp.path(), serde_json::json!({}));

        let plugins = list_gateway_plugins(&state).unwrap();
        assert_eq!(plugins.len(), 2);
        assert!(plugins.iter().all(|p| !p.enabled));
    }

    #[test]
    fn list_plugins_fails_on_missing_config() {
        let tmp = tempfile::tempdir().unwrap();
        let state = make_state(tmp.path());
        // Don't write gateway config
        let _ = fs::remove_file(tmp.path().join("compose/.openclaw/openclaw.json"));

        let result = list_gateway_plugins(&state);
        assert!(result.is_err());
    }

    // -----------------------------------------------------------------------
    // toggle_gateway_plugin
    // -----------------------------------------------------------------------

    #[test]
    fn toggle_plugin_enables() {
        let tmp = tempfile::tempdir().unwrap();
        let state = make_state(tmp.path());
        write_gw_config(tmp.path(), serde_json::json!({
            "plugins": { "allow": [], "entries": {} }
        }));

        toggle_gateway_plugin(&state, "telegram".to_string(), true).unwrap();

        let content = fs::read_to_string(tmp.path().join("compose/.openclaw/openclaw.json")).unwrap();
        let config: serde_json::Value = serde_json::from_str(&content).unwrap();
        let allow = config["plugins"]["allow"].as_array().unwrap();
        assert!(allow.iter().any(|v| v == "telegram"));
        assert_eq!(config["plugins"]["entries"]["telegram"]["enabled"], true);
    }

    #[test]
    fn toggle_plugin_disables() {
        let tmp = tempfile::tempdir().unwrap();
        let state = make_state(tmp.path());
        write_gw_config(tmp.path(), serde_json::json!({
            "plugins": { "allow": ["telegram"], "entries": { "telegram": { "enabled": true } } }
        }));

        toggle_gateway_plugin(&state, "telegram".to_string(), false).unwrap();

        let content = fs::read_to_string(tmp.path().join("compose/.openclaw/openclaw.json")).unwrap();
        let config: serde_json::Value = serde_json::from_str(&content).unwrap();
        let allow = config["plugins"]["allow"].as_array().unwrap();
        assert!(!allow.iter().any(|v| v == "telegram"));
        assert_eq!(config["plugins"]["entries"]["telegram"]["enabled"], false);
    }

    #[test]
    fn toggle_plugin_creates_plugins_object_if_missing() {
        let tmp = tempfile::tempdir().unwrap();
        let state = make_state(tmp.path());
        write_gw_config(tmp.path(), serde_json::json!({}));

        toggle_gateway_plugin(&state, "memory-core".to_string(), true).unwrap();

        let content = fs::read_to_string(tmp.path().join("compose/.openclaw/openclaw.json")).unwrap();
        let config: serde_json::Value = serde_json::from_str(&content).unwrap();
        assert!(config["plugins"]["allow"].is_array());
        assert!(config["plugins"]["entries"]["memory-core"]["enabled"].as_bool().unwrap());
    }

    #[test]
    fn toggle_plugin_idempotent_enable() {
        let tmp = tempfile::tempdir().unwrap();
        let state = make_state(tmp.path());
        write_gw_config(tmp.path(), serde_json::json!({
            "plugins": { "allow": ["telegram"], "entries": { "telegram": { "enabled": true } } }
        }));

        // Enable again — should not duplicate in allow list
        toggle_gateway_plugin(&state, "telegram".to_string(), true).unwrap();

        let content = fs::read_to_string(tmp.path().join("compose/.openclaw/openclaw.json")).unwrap();
        let config: serde_json::Value = serde_json::from_str(&content).unwrap();
        let allow = config["plugins"]["allow"].as_array().unwrap();
        let count = allow.iter().filter(|v| v.as_str() == Some("telegram")).count();
        assert_eq!(count, 1, "plugin should not be duplicated in allow list");
    }
}
