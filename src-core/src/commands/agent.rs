use crate::fs_utils::atomic_write;
use crate::security::{audit, sanitize};
use crate::state::AppState;
use serde::{Deserialize, Serialize};
use std::fs;
use std::path::Path;

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct AgentInfo {
    pub id: String,
    pub name: String,
    pub personality_file: Option<String>,
    pub model: Option<String>,
    pub enabled: bool,
}

pub fn list_agents(state: &AppState) -> Result<Vec<AgentInfo>, String> {
    let config_path = state.desktop_config_path();
    let content = fs::read_to_string(&config_path)
        .map_err(|e| format!("Failed to read config: {}", e))?;
    let config: serde_json::Value =
        serde_json::from_str(&content).map_err(|e| format!("Invalid JSON: {}", e))?;

    let empty = vec![];
    let agents = config
        .get("agents")
        .and_then(|a| a.get("list"))
        .and_then(|l| l.as_array())
        .unwrap_or(&empty);

    let result: Vec<AgentInfo> = agents
        .iter()
        .map(|a| {
            // Model can be a string ("grok-3-mini") or an object ({"primary": "xai/grok-3-mini"})
            let model = a["model"].as_str().map(|s| s.to_string())
                .or_else(|| a["model"]["primary"].as_str().map(|s| s.to_string()));
            AgentInfo {
                id: a["id"].as_str().unwrap_or("").to_string(),
                name: a["name"].as_str().unwrap_or("").to_string(),
                personality_file: a["personality"].as_str().map(|s| s.to_string()),
                model,
                enabled: a["enabled"].as_bool().unwrap_or(true),
            }
        })
        .collect();

    Ok(result)
}

pub fn read_agent_file(
    state: &AppState,
    relative_path: String,
) -> Result<String, String> {
    let safe_path = sanitize::sanitize_path(&state.openclaw_dir, &relative_path)
        .ok_or("Invalid path: access denied")?;
    fs::read_to_string(&safe_path).map_err(|e| format!("Failed to read file: {}", e))
}

pub fn write_agent_file(
    state: &AppState,
    relative_path: String,
    content: String,
) -> Result<(), String> {
    let safe_path = sanitize::sanitize_path(&state.openclaw_dir, &relative_path)
        .ok_or("Invalid path: access denied")?;
    if let Some(parent) = Path::new(&safe_path).parent() {
        fs::create_dir_all(parent).map_err(|e| format!("Failed to create directories: {}", e))?;
    }
    fs::write(&safe_path, &content).map_err(|e| format!("Failed to write file: {}", e))?;
    audit::log_action(
        &state.audit_log_path,
        "AGENT_FILE_WRITE",
        &format!("Updated: {}", relative_path),
    );
    Ok(())
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FileNode {
    pub name: String,
    pub path: String,
    #[serde(rename = "type")]
    pub node_type: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub children: Option<Vec<FileNode>>,
}

pub fn list_workspace_tree(state: &AppState) -> Result<Vec<FileNode>, String> {
    fn build_tree(dir: &Path, base: &Path) -> Vec<FileNode> {
        let mut nodes = Vec::new();
        let Ok(entries) = fs::read_dir(dir) else {
            return nodes;
        };

        let mut entries: Vec<_> = entries.flatten().collect();
        entries.sort_by_key(|e| e.file_name());

        for entry in entries {
            let path = entry.path();
            let name = entry.file_name().to_string_lossy().to_string();

            if name.starts_with('.') {
                continue;
            }

            let relative = path
                .strip_prefix(base)
                .unwrap_or(&path)
                .to_string_lossy()
                .to_string();

            if path.is_dir() {
                let children = build_tree(&path, base);
                nodes.push(FileNode {
                    name,
                    path: relative,
                    node_type: "directory".to_string(),
                    children: Some(children),
                });
            } else {
                nodes.push(FileNode {
                    name,
                    path: relative,
                    node_type: "file".to_string(),
                    children: None,
                });
            }
        }
        nodes
    }

    let base = Path::new(&state.openclaw_dir);
    if !base.exists() {
        return Ok(vec![]);
    }
    Ok(build_tree(base, base))
}

pub fn create_workspace_file(
    state: &AppState,
    relative_path: String,
    content: String,
) -> Result<(), String> {
    let full_path = Path::new(&state.openclaw_dir).join(&relative_path);

    let canonical_base = Path::new(&state.openclaw_dir)
        .canonicalize()
        .map_err(|e| format!("Base path error: {}", e))?;

    let canonical_full = if let Some(parent) = full_path.parent() {
        let mut ancestor = parent.to_path_buf();
        while !ancestor.exists() {
            ancestor = match ancestor.parent() {
                Some(p) => p.to_path_buf(),
                None => return Err("Access denied: path outside workspace".to_string()),
            };
        }
        let canonical_ancestor = ancestor
            .canonicalize()
            .map_err(|e| format!("Path error: {}", e))?;
        if !canonical_ancestor.starts_with(&canonical_base) {
            return Err("Access denied: path outside workspace".to_string());
        }
        canonical_ancestor
            .join(full_path.strip_prefix(&ancestor).unwrap_or(&full_path))
    } else {
        return Err("Access denied: path outside workspace".to_string());
    };

    if !canonical_full.starts_with(&canonical_base) {
        return Err("Access denied: path outside workspace".to_string());
    }

    if let Some(parent) = full_path.parent() {
        fs::create_dir_all(parent).map_err(|e| format!("Failed to create dirs: {}", e))?;
    }

    fs::write(&full_path, &content).map_err(|e| format!("Failed to write: {}", e))?;
    audit::log_action(
        &state.audit_log_path,
        "FILE_CREATE",
        &format!("Created: {}", relative_path),
    );
    Ok(())
}

pub fn create_agent(
    state: &AppState,
    id: String,
    name: String,
    model: Option<String>,
    personality: Option<String>,
) -> Result<(), String> {
    sanitize::validate_id(&id)?;

    let config_path = state.desktop_config_path();
    let content = fs::read_to_string(&config_path)
        .map_err(|e| format!("Failed to read config: {}", e))?;
    let mut config: serde_json::Value =
        serde_json::from_str(&content).map_err(|e| format!("Invalid JSON: {}", e))?;
    if let Some(list) = config["agents"]["list"].as_array() {
        if list.iter().any(|a| a["id"].as_str() == Some(&id)) {
            return Err(format!("Agent with ID '{}' already exists", id));
        }
    }

    let agent_dir = format!("{}/agents/{}/agent", state.openclaw_dir, id);
    fs::create_dir_all(&agent_dir).map_err(|e| format!("Failed to create agent dir: {}", e))?;

    let soul_content = personality.unwrap_or_else(|| {
        format!(
            "# {}\n\nYou are a helpful assistant.\n\n## Tone\n- Professional and concise\n\n## Behaviour\n- Ask clarifying questions when needed\n",
            name
        )
    });
    fs::write(format!("{}/SOUL.md", agent_dir), &soul_content)
        .map_err(|e| format!("Failed to write SOUL.md: {}", e))?;

    let tools_content = "# Tool Permissions\n\n- web_search: allowed\n- web_fetch: allowed\n- file_read: allowed\n- file_write: denied\n- code_execute: denied\n- shell_exec: denied\n";
    fs::write(format!("{}/TOOLS.md", agent_dir), tools_content)
        .map_err(|e| format!("Failed to write TOOLS.md: {}", e))?;

    let boot_content = format!("# Boot Sequence\n\n1. Load personality from SOUL.md\n2. Initialize tools from TOOLS.md\n3. Agent '{}' ready\n", name);
    fs::write(format!("{}/BOOT.md", agent_dir), &boot_content)
        .map_err(|e| format!("Failed to write BOOT.md: {}", e))?;

    let agent_entry = serde_json::json!({
        "id": id,
        "name": name,
        "personality": format!("agents/{}/agent/SOUL.md", id),
        "model": model.unwrap_or_else(|| "claude-sonnet-4-20250514".to_string()),
        "enabled": true,
    });

    if let Some(list) = config["agents"]["list"].as_array_mut() {
        list.push(agent_entry);
    }

    let updated = serde_json::to_string_pretty(&config)
        .map_err(|e| format!("Failed to serialize: {}", e))?;
    atomic_write(Path::new(&config_path), &updated)?;

    let memory_dir = format!("{}/agents/{}/memory", state.openclaw_dir, id);
    fs::create_dir_all(&memory_dir)
        .map_err(|e| format!("Failed to create memory dir: {}", e))?;

    audit::log_action(
        &state.audit_log_path,
        "AGENT_CREATE",
        &format!("Created agent: {} ({})", name, id),
    );

    if let Err(e) = do_sync_agents_to_gateway(state) {
        audit::log_action(
            &state.audit_log_path,
            "SYNC_WARN",
            &format!("Gateway sync after create failed: {}", e),
        );
    }

    Ok(())
}

pub fn update_agent(
    state: &AppState,
    id: String,
    name: Option<String>,
    model: Option<String>,
    enabled: Option<bool>,
) -> Result<(), String> {
    sanitize::validate_id(&id)?;
    let config_path = state.desktop_config_path();
    let content = fs::read_to_string(&config_path)
        .map_err(|e| format!("Failed to read config: {}", e))?;
    let mut config: serde_json::Value =
        serde_json::from_str(&content).map_err(|e| format!("Invalid JSON: {}", e))?;

    let mut found = false;
    if let Some(list) = config["agents"]["list"].as_array_mut() {
        for agent in list.iter_mut() {
            if agent["id"].as_str() == Some(&id) {
                if let Some(ref n) = name {
                    agent["name"] = serde_json::Value::String(n.clone());
                }
                if let Some(ref m) = model {
                    agent["model"] = serde_json::Value::String(m.clone());
                }
                if let Some(e) = enabled {
                    agent["enabled"] = serde_json::Value::Bool(e);
                }
                found = true;
                break;
            }
        }
    }

    if !found {
        return Err(format!("Agent '{}' not found", id));
    }

    let updated = serde_json::to_string_pretty(&config)
        .map_err(|e| format!("Failed to serialize: {}", e))?;
    atomic_write(Path::new(&config_path), &updated)?;

    let mut changes = Vec::new();
    if let Some(ref n) = name {
        changes.push(format!("name={}", n));
    }
    if let Some(ref m) = model {
        changes.push(format!("model={}", m));
    }
    if let Some(e) = enabled {
        changes.push(format!("enabled={}", e));
    }
    audit::log_action(
        &state.audit_log_path,
        "AGENT_UPDATE",
        &format!("Updated agent {}: {}", id, changes.join(", ")),
    );

    if let Err(e) = do_sync_agents_to_gateway(state) {
        audit::log_action(
            &state.audit_log_path,
            "SYNC_WARN",
            &format!("Gateway sync after update failed: {}", e),
        );
    }

    Ok(())
}

pub fn delete_agent(
    state: &AppState,
    id: String,
    delete_files: bool,
) -> Result<(), String> {
    sanitize::validate_id(&id)?;
    let config_path = state.desktop_config_path();
    let content = fs::read_to_string(&config_path)
        .map_err(|e| format!("Failed to read config: {}", e))?;
    let mut config: serde_json::Value =
        serde_json::from_str(&content).map_err(|e| format!("Invalid JSON: {}", e))?;

    if let Some(list) = config["agents"]["list"].as_array_mut() {
        list.retain(|a| a["id"].as_str() != Some(&id));
    }

    let updated = serde_json::to_string_pretty(&config)
        .map_err(|e| format!("Failed to serialize: {}", e))?;
    atomic_write(Path::new(&config_path), &updated)?;

    if delete_files {
        let agent_dir = format!("{}/agents/{}", state.openclaw_dir, id);
        let _ = fs::remove_dir_all(&agent_dir);
    }

    audit::log_action(
        &state.audit_log_path,
        "AGENT_DELETE",
        &format!("Deleted agent: {}", id),
    );

    if let Err(e) = do_sync_agents_to_gateway(state) {
        audit::log_action(
            &state.audit_log_path,
            "SYNC_WARN",
            &format!("Gateway sync after delete failed: {}", e),
        );
    }

    Ok(())
}

pub fn clear_agent_memory(
    state: &AppState,
    agent_id: String,
) -> Result<(), String> {
    sanitize::validate_id(&agent_id)?;
    let memory_dir = format!("{}/agents/{}/memory", state.openclaw_dir, agent_id);
    if Path::new(&memory_dir).exists() {
        fs::remove_dir_all(&memory_dir)
            .map_err(|e| format!("Failed to clear memory: {}", e))?;
        fs::create_dir_all(&memory_dir)
            .map_err(|e| format!("Failed to recreate memory dir: {}", e))?;
    }
    audit::log_action(
        &state.audit_log_path,
        "MEMORY_CLEAR",
        &format!("Cleared memory for agent: {}", agent_id),
    );
    Ok(())
}

pub fn archive_agent_memory(
    state: &AppState,
    agent_id: String,
) -> Result<String, String> {
    sanitize::validate_id(&agent_id)?;
    let memory_dir = format!("{}/agents/{}/memory", state.openclaw_dir, agent_id);
    let timestamp = chrono::Utc::now().format("%Y%m%d_%H%M%S").to_string();
    let archive_dir = format!("{}/archives/{}_{}", state.openclaw_dir, agent_id, timestamp);

    fs::create_dir_all(&archive_dir)
        .map_err(|e| format!("Failed to create archive dir: {}", e))?;

    if Path::new(&memory_dir).exists() {
        let mut copied = 0usize;
        if let Ok(entries) = fs::read_dir(&memory_dir) {
            for entry in entries.flatten() {
                let dest = Path::new(&archive_dir).join(entry.file_name());
                fs::copy(entry.path(), dest)
                    .map_err(|e| format!("Failed to archive {}: {}", entry.file_name().to_string_lossy(), e))?;
                copied += 1;
            }
        }
        if copied > 0 {
            fs::remove_dir_all(&memory_dir)
                .map_err(|e| format!("Failed to clear memory after archive: {}", e))?;
            fs::create_dir_all(&memory_dir)
                .map_err(|e| format!("Failed to recreate memory dir: {}", e))?;
        }
    }

    audit::log_action(
        &state.audit_log_path,
        "MEMORY_ARCHIVE",
        &format!("Archived memory for agent: {} to {}", agent_id, archive_dir),
    );
    Ok(archive_dir)
}
pub(crate) fn do_sync_agents_to_gateway(state: &AppState) -> Result<(), String> {
    let desktop_config_path = state.desktop_config_path();
    let desktop_content = fs::read_to_string(&desktop_config_path)
        .map_err(|e| format!("Failed to read desktop config: {}", e))?;
    let desktop_config: serde_json::Value =
        serde_json::from_str(&desktop_content).map_err(|e| format!("Invalid desktop JSON: {}", e))?;

    let empty = vec![];
    let desktop_agents = desktop_config
        .get("agents")
        .and_then(|a| a.get("list"))
        .and_then(|l| l.as_array())
        .unwrap_or(&empty);

    let mut gateway_agents = Vec::new();
    for agent in desktop_agents {
        let enabled = agent["enabled"].as_bool().unwrap_or(true);
        if !enabled {
            continue;
        }

        let id = agent["id"].as_str().unwrap_or("").to_string();
        if id.is_empty() {
            continue;
        }

        let name = agent["name"].as_str().unwrap_or(&id).to_string();
        // Model can be a string or {"primary": "provider/model"} object
        let model_raw = agent["model"].as_str()
            .or_else(|| agent["model"]["primary"].as_str())
            .unwrap_or("grok-3-mini");

        let model_primary = if model_raw.contains('/') {
            model_raw.to_string()
        } else if model_raw.starts_with("claude") {
            format!("anthropic/{}", model_raw)
        } else if model_raw.starts_with("gpt-") || model_raw.starts_with("o1") || model_raw.starts_with("o3") {
            format!("openai/{}", model_raw)
        } else if model_raw.starts_with("llama") || model_raw.starts_with("mistral") || model_raw.starts_with("codellama") || model_raw.starts_with("phi-") {
            format!("ollama/{}", model_raw)
        } else {
            format!("xai/{}", model_raw)
        };

        let workspace = format!("/home/openclaw/.openclaw/agents/{}", id);

        let tools = if let Some(tools_arr) = agent["tools"].as_array() {
            let allow: Vec<serde_json::Value> = tools_arr
                .iter()
                .filter_map(|t| t.as_str().map(|s| serde_json::Value::String(s.to_string())))
                .collect();
            serde_json::json!({ "allow": allow, "deny": [] })
        } else {
            serde_json::json!({ "allow": ["*"], "deny": [] })
        };

        gateway_agents.push(serde_json::json!({
            "id": id,
            "name": name,
            "workspace": workspace,
            "model": { "primary": model_primary },
            "tools": tools,
        }));
    }

    let compose_dir = state.docker_compose_dir();
    let gw_config_path = format!("{}/.openclaw/openclaw.json", compose_dir);

    let mut gw_config = if let Ok(content) = fs::read_to_string(&gw_config_path) {
        serde_json::from_str::<serde_json::Value>(&content).unwrap_or_else(|_| serde_json::json!({}))
    } else {
        serde_json::json!({})
    };

    if gw_config.get("agents").is_none() {
        gw_config["agents"] = serde_json::json!({});
    }
    gw_config["agents"]["list"] = serde_json::Value::Array(gateway_agents.clone());

    if let Some(channels) = desktop_config.get("settings").and_then(|s| s.get("channels")) {
        if let Some(channels_obj) = channels.as_object() {
            if gw_config.get("channels").is_none() {
                gw_config["channels"] = serde_json::json!({});
            }
            for (ch_type, ch_config) in channels_obj {
                let enabled = ch_config.get("enabled").and_then(|v| v.as_bool()).unwrap_or(false);
                if enabled {
                    let mut gw_ch = serde_json::json!({ "enabled": true });
                    if let Some(obj) = ch_config.as_object() {
                        for (key, val) in obj {
                            match key.as_str() {
                                "enabled" | "pendingSetup" | "botToken" => {}
                                _ => { gw_ch[key] = val.clone(); }
                            }
                        }
                    }
                    gw_config["channels"][ch_type] = gw_ch;
                }
            }
        }
    }

    if let Some(plugins) = desktop_config.get("plugins") {
        gw_config["plugins"] = plugins.clone();
    }

    if let Some(parent) = Path::new(&gw_config_path).parent() {
        let _ = fs::create_dir_all(parent);
    }

    let updated = serde_json::to_string_pretty(&gw_config)
        .map_err(|e| format!("Failed to serialize gateway config: {}", e))?;
    atomic_write(Path::new(&gw_config_path), &updated)?;

    for agent in &gateway_agents {
        if let Some(id) = agent["id"].as_str() {
            let gw_memory_dir = format!("{}/.openclaw/agents/{}/memory", compose_dir, id);
            let _ = fs::create_dir_all(&gw_memory_dir);
        }
    }

    let bootstrap_main = format!("{}/.openclaw/workspace/BOOTSTRAP.md", compose_dir);
    let _ = fs::remove_file(&bootstrap_main);
    for agent in &gateway_agents {
        if let Some(id) = agent["id"].as_str() {
            let bootstrap_agent = format!("{}/.openclaw/workspace-{}/BOOTSTRAP.md", compose_dir, id);
            let _ = fs::remove_file(&bootstrap_agent);
        }
    }

    Ok(())
}

pub fn sync_agents_to_gateway(state: &AppState) -> Result<(), String> {
    do_sync_agents_to_gateway(state)?;
    audit::log_action(
        &state.audit_log_path,
        "AGENT_SYNC",
        "Synced agents to gateway config",
    );
    Ok(())
}

pub fn delete_workspace_file(
    state: &AppState,
    relative_path: String,
) -> Result<(), String> {
    let safe_path = sanitize::sanitize_path(&state.openclaw_dir, &relative_path)
        .ok_or("Invalid path: access denied")?;
    fs::remove_file(&safe_path).map_err(|e| format!("Failed to delete: {}", e))?;
    audit::log_action(
        &state.audit_log_path,
        "FILE_DELETE",
        &format!("Deleted: {}", relative_path),
    );
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;

    fn make_state(tmp: &std::path::Path) -> AppState {
        let audit_path = tmp.join("audit.log");
        let _ = fs::write(&audit_path, "");
        // Create a docker-compose dir that mirrors the real layout so
        // do_sync_agents_to_gateway can write gateway config.
        let compose_dir = tmp.join("compose");
        let _ = fs::create_dir_all(compose_dir.join(".openclaw"));
        // Write a minimal openclaw.json so docker_compose_dir() can read it.
        let oc_json = tmp.join("openclaw.json");
        let _ = fs::write(
            &oc_json,
            serde_json::json!({
                "settings": { "desktop": { "dockerComposePath": compose_dir.to_str().unwrap() } }
            })
            .to_string(),
        );
        AppState {
            openclaw_dir: tmp.to_str().unwrap().to_string(),
            vault_dir: String::new(),
            audit_log_path: audit_path.to_str().unwrap().to_string(),
            vault: std::sync::Mutex::new(crate::state::VaultRuntime::default()),
        }
    }

    fn write_config(tmp: &std::path::Path, agents: serde_json::Value) {
        let config = serde_json::json!({
            "agents": { "list": agents, "defaults": {} },
            "settings": {
                "gateway": { "url": "http://localhost:18790", "port": 18790, "wsUrl": "ws://localhost:18790" },
                "security": { "sandboxMode": "docker", "networkIsolation": true, "auditLogging": true },
                "desktop": { "dockerComposePath": tmp.join("compose").to_str().unwrap() }
            }
        });
        // desktop_config_path() returns openclaw_dir/desktop-config.json in bridge mode,
        // or openclaw_dir/openclaw.json in normal mode. We write both to be safe.
        let _ = fs::write(tmp.join("desktop-config.json"), config.to_string());
        let _ = fs::write(tmp.join("openclaw.json"), config.to_string());
    }

    #[test]
    fn validate_id_blocks_traversal_in_create_agent() {
        use crate::security::sanitize;
        assert!(sanitize::validate_id("../etc").is_err());
        assert!(sanitize::validate_id("my-agent").is_ok());
    }
    #[test]
    fn list_agents_returns_empty_for_no_agents() {
        let tmp = tempfile::tempdir().unwrap();
        let state = make_state(tmp.path());
        write_config(tmp.path(), serde_json::json!([]));
        let agents = list_agents(&state).unwrap();
        assert!(agents.is_empty());
    }

    #[test]
    fn list_agents_reads_string_model() {
        let tmp = tempfile::tempdir().unwrap();
        let state = make_state(tmp.path());
        write_config(tmp.path(), serde_json::json!([
            { "id": "a1", "name": "Agent One", "model": "grok-3-mini", "enabled": true }
        ]));
        let agents = list_agents(&state).unwrap();
        assert_eq!(agents.len(), 1);
        assert_eq!(agents[0].id, "a1");
        assert_eq!(agents[0].model, Some("grok-3-mini".to_string()));
    }

    #[test]
    fn list_agents_reads_object_model() {
        let tmp = tempfile::tempdir().unwrap();
        let state = make_state(tmp.path());
        write_config(tmp.path(), serde_json::json!([
            { "id": "a2", "name": "Agent Two", "model": { "primary": "xai/grok-4" }, "enabled": false }
        ]));
        let agents = list_agents(&state).unwrap();
        assert_eq!(agents.len(), 1);
        assert_eq!(agents[0].model, Some("xai/grok-4".to_string()));
        assert!(!agents[0].enabled);
    }

    #[test]
    fn list_agents_handles_missing_model() {
        let tmp = tempfile::tempdir().unwrap();
        let state = make_state(tmp.path());
        write_config(tmp.path(), serde_json::json!([
            { "id": "a3", "name": "No Model" }
        ]));
        let agents = list_agents(&state).unwrap();
        assert_eq!(agents[0].model, None);
        // enabled defaults to true when missing
        assert!(agents[0].enabled);
    }

    #[test]
    fn list_agents_fails_on_missing_config() {
        let tmp = tempfile::tempdir().unwrap();
        let state = make_state(tmp.path());
        // Delete config files
        let _ = fs::remove_file(tmp.path().join("openclaw.json"));
        let _ = fs::remove_file(tmp.path().join("desktop-config.json"));
        let result = list_agents(&state);
        assert!(result.is_err());
    }

    #[test]
    fn list_agents_fails_on_malformed_json() {
        let tmp = tempfile::tempdir().unwrap();
        let state = make_state(tmp.path());
        fs::write(tmp.path().join("openclaw.json"), "not json {{{").unwrap();
        fs::write(tmp.path().join("desktop-config.json"), "not json {{{").unwrap();
        let result = list_agents(&state);
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("Invalid JSON"));
    }

    #[test]
    fn list_agents_returns_empty_when_agents_key_missing() {
        let tmp = tempfile::tempdir().unwrap();
        let state = make_state(tmp.path());
        fs::write(tmp.path().join("openclaw.json"), r#"{"settings":{}}"#).unwrap();
        fs::write(tmp.path().join("desktop-config.json"), r#"{"settings":{}}"#).unwrap();
        let agents = list_agents(&state).unwrap();
        assert!(agents.is_empty());
    }
    #[test]
    fn create_agent_adds_to_config_and_creates_files() {
        let tmp = tempfile::tempdir().unwrap();
        let state = make_state(tmp.path());
        write_config(tmp.path(), serde_json::json!([]));

        create_agent(&state, "test-bot".to_string(), "Test Bot".to_string(), Some("grok-3-mini".to_string()), None).unwrap();

        // Verify agent appears in list
        let agents = list_agents(&state).unwrap();
        assert_eq!(agents.len(), 1);
        assert_eq!(agents[0].id, "test-bot");
        assert_eq!(agents[0].name, "Test Bot");

        // Verify files were created
        assert!(tmp.path().join("agents/test-bot/agent/SOUL.md").exists());
        assert!(tmp.path().join("agents/test-bot/agent/TOOLS.md").exists());
        assert!(tmp.path().join("agents/test-bot/agent/BOOT.md").exists());
        assert!(tmp.path().join("agents/test-bot/memory").is_dir());
    }

    #[test]
    fn create_agent_rejects_duplicate_id() {
        let tmp = tempfile::tempdir().unwrap();
        let state = make_state(tmp.path());
        write_config(tmp.path(), serde_json::json!([
            { "id": "existing", "name": "Existing", "model": "grok-3-mini", "enabled": true }
        ]));

        let result = create_agent(&state, "existing".to_string(), "Duplicate".to_string(), None, None);
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("already exists"));
    }

    #[test]
    fn create_agent_rejects_invalid_id() {
        let tmp = tempfile::tempdir().unwrap();
        let state = make_state(tmp.path());
        write_config(tmp.path(), serde_json::json!([]));

        assert!(create_agent(&state, "../escape".to_string(), "Bad".to_string(), None, None).is_err());
        assert!(create_agent(&state, "".to_string(), "Empty".to_string(), None, None).is_err());
        assert!(create_agent(&state, "foo/bar".to_string(), "Slash".to_string(), None, None).is_err());
    }

    #[test]
    fn create_agent_uses_custom_personality() {
        let tmp = tempfile::tempdir().unwrap();
        let state = make_state(tmp.path());
        write_config(tmp.path(), serde_json::json!([]));

        let custom_soul = "# Custom\nYou are a pirate.".to_string();
        create_agent(&state, "pirate".to_string(), "Pirate".to_string(), None, Some(custom_soul.clone())).unwrap();

        let soul = fs::read_to_string(tmp.path().join("agents/pirate/agent/SOUL.md")).unwrap();
        assert_eq!(soul, custom_soul);
    }

    #[test]
    fn create_agent_uses_default_model_when_none() {
        let tmp = tempfile::tempdir().unwrap();
        let state = make_state(tmp.path());
        write_config(tmp.path(), serde_json::json!([]));

        create_agent(&state, "default-model".to_string(), "Default".to_string(), None, None).unwrap();

        let agents = list_agents(&state).unwrap();
        assert_eq!(agents[0].model, Some("claude-sonnet-4-20250514".to_string()));
    }
    #[test]
    fn update_agent_changes_fields() {
        let tmp = tempfile::tempdir().unwrap();
        let state = make_state(tmp.path());
        write_config(tmp.path(), serde_json::json!([
            { "id": "bot1", "name": "Old Name", "model": "old-model", "enabled": true }
        ]));

        update_agent(&state, "bot1".to_string(), Some("New Name".to_string()), Some("new-model".to_string()), Some(false)).unwrap();

        let agents = list_agents(&state).unwrap();
        assert_eq!(agents[0].name, "New Name");
        assert_eq!(agents[0].model, Some("new-model".to_string()));
        assert!(!agents[0].enabled);
    }

    #[test]
    fn update_agent_partial_update() {
        let tmp = tempfile::tempdir().unwrap();
        let state = make_state(tmp.path());
        write_config(tmp.path(), serde_json::json!([
            { "id": "bot2", "name": "Keep This", "model": "keep-model", "enabled": true }
        ]));

        // Only update enabled, keep name and model
        update_agent(&state, "bot2".to_string(), None, None, Some(false)).unwrap();

        let agents = list_agents(&state).unwrap();
        assert_eq!(agents[0].name, "Keep This");
        assert_eq!(agents[0].model, Some("keep-model".to_string()));
        assert!(!agents[0].enabled);
    }

    #[test]
    fn update_agent_fails_for_unknown_id() {
        let tmp = tempfile::tempdir().unwrap();
        let state = make_state(tmp.path());
        write_config(tmp.path(), serde_json::json!([]));

        let result = update_agent(&state, "nonexistent".to_string(), Some("X".to_string()), None, None);
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("not found"));
    }

    #[test]
    fn update_agent_rejects_invalid_id() {
        let tmp = tempfile::tempdir().unwrap();
        let state = make_state(tmp.path());
        write_config(tmp.path(), serde_json::json!([]));

        assert!(update_agent(&state, "../evil".to_string(), None, None, None).is_err());
    }
    #[test]
    fn delete_agent_removes_from_config() {
        let tmp = tempfile::tempdir().unwrap();
        let state = make_state(tmp.path());
        write_config(tmp.path(), serde_json::json!([
            { "id": "keep", "name": "Keep", "model": "m", "enabled": true },
            { "id": "remove", "name": "Remove", "model": "m", "enabled": true }
        ]));

        delete_agent(&state, "remove".to_string(), false).unwrap();

        let agents = list_agents(&state).unwrap();
        assert_eq!(agents.len(), 1);
        assert_eq!(agents[0].id, "keep");
    }

    #[test]
    fn delete_agent_with_files() {
        let tmp = tempfile::tempdir().unwrap();
        let state = make_state(tmp.path());
        write_config(tmp.path(), serde_json::json!([
            { "id": "doomed", "name": "Doomed", "model": "m", "enabled": true }
        ]));
        // Create agent files
        let agent_dir = tmp.path().join("agents/doomed/agent");
        fs::create_dir_all(&agent_dir).unwrap();
        fs::write(agent_dir.join("SOUL.md"), "test").unwrap();

        delete_agent(&state, "doomed".to_string(), true).unwrap();

        assert!(!tmp.path().join("agents/doomed").exists());
    }

    #[test]
    fn delete_agent_without_files_preserves_directory() {
        let tmp = tempfile::tempdir().unwrap();
        let state = make_state(tmp.path());
        write_config(tmp.path(), serde_json::json!([
            { "id": "kept-files", "name": "KF", "model": "m", "enabled": true }
        ]));
        let agent_dir = tmp.path().join("agents/kept-files/agent");
        fs::create_dir_all(&agent_dir).unwrap();
        fs::write(agent_dir.join("SOUL.md"), "preserve me").unwrap();

        delete_agent(&state, "kept-files".to_string(), false).unwrap();

        // Files should still exist
        assert!(tmp.path().join("agents/kept-files/agent/SOUL.md").exists());
        // But agent should be gone from config
        let agents = list_agents(&state).unwrap();
        assert!(agents.is_empty());
    }
    #[test]
    fn clear_agent_memory_removes_files() {
        let tmp = tempfile::tempdir().unwrap();
        let state = make_state(tmp.path());
        let memory_dir = tmp.path().join("agents/bot/memory");
        fs::create_dir_all(&memory_dir).unwrap();
        fs::write(memory_dir.join("chat.log"), "some memory").unwrap();

        clear_agent_memory(&state, "bot".to_string()).unwrap();

        assert!(memory_dir.exists(), "memory dir should be recreated");
        assert!(fs::read_dir(&memory_dir).unwrap().next().is_none(), "memory dir should be empty");
    }

    #[test]
    fn clear_agent_memory_noop_when_no_dir() {
        let tmp = tempfile::tempdir().unwrap();
        let state = make_state(tmp.path());
        // No memory dir exists — should not error
        clear_agent_memory(&state, "nonexistent".to_string()).unwrap();
    }

    #[test]
    fn archive_agent_memory_copies_files() {
        let tmp = tempfile::tempdir().unwrap();
        let state = make_state(tmp.path());
        let memory_dir = tmp.path().join("agents/bot/memory");
        fs::create_dir_all(&memory_dir).unwrap();
        fs::write(memory_dir.join("log1.txt"), "data1").unwrap();
        fs::write(memory_dir.join("log2.txt"), "data2").unwrap();

        let archive_path = archive_agent_memory(&state, "bot".to_string()).unwrap();

        // Archive should contain the files
        assert!(Path::new(&archive_path).join("log1.txt").exists());
        assert!(Path::new(&archive_path).join("log2.txt").exists());
        // Original memory should be cleared
        assert!(memory_dir.exists());
        assert!(fs::read_dir(&memory_dir).unwrap().next().is_none());
    }
    #[test]
    fn list_workspace_tree_returns_files_and_dirs() {
        let tmp = tempfile::tempdir().unwrap();
        let state = make_state(tmp.path());
        fs::create_dir_all(tmp.path().join("agents/bot")).unwrap();
        fs::write(tmp.path().join("agents/bot/SOUL.md"), "soul").unwrap();
        fs::write(tmp.path().join("readme.txt"), "hello").unwrap();

        let tree = list_workspace_tree(&state).unwrap();
        let names: Vec<&str> = tree.iter().map(|n| n.name.as_str()).collect();
        assert!(names.contains(&"agents"));
        assert!(names.contains(&"readme.txt"));
    }

    #[test]
    fn list_workspace_tree_skips_dotfiles() {
        let tmp = tempfile::tempdir().unwrap();
        let state = make_state(tmp.path());
        fs::write(tmp.path().join(".hidden"), "secret").unwrap();
        fs::write(tmp.path().join("visible"), "public").unwrap();

        let tree = list_workspace_tree(&state).unwrap();
        let names: Vec<&str> = tree.iter().map(|n| n.name.as_str()).collect();
        assert!(!names.contains(&".hidden"));
        assert!(names.contains(&"visible"));
    }

    #[test]
    fn list_workspace_tree_empty_for_nonexistent_dir() {
        let state = AppState {
            openclaw_dir: "/tmp/nonexistent_workspace_test_12345".to_string(),
            vault_dir: String::new(),
            audit_log_path: String::new(),
            vault: std::sync::Mutex::new(crate::state::VaultRuntime::default()),
        };
        let tree = list_workspace_tree(&state).unwrap();
        assert!(tree.is_empty());
    }

    #[test]
    fn create_workspace_file_writes_content() {
        let tmp = tempfile::tempdir().unwrap();
        let state = make_state(tmp.path());

        create_workspace_file(&state, "test/hello.txt".to_string(), "world".to_string()).unwrap();

        let content = fs::read_to_string(tmp.path().join("test/hello.txt")).unwrap();
        assert_eq!(content, "world");
    }

    #[test]
    fn create_workspace_file_rejects_path_traversal() {
        let tmp = tempfile::tempdir().unwrap();
        let state = make_state(tmp.path());

        let result = create_workspace_file(&state, "../../etc/evil".to_string(), "bad".to_string());
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("Access denied"));
    }

    #[test]
    fn delete_workspace_file_removes_file() {
        let tmp = tempfile::tempdir().unwrap();
        let state = make_state(tmp.path());
        fs::write(tmp.path().join("deleteme.txt"), "bye").unwrap();

        delete_workspace_file(&state, "deleteme.txt".to_string()).unwrap();
        assert!(!tmp.path().join("deleteme.txt").exists());
    }

    #[test]
    fn delete_workspace_file_rejects_traversal() {
        let tmp = tempfile::tempdir().unwrap();
        let state = make_state(tmp.path());

        let result = delete_workspace_file(&state, "../../etc/passwd".to_string());
        assert!(result.is_err());
    }

    #[test]
    fn read_agent_file_returns_content() {
        let tmp = tempfile::tempdir().unwrap();
        let state = make_state(tmp.path());
        fs::create_dir_all(tmp.path().join("agents/bot/agent")).unwrap();
        fs::write(tmp.path().join("agents/bot/agent/SOUL.md"), "# My Soul").unwrap();

        let content = read_agent_file(&state, "agents/bot/agent/SOUL.md".to_string()).unwrap();
        assert_eq!(content, "# My Soul");
    }

    #[test]
    fn read_agent_file_rejects_traversal() {
        let tmp = tempfile::tempdir().unwrap();
        let state = make_state(tmp.path());

        let result = read_agent_file(&state, "../../etc/passwd".to_string());
        assert!(result.is_err());
    }

    #[test]
    fn write_agent_file_creates_and_writes() {
        let tmp = tempfile::tempdir().unwrap();
        let state = make_state(tmp.path());
        fs::create_dir_all(tmp.path().join("agents/bot/agent")).unwrap();

        write_agent_file(&state, "agents/bot/agent/NEW.md".to_string(), "new content".to_string()).unwrap();

        let content = fs::read_to_string(tmp.path().join("agents/bot/agent/NEW.md")).unwrap();
        assert_eq!(content, "new content");
    }
    #[test]
    fn sync_agents_writes_gateway_config() {
        let tmp = tempfile::tempdir().unwrap();
        let state = make_state(tmp.path());
        write_config(tmp.path(), serde_json::json!([
            { "id": "bot1", "name": "Bot One", "model": "xai/grok-3-mini", "enabled": true }
        ]));

        do_sync_agents_to_gateway(&state).unwrap();

        let compose_dir = tmp.path().join("compose");
        let gw_config_path = compose_dir.join(".openclaw/openclaw.json");
        assert!(gw_config_path.exists());
        let content = fs::read_to_string(gw_config_path).unwrap();
        let config: serde_json::Value = serde_json::from_str(&content).unwrap();
        let agents = config["agents"]["list"].as_array().unwrap();
        assert_eq!(agents.len(), 1);
        assert_eq!(agents[0]["id"], "bot1");
    }

    #[test]
    fn sync_agents_skips_disabled_agents() {
        let tmp = tempfile::tempdir().unwrap();
        let state = make_state(tmp.path());
        write_config(tmp.path(), serde_json::json!([
            { "id": "enabled", "name": "On", "model": "grok-3-mini", "enabled": true },
            { "id": "disabled", "name": "Off", "model": "grok-3-mini", "enabled": false }
        ]));

        do_sync_agents_to_gateway(&state).unwrap();

        let gw_config_path = tmp.path().join("compose/.openclaw/openclaw.json");
        let content = fs::read_to_string(gw_config_path).unwrap();
        let config: serde_json::Value = serde_json::from_str(&content).unwrap();
        let agents = config["agents"]["list"].as_array().unwrap();
        assert_eq!(agents.len(), 1);
        assert_eq!(agents[0]["id"], "enabled");
    }

    #[test]
    fn sync_agents_auto_prefixes_model_provider() {
        let tmp = tempfile::tempdir().unwrap();
        let state = make_state(tmp.path());
        write_config(tmp.path(), serde_json::json!([
            { "id": "a", "name": "A", "model": "claude-sonnet-4-20250514", "enabled": true },
            { "id": "b", "name": "B", "model": "gpt-4o", "enabled": true },
            { "id": "c", "name": "C", "model": "llama3", "enabled": true },
            { "id": "d", "name": "D", "model": "grok-3-mini", "enabled": true }
        ]));

        do_sync_agents_to_gateway(&state).unwrap();

        let gw_config_path = tmp.path().join("compose/.openclaw/openclaw.json");
        let content = fs::read_to_string(gw_config_path).unwrap();
        let config: serde_json::Value = serde_json::from_str(&content).unwrap();
        let agents = config["agents"]["list"].as_array().unwrap();
        assert_eq!(agents[0]["model"]["primary"], "anthropic/claude-sonnet-4-20250514");
        assert_eq!(agents[1]["model"]["primary"], "openai/gpt-4o");
        assert_eq!(agents[2]["model"]["primary"], "ollama/llama3");
        assert_eq!(agents[3]["model"]["primary"], "xai/grok-3-mini");
    }

    #[test]
    fn sync_agents_preserves_existing_gateway_config() {
        let tmp = tempfile::tempdir().unwrap();
        let state = make_state(tmp.path());
        write_config(tmp.path(), serde_json::json!([
            { "id": "a1", "name": "A1", "model": "grok-3-mini", "enabled": true }
        ]));

        // Write existing gateway config with extra fields
        let gw_dir = tmp.path().join("compose/.openclaw");
        fs::create_dir_all(&gw_dir).unwrap();
        fs::write(gw_dir.join("openclaw.json"), r#"{"customField":"preserved","agents":{"list":[]}}"#).unwrap();

        do_sync_agents_to_gateway(&state).unwrap();

        let content = fs::read_to_string(gw_dir.join("openclaw.json")).unwrap();
        let config: serde_json::Value = serde_json::from_str(&content).unwrap();
        assert_eq!(config["customField"], "preserved");
        assert_eq!(config["agents"]["list"].as_array().unwrap().len(), 1);
    }

    #[test]
    fn sync_agents_propagates_channel_config() {
        let tmp = tempfile::tempdir().unwrap();
        let state = make_state(tmp.path());
        let config = serde_json::json!({
            "agents": { "list": [], "defaults": {} },
            "settings": {
                "gateway": { "url": "http://localhost:18790", "port": 18790, "wsUrl": "ws://localhost:18790" },
                "security": { "sandboxMode": "docker", "networkIsolation": true, "auditLogging": true },
                "desktop": { "dockerComposePath": tmp.path().join("compose").to_str().unwrap() },
                "channels": {
                    "telegram": { "enabled": true, "groupId": "-100123" },
                    "discord": { "enabled": false }
                }
            }
        });
        fs::write(tmp.path().join("openclaw.json"), config.to_string()).unwrap();
        fs::write(tmp.path().join("desktop-config.json"), config.to_string()).unwrap();

        do_sync_agents_to_gateway(&state).unwrap();

        let gw_content = fs::read_to_string(tmp.path().join("compose/.openclaw/openclaw.json")).unwrap();
        let gw: serde_json::Value = serde_json::from_str(&gw_content).unwrap();
        assert_eq!(gw["channels"]["telegram"]["enabled"], true);
        assert_eq!(gw["channels"]["telegram"]["groupId"], "-100123");
        // Disabled channels should not be synced
        assert!(gw["channels"]["discord"].is_null() || gw["channels"].get("discord").is_none());
    }
}
