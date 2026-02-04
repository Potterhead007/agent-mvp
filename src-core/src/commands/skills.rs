use crate::fs_utils::atomic_write;
use crate::security::{audit, sanitize};
use crate::state::AppState;
use serde::{Deserialize, Serialize};
use std::fs;
use std::path::Path;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SkillInfo {
    pub id: String,
    pub name: String,
    pub description: String,
    pub version: String,
    pub installed: bool,
    pub enabled: bool,
}

pub fn list_skills(state: &AppState) -> Result<Vec<SkillInfo>, String> {
    let skills_dir = format!("{}/skills", state.openclaw_dir);
    let mut skills = Vec::new();

    if let Ok(entries) = fs::read_dir(&skills_dir) {
        for entry in entries.flatten() {
            let path = entry.path();
            if path.is_dir() {
                let skill_json = path.join("skill.json");
                if skill_json.exists() {
                    if let Ok(content) = fs::read_to_string(&skill_json) {
                        if let Ok(val) = serde_json::from_str::<serde_json::Value>(&content) {
                            skills.push(SkillInfo {
                                id: val["id"].as_str().unwrap_or("").to_string(),
                                name: val["name"].as_str().unwrap_or("").to_string(),
                                description: val["description"]
                                    .as_str()
                                    .unwrap_or("")
                                    .to_string(),
                                version: val["version"].as_str().unwrap_or("0.0.0").to_string(),
                                installed: true,
                                enabled: val["enabled"].as_bool().unwrap_or(true),
                            });
                        }
                    }
                }
            }
        }
    }

    Ok(skills)
}

pub fn toggle_skill(
    state: &AppState,
    skill_id: String,
    enabled: bool,
) -> Result<(), String> {
    sanitize::validate_id(&skill_id)?;
    let skill_json_path = format!("{}/skills/{}/skill.json", state.openclaw_dir, skill_id);
    let content = fs::read_to_string(&skill_json_path)
        .map_err(|e| format!("Failed to read skill config: {}", e))?;
    let mut val: serde_json::Value =
        serde_json::from_str(&content).map_err(|e| format!("Invalid JSON: {}", e))?;

    val["enabled"] = serde_json::Value::Bool(enabled);

    let updated = serde_json::to_string_pretty(&val)
        .map_err(|e| format!("Failed to serialize: {}", e))?;
    atomic_write(Path::new(&skill_json_path), &updated)
        .map_err(|e| format!("Failed to write skill config: {}", e))?;

    audit::log_action(
        &state.audit_log_path,
        "SKILL_TOGGLE",
        &format!("Skill {} set to enabled={}", skill_id, enabled),
    );
    Ok(())
}

pub fn remove_skill(
    state: &AppState,
    skill_id: String,
) -> Result<(), String> {
    sanitize::validate_id(&skill_id)?;
    let skill_dir = format!("{}/skills/{}", state.openclaw_dir, skill_id);
    if std::path::Path::new(&skill_dir).exists() {
        fs::remove_dir_all(&skill_dir)
            .map_err(|e| format!("Failed to remove skill: {}", e))?;
    }
    audit::log_action(
        &state.audit_log_path,
        "SKILL_REMOVE",
        &format!("Removed skill: {}", skill_id),
    );
    Ok(())
}

pub struct CreateSkillParams {
    pub id: String,
    pub name: String,
    pub description: String,
    pub version: Option<String>,
    pub tools: Option<Vec<serde_json::Value>>,
    pub handler_code: Option<String>,
    pub requirements: Option<String>,
}

pub fn create_skill(
    state: &AppState,
    params: CreateSkillParams,
) -> Result<(), String> {
    let CreateSkillParams { id, name, description, version, tools, handler_code, requirements } = params;
    sanitize::validate_id(&id)?;

    let skills_dir = format!("{}/skills", state.openclaw_dir);
    let skill_dir = format!("{}/{}", skills_dir, id);

    // Check for duplicate
    if std::path::Path::new(&skill_dir).exists() {
        return Err(format!("Skill with ID '{}' already exists", id));
    }

    // Create directory structure
    fs::create_dir_all(format!("{}/tools", skill_dir))
        .map_err(|e| format!("Failed to create skill dirs: {}", e))?;
    fs::create_dir_all(format!("{}/src", skill_dir))
        .map_err(|e| format!("Failed to create src dir: {}", e))?;

    // Build tool names list for skill.json
    let tool_names: Vec<serde_json::Value> = tools
        .as_ref()
        .map(|t| {
            t.iter()
                .filter_map(|tool| {
                    tool.get("name")
                        .and_then(|n| n.as_str())
                        .map(|n| serde_json::Value::String(n.to_string()))
                })
                .collect()
        })
        .unwrap_or_default();

    // Write skill.json
    let skill_meta = serde_json::json!({
        "id": id,
        "name": name,
        "description": description,
        "version": version.as_deref().unwrap_or("1.0.0"),
        "enabled": true,
        "tools": tool_names,
    });
    let skill_json = serde_json::to_string_pretty(&skill_meta)
        .map_err(|e| format!("Failed to serialize skill.json: {}", e))?;
    atomic_write(Path::new(&format!("{}/skill.json", skill_dir)), &skill_json)
        .map_err(|e| format!("Failed to write skill.json: {}", e))?;

    // Write individual tool definition files
    if let Some(ref tool_list) = tools {
        for tool in tool_list {
            let tool_name = tool
                .get("name")
                .and_then(|n| n.as_str())
                .unwrap_or("unnamed");
            let tool_json = serde_json::to_string_pretty(tool)
                .map_err(|e| format!("Failed to serialize tool {}: {}", tool_name, e))?;
            atomic_write(Path::new(&format!("{}/tools/{}.json", skill_dir, tool_name)), &tool_json)
                .map_err(|e| format!("Failed to write tool {}: {}", tool_name, e))?;
        }
    }

    // Write handler.py (template or user-provided)
    let handler = handler_code.unwrap_or_else(|| {
        let mut template = String::from("# Skill handler for ");
        template.push_str(&name);
        template.push_str("\n\n");
        if let Some(ref tool_list) = tools {
            for tool in tool_list {
                let fn_name = tool
                    .get("name")
                    .and_then(|n| n.as_str())
                    .unwrap_or("handle");
                template.push_str(&format!(
                    "async def {}(input: dict, context: dict) -> dict:\n",
                    fn_name
                ));
                template.push_str("    # input[\"param_name\"] — access parameters\n");
                template.push_str("    # context[\"workspace\"] — agent workspace path\n");
                template.push_str("    return {\"result\": \"value\"}\n\n");
            }
        } else {
            template.push_str("async def handle(input: dict, context: dict) -> dict:\n");
            template.push_str("    # input[\"param_name\"] — access parameters\n");
            template.push_str("    # context[\"workspace\"] — agent workspace path\n");
            template.push_str("    return {\"result\": \"value\"}\n");
        }
        template
    });
    fs::write(format!("{}/src/handler.py", skill_dir), &handler)
        .map_err(|e| format!("Failed to write handler.py: {}", e))?;

    // Write requirements.txt
    let reqs = requirements.unwrap_or_default();
    fs::write(format!("{}/requirements.txt", skill_dir), &reqs)
        .map_err(|e| format!("Failed to write requirements.txt: {}", e))?;

    audit::log_action(
        &state.audit_log_path,
        "SKILL_CREATE",
        &format!("Created skill: {} ({})", name, id),
    );

    Ok(())
}

pub fn read_skill_file(
    state: &AppState,
    skill_id: String,
    relative_path: String,
) -> Result<String, String> {
    sanitize::validate_id(&skill_id)?;

    let skills_base = format!("{}/skills/{}", state.openclaw_dir, skill_id);
    let safe_path = sanitize::sanitize_path(&skills_base, &relative_path)
        .ok_or("Invalid path: access denied")?;

    fs::read_to_string(&safe_path).map_err(|e| format!("Failed to read file: {}", e))
}

pub fn update_skill_file(
    state: &AppState,
    skill_id: String,
    relative_path: String,
    content: String,
) -> Result<(), String> {
    sanitize::validate_id(&skill_id)?;

    let skills_base = format!("{}/skills/{}", state.openclaw_dir, skill_id);
    let safe_path = sanitize::sanitize_path(&skills_base, &relative_path)
        .ok_or("Invalid path: access denied")?;

    if let Some(parent) = std::path::Path::new(&safe_path).parent() {
        fs::create_dir_all(parent).map_err(|e| format!("Failed to create directories: {}", e))?;
    }

    fs::write(&safe_path, &content).map_err(|e| format!("Failed to write file: {}", e))?;

    audit::log_action(
        &state.audit_log_path,
        "SKILL_FILE_WRITE",
        &format!("Updated skill {} file: {}", skill_id, relative_path),
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
        crate::state::AppState {
            openclaw_dir: tmp.to_str().unwrap().to_string(),
            vault_dir: String::new(),
            audit_log_path: audit_path.to_str().unwrap().to_string(),
            vault: std::sync::Mutex::new(crate::state::VaultRuntime::default()),
        }
    }

    #[test]
    fn list_skills_empty_when_no_skills_dir() {
        let tmp = tempfile::tempdir().unwrap();
        let state = make_state(tmp.path());
        let skills = list_skills(&state).unwrap();
        assert!(skills.is_empty());
    }

    #[test]
    fn list_skills_reads_skill_json() {
        let tmp = tempfile::tempdir().unwrap();
        let state = make_state(tmp.path());
        let skill_dir = tmp.path().join("skills/web-search");
        fs::create_dir_all(&skill_dir).unwrap();
        fs::write(skill_dir.join("skill.json"), r#"{
            "id": "web-search",
            "name": "Web Search",
            "description": "Search the web",
            "version": "1.2.0",
            "enabled": true
        }"#).unwrap();

        let skills = list_skills(&state).unwrap();
        assert_eq!(skills.len(), 1);
        assert_eq!(skills[0].id, "web-search");
        assert_eq!(skills[0].name, "Web Search");
        assert_eq!(skills[0].version, "1.2.0");
        assert!(skills[0].enabled);
        assert!(skills[0].installed);
    }

    #[test]
    fn list_skills_skips_dirs_without_skill_json() {
        let tmp = tempfile::tempdir().unwrap();
        let state = make_state(tmp.path());
        fs::create_dir_all(tmp.path().join("skills/incomplete")).unwrap();

        let skills = list_skills(&state).unwrap();
        assert!(skills.is_empty());
    }

    #[test]
    fn list_skills_skips_malformed_json() {
        let tmp = tempfile::tempdir().unwrap();
        let state = make_state(tmp.path());
        let skill_dir = tmp.path().join("skills/broken");
        fs::create_dir_all(&skill_dir).unwrap();
        fs::write(skill_dir.join("skill.json"), "not json {{{").unwrap();

        let skills = list_skills(&state).unwrap();
        assert!(skills.is_empty());
    }

    #[test]
    fn list_skills_defaults_missing_fields() {
        let tmp = tempfile::tempdir().unwrap();
        let state = make_state(tmp.path());
        let skill_dir = tmp.path().join("skills/minimal");
        fs::create_dir_all(&skill_dir).unwrap();
        fs::write(skill_dir.join("skill.json"), r#"{}"#).unwrap();

        let skills = list_skills(&state).unwrap();
        assert_eq!(skills.len(), 1);
        assert_eq!(skills[0].id, "");
        assert_eq!(skills[0].version, "0.0.0");
        assert!(skills[0].enabled);
    }

    #[test]
    fn create_skill_builds_full_structure() {
        let tmp = tempfile::tempdir().unwrap();
        let state = make_state(tmp.path());

        let tools = vec![serde_json::json!({
            "name": "search",
            "description": "Search tool",
            "inputSchema": { "type": "object" }
        })];

        create_skill(&state, CreateSkillParams {
            id: "my-skill".into(), name: "My Skill".into(),
            description: "Does things".into(), version: Some("2.0.0".into()),
            tools: Some(tools), handler_code: None, requirements: Some("requests>=2.0".into()),
        }).unwrap();

        let skill_dir = tmp.path().join("skills/my-skill");
        assert!(skill_dir.join("skill.json").exists());
        assert!(skill_dir.join("tools/search.json").exists());
        assert!(skill_dir.join("src/handler.py").exists());
        assert!(skill_dir.join("requirements.txt").exists());

        let meta: serde_json::Value = serde_json::from_str(
            &fs::read_to_string(skill_dir.join("skill.json")).unwrap()
        ).unwrap();
        assert_eq!(meta["id"], "my-skill");
        assert_eq!(meta["version"], "2.0.0");
        assert_eq!(meta["enabled"], true);
    }

    #[test]
    fn create_skill_rejects_duplicate() {
        let tmp = tempfile::tempdir().unwrap();
        let state = make_state(tmp.path());
        fs::create_dir_all(tmp.path().join("skills/existing")).unwrap();

        let result = create_skill(&state, CreateSkillParams {
            id: "existing".into(), name: "X".into(), description: "X".into(),
            version: None, tools: None, handler_code: None, requirements: None,
        });
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("already exists"));
    }

    #[test]
    fn create_skill_rejects_invalid_id() {
        let tmp = tempfile::tempdir().unwrap();
        let state = make_state(tmp.path());

        assert!(create_skill(&state, CreateSkillParams {
            id: "../bad".into(), name: "X".into(), description: "X".into(),
            version: None, tools: None, handler_code: None, requirements: None,
        }).is_err());
        assert!(create_skill(&state, CreateSkillParams {
            id: "".into(), name: "X".into(), description: "X".into(),
            version: None, tools: None, handler_code: None, requirements: None,
        }).is_err());
    }

    #[test]
    fn create_skill_generates_handler_template() {
        let tmp = tempfile::tempdir().unwrap();
        let state = make_state(tmp.path());

        create_skill(&state, CreateSkillParams {
            id: "no-tools".into(), name: "No Tools".into(), description: "Bare".into(),
            version: None, tools: None, handler_code: None, requirements: None,
        }).unwrap();

        let handler = fs::read_to_string(tmp.path().join("skills/no-tools/src/handler.py")).unwrap();
        assert!(handler.contains("async def handle"));
    }

    #[test]
    fn create_skill_uses_custom_handler() {
        let tmp = tempfile::tempdir().unwrap();
        let state = make_state(tmp.path());

        let custom = "async def run(input, ctx): return {}".to_string();
        create_skill(&state, CreateSkillParams {
            id: "custom".into(), name: "Custom".into(), description: "C".into(),
            version: None, tools: None, handler_code: Some(custom.clone()), requirements: None,
        }).unwrap();

        let handler = fs::read_to_string(tmp.path().join("skills/custom/src/handler.py")).unwrap();
        assert_eq!(handler, custom);
    }

    #[test]
    fn toggle_skill_updates_enabled() {
        let tmp = tempfile::tempdir().unwrap();
        let state = make_state(tmp.path());
        let skill_dir = tmp.path().join("skills/toggleable");
        fs::create_dir_all(&skill_dir).unwrap();
        fs::write(skill_dir.join("skill.json"), r#"{"id":"toggleable","enabled":true}"#).unwrap();

        toggle_skill(&state, "toggleable".to_string(), false).unwrap();

        let meta: serde_json::Value = serde_json::from_str(
            &fs::read_to_string(skill_dir.join("skill.json")).unwrap()
        ).unwrap();
        assert_eq!(meta["enabled"], false);
    }

    #[test]
    fn toggle_skill_fails_for_missing_skill() {
        let tmp = tempfile::tempdir().unwrap();
        let state = make_state(tmp.path());
        assert!(toggle_skill(&state, "ghost".to_string(), true).is_err());
    }

    #[test]
    fn toggle_skill_rejects_invalid_id() {
        let tmp = tempfile::tempdir().unwrap();
        let state = make_state(tmp.path());
        assert!(toggle_skill(&state, "../evil".to_string(), true).is_err());
    }

    #[test]
    fn remove_skill_deletes_directory() {
        let tmp = tempfile::tempdir().unwrap();
        let state = make_state(tmp.path());
        let skill_dir = tmp.path().join("skills/doomed");
        fs::create_dir_all(skill_dir.join("src")).unwrap();
        fs::write(skill_dir.join("skill.json"), "{}").unwrap();

        remove_skill(&state, "doomed".to_string()).unwrap();
        assert!(!skill_dir.exists());
    }

    #[test]
    fn remove_skill_noop_for_missing() {
        let tmp = tempfile::tempdir().unwrap();
        let state = make_state(tmp.path());
        remove_skill(&state, "nonexistent".to_string()).unwrap();
    }

    #[test]
    fn read_skill_file_returns_content() {
        let tmp = tempfile::tempdir().unwrap();
        let state = make_state(tmp.path());
        let skill_dir = tmp.path().join("skills/test-skill/src");
        fs::create_dir_all(&skill_dir).unwrap();
        fs::write(skill_dir.join("handler.py"), "print('hello')").unwrap();

        let content = read_skill_file(&state, "test-skill".to_string(), "src/handler.py".to_string()).unwrap();
        assert_eq!(content, "print('hello')");
    }

    #[test]
    fn read_skill_file_rejects_traversal() {
        let tmp = tempfile::tempdir().unwrap();
        let state = make_state(tmp.path());
        fs::create_dir_all(tmp.path().join("skills/safe")).unwrap();

        let result = read_skill_file(&state, "safe".to_string(), "../../etc/passwd".to_string());
        assert!(result.is_err());
    }

    #[test]
    fn update_skill_file_writes_content() {
        let tmp = tempfile::tempdir().unwrap();
        let state = make_state(tmp.path());
        let skill_dir = tmp.path().join("skills/test-skill/src");
        fs::create_dir_all(&skill_dir).unwrap();

        update_skill_file(&state, "test-skill".to_string(), "src/handler.py".to_string(), "new code".to_string()).unwrap();

        let content = fs::read_to_string(skill_dir.join("handler.py")).unwrap();
        assert_eq!(content, "new code");
    }

    #[test]
    fn update_skill_file_rejects_traversal() {
        let tmp = tempfile::tempdir().unwrap();
        let state = make_state(tmp.path());
        fs::create_dir_all(tmp.path().join("skills/safe")).unwrap();

        let result = update_skill_file(&state, "safe".to_string(), "../../etc/evil".to_string(), "bad".to_string());
        assert!(result.is_err());
    }
}
