use crate::fs_utils::atomic_write;
use crate::security::{audit, sanitize};
use crate::state::AppState;
use serde::{Deserialize, Serialize};
use std::fs;
use std::path::Path;

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct SkillMdData {
    pub agent_name: String,
    pub description: String,
    pub capabilities: Vec<String>,
    pub model: String,
    pub channels: Vec<String>,
}

pub fn generate_skill_md(data: SkillMdData) -> Result<String, String> {
    let capabilities_list = data
        .capabilities
        .iter()
        .map(|c| format!("- {}", c))
        .collect::<Vec<_>>()
        .join("\n");

    let channels_list = data
        .channels
        .iter()
        .map(|c| format!("- {}", c))
        .collect::<Vec<_>>()
        .join("\n");

    let skill_md = format!(
        r#"# {}

{}

## Capabilities

{}

## Technical Details

- **Model:** {}
- **Runtime:** Agentic Console Gateway (Docker)
- **Protocol:** WebSocket

## Channels

{}

## Privacy

- All processing is local
- No data leaves the machine
- Credentials stored in local vault
"#,
        data.agent_name, data.description, capabilities_list, data.model, channels_list
    );

    Ok(skill_md)
}

pub fn save_skill_md(
    state: &AppState,
    agent_id: String,
    content: String,
) -> Result<(), String> {
    sanitize::validate_id(&agent_id)?;
    let path = format!("{}/agents/{}/skill.md", state.openclaw_dir, agent_id);

    // Ensure parent directory exists
    if let Some(parent) = Path::new(&path).parent() {
        fs::create_dir_all(parent).map_err(|e| format!("Failed to create directory: {}", e))?;
    }

    atomic_write(Path::new(&path), &content)
        .map_err(|e| format!("Failed to write skill.md: {}", e))?;

    audit::log_action(
        &state.audit_log_path,
        "MOLTBOOK_SKILL_MD",
        &format!("Generated skill.md for agent: {}", agent_id),
    );
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn generate_skill_md_includes_all_fields() {
        let data = SkillMdData {
            agent_name: "TestBot".to_string(),
            description: "A test bot for unit testing".to_string(),
            capabilities: vec!["chat".to_string(), "search".to_string()],
            model: "gpt-4".to_string(),
            channels: vec!["telegram".to_string(), "slack".to_string()],
        };

        let md = generate_skill_md(data).unwrap();
        assert!(md.contains("# TestBot"));
        assert!(md.contains("A test bot for unit testing"));
        assert!(md.contains("- chat"));
        assert!(md.contains("- search"));
        assert!(md.contains("**Model:** gpt-4"));
        assert!(md.contains("- telegram"));
        assert!(md.contains("- slack"));
        assert!(md.contains("## Capabilities"));
        assert!(md.contains("## Channels"));
        assert!(md.contains("## Privacy"));
    }

    #[test]
    fn generate_skill_md_empty_capabilities() {
        let data = SkillMdData {
            agent_name: "EmptyBot".to_string(),
            description: "No caps".to_string(),
            capabilities: vec![],
            model: "claude".to_string(),
            channels: vec!["discord".to_string()],
        };

        let md = generate_skill_md(data).unwrap();
        assert!(md.contains("# EmptyBot"));
        assert!(md.contains("## Capabilities"));
    }

    #[test]
    fn generate_skill_md_empty_channels() {
        let data = SkillMdData {
            agent_name: "Bot".to_string(),
            description: "Desc".to_string(),
            capabilities: vec!["cap".to_string()],
            model: "model".to_string(),
            channels: vec![],
        };

        let md = generate_skill_md(data).unwrap();
        assert!(md.contains("## Channels"));
    }
    fn make_state(tmp: &std::path::Path) -> crate::state::AppState {
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
    fn save_skill_md_creates_file() {
        let tmp = tempfile::tempdir().unwrap();
        let state = make_state(tmp.path());

        save_skill_md(&state, "my-agent".to_string(), "# Test\nContent".to_string()).unwrap();

        let path = tmp.path().join("agents/my-agent/skill.md");
        assert!(path.exists());
        let content = fs::read_to_string(&path).unwrap();
        assert_eq!(content, "# Test\nContent");
    }

    #[test]
    fn save_skill_md_overwrites_existing() {
        let tmp = tempfile::tempdir().unwrap();
        let state = make_state(tmp.path());

        save_skill_md(&state, "bot".to_string(), "old".to_string()).unwrap();
        save_skill_md(&state, "bot".to_string(), "new".to_string()).unwrap();

        let content = fs::read_to_string(tmp.path().join("agents/bot/skill.md")).unwrap();
        assert_eq!(content, "new");
    }

    #[test]
    fn save_skill_md_rejects_path_traversal() {
        let tmp = tempfile::tempdir().unwrap();
        let state = make_state(tmp.path());

        let result = save_skill_md(&state, "../escape".to_string(), "bad".to_string());
        assert!(result.is_err());
    }

    #[test]
    fn save_skill_md_rejects_empty_id() {
        let tmp = tempfile::tempdir().unwrap();
        let state = make_state(tmp.path());
        assert!(save_skill_md(&state, "".to_string(), "content".to_string()).is_err());
    }

    #[test]
    fn save_skill_md_logs_audit() {
        let tmp = tempfile::tempdir().unwrap();
        let state = make_state(tmp.path());

        save_skill_md(&state, "bot".to_string(), "md".to_string()).unwrap();

        let log = fs::read_to_string(&state.audit_log_path).unwrap();
        assert!(log.contains("MOLTBOOK_SKILL_MD"));
        assert!(log.contains("bot"));
    }
}
