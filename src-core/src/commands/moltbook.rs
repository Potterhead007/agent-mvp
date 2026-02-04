use crate::security::{audit, sanitize};
use crate::state::AppState;
use serde::{Deserialize, Serialize};
use std::fs;

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
    if let Some(parent) = std::path::Path::new(&path).parent() {
        fs::create_dir_all(parent).map_err(|e| format!("Failed to create directory: {}", e))?;
    }

    fs::write(&path, &content).map_err(|e| format!("Failed to write skill.md: {}", e))?;

    audit::log_action(
        &state.audit_log_path,
        "MOLTBOOK_SKILL_MD",
        &format!("Generated skill.md for agent: {}", agent_id),
    );
    Ok(())
}
