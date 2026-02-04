use std::sync::Mutex;

#[derive(Default)]
pub struct VaultRuntime {
    pub encryption_key: Option<[u8; 32]>,
    pub failed_attempts: u32,
    pub last_failed_at: u64,
}

pub struct AppState {
    pub openclaw_dir: String,
    pub vault_dir: String,
    pub audit_log_path: String,
    pub vault: Mutex<VaultRuntime>,
}

impl AppState {
    pub fn new() -> Self {
        let home = dirs::home_dir().unwrap_or_default();
        let openclaw_dir = home.join(".openclaw").to_string_lossy().to_string();
        let vault_dir = home.join(".openclaw-desktop").to_string_lossy().to_string();
        let audit_log_path = home
            .join(".openclaw-desktop")
            .join("audit.log")
            .to_string_lossy()
            .to_string();

        Self {
            openclaw_dir,
            vault_dir,
            audit_log_path,
            vault: Mutex::new(VaultRuntime::default()),
        }
    }

    /// In bridge mode uses `desktop-config.json` to coexist with the gateway's `openclaw.json`.
    pub fn desktop_config_path(&self) -> String {
        if crate::commands::health::is_bridge_mode() {
            format!("{}/desktop-config.json", self.openclaw_dir)
        } else {
            format!("{}/openclaw.json", self.openclaw_dir)
        }
    }

    /// In bridge mode returns parent of `openclaw_dir`. Otherwise reads from config, falls back to ~/agent-mvp.
    pub fn docker_compose_dir(&self) -> String {
        if crate::commands::health::is_bridge_mode() {
            return std::path::Path::new(&self.openclaw_dir)
                .parent()
                .unwrap_or(std::path::Path::new(&self.openclaw_dir))
                .to_string_lossy()
                .to_string();
        }

        let config_path = format!("{}/openclaw.json", self.openclaw_dir);
        if let Ok(content) = std::fs::read_to_string(&config_path) {
            if let Ok(config) = serde_json::from_str::<serde_json::Value>(&content) {
                if let Some(path) = config["settings"]["desktop"]["dockerComposePath"].as_str() {
                    if let Some(stripped) = path.strip_prefix("~/") {
                        if let Some(home) = dirs::home_dir() {
                            return home.join(stripped).to_string_lossy().to_string();
                        }
                    }
                    return path.to_string();
                }
            }
        }
        let home = dirs::home_dir().unwrap_or_default();
        home.join("agent-mvp").to_string_lossy().to_string()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn state_with_dir(dir: &str) -> AppState {
        AppState {
            openclaw_dir: dir.to_string(),
            vault_dir: String::new(),
            audit_log_path: String::new(),
            vault: Mutex::new(VaultRuntime::default()),
        }
    }

    #[test]
    fn docker_compose_dir_falls_back_when_no_config() {
        let tmp = tempfile::tempdir().unwrap();
        let state = state_with_dir(tmp.path().to_str().unwrap());
        let result = state.docker_compose_dir();
        assert!(result.ends_with("agent-mvp"));
    }

    #[test]
    fn docker_compose_dir_reads_from_config() {
        let tmp = tempfile::tempdir().unwrap();
        let config = serde_json::json!({
            "settings": {
                "desktop": { "dockerComposePath": "/opt/my-stack" }
            }
        });
        std::fs::write(
            tmp.path().join("openclaw.json"),
            serde_json::to_string(&config).unwrap(),
        ).unwrap();

        let state = state_with_dir(tmp.path().to_str().unwrap());
        assert_eq!(state.docker_compose_dir(), "/opt/my-stack");
    }

    #[test]
    fn docker_compose_dir_expands_tilde() {
        let tmp = tempfile::tempdir().unwrap();
        let config = serde_json::json!({
            "settings": {
                "desktop": { "dockerComposePath": "~/my-project" }
            }
        });
        std::fs::write(
            tmp.path().join("openclaw.json"),
            serde_json::to_string(&config).unwrap(),
        ).unwrap();

        let state = state_with_dir(tmp.path().to_str().unwrap());
        let result = state.docker_compose_dir();
        assert!(result.ends_with("my-project"));
        assert!(!result.contains('~'));
    }

    #[test]
    fn desktop_config_path_returns_openclaw_json_in_normal_mode() {
        // When not in bridge mode, desktop_config_path == openclaw_dir/openclaw.json
        if !crate::commands::health::is_bridge_mode() {
            let state = state_with_dir("/tmp/fake-openclaw");
            let path = state.desktop_config_path();
            assert_eq!(path, "/tmp/fake-openclaw/openclaw.json");
        }
    }

    #[test]
    fn docker_compose_dir_ignores_malformed_json() {
        let tmp = tempfile::tempdir().unwrap();
        std::fs::write(tmp.path().join("openclaw.json"), "not json at all {{{").unwrap();

        let state = state_with_dir(tmp.path().to_str().unwrap());
        let result = state.docker_compose_dir();
        // Should fall back to ~/agent-mvp when JSON is unparseable
        assert!(result.ends_with("agent-mvp"));
    }

    #[test]
    fn docker_compose_dir_ignores_missing_desktop_key() {
        let tmp = tempfile::tempdir().unwrap();
        let config = serde_json::json!({
            "settings": {
                "gateway": { "port": 18790 }
            }
        });
        std::fs::write(
            tmp.path().join("openclaw.json"),
            serde_json::to_string(&config).unwrap(),
        ).unwrap();

        let state = state_with_dir(tmp.path().to_str().unwrap());
        let result = state.docker_compose_dir();
        // Should fall back to ~/agent-mvp when dockerComposePath is absent
        assert!(result.ends_with("agent-mvp"));
    }
}
