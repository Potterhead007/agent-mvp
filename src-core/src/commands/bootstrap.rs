use crate::constants::DEFAULT_GATEWAY_PORT;
use crate::security::audit;
use crate::state::AppState;
use rand::RngCore;
use serde::{Deserialize, Serialize};
use std::fs;
#[cfg(unix)]
use std::os::unix::fs::PermissionsExt;
use std::process::Command;

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum BootstrapStatus {
    AlreadyExists,
    Created,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct BootstrapResult {
    pub status: BootstrapStatus,
    pub message: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct DockerCheck {
    pub docker_installed: bool,
    pub compose_installed: bool,
    pub docker_running: bool,
    pub docker_version: Option<String>,
    pub compose_version: Option<String>,
}

fn random_hex(bytes: usize) -> String {
    let mut buf = vec![0u8; bytes];
    rand::rngs::OsRng.fill_bytes(&mut buf);
    super::vault::hex::encode(&buf)
}

fn provider_env_key(provider: &str) -> Result<&str, String> {
    match provider {
        "anthropic" => Ok("ANTHROPIC_API_KEY"),
        "xai" => Ok("XAI_API_KEY"),
        "openai" => Ok("OPENAI_API_KEY"),
        "ollama" => Ok("OLLAMA_BASE_URL"),
        _ => Err(format!("Unknown provider: {}", provider)),
    }
}

fn sanitize_env_value(input: &str) -> String {
    input
        .chars()
        .filter(|c| *c != '\n' && *c != '\r' && *c != '\0' && *c != '#')
        .collect()
}

fn copy_dir_all(src: &std::path::Path, dst: &std::path::Path) -> Result<(), std::io::Error> {
    fs::create_dir_all(dst)?;
    for entry in fs::read_dir(src)? {
        let entry = entry?;
        let ty = entry.file_type()?;
        let dest = dst.join(entry.file_name());
        if ty.is_dir() {
            copy_dir_all(&entry.path(), &dest)?;
        } else {
            fs::copy(entry.path(), &dest)?;
        }
    }
    Ok(())
}

/// Resolve a bundled resource path by looking for `{resource_dir}/{filename}`.
/// The caller (Tauri wrapper or test harness) is responsible for providing the
/// correct `resource_dir`.
fn resource_path(resource_dir: &str, filename: &str) -> Result<std::path::PathBuf, String> {
    let path = std::path::PathBuf::from(resource_dir).join(filename);
    if path.is_file() {
        return Ok(path);
    }
    Err(format!("Bundled resource not found: {}", filename))
}

fn build_env_body(comment: &str, vars: &[(&str, &str)]) -> String {
    let mut out = format!("# {}\n", comment);
    for (k, v) in vars {
        out.push_str(k);
        out.push('=');
        out.push_str(v);
        out.push('\n');
    }
    out
}

pub fn bootstrap_backend(
    resource_dir: &str,
    state: &AppState,
) -> Result<BootstrapResult, String> {
    let home = dirs::home_dir().ok_or("Cannot determine home directory")?;
    let backend_dir = home.join("agent-mvp");
    let compose_path = backend_dir.join("docker-compose.yml");

    if compose_path.is_file() {
        return Ok(BootstrapResult {
            status: BootstrapStatus::AlreadyExists,
            message: "Backend directory already exists".to_string(),
        });
    }

    // Create directory structure
    fs::create_dir_all(&backend_dir)
        .map_err(|e| format!("Failed to create backend directory: {}", e))?;
    fs::create_dir_all(backend_dir.join(".openclaw"))
        .map_err(|e| format!("Failed to create .openclaw directory: {}", e))?;

    // Copy bundled resources
    let compose_src = resource_path(resource_dir, "docker-compose.yml")?;
    fs::copy(&compose_src, &compose_path)
        .map_err(|e| format!("Failed to copy docker-compose.yml: {}", e))?;

    let dockerfile_src = resource_path(resource_dir, "Dockerfile.gateway")?;
    fs::copy(&dockerfile_src, backend_dir.join("Dockerfile.gateway"))
        .map_err(|e| format!("Failed to copy Dockerfile.gateway: {}", e))?;

    let dockerfile_bridge_src = resource_path(resource_dir, "Dockerfile.bridge")?;
    fs::copy(&dockerfile_bridge_src, backend_dir.join("Dockerfile.bridge"))
        .map_err(|e| format!("Failed to copy Dockerfile.bridge: {}", e))?;

    // Copy Rust workspace files needed to build the bridge container.
    // The Dockerfile.bridge expects Cargo.toml, Cargo.lock, src-core/, src-bridge/,
    // and src-tauri/Cargo.toml relative to the build context.
    let repo_root = std::path::Path::new(resource_dir)
        .parent()  // src-tauri
        .and_then(|p| p.parent())  // repo root
        .ok_or("Cannot determine repo root from resource dir")?;

    // Copy workspace manifests
    let copy_file = |src: &str, dst: &str| -> Result<(), String> {
        let from = repo_root.join(src);
        let to = backend_dir.join(dst);
        if let Some(parent) = to.parent() {
            fs::create_dir_all(parent)
                .map_err(|e| format!("Failed to create dir for {}: {}", dst, e))?;
        }
        fs::copy(&from, &to)
            .map_err(|e| format!("Failed to copy {} -> {}: {}", src, dst, e))?;
        Ok(())
    };

    let copy_dir_recursive = |src: &str, dst: &str| -> Result<(), String> {
        let from = repo_root.join(src);
        let to = backend_dir.join(dst);
        if !from.is_dir() {
            return Err(format!("Source directory not found: {}", src));
        }
        copy_dir_all(&from, &to)
            .map_err(|e| format!("Failed to copy directory {} -> {}: {}", src, dst, e))
    };

    copy_file("Cargo.toml", "Cargo.toml")?;
    copy_file("Cargo.lock", "Cargo.lock")?;
    copy_file("src-tauri/Cargo.toml", "src-tauri/Cargo.toml")?;
    copy_dir_recursive("src-core", "src-core")?;
    copy_dir_recursive("src-bridge", "src-bridge")?;

    audit::log_action(
        &state.audit_log_path,
        "BOOTSTRAP_BACKEND",
        "Created ~/agent-mvp/ with bundled Docker files",
    );

    Ok(BootstrapResult {
        status: BootstrapStatus::Created,
        message: "Backend directory created with Docker files".to_string(),
    })
}

pub fn check_backend_exists() -> bool {
    dirs::home_dir()
        .map(|h| h.join("agent-mvp").join("docker-compose.yml").is_file())
        .unwrap_or(false)
}

pub fn write_backend_env(
    state: &AppState,
    api_key: String,
    provider: String,
) -> Result<String, String> {
    let home = dirs::home_dir().ok_or("Cannot determine home directory")?;
    let backend_dir = home.join("agent-mvp");
    let openclaw_dir = backend_dir.join(".openclaw");

    // Ensure directories exist
    fs::create_dir_all(&openclaw_dir)
        .map_err(|e| format!("Failed to create .openclaw directory: {}", e))?;

    // If .env already exists, extract the existing GATEWAY_TOKEN and return it
    // instead of regenerating secrets (which would break running services).
    let root_env_path = backend_dir.join(".env");
    if root_env_path.is_file() {
        let existing = fs::read_to_string(&root_env_path).unwrap_or_default();
        if let Some(token) = existing
            .lines()
            .find_map(|l| l.strip_prefix("GATEWAY_TOKEN="))
        {
            let token = token.trim().to_string();
            if !token.is_empty() {
                audit::log_action(
                    &state.audit_log_path,
                    "WRITE_BACKEND_ENV",
                    "Skipped — .env already exists, returning existing GATEWAY_TOKEN",
                );
                return Ok(token);
            }
        }
    }

    // Validate and sanitize inputs
    let env_key = provider_env_key(&provider)?;
    let safe_api_key = sanitize_env_value(&api_key);

    // Generate secrets
    let gateway_token = random_hex(32); // 64 hex chars
    let bridge_auto_token = random_hex(32); // 64 hex chars — lets web console auto-connect
    let postgres_password = random_hex(16); // 32 hex chars
    let redis_password = random_hex(16); // 32 hex chars

    let gateway_port_str = DEFAULT_GATEWAY_PORT.to_string();
    let env_vars: Vec<(&str, &str)> = vec![
        (env_key, &safe_api_key),
        ("GATEWAY_TOKEN", &gateway_token),
        ("OPENCLAW_GATEWAY_TOKEN", &gateway_token),
        ("BRIDGE_AUTO_TOKEN", &bridge_auto_token),
        ("GATEWAY_PORT", &gateway_port_str),
        ("POSTGRES_PASSWORD", &postgres_password),
        ("POSTGRES_USER", "openclaw"),
        ("POSTGRES_DB", "openclaw"),
        ("POSTGRES_PORT", "5433"),
        ("REDIS_PASSWORD", &redis_password),
        ("REDIS_PORT", "6380"),
        ("OPENCLAW_DISABLE_BONJOUR", "1"),
        ("NODE_ENV", "production"),
    ];

    // 1. Root .env for docker-compose variable substitution
    let root_env = build_env_body("Generated by Agentic Console — do not edit manually", &env_vars);
    fs::write(&root_env_path, &root_env)
        .map_err(|e| format!("Failed to write .env: {}", e))?;
    #[cfg(unix)]
    fs::set_permissions(&root_env_path, fs::Permissions::from_mode(0o600))
        .map_err(|e| format!("Failed to set .env permissions: {}", e))?;

    // 2. .openclaw/.env for the gateway container (env_file in compose)
    let gateway_env = build_env_body("Gateway environment — generated by Agentic Console", &env_vars);
    let gw_env_path = openclaw_dir.join(".env");
    fs::write(&gw_env_path, &gateway_env)
        .map_err(|e| format!("Failed to write .openclaw/.env: {}", e))?;
    #[cfg(unix)]
    fs::set_permissions(&gw_env_path, fs::Permissions::from_mode(0o600))
        .map_err(|e| format!("Failed to set .openclaw/.env permissions: {}", e))?;

    // 3. Sync gateway.auth.token in openclaw.json so the gateway server uses
    //    the same token as the .env / vault.
    let config_path = openclaw_dir.join("openclaw.json");
    if config_path.is_file() {
        if let Ok(content) = fs::read_to_string(&config_path) {
            if let Ok(mut config) = serde_json::from_str::<serde_json::Value>(&content) {
                if let Some(gw) = config.get_mut("gateway") {
                    if let Some(auth) = gw.get_mut("auth") {
                        auth["token"] = serde_json::Value::String(gateway_token.clone());
                    } else {
                        gw["auth"] = serde_json::json!({
                            "mode": "token",
                            "token": &gateway_token,
                        });
                    }
                } else {
                    config["gateway"] = serde_json::json!({
                        "auth": {
                            "mode": "token",
                            "token": &gateway_token,
                        }
                    });
                }
                if let Ok(updated) = serde_json::to_string_pretty(&config) {
                    let _ = fs::write(&config_path, updated.as_bytes());
                }
            }
        }
    }

    audit::log_action(
        &state.audit_log_path,
        "WRITE_BACKEND_ENV",
        &format!("Generated .env files for provider: {}", provider),
    );

    // Return the gateway token so the frontend can store it in the vault
    Ok(gateway_token)
}

pub fn check_docker_installed() -> DockerCheck {
    // Inside Docker (bridge mode): everything is already running
    if super::health::is_bridge_mode() {
        return DockerCheck {
            docker_installed: true,
            compose_installed: true,
            docker_running: true,
            docker_version: Some("Docker (managed externally)".to_string()),
            compose_version: Some("Docker Compose (managed externally)".to_string()),
        };
    }

    let docker = crate::commands::docker::find_docker();
    let docker_version = Command::new(&docker)
        .arg("--version")
        .output()
        .ok()
        .filter(|o| o.status.success())
        .map(|o| String::from_utf8_lossy(&o.stdout).trim().to_string());

    // Short-circuit: if docker binary not found, skip compose and info checks
    if docker_version.is_none() {
        return DockerCheck {
            docker_installed: false,
            compose_installed: false,
            docker_running: false,
            docker_version: None,
            compose_version: None,
        };
    }

    let compose_version = Command::new(&docker)
        .args(["compose", "version"])
        .output()
        .ok()
        .filter(|o| o.status.success())
        .map(|o| String::from_utf8_lossy(&o.stdout).trim().to_string());

    let docker_running = Command::new(&docker)
        .arg("info")
        .output()
        .map(|o| o.status.success())
        .unwrap_or(false);

    DockerCheck {
        docker_installed: true,
        compose_installed: compose_version.is_some(),
        docker_running,
        docker_version,
        compose_version,
    }
}

fn parse_env_file(content: &str) -> std::collections::BTreeMap<String, String> {
    let mut map = std::collections::BTreeMap::new();
    for line in content.lines() {
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        if let Some((k, v)) = line.split_once('=') {
            map.insert(k.to_string(), v.to_string());
        }
    }
    map
}

fn serialize_env_map(map: &std::collections::BTreeMap<String, String>) -> String {
    let mut body = String::from("# Generated by Agentic Console — do not edit manually\n");
    for (k, v) in map {
        body.push_str(k);
        body.push('=');
        body.push_str(v);
        body.push('\n');
    }
    body
}

fn write_env_secure(path: &std::path::Path, body: &str) -> Result<(), String> {
    fs::write(path, body)
        .map_err(|e| format!("Failed to write {}: {}", path.display(), e))?;
    #[cfg(unix)]
    fs::set_permissions(path, fs::Permissions::from_mode(0o600))
        .map_err(|e| format!("Failed to set permissions on {}: {}", path.display(), e))?;
    Ok(())
}

pub fn sync_env_to_gateway(state: &AppState) -> Result<(), String> {
    let home = dirs::home_dir().ok_or("Cannot determine home directory")?;
    let backend_dir = home.join("agent-mvp");
    let root_env_path = backend_dir.join(".env");
    let gw_env_path = backend_dir.join(".openclaw").join(".env");

    // Read existing .env into a key→value map (preserves generated secrets)
    let mut env_map = if root_env_path.is_file() {
        parse_env_file(&fs::read_to_string(&root_env_path).unwrap_or_default())
    } else {
        std::collections::BTreeMap::new()
    };

    // Read vault secrets and merge them
    let vault = state.vault.lock().map_err(|e| format!("Vault lock error: {}", e))?;
    let encryption_key = vault.encryption_key
        .ok_or("Vault is locked — unlock it first to sync credentials")?;
    drop(vault);

    // Read encrypted secrets using shared vault crypto
    use super::vault::{decrypt_data, EncryptedBlob};
    let secrets_path = format!("{}/vault_secrets.enc", state.vault_dir);
    let secrets_map: std::collections::HashMap<String, String> =
        if let Ok(content) = fs::read_to_string(&secrets_path) {
            if let Ok(blob) = serde_json::from_str::<EncryptedBlob>(&content) {
                match decrypt_data(&encryption_key, &blob) {
                    Ok(plaintext) => {
                        let json = String::from_utf8(plaintext).unwrap_or_default();
                        serde_json::from_str(&json).unwrap_or_default()
                    }
                    Err(_) => std::collections::HashMap::new(),
                }
            } else {
                std::collections::HashMap::new()
            }
        } else {
            std::collections::HashMap::new()
        };

    // Map vault keys to env var names
    let passthrough_keys = [
        "XAI_API_KEY", "ANTHROPIC_API_KEY", "OPENAI_API_KEY", "OLLAMA_BASE_URL",
        "TELEGRAM_BOT_TOKEN", "SLACK_BOT_TOKEN", "SLACK_APP_TOKEN",
        "DISCORD_BOT_TOKEN", "GATEWAY_TOKEN", "BRIDGE_AUTO_TOKEN",
    ];

    for key in &passthrough_keys {
        if let Some(value) = secrets_map.get(*key) {
            if !value.is_empty() {
                let safe_value = sanitize_env_value(value);
                if *key == "GATEWAY_TOKEN" {
                    env_map.insert("OPENCLAW_GATEWAY_TOKEN".to_string(), safe_value.clone());
                }
                env_map.insert(key.to_string(), safe_value);
            }
        }
    }

    let body = serialize_env_map(&env_map);
    write_env_secure(&root_env_path, &body)?;
    let _ = fs::create_dir_all(backend_dir.join(".openclaw"));
    write_env_secure(&gw_env_path, &body)?;

    audit::log_action(
        &state.audit_log_path,
        "ENV_SYNC",
        "Synced vault credentials to gateway .env files",
    );

    Ok(())
}

pub fn sync_env_secret(state: &AppState, key: String, value: String) -> Result<(), String> {
    let openclaw_dir = std::path::Path::new(&state.openclaw_dir);
    let env_path = openclaw_dir.join(".env");

    let mut env_map = if env_path.is_file() {
        parse_env_file(&fs::read_to_string(&env_path).unwrap_or_default())
    } else {
        std::collections::BTreeMap::new()
    };

    env_map.insert(key.clone(), sanitize_env_value(&value));

    let body = serialize_env_map(&env_map);

    let _ = fs::create_dir_all(openclaw_dir);
    write_env_secure(&env_path, &body)?;

    audit::log_action(
        &state.audit_log_path,
        "ENV_SECRET_SET",
        &format!("Set env key: {}", key),
    );

    Ok(())
}

pub fn read_env_secret(state: &AppState, key: String) -> Result<Option<String>, String> {
    let path = std::path::Path::new(&state.openclaw_dir).join(".env");
    if !path.is_file() {
        return Ok(None);
    }
    let env_map = parse_env_file(&fs::read_to_string(&path).unwrap_or_default());
    Ok(env_map.get(&key).filter(|v| !v.trim().is_empty()).map(|v| v.trim().to_string()))
}

pub fn list_env_secrets(state: &AppState) -> Result<Vec<String>, String> {
    let path = std::path::Path::new(&state.openclaw_dir).join(".env");
    if !path.is_file() {
        return Ok(vec![]);
    }
    let env_map = parse_env_file(&fs::read_to_string(&path).unwrap_or_default());
    Ok(env_map.into_iter()
        .filter(|(_, v)| !v.trim().is_empty())
        .map(|(k, _)| k)
        .collect())
}

pub fn remove_env_secret(state: &AppState, key: String) -> Result<(), String> {
    let path = std::path::Path::new(&state.openclaw_dir).join(".env");
    if !path.is_file() {
        return Ok(());
    }
    let mut env_map = parse_env_file(&fs::read_to_string(&path).unwrap_or_default());
    if env_map.remove(&key).is_some() {
        let body = serialize_env_map(&env_map);
        fs::write(&path, body)
            .map_err(|e| format!("Failed to write .env: {}", e))?;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn random_hex_correct_length() {
        let h32 = random_hex(32);
        assert_eq!(h32.len(), 64);
        let h16 = random_hex(16);
        assert_eq!(h16.len(), 32);
    }

    #[test]
    fn random_hex_is_valid_hex() {
        let h = random_hex(16);
        assert!(h.chars().all(|c| c.is_ascii_hexdigit()));
    }

    #[test]
    fn provider_env_key_mapping() {
        assert_eq!(provider_env_key("anthropic").unwrap(), "ANTHROPIC_API_KEY");
        assert_eq!(provider_env_key("xai").unwrap(), "XAI_API_KEY");
        assert_eq!(provider_env_key("openai").unwrap(), "OPENAI_API_KEY");
        assert_eq!(provider_env_key("ollama").unwrap(), "OLLAMA_BASE_URL");
        assert!(provider_env_key("unknown").is_err());
    }

    #[test]
    fn sanitize_env_value_strips_dangerous_chars() {
        assert_eq!(sanitize_env_value("normal-key-123"), "normal-key-123");
        assert_eq!(
            sanitize_env_value("xai-key\nSECRET=evil"),
            "xai-keySECRET=evil"
        );
        assert_eq!(sanitize_env_value("key\r\n\0bad"), "keybad");
        assert_eq!(sanitize_env_value("key#comment"), "keycomment");
    }

    #[test]
    fn build_env_body_no_leading_whitespace() {
        let body = build_env_body("test", &[("KEY", "val"), ("B", "2")]);
        for line in body.lines().skip(1) {
            assert!(
                !line.starts_with(' '),
                "Line has leading whitespace: {:?}",
                line
            );
        }
        assert!(body.contains("KEY=val\n"));
        assert!(body.contains("B=2\n"));
    }
    fn make_state_with_dir(dir: &str) -> AppState {
        AppState {
            openclaw_dir: dir.to_string(),
            vault_dir: String::new(),
            audit_log_path: String::new(),
            vault: std::sync::Mutex::new(crate::state::VaultRuntime::default()),
        }
    }

    #[test]
    fn list_env_secrets_returns_keys_with_values() {
        let tmp = tempfile::tempdir().unwrap();
        let env_path = tmp.path().join(".env");
        fs::write(&env_path, "# comment\nKEY_A=value_a\nKEY_B=value_b\nEMPTY=\n").unwrap();

        let state = make_state_with_dir(tmp.path().to_str().unwrap());
        let keys = list_env_secrets(&state).unwrap();
        assert!(keys.contains(&"KEY_A".to_string()));
        assert!(keys.contains(&"KEY_B".to_string()));
        assert!(!keys.contains(&"EMPTY".to_string()), "empty values should be excluded");
    }

    #[test]
    fn list_env_secrets_empty_when_no_file() {
        let tmp = tempfile::tempdir().unwrap();
        let state = make_state_with_dir(tmp.path().to_str().unwrap());
        let keys = list_env_secrets(&state).unwrap();
        assert!(keys.is_empty());
    }

    #[test]
    fn list_env_secrets_skips_comments_and_blank_lines() {
        let tmp = tempfile::tempdir().unwrap();
        let env_path = tmp.path().join(".env");
        fs::write(&env_path, "# header\n\n  \n# another comment\nONLY_KEY=val\n").unwrap();

        let state = make_state_with_dir(tmp.path().to_str().unwrap());
        let keys = list_env_secrets(&state).unwrap();
        assert_eq!(keys, vec!["ONLY_KEY".to_string()]);
    }
    #[test]
    fn remove_env_secret_deletes_line() {
        let tmp = tempfile::tempdir().unwrap();
        let env_path = tmp.path().join(".env");
        fs::write(&env_path, "# header\nKEEP=yes\nDELETE_ME=gone\nALSO_KEEP=yep\n").unwrap();

        let state = make_state_with_dir(tmp.path().to_str().unwrap());
        remove_env_secret(&state, "DELETE_ME".to_string()).unwrap();

        let content = fs::read_to_string(&env_path).unwrap();
        assert!(content.contains("KEEP=yes"));
        assert!(content.contains("ALSO_KEEP=yep"));
        assert!(!content.contains("DELETE_ME"));
    }

    #[test]
    fn remove_env_secret_noop_when_key_missing() {
        let tmp = tempfile::tempdir().unwrap();
        let env_path = tmp.path().join(".env");
        let original = "# header\nFOO=bar\n";
        fs::write(&env_path, original).unwrap();

        let state = make_state_with_dir(tmp.path().to_str().unwrap());
        remove_env_secret(&state, "NONEXISTENT".to_string()).unwrap();

        let content = fs::read_to_string(&env_path).unwrap();
        assert!(content.contains("FOO=bar"));
    }

    #[test]
    fn remove_env_secret_noop_when_no_file() {
        let tmp = tempfile::tempdir().unwrap();
        let state = make_state_with_dir(tmp.path().to_str().unwrap());
        // Should not error
        remove_env_secret(&state, "ANYTHING".to_string()).unwrap();
    }
    #[test]
    fn sync_env_secret_creates_file_when_missing() {
        let tmp = tempfile::tempdir().unwrap();
        let state = make_state_with_dir(tmp.path().to_str().unwrap());
        sync_env_secret(&state, "NEW_KEY".to_string(), "new_val".to_string()).unwrap();

        let env_path = tmp.path().join(".env");
        assert!(env_path.exists());
        let content = fs::read_to_string(&env_path).unwrap();
        assert!(content.contains("NEW_KEY=new_val"));
    }

    #[test]
    fn sync_env_secret_merges_with_existing() {
        let tmp = tempfile::tempdir().unwrap();
        let env_path = tmp.path().join(".env");
        fs::write(&env_path, "EXISTING=keep\n").unwrap();

        let state = make_state_with_dir(tmp.path().to_str().unwrap());
        sync_env_secret(&state, "ADDED".to_string(), "new".to_string()).unwrap();

        let content = fs::read_to_string(&env_path).unwrap();
        assert!(content.contains("EXISTING=keep"), "existing key preserved");
        assert!(content.contains("ADDED=new"), "new key added");
    }

    #[test]
    fn sync_env_secret_overwrites_existing_key() {
        let tmp = tempfile::tempdir().unwrap();
        let env_path = tmp.path().join(".env");
        fs::write(&env_path, "MY_KEY=old_value\n").unwrap();

        let state = make_state_with_dir(tmp.path().to_str().unwrap());
        sync_env_secret(&state, "MY_KEY".to_string(), "new_value".to_string()).unwrap();

        let content = fs::read_to_string(&env_path).unwrap();
        assert!(content.contains("MY_KEY=new_value"));
        assert!(!content.contains("old_value"));
    }
    #[test]
    fn read_env_secret_returns_value() {
        let tmp = tempfile::tempdir().unwrap();
        let env_path = tmp.path().join(".env");
        fs::write(&env_path, "TARGET=found_it\nOTHER=nope\n").unwrap();

        let state = make_state_with_dir(tmp.path().to_str().unwrap());
        let val = read_env_secret(&state, "TARGET".to_string()).unwrap();
        assert_eq!(val, Some("found_it".to_string()));
    }

    #[test]
    fn read_env_secret_returns_none_for_missing_key() {
        let tmp = tempfile::tempdir().unwrap();
        let env_path = tmp.path().join(".env");
        fs::write(&env_path, "OTHER=val\n").unwrap();

        let state = make_state_with_dir(tmp.path().to_str().unwrap());
        let val = read_env_secret(&state, "MISSING".to_string()).unwrap();
        assert_eq!(val, None);
    }

    #[test]
    fn read_env_secret_returns_none_for_empty_value() {
        let tmp = tempfile::tempdir().unwrap();
        let env_path = tmp.path().join(".env");
        fs::write(&env_path, "EMPTY_KEY=\n").unwrap();

        let state = make_state_with_dir(tmp.path().to_str().unwrap());
        let val = read_env_secret(&state, "EMPTY_KEY".to_string()).unwrap();
        assert_eq!(val, None);
    }

    #[test]
    fn read_env_secret_returns_none_when_no_file() {
        let tmp = tempfile::tempdir().unwrap();
        let state = make_state_with_dir(tmp.path().to_str().unwrap());
        let val = read_env_secret(&state, "ANYTHING".to_string()).unwrap();
        assert_eq!(val, None);
    }
    #[test]
    fn env_secret_full_lifecycle() {
        let tmp = tempfile::tempdir().unwrap();
        let state = make_state_with_dir(tmp.path().to_str().unwrap());

        // Initially empty (the temp dir has no .env)
        assert!(list_env_secrets(&state).unwrap().is_empty());
        assert_eq!(read_env_secret(&state, "_TEST_LC_KEY".to_string()).unwrap(), None);

        // Store
        sync_env_secret(&state, "_TEST_LC_KEY".to_string(), "sk-test-123".to_string()).unwrap();
        assert_eq!(
            read_env_secret(&state, "_TEST_LC_KEY".to_string()).unwrap(),
            Some("sk-test-123".to_string())
        );
        assert!(list_env_secrets(&state).unwrap().contains(&"_TEST_LC_KEY".to_string()));

        // Overwrite
        sync_env_secret(&state, "_TEST_LC_KEY".to_string(), "sk-updated".to_string()).unwrap();
        assert_eq!(
            read_env_secret(&state, "_TEST_LC_KEY".to_string()).unwrap(),
            Some("sk-updated".to_string())
        );

        // Add second key
        sync_env_secret(&state, "_TEST_LC_TOK".to_string(), "tok-456".to_string()).unwrap();
        let keys = list_env_secrets(&state).unwrap();
        assert!(keys.contains(&"_TEST_LC_KEY".to_string()));
        assert!(keys.contains(&"_TEST_LC_TOK".to_string()));

        // Remove first
        remove_env_secret(&state, "_TEST_LC_KEY".to_string()).unwrap();
        assert_eq!(read_env_secret(&state, "_TEST_LC_KEY".to_string()).unwrap(), None);
        let keys = list_env_secrets(&state).unwrap();
        assert!(!keys.contains(&"_TEST_LC_KEY".to_string()));
        assert!(keys.contains(&"_TEST_LC_TOK".to_string()));

        // Remove second
        remove_env_secret(&state, "_TEST_LC_TOK".to_string()).unwrap();
        assert!(!list_env_secrets(&state).unwrap().contains(&"_TEST_LC_TOK".to_string()));
    }
    #[test]
    fn parse_env_file_empty_input() {
        let map = parse_env_file("");
        assert!(map.is_empty());
    }

    #[test]
    fn parse_env_file_only_comments() {
        let map = parse_env_file("# comment 1\n# comment 2\n");
        assert!(map.is_empty());
    }

    #[test]
    fn parse_env_file_blank_lines() {
        let map = parse_env_file("\n\n   \n\t\n");
        assert!(map.is_empty());
    }

    #[test]
    fn parse_env_file_equals_in_value() {
        let map = parse_env_file("KEY=val=ue=with=equals\n");
        assert_eq!(map.get("KEY").unwrap(), "val=ue=with=equals");
    }

    #[test]
    fn parse_env_file_no_value() {
        // A line with just KEY= should produce empty value
        let map = parse_env_file("EMPTY_VAL=\n");
        assert_eq!(map.get("EMPTY_VAL").unwrap(), "");
    }

    #[test]
    fn parse_env_file_no_equals() {
        // A line without = should be skipped
        let map = parse_env_file("JUSTAKEYWITHOUTEQ\n");
        assert!(map.is_empty());
    }

    #[test]
    fn parse_env_file_strips_whitespace_around_lines() {
        let map = parse_env_file("  KEY=val  \n");
        // The line gets trimmed, so "KEY=val" is parsed
        assert_eq!(map.get("KEY").unwrap(), "val");
    }

    #[test]
    fn parse_env_file_keys_sorted() {
        let map = parse_env_file("ZEBRA=z\nAPPLE=a\nMIDDLE=m\n");
        let keys: Vec<&String> = map.keys().collect();
        // BTreeMap maintains sorted order
        assert_eq!(keys, vec!["APPLE", "MIDDLE", "ZEBRA"]);
    }
    #[test]
    fn serialize_then_parse_roundtrip() {
        let mut map = std::collections::BTreeMap::new();
        map.insert("A_KEY".to_string(), "value1".to_string());
        map.insert("B_KEY".to_string(), "value2".to_string());

        let body = serialize_env_map(&map);
        let parsed = parse_env_file(&body);

        assert_eq!(parsed.len(), 2);
        assert_eq!(parsed.get("A_KEY").unwrap(), "value1");
        assert_eq!(parsed.get("B_KEY").unwrap(), "value2");
    }

    #[test]
    fn serialize_env_map_includes_header() {
        let map = std::collections::BTreeMap::new();
        let body = serialize_env_map(&map);
        assert!(body.starts_with("# Generated by Agentic Console"));
    }

    #[test]
    fn serialize_env_map_empty() {
        let map = std::collections::BTreeMap::new();
        let body = serialize_env_map(&map);
        // Only the header line
        assert_eq!(body.lines().count(), 1);
    }
    #[test]
    fn write_env_secure_creates_file() {
        let tmp = tempfile::tempdir().unwrap();
        let path = tmp.path().join(".env");
        write_env_secure(&path, "KEY=val\n").unwrap();

        let content = fs::read_to_string(&path).unwrap();
        assert_eq!(content, "KEY=val\n");
    }

    #[cfg(unix)]
    #[test]
    fn write_env_secure_sets_permissions() {
        use std::os::unix::fs::PermissionsExt;
        let tmp = tempfile::tempdir().unwrap();
        let path = tmp.path().join(".env");
        write_env_secure(&path, "SECRET=val\n").unwrap();

        let meta = fs::metadata(&path).unwrap();
        let mode = meta.permissions().mode() & 0o777;
        assert_eq!(mode, 0o600);
    }
    #[test]
    fn sanitize_env_value_empty_string() {
        assert_eq!(sanitize_env_value(""), "");
    }

    #[test]
    fn sanitize_env_value_preserves_normal_chars() {
        let input = "sk-proj-abc123-DEF456_xyz.789";
        assert_eq!(sanitize_env_value(input), input);
    }

    #[test]
    fn sanitize_env_value_strips_all_dangerous() {
        // newlines, carriage return, null byte, hash
        let input = "good\nbad\r\0evil#comment";
        let result = sanitize_env_value(input);
        assert!(!result.contains('\n'));
        assert!(!result.contains('\r'));
        assert!(!result.contains('\0'));
        assert!(!result.contains('#'));
    }
    #[test]
    fn random_hex_zero_bytes() {
        let h = random_hex(0);
        assert!(h.is_empty());
    }

    #[test]
    fn random_hex_uniqueness() {
        let h1 = random_hex(16);
        let h2 = random_hex(16);
        assert_ne!(h1, h2);
    }
    #[test]
    fn provider_env_key_unknown_providers() {
        assert!(provider_env_key("").is_err());
        assert!(provider_env_key("nonexistent").is_err());
        assert!(provider_env_key("ANTHROPIC").is_err()); // case-sensitive
    }
}
