use crate::constants::DEFAULT_GATEWAY_PORT;
use crate::security::{audit, sanitize};
use crate::state::AppState;
use serde::{Deserialize, Serialize};
use std::fs;
use std::path::Path;
use std::process::Command;
use std::time::Duration;

const DOCKER_TIMEOUT_SECS: u64 = 120;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ServiceStatus {
    pub name: String,
    pub status: String,
    pub health: String,
}
pub(crate) fn validate_compose_dir(dir: &str) -> Result<(), String> {
    let path = Path::new(dir);
    if !path.is_dir() {
        return Err(format!(
            "Docker compose directory does not exist: {}",
            dir
        ));
    }

    let compose_files = [
        "docker-compose.yml",
        "docker-compose.yaml",
        "compose.yml",
        "compose.yaml",
    ];
    let found = compose_files.iter().any(|f| path.join(f).is_file());
    if !found {
        return Err(format!(
            "No compose file found in {}. Expected one of: {}",
            dir,
            compose_files.join(", ")
        ));
    }
    Ok(())
}

pub(crate) fn find_docker() -> String {
    #[cfg(target_os = "macos")]
    let candidates: &[&str] = &[
        "/usr/local/bin/docker",
        "/opt/homebrew/bin/docker",
        "/Applications/Docker.app/Contents/Resources/bin/docker",
    ];

    #[cfg(target_os = "windows")]
    let candidates: &[&str] = &[
        "C:\\Program Files\\Docker\\Docker\\resources\\bin\\docker.exe",
        "C:\\Program Files\\Docker\\Docker\\Docker Desktop.exe",
    ];

    #[cfg(target_os = "linux")]
    let candidates: &[&str] = &[
        "/usr/bin/docker",
        "/usr/local/bin/docker",
        "/snap/bin/docker",
    ];

    for path in candidates {
        if Path::new(path).exists() {
            return path.to_string();
        }
    }
    // Fall back to bare name and rely on PATH
    "docker".to_string()
}

fn run_docker_compose(
    dir: &str,
    args: &[&str],
    timeout_secs: u64,
) -> Result<std::process::Output, String> {
    let docker = find_docker();
    let mut child = Command::new(&docker)
        .arg("compose")
        .args(args)
        .current_dir(dir)
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped())
        .spawn()
        .map_err(|e| format!("Failed to spawn docker compose ({}): {}", docker, e))?;

    let deadline = std::time::Instant::now() + Duration::from_secs(timeout_secs);
    loop {
        match child.try_wait() {
            Ok(Some(_status)) => {
                // Process finished — collect output
                return child
                    .wait_with_output()
                    .map_err(|e| format!("Failed to read docker output: {}", e));
            }
            Ok(None) => {
                if std::time::Instant::now() >= deadline {
                    let _ = child.kill();
                    let _ = child.wait();
                    return Err(format!(
                        "Docker compose command timed out after {}s",
                        timeout_secs
                    ));
                }
                std::thread::sleep(Duration::from_millis(100));
            }
            Err(e) => return Err(format!("Failed to check docker process: {}", e)),
        }
    }
}
pub fn docker_status(state: &AppState) -> Result<Vec<ServiceStatus>, String> {
    let dir = state.docker_compose_dir();
    // If the compose directory doesn't exist (e.g. running inside Docker),
    // return an empty list instead of erroring.
    if validate_compose_dir(&dir).is_err() {
        return Ok(Vec::new());
    }

    let output = run_docker_compose(&dir, &["ps", "--format", "json"], DOCKER_TIMEOUT_SECS)?;
    let stdout = String::from_utf8_lossy(&output.stdout);
    let mut services = Vec::new();

    for line in stdout.lines() {
        if let Ok(val) = serde_json::from_str::<serde_json::Value>(line) {
            services.push(ServiceStatus {
                name: val["Service"]
                    .as_str()
                    .unwrap_or("unknown")
                    .to_string(),
                status: val["State"]
                    .as_str()
                    .unwrap_or("unknown")
                    .to_string(),
                health: val["Health"]
                    .as_str()
                    .unwrap_or("N/A")
                    .to_string(),
            });
        }
    }

    Ok(services)
}

fn are_own_containers_running(dir: &str) -> bool {
    match run_docker_compose(dir, &["ps", "-q", "--filter", "status=running"], 10) {
        Ok(output) => !String::from_utf8_lossy(&output.stdout).trim().is_empty(),
        Err(_) => false,
    }
}

fn check_port_available(port: u16) -> Result<(), String> {
    use std::net::{SocketAddr, TcpListener};
    let addr = SocketAddr::from(([127, 0, 0, 1], port));
    match TcpListener::bind(addr) {
        Ok(_) => Ok(()), // Port is free
        Err(_) => Err(format!(
            "Port {} is already in use. Stop the other service or change the port in Settings.",
            port
        )),
    }
}

fn read_env_ports(dir: &str) -> (u16, u16, u16) {
    let env_path = Path::new(dir).join(".env");
    let content = fs::read_to_string(env_path).unwrap_or_default();
    let mut gw: u16 = DEFAULT_GATEWAY_PORT;
    let mut pg: u16 = 5433;
    let mut rd: u16 = 6380;
    for line in content.lines() {
        if let Some(v) = line.strip_prefix("GATEWAY_PORT=") {
            gw = v.trim().parse().unwrap_or(gw);
        } else if let Some(v) = line.strip_prefix("POSTGRES_PORT=") {
            pg = v.trim().parse().unwrap_or(pg);
        } else if let Some(v) = line.strip_prefix("REDIS_PORT=") {
            rd = v.trim().parse().unwrap_or(rd);
        }
    }
    (gw, pg, rd)
}

pub fn docker_up(state: &AppState) -> Result<String, String> {
    let dir = state.docker_compose_dir();
    if validate_compose_dir(&dir).is_err() {
        return Ok("Services already running (managed externally)".to_string());
    }

    // Pre-flight: check ports are available before starting containers.
    // Skip the check if our own containers are already running (ports are ours).
    let already_running = are_own_containers_running(&dir);
    if !already_running {
        let (gw_port, pg_port, rd_port) = read_env_ports(&dir);
        let mut port_errors = Vec::new();
        if check_port_available(gw_port).is_err() {
            port_errors.push(format!("Gateway port {} in use", gw_port));
        }
        if check_port_available(pg_port).is_err() {
            port_errors.push(format!("Postgres port {} in use", pg_port));
        }
        if check_port_available(rd_port).is_err() {
            port_errors.push(format!("Redis port {} in use", rd_port));
        }
        if !port_errors.is_empty() {
            return Err(format!(
                "Port conflict: {}. Stop the conflicting services or change ports in Settings.",
                port_errors.join(", ")
            ));
        }
    }

    let output = run_docker_compose(&dir, &["up", "-d"], DOCKER_TIMEOUT_SECS)?;

    audit::log_action(&state.audit_log_path, "DOCKER_UP", "Started docker services");

    if output.status.success() {
        // Auto-pair the desktop device with the gateway on a background thread
        // so we return to the frontend immediately. The frontend polls for
        // connection and will pick up once pairing completes.
        let audit_path = state.audit_log_path.clone();
        let pair_dir = dir.clone();
        std::thread::spawn(move || {
            if let Err(e) = ensure_device_paired(&pair_dir) {
                audit::log_action(
                    &audit_path,
                    "DEVICE_PAIR_SKIP",
                    &format!("Auto-pair skipped: {}", e),
                );
            }
        });
        Ok("Services started".to_string())
    } else {
        Err(String::from_utf8_lossy(&output.stderr).to_string())
    }
}

fn ensure_device_paired(compose_dir: &str) -> Result<(), String> {
    ensure_device_paired_with_retries(compose_dir, 8)
}

fn ensure_device_paired_with_retries(compose_dir: &str, max_attempts: u32) -> Result<(), String> {
    let home = dirs::home_dir().ok_or("Cannot determine home directory")?;
    let identity_path = home
        .join("agent-mvp")
        .join(".openclaw")
        .join("identity")
        .join("device.json");

    if !identity_path.is_file() {
        return Err("No device identity file".to_string());
    }

    // Verify file permissions are restrictive (owner-only) to protect the private key.
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let meta = fs::metadata(&identity_path)
            .map_err(|e| format!("Failed to stat device identity: {}", e))?;
        let mode = meta.permissions().mode() & 0o777;
        if mode & 0o077 != 0 {
            return Err(format!(
                "Device identity file has insecure permissions {:o}. Fix with: chmod 600 {}",
                mode,
                identity_path.display()
            ));
        }
    }

    let content = fs::read_to_string(&identity_path)
        .map_err(|e| format!("Failed to read device identity: {}", e))?;
    let identity: serde_json::Value =
        serde_json::from_str(&content).map_err(|e| format!("Failed to parse identity: {}", e))?;

    let device_id = identity["deviceId"]
        .as_str()
        .ok_or("Missing deviceId in identity file")?;
    let public_key_pem = identity["publicKeyPem"]
        .as_str()
        .ok_or("Missing publicKeyPem in identity file")?;

    // Extract raw base64url public key from SPKI PEM (reuses device.rs helper)
    let public_key_b64url = super::device::public_key_raw_base64url(public_key_pem)?;

    // Validate inputs before passing to container to prevent injection.
    if !device_id.chars().all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '_') {
        return Err(format!("Invalid device_id format: {}", device_id));
    }
    if !public_key_b64url.chars().all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '_' || c == '=') {
        return Err("Invalid public key format".to_string());
    }

    // Use docker exec with environment variables to avoid string interpolation
    // into JavaScript code. The script reads values from process.env.
    let js_script = r#"
const { getPairedDevice, requestDevicePairing, approveDevicePairing } = await import('/usr/local/lib/node_modules/openclaw/dist/infra/device-pairing.js');
const deviceId = process.env.OC_DEVICE_ID;
const publicKey = process.env.OC_PUBLIC_KEY;
const paired = await getPairedDevice(deviceId);
if (paired) {
    process.stdout.write('already-paired');
    process.exit(0);
}
const req = await requestDevicePairing({
    deviceId,
    publicKey,
    platform: 'macos',
    clientId: 'openclaw-macos',
    clientMode: 'ui',
    role: 'operator',
    scopes: ['operator.read', 'operator.write', 'operator.admin', 'operator.pairing'],
    silent: true,
});
const approved = await approveDevicePairing(req.request.requestId);
process.stdout.write(approved ? 'paired' : 'failed');
"#;

    let docker = find_docker();
    let mut last_err = String::new();

    // Retry with exponential backoff: 3s, 4s, 5s, 6s, 8s, 10s, 12s, 15s
    // Total wait: ~63 seconds max, giving the gateway plenty of time to boot
    for attempt in 0..max_attempts {
        let wait_secs = match attempt {
            0 => 3,
            1 => 4,
            2 => 5,
            3 => 6,
            4 => 8,
            5 => 10,
            6 => 12,
            _ => 15,
        };
        std::thread::sleep(Duration::from_secs(wait_secs));

        // Find the gateway container name (it may not exist yet on early attempts)
        let output = match run_docker_compose(
            compose_dir,
            &["ps", "--format", "{{.Name}}", "gateway"],
            10,
        ) {
            Ok(o) => o,
            Err(e) => {
                last_err = format!("Attempt {}: container lookup failed: {}", attempt + 1, e);
                continue;
            }
        };

        let container_name = String::from_utf8_lossy(&output.stdout).trim().to_string();
        if container_name.is_empty() {
            last_err = format!("Attempt {}: gateway container not found", attempt + 1);
            continue;
        }

        // Check if the container is actually running and healthy before exec
        let health_output = match run_docker_compose(
            compose_dir,
            &["ps", "--format", "{{.State}}", "gateway"],
            10,
        ) {
            Ok(o) => o,
            Err(_) => {
                last_err = format!("Attempt {}: health check failed", attempt + 1);
                continue;
            }
        };
        let state = String::from_utf8_lossy(&health_output.stdout).trim().to_string();
        if state != "running" {
            last_err = format!("Attempt {}: gateway state is '{}', not running", attempt + 1, state);
            continue;
        }

        // Attempt the pairing
        let child = match Command::new(&docker)
            .args([
                "exec",
                "-e", &format!("OC_DEVICE_ID={}", device_id),
                "-e", &format!("OC_PUBLIC_KEY={}", public_key_b64url),
                &container_name, "node", "--input-type=module", "-e", js_script,
            ])
            .stdout(std::process::Stdio::piped())
            .stderr(std::process::Stdio::piped())
            .output()
        {
            Ok(c) => c,
            Err(e) => {
                last_err = format!("Attempt {}: exec failed: {}", attempt + 1, e);
                continue;
            }
        };

        let stdout = String::from_utf8_lossy(&child.stdout);
        let trimmed = stdout.trim();
        if trimmed == "already-paired" || trimmed == "paired" {
            return Ok(());
        }

        let stderr = String::from_utf8_lossy(&child.stderr);
        last_err = format!(
            "Attempt {}: pairing returned '{}' stderr: {}",
            attempt + 1,
            trimmed,
            stderr.chars().take(200).collect::<String>()
        );
    }

    Err(format!(
        "Device pairing failed after {} attempts. Last error: {}",
        max_attempts, last_err
    ))
}

pub fn docker_down(state: &AppState) -> Result<String, String> {
    let dir = state.docker_compose_dir();
    if validate_compose_dir(&dir).is_err() {
        return Ok("Cannot stop services (managed externally)".to_string());
    }

    let output = run_docker_compose(&dir, &["down"], DOCKER_TIMEOUT_SECS)?;

    audit::log_action(
        &state.audit_log_path,
        "DOCKER_DOWN",
        "Stopped docker services",
    );

    if output.status.success() {
        Ok("Services stopped".to_string())
    } else {
        Err(String::from_utf8_lossy(&output.stderr).to_string())
    }
}

pub fn docker_restart_service(
    state: &AppState,
    service: String,
) -> Result<String, String> {
    let dir = state.docker_compose_dir();
    if validate_compose_dir(&dir).is_err() {
        return Ok("Cannot restart services (managed externally)".to_string());
    }

    let safe_service = sanitize::sanitize_shell_arg(&service);
    // Use `up -d --force-recreate` instead of `restart` so Docker re-reads
    // the env_file. Plain `restart` only sends SIGTERM + SIGKILL to the
    // existing container — the process.env stays stale.
    let output = run_docker_compose(
        &dir,
        &["up", "-d", "--force-recreate", &safe_service],
        DOCKER_TIMEOUT_SECS,
    )?;

    audit::log_action(
        &state.audit_log_path,
        "DOCKER_RESTART",
        &format!("Recreated service: {}", safe_service),
    );

    if output.status.success() {
        // Re-pair device on a background thread so we return immediately
        if safe_service == "gateway" {
            let audit_path = state.audit_log_path.clone();
            let pair_dir = dir.clone();
            std::thread::spawn(move || {
                if let Err(e) = ensure_device_paired_with_retries(&pair_dir, 5) {
                    audit::log_action(
                        &audit_path,
                        "DEVICE_PAIR_SKIP",
                        &format!("Auto-pair after gateway restart skipped: {}", e),
                    );
                }
            });
        }
        Ok(format!("Service {} restarted", safe_service))
    } else {
        Err(String::from_utf8_lossy(&output.stderr).to_string())
    }
}

pub fn docker_rebuild_gateway(state: &AppState) -> Result<String, String> {
    let dir = state.docker_compose_dir();
    if validate_compose_dir(&dir).is_err() {
        return Ok("Cannot rebuild gateway (managed externally)".to_string());
    }

    // Pull latest image and rebuild (5 min timeout for image pull + build)
    let build_output = run_docker_compose(
        &dir,
        &["build", "--pull", "gateway"],
        300,
    )?;
    if !build_output.status.success() {
        return Err(format!(
            "Gateway build failed: {}",
            String::from_utf8_lossy(&build_output.stderr)
        ));
    }

    // Restart the gateway container with the new image
    let up_output = run_docker_compose(&dir, &["up", "-d", "gateway"], DOCKER_TIMEOUT_SECS)?;
    if !up_output.status.success() {
        return Err(format!(
            "Gateway restart failed: {}",
            String::from_utf8_lossy(&up_output.stderr)
        ));
    }

    // Re-pair device on background thread
    let audit_path = state.audit_log_path.clone();
    let pair_dir = dir.clone();
    std::thread::spawn(move || {
        if let Err(e) = ensure_device_paired(&pair_dir) {
            audit::log_action(
                &audit_path,
                "DEVICE_PAIR_SKIP",
                &format!("Auto-pair after rebuild skipped: {}", e),
            );
        }
    });

    audit::log_action(
        &state.audit_log_path,
        "DOCKER_REBUILD_GATEWAY",
        "Rebuilt and restarted gateway with latest image",
    );

    Ok("Gateway rebuilt and restarted".to_string())
}
#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn validate_compose_dir_rejects_missing_dir() {
        let result = validate_compose_dir("/nonexistent/path/abc123");
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("does not exist"));
    }

    #[test]
    fn validate_compose_dir_rejects_no_compose_file() {
        let tmp = tempfile::tempdir().unwrap();
        let result = validate_compose_dir(tmp.path().to_str().unwrap());
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("No compose file found"));
    }

    #[test]
    fn validate_compose_dir_accepts_docker_compose_yml() {
        let tmp = tempfile::tempdir().unwrap();
        std::fs::write(tmp.path().join("docker-compose.yml"), "version: '3'").unwrap();
        assert!(validate_compose_dir(tmp.path().to_str().unwrap()).is_ok());
    }

    #[test]
    fn validate_compose_dir_accepts_compose_yaml() {
        let tmp = tempfile::tempdir().unwrap();
        std::fs::write(tmp.path().join("compose.yaml"), "services:").unwrap();
        assert!(validate_compose_dir(tmp.path().to_str().unwrap()).is_ok());
    }
}
