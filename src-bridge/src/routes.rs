use crate::auth::AuthManager;
use agentic_console_core::commands;
use agentic_console_core::state::AppState;
use axum::extract::ws::{Message, WebSocket};
use axum::extract::{Path, Query, State as AxumState, WebSocketUpgrade};
use axum::http::{HeaderMap, StatusCode};
use axum::response::{IntoResponse, Json};
use futures_util::stream::StreamExt;
use futures_util::SinkExt;
use serde_json::Value;
use std::sync::Arc;
use tokio_tungstenite::tungstenite;

pub struct BridgeState {
    pub app_state: AppState,
    pub auth: AuthManager,
    pub gateway_ws_url: String,
}

#[derive(serde::Deserialize)]
pub struct WsQuery {
    token: Option<String>,
}

pub async fn ws_handler(
    AxumState(state): AxumState<Arc<BridgeState>>,
    Query(query): Query<WsQuery>,
    ws: WebSocketUpgrade,
) -> impl IntoResponse {
    // Authenticate via query param since WebSocket upgrade can't carry headers
    let token = match query.token {
        Some(t) => t,
        None => {
            return (
                StatusCode::UNAUTHORIZED,
                "Missing token query parameter",
            )
                .into_response();
        }
    };

    if !state.auth.validate_token(&token) {
        return (StatusCode::UNAUTHORIZED, "Invalid or expired token").into_response();
    }

    // Token is valid — accept the WebSocket upgrade
    let gateway_url = state.gateway_ws_url.clone();
    ws.on_upgrade(move |socket| handle_ws_proxy(socket, gateway_url))
}

async fn handle_ws_proxy(browser_ws: WebSocket, gateway_ws_url: String) {
    // Connect to the Docker gateway
    let gateway_conn = tokio_tungstenite::connect_async(&gateway_ws_url).await;

    let gateway_ws = match gateway_conn {
        Ok((stream, _response)) => stream,
        Err(e) => {
            eprintln!("[ws-proxy] Failed to connect to gateway at {}: {}", gateway_ws_url, e);
            // Send an error frame to the browser before closing
            let (mut browser_sink, _) = browser_ws.split();
            let err_msg = serde_json::json!({
                "error": "gateway_unreachable",
                "message": format!("Could not connect to gateway: {}", e),
            });
            let _ = browser_sink
                .send(Message::Text(err_msg.to_string()))
                .await;
            let _ = browser_sink.send(Message::Close(None)).await;
            return;
        }
    };

    // Split both WebSocket connections into sender/receiver halves
    let (mut browser_sink, mut browser_stream) = browser_ws.split();
    let (mut gateway_sink, mut gateway_stream) = gateway_ws.split();

    // browser -> gateway
    let browser_to_gateway = tokio::spawn(async move {
        while let Some(msg_result) = browser_stream.next().await {
            match msg_result {
                Ok(msg) => {
                    let tung_msg = match axum_msg_to_tungstenite(msg) {
                        Some(m) => m,
                        None => break, // Close frame or unhandled type
                    };
                    if gateway_sink.send(tung_msg).await.is_err() {
                        break; // Gateway disconnected
                    }
                }
                Err(_) => break, // Browser disconnected
            }
        }
        // Attempt graceful close toward gateway
        let _ = gateway_sink
            .send(tungstenite::Message::Close(None))
            .await;
    });

    // gateway -> browser
    let gateway_to_browser = tokio::spawn(async move {
        while let Some(msg_result) = gateway_stream.next().await {
            match msg_result {
                Ok(msg) => {
                    let axum_msg = match tungstenite_msg_to_axum(msg) {
                        Some(m) => m,
                        None => break, // Close frame or unhandled type
                    };
                    if browser_sink.send(axum_msg).await.is_err() {
                        break; // Browser disconnected
                    }
                }
                Err(_) => break, // Gateway disconnected
            }
        }
        // Attempt graceful close toward browser
        let _ = browser_sink.send(Message::Close(None)).await;
    });

    // Wait for either direction to finish, then abort the other
    tokio::select! {
        _ = browser_to_gateway => {},
        _ = gateway_to_browser => {},
    }
}

fn axum_msg_to_tungstenite(msg: Message) -> Option<tungstenite::Message> {
    match msg {
        Message::Text(text) => Some(tungstenite::Message::Text(text)),
        Message::Binary(data) => Some(tungstenite::Message::Binary(data)),
        Message::Ping(data) => Some(tungstenite::Message::Ping(data)),
        Message::Pong(data) => Some(tungstenite::Message::Pong(data)),
        Message::Close(_) => None, // Signal to stop the loop
    }
}

fn tungstenite_msg_to_axum(msg: tungstenite::Message) -> Option<Message> {
    match msg {
        tungstenite::Message::Text(text) => Some(Message::Text(text)),
        tungstenite::Message::Binary(data) => Some(Message::Binary(data)),
        tungstenite::Message::Ping(data) => Some(Message::Ping(data)),
        tungstenite::Message::Pong(data) => Some(Message::Pong(data)),
        tungstenite::Message::Close(_) => None, // Signal to stop the loop
        tungstenite::Message::Frame(_) => None, // Raw frames — ignore
    }
}

#[derive(serde::Deserialize)]
pub struct PairRequest {
    pub code: String,
}

#[derive(serde::Serialize)]
pub struct PairResponse {
    pub token: String,
    #[serde(rename = "expiresAt")]
    pub expires_at: String,
}

pub async fn pair_handler(
    AxumState(state): AxumState<Arc<BridgeState>>,
    Json(body): Json<PairRequest>,
) -> Result<Json<PairResponse>, (StatusCode, Json<Value>)> {
    match state.auth.pair(&body.code) {
        Ok(token) => {
            let expires = chrono::Utc::now() + chrono::Duration::hours(24);
            Ok(Json(PairResponse {
                token,
                expires_at: expires.to_rfc3339(),
            }))
        }
        Err(msg) => Err((
            StatusCode::UNAUTHORIZED,
            Json(serde_json::json!({ "error": msg })),
        )),
    }
}

fn extract_bearer_token(headers: &HeaderMap) -> Option<String> {
    headers
        .get("authorization")
        .and_then(|v| v.to_str().ok())
        .and_then(|v| v.strip_prefix("Bearer "))
        .map(|s| s.to_string())
}

fn require_auth(
    headers: &HeaderMap,
    auth: &AuthManager,
) -> Result<(), (StatusCode, Json<Value>)> {
    let token = extract_bearer_token(headers).ok_or_else(|| {
        (
            StatusCode::UNAUTHORIZED,
            Json(serde_json::json!({ "error": "Missing Authorization header" })),
        )
    })?;
    if !auth.validate_token(&token) {
        return Err((
            StatusCode::UNAUTHORIZED,
            Json(serde_json::json!({ "error": "Invalid or expired token" })),
        ));
    }
    Ok(())
}

pub async fn invoke_handler(
    AxumState(state): AxumState<Arc<BridgeState>>,
    headers: HeaderMap,
    Path(command): Path<String>,
    Json(args): Json<Value>,
) -> Result<Json<Value>, (StatusCode, Json<Value>)> {
    require_auth(&headers, &state.auth)?;

    let app = &state.app_state;
    let result = dispatch_command(app, &command, args);

    match result {
        Ok(val) => Ok(Json(val)),
        Err(msg) => Err((
            StatusCode::BAD_REQUEST,
            Json(serde_json::json!({ "error": msg })),
        )),
    }
}

fn str_arg(args: &Value, key: &str) -> Result<String, String> {
    args.get(key)
        .and_then(|v| v.as_str())
        .map(|s| s.to_string())
        .ok_or_else(|| format!("{} required", key))
}

fn opt_str(args: &Value, key: &str) -> Option<String> {
    args.get(key).and_then(|v| v.as_str()).map(|s| s.to_string())
}

fn opt_usize(args: &Value, key: &str) -> Option<usize> {
    args.get(key).and_then(|v| v.as_u64()).map(|n| n as usize)
}

fn dispatch_command(
    state: &AppState,
    command: &str,
    args: Value,
) -> Result<Value, String> {
    match command {
        // Config
        "read_config" => commands::config::read_config(state),
        "write_config" => {
            let config = args.get("config").cloned().unwrap_or(Value::Null);
            commands::config::write_config(state, config)?;
            Ok(Value::Null)
        }
        "validate_config" => {
            let config = args.get("config").cloned().unwrap_or(Value::Null);
            let msg = commands::config::validate_config(config)?;
            Ok(Value::String(msg))
        }
        "get_openclaw_dir" => {
            Ok(Value::String(commands::config::get_openclaw_dir(state)))
        }
        "restore_config_backup" => {
            commands::config::restore_config_backup(state)?;
            Ok(Value::Null)
        }

        // Vault
        "vault_unlock" => {
            let password = str_arg(&args, "password")?;
            let result = commands::vault::vault_unlock(state, password)?;
            serde_json::to_value(result).map_err(|e| e.to_string())
        }
        "vault_lock" => {
            commands::vault::vault_lock(state)?;
            Ok(Value::Null)
        }
        "vault_exists" => {
            Ok(Value::Bool(commands::vault::vault_exists(state)))
        }
        "vault_store_secret" => {
            let key = str_arg(&args, "key")?;
            let value = str_arg(&args, "value")?;
            commands::vault::vault_store_secret(state, key, value)?;
            Ok(Value::Null)
        }
        "vault_read_secret" => {
            let key = str_arg(&args, "key")?;
            let val = commands::vault::vault_read_secret(state, key)?;
            Ok(val.map_or(Value::Null, Value::String))
        }
        "vault_remove" => {
            let key = str_arg(&args, "key")?;
            commands::vault::vault_remove(state, key)?;
            Ok(Value::Null)
        }
        "vault_list" => {
            let entries = commands::vault::vault_list(state)?;
            serde_json::to_value(entries).map_err(|e| e.to_string())
        }
        "vault_store_meta" => {
            let entry_val = args.get("entry").cloned().unwrap_or(args.clone());
            let entry: commands::vault::VaultEntry = serde_json::from_value(entry_val)
                .map_err(|e| format!("Invalid vault entry: {}", e))?;
            commands::vault::vault_store_meta(state, entry)?;
            Ok(Value::Null)
        }

        // Docker
        "docker_status" => {
            let status = commands::docker::docker_status(state)?;
            serde_json::to_value(status).map_err(|e| e.to_string())
        }
        "docker_up" => {
            let result = commands::docker::docker_up(state)?;
            Ok(Value::String(result))
        }
        "docker_down" => {
            let result = commands::docker::docker_down(state)?;
            Ok(Value::String(result))
        }
        "docker_restart_service" => {
            let service = str_arg(&args, "service")?;
            let result = commands::docker::docker_restart_service(state, service)?;
            Ok(Value::String(result))
        }
        "docker_rebuild_gateway" => {
            let result = commands::docker::docker_rebuild_gateway(state)?;
            Ok(Value::String(result))
        }

        // Health
        "check_health" => {
            let report = commands::health::check_health(state)?;
            serde_json::to_value(report).map_err(|e| e.to_string())
        }
        "security_audit" => {
            let results = commands::health::security_audit(state)?;
            serde_json::to_value(results).map_err(|e| e.to_string())
        }
        "get_gateway_token" => {
            let token = commands::health::get_gateway_token(state);
            Ok(token.map_or(Value::Null, Value::String))
        }

        // Logs
        "read_audit_log" => {
            let limit = opt_usize(&args, "limit");
            let entries = commands::logs::read_audit_log(state, limit)?;
            serde_json::to_value(entries).map_err(|e| e.to_string())
        }
        "read_gateway_logs" => {
            let limit = opt_usize(&args, "limit");
            let entries = commands::logs::read_gateway_logs(state, limit)?;
            serde_json::to_value(entries).map_err(|e| e.to_string())
        }
        "search_logs" => {
            let query = str_arg(&args, "query")?;
            let limit = opt_usize(&args, "limit");
            let entries = commands::logs::search_logs(state, query, limit)?;
            serde_json::to_value(entries).map_err(|e| e.to_string())
        }
        "log_frontend_error" => {
            let severity = str_arg(&args, "severity")?;
            let message = str_arg(&args, "message")?;
            let component = opt_str(&args, "component");
            let stack = opt_str(&args, "stack");
            let _ = commands::logs::log_frontend_error(state, severity, message, component, stack);
            Ok(Value::Null)
        }
        "get_usage_stats" => {
            let stats = commands::logs::get_usage_stats(state)?;
            serde_json::to_value(stats).map_err(|e| e.to_string())
        }

        // Agents
        "list_agents" => {
            let agents = commands::agent::list_agents(state)?;
            serde_json::to_value(agents).map_err(|e| e.to_string())
        }
        "read_agent_file" => {
            let path = str_arg(&args, "relativePath")?;
            let content = commands::agent::read_agent_file(state, path)?;
            Ok(Value::String(content))
        }
        "write_agent_file" => {
            let path = str_arg(&args, "relativePath")?;
            let content = str_arg(&args, "content")?;
            commands::agent::write_agent_file(state, path, content)?;
            Ok(Value::Null)
        }
        "list_workspace_tree" => {
            let tree = commands::agent::list_workspace_tree(state)?;
            serde_json::to_value(tree).map_err(|e| e.to_string())
        }
        "create_workspace_file" => {
            let path = str_arg(&args, "relativePath")?;
            let content = str_arg(&args, "content")?;
            commands::agent::create_workspace_file(state, path, content)?;
            Ok(Value::Null)
        }
        "delete_workspace_file" => {
            let path = str_arg(&args, "relativePath")?;
            commands::agent::delete_workspace_file(state, path)?;
            Ok(Value::Null)
        }
        "create_agent" => {
            let id = str_arg(&args, "id")?;
            let name = str_arg(&args, "name")?;
            let model = opt_str(&args, "model");
            let personality = opt_str(&args, "personality");
            commands::agent::create_agent(state, id, name, model, personality)?;
            Ok(Value::Null)
        }
        "update_agent" => {
            let id = str_arg(&args, "id")?;
            let name = opt_str(&args, "name");
            let model = opt_str(&args, "model");
            let enabled = args.get("enabled").and_then(|v| v.as_bool());
            commands::agent::update_agent(state, id, name, model, enabled)?;
            Ok(Value::Null)
        }
        "delete_agent" => {
            let id = str_arg(&args, "id")?;
            let delete_files = args.get("deleteFiles").and_then(|v| v.as_bool()).unwrap_or(false);
            commands::agent::delete_agent(state, id, delete_files)?;
            Ok(Value::Null)
        }
        "clear_agent_memory" => {
            let agent_id = str_arg(&args, "agentId")?;
            commands::agent::clear_agent_memory(state, agent_id)?;
            Ok(Value::Null)
        }
        "archive_agent_memory" => {
            let agent_id = str_arg(&args, "agentId")?;
            let path = commands::agent::archive_agent_memory(state, agent_id)?;
            Ok(Value::String(path))
        }
        "sync_agents_to_gateway" => {
            commands::agent::sync_agents_to_gateway(state)?;
            Ok(Value::Null)
        }

        // Skills
        "list_skills" => {
            let skills = commands::skills::list_skills(state)?;
            serde_json::to_value(skills).map_err(|e| e.to_string())
        }
        "toggle_skill" => {
            let id = str_arg(&args, "skillId")?;
            let enabled = args["enabled"].as_bool().ok_or("enabled required")?;
            commands::skills::toggle_skill(state, id, enabled)?;
            Ok(Value::Null)
        }
        "remove_skill" => {
            let id = str_arg(&args, "skillId")?;
            commands::skills::remove_skill(state, id)?;
            Ok(Value::Null)
        }
        "create_skill" => {
            let id = str_arg(&args, "id")?;
            let name = str_arg(&args, "name")?;
            let description = args.get("description").and_then(|v| v.as_str()).unwrap_or("").to_string();
            let version = opt_str(&args, "version");
            let tools = args.get("tools").and_then(|v| v.as_array()).cloned();
            let handler_code = opt_str(&args, "handlerCode");
            let requirements = opt_str(&args, "requirements");
            commands::skills::create_skill(state, id, name, description, version, tools, handler_code, requirements)?;
            Ok(Value::Null)
        }
        "read_skill_file" => {
            let skill_id = str_arg(&args, "skillId")?;
            let relative_path = str_arg(&args, "relativePath")?;
            let content = commands::skills::read_skill_file(state, skill_id, relative_path)?;
            Ok(Value::String(content))
        }
        "update_skill_file" => {
            let skill_id = str_arg(&args, "skillId")?;
            let relative_path = str_arg(&args, "relativePath")?;
            let content = str_arg(&args, "content")?;
            commands::skills::update_skill_file(state, skill_id, relative_path, content)?;
            Ok(Value::Null)
        }

        // Plugins
        "list_gateway_plugins" => {
            let plugins = commands::plugins::list_gateway_plugins(state)?;
            serde_json::to_value(plugins).map_err(|e| e.to_string())
        }
        "toggle_gateway_plugin" => {
            let id = str_arg(&args, "pluginId")?;
            let enabled = args["enabled"].as_bool().ok_or("enabled required")?;
            commands::plugins::toggle_gateway_plugin(state, id, enabled)?;
            Ok(Value::Null)
        }

        // Bootstrap
        "check_backend_exists" => {
            Ok(Value::Bool(commands::bootstrap::check_backend_exists()))
        }
        "write_backend_env" => {
            let api_key = str_arg(&args, "apiKey")?;
            let provider = str_arg(&args, "provider")?;
            let result = commands::bootstrap::write_backend_env(state, api_key, provider)?;
            Ok(Value::String(result))
        }
        "check_docker_installed" => {
            let check = commands::bootstrap::check_docker_installed();
            serde_json::to_value(check).map_err(|e| e.to_string())
        }
        "sync_env_to_gateway" => {
            commands::bootstrap::sync_env_to_gateway(state)?;
            Ok(Value::Null)
        }
        "sync_env_secret" => {
            let key = str_arg(&args, "key")?;
            let value = str_arg(&args, "value")?;
            commands::bootstrap::sync_env_secret(state, key, value)?;
            Ok(Value::Null)
        }
        "read_env_secret" => {
            let key = str_arg(&args, "key")?;
            let val = commands::bootstrap::read_env_secret(state, key)?;
            Ok(val.map_or(Value::Null, Value::String))
        }
        "list_env_secrets" => {
            let keys = commands::bootstrap::list_env_secrets(state)?;
            serde_json::to_value(keys).map_err(|e| e.to_string())
        }
        "remove_env_secret" => {
            let key = str_arg(&args, "key")?;
            commands::bootstrap::remove_env_secret(state, key)?;
            Ok(Value::Null)
        }

        // Device
        "generate_device_identity" => {
            let result = commands::device::generate_device_identity(state)?;
            Ok(Value::String(result))
        }
        "sign_device_challenge" => {
            // Frontend sends { params: { clientId, ... } } — unwrap the params key
            let params_val = args.get("params").cloned().unwrap_or(args.clone());
            let params: commands::device::SignDeviceParams = serde_json::from_value(params_val)
                .map_err(|e| format!("Invalid params: {}", e))?;
            let auth = commands::device::sign_device_challenge(state, params)?;
            serde_json::to_value(auth).map_err(|e| e.to_string())
        }

        // Moltbook
        "generate_skill_md" => {
            let data: commands::moltbook::SkillMdData = serde_json::from_value(args)
                .map_err(|e| format!("Invalid params: {}", e))?;
            let md = commands::moltbook::generate_skill_md(data)?;
            Ok(Value::String(md))
        }
        "save_skill_md" => {
            let agent_id = str_arg(&args, "agentId")?;
            let content = str_arg(&args, "content")?;
            commands::moltbook::save_skill_md(state, agent_id, content)?;
            Ok(Value::Null)
        }

        // Pairing
        "list_pairing_requests" => {
            let channel = str_arg(&args, "channel")?;
            let requests = commands::pairing::list_pairing_requests(state, channel)?;
            serde_json::to_value(requests).map_err(|e| e.to_string())
        }
        "approve_pairing_request" => {
            let channel = str_arg(&args, "channel")?;
            let code = str_arg(&args, "code")?;
            let result = commands::pairing::approve_pairing_request(state, channel, code)?;
            Ok(Value::String(result))
        }

        // Usage
        "get_user_usage" => {
            let channel = str_arg(&args, "channel")?;
            let user_id = str_arg(&args, "userId")?;
            let usage = commands::usage::get_user_usage(state, channel, user_id)?;
            serde_json::to_value(usage).map_err(|e| e.to_string())
        }
        "list_channel_users" => {
            let channel = str_arg(&args, "channel")?;
            let users = commands::usage::list_channel_users(state, channel)?;
            serde_json::to_value(users).map_err(|e| e.to_string())
        }
        "set_user_quota" => {
            let channel = str_arg(&args, "channel")?;
            let user_id = str_arg(&args, "userId")?;
            let daily_quota = args.get("dailyQuota").and_then(|v| v.as_i64());
            commands::usage::set_user_quota(state, channel, user_id, daily_quota)?;
            Ok(Value::Null)
        }
        "set_default_quota" => {
            let daily_quota = args["dailyQuota"].as_i64().ok_or("dailyQuota required")?;
            commands::usage::set_default_quota(state, daily_quota)?;
            Ok(Value::Null)
        }
        "record_usage" => {
            let channel = str_arg(&args, "channel")?;
            let user_id = str_arg(&args, "userId")?;
            let display_name = opt_str(&args, "displayName");
            let check = commands::usage::record_usage(state, channel, user_id, display_name)?;
            serde_json::to_value(check).map_err(|e| e.to_string())
        }
        "check_quota" => {
            let channel = str_arg(&args, "channel")?;
            let user_id = str_arg(&args, "userId")?;
            let check = commands::usage::check_quota(state, channel, user_id)?;
            serde_json::to_value(check).map_err(|e| e.to_string())
        }

        _ => Err(format!("Unknown command: {}", command)),
    }
}

pub async fn health_handler() -> Json<Value> {
    Json(serde_json::json!({
        "status": "ok",
        "bridge": true,
        "version": env!("CARGO_PKG_VERSION"),
    }))
}

pub async fn auto_token_handler(
    AxumState(state): AxumState<Arc<BridgeState>>,
) -> Result<Json<Value>, StatusCode> {
    match state.auth.get_auto_token() {
        Some(token) => Ok(Json(serde_json::json!({ "token": token }))),
        None => Err(StatusCode::NOT_FOUND),
    }
}
