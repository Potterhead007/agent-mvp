mod auth;
mod auto_token;
mod routes;

use agentic_console_core::commands::config::ensure_default_config;
use agentic_console_core::state::AppState;
use auth::AuthManager;
use auto_token::load_auto_token_from_env;
use axum::response::Html;
use axum::routing::{get, post};
use axum::Router;
use routes::BridgeState;
use std::net::SocketAddr;
use std::process;
use std::sync::Arc;
use tower_http::cors::{AllowHeaders, AllowMethods, AllowOrigin, CorsLayer};
use tower_http::services::ServeDir;

const DEFAULT_PORT: u16 = 18791;
const DEFAULT_GATEWAY_WS_URL: &str = "ws://127.0.0.1:18790";

fn print_version() {
    println!("agentic-bridge {}", env!("CARGO_PKG_VERSION"));
}

fn print_usage() {
    print_version();
    println!();
    println!("Local bridge server for Agentic Console web access.");
    println!();
    println!("USAGE:");
    println!("    agentic-bridge [OPTIONS]");
    println!();
    println!("OPTIONS:");
    println!("    --port <PORT>               Listen port (default: {})", DEFAULT_PORT);
    println!("    --bind <ADDR>               Bind address (default: 127.0.0.1)");
    println!("    --gateway-url <URL>         Gateway WebSocket URL (default: {})", DEFAULT_GATEWAY_WS_URL);
    println!("    --auto-token-env <VAR>      Enable auto-token mode from env var");
    println!("    --allow-origin <URL>        Additional CORS origin");
    println!("    --verbose, -v               Verbose output");
    println!("    --version, -V               Print version");
    println!("    --help, -h                  Print this help");
}

fn get_flag_value(flag: &str) -> Option<String> {
    std::env::args()
        .position(|a| a == flag)
        .and_then(|i| std::env::args().nth(i + 1))
}

#[tokio::main]
async fn main() {
    // Handle --help / -h early
    if std::env::args().any(|a| a == "--help" || a == "-h") {
        print_usage();
        process::exit(0);
    }

    // Handle --version / -V early
    if std::env::args().any(|a| a == "--version" || a == "-V") {
        print_version();
        process::exit(0);
    }

    let port = get_flag_value("--port")
        .and_then(|p| p.parse::<u16>().ok())
        .unwrap_or(DEFAULT_PORT);

    let bind_addr: std::net::Ipv4Addr = get_flag_value("--bind")
        .and_then(|b| b.parse().ok())
        .unwrap_or(std::net::Ipv4Addr::LOCALHOST);

    let verbose = std::env::args().any(|a| a == "--verbose" || a == "-v");

    let gateway_ws_url = get_flag_value("--gateway-url")
        .or_else(|| std::env::var("GATEWAY_WS_URL").ok())
        .unwrap_or_else(|| DEFAULT_GATEWAY_WS_URL.to_string());

    let auto_token_env = get_flag_value("--auto-token-env");

    // Load auto-token from env var if configured
    let auto_token_config = auto_token_env
        .as_deref()
        .and_then(load_auto_token_from_env);

    let auto_token_active = auto_token_config.is_some();

    // Initialize core state (AppState::new() resolves paths from home dir)
    let app_state = AppState::new();
    let openclaw_dir = app_state.openclaw_dir.clone();

    if let Err(e) = ensure_default_config(&openclaw_dir) {
        eprintln!("Warning: Could not ensure default config: {}", e);
    }

    let auth_manager = match auto_token_config {
        Some(config) => AuthManager::with_auto_token(config.token),
        None => AuthManager::new(),
    };
    let pairing_code = auth_manager.current_code();

    // Load gateway token for bridge→gateway authentication.
    // In Docker, this comes from the OPENCLAW_GATEWAY_TOKEN env var.
    let gateway_token = std::env::var("OPENCLAW_GATEWAY_TOKEN")
        .or_else(|_| std::env::var("GATEWAY_TOKEN"))
        .ok()
        .filter(|t| !t.is_empty());

    let bridge_state = Arc::new(BridgeState {
        app_state,
        auth: auth_manager,
        gateway_ws_url: gateway_ws_url.clone(),
        gateway_token,
    });

    // CORS configuration — the bridge only listens on localhost (127.0.0.1),
    // so the network boundary is the security layer. Allow any origin since
    // the web console may be served from Vercel, localhost, or other hosts.
    let cors = CorsLayer::new()
        .allow_origin(AllowOrigin::any())
        .allow_methods(AllowMethods::any())
        .allow_headers(AllowHeaders::any());

    // Web console static files directory — mounted via Docker volume or
    // placed alongside the binary. Serves the SPA with index.html fallback.
    let web_dir = get_flag_value("--web-dir")
        .or_else(|| std::env::var("BRIDGE_WEB_DIR").ok())
        .unwrap_or_else(|| "/home/bridge/web".to_string());

    let web_dir_exists = std::path::Path::new(&web_dir).join("index.html").exists();

    // API routes (always available)
    let api_routes = Router::new()
        .route("/api/health", get(routes::health_handler))
        .route("/api/auto-token", get(routes::auto_token_handler))
        .route("/api/pair", post(routes::pair_handler))
        .route("/api/invoke/:command", post(routes::invoke_handler))
        .route("/api/ws", get(routes::ws_handler))
        .with_state(bridge_state);

    // If web console files exist, serve them as SPA.
    // Static assets (JS, CSS) are served from /assets/ via ServeDir.
    // All other paths return index.html so the React client-side router handles them.
    let app = if web_dir_exists {
        let index_html = std::fs::read_to_string(format!("{}/index.html", web_dir))
            .expect("Failed to read web console index.html");
        api_routes
            .nest_service("/assets", ServeDir::new(format!("{}/assets", web_dir)))
            .route_service("/app-icon.png", tower_http::services::ServeFile::new(format!("{}/app-icon.png", web_dir)))
            .fallback(move || async move { Html(index_html) })
    } else {
        api_routes
    };

    let app = app.layer(cors);

    let addr = SocketAddr::from((bind_addr, port));

    // Bind — handle port conflicts gracefully
    let listener = match tokio::net::TcpListener::bind(addr).await {
        Ok(l) => l,
        Err(e) => {
            eprintln!("Error: Cannot bind to {}: {}", addr, e);
            if e.kind() == std::io::ErrorKind::AddrInUse {
                eprintln!("Port {} is already in use. Try a different port with: --port <PORT>", port);
            }
            process::exit(1);
        }
    };

    // Print banner only after successful bind
    println!();
    println!("  \x1b[1mAgentic Console Bridge\x1b[0m v{}", env!("CARGO_PKG_VERSION"));
    println!("  ─────────────────────────────────────");
    println!("  Listening on: http://{}", addr);
    println!("  Gateway:      {}", gateway_ws_url);
    println!();

    if auto_token_active {
        println!("  Mode: \x1b[1mauto-token\x1b[0m (Docker — no pairing needed)");
    } else {
        println!("  Pairing code: \x1b[1m{}\x1b[0m", pairing_code);
        println!();
        println!("  Open \x1b[4mhttps://agenticconsole.com/build\x1b[0m");
        println!("  and enter this code to connect.");
    }
    println!();

    if verbose {
        println!("  [verbose] OpenClaw dir: {}", openclaw_dir);
        println!("  [verbose] Gateway WS:   {}", gateway_ws_url);
        println!("  [verbose] Auto-token:   {}", auto_token_active);
        println!();
    }

    axum::serve(listener, app)
        .await
        .expect("Server error");
}
