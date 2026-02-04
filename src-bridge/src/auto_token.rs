/// Auto-token mode: when the bridge runs inside Docker alongside the gateway,
/// authentication is handled via a shared secret from the environment instead
/// of the interactive pairing code flow.

pub struct AutoTokenConfig {
    pub token: String,
}

/// Read an auto-token from the given environment variable.
/// Returns `Some` if the env var is set and non-empty.
pub fn load_auto_token_from_env(env_var: &str) -> Option<AutoTokenConfig> {
    match std::env::var(env_var) {
        Ok(val) if !val.is_empty() => Some(AutoTokenConfig { token: val }),
        _ => None,
    }
}
