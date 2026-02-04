pub struct AutoTokenConfig {
    pub token: String,
}

pub fn load_auto_token_from_env(env_var: &str) -> Option<AutoTokenConfig> {
    match std::env::var(env_var) {
        Ok(val) if !val.is_empty() => Some(AutoTokenConfig { token: val }),
        _ => None,
    }
}
