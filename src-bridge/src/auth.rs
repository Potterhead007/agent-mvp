use rand::Rng;
use std::collections::HashMap;
use std::sync::Mutex;
use std::time::{Duration, Instant};

pub struct PairingState {
    pub code: String,
    pub used: bool,
    pub failures: Vec<Instant>,
}

pub struct Session {
    #[allow(dead_code)]
    pub token: String,
    pub created_at: Instant,
    pub ttl: Duration,
}

impl Session {
    pub fn is_expired(&self) -> bool {
        self.created_at.elapsed() > self.ttl
    }
}

pub struct AuthManager {
    pub pairing: Mutex<PairingState>,
    pub sessions: Mutex<HashMap<String, Session>>,
    auto_token: Option<String>,
}

const PAIRING_CODE_LEN: usize = 6;
const SESSION_TOKEN_LEN: usize = 32;
const SESSION_TTL_HOURS: u64 = 24;
const MAX_FAILURES_PER_MINUTE: usize = 5;
const LOCKOUT_SECS: u64 = 60;

impl AuthManager {
    pub fn new() -> Self {
        Self {
            pairing: Mutex::new(PairingState {
                code: generate_pairing_code(),
                used: false,
                failures: Vec::new(),
            }),
            sessions: Mutex::new(HashMap::new()),
            auto_token: None,
        }
    }

    pub fn with_auto_token(token: String) -> Self {
        let mut mgr = Self::new();
        mgr.auto_token = Some(token);
        mgr
    }

    pub fn get_auto_token(&self) -> Option<&str> {
        self.auto_token.as_deref()
    }

    pub fn pair(&self, code: &str) -> Result<String, String> {
        let mut pairing = self.pairing.lock().unwrap();

        // Rate limiting: prune old failures, check count
        let now = Instant::now();
        pairing.failures.retain(|t| now.duration_since(*t) < Duration::from_secs(LOCKOUT_SECS));
        if pairing.failures.len() >= MAX_FAILURES_PER_MINUTE {
            return Err("Too many failed attempts. Try again later.".to_string());
        }

        if pairing.used {
            return Err("Pairing code already used. Restart the bridge to get a new code.".to_string());
        }

        if code != pairing.code {
            pairing.failures.push(now);
            return Err("Invalid pairing code.".to_string());
        }

        // Success — mark code as used, generate session token
        pairing.used = true;

        let token = generate_session_token();
        let session = Session {
            token: token.clone(),
            created_at: Instant::now(),
            ttl: Duration::from_secs(SESSION_TTL_HOURS * 3600),
        };

        self.sessions.lock().unwrap().insert(token.clone(), session);
        Ok(token)
    }

    pub fn validate_token(&self, token: &str) -> bool {
        // Check auto-token first (constant-time comparison not needed — not a
        // high-security boundary; the auto-token is only accessible via localhost)
        if let Some(ref auto) = self.auto_token {
            if token == auto {
                return true;
            }
        }

        let sessions = self.sessions.lock().unwrap();
        match sessions.get(token) {
            Some(session) if !session.is_expired() => true,
            Some(_) => false, // expired
            None => false,
        }
    }

    pub fn current_code(&self) -> String {
        self.pairing.lock().unwrap().code.clone()
    }
}

fn generate_pairing_code() -> String {
    let chars: Vec<char> = "ABCDEFGHJKLMNPQRSTUVWXYZ23456789".chars().collect();
    let mut rng = rand::thread_rng();
    (0..PAIRING_CODE_LEN)
        .map(|_| chars[rng.gen_range(0..chars.len())])
        .collect()
}

fn generate_session_token() -> String {
    let mut buf = [0u8; SESSION_TOKEN_LEN];
    rand::thread_rng().fill(&mut buf);
    base64::Engine::encode(&base64::engine::general_purpose::URL_SAFE_NO_PAD, &buf)
}
