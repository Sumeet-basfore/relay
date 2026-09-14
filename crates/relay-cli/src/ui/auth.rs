use std::collections::HashMap;
use std::time::{Duration, Instant};
use uuid::Uuid;

pub const DEFAULT_IDLE_TIMEOUT: Duration = Duration::from_secs(15 * 60); // 15 minutes

#[derive(Debug, thiserror::Error)]
pub enum AuthError {
    #[error("Missing authentication token")]
    MissingToken,
    #[error("Invalid authentication token")]
    InvalidToken,
    #[error("Session has expired due to inactivity")]
    SessionExpired,
    #[error("Session not found")]
    SessionNotFound,
    #[error("Invalid CSRF token")]
    InvalidCsrfToken,
    #[error("Missing CSRF token")]
    MissingCsrfToken,
}

#[derive(Debug, Clone)]
pub struct Session {
    pub session_token: String,
    pub csrf_token: String,
    pub created_at: Instant,
    pub last_active_at: Instant,
}

pub struct SessionManager {
    bootstrap_token: String,
    sessions: HashMap<String, Session>,
    idle_timeout: Duration,
}

impl SessionManager {
    pub fn new(bootstrap_token: Option<String>) -> Self {
        let token = bootstrap_token
            .unwrap_or_else(|| format!("{}{}", Uuid::now_v7().simple(), Uuid::now_v7().simple()));
        Self {
            bootstrap_token: token,
            sessions: HashMap::new(),
            idle_timeout: DEFAULT_IDLE_TIMEOUT,
        }
    }

    pub fn bootstrap_token(&self) -> &str {
        &self.bootstrap_token
    }

    /// Constant-time comparison between two strings to prevent timing attacks
    fn constant_time_compare(a: &str, b: &str) -> bool {
        let a_bytes = a.as_bytes();
        let b_bytes = b.as_bytes();
        if a_bytes.len() != b_bytes.len() {
            return false;
        }
        let mut result = 0u8;
        for (x, y) in a_bytes.iter().zip(b_bytes.iter()) {
            result |= x ^ y;
        }
        result == 0
    }

    /// Exchanges the bootstrap token for a session token and CSRF token
    pub fn exchange_token(&mut self, token: &str) -> Result<(String, String), AuthError> {
        self.cleanup_expired();

        if !Self::constant_time_compare(token.trim(), self.bootstrap_token.trim()) {
            return Err(AuthError::InvalidToken);
        }

        let session_token = format!(
            "relaysess_{}{}",
            Uuid::now_v7().simple(),
            Uuid::now_v7().simple()
        );
        let csrf_token = format!("relaycsrf_{}", Uuid::now_v7().simple());
        let now = Instant::now();

        let session = Session {
            session_token: session_token.clone(),
            csrf_token: csrf_token.clone(),
            created_at: now,
            last_active_at: now,
        };

        self.sessions.insert(session_token.clone(), session);
        Ok((session_token, csrf_token))
    }

    /// Validates an active session token and updates last activity time
    pub fn validate_session(&mut self, session_token: &str) -> Result<(), AuthError> {
        self.cleanup_expired();

        let session = match self.sessions.get_mut(session_token) {
            Some(s) => s,
            None => return Err(AuthError::SessionNotFound),
        };

        if session.last_active_at.elapsed() > self.idle_timeout {
            self.sessions.remove(session_token);
            return Err(AuthError::SessionExpired);
        }

        session.last_active_at = Instant::now();
        Ok(())
    }

    /// Validates CSRF token for a given active session
    pub fn validate_csrf(&self, session_token: &str, csrf_token: &str) -> Result<(), AuthError> {
        let session = match self.sessions.get(session_token) {
            Some(s) => s,
            None => return Err(AuthError::SessionNotFound),
        };

        if !Self::constant_time_compare(&session.csrf_token, csrf_token.trim()) {
            return Err(AuthError::InvalidCsrfToken);
        }

        Ok(())
    }

    /// Invalidate a specific session (logout)
    pub fn invalidate(&mut self, session_token: &str) {
        self.sessions.remove(session_token);
    }

    /// Clean up expired sessions
    pub fn cleanup_expired(&mut self) {
        let timeout = self.idle_timeout;
        self.sessions
            .retain(|_, s| s.last_active_at.elapsed() <= timeout);
    }
}
