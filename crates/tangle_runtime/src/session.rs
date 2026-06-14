#![forbid(unsafe_code)]

use axum::extract::ws::WebSocket;
use std::time::Instant;

#[derive(Debug)]
pub struct TangleWebSocketSession {
    connected_at: Instant,
}

impl TangleWebSocketSession {
    pub fn new() -> Self {
        Self {
            connected_at: Instant::now(),
        }
    }

    pub fn connected_at(&self) -> Instant {
        self.connected_at
    }

    pub async fn run(self, _socket: WebSocket) {}
}

impl Default for TangleWebSocketSession {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::TangleWebSocketSession;

    #[test]
    fn websocket_session_records_connection_time() {
        let before = std::time::Instant::now();
        let session = TangleWebSocketSession::new();

        assert!(session.connected_at() >= before);
    }
}
