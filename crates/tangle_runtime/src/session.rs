#![forbid(unsafe_code)]

use crate::{
    errors::BaseRelayError,
    relay::auth::{BaseAuthState, generate_auth_challenge},
    runtime::TangleRuntimeHandle,
};
use axum::extract::ws::{Message, WebSocket};
use std::time::{Instant, SystemTime, UNIX_EPOCH};
use tangle_protocol::{RelayMessage, UnixTimestamp, parse_client_message};
use tokio::sync::{mpsc, watch};

#[derive(Debug)]
pub struct TangleWebSocketSession {
    connected_at: Instant,
    outbound: TangleOutboundSender,
    outbound_receiver: mpsc::Receiver<Message>,
    shutdown: watch::Receiver<bool>,
    runtime: TangleRuntimeHandle,
    auth: BaseAuthState,
}

impl TangleWebSocketSession {
    pub fn new(
        outbound_queue_capacity: usize,
        shutdown: watch::Receiver<bool>,
        runtime: TangleRuntimeHandle,
        auth: BaseAuthState,
    ) -> Result<Self, BaseRelayError> {
        if outbound_queue_capacity == 0 {
            return Err(BaseRelayError::invalid(
                "runtime outbound queue capacity must be greater than zero",
            ));
        }
        let (sender, receiver) = mpsc::channel(outbound_queue_capacity);
        Ok(Self {
            connected_at: Instant::now(),
            outbound: TangleOutboundSender {
                sender,
                capacity: outbound_queue_capacity,
            },
            outbound_receiver: receiver,
            shutdown,
            runtime,
            auth,
        })
    }

    pub fn connected_at(&self) -> Instant {
        self.connected_at
    }

    pub fn outbound(&self) -> TangleOutboundSender {
        self.outbound.clone()
    }

    pub fn shutdown_requested(&self) -> bool {
        *self.shutdown.borrow()
    }

    pub async fn run(mut self, mut socket: WebSocket) {
        if !self.issue_auth_challenge() {
            return;
        }
        loop {
            if self.shutdown_requested() {
                let _ = socket.send(Message::Close(None)).await;
                break;
            }
            tokio::select! {
                incoming = socket.recv() => {
                    match incoming {
                        Some(Ok(Message::Close(_))) | Some(Err(_)) | None => break,
                        Some(Ok(message)) => {
                            if !self.handle_incoming_message(message).await {
                                break;
                            }
                        }
                    }
                }
                outgoing = self.outbound_receiver.recv() => {
                    let Some(message) = outgoing else {
                        break;
                    };
                    if socket.send(message).await.is_err() {
                        break;
                    }
                }
                changed = self.shutdown.changed() => {
                    if changed.is_err() || self.shutdown_requested() {
                        let _ = socket.send(Message::Close(None)).await;
                        break;
                    }
                }
            }
        }
    }

    async fn handle_incoming_message(&mut self, message: Message) -> bool {
        match message {
            Message::Text(raw) => self.dispatch_text(raw.as_str()).await,
            Message::Binary(_) => self
                .send_relay_message(RelayMessage::Notice(
                    "invalid: client message must be a text frame".to_owned(),
                ))
                .is_ok(),
            Message::Ping(_) | Message::Pong(_) => true,
            Message::Close(_) => false,
        }
    }

    fn issue_auth_challenge(&mut self) -> bool {
        let message = generate_auth_challenge()
            .and_then(|challenge| {
                self.auth
                    .issue_challenge(challenge, current_unix_timestamp())
            })
            .unwrap_or_else(|error| RelayMessage::Notice(error.prefixed_message()));
        self.send_relay_message(message).is_ok()
    }

    async fn dispatch_text(&mut self, raw: &str) -> bool {
        let replies = match parse_client_message(raw) {
            Ok(message) => {
                match self
                    .runtime
                    .handle_client_message(message, &mut self.auth, current_unix_timestamp())
                    .await
                {
                    Ok(replies) => replies,
                    Err(error) => vec![RelayMessage::Notice(error.prefixed_message())],
                }
            }
            Err(error) => vec![RelayMessage::Notice(format!("invalid: {error}"))],
        };
        for reply in replies {
            if self.send_relay_message(reply).is_err() {
                return false;
            }
        }
        true
    }

    fn send_relay_message(&self, message: RelayMessage) -> Result<(), TangleOutboundQueueError> {
        self.outbound
            .try_send(Message::Text(message.encode().into()))
    }
}

#[derive(Debug, Clone)]
pub struct TangleOutboundSender {
    sender: mpsc::Sender<Message>,
    capacity: usize,
}

impl TangleOutboundSender {
    pub fn capacity(&self) -> usize {
        self.capacity
    }

    pub fn try_send(&self, message: Message) -> Result<(), TangleOutboundQueueError> {
        self.sender.try_send(message).map_err(Into::into)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TangleOutboundQueueError {
    Full,
    Closed,
}

impl From<mpsc::error::TrySendError<Message>> for TangleOutboundQueueError {
    fn from(error: mpsc::error::TrySendError<Message>) -> Self {
        match error {
            mpsc::error::TrySendError::Full(_) => Self::Full,
            mpsc::error::TrySendError::Closed(_) => Self::Closed,
        }
    }
}

fn current_unix_timestamp() -> UnixTimestamp {
    UnixTimestamp::new(
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|duration| duration.as_secs())
            .unwrap_or(0),
    )
}

#[cfg(test)]
mod tests {
    use super::{TangleOutboundQueueError, TangleWebSocketSession};
    use crate::{
        config::{BaseRelayRuntimeConfig, parse_base_relay_runtime_config_json},
        runtime::{TangleRuntime, TangleRuntimeHandle, TangleShutdownSignal},
    };
    use axum::extract::ws::Message;
    use serde_json::json;
    use std::path::{Path, PathBuf};

    #[test]
    fn websocket_session_records_connection_time() {
        let before = std::time::Instant::now();
        let shutdown = TangleShutdownSignal::new();
        let (runtime, auth) = session_runtime("records-connection-time");
        let session =
            TangleWebSocketSession::new(8, shutdown.subscribe(), runtime, auth).expect("session");

        assert!(session.connected_at() >= before);
    }

    #[test]
    fn websocket_session_rejects_zero_outbound_capacity() {
        let shutdown = TangleShutdownSignal::new();
        let (runtime, auth) = session_runtime("zero-outbound-capacity");

        assert!(TangleWebSocketSession::new(0, shutdown.subscribe(), runtime, auth).is_err());
    }

    #[test]
    fn websocket_session_observes_shutdown_request() {
        let shutdown = TangleShutdownSignal::new();
        let (runtime, auth) = session_runtime("observes-shutdown");
        let session =
            TangleWebSocketSession::new(8, shutdown.subscribe(), runtime, auth).expect("session");

        assert!(!session.shutdown_requested());

        shutdown.request_shutdown();

        assert!(session.shutdown_requested());
    }

    #[test]
    fn outbound_queue_is_bounded() {
        let shutdown = TangleShutdownSignal::new();
        let (runtime, auth) = session_runtime("outbound-queue");
        let session =
            TangleWebSocketSession::new(1, shutdown.subscribe(), runtime, auth).expect("session");
        let outbound = session.outbound();

        assert_eq!(outbound.capacity(), 1);
        outbound
            .try_send(Message::Text("first".into()))
            .expect("first");
        assert_eq!(
            outbound
                .try_send(Message::Text("second".into()))
                .expect_err("full"),
            TangleOutboundQueueError::Full
        );
    }

    fn session_runtime(name: &str) -> (TangleRuntimeHandle, crate::relay::auth::BaseAuthState) {
        let root = temp_root(name);
        let _ = std::fs::remove_dir_all(&root);
        let runtime = TangleRuntime::open(runtime_config(&root)).expect("runtime");
        let auth = runtime.auth_state().expect("auth");
        (TangleRuntimeHandle::new(runtime), auth)
    }

    fn runtime_config(root: &Path) -> BaseRelayRuntimeConfig {
        let raw = json!({
            "server": {
                "listen_addr": "127.0.0.1:0",
                "relay_url": "wss://relay.radroots.test"
            },
            "pocket": {
                "data_directory": root.join("pocket"),
                "map_size_bytes": 1073741824_u64,
                "reader_slots": 128,
                "sync_policy": "flush_on_shutdown"
            },
            "groups": {
                "enabled": false
            },
            "auth": {
                "challenge_ttl_seconds": 300,
                "created_at_skew_seconds": 600
            },
            "limits": {
                "max_pending_events": 8
            }
        })
        .to_string();
        parse_base_relay_runtime_config_json(&raw).expect("config")
    }

    fn temp_root(name: &str) -> PathBuf {
        std::env::temp_dir().join(format!("tangle-session-{name}-{}", std::process::id()))
    }
}
