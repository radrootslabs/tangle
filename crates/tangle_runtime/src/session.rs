#![forbid(unsafe_code)]

use crate::{
    errors::BaseRelayError,
    event_bus::{TangleEventReceiveError, TangleEventReceiver},
    relay::{
        auth::{BaseAuthState, generate_auth_challenge},
        live::LiveSubscriptionSet,
    },
    runtime::TangleRuntimeHandle,
};
use axum::extract::ws::{Message, WebSocket};
use std::time::{Instant, SystemTime, UNIX_EPOCH};
use tangle_groups::GroupAuthContext;
use tangle_protocol::{
    ClientMessage, Filter, RelayMessage, SubscriptionId, UnixTimestamp, parse_client_message,
};
use tokio::sync::{mpsc, watch};

#[derive(Debug)]
pub struct TangleWebSocketSession {
    connected_at: Instant,
    outbound: TangleOutboundSender,
    outbound_receiver: mpsc::Receiver<Message>,
    shutdown: watch::Receiver<bool>,
    runtime: TangleRuntimeHandle,
    auth: BaseAuthState,
    subscriptions: LiveSubscriptionSet,
    events: TangleEventReceiver,
}

impl TangleWebSocketSession {
    pub fn new(
        outbound_queue_capacity: usize,
        shutdown: watch::Receiver<bool>,
        runtime: TangleRuntimeHandle,
        auth: BaseAuthState,
        events: TangleEventReceiver,
    ) -> Result<Self, BaseRelayError> {
        if outbound_queue_capacity == 0 {
            return Err(BaseRelayError::invalid(
                "runtime outbound queue capacity must be greater than zero",
            ));
        }
        let (sender, receiver) = mpsc::channel(outbound_queue_capacity);
        let subscriptions = LiveSubscriptionSet::new(outbound_queue_capacity)?;
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
            subscriptions,
            events,
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

    #[cfg(test)]
    fn active_subscription_count(&self) -> usize {
        self.subscriptions.active_count()
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
                event_offset = self.events.recv() => {
                    match event_offset {
                        Ok(offset) => {
                            if !self.handle_event_offset(offset).await {
                                break;
                            }
                        }
                        Err(TangleEventReceiveError::Closed | TangleEventReceiveError::Lagged(_)) => break,
                        Err(TangleEventReceiveError::Empty) => {}
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
        self.subscriptions.close_all();
    }

    async fn handle_event_offset(&mut self, offset: tangle_groups::StoreOffset) -> bool {
        let runtime = self.runtime.clone();
        let replies = match runtime
            .fanout_event_offset(offset, &mut self.subscriptions)
            .await
        {
            Ok(replies) => replies,
            Err(error) => vec![RelayMessage::Notice(error.prefixed_message())],
        };
        for reply in replies {
            if self.send_relay_message(reply).is_err() {
                return false;
            }
        }
        true
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
            Ok(message) => match self.handle_client_message(message).await {
                Ok(replies) => replies,
                Err(error) => vec![RelayMessage::Notice(error.prefixed_message())],
            },
            Err(error) => vec![RelayMessage::Notice(format!("invalid: {error}"))],
        };
        for reply in replies {
            if self.send_relay_message(reply).is_err() {
                return false;
            }
        }
        true
    }

    async fn handle_client_message(
        &mut self,
        message: ClientMessage,
    ) -> Result<Vec<RelayMessage>, BaseRelayError> {
        match message {
            ClientMessage::Req {
                subscription_id,
                filters,
            } => self.handle_req(subscription_id, filters).await,
            ClientMessage::Close(subscription_id) => {
                self.subscriptions.close(&subscription_id);
                Ok(Vec::new())
            }
            message => {
                self.runtime
                    .handle_client_message(message, &mut self.auth, current_unix_timestamp())
                    .await
            }
        }
    }

    async fn handle_req(
        &mut self,
        subscription_id: SubscriptionId,
        filters: Vec<Filter>,
    ) -> Result<Vec<RelayMessage>, BaseRelayError> {
        self.subscriptions.subscribe(
            subscription_id.clone(),
            filters.clone(),
            GroupAuthContext::new(self.auth.authenticated_pubkeys().iter().cloned()),
        )?;
        match self
            .runtime
            .query_req_with_auth(subscription_id.clone(), filters, &self.auth)
            .await
        {
            Ok(replies) => Ok(replies),
            Err(error) => {
                self.subscriptions.close(&subscription_id);
                Err(error)
            }
        }
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
        event_bus::TangleEventReceiver,
        runtime::{TangleRuntime, TangleRuntimeHandle, TangleShutdownSignal},
    };
    use axum::extract::ws::Message;
    use serde_json::json;
    use std::path::{Path, PathBuf};
    use tangle_protocol::{ClientMessage, Filter, RelayMessage, SubscriptionId};

    #[test]
    fn websocket_session_records_connection_time() {
        let before = std::time::Instant::now();
        let shutdown = TangleShutdownSignal::new();
        let (runtime, auth, events) = session_runtime("records-connection-time");
        let session = TangleWebSocketSession::new(8, shutdown.subscribe(), runtime, auth, events)
            .expect("session");

        assert!(session.connected_at() >= before);
    }

    #[test]
    fn websocket_session_rejects_zero_outbound_capacity() {
        let shutdown = TangleShutdownSignal::new();
        let (runtime, auth, events) = session_runtime("zero-outbound-capacity");

        assert!(
            TangleWebSocketSession::new(0, shutdown.subscribe(), runtime, auth, events).is_err()
        );
    }

    #[test]
    fn websocket_session_observes_shutdown_request() {
        let shutdown = TangleShutdownSignal::new();
        let (runtime, auth, events) = session_runtime("observes-shutdown");
        let session = TangleWebSocketSession::new(8, shutdown.subscribe(), runtime, auth, events)
            .expect("session");

        assert!(!session.shutdown_requested());

        shutdown.request_shutdown();

        assert!(session.shutdown_requested());
    }

    #[tokio::test]
    async fn websocket_session_scopes_subscriptions_per_connection() {
        let shutdown = TangleShutdownSignal::new();
        let root = temp_root("connection-scope");
        let _ = std::fs::remove_dir_all(&root);
        let runtime =
            TangleRuntimeHandle::new(TangleRuntime::open(runtime_config(&root)).expect("runtime"));
        let auth_a = runtime.auth_state().await.expect("auth a");
        let auth_b = runtime.auth_state().await.expect("auth b");
        let events_a = runtime.subscribe_events().await;
        let events_b = runtime.subscribe_events().await;
        let mut first =
            TangleWebSocketSession::new(8, shutdown.subscribe(), runtime.clone(), auth_a, events_a)
                .expect("first");
        let mut second =
            TangleWebSocketSession::new(8, shutdown.subscribe(), runtime, auth_b, events_b)
                .expect("second");
        let subscription_id = SubscriptionId::new("shared").expect("subscription");

        assert_eq!(
            first
                .handle_client_message(req(subscription_id.clone()))
                .await
                .expect("first req"),
            vec![RelayMessage::Eose(subscription_id.clone())]
        );
        assert_eq!(
            second
                .handle_client_message(req(subscription_id.clone()))
                .await
                .expect("second req"),
            vec![RelayMessage::Eose(subscription_id.clone())]
        );
        assert_eq!(first.active_subscription_count(), 1);
        assert_eq!(second.active_subscription_count(), 1);

        assert_eq!(
            first
                .handle_client_message(ClientMessage::Close(subscription_id.clone()))
                .await
                .expect("close first"),
            Vec::<RelayMessage>::new()
        );
        assert_eq!(first.active_subscription_count(), 0);
        assert_eq!(second.active_subscription_count(), 1);

        assert_eq!(
            second
                .handle_client_message(req(subscription_id.clone()))
                .await
                .expect("replace second"),
            vec![RelayMessage::Eose(subscription_id.clone())]
        );
        assert_eq!(first.active_subscription_count(), 0);
        assert_eq!(second.active_subscription_count(), 1);

        assert_eq!(
            second
                .handle_client_message(ClientMessage::Close(subscription_id))
                .await
                .expect("close second"),
            Vec::<RelayMessage>::new()
        );
        assert_eq!(second.active_subscription_count(), 0);

        let _ = std::fs::remove_dir_all(root);
    }

    #[test]
    fn outbound_queue_is_bounded() {
        let shutdown = TangleShutdownSignal::new();
        let (runtime, auth, events) = session_runtime("outbound-queue");
        let session = TangleWebSocketSession::new(1, shutdown.subscribe(), runtime, auth, events)
            .expect("session");
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

    fn session_runtime(
        name: &str,
    ) -> (
        TangleRuntimeHandle,
        crate::relay::auth::BaseAuthState,
        TangleEventReceiver,
    ) {
        let root = temp_root(name);
        let _ = std::fs::remove_dir_all(&root);
        let runtime = TangleRuntime::open(runtime_config(&root)).expect("runtime");
        let auth = runtime.auth_state().expect("auth");
        let events = runtime.event_bus().subscribe();
        (TangleRuntimeHandle::new(runtime), auth, events)
    }

    fn req(subscription_id: SubscriptionId) -> ClientMessage {
        ClientMessage::Req {
            subscription_id,
            filters: vec![Filter::empty()],
        }
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
