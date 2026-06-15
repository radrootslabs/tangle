#![forbid(unsafe_code)]

use crate::{
    client_message::parse_runtime_client_message,
    errors::BaseRelayError,
    event_bus::{TangleEventReceiveError, TangleEventReceiver},
    logging,
    relay::{
        auth::{BaseAuthState, generate_auth_challenge},
        core::BaseRelay,
        live::{CloseResult, LiveSubscriptionSet},
    },
    runtime::{
        TangleClientMessageMetricKind, TangleClientRateLimitContext, TangleRuntimeHandle,
        TangleRuntimeLimits,
    },
};
use axum::extract::ws::{CloseFrame, Message, Utf8Bytes, WebSocket};
use std::{
    net::IpAddr,
    sync::atomic::{AtomicU64, Ordering},
    time::{Instant, SystemTime, UNIX_EPOCH},
};
use tangle_protocol::{ClientMessage, Filter, RelayMessage, SubscriptionId, UnixTimestamp};
use tokio::sync::{mpsc, watch};

#[derive(Debug)]
pub struct TangleWebSocketSession {
    connection_id: u64,
    peer_ip: Option<IpAddr>,
    connected_at: Instant,
    outbound: TangleOutboundSender,
    outbound_receiver: mpsc::Receiver<Message>,
    shutdown: watch::Receiver<bool>,
    runtime: TangleRuntimeHandle,
    limits: TangleRuntimeLimits,
    auth: BaseAuthState,
    subscriptions: LiveSubscriptionSet,
    events: TangleEventReceiver,
}

static NEXT_TANGLE_CONNECTION_ID: AtomicU64 = AtomicU64::new(1);

impl TangleWebSocketSession {
    pub fn new(
        limits: TangleRuntimeLimits,
        shutdown: watch::Receiver<bool>,
        runtime: TangleRuntimeHandle,
        auth: BaseAuthState,
        events: TangleEventReceiver,
    ) -> Result<Self, BaseRelayError> {
        Self::new_with_peer(limits, shutdown, runtime, auth, events, None)
    }

    pub fn new_with_peer(
        limits: TangleRuntimeLimits,
        shutdown: watch::Receiver<bool>,
        runtime: TangleRuntimeHandle,
        auth: BaseAuthState,
        events: TangleEventReceiver,
        peer_ip: Option<IpAddr>,
    ) -> Result<Self, BaseRelayError> {
        let outbound_queue_capacity = limits.outbound_queue_capacity();
        let (sender, receiver) = mpsc::channel(outbound_queue_capacity);
        let subscriptions = LiveSubscriptionSet::new(
            limits.base_relay_limits().max_pending_events(),
            limits.base_relay_limits().max_subscriptions(),
        )?;
        Ok(Self {
            connection_id: NEXT_TANGLE_CONNECTION_ID.fetch_add(1, Ordering::Relaxed),
            peer_ip,
            connected_at: Instant::now(),
            outbound: TangleOutboundSender {
                sender,
                capacity: outbound_queue_capacity,
            },
            outbound_receiver: receiver,
            shutdown,
            runtime,
            limits,
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
        let metrics = self.runtime.metrics();
        metrics.record_session_opened();
        logging::log_websocket_session_opened(self.connection_id, self.peer_ip);
        if !self.issue_auth_challenge() {
            let closed_subscriptions = self.subscriptions.close_all();
            metrics.record_subscriptions_closed(closed_subscriptions);
            metrics.record_session_closed();
            metrics.record_event_bus_receivers(
                metrics.event_bus_receivers_current().saturating_sub(1),
            );
            logging::log_websocket_session_closed(
                self.connection_id,
                self.peer_ip,
                closed_subscriptions,
            );
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
                            match self.handle_incoming_message(message).await {
                                TangleSessionControl::Continue => {}
                                TangleSessionControl::Close(message) => {
                                    let _ = socket.send(message).await;
                                    break;
                                }
                                TangleSessionControl::Stop => break,
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
                event = self.events.recv() => {
                    match self.handle_event_receive_result(event).await {
                        TangleSessionControl::Continue => {}
                        TangleSessionControl::Close(message) => {
                            let _ = socket.send(message).await;
                            break;
                        }
                        TangleSessionControl::Stop => break,
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
        let closed_subscriptions = self.subscriptions.close_all();
        metrics.record_subscriptions_closed(closed_subscriptions);
        metrics.record_session_closed();
        metrics.record_event_bus_receivers(metrics.event_bus_receivers_current().saturating_sub(1));
        logging::log_websocket_session_closed(
            self.connection_id,
            self.peer_ip,
            closed_subscriptions,
        );
    }

    async fn handle_event_receive_result(
        &mut self,
        result: Result<tangle_groups::StoreOffset, TangleEventReceiveError>,
    ) -> TangleSessionControl {
        match result {
            Ok(offset) => self.handle_event_offset(offset).await,
            Err(TangleEventReceiveError::Lagged(skipped)) => {
                self.runtime.metrics().record_event_bus_lagged(skipped);
                TangleSessionControl::Close(event_stream_lag_close_message())
            }
            Err(TangleEventReceiveError::Closed) => TangleSessionControl::Stop,
            Err(TangleEventReceiveError::Empty) => TangleSessionControl::Continue,
        }
    }

    async fn handle_event_offset(
        &mut self,
        offset: tangle_groups::StoreOffset,
    ) -> TangleSessionControl {
        let runtime = self.runtime.clone();
        let auth = self.auth.clone();
        let replies = match runtime
            .fanout_event_offset(offset, &mut self.subscriptions, &auth)
            .await
        {
            Ok(replies) => replies,
            Err(error) => vec![RelayMessage::Notice(error.prefixed_message())],
        };
        for reply in replies {
            if let Err(control) = self.enqueue_relay_message(reply) {
                return control;
            }
        }
        TangleSessionControl::Continue
    }

    async fn handle_incoming_message(&mut self, message: Message) -> TangleSessionControl {
        match message {
            Message::Text(raw) => self.dispatch_text(raw.as_str()).await,
            Message::Binary(_) => self
                .enqueue_relay_message(RelayMessage::Notice(
                    "invalid: client message must be a text frame".to_owned(),
                ))
                .map(|_| TangleSessionControl::Continue)
                .unwrap_or_else(|control| control),
            Message::Ping(_) | Message::Pong(_) => TangleSessionControl::Continue,
            Message::Close(_) => TangleSessionControl::Stop,
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

    async fn dispatch_text(&mut self, raw: &str) -> TangleSessionControl {
        if raw.len() > self.limits.max_message_length() {
            return self
                .enqueue_relay_message(RelayMessage::Notice(format!(
                    "invalid: client message length exceeds runtime max_message_length {}",
                    self.limits.max_message_length()
                )))
                .map(|_| TangleSessionControl::Continue)
                .unwrap_or_else(|control| control);
        }
        let replies = match parse_runtime_client_message(raw) {
            Ok(message) => match self.handle_client_message(message).await {
                Ok(replies) => replies,
                Err(error) => vec![RelayMessage::Notice(error.prefixed_message())],
            },
            Err(error) => vec![RelayMessage::Notice(format!("invalid: {error}"))],
        };
        for reply in replies {
            if let Err(control) = self.enqueue_relay_message(reply) {
                return control;
            }
        }
        TangleSessionControl::Continue
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
            ClientMessage::Count {
                subscription_id,
                filters,
            } => {
                let context = self.client_rate_limit_context();
                self.runtime
                    .handle_client_message_with_rate_limit_context(
                        ClientMessage::Count {
                            subscription_id,
                            filters,
                        },
                        &mut self.auth,
                        context,
                        current_unix_timestamp(),
                    )
                    .await
            }
            ClientMessage::Close(subscription_id) => {
                let metrics = self.runtime.metrics();
                metrics.record_client_message(TangleClientMessageMetricKind::Close);
                self.limits
                    .base_relay_limits()
                    .validate_subscription_id(&subscription_id)?;
                if self.subscriptions.close(&subscription_id) == CloseResult::Closed {
                    metrics.record_subscriptions_closed(1);
                }
                Ok(Vec::new())
            }
            message => {
                let context = self.client_rate_limit_context();
                self.runtime
                    .handle_client_message_with_rate_limit_context(
                        message,
                        &mut self.auth,
                        context,
                        current_unix_timestamp(),
                    )
                    .await
            }
        }
    }

    async fn handle_req(
        &mut self,
        subscription_id: SubscriptionId,
        filters: Vec<Filter>,
    ) -> Result<Vec<RelayMessage>, BaseRelayError> {
        let metrics = self.runtime.metrics();
        metrics.record_client_message(TangleClientMessageMetricKind::Req);
        self.limits
            .base_relay_limits()
            .validate_subscription_id(&subscription_id)?;
        self.limits.base_relay_limits().validate_filters(&filters)?;
        if let Some(message) = BaseRelay::unsupported_search_closed(&subscription_id, &filters) {
            return Ok(vec![message]);
        }
        if let Some(message) = self
            .runtime
            .rate_limit_req(
                &subscription_id,
                &filters,
                &self.auth,
                self.client_rate_limit_context(),
                current_unix_timestamp(),
            )
            .await
        {
            return Ok(vec![message]);
        }
        let should_subscribe = !filters_are_complete(&filters);
        if should_subscribe {
            self.subscriptions
                .ensure_can_subscribe(&subscription_id, &filters)?;
        }
        let report = self
            .runtime
            .query_req_with_auth_report(subscription_id.clone(), filters.clone(), &self.auth)
            .await?;
        let closes_subscription = report.group_read_denied();
        let replies = report.into_messages();
        if should_subscribe && !closes_subscription {
            self.subscriptions
                .subscribe(subscription_id.clone(), filters)?;
            metrics.record_subscription_opened();
            logging::log_subscription_opened(self.connection_id, &subscription_id);
        }
        Ok(replies)
    }

    fn client_rate_limit_context(&self) -> TangleClientRateLimitContext {
        TangleClientRateLimitContext::new(self.peer_ip, Some(self.connection_id))
    }

    fn send_relay_message(&self, message: RelayMessage) -> Result<(), TangleOutboundQueueError> {
        self.outbound
            .try_send(Message::Text(message.encode().into()))
    }

    fn enqueue_relay_message(&self, message: RelayMessage) -> Result<(), TangleSessionControl> {
        self.send_relay_message(message)
            .map_err(|error| self.outbound_queue_error_control(error))
    }

    fn outbound_queue_error_control(
        &self,
        error: TangleOutboundQueueError,
    ) -> TangleSessionControl {
        match error {
            TangleOutboundQueueError::Full => {
                self.runtime.metrics().record_outbound_queue_full_close();
                TangleSessionControl::Close(outbound_queue_full_close_message())
            }
            TangleOutboundQueueError::Closed => TangleSessionControl::Stop,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
enum TangleSessionControl {
    Continue,
    Close(Message),
    Stop,
}

fn event_stream_lag_close_message() -> Message {
    Message::Close(Some(CloseFrame {
        code: 1008,
        reason: Utf8Bytes::from_static("event stream lagged; reconnect required"),
    }))
}

fn outbound_queue_full_close_message() -> Message {
    Message::Close(Some(CloseFrame {
        code: 1013,
        reason: Utf8Bytes::from_static("outbound queue full; reconnect required"),
    }))
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

fn filters_are_complete(filters: &[Filter]) -> bool {
    !filters.is_empty() && filters.iter().all(Filter::is_complete)
}

#[cfg(test)]
mod tests {
    use super::{
        TangleOutboundQueueError, TangleSessionControl, TangleWebSocketSession,
        current_unix_timestamp, event_stream_lag_close_message, outbound_queue_full_close_message,
    };
    use crate::{
        config::{BaseRelayRuntimeConfig, parse_base_relay_runtime_config_json},
        errors::BaseRelayError,
        event_bus::TangleEventReceiver,
        rate_limits::{TangleRateLimitKey, TangleRateLimitScope},
        relay::core::{BaseRelayLimitSettings, BaseRelayLimits},
        runtime::{TangleRuntime, TangleRuntimeHandle, TangleRuntimeLimits, TangleShutdownSignal},
    };
    use axum::extract::ws::Message;
    use serde_json::json;
    use std::path::{Path, PathBuf};
    use tangle_groups::StoreOffset;
    use tangle_protocol::{
        ClientMessage, Filter, RelayMessage, SubscriptionId, UnixTimestamp, event_to_value,
        filter_from_value,
    };
    use tangle_test_support::{
        FixtureKey, tangle_v2_auth_event, tangle_v2_event, tangle_v2_group_create_event,
        tangle_v2_group_event,
    };

    #[test]
    fn websocket_session_records_connection_time() {
        let before = std::time::Instant::now();
        let shutdown = TangleShutdownSignal::new();
        let (runtime, auth, events) = session_runtime("records-connection-time");
        let session = TangleWebSocketSession::new(
            session_limits(8),
            shutdown.subscribe(),
            runtime,
            auth,
            events,
        )
        .expect("session");

        assert!(session.connected_at() >= before);
    }

    #[test]
    fn websocket_session_limit_config_rejects_zero_outbound_capacity() {
        assert!(session_limits_result(0).is_err());
    }

    #[test]
    fn websocket_session_observes_shutdown_request() {
        let shutdown = TangleShutdownSignal::new();
        let (runtime, auth, events) = session_runtime("observes-shutdown");
        let session = TangleWebSocketSession::new(
            session_limits(8),
            shutdown.subscribe(),
            runtime,
            auth,
            events,
        )
        .expect("session");

        assert!(!session.shutdown_requested());

        shutdown.request_shutdown();

        assert!(session.shutdown_requested());
    }

    #[tokio::test]
    async fn websocket_session_rejects_overlong_text_before_parsing() {
        let shutdown = TangleShutdownSignal::new();
        let (runtime, auth, events) = session_runtime("overlong-text");
        let mut session = TangleWebSocketSession::new(
            session_limits_with_message_length(8, 8),
            shutdown.subscribe(),
            runtime,
            auth,
            events,
        )
        .expect("session");

        assert_eq!(
            session.dispatch_text("123456789").await,
            TangleSessionControl::Continue
        );
        let message = session.outbound_receiver.try_recv().expect("notice");
        let Message::Text(text) = message else {
            panic!("expected text notice")
        };
        assert_eq!(
            text.as_str(),
            "[\"NOTICE\",\"invalid: client message length exceeds runtime max_message_length 8\"]"
        );
    }

    #[tokio::test]
    async fn websocket_session_preserves_chorus_malformed_message_parity() {
        let shutdown = TangleShutdownSignal::new();
        let (runtime, auth, events) = session_runtime("chorus-malformed-parity");
        let mut session = TangleWebSocketSession::new(
            session_limits(16),
            shutdown.subscribe(),
            runtime,
            auth,
            events,
        )
        .expect("session");
        let event = tangle_v2_event(FixtureKey::Member, 1_714_124_433, 1, Vec::new(), "parity")
            .expect("event");
        for (raw, expected) in [
            ("{", None),
            (
                "[\"NOTICE\",\"client\"]",
                Some("[\"NOTICE\",\"invalid: client message command `NOTICE` is unsupported\"]"),
            ),
            (
                "[\"NEG-OPEN\",\"sub\",{}]",
                Some(
                    "[\"NOTICE\",\"invalid: NEG-OPEN client message must contain a subscription id, filter, and message\"]",
                ),
            ),
            (
                "[\"REQ\"]",
                Some(
                    "[\"NOTICE\",\"invalid: REQ client message must contain a subscription id and filters\"]",
                ),
            ),
            (
                "[\"CLOSE\",1]",
                Some("[\"NOTICE\",\"invalid: CLOSE subscription id must be a string\"]"),
            ),
        ] {
            assert_eq!(
                session.dispatch_text(raw).await,
                TangleSessionControl::Continue
            );
            let text = take_outbound_text(&mut session);
            if let Some(expected) = expected {
                assert_eq!(text, expected);
            } else {
                assert!(text.starts_with("[\"NOTICE\",\"invalid: client message JSON is invalid:"));
            }
        }

        assert_eq!(
            session
                .dispatch_text("[\"REQ\",\"sub-search\",{\"search\":\"carrots\"}]")
                .await,
            TangleSessionControl::Continue
        );
        assert_eq!(
            take_outbound_text(&mut session),
            "[\"CLOSED\",\"sub-search\",\"unsupported: search filters are not supported\"]"
        );

        assert_eq!(
            session
                .dispatch_text(&json!(["EVENT", event_to_value(&event)]).to_string())
                .await,
            TangleSessionControl::Continue
        );
        assert_eq!(
            take_outbound_text(&mut session),
            format!("[\"OK\",\"{}\",true,\"\"]", event.id().as_str())
        );
    }

    #[tokio::test]
    async fn websocket_session_returns_disabled_negentropy_errors() {
        let shutdown = TangleShutdownSignal::new();
        let (runtime, auth, events) = session_runtime("disabled-negentropy");
        let mut session = TangleWebSocketSession::new(
            session_limits(16),
            shutdown.subscribe(),
            runtime,
            auth,
            events,
        )
        .expect("session");

        assert_eq!(
            session
                .dispatch_text("[\"NEG-OPEN\",\"neg-sub\",{\"kinds\":[1]},\"00\"]")
                .await,
            TangleSessionControl::Continue
        );
        assert_eq!(
            take_outbound_text(&mut session),
            "[\"NEG-ERR\",\"neg-sub\",\"blocked: Negentropy sync is disabled\"]"
        );
        assert_eq!(
            session
                .dispatch_text("[\"NEG-MSG\",\"neg-sub\",\"\"]")
                .await,
            TangleSessionControl::Continue
        );
        assert_eq!(
            take_outbound_text(&mut session),
            "[\"NEG-ERR\",\"neg-sub\",\"blocked: Negentropy sync is disabled\"]"
        );
        assert_eq!(
            session.dispatch_text("[\"NEG-CLOSE\",\"neg-sub\"]").await,
            TangleSessionControl::Continue
        );
        assert!(session.outbound_receiver.try_recv().is_err());
    }

    #[tokio::test]
    async fn websocket_session_disabled_negentropy_privacy_response_omits_filter_material() {
        let shutdown = TangleShutdownSignal::new();
        let (runtime, auth, events) = session_runtime("disabled-negentropy-privacy");
        let mut session = TangleWebSocketSession::new(
            session_limits(16),
            shutdown.subscribe(),
            runtime,
            auth,
            events,
        )
        .expect("session");
        let hidden_event_id = "a".repeat(64);
        let private_group_id = "private-group-alpha";
        let raw = json!([
            "NEG-OPEN",
            "neg-private",
            {"ids": [hidden_event_id], "#h": [private_group_id]},
            "00"
        ])
        .to_string();

        assert_eq!(
            session.dispatch_text(&raw).await,
            TangleSessionControl::Continue
        );
        let text = take_outbound_text(&mut session);

        assert_eq!(
            text,
            "[\"NEG-ERR\",\"neg-private\",\"blocked: Negentropy sync is disabled\"]"
        );
        assert!(!text.contains(private_group_id));
        assert!(!text.contains(&hidden_event_id));
        assert!(!text.contains("inventory"));
        assert!(!text.contains("#h"));
    }

    #[tokio::test]
    async fn websocket_session_scopes_subscriptions_per_connection() {
        let shutdown = TangleShutdownSignal::new();
        let root = temp_root("connection-scope");
        let _ = std::fs::remove_dir_all(&root);
        let runtime =
            TangleRuntimeHandle::new(TangleRuntime::open(runtime_config(&root)).expect("runtime"));
        let metrics = runtime.metrics();
        let auth_a = runtime.auth_state().await.expect("auth a");
        let auth_b = runtime.auth_state().await.expect("auth b");
        let events_a = runtime.subscribe_events().await;
        let events_b = runtime.subscribe_events().await;
        let mut first = TangleWebSocketSession::new(
            session_limits(8),
            shutdown.subscribe(),
            runtime.clone(),
            auth_a,
            events_a,
        )
        .expect("first");
        let mut second = TangleWebSocketSession::new(
            session_limits(8),
            shutdown.subscribe(),
            runtime.clone(),
            auth_b,
            events_b,
        )
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
        let snapshot = metrics.snapshot();
        assert_eq!(snapshot.client_messages(), 5);
        assert_eq!(snapshot.req_messages(), 3);
        assert_eq!(snapshot.close_messages(), 2);
        assert_eq!(snapshot.opened_subscriptions(), 3);
        assert_eq!(snapshot.closed_subscriptions(), 2);

        let _ = std::fs::remove_dir_all(root);
    }

    #[tokio::test]
    async fn websocket_session_live_fanout_uses_current_auth() {
        let shutdown = TangleShutdownSignal::new();
        let root = temp_root("current-auth-live");
        let _ = std::fs::remove_dir_all(&root);
        let runtime = TangleRuntimeHandle::new(
            TangleRuntime::open(runtime_config_with_groups(&root)).expect("runtime"),
        );
        let mut owner_auth = runtime.auth_state().await.expect("owner auth");
        owner_auth
            .issue_challenge("owner-live", UnixTimestamp::new(100))
            .expect("owner challenge");
        let owner_auth_event =
            tangle_v2_auth_event(FixtureKey::Owner, "owner-live", 120).expect("owner auth event");
        assert_eq!(
            runtime
                .handle_client_message(
                    ClientMessage::Auth(owner_auth_event.clone()),
                    &mut owner_auth,
                    UnixTimestamp::new(120)
                )
                .await
                .expect("owner auth"),
            vec![RelayMessage::Ok {
                event_id: owner_auth_event.id().clone(),
                accepted: true,
                message: String::new()
            }]
        );
        let create = tangle_v2_group_create_event(FixtureKey::Owner, "LiveFarm", 121, &["private"])
            .expect("create");
        assert_eq!(
            runtime
                .handle_client_message(
                    ClientMessage::Event(create.clone()),
                    &mut owner_auth,
                    UnixTimestamp::new(121)
                )
                .await
                .expect("create"),
            vec![RelayMessage::Ok {
                event_id: create.id().clone(),
                accepted: true,
                message: String::new()
            }]
        );
        let session_auth = runtime.auth_state().await.expect("session auth");
        let events = runtime.subscribe_events().await;
        let mut session = TangleWebSocketSession::new(
            session_limits(8),
            shutdown.subscribe(),
            runtime.clone(),
            session_auth,
            events,
        )
        .expect("session");
        let subscription_id = SubscriptionId::new("current-auth-live").expect("subscription");

        assert_eq!(
            session
                .handle_client_message(ClientMessage::Req {
                    subscription_id: subscription_id.clone(),
                    filters: vec![
                        filter_from_value(&json!({"kinds":[1], "#h":["LiveFarm"]}))
                            .expect("filter")
                    ],
                })
                .await
                .expect("req"),
            vec![RelayMessage::Eose(subscription_id.clone())]
        );
        assert_eq!(session.active_subscription_count(), 1);
        let before_auth =
            tangle_v2_group_event(FixtureKey::Owner, "LiveFarm", 122, 1, "before auth")
                .expect("before auth");
        let before_auth_id = before_auth.id().clone();
        assert_eq!(
            runtime
                .handle_client_message(
                    ClientMessage::Event(before_auth),
                    &mut owner_auth,
                    UnixTimestamp::new(122)
                )
                .await
                .expect("before event"),
            vec![RelayMessage::Ok {
                event_id: before_auth_id,
                accepted: true,
                message: String::new()
            }]
        );
        let offset = session.events.recv().await;
        assert_eq!(
            session.handle_event_receive_result(offset).await,
            TangleSessionControl::Continue
        );
        assert!(session.outbound_receiver.try_recv().is_err());

        let session_now = current_unix_timestamp();
        session
            .auth
            .issue_challenge("session-live", session_now)
            .expect("session challenge");
        let session_auth_event =
            tangle_v2_auth_event(FixtureKey::Owner, "session-live", session_now.as_u64())
                .expect("auth event");
        assert_eq!(
            session
                .handle_client_message(ClientMessage::Auth(session_auth_event.clone()))
                .await
                .expect("session auth"),
            vec![RelayMessage::Ok {
                event_id: session_auth_event.id().clone(),
                accepted: true,
                message: String::new()
            }]
        );
        let after_auth = tangle_v2_group_event(FixtureKey::Owner, "LiveFarm", 132, 1, "after auth")
            .expect("after auth");
        assert_eq!(
            runtime
                .handle_client_message(
                    ClientMessage::Event(after_auth.clone()),
                    &mut owner_auth,
                    UnixTimestamp::new(132)
                )
                .await
                .expect("after event"),
            vec![RelayMessage::Ok {
                event_id: after_auth.id().clone(),
                accepted: true,
                message: String::new()
            }]
        );
        let offset = session.events.recv().await;
        assert_eq!(
            session.handle_event_receive_result(offset).await,
            TangleSessionControl::Continue
        );
        assert_eq!(
            take_outbound_text(&mut session),
            RelayMessage::Event {
                subscription_id,
                event: after_auth
            }
            .encode()
        );

        let _ = std::fs::remove_dir_all(root);
    }

    #[tokio::test]
    async fn websocket_session_complete_and_failed_reqs_do_not_subscribe() {
        let shutdown = TangleShutdownSignal::new();
        let root = temp_root("complete-req-lifecycle");
        let _ = std::fs::remove_dir_all(&root);
        let runtime =
            TangleRuntimeHandle::new(TangleRuntime::open(runtime_config(&root)).expect("runtime"));
        let mut auth = runtime.auth_state().await.expect("auth");
        let events = runtime.subscribe_events().await;
        let mut session = TangleWebSocketSession::new(
            session_limits(8),
            shutdown.subscribe(),
            runtime.clone(),
            runtime.auth_state().await.expect("session auth"),
            events,
        )
        .expect("session");
        let event = tangle_v2_event(FixtureKey::Member, 1_714_124_433, 1, Vec::new(), "complete")
            .expect("event");

        assert_eq!(
            runtime
                .handle_client_message(
                    ClientMessage::Event(event.clone()),
                    &mut auth,
                    UnixTimestamp::new(1_714_124_433)
                )
                .await
                .expect("event"),
            vec![RelayMessage::Ok {
                event_id: event.id().clone(),
                accepted: true,
                message: String::new()
            }]
        );
        let exact_id = SubscriptionId::new("exact-id").expect("subscription");
        assert_eq!(
            session
                .handle_client_message(ClientMessage::Req {
                    subscription_id: exact_id.clone(),
                    filters: vec![
                        filter_from_value(&json!({"ids":[event.id().as_str()]}))
                            .expect("exact filter")
                    ],
                })
                .await
                .expect("exact req"),
            vec![
                RelayMessage::Event {
                    subscription_id: exact_id.clone(),
                    event: event.clone()
                },
                RelayMessage::Eose(exact_id)
            ]
        );
        assert_eq!(session.active_subscription_count(), 0);

        let open = SubscriptionId::new("open").expect("subscription");
        assert_eq!(
            session
                .handle_client_message(ClientMessage::Req {
                    subscription_id: open.clone(),
                    filters: vec![filter_from_value(&json!({"kinds":[1]})).expect("open filter")],
                })
                .await
                .expect("open req"),
            vec![
                RelayMessage::Event {
                    subscription_id: open.clone(),
                    event
                },
                RelayMessage::Eose(open.clone())
            ]
        );
        assert_eq!(session.active_subscription_count(), 1);

        let search = SubscriptionId::new("search").expect("subscription");
        assert_eq!(
            session
                .handle_client_message(ClientMessage::Req {
                    subscription_id: search.clone(),
                    filters: vec![
                        filter_from_value(&json!({"search":"carrots"})).expect("search filter")
                    ],
                })
                .await
                .expect("search req"),
            vec![RelayMessage::Closed {
                subscription_id: search,
                message: "unsupported: search filters are not supported".to_owned()
            }]
        );
        assert_eq!(session.active_subscription_count(), 1);

        let invalid = SubscriptionId::new("invalid").expect("subscription");
        let invalid_result = session
            .handle_client_message(ClientMessage::Req {
                subscription_id: invalid,
                filters: vec![Filter::empty(); 11],
            })
            .await;
        assert!(invalid_result.is_err());
        assert_eq!(session.active_subscription_count(), 1);

        let _ = std::fs::remove_dir_all(root);
    }

    #[tokio::test]
    async fn websocket_session_redacted_initial_req_closes_without_live_subscription() {
        let shutdown = TangleShutdownSignal::new();
        let root = temp_root("redacted-req-close");
        let _ = std::fs::remove_dir_all(&root);
        let runtime = TangleRuntimeHandle::new(
            TangleRuntime::open(runtime_config_with_groups(&root)).expect("runtime"),
        );
        let mut owner_auth = runtime.auth_state().await.expect("owner auth");
        owner_auth
            .issue_challenge("owner-redacted", UnixTimestamp::new(100))
            .expect("owner challenge");
        let owner_auth_event = tangle_v2_auth_event(FixtureKey::Owner, "owner-redacted", 120)
            .expect("owner auth event");
        assert_eq!(
            runtime
                .handle_client_message(
                    ClientMessage::Auth(owner_auth_event.clone()),
                    &mut owner_auth,
                    UnixTimestamp::new(120)
                )
                .await
                .expect("owner auth"),
            vec![RelayMessage::Ok {
                event_id: owner_auth_event.id().clone(),
                accepted: true,
                message: String::new()
            }]
        );
        let create =
            tangle_v2_group_create_event(FixtureKey::Owner, "RedactedFarm", 121, &["private"])
                .expect("create");
        assert_eq!(
            runtime
                .handle_client_message(
                    ClientMessage::Event(create.clone()),
                    &mut owner_auth,
                    UnixTimestamp::new(121)
                )
                .await
                .expect("create"),
            vec![RelayMessage::Ok {
                event_id: create.id().clone(),
                accepted: true,
                message: String::new()
            }]
        );
        let public_event =
            tangle_v2_event(FixtureKey::Member, 1_714_124_433, 1, Vec::new(), "public")
                .expect("public");
        assert_eq!(
            runtime
                .handle_client_message(
                    ClientMessage::Event(public_event.clone()),
                    &mut owner_auth,
                    UnixTimestamp::new(122)
                )
                .await
                .expect("public event"),
            vec![RelayMessage::Ok {
                event_id: public_event.id().clone(),
                accepted: true,
                message: String::new()
            }]
        );
        let private_event =
            tangle_v2_group_event(FixtureKey::Owner, "RedactedFarm", 123, 1, "private")
                .expect("private");
        assert_eq!(
            runtime
                .handle_client_message(
                    ClientMessage::Event(private_event.clone()),
                    &mut owner_auth,
                    UnixTimestamp::new(123)
                )
                .await
                .expect("private event"),
            vec![RelayMessage::Ok {
                event_id: private_event.id().clone(),
                accepted: true,
                message: String::new()
            }]
        );

        let events = runtime.subscribe_events().await;
        let mut session = TangleWebSocketSession::new(
            session_limits(8),
            shutdown.subscribe(),
            runtime.clone(),
            runtime.auth_state().await.expect("session auth"),
            events,
        )
        .expect("session");
        let subscription_id = SubscriptionId::new("redacted-req").expect("subscription");
        assert_eq!(
            session
                .handle_client_message(ClientMessage::Req {
                    subscription_id: subscription_id.clone(),
                    filters: vec![filter_from_value(&json!({"kinds":[1]})).expect("filter")],
                })
                .await
                .expect("redacted req"),
            vec![
                RelayMessage::Event {
                    subscription_id: subscription_id.clone(),
                    event: public_event
                },
                RelayMessage::Closed {
                    subscription_id,
                    message: "auth-required: authentication required to read group events"
                        .to_owned()
                }
            ]
        );
        assert_eq!(session.active_subscription_count(), 0);

        let _ = std::fs::remove_dir_all(root);
    }

    #[tokio::test]
    async fn websocket_session_preserves_chorus_close_scope_parity() {
        let shutdown = TangleShutdownSignal::new();
        let root = temp_root("chorus-close-scope-parity");
        let _ = std::fs::remove_dir_all(&root);
        let runtime =
            TangleRuntimeHandle::new(TangleRuntime::open(runtime_config(&root)).expect("runtime"));
        let metrics = runtime.metrics();
        let auth_a = runtime.auth_state().await.expect("auth a");
        let auth_b = runtime.auth_state().await.expect("auth b");
        let events_a = runtime.subscribe_events().await;
        let events_b = runtime.subscribe_events().await;
        let mut first = TangleWebSocketSession::new(
            session_limits(8),
            shutdown.subscribe(),
            runtime.clone(),
            auth_a,
            events_a,
        )
        .expect("first");
        let mut second = TangleWebSocketSession::new(
            session_limits(8),
            shutdown.subscribe(),
            runtime,
            auth_b,
            events_b,
        )
        .expect("second");
        let subscription_id = SubscriptionId::new("shared-close").expect("subscription");
        let req_text = json!(["REQ", subscription_id.as_str(), {"kinds":[1]}]).to_string();

        assert_eq!(
            first.dispatch_text(&req_text).await,
            TangleSessionControl::Continue
        );
        assert_eq!(
            take_outbound_text(&mut first),
            RelayMessage::Eose(subscription_id.clone()).encode()
        );
        assert_eq!(
            second.dispatch_text(&req_text).await,
            TangleSessionControl::Continue
        );
        assert_eq!(
            take_outbound_text(&mut second),
            RelayMessage::Eose(subscription_id.clone()).encode()
        );
        assert_eq!(first.active_subscription_count(), 1);
        assert_eq!(second.active_subscription_count(), 1);

        let close_text = json!(["CLOSE", subscription_id.as_str()]).to_string();
        assert_eq!(
            first.dispatch_text(&close_text).await,
            TangleSessionControl::Continue
        );
        assert!(first.outbound_receiver.try_recv().is_err());
        assert_eq!(
            first.dispatch_text(&close_text).await,
            TangleSessionControl::Continue
        );
        assert!(first.outbound_receiver.try_recv().is_err());
        assert_eq!(first.active_subscription_count(), 0);
        assert_eq!(second.active_subscription_count(), 1);

        let event = tangle_v2_event(
            FixtureKey::Member,
            1_714_124_433,
            1,
            Vec::new(),
            "close scope parity",
        )
        .expect("event");
        assert_eq!(
            first
                .dispatch_text(&json!(["EVENT", event_to_value(&event)]).to_string())
                .await,
            TangleSessionControl::Continue
        );
        assert_eq!(
            take_outbound_text(&mut first),
            RelayMessage::Ok {
                event_id: event.id().clone(),
                accepted: true,
                message: String::new()
            }
            .encode()
        );

        let first_offset = first.events.recv().await;
        let second_offset = second.events.recv().await;
        assert_eq!(
            first.handle_event_receive_result(first_offset).await,
            TangleSessionControl::Continue
        );
        assert!(first.outbound_receiver.try_recv().is_err());
        assert_eq!(
            second.handle_event_receive_result(second_offset).await,
            TangleSessionControl::Continue
        );
        assert_eq!(
            take_outbound_text(&mut second),
            RelayMessage::Event {
                subscription_id: subscription_id.clone(),
                event
            }
            .encode()
        );
        let snapshot = metrics.snapshot();
        assert_eq!(snapshot.client_messages(), 5);
        assert_eq!(snapshot.event_messages(), 1);
        assert_eq!(snapshot.req_messages(), 2);
        assert_eq!(snapshot.close_messages(), 2);
        assert_eq!(snapshot.opened_subscriptions(), 2);
        assert_eq!(snapshot.closed_subscriptions(), 1);

        let _ = std::fs::remove_dir_all(root);
    }

    #[tokio::test]
    async fn websocket_session_rate_limited_req_does_not_subscribe() {
        let shutdown = TangleShutdownSignal::new();
        let root = temp_root("rate-limited-req");
        let _ = std::fs::remove_dir_all(&root);
        let runtime = TangleRuntime::open(runtime_config(&root)).expect("runtime");
        let rule = runtime.config().rate_limits().req().per_connection();
        let runtime = TangleRuntimeHandle::new(runtime);
        let auth = runtime.auth_state().await.expect("auth");
        let events = runtime.subscribe_events().await;
        let now = current_unix_timestamp();
        let mut session = TangleWebSocketSession::new(
            session_limits(8),
            shutdown.subscribe(),
            runtime.clone(),
            auth,
            events,
        )
        .expect("session");
        let key = TangleRateLimitKey::connection(TangleRateLimitScope::Req, session.connection_id);
        let limiter = runtime.rate_limiter().await;
        for _ in 0..rule.max_hits() {
            limiter.record(key.clone(), rule, now);
        }
        let subscription_id = SubscriptionId::new("limited").expect("subscription");

        assert_eq!(
            session
                .handle_client_message(ClientMessage::Req {
                    subscription_id: subscription_id.clone(),
                    filters: vec![
                        filter_from_value(&json!({"kinds": [1], "limit": 1})).expect("filter")
                    ]
                })
                .await
                .expect("req"),
            vec![RelayMessage::Closed {
                subscription_id,
                message: format!(
                    "rate-limited: req connection rate limit exceeded until {}",
                    now.as_u64() + 60
                )
            }]
        );
        assert_eq!(session.active_subscription_count(), 0);
        let snapshot = runtime.metrics().snapshot();
        assert_eq!(snapshot.client_messages(), 1);
        assert_eq!(snapshot.req_messages(), 1);
        assert_eq!(snapshot.opened_subscriptions(), 0);
        assert_eq!(snapshot.rate_limit_rejections(), 1);

        let _ = std::fs::remove_dir_all(root);
    }

    #[tokio::test]
    async fn websocket_session_closes_when_event_receiver_lags() {
        let shutdown = TangleShutdownSignal::new();
        let root = temp_root("event-receiver-lag");
        let _ = std::fs::remove_dir_all(&root);
        let runtime =
            TangleRuntime::open(runtime_config_with_outbound_queue(&root, 1)).expect("runtime");
        let auth = runtime.auth_state().expect("auth");
        let events = runtime.event_bus().subscribe();
        assert_eq!(runtime.event_bus().publish(StoreOffset::new(1)), 1);
        assert_eq!(runtime.event_bus().publish(StoreOffset::new(2)), 1);
        let runtime = TangleRuntimeHandle::new(runtime);
        let metrics = runtime.metrics();
        let mut session = TangleWebSocketSession::new(
            session_limits(1),
            shutdown.subscribe(),
            runtime,
            auth,
            events,
        )
        .expect("session");
        let event = session.events.recv().await;

        assert_eq!(
            session.handle_event_receive_result(event).await,
            TangleSessionControl::Close(event_stream_lag_close_message())
        );
        assert_eq!(metrics.event_bus_lagged_receivers(), 1);
        assert_eq!(metrics.event_bus_lagged_offsets(), 1);

        let _ = std::fs::remove_dir_all(root);
    }

    #[tokio::test]
    async fn websocket_session_preserves_chorus_live_fanout_backpressure_parity() {
        let shutdown = TangleShutdownSignal::new();
        let live_root = temp_root("chorus-live-fanout-parity");
        let _ = std::fs::remove_dir_all(&live_root);
        let runtime = TangleRuntimeHandle::new(
            TangleRuntime::open(runtime_config_with_outbound_queue(&live_root, 1))
                .expect("runtime"),
        );
        let metrics = runtime.metrics();
        let auth = runtime.auth_state().await.expect("auth");
        let events = runtime.subscribe_events().await;
        let mut session = TangleWebSocketSession::new(
            session_limits(1),
            shutdown.subscribe(),
            runtime,
            auth,
            events,
        )
        .expect("session");
        let subscription_id = SubscriptionId::new("chorus-live").expect("subscription");
        let req_text = json!(["REQ", subscription_id.as_str(), {"kinds":[1]}]).to_string();

        assert_eq!(
            session.dispatch_text(&req_text).await,
            TangleSessionControl::Continue
        );
        assert_eq!(
            take_outbound_text(&mut session),
            RelayMessage::Eose(subscription_id.clone()).encode()
        );
        for index in 0..3 {
            let content = format!("chorus live {index}");
            let event = tangle_v2_event(
                FixtureKey::Member,
                1_714_124_433 + index,
                1,
                Vec::new(),
                &content,
            )
            .expect("event");
            assert_eq!(
                session
                    .dispatch_text(&json!(["EVENT", event_to_value(&event)]).to_string())
                    .await,
                TangleSessionControl::Continue
            );
            assert_eq!(
                take_outbound_text(&mut session),
                RelayMessage::Ok {
                    event_id: event.id().clone(),
                    accepted: true,
                    message: String::new()
                }
                .encode()
            );
            let offset = session.events.recv().await;
            assert_eq!(
                session.handle_event_receive_result(offset).await,
                TangleSessionControl::Continue
            );
            assert_eq!(
                take_outbound_text(&mut session),
                RelayMessage::Event {
                    subscription_id: subscription_id.clone(),
                    event
                }
                .encode()
            );
            assert_eq!(session.active_subscription_count(), 1);
        }
        assert_eq!(metrics.outbound_queue_full_closes(), 0);
        assert_eq!(metrics.event_bus_lagged_receivers(), 0);
        assert_eq!(metrics.event_bus_lagged_offsets(), 0);
        let _ = std::fs::remove_dir_all(live_root);

        let lag_root = temp_root("chorus-live-lag-parity");
        let _ = std::fs::remove_dir_all(&lag_root);
        let runtime =
            TangleRuntime::open(runtime_config_with_outbound_queue(&lag_root, 1)).expect("runtime");
        let auth = runtime.auth_state().expect("auth");
        let events = runtime.event_bus().subscribe();
        assert_eq!(runtime.event_bus().publish(StoreOffset::new(1)), 1);
        assert_eq!(runtime.event_bus().publish(StoreOffset::new(2)), 1);
        let runtime = TangleRuntimeHandle::new(runtime);
        let metrics = runtime.metrics();
        let mut lagged = TangleWebSocketSession::new(
            session_limits(1),
            shutdown.subscribe(),
            runtime,
            auth,
            events,
        )
        .expect("lagged");
        let event = lagged.events.recv().await;
        assert_eq!(
            lagged.handle_event_receive_result(event).await,
            TangleSessionControl::Close(event_stream_lag_close_message())
        );
        assert_eq!(metrics.event_bus_lagged_receivers(), 1);
        assert_eq!(metrics.event_bus_lagged_offsets(), 1);
        let _ = std::fs::remove_dir_all(lag_root);

        let (runtime, auth, events) = session_runtime("chorus-outbound-full-parity");
        let metrics = runtime.metrics();
        let mut blocked = TangleWebSocketSession::new(
            session_limits(1),
            shutdown.subscribe(),
            runtime,
            auth,
            events,
        )
        .expect("blocked");
        blocked
            .outbound()
            .try_send(Message::Text("blocked".into()))
            .expect("fill queue");
        assert_eq!(
            blocked.dispatch_text("{").await,
            TangleSessionControl::Close(outbound_queue_full_close_message())
        );
        assert_eq!(metrics.outbound_queue_full_closes(), 1);
    }

    #[test]
    fn outbound_queue_is_bounded() {
        let shutdown = TangleShutdownSignal::new();
        let (runtime, auth, events) = session_runtime("outbound-queue");
        let session = TangleWebSocketSession::new(
            session_limits(1),
            shutdown.subscribe(),
            runtime,
            auth,
            events,
        )
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

    #[tokio::test]
    async fn websocket_session_closes_when_outbound_queue_is_full() {
        let shutdown = TangleShutdownSignal::new();
        let (runtime, auth, events) = session_runtime("outbound-queue-full-close");
        let metrics = runtime.metrics();
        let mut session = TangleWebSocketSession::new(
            session_limits(1),
            shutdown.subscribe(),
            runtime,
            auth,
            events,
        )
        .expect("session");
        session
            .outbound()
            .try_send(Message::Text("blocked".into()))
            .expect("fill queue");

        assert_eq!(
            session.dispatch_text("{").await,
            TangleSessionControl::Close(outbound_queue_full_close_message())
        );
        assert_eq!(metrics.outbound_queue_full_closes(), 1);
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

    fn take_outbound_text(session: &mut TangleWebSocketSession) -> String {
        let message = session.outbound_receiver.try_recv().expect("message");
        let Message::Text(text) = message else {
            panic!("expected text message")
        };
        text.to_string()
    }

    fn runtime_config(root: &Path) -> BaseRelayRuntimeConfig {
        runtime_config_with_outbound_queue(root, 8)
    }

    fn runtime_config_with_groups(root: &Path) -> BaseRelayRuntimeConfig {
        let raw = json!({
            "server": {
                "listen_addr": "127.0.0.1:0",
                "relay_url": "wss://relay.radroots.test"
            },
            "pocket": {
                "data_directory": root.join("pocket"),
                "sync_policy": "flush_on_shutdown",
                "query": {
                  "allow_scraping": false,
                  "allow_scrape_if_limited_to": 100,
                  "allow_scrape_if_max_seconds": 3600
                }
            },
            "groups": {
                "enabled": true,
                "canonical_relay_url": "wss://relay.radroots.test",
                "relay_secret": "7777777777777777777777777777777777777777777777777777777777777777",
                "owner_pubkeys": [FixtureKey::Owner.public_key().as_str()],
                "policy": {
                    "public_join": false,
                    "invites_enabled": false
                }
            },
            "auth": {
                "challenge_ttl_seconds": 300,
                "created_at_skew_seconds": 600
            },
            "limits": {
                "max_message_length": 1048576,
                "max_subid_length": 64,
                "max_subscriptions_per_connection": 64,
                "max_filters_per_request": 10,
                "max_tag_values_per_filter": 100,
                "max_query_complexity": 2048,
                "max_limit": 500,
                "default_limit": 100,
                "max_event_tags": 200,
                "max_content_length": 65536,
                "broadcast_channel_capacity": 8,
                "per_connection_outbound_queue": 8
            },
            "rate_limits": {
                "auth": {
                    "per_ip": {"window_seconds": 60, "max_hits": 120},
                    "per_pubkey": {"window_seconds": 60, "max_hits": 30},
                    "failures": {"window_seconds": 300, "max_hits": 5},
                    "failures_per_ip": {"window_seconds": 300, "max_hits": 20}
                },
                "event": {
                    "per_ip": {"window_seconds": 60, "max_hits": 600},
                    "per_pubkey": {"window_seconds": 60, "max_hits": 120},
                    "per_kind": {"window_seconds": 60, "max_hits": 1000}
                },
                "group": {
                    "write_per_ip": {"window_seconds": 60, "max_hits": 300},
                    "write_per_pubkey": {"window_seconds": 60, "max_hits": 60},
                    "write_per_group": {"window_seconds": 60, "max_hits": 90},
                    "write_per_kind": {"window_seconds": 60, "max_hits": 300},
                    "join_flow": {"window_seconds": 300, "max_hits": 10},
                    "join_flow_per_ip": {"window_seconds": 300, "max_hits": 30}
                },
                "req": {
                    "per_ip": {"window_seconds": 60, "max_hits": 600},
                    "per_connection": {"window_seconds": 60, "max_hits": 120},
                    "per_pubkey": {"window_seconds": 60, "max_hits": 240},
                    "per_group": {"window_seconds": 60, "max_hits": 240},
                    "per_kind": {"window_seconds": 60, "max_hits": 500},
                    "broad": {"window_seconds": 60, "max_hits": 30}
                },
                "count": {
                    "per_ip": {"window_seconds": 60, "max_hits": 300},
                    "per_connection": {"window_seconds": 60, "max_hits": 60},
                    "per_pubkey": {"window_seconds": 60, "max_hits": 120},
                    "per_group": {"window_seconds": 60, "max_hits": 120},
                    "per_kind": {"window_seconds": 60, "max_hits": 240},
                    "broad": {"window_seconds": 60, "max_hits": 20}
                }
            }
        })
        .to_string();
        parse_base_relay_runtime_config_json(&raw).expect("config")
    }

    fn runtime_config_with_outbound_queue(
        root: &Path,
        per_connection_outbound_queue: usize,
    ) -> BaseRelayRuntimeConfig {
        let raw = json!({
            "server": {
                "listen_addr": "127.0.0.1:0",
                "relay_url": "wss://relay.radroots.test"
            },
            "pocket": {
                "data_directory": root.join("pocket"),
                "sync_policy": "flush_on_shutdown",
                "query": {
                  "allow_scraping": false,
                  "allow_scrape_if_limited_to": 100,
                  "allow_scrape_if_max_seconds": 3600
                }
            },
            "groups": {
                "enabled": false
            },
            "auth": {
                "challenge_ttl_seconds": 300,
                "created_at_skew_seconds": 600
            },
            "limits": {
                "max_message_length": 1048576,
                "max_subid_length": 64,
                "max_subscriptions_per_connection": 64,
                "max_filters_per_request": 10,
                "max_tag_values_per_filter": 100,
                "max_query_complexity": 2048,
                "max_limit": 500,
                "default_limit": 100,
                "max_event_tags": 200,
                "max_content_length": 65536,
                "broadcast_channel_capacity": per_connection_outbound_queue,
                "per_connection_outbound_queue": per_connection_outbound_queue
            },
            "rate_limits": {
                "auth": {
                    "per_ip": {"window_seconds": 60, "max_hits": 120},
                    "per_pubkey": {"window_seconds": 60, "max_hits": 30},
                    "failures": {"window_seconds": 300, "max_hits": 5},
                    "failures_per_ip": {"window_seconds": 300, "max_hits": 20}
                },
                "event": {
                    "per_ip": {"window_seconds": 60, "max_hits": 600},
                    "per_pubkey": {"window_seconds": 60, "max_hits": 120},
                    "per_kind": {"window_seconds": 60, "max_hits": 1000}
                },
                "group": {
                    "write_per_ip": {"window_seconds": 60, "max_hits": 300},
                    "write_per_pubkey": {"window_seconds": 60, "max_hits": 60},
                    "write_per_group": {"window_seconds": 60, "max_hits": 90},
                    "write_per_kind": {"window_seconds": 60, "max_hits": 300},
                    "join_flow": {"window_seconds": 300, "max_hits": 10},
                    "join_flow_per_ip": {"window_seconds": 300, "max_hits": 30}
                },
                "req": {
                    "per_ip": {"window_seconds": 60, "max_hits": 600},
                    "per_connection": {"window_seconds": 60, "max_hits": 120},
                    "per_pubkey": {"window_seconds": 60, "max_hits": 240},
                    "per_group": {"window_seconds": 60, "max_hits": 240},
                    "per_kind": {"window_seconds": 60, "max_hits": 500},
                    "broad": {"window_seconds": 60, "max_hits": 30}
                },
                "count": {
                    "per_ip": {"window_seconds": 60, "max_hits": 300},
                    "per_connection": {"window_seconds": 60, "max_hits": 60},
                    "per_pubkey": {"window_seconds": 60, "max_hits": 120},
                    "per_group": {"window_seconds": 60, "max_hits": 120},
                    "per_kind": {"window_seconds": 60, "max_hits": 240},
                    "broad": {"window_seconds": 60, "max_hits": 20}
                }
            }
        })
        .to_string();
        parse_base_relay_runtime_config_json(&raw).expect("config")
    }

    fn session_limits(per_connection_outbound_queue: usize) -> TangleRuntimeLimits {
        session_limits_result(per_connection_outbound_queue).expect("limits")
    }

    fn session_limits_with_message_length(
        max_message_length: usize,
        per_connection_outbound_queue: usize,
    ) -> TangleRuntimeLimits {
        TangleRuntimeLimits::new(
            max_message_length,
            BaseRelayLimits::new(BaseRelayLimitSettings {
                max_pending_events: per_connection_outbound_queue,
                max_subscription_id_length: 64,
                max_subscriptions: 64,
                max_filters_per_request: 10,
                max_tag_values_per_filter: 100,
                max_query_complexity: 610,
                max_event_tags: 200,
                max_content_length: 65_536,
                max_limit: 500,
                default_limit: 100,
            })
            .expect("relay limits"),
            16,
            per_connection_outbound_queue,
        )
        .expect("limits")
    }

    fn session_limits_result(
        per_connection_outbound_queue: usize,
    ) -> Result<TangleRuntimeLimits, BaseRelayError> {
        TangleRuntimeLimits::new(
            1_048_576,
            BaseRelayLimits::new(BaseRelayLimitSettings {
                max_pending_events: per_connection_outbound_queue,
                max_subscription_id_length: 64,
                max_subscriptions: 64,
                max_filters_per_request: 10,
                max_tag_values_per_filter: 100,
                max_query_complexity: 610,
                max_event_tags: 200,
                max_content_length: 65_536,
                max_limit: 500,
                default_limit: 100,
            })?,
            16,
            per_connection_outbound_queue,
        )
    }

    fn temp_root(name: &str) -> PathBuf {
        std::env::temp_dir().join(format!("tangle-session-{name}-{}", std::process::id()))
    }
}
