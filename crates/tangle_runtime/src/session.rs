#![forbid(unsafe_code)]

use crate::errors::BaseRelayError;
use axum::extract::ws::{Message, WebSocket};
use std::time::Instant;
use tokio::sync::{mpsc, watch};

#[derive(Debug)]
pub struct TangleWebSocketSession {
    connected_at: Instant,
    outbound: TangleOutboundSender,
    outbound_receiver: mpsc::Receiver<Message>,
    shutdown: watch::Receiver<bool>,
}

impl TangleWebSocketSession {
    pub fn new(
        outbound_queue_capacity: usize,
        shutdown: watch::Receiver<bool>,
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
        })
    }

    pub fn connected_at(&self) -> Instant {
        self.connected_at
    }

    pub fn outbound(&self) -> TangleOutboundSender {
        self.outbound.clone()
    }

    pub async fn run(mut self, mut socket: WebSocket) {
        loop {
            if *self.shutdown.borrow() {
                break;
            }
            tokio::select! {
                incoming = socket.recv() => {
                    match incoming {
                        Some(Ok(Message::Close(_))) | Some(Err(_)) | None => break,
                        Some(Ok(_)) => {}
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
                    if changed.is_err() || *self.shutdown.borrow() {
                        break;
                    }
                }
            }
        }
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

#[cfg(test)]
mod tests {
    use super::{TangleOutboundQueueError, TangleWebSocketSession};
    use crate::runtime::TangleShutdownSignal;
    use axum::extract::ws::Message;

    #[test]
    fn websocket_session_records_connection_time() {
        let before = std::time::Instant::now();
        let shutdown = TangleShutdownSignal::new();
        let session = TangleWebSocketSession::new(8, shutdown.subscribe()).expect("session");

        assert!(session.connected_at() >= before);
    }

    #[test]
    fn websocket_session_rejects_zero_outbound_capacity() {
        let shutdown = TangleShutdownSignal::new();
        assert!(TangleWebSocketSession::new(0, shutdown.subscribe()).is_err());
    }

    #[test]
    fn outbound_queue_is_bounded() {
        let shutdown = TangleShutdownSignal::new();
        let session = TangleWebSocketSession::new(1, shutdown.subscribe()).expect("session");
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
}
