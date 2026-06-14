#![forbid(unsafe_code)]

use crate::errors::BaseRelayError;
use tangle_groups::StoreOffset;
use tokio::sync::broadcast;

#[derive(Debug, Clone)]
pub struct TangleEventBus {
    sender: broadcast::Sender<StoreOffset>,
    capacity: usize,
}

impl TangleEventBus {
    pub fn new(capacity: usize) -> Result<Self, BaseRelayError> {
        if capacity == 0 {
            return Err(BaseRelayError::invalid(
                "runtime event bus capacity must be greater than zero",
            ));
        }
        let (sender, _) = broadcast::channel(capacity);
        Ok(Self { sender, capacity })
    }

    pub fn capacity(&self) -> usize {
        self.capacity
    }

    pub fn subscribe(&self) -> TangleEventReceiver {
        TangleEventReceiver {
            receiver: self.sender.subscribe(),
        }
    }

    pub fn publish(&self, offset: StoreOffset) -> usize {
        self.sender.send(offset).unwrap_or(0)
    }

    pub fn receiver_count(&self) -> usize {
        self.sender.receiver_count()
    }
}

#[derive(Debug)]
pub struct TangleEventReceiver {
    receiver: broadcast::Receiver<StoreOffset>,
}

impl TangleEventReceiver {
    pub async fn recv(&mut self) -> Result<StoreOffset, TangleEventReceiveError> {
        self.receiver.recv().await.map_err(Into::into)
    }

    pub fn try_recv(&mut self) -> Result<StoreOffset, TangleEventReceiveError> {
        self.receiver.try_recv().map_err(Into::into)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TangleEventReceiveError {
    Empty,
    Closed,
    Lagged(u64),
}

impl From<broadcast::error::TryRecvError> for TangleEventReceiveError {
    fn from(error: broadcast::error::TryRecvError) -> Self {
        match error {
            broadcast::error::TryRecvError::Empty => Self::Empty,
            broadcast::error::TryRecvError::Closed => Self::Closed,
            broadcast::error::TryRecvError::Lagged(skipped) => Self::Lagged(skipped),
        }
    }
}

impl From<broadcast::error::RecvError> for TangleEventReceiveError {
    fn from(error: broadcast::error::RecvError) -> Self {
        match error {
            broadcast::error::RecvError::Closed => Self::Closed,
            broadcast::error::RecvError::Lagged(skipped) => Self::Lagged(skipped),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::{TangleEventBus, TangleEventReceiveError};
    use tangle_groups::StoreOffset;

    #[test]
    fn event_bus_broadcasts_offsets_to_subscribers() {
        let bus = TangleEventBus::new(2).expect("bus");
        let mut first = bus.subscribe();
        let mut second = bus.subscribe();

        assert_eq!(bus.capacity(), 2);
        assert_eq!(bus.receiver_count(), 2);
        assert_eq!(bus.publish(StoreOffset::new(42)), 2);
        assert_eq!(first.try_recv().expect("first"), StoreOffset::new(42));
        assert_eq!(second.try_recv().expect("second"), StoreOffset::new(42));
    }

    #[test]
    fn event_bus_reports_lagged_receivers() {
        let bus = TangleEventBus::new(2).expect("bus");
        let mut receiver = bus.subscribe();

        assert_eq!(bus.publish(StoreOffset::new(1)), 1);
        assert_eq!(bus.publish(StoreOffset::new(2)), 1);
        assert_eq!(bus.publish(StoreOffset::new(3)), 1);
        assert_eq!(bus.publish(StoreOffset::new(4)), 1);
        assert_eq!(
            receiver.try_recv().expect_err("lagged"),
            TangleEventReceiveError::Lagged(2)
        );
        assert_eq!(receiver.try_recv().expect("next"), StoreOffset::new(3));
        assert_eq!(receiver.try_recv().expect("latest"), StoreOffset::new(4));
    }

    #[test]
    fn event_bus_accepts_publish_without_receivers() {
        let bus = TangleEventBus::new(2).expect("bus");

        assert_eq!(bus.receiver_count(), 0);
        assert_eq!(bus.publish(StoreOffset::new(7)), 0);
    }
}
