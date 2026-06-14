#![forbid(unsafe_code)]

use crate::errors::BaseRelayError;
use std::collections::BTreeMap;
use tangle_groups::GroupAuthContext;
use tangle_protocol::{Event, Filter, RelayMessage, SubscriptionId};

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct LiveSubscriptionSet {
    subscriptions: BTreeMap<SubscriptionId, LiveSubscription>,
    pending: BTreeMap<SubscriptionId, usize>,
    max_pending_events: usize,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct LiveSubscription {
    filters: Vec<Filter>,
    auth: GroupAuthContext,
}

impl LiveSubscriptionSet {
    pub(crate) fn new(max_pending_events: usize) -> Result<Self, BaseRelayError> {
        if max_pending_events == 0 {
            return Err(BaseRelayError::invalid(
                "live subscription pending event limit must be greater than zero",
            ));
        }
        Ok(Self {
            subscriptions: BTreeMap::new(),
            pending: BTreeMap::new(),
            max_pending_events,
        })
    }

    pub(crate) fn subscribe(
        &mut self,
        subscription_id: SubscriptionId,
        filters: Vec<Filter>,
        auth: GroupAuthContext,
    ) -> Result<(), BaseRelayError> {
        if filters.is_empty() {
            return Err(BaseRelayError::invalid(
                "subscription must include at least one filter",
            ));
        }
        self.subscriptions
            .insert(subscription_id.clone(), LiveSubscription { filters, auth });
        self.pending.insert(subscription_id, 0);
        Ok(())
    }

    pub(crate) fn close(&mut self, subscription_id: &SubscriptionId) -> CloseResult {
        self.pending.remove(subscription_id);
        if self.subscriptions.remove(subscription_id).is_some() {
            CloseResult::Closed
        } else {
            CloseResult::NotFound
        }
    }

    pub(crate) fn close_all(&mut self) -> usize {
        let closed = self.subscriptions.len();
        self.subscriptions.clear();
        self.pending.clear();
        closed
    }

    pub(crate) fn fanout(
        &mut self,
        event: &Event,
        visible_to_auth: impl Fn(&Event, &GroupAuthContext) -> bool,
    ) -> Vec<RelayMessage> {
        let matched = self
            .subscriptions
            .iter()
            .filter_map(|(subscription_id, subscription)| {
                if !subscription
                    .filters
                    .iter()
                    .any(|filter| filter.matches(event))
                {
                    return None;
                }
                if visible_to_auth(event, &subscription.auth) {
                    Some(subscription_id.clone())
                } else {
                    None
                }
            })
            .collect::<Vec<_>>();
        let mut messages = Vec::new();
        for subscription_id in matched {
            let pending = self.pending.entry(subscription_id.clone()).or_insert(0);
            *pending += 1;
            if *pending > self.max_pending_events {
                self.close(&subscription_id);
                messages.push(RelayMessage::Closed {
                    subscription_id,
                    message: "error: subscription lagged; resync required".to_owned(),
                });
            } else {
                messages.push(RelayMessage::Event {
                    subscription_id,
                    event: event.clone(),
                });
            }
        }
        messages
    }

    pub(crate) fn mark_delivered(&mut self, subscription_id: &SubscriptionId) {
        if let Some(pending) = self.pending.get_mut(subscription_id) {
            *pending = 0;
        }
    }

    pub(crate) fn active_count(&self) -> usize {
        self.subscriptions.len()
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CloseResult {
    Closed,
    NotFound,
}

#[cfg(test)]
mod tests {
    use super::{CloseResult, LiveSubscriptionSet};
    use tangle_groups::GroupAuthContext;
    use tangle_protocol::{RelayMessage, SubscriptionId, filter_from_value};
    use tangle_test_support::{FixtureKey, tangle_v2_event};

    #[test]
    fn live_subscription_fanout_closes_lagged_subscriptions() {
        let mut subscriptions = LiveSubscriptionSet::new(1).expect("subscriptions");
        let subscription_id = SubscriptionId::new("live").expect("subscription");
        subscriptions
            .subscribe(
                subscription_id.clone(),
                vec![filter_from_value(&serde_json::json!({"kinds":[1]})).expect("filter")],
                GroupAuthContext::unauthenticated(),
            )
            .expect("subscribe");
        let first = tangle_v2_event(FixtureKey::Member, 1_714_124_433, 1, Vec::new(), "first")
            .expect("first");
        let second = tangle_v2_event(FixtureKey::Member, 1_714_124_434, 1, Vec::new(), "second")
            .expect("second");

        assert!(matches!(
            subscriptions.fanout(&first, |_, _| true).as_slice(),
            [RelayMessage::Event { subscription_id: delivered, event }]
                if delivered == &subscription_id && event.id() == first.id()
        ));
        assert_eq!(
            subscriptions.fanout(&second, |_, _| true),
            vec![RelayMessage::Closed {
                subscription_id: subscription_id.clone(),
                message: "error: subscription lagged; resync required".to_owned()
            }]
        );
        assert_eq!(subscriptions.close(&subscription_id), CloseResult::NotFound);
    }
}
