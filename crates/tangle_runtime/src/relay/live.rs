#![forbid(unsafe_code)]

use crate::errors::BaseRelayError;
use std::collections::BTreeMap;
use tangle_groups::GroupAuthContext;
use tangle_protocol::{Event, Filter, RelayMessage, SubscriptionId};

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct LiveSubscriptionSet {
    subscriptions: BTreeMap<SubscriptionId, LiveSubscription>,
    max_subscriptions: usize,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct LiveSubscription {
    filters: Vec<Filter>,
    auth: GroupAuthContext,
}

impl LiveSubscriptionSet {
    pub(crate) fn new(
        max_pending_events: usize,
        max_subscriptions: usize,
    ) -> Result<Self, BaseRelayError> {
        if max_pending_events == 0 {
            return Err(BaseRelayError::invalid(
                "live subscription pending event limit must be greater than zero",
            ));
        }
        if max_subscriptions == 0 {
            return Err(BaseRelayError::invalid(
                "live subscription count limit must be greater than zero",
            ));
        }
        Ok(Self {
            subscriptions: BTreeMap::new(),
            max_subscriptions,
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
        if !self.subscriptions.contains_key(&subscription_id)
            && self.subscriptions.len() >= self.max_subscriptions
        {
            return Err(BaseRelayError::invalid(
                "connection subscription limit exceeded",
            ));
        }
        self.subscriptions
            .insert(subscription_id, LiveSubscription { filters, auth });
        Ok(())
    }

    pub(crate) fn close(&mut self, subscription_id: &SubscriptionId) -> CloseResult {
        if self.subscriptions.remove(subscription_id).is_some() {
            CloseResult::Closed
        } else {
            CloseResult::NotFound
        }
    }

    pub(crate) fn close_all(&mut self) -> usize {
        let closed = self.subscriptions.len();
        self.subscriptions.clear();
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
            messages.push(RelayMessage::Event {
                subscription_id,
                event: event.clone(),
            });
        }
        messages
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
    fn live_subscription_fanout_keeps_healthy_subscriptions_open() {
        let mut subscriptions = LiveSubscriptionSet::new(1, 1).expect("subscriptions");
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
        let third = tangle_v2_event(FixtureKey::Member, 1_714_124_435, 1, Vec::new(), "third")
            .expect("third");

        assert!(matches!(
            subscriptions.fanout(&first, |_, _| true).as_slice(),
            [RelayMessage::Event { subscription_id: delivered, event }]
                if delivered == &subscription_id && event.id() == first.id()
        ));
        assert!(matches!(
            subscriptions.fanout(&second, |_, _| true).as_slice(),
            [RelayMessage::Event { subscription_id: delivered, event }]
                if delivered == &subscription_id && event.id() == second.id()
        ));
        assert!(matches!(
            subscriptions.fanout(&third, |_, _| true).as_slice(),
            [RelayMessage::Event { subscription_id: delivered, event }]
                if delivered == &subscription_id && event.id() == third.id()
        ));
        assert_eq!(subscriptions.close(&subscription_id), CloseResult::Closed);
    }
}
