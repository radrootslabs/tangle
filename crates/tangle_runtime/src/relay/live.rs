#![forbid(unsafe_code)]

use crate::errors::BaseRelayError;
use std::collections::BTreeMap;
use tangle_groups::GroupAuthContext;
use tangle_protocol::SubscriptionId;
use tangle_store_pocket::{PocketEvent, PocketOwnedFilter};

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct LiveSubscriptionSet {
    subscriptions: BTreeMap<SubscriptionId, LiveSubscription>,
    max_subscriptions: usize,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct LiveSubscription {
    filters: Vec<PocketOwnedFilter>,
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
        filters: Vec<PocketOwnedFilter>,
    ) -> Result<(), BaseRelayError> {
        self.ensure_can_subscribe(&subscription_id, &filters)?;
        self.subscriptions
            .insert(subscription_id, LiveSubscription { filters });
        Ok(())
    }

    pub(crate) fn ensure_can_subscribe(
        &self,
        subscription_id: &SubscriptionId,
        filters: &[PocketOwnedFilter],
    ) -> Result<(), BaseRelayError> {
        if filters.is_empty() {
            return Err(BaseRelayError::invalid(
                "subscription must include at least one filter",
            ));
        }
        if !self.subscriptions.contains_key(subscription_id)
            && self.subscriptions.len() >= self.max_subscriptions
        {
            return Err(BaseRelayError::invalid(
                "connection subscription limit exceeded",
            ));
        }
        Ok(())
    }

    pub(crate) fn close(&mut self, subscription_id: &SubscriptionId) -> CloseResult {
        if self.subscriptions.remove(subscription_id).is_some() {
            CloseResult::Closed
        } else {
            CloseResult::NotFound
        }
    }

    pub(crate) fn contains(&self, subscription_id: &SubscriptionId) -> bool {
        self.subscriptions.contains_key(subscription_id)
    }

    pub(crate) fn close_all(&mut self) -> usize {
        let closed = self.subscriptions.len();
        self.subscriptions.clear();
        closed
    }

    pub(crate) fn fanout(
        &self,
        event: &PocketEvent,
        auth: &GroupAuthContext,
        visible_to_auth: impl Fn(&PocketEvent, &GroupAuthContext) -> bool,
    ) -> Result<Vec<SubscriptionId>, BaseRelayError> {
        self.subscriptions.iter().try_fold(
            Vec::new(),
            |mut matched, (subscription_id, subscription)| {
                if !subscription
                    .filters
                    .iter()
                    .map(|filter| filter.event_matches(event))
                    .collect::<Result<Vec<_>, _>>()
                    .map_err(|error| BaseRelayError::error(error.to_string()))?
                    .into_iter()
                    .any(|matches| matches)
                {
                    return Ok(matched);
                }
                if visible_to_auth(event, auth) {
                    matched.push(subscription_id.clone());
                }
                Ok(matched)
            },
        )
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
    use tangle_protocol::{SubscriptionId, filter_from_value};
    use tangle_test_support::{FixtureKey, tangle_v2_event};

    #[test]
    fn live_subscription_fanout_keeps_healthy_subscriptions_open() {
        let mut subscriptions = LiveSubscriptionSet::new(1, 1).expect("subscriptions");
        let subscription_id = SubscriptionId::new("live").expect("subscription");
        subscriptions
            .subscribe(
                subscription_id.clone(),
                vec![pocket_filter(serde_json::json!({"kinds":[1]}))],
            )
            .expect("subscribe");
        let first = tangle_v2_event(FixtureKey::Member, 1_714_124_433, 1, Vec::new(), "first")
            .expect("first");
        let second = tangle_v2_event(FixtureKey::Member, 1_714_124_434, 1, Vec::new(), "second")
            .expect("second");
        let third = tangle_v2_event(FixtureKey::Member, 1_714_124_435, 1, Vec::new(), "third")
            .expect("third");

        assert!(matches!(
            subscriptions
                .fanout(&pocket_event(&first), &GroupAuthContext::unauthenticated(), |_, _| true)
                .expect("fanout")
                .as_slice(),
            [delivered] if delivered == &subscription_id
        ));
        assert!(matches!(
            subscriptions
                .fanout(&pocket_event(&second), &GroupAuthContext::unauthenticated(), |_, _| true)
                .expect("fanout")
                .as_slice(),
            [delivered] if delivered == &subscription_id
        ));
        assert!(matches!(
            subscriptions
                .fanout(&pocket_event(&third), &GroupAuthContext::unauthenticated(), |_, _| true)
                .expect("fanout")
                .as_slice(),
            [delivered] if delivered == &subscription_id
        ));
        assert_eq!(subscriptions.close(&subscription_id), CloseResult::Closed);
    }

    #[test]
    fn live_subscription_fanout_uses_pocket_filter_matching_and_auth_gate() {
        let mut subscriptions = LiveSubscriptionSet::new(4, 4).expect("subscriptions");
        let event = tangle_v2_event(
            FixtureKey::Member,
            1_714_124_433,
            1,
            vec![tangle_protocol::Tag::from_parts("t", &["market"]).expect("tag")],
            "first",
        )
        .expect("event");
        let matched = SubscriptionId::new("matched").expect("subscription");
        let mismatched = SubscriptionId::new("mismatched").expect("subscription");
        subscriptions
            .subscribe(
                matched.clone(),
                vec![pocket_filter(serde_json::json!({
                    "ids": [event.id().as_str()],
                    "authors": [event.unsigned().pubkey().as_str()],
                    "kinds": [1],
                    "#t": ["market"],
                    "since": 1_714_124_433,
                    "until": 1_714_124_434
                }))],
            )
            .expect("matched subscribe");
        subscriptions
            .subscribe(
                mismatched,
                vec![pocket_filter(serde_json::json!({"kinds":[2]}))],
            )
            .expect("mismatched subscribe");
        let event = pocket_event(&event);

        assert_eq!(
            subscriptions
                .fanout(&event, &GroupAuthContext::unauthenticated(), |_, _| true)
                .expect("fanout"),
            vec![matched.clone()]
        );
        assert!(
            subscriptions
                .fanout(&event, &GroupAuthContext::unauthenticated(), |_, _| false)
                .expect("auth gated fanout")
                .is_empty()
        );
    }

    fn pocket_filter(value: serde_json::Value) -> tangle_store_pocket::PocketOwnedFilter {
        let filter = filter_from_value(&value).expect("filter");
        crate::pocket_conversion::tangle_filter_to_pocket(&filter).expect("pocket filter")
    }

    fn pocket_event(event: &tangle_protocol::Event) -> tangle_store_pocket::PocketOwnedEvent {
        crate::pocket_conversion::tangle_event_to_pocket(event).expect("pocket event")
    }
}
