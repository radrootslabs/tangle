#![forbid(unsafe_code)]

use crate::{errors::BaseRelayError, relay::filter::BaseRelayMatchedFilterContext};
use std::collections::BTreeMap;
use tangle_groups::GroupAuthContext;
use tangle_protocol::SubscriptionId;
use tangle_store_pocket::{PocketEvent, PocketFilter, PocketOwnedFilter};

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct LiveSubscriptionSet {
    subscriptions: BTreeMap<SubscriptionId, LiveSubscription>,
    max_subscriptions: usize,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct LiveSubscription {
    filters: Vec<PocketOwnedFilter>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct LiveSubscriptionMatch {
    subscription_id: SubscriptionId,
    matched_filters: Vec<(usize, PocketOwnedFilter)>,
}

impl LiveSubscriptionMatch {
    fn new(
        subscription_id: SubscriptionId,
        matched_filters: Vec<(usize, PocketOwnedFilter)>,
    ) -> Self {
        Self {
            subscription_id,
            matched_filters,
        }
    }

    pub(crate) fn subscription_id(&self) -> &SubscriptionId {
        &self.subscription_id
    }

    pub(crate) fn into_subscription_id(self) -> SubscriptionId {
        self.subscription_id
    }

    #[cfg(test)]
    pub(crate) fn matched_filter_context(&self) -> BaseRelayMatchedFilterContext {
        let (filter_index, filter) = &self.matched_filters[0];
        BaseRelayMatchedFilterContext::from_filter(*filter_index, filter)
    }

    pub(crate) fn matched_filter_contexts(&self) -> Vec<BaseRelayMatchedFilterContext> {
        self.matched_filters
            .iter()
            .map(|(filter_index, filter)| {
                BaseRelayMatchedFilterContext::from_filter(*filter_index, filter)
            })
            .collect()
    }

    pub(crate) fn filters(&self) -> impl Iterator<Item = &PocketFilter> {
        self.matched_filters
            .iter()
            .map(|(_, filter)| -> &PocketFilter { filter })
    }
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
    ) -> Result<Vec<LiveSubscriptionMatch>, BaseRelayError> {
        self.subscriptions.iter().try_fold(
            Vec::new(),
            |mut matched, (subscription_id, subscription)| {
                let mut matched_filters = Vec::new();
                for (filter_index, filter) in subscription.filters.iter().enumerate() {
                    if filter
                        .event_matches(event)
                        .map_err(|error| BaseRelayError::error(error.to_string()))?
                    {
                        matched_filters.push((filter_index, filter.clone()));
                    }
                }
                if matched_filters.is_empty() {
                    return Ok(matched);
                }
                if visible_to_auth(event, auth) {
                    matched.push(LiveSubscriptionMatch::new(
                        subscription_id.clone(),
                        matched_filters,
                    ));
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

        assert_live_match(
            subscriptions
                .fanout(
                    &pocket_event(&first),
                    &GroupAuthContext::unauthenticated(),
                    |_, _| true,
                )
                .expect("fanout")
                .as_slice(),
            &subscription_id,
            0,
        );
        assert_live_match(
            subscriptions
                .fanout(
                    &pocket_event(&second),
                    &GroupAuthContext::unauthenticated(),
                    |_, _| true,
                )
                .expect("fanout")
                .as_slice(),
            &subscription_id,
            0,
        );
        assert_live_match(
            subscriptions
                .fanout(
                    &pocket_event(&third),
                    &GroupAuthContext::unauthenticated(),
                    |_, _| true,
                )
                .expect("fanout")
                .as_slice(),
            &subscription_id,
            0,
        );
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

        let output = subscriptions
            .fanout(&event, &GroupAuthContext::unauthenticated(), |_, _| true)
            .expect("fanout");
        assert_live_match(output.as_slice(), &matched, 0);
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

    fn assert_live_match(
        matches: &[super::LiveSubscriptionMatch],
        subscription_id: &SubscriptionId,
        filter_index: usize,
    ) {
        assert!(matches!(
            matches,
            [delivered] if delivered.subscription_id() == subscription_id
                && delivered.matched_filter_context().filter_index() == filter_index
        ));
    }

    fn pocket_event(event: &tangle_protocol::Event) -> tangle_store_pocket::PocketOwnedEvent {
        crate::pocket_conversion::tangle_event_to_pocket(event).expect("pocket event")
    }
}
