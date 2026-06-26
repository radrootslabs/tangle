#![forbid(unsafe_code)]

use std::collections::BTreeSet;
use tangle_store_pocket::PocketFilter;

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct BaseRelayMatchedFilterContext {
    filter_index: usize,
    requested_kinds: BaseRelayRequestedKinds,
}

impl BaseRelayMatchedFilterContext {
    pub(crate) fn from_filter(filter_index: usize, filter: &PocketFilter) -> Self {
        Self {
            filter_index,
            requested_kinds: BaseRelayRequestedKinds::from_filter(filter),
        }
    }

    pub(crate) fn filter_index(&self) -> usize {
        self.filter_index
    }

    pub(crate) fn requested_kinds(&self) -> &BaseRelayRequestedKinds {
        &self.requested_kinds
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum BaseRelayRequestedKinds {
    Absent,
    Explicit(BTreeSet<u32>),
}

impl BaseRelayRequestedKinds {
    fn from_filter(filter: &PocketFilter) -> Self {
        if filter.num_kinds() == 0 {
            Self::Absent
        } else {
            Self::Explicit(
                filter
                    .kinds()
                    .map(|kind| u32::from(kind.as_u16()))
                    .collect(),
            )
        }
    }
}
