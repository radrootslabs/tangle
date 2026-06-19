#![forbid(unsafe_code)]

use crate::errors::BaseRelayError;
use std::sync::{
    Arc,
    atomic::{AtomicUsize, Ordering},
};

#[derive(Debug, Clone)]
pub struct RelayResourceLimiter {
    inner: Arc<RelayResourceLimiterInner>,
}

#[derive(Debug)]
struct RelayResourceLimiterInner {
    max_connections: usize,
    max_subscriptions: usize,
    active_connections: AtomicUsize,
    active_subscriptions: AtomicUsize,
}

impl RelayResourceLimiter {
    pub fn new(max_connections: usize, max_subscriptions: usize) -> Self {
        Self {
            inner: Arc::new(RelayResourceLimiterInner {
                max_connections,
                max_subscriptions,
                active_connections: AtomicUsize::new(0),
                active_subscriptions: AtomicUsize::new(0),
            }),
        }
    }

    pub fn try_open_connection(&self) -> Result<RelayConnectionPermit, BaseRelayError> {
        increment_with_limit(
            &self.inner.active_connections,
            1,
            self.inner.max_connections,
            "host total connection limit exceeded",
        )?;
        Ok(RelayConnectionPermit {
            resources: self.inner.clone(),
            released: false,
        })
    }

    pub fn try_open_subscriptions(
        &self,
        count: usize,
    ) -> Result<RelaySubscriptionPermit, BaseRelayError> {
        if count == 0 {
            return Err(BaseRelayError::invalid(
                "subscription reservation count must be greater than zero",
            ));
        }
        increment_with_limit(
            &self.inner.active_subscriptions,
            count,
            self.inner.max_subscriptions,
            "host total subscription limit exceeded",
        )?;
        Ok(RelaySubscriptionPermit {
            resources: self.inner.clone(),
            count,
            released: false,
        })
    }

    pub fn active_connections(&self) -> usize {
        self.inner.active_connections.load(Ordering::Relaxed)
    }

    pub fn active_subscriptions(&self) -> usize {
        self.inner.active_subscriptions.load(Ordering::Relaxed)
    }

    pub fn max_connections(&self) -> usize {
        self.inner.max_connections
    }

    pub fn max_subscriptions(&self) -> usize {
        self.inner.max_subscriptions
    }
}

#[derive(Debug)]
pub struct RelayConnectionPermit {
    resources: Arc<RelayResourceLimiterInner>,
    released: bool,
}

impl RelayConnectionPermit {
    pub fn release(mut self) {
        self.release_inner();
    }

    fn release_inner(&mut self) {
        if !self.released {
            self.resources
                .active_connections
                .fetch_sub(1, Ordering::Relaxed);
            self.released = true;
        }
    }
}

impl Drop for RelayConnectionPermit {
    fn drop(&mut self) {
        self.release_inner();
    }
}

#[derive(Debug)]
pub struct RelaySubscriptionPermit {
    resources: Arc<RelayResourceLimiterInner>,
    count: usize,
    released: bool,
}

impl RelaySubscriptionPermit {
    pub fn release(mut self) {
        self.release_inner();
    }

    fn release_inner(&mut self) {
        if !self.released {
            self.resources
                .active_subscriptions
                .fetch_sub(self.count, Ordering::Relaxed);
            self.released = true;
        }
    }
}

impl Drop for RelaySubscriptionPermit {
    fn drop(&mut self) {
        self.release_inner();
    }
}

fn increment_with_limit(
    counter: &AtomicUsize,
    amount: usize,
    limit: usize,
    message: &'static str,
) -> Result<(), BaseRelayError> {
    let mut current = counter.load(Ordering::Relaxed);
    loop {
        let Some(next) = current.checked_add(amount) else {
            return Err(BaseRelayError::restricted(message));
        };
        if next > limit {
            return Err(BaseRelayError::restricted(message));
        }
        match counter.compare_exchange(current, next, Ordering::Relaxed, Ordering::Relaxed) {
            Ok(_) => return Ok(()),
            Err(actual) => current = actual,
        }
    }
}
