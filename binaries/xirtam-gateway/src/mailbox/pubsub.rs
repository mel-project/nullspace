use std::{
    sync::{
        Arc,
        atomic::{AtomicU64, Ordering},
    },
    time::Duration,
};

use async_event::Event;
use moka::sync::{Cache, CacheBuilder};
use xirtam_structs::gateway::MailboxId;

pub struct PubSub {
    inner: Cache<MailboxId, Arc<(AtomicU64, Event)>>,
}

impl PubSub {
    pub fn new() -> Self {
        Self {
            inner: CacheBuilder::default()
                .time_to_idle(Duration::from_secs(3600))
                .build(),
        }
    }

    pub fn counter(&self, mailbox: MailboxId) -> u64 {
        self.inner
            .get_with(mailbox, Default::default)
            .0
            .load(Ordering::SeqCst)
    }

    pub fn incr(&self, mailbox: MailboxId) {
        let val = self.inner.get_with(mailbox, Default::default);
        val.0.fetch_add(1, Ordering::SeqCst);
        val.1.notify_all();
    }

    pub async fn wait_gt(&self, mailbox: MailboxId, counter: u64) {
        let val = self.inner.get_with(mailbox, Default::default);
        val.1
            .wait_until(|| {
                if val.0.load(Ordering::SeqCst) > counter {
                    Some(())
                } else {
                    None
                }
            })
            .await
    }
}
