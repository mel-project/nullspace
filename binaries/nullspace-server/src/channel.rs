use std::cmp::Reverse;
use std::collections::{BinaryHeap, HashSet};
use std::sync::{Arc, LazyLock};
use std::time::Duration;

use moka::notification::RemovalCause;
use moka::policy::EvictionPolicy;
use moka::sync::Cache;
use nullspace_structs::Blob;
use nullspace_structs::server::{AuthToken, ChanDirection, ServerRpcError};
use parking_lot::Mutex;

use crate::device;

const CHANNEL_TTL: Duration = Duration::from_secs(30);

#[derive(Clone, Default)]
struct ChannelState {
    forward: Option<Blob>,
    backward: Option<Blob>,
}

impl ChannelState {
    fn send(&mut self, direction: ChanDirection, value: Blob) {
        match direction {
            ChanDirection::Forward => self.forward = Some(value),
            ChanDirection::Backward => self.backward = Some(value),
        }
    }

    fn recv(&self, direction: ChanDirection) -> Option<Blob> {
        match direction {
            ChanDirection::Forward => self.forward.clone(),
            ChanDirection::Backward => self.backward.clone(),
        }
    }
}

#[derive(Default)]
struct ChannelAllocator {
    next_fresh: u32,
    recycled_min: BinaryHeap<Reverse<u32>>,
    recycled_set: HashSet<u32>,
}

impl ChannelAllocator {
    fn allocate(&mut self) -> u32 {
        if let Some(id) = self.pop_recycled_min() {
            return id;
        }
        let id = self.next_fresh;
        self.next_fresh = self.next_fresh.saturating_add(1);
        id
    }

    fn free(&mut self, id: u32) {
        if id >= self.next_fresh {
            return;
        }
        if self.recycled_set.insert(id) {
            self.recycled_min.push(Reverse(id));
        }
        self.compact_tail();
    }

    fn pop_recycled_min(&mut self) -> Option<u32> {
        while let Some(Reverse(id)) = self.recycled_min.pop() {
            if self.recycled_set.remove(&id) {
                return Some(id);
            }
        }
        None
    }

    fn compact_tail(&mut self) {
        while self.next_fresh > 0 {
            let tail = self.next_fresh - 1;
            if !self.recycled_set.remove(&tail) {
                break;
            }
            self.next_fresh = tail;
        }
    }
}

static CHANNEL_ALLOCATOR: LazyLock<Mutex<ChannelAllocator>> =
    LazyLock::new(|| Mutex::new(ChannelAllocator::default()));

static CHANNEL_CACHE: LazyLock<Cache<u32, ChannelState>> = LazyLock::new(|| {
    Cache::builder()
        .eviction_policy(EvictionPolicy::lru())
        .time_to_idle(CHANNEL_TTL)
        .eviction_listener(
            |channel_id: Arc<u32>, _value: ChannelState, cause: RemovalCause| {
                if matches!(cause, RemovalCause::Replaced) {
                    return;
                }
                let mut allocator = CHANNEL_ALLOCATOR.lock();
                allocator.free(*channel_id);
            },
        )
        .build()
});

pub async fn chan_allocate(auth: AuthToken) -> Result<u32, ServerRpcError> {
    if !device::auth_token_exists(auth).await? {
        return Err(ServerRpcError::AccessDenied);
    }
    let channel_id = {
        let mut allocator = CHANNEL_ALLOCATOR.lock();
        allocator.allocate()
    };
    CHANNEL_CACHE.insert(channel_id, ChannelState::default());
    Ok(channel_id)
}

pub async fn chan_send(
    channel: u32,
    direction: ChanDirection,
    value: Blob,
) -> Result<(), ServerRpcError> {
    let Some(mut state) = CHANNEL_CACHE.get(&channel) else {
        return Err(ServerRpcError::AccessDenied);
    };
    state.send(direction, value);
    CHANNEL_CACHE.insert(channel, state);
    Ok(())
}

pub async fn chan_recv(
    channel: u32,
    direction: ChanDirection,
) -> Result<Option<Blob>, ServerRpcError> {
    Ok(CHANNEL_CACHE
        .get(&channel)
        .and_then(|state| state.recv(direction)))
}
