use std::cmp::Reverse;
use std::collections::{BinaryHeap, HashSet};
use std::sync::{Arc, LazyLock};
use std::time::Duration;

use moka::notification::RemovalCause;
use moka::sync::Cache;
use nullspace_structs::Blob;
use nullspace_structs::server::{AuthToken, ServerRpcError};
use parking_lot::Mutex;

use crate::device;

const MULTICAST_TTL: Duration = Duration::from_secs(30);

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

static MULTICAST_CACHE: LazyLock<Cache<u32, Option<Blob>>> = LazyLock::new(|| {
    Cache::builder()
        .time_to_live(MULTICAST_TTL)
        .eviction_listener(
            |channel_id: Arc<u32>, _value: Option<Blob>, cause: RemovalCause| {
                if matches!(cause, RemovalCause::Replaced) {
                    return;
                }
                let mut allocator = CHANNEL_ALLOCATOR.lock();
                allocator.free(*channel_id);
            },
        )
        .build()
});

pub async fn multicast_allocate(auth: AuthToken) -> Result<u32, ServerRpcError> {
    if !device::auth_token_exists(auth).await? {
        return Err(ServerRpcError::AccessDenied);
    }
    let channel_id = {
        let mut allocator = CHANNEL_ALLOCATOR.lock();
        allocator.allocate()
    };
    MULTICAST_CACHE.insert(channel_id, None);
    Ok(channel_id)
}

pub async fn multicast_post(channel: u32, value: Blob) -> Result<(), ServerRpcError> {
    if !MULTICAST_CACHE.contains_key(&channel) {
        return Err(ServerRpcError::AccessDenied);
    }
    MULTICAST_CACHE.insert(channel, Some(value));
    Ok(())
}

pub async fn multicast_poll(channel: u32) -> Result<Option<Blob>, ServerRpcError> {
    Ok(MULTICAST_CACHE.get(&channel).flatten())
}
