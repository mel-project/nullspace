use std::{
    ops::{Deref, DerefMut},
    sync::{LazyLock, atomic::AtomicUsize},
    thread::JoinHandle,
};

use generational_box::{GenerationalBox, Owner, SyncStorage};
use parking_lot::Mutex;

static GUARDS: AtomicUsize = AtomicUsize::new(0);
static GLOBAL_OWNER: LazyLock<Mutex<Owner<SyncStorage>>> = LazyLock::new(Default::default);

pub struct GBox<T>(GenerationalBox<T, SyncStorage>);

impl<T: Send + Sync + 'static> GBox<T> {
    pub fn new(inner: T) -> Self {
        Self(GLOBAL_OWNER.lock().insert(inner))
    }
}

/// Spawns a "guarded" thread that keeps the current generation of GBoxes alive
pub fn g_spawn<T: Send + 'static>(f: impl FnOnce() -> T + Send + 'static) -> JoinHandle<T> {
    GUARDS.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
    let wrapped = move || {
        scopeguard::defer!({
            GUARDS.fetch_sub(1, std::sync::atomic::Ordering::SeqCst);
        });
        f()
    };
    std::thread::spawn(wrapped)
}

/// Spawns a "guarded" async task that keeps the current generation of GBoxes alive
pub fn g_spawn_async<T: Send + 'static>(
    f: impl Future<Output = T> + Send + 'static,
) -> smol::Task<T> {
    GUARDS.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
    let wrapped = async move {
        scopeguard::defer!({
            GUARDS.fetch_sub(1, std::sync::atomic::Ordering::SeqCst);
        });
        f.await
    };
    smol::spawn(wrapped)
}

/// Advances the generation if possible, dropping every box in the previous generation.
pub fn advance_generation() {
    if GUARDS.load(std::sync::atomic::Ordering::SeqCst) == 0 {
        *GLOBAL_OWNER.lock() = Default::default();
    }
}

impl<T> Deref for GBox<T> {
    type Target = GenerationalBox<T, SyncStorage>;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl<T> DerefMut for GBox<T> {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.0
    }
}

#[cfg(test)]
mod tests {
    use generational_box::{AnyStorage, SyncStorage};
    use std::time::Duration;

    #[test]
    fn test() {
        {
            let storage = SyncStorage::owner();
            let b = storage.insert("hello");
            std::thread::spawn(move || {
                std::thread::sleep(Duration::from_secs(1));
                dbg!(b.try_read());
            });
        }

        std::thread::sleep(Duration::from_secs(2));
    }
}
