use std::ops::{Deref, DerefMut};

use egui_hooks::UseHookExt;
use generational_box::{AnyStorage, GenerationalBox, SyncStorage};

pub struct GBox<T>(GenerationalBox<T, SyncStorage>);

impl<T> Copy for GBox<T> {}
impl<T> Clone for GBox<T> {
    fn clone(&self) -> Self {
        *self
    }
}

impl<T: Send + Sync + 'static> GBox<T> {
    /// Create a GBox with no owner. The backing storage will never be reclaimed
    /// unless you call [`GenerationalBox::manually_drop`] on it.
    #[track_caller]
    pub fn leak(inner: T) -> Self {
        Self(GenerationalBox::leak(
            inner,
            std::panic::Location::caller(),
        ))
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

/// Extension trait that adds [`use_gbox`](UseGBoxExt::use_gbox) to [`egui::Ui`].
pub trait UseGBoxExt {
    /// Create a [`GBox`] whose lifetime is tied to this widget's scope.
    ///
    /// The backing storage is kept alive by a hidden [`Owner`] stored in egui's
    /// per-widget memory. When the widget is removed from the tree (or `deps`
    /// change), the owner is dropped and the slot is recycled.
    ///
    /// Because [`GBox`] is [`Copy`], the returned handle can be captured by
    /// move closures without cloning.
    fn use_gbox<T: Send + Sync + 'static>(
        &mut self,
        init: impl FnOnce() -> T,
        deps: impl PartialEq + Send + Sync + 'static,
    ) -> GBox<T>;
}

impl UseGBoxExt for egui::Ui {
    fn use_gbox<T: Send + Sync + 'static>(
        &mut self,
        init: impl FnOnce() -> T,
        deps: impl PartialEq + Send + Sync + 'static,
    ) -> GBox<T> {
        let pair = self.use_state(
            move || {
                let owner = SyncStorage::owner();
                let gbox = GBox(owner.insert(init()));
                (owner, gbox)
            },
            deps,
        );
        pair.1
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
