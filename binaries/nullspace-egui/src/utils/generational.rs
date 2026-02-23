use std::ops::{Deref, DerefMut};

use generational_box::{GenerationalBox, SyncStorage};

pub struct GBox<T>(GenerationalBox<T, SyncStorage>);

impl<T> Copy for GBox<T> {}
impl<T> Clone for GBox<T> {
    fn clone(&self) -> Self {
        *self
    }
}

impl<T: Send + Sync + Clone + 'static> GBox<T> {
    /// Gets a cloned copy of the content of the GBox.
    pub fn get(&self) -> T {
        self.read().clone()
    }
}

impl<T: Send + Sync + 'static> GBox<T> {
    /// Create a GBox with no owner. The backing storage will never be reclaimed
    /// unless you call [`GenerationalBox::manually_drop`] on it.
    #[track_caller]
    #[allow(dead_code)]
    pub fn leak(inner: T) -> Self {
        Self(GenerationalBox::leak(inner, std::panic::Location::caller()))
    }
}

impl<T> GBox<T> {
    pub(crate) fn from_inner(inner: GenerationalBox<T, SyncStorage>) -> Self {
        Self(inner)
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
