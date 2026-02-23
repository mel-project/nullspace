use std::{
    collections::{hash_map::Entry, HashMap},
    ops::{Deref, DerefMut},
    sync::{Arc, Mutex},
};

use egui_hooks::UseHookExt;
use egui_hooks::hook::Hook;
use generational_box::{AnyStorage, GenerationalBox, Owner, SyncStorage};

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

const WIDGET_OWNER_TABLE_ID: &str = "nullspace_egui::utils::generational::widget_owner_table";

#[derive(Clone, Default)]
struct WidgetOwnerTable(Arc<Mutex<HashMap<egui::Id, WidgetOwnerEntry>>>);

struct WidgetOwnerEntry {
    owner: Owner<SyncStorage>,
    last_seen_pass: u64,
}

fn prune_stale_widget_owners(
    owners: &mut HashMap<egui::Id, WidgetOwnerEntry>,
    current_pass: u64,
) {
    // Match egui_hooks two-frame cleanup behavior:
    // keep owners seen this pass or previous pass, prune older.
    owners.retain(|_, owner| owner.last_seen_pass.saturating_add(1) >= current_pass);
}

fn widget_owner_table(ui: &egui::Ui) -> WidgetOwnerTable {
    ui.data_mut(|data| {
        data.get_temp_mut_or_insert_with(
            egui::Id::new(WIDGET_OWNER_TABLE_ID),
            WidgetOwnerTable::default,
        )
        .clone()
    })
}

fn touch_widget_owner(ui: &egui::Ui, create_if_missing: bool) -> Option<Owner<SyncStorage>> {
    let current_pass = ui.ctx().cumulative_pass_nr();
    let owner_table = widget_owner_table(ui);
    let mut owners = owner_table.0.lock().unwrap();
    prune_stale_widget_owners(&mut owners, current_pass);

    match owners.entry(ui.id()) {
        Entry::Occupied(mut entry) => {
            entry.get_mut().last_seen_pass = current_pass;
            Some(entry.get().owner.clone())
        }
        Entry::Vacant(entry) => {
            if !create_if_missing {
                return None;
            }
            let owner = SyncStorage::owner();
            entry.insert(WidgetOwnerEntry {
                owner: owner.clone(),
                last_seen_pass: current_pass,
            });
            Some(owner)
        }
    }
}

struct GBoxHook<F> {
    init: Option<F>,
}

impl<F> GBoxHook<F> {
    fn new(init: F) -> Self {
        Self { init: Some(init) }
    }
}

impl<T, F, D> Hook<D> for GBoxHook<F>
where
    T: Send + Sync + 'static,
    F: FnOnce() -> T,
{
    type Backend = GBox<T>;
    type Output = GBox<T>;

    fn init(
        &mut self,
        _index: usize,
        _deps: &D,
        _backend: Option<Self::Backend>,
        ui: &mut egui::Ui,
    ) -> Self::Backend {
        let owner = touch_widget_owner(ui, true).expect("owner must exist");
        let init = self.init.take().expect("GBoxHook init called twice");
        GBox(owner.insert(init()))
    }

    fn hook(self, backend: &mut Self::Backend, ui: &mut egui::Ui) -> Self::Output {
        let _ = touch_widget_owner(ui, false);
        *backend
    }
}

/// Extension trait that adds [`use_gbox`](UseGBoxExt::use_gbox) to [`egui::Ui`].
pub trait UseGBoxExt {
    /// Create a [`GBox`] whose lifetime is tied to this widget's scope.
    ///
    /// The backing storage is kept alive by a hidden per-widget [`Owner`]. All
    /// `use_gbox` calls inside the same widget share that owner, so old inserts
    /// can accumulate until the widget is removed from the tree.
    ///
    /// `deps` only controls when this specific hook instance re-initializes. A
    /// dependency change creates a new [`GBox`], and older values stay alive
    /// until widget teardown.
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
        self.use_hook(GBoxHook::new(init), deps)
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
