use std::{
    collections::{HashMap, hash_map::Entry},
    future::Future,
    pin::Pin,
    sync::{Arc, Mutex},
    task::{Context, Poll},
};

use egui_hooks::UseHookExt;
use egui_hooks::hook::Hook;
use futures_util::task::noop_waker_ref;
use generational_box::{AnyStorage, Owner, SyncStorage};

use crate::utils::generational::GBox;

const WIDGET_OWNER_TABLE_ID: &str = "nullspace_egui::utils::hooks::widget_owner_table";

#[derive(Clone, Default)]
struct WidgetOwnerTable(Arc<Mutex<HashMap<egui::Id, WidgetOwnerEntry>>>);

struct WidgetOwnerEntry {
    owner: Owner<SyncStorage>,
    last_seen_pass: u64,
}

fn prune_stale_widget_owners(owners: &mut HashMap<egui::Id, WidgetOwnerEntry>, current_pass: u64) {
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
        GBox::from_inner(owner.insert(init()))
    }

    fn hook(self, backend: &mut Self::Backend, ui: &mut egui::Ui) -> Self::Output {
        let _ = touch_widget_owner(ui, false);
        *backend
    }
}

pub trait CustomHooksExt {
    /// Create a [`GBox`] whose lifetime is tied to this widget's scope.
    ///
    /// The backing storage is kept alive by a hidden per-widget [`Owner`]. All
    /// `use_gbox` calls inside the same widget share that owner, so old inserts
    /// can accumulate until the widget is removed from the tree.
    ///
    /// Because [`GBox`] is [`Copy`], the returned handle can be captured by
    /// move closures without cloning.
    fn use_gbox<T: Send + Sync + 'static>(
        &mut self,
        init: impl FnOnce() -> T,
        deps: impl PartialEq + Send + Sync + 'static,
    ) -> GBox<T>;

    /// Poll a future once per frame until completion.
    ///
    /// While the future is pending, this hook requests repaint every frame.
    ///
    /// Because the hook returns the "same" value over and over after the future completes, it returns Arc<T> to avoid cloning.
    fn use_async<T: Send + Sync + 'static>(
        &mut self,
        future: impl Future<Output = T> + Send + 'static,
        deps: impl PartialEq + Send + Sync + 'static,
    ) -> Option<Arc<T>>;
}

impl CustomHooksExt for egui::Ui {
    fn use_gbox<T: Send + Sync + 'static>(
        &mut self,
        init: impl FnOnce() -> T,
        deps: impl PartialEq + Send + Sync + 'static,
    ) -> GBox<T> {
        self.use_hook(GBoxHook::new(init), deps)
    }
    fn use_async<T: Send + Sync + 'static>(
        &mut self,
        future: impl Future<Output = T> + Send + 'static,
        deps: impl PartialEq + Send + Sync + 'static,
    ) -> Option<Arc<T>> {
        self.use_hook(AsyncHook::new(future), deps)
    }
}

struct AsyncBackend<T> {
    state: Mutex<AsyncState<T>>,
}

impl<T> AsyncBackend<T> {
    fn new(future: Pin<Box<dyn Future<Output = T> + Send + 'static>>) -> Self {
        Self {
            state: Mutex::new(AsyncState {
                future: Some(future),
                output: None,
            }),
        }
    }
}

struct AsyncState<T> {
    future: Option<Pin<Box<dyn Future<Output = T> + Send + 'static>>>,
    output: Option<Arc<T>>,
}

struct AsyncHook<F> {
    future: Option<F>,
}

impl<F> AsyncHook<F> {
    fn new(future: F) -> Self {
        Self {
            future: Some(future),
        }
    }
}

impl<T, F, D> Hook<D> for AsyncHook<F>
where
    T: Send + Sync + 'static,
    F: Future<Output = T> + Send + 'static,
{
    type Backend = AsyncBackend<T>;
    type Output = Option<Arc<T>>;

    fn init(
        &mut self,
        _index: usize,
        _deps: &D,
        _backend: Option<Self::Backend>,
        _ui: &mut egui::Ui,
    ) -> Self::Backend {
        let future = self.future.take().expect("AsyncHook init called twice");
        AsyncBackend::new(Box::pin(future))
    }

    fn hook(self, backend: &mut Self::Backend, ui: &mut egui::Ui) -> Self::Output {
        let mut state = backend.state.lock().unwrap();
        if let Some(output) = state.output.as_ref() {
            return Some(output.clone());
        }

        let future = state.future.as_mut()?;

        let mut cx = Context::from_waker(noop_waker_ref());
        let poll_result = future.as_mut().poll(&mut cx);
        match poll_result {
            Poll::Ready(output) => {
                state.output = Some(Arc::new(output));
                state.future = None;
                state.output.as_ref().cloned()
            }
            Poll::Pending => {
                ui.ctx().request_repaint();
                None
            }
        }
    }
}
