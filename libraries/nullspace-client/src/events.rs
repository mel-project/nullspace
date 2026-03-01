use anyctx::AnyCtx;
use async_channel::Sender as AsyncSender;
use parking_lot::Mutex;

use crate::Config;
use crate::config::Ctx;
use crate::database::DATABASE;
use crate::identity::identity_exists;
use crate::internal::Event;

static EVENT_TX: Ctx<Mutex<Option<AsyncSender<Event>>>> = |_ctx| Mutex::new(None);

pub fn init_event_tx(ctx: &AnyCtx<Config>, tx: AsyncSender<Event>) {
    let mut guard = ctx.get(EVENT_TX).lock();
    *guard = Some(tx);
}

pub fn emit_event(ctx: &AnyCtx<Config>, event: Event) {
    let tx = ctx.get(EVENT_TX).lock();
    let Some(tx) = tx.as_ref() else {
        return;
    };
    let _ = tx.send_blocking(event);
}

/// Emits the initial login state event, then parks forever.
///
/// Login state transitions and conversation updates are emitted directly
/// at their mutation sites — no polling needed.
pub async fn event_loop(ctx: &AnyCtx<Config>) {
    let db = ctx.get(DATABASE);
    let logged_in = match db.acquire().await {
        Ok(mut conn) => identity_exists(&mut conn).await.unwrap_or(false),
        Err(_) => false,
    };
    emit_event(ctx, Event::State { logged_in });
    std::future::pending::<()>().await;
}
