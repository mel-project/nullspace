use anyctx::AnyCtx;
use async_channel::Receiver;
use futures_concurrency::future::Race;
use nanorpc::{JrpcRequest, JrpcResponse, RpcService};
use tokio::sync::oneshot;

use crate::Config;
use crate::api::Event;
use crate::api::InternalImpl;
use crate::database::{DATABASE, DbNotify};
use crate::events::{emit_event, init_event_tx};
use crate::identity::{Identity, identity_exists};
use crate::identity::medium_keys::medium_key_loop;
use crate::messaging::{group_worker_loop, message_loop};
use crate::storage::purge_corrupted_group_state;

pub async fn main_loop(
    cfg: Config,
    req_rx: Receiver<(JrpcRequest, oneshot::Sender<JrpcResponse>)>,
) {
    let ctx = AnyCtx::new(cfg);
    let _db = ctx.get(DATABASE);

    let (event_tx, event_rx) = async_channel::unbounded();
    init_event_tx(&ctx, event_tx.clone());
    emit_initial_login_state(&ctx).await;
    let internal = InternalImpl::new(ctx.clone(), event_rx);
    let futs = (rpc_loop(internal, req_rx), worker_loop(&ctx));
    futs.race().await;
}

async fn emit_initial_login_state(ctx: &AnyCtx<Config>) {
    let db = ctx.get(DATABASE);
    let logged_in = match db.acquire().await {
        Ok(mut conn) => identity_exists(&mut conn).await.unwrap_or(false),
        Err(_) => false,
    };
    emit_event(ctx, Event::State { logged_in });
}

async fn rpc_loop(
    internal: InternalImpl,
    req_rx: Receiver<(JrpcRequest, oneshot::Sender<JrpcResponse>)>,
) {
    while let Ok((req, resp_tx)) = req_rx.recv().await {
        let service = crate::api::InternalService(internal.clone());
        tokio::spawn(async move {
            let response = service.respond_raw(req).await;
            let _ = resp_tx.send(response);
        });
    }
}

async fn worker_loop(ctx: &AnyCtx<Config>) {
    let db = ctx.get(DATABASE);
    let mut notify = DbNotify::new();
    loop {
        match db.acquire().await {
            Ok(mut conn) => match identity_exists(&mut conn).await {
                Ok(true) => break,
                Ok(false) => {}
                Err(err) => {
                    tracing::warn!(error = %err, "failed to check identity state");
                }
            },
            Err(err) => {
                tracing::warn!(error = %err, "failed to acquire database connection");
            }
        }
        notify.wait_for_change().await;
    }
    scrub_group_state(ctx).await;
    (message_loop(ctx), group_worker_loop(ctx), medium_key_loop(ctx))
        .race()
        .await;
}

async fn scrub_group_state(ctx: &AnyCtx<Config>) {
    let db = ctx.get(DATABASE);
    let mut conn = match db.acquire().await {
        Ok(conn) => conn,
        Err(err) => {
            tracing::warn!(error = %err, "failed to acquire database connection for group scrub");
            return;
        }
    };
    let identity = match Identity::load(&mut conn).await {
        Ok(identity) => identity,
        Err(err) => {
            tracing::warn!(error = %err, "failed to load identity for group scrub");
            return;
        }
    };
    match purge_corrupted_group_state(&mut conn, identity.username.as_str()).await {
        Ok(true) => DbNotify::touch(),
        Ok(false) => {}
        Err(err) => tracing::warn!(error = %err, "failed to purge corrupted group state"),
    }
}
