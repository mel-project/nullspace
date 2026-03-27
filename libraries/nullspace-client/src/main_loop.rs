use std::sync::mpsc::Receiver;

use anyctx::AnyCtx;
use futures_concurrency::future::Race;
use nanorpc::{JrpcRequest, JrpcResponse, RpcService};
use tokio::sync::oneshot;

use crate::Config;
use crate::database::{DATABASE, DbNotify};
use crate::events::{event_loop, init_event_tx};
use crate::identity::identity_exists;

use crate::convo::convo_loop;

use crate::identity::medium_keys::medium_key_loop;
use crate::internal::InternalImpl;

pub async fn main_loop(
    cfg: Config,
    recv_rpc: Receiver<(JrpcRequest, oneshot::Sender<JrpcResponse>)>,
) {
    let ctx = AnyCtx::new(cfg);
    let _db = ctx.get(DATABASE);

    let (req_tx, req_rx) = tokio::sync::mpsc::unbounded_channel();
    std::thread::spawn(move || {
        for msg in recv_rpc {
            let _ = req_tx.send(msg);
        }
    });

    let (event_tx, event_rx) = async_channel::unbounded();
    init_event_tx(&ctx, event_tx.clone());
    let internal = InternalImpl::new(ctx.clone(), event_rx);
    let futs = (
        rpc_loop(internal, req_rx),
        event_loop(&ctx),
        worker_loop(&ctx),
    );
    futs.race().await;
}

async fn rpc_loop(
    internal: InternalImpl,
    mut req_rx: tokio::sync::mpsc::UnboundedReceiver<(JrpcRequest, oneshot::Sender<JrpcResponse>)>,
) {
    while let Some((req, resp_tx)) = req_rx.recv().await {
        let service = crate::internal::InternalService(internal.clone());
        tokio::spawn(async move {
            let response = service.respond_raw(req).await;
            resp_tx.send(response).ok();
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
    (convo_loop(ctx), medium_key_loop(ctx)).race().await;
}
