use std::sync::mpsc::Receiver;

use anyctx::AnyCtx;
use futures_concurrency::future::Race;
use nanorpc::{JrpcRequest, JrpcResponse, RpcService};
use tokio::sync::oneshot;

use crate::Config;
use crate::database::{DATABASE, DbNotify, event_loop, identity_exists};
use crate::dm::{recv_loop, send_loop};
use crate::groups::{group_recv_loop, group_rekey_loop, group_send_loop};

use crate::internal::InternalImpl;
use crate::medium_keys::rotation_loop;

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
    let internal = InternalImpl::new(ctx.clone(), event_rx);
    let futs = (
        rpc_loop(internal, req_rx),
        event_loop(&ctx, event_tx),
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
        match identity_exists(db).await {
            Ok(true) => break,
            Ok(false) => {}
            Err(err) => {
                tracing::warn!(error = %err, "failed to check identity state");
            }
        }
        notify.wait_for_change().await;
    }
    (
        send_loop(ctx),
        recv_loop(ctx),
        rotation_loop(ctx),
        group_send_loop(ctx),
        group_recv_loop(ctx),
        group_rekey_loop(ctx),
    )
        .race()
        .await;
}
