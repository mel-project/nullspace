use std::collections::{BTreeMap, HashMap};
use std::sync::Arc;
use std::time::Duration;

use anyctx::AnyCtx;
use anyhow::Context;
use async_channel::{Receiver, Sender};
use dashmap::DashMap;
use dashmap::mapref::entry::Entry;
use futures_concurrency::future::Race;
use nullspace_structs::mailbox::{MailboxEntry, MailboxId, MailboxKey, MailboxRecvArgs};
use nullspace_structs::server::{ServerName, ServerRpcError};
use nullspace_structs::timestamp::NanoTimestamp;
use tokio::sync::oneshot;

use crate::config::{Config, Ctx};
use super::server::get_server_client;

const LONG_POLL_MIN_MS: u64 = 15_000;
const LONG_POLL_MAX_MS: u64 = 30 * 60 * 1000;
const LONG_POLL_INC_MS: u64 = 5_000;
const LONG_POLL_DEC_FACTOR: f64 = 0.5;

pub static LONG_POLLER: Ctx<Arc<LongPoller>> = |ctx| Arc::new(LongPoller::new(ctx.clone()));

pub struct LongPoller {
    ctx: AnyCtx<Config>,
    workers: DashMap<ServerName, ServerWorker>,
}

impl LongPoller {
    fn new(ctx: AnyCtx<Config>) -> Self {
        Self {
            ctx,
            workers: DashMap::new(),
        }
    }

    pub async fn recv(
        &self,
        server_name: ServerName,
        mailbox_key: MailboxKey,
        mailbox: MailboxId,
        after: NanoTimestamp,
    ) -> anyhow::Result<MailboxEntry> {
        let worker = self.worker_for_server(server_name);
        let (tx, rx) = oneshot::channel();
        let request = PollRequest {
            mailbox_key,
            mailbox,
            after,
            respond_to: tx,
        };
        worker
            .sender
            .send(request)
            .await
            .context("long poller worker closed")?;
        rx.await.context("long poller worker closed")?
    }

    fn worker_for_server(&self, server_name: ServerName) -> ServerWorker {
        match self.workers.entry(server_name.clone()) {
            Entry::Occupied(existing) => existing.get().clone(),
            Entry::Vacant(vacant) => {
                let (sender, receiver) = async_channel::unbounded();
                let worker = ServerWorker { sender };
                let task = run_server_worker(self.ctx.clone(), server_name, receiver);
                tokio::spawn(task);
                vacant.insert(worker.clone());
                worker
            }
        }
    }
}

#[derive(Clone)]
struct ServerWorker {
    sender: Sender<PollRequest>,
}

struct PollRequest {
    mailbox_key: MailboxKey,
    mailbox: MailboxId,
    after: NanoTimestamp,
    respond_to: oneshot::Sender<anyhow::Result<MailboxEntry>>,
}

async fn run_server_worker(
    ctx: AnyCtx<Config>,
    server_name: ServerName,
    receiver: Receiver<PollRequest>,
) {
    let mut pending: Vec<PollRequest> = Vec::new();
    let mut timeout_ms = LONG_POLL_MIN_MS;
    let mut server_client = None;
    loop {
        if pending.is_empty() {
            match receiver.recv().await {
                Ok(request) => {
                    pending.push(request);
                }
                Err(_) => break,
            }
            continue;
        }
        let (args, mailbox_keys) = build_args(&pending);
        let recv_fut = async {
            match receiver.recv().await {
                Ok(request) => WorkerEvent::NewRequest(request),
                Err(_) => WorkerEvent::Shutdown,
            }
        };
        let poll_fut = async {
            if server_client.is_none() {
                let client = match get_server_client(&ctx, &server_name).await {
                    Ok(client) => client,
                    Err(err) => {
                        return WorkerEvent::PollResponse(Err(err));
                    }
                };
                server_client = Some(client);
            }
            let client = server_client.clone().expect("server client set");
            let response = client
                .mailbox_multirecv(args, timeout_ms)
                .await
                .map_err(|err| anyhow::anyhow!(err.to_string()));
            WorkerEvent::PollResponse(response)
        };
        match (recv_fut, poll_fut).race().await {
            WorkerEvent::NewRequest(request) => {
                pending.push(request);
            }
            WorkerEvent::Shutdown => {
                for request in pending.drain(..) {
                    let _ = request
                        .respond_to
                        .send(Err(anyhow::anyhow!("long poller shutdown")));
                }
                break;
            }
            WorkerEvent::PollResponse(response) => {
                match &response {
                    Err(_) => {
                        server_client = None;
                        timeout_ms = aimd_decrease(timeout_ms);
                    }
                    Ok(Ok(map)) => {
                        if map.is_empty() {
                            timeout_ms = aimd_increase(timeout_ms);
                        }
                    }
                    Ok(Err(_)) => {}
                }
                if let Err(err) =
                    username_poll_response(response, &mailbox_keys, &mut pending).await
                {
                    tracing::warn!(error = %err, "long poller error");
                    tokio::time::sleep(Duration::from_secs(1)).await;
                }
            }
        }
    }
}

enum WorkerEvent {
    NewRequest(PollRequest),
    PollResponse(
        Result<Result<BTreeMap<MailboxId, Vec<MailboxEntry>>, ServerRpcError>, anyhow::Error>,
    ),
    Shutdown,
}

fn build_args(
    pending: &[PollRequest],
) -> (
    Vec<MailboxRecvArgs>,
    HashMap<(MailboxId, MailboxKey), Vec<usize>>,
) {
    let mut min_after: HashMap<(MailboxId, MailboxKey), NanoTimestamp> = HashMap::new();
    let mut indices: HashMap<(MailboxId, MailboxKey), Vec<usize>> = HashMap::new();
    for (idx, req) in pending.iter().enumerate() {
        let key = (req.mailbox, req.mailbox_key);
        indices.entry(key).or_default().push(idx);
        min_after
            .entry(key)
            .and_modify(|existing| {
                if req.after.0 < existing.0 {
                    *existing = req.after;
                }
            })
            .or_insert(req.after);
    }
    let args = min_after
        .into_iter()
        .map(|((mailbox, mailbox_key), after)| MailboxRecvArgs {
            mailbox,
            mailbox_key,
            after,
        })
        .collect();
    (args, indices)
}

async fn username_poll_response(
    response: Result<Result<BTreeMap<MailboxId, Vec<MailboxEntry>>, ServerRpcError>, anyhow::Error>,
    mailbox_keys: &HashMap<(MailboxId, MailboxKey), Vec<usize>>,
    pending: &mut Vec<PollRequest>,
) -> anyhow::Result<()> {
    let response = match response {
        Ok(response) => response,
        Err(err) => {
            return Err(err);
        }
    };
    let response = match response {
        Ok(response) => response,
        Err(err) => {
            for request in pending.drain(..) {
                let err = anyhow::anyhow!(err.to_string());
                let _ = request.respond_to.send(Err(err));
            }
            return Ok(());
        }
    };
    if response.is_empty() {
        return Ok(());
    }
    let mut still_pending = Vec::new();
    for (idx, request) in pending.drain(..).enumerate() {
        let key = (request.mailbox, request.mailbox_key);
        let Some(indices) = mailbox_keys.get(&key) else {
            still_pending.push(request);
            continue;
        };
        if !indices.contains(&idx) {
            still_pending.push(request);
            continue;
        }
        let Some(entries) = response.get(&request.mailbox) else {
            still_pending.push(request);
            continue;
        };
        let mut found = None;
        for entry in entries {
            if entry.received_at > request.after {
                found = Some(entry.clone());
                break;
            }
        }
        match found {
            Some(entry) => {
                let _ = request.respond_to.send(Ok(entry));
            }
            None => still_pending.push(request),
        }
    }
    *pending = still_pending;
    Ok(())
}

fn aimd_increase(current: u64) -> u64 {
    let next = current
        .saturating_add(LONG_POLL_INC_MS)
        .clamp(LONG_POLL_MIN_MS, LONG_POLL_MAX_MS);
    if next != current {
        tracing::debug!(old_ms = current, new_ms = next, "long poll aimd increase");
    }
    next
}

fn aimd_decrease(current: u64) -> u64 {
    let dec = (current as f64 * LONG_POLL_DEC_FACTOR) as u64;
    let next = dec.clamp(LONG_POLL_MIN_MS, LONG_POLL_MAX_MS);
    if next != current {
        tracing::debug!(old_ms = current, new_ms = next, "long poll aimd decrease");
    }
    next
}
