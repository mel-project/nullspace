use std::collections::{BTreeMap, HashMap};
use std::sync::Arc;
use std::time::Duration;

use anyhow::Context;
use async_channel::{Receiver, Sender};
use dashmap::DashMap;
use futures_concurrency::future::Race;
use tokio::sync::oneshot;
use xirtam_structs::server::{
    AuthToken, ServerClient, ServerError, MailboxEntry, MailboxId, MailboxRecvArgs,
};
use xirtam_structs::timestamp::NanoTimestamp;

use crate::config::Ctx;

const LONG_POLL_MIN_MS: u64 = 15_000;
const LONG_POLL_MAX_MS: u64 = 30 * 60 * 1000;
const LONG_POLL_INC_MS: u64 = 5_000;
const LONG_POLL_DEC_FACTOR: f64 = 0.5;

pub static LONG_POLLER: Ctx<Arc<LongPoller>> = |_ctx| Arc::new(LongPoller::new());

pub struct LongPoller {
    workers: DashMap<usize, ServerWorker>,
}

impl LongPoller {
    pub fn new() -> Self {
        Self {
            workers: DashMap::new(),
        }
    }

    pub async fn recv(
        &self,
        server: Arc<ServerClient>,
        auth: AuthToken,
        mailbox: MailboxId,
        after: NanoTimestamp,
    ) -> anyhow::Result<MailboxEntry> {
        let worker = self.worker_for_server(server);
        let (tx, rx) = oneshot::channel();
        let request = PollRequest {
            auth,
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

    fn worker_for_server(&self, server: Arc<ServerClient>) -> ServerWorker {
        let key = Arc::as_ptr(&server) as usize;
        if let Some(existing) = self.workers.get(&key) {
            return existing.clone();
        }
        let (sender, receiver) = async_channel::unbounded();
        let worker = ServerWorker { sender };
        let task = run_server_worker(server, receiver);
        tokio::spawn(task);
        self.workers.insert(key, worker.clone());
        worker
    }
}

#[derive(Clone)]
struct ServerWorker {
    sender: Sender<PollRequest>,
}

struct PollRequest {
    auth: AuthToken,
    mailbox: MailboxId,
    after: NanoTimestamp,
    respond_to: oneshot::Sender<anyhow::Result<MailboxEntry>>,
}

async fn run_server_worker(server: Arc<ServerClient>, receiver: Receiver<PollRequest>) {
    let mut pending: Vec<PollRequest> = Vec::new();
    let mut timeout_ms = LONG_POLL_MIN_MS;
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
            let response = server
                .v1_mailbox_multirecv(args, timeout_ms)
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
                        timeout_ms = aimd_decrease(timeout_ms);
                    }
                    Ok(Ok(map)) => {
                        if map.is_empty() {
                            timeout_ms = aimd_increase(timeout_ms);
                        }
                    }
                    Ok(Err(_)) => {}
                }
                if let Err(err) = username_poll_response(response, &mailbox_keys, &mut pending).await
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
        Result<Result<BTreeMap<MailboxId, Vec<MailboxEntry>>, ServerError>, anyhow::Error>,
    ),
    Shutdown,
}

fn build_args(
    pending: &[PollRequest],
) -> (
    Vec<MailboxRecvArgs>,
    HashMap<(MailboxId, AuthToken), Vec<usize>>,
) {
    let mut min_after: HashMap<(MailboxId, AuthToken), NanoTimestamp> = HashMap::new();
    let mut indices: HashMap<(MailboxId, AuthToken), Vec<usize>> = HashMap::new();
    for (idx, req) in pending.iter().enumerate() {
        let key = (req.mailbox, req.auth);
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
        .map(|((mailbox, auth), after)| MailboxRecvArgs {
            auth,
            mailbox,
            after,
        })
        .collect();
    (args, indices)
}

async fn username_poll_response(
    response: Result<
        Result<BTreeMap<MailboxId, Vec<MailboxEntry>>, ServerError>,
        anyhow::Error,
    >,
    mailbox_keys: &HashMap<(MailboxId, AuthToken), Vec<usize>>,
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
        let key = (request.mailbox, request.auth);
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
