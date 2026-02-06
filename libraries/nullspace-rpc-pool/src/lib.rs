use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};

use async_trait::async_trait;
use moka::future::Cache;
use nanorpc::{JrpcRequest, JrpcResponse, RpcTransport};
use nullspace_nanorpc::Transport;
use url::Url;

#[derive(Clone)]
pub struct RpcPool {
    inner: Arc<RpcPoolInner>,
}

pub struct RpcPoolBuilder {
    max_concurrency: usize,
}

struct RpcPoolInner {
    max_concurrency: usize,
    pools: Cache<Url, Arc<PerUrlPool>>,
}

struct PerUrlPool {
    url: Url,
    max_concurrency: usize,
    next_index: AtomicUsize,
    transports: Mutex<Vec<Option<Arc<Transport>>>>,
}

#[derive(Clone)]
pub struct PooledTransport {
    pool: RpcPool,
    url: Url,
}

impl RpcPool {
    pub fn new() -> Self {
        RpcPoolBuilder::new().build()
    }

    pub fn builder() -> RpcPoolBuilder {
        RpcPoolBuilder::new()
    }

    pub fn rpc(&self, url: Url) -> PooledTransport {
        PooledTransport {
            pool: self.clone(),
            url,
        }
    }

    async fn call_raw(&self, url: Url, req: JrpcRequest) -> Result<JrpcResponse, anyhow::Error> {
        let max_concurrency = self.inner.max_concurrency;
        let pool = self
            .inner
            .pools
            .get_with(url.clone(), async move {
                Arc::new(PerUrlPool::new(url, max_concurrency))
            })
            .await;
        pool.call_raw(req).await
    }
}

impl Default for RpcPool {
    fn default() -> Self {
        Self::new()
    }
}

impl RpcPoolBuilder {
    pub fn new() -> Self {
        Self { max_concurrency: 1 }
    }

    pub fn max_concurrency(mut self, max_concurrency: usize) -> Self {
        self.max_concurrency = max_concurrency;
        self
    }

    pub fn build(self) -> RpcPool {
        assert!(
            self.max_concurrency > 0,
            "max_concurrency must be greater than 0"
        );
        RpcPool {
            inner: Arc::new(RpcPoolInner {
                max_concurrency: self.max_concurrency,
                pools: Cache::builder().build(),
            }),
        }
    }
}

impl Default for RpcPoolBuilder {
    fn default() -> Self {
        Self::new()
    }
}

impl PerUrlPool {
    fn new(url: Url, max_concurrency: usize) -> Self {
        Self {
            url,
            max_concurrency,
            next_index: AtomicUsize::new(0),
            transports: Mutex::new(Vec::new()),
        }
    }

    async fn call_raw(&self, req: JrpcRequest) -> Result<JrpcResponse, anyhow::Error> {
        let index = self
            .next_index
            .fetch_add(1, Ordering::Relaxed)
            % self.max_concurrency;
        let transport = self.get_or_init_transport(index);
        let result = transport.call_raw(req).await;
        if result.is_err() {
            self.drop_transport(&transport);
        }
        result
    }

    fn get_or_init_transport(&self, index: usize) -> Arc<Transport> {
        let mut transports = self
            .transports
            .lock()
            .expect("rpc pool transport lock poisoned");
        if transports.len() <= index {
            transports.resize_with(index + 1, || None);
        }
        if let Some(existing) = transports[index].as_ref() {
            return existing.clone();
        }
        let transport = Arc::new(Transport::new(self.url.clone()));
        transports[index] = Some(transport.clone());
        transport
    }

    fn drop_transport(&self, target: &Arc<Transport>) {
        let mut transports = self
            .transports
            .lock()
            .expect("rpc pool transport lock poisoned");
        for slot in transports.iter_mut() {
            if let Some(existing) = slot.as_ref()
                && Arc::ptr_eq(existing, target) {
                    *slot = None;
                }
        }
    }
}

#[async_trait]
impl RpcTransport for PooledTransport {
    type Error = anyhow::Error;

    async fn call_raw(&self, req: JrpcRequest) -> Result<JrpcResponse, Self::Error> {
        self.pool.call_raw(self.url.clone(), req).await
    }
}
