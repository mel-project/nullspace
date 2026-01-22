use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, LazyLock};
use std::time::Duration;

use anyhow::Context;
use async_trait::async_trait;
use moka::future::Cache;
use nanorpc::{JrpcRequest, JrpcResponse, RpcTransport};
use nullspace_dirclient::DirClient;
use nullspace_nanorpc::Transport;
use nullspace_structs::server::{AuthToken, ProxyError, ServerClient, ServerName};

use crate::config::Config;
use crate::database::DATABASE;
use crate::identity::Identity;

static SERVER_CACHE: LazyLock<Cache<ServerName, Arc<ServerClient>>> = LazyLock::new(|| {
    Cache::builder()
        .time_to_idle(Duration::from_secs(3600))
        .build()
});

pub async fn get_server_client(
    ctx: &anyctx::AnyCtx<Config>,
    name: &ServerName,
) -> anyhow::Result<Arc<ServerClient>> {
    SERVER_CACHE
        .try_get_with(name.clone(), async {
            let transport = Transport::new(ctx.init().dir_endpoint.clone());
            let dir = DirClient::new(
                transport,
                ctx.init().dir_anchor_pk,
                ctx.get(DATABASE).clone(),
            )
            .await?;
            let identity = Identity::load(ctx.get(DATABASE)).await.ok();
            let own_server_name = identity
                .as_ref()
                .and_then(|identity| identity.server_name.clone());
            let proxy_info =
                if let (Some(identity), Some(own_server_name)) = (identity, own_server_name) {
                    if &own_server_name == name {
                        None
                    } else {
                        let descriptor = dir
                            .get_server_descriptor(&own_server_name)
                            .await?
                            .context("server not in directory")?;
                        let endpoint = descriptor
                            .public_urls
                            .first()
                            .cloned()
                            .context("server has no public URLs")?;
                        let proxy_client = Arc::new(ServerClient::from(Transport::new(endpoint)));
                        let auth_token = proxy_client
                            .v1_device_auth(identity.username, identity.cert_chain)
                            .await?
                            .map_err(|err| anyhow::anyhow!(err.to_string()))?;
                        Some(ProxyInfo {
                            own_server_name,
                            proxy_client,
                            auth_token,
                        })
                    }
                } else {
                    None
                };
            let descriptor = dir
                .get_server_descriptor(name)
                .await?
                .context("server not in directory")?;
            let endpoint = descriptor
                .public_urls
                .first()
                .cloned()
                .context("server has no public URLs")?;
            Ok(Arc::new(ServerClient::from(ProxyingTransport::new(
                name.clone(),
                endpoint,
                proxy_info,
            ))))
        })
        .await
        .map_err(|err: Arc<anyhow::Error>| anyhow::anyhow!(err.to_string()))
}

#[derive(Clone)]
struct ProxyingTransport {
    inner: Arc<ProxyingTransportInner>,
}

struct ProxyingTransportInner {
    target_name: ServerName,
    target_transport: Transport,
    proxy_unsupported: AtomicBool,
    proxy_info: Option<ProxyInfo>,
}

struct ProxyInfo {
    own_server_name: ServerName,
    proxy_client: Arc<ServerClient>,
    auth_token: AuthToken,
}

impl ProxyingTransport {
    fn new(target_name: ServerName, endpoint: url::Url, proxy_info: Option<ProxyInfo>) -> Self {
        Self {
            inner: Arc::new(ProxyingTransportInner {
                target_name,
                target_transport: Transport::new(endpoint),
                proxy_unsupported: AtomicBool::new(proxy_info.is_none()),
                proxy_info,
            }),
        }
    }
}

#[async_trait]
impl RpcTransport for ProxyingTransport {
    type Error = anyhow::Error;

    async fn call_raw(&self, req: JrpcRequest) -> Result<JrpcResponse, Self::Error> {
        let inner = &self.inner;
        if inner.proxy_unsupported.load(Ordering::Relaxed) {
            return inner.target_transport.call_raw(req).await;
        }
        let Some(proxy_info) = &inner.proxy_info else {
            return inner.target_transport.call_raw(req).await;
        };
        if proxy_info.own_server_name == inner.target_name {
            return inner.target_transport.call_raw(req).await;
        }
        let req_direct = req.clone();
        let proxied = proxy_info
            .proxy_client
            .v1_proxy_server(proxy_info.auth_token, inner.target_name.clone(), req)
            .await?;
        match proxied {
            Ok(response) => Ok(response),
            Err(ProxyError::NotSupported) => {
                inner.proxy_unsupported.store(true, Ordering::Relaxed);
                tracing::warn!(
                    target = %inner.target_name,
                    "proxy unsupported, switching direct connection"
                );
                inner.target_transport.call_raw(req_direct).await
            }
            Err(ProxyError::Upstream(err)) => Err(anyhow::anyhow!(err)),
        }
    }
}
