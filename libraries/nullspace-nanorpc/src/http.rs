use std::time::Duration;

use nanorpc::{JrpcRequest, JrpcResponse};
use url::Url;

use crate::{MAX_MESSAGE_BYTES, REQUEST_TIMEOUT_SECS};

#[derive(Clone)]
pub(crate) struct HttpTransport {
    client: reqwest::Client,
    endpoint: Url,
}

impl HttpTransport {
    pub(crate) fn new(endpoint: Url) -> Self {
        Self {
            client: reqwest::ClientBuilder::new()
                .timeout(Duration::from_secs(REQUEST_TIMEOUT_SECS))
                .build()
                .unwrap(),
            endpoint,
        }
    }

    pub(crate) async fn call_raw(
        &self,
        req: JrpcRequest,
    ) -> Result<JrpcResponse, anyhow::Error> {
        let mut resp = self
            .client
            .post(self.endpoint.clone())
            .json(&req)
            .send()
            .await?
            .error_for_status()?;

        let mut body = Vec::new();
        while let Some(chunk) = resp.chunk().await? {
            if body.len() + chunk.len() > MAX_MESSAGE_BYTES {
                let remaining = MAX_MESSAGE_BYTES.saturating_sub(body.len());
                body.extend_from_slice(&chunk[..remaining]);
                break;
            }
            body.extend_from_slice(&chunk);
        }

        Ok(serde_json::from_slice::<JrpcResponse>(&body)?)
    }
}
