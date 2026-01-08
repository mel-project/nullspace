use std::time::Duration;

use nanorpc::{JrpcRequest, JrpcResponse};
use url::Url;

use crate::REQUEST_TIMEOUT_SECS;

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
        let resp = self
            .client
            .post(self.endpoint.clone())
            .json(&req)
            .send()
            .await?
            .error_for_status()?;
        Ok(resp.json::<JrpcResponse>().await?)
    }
}
