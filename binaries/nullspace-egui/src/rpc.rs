use std::sync::OnceLock;

use nullspace_client::InternalClient;

static RPC: OnceLock<InternalClient> = OnceLock::new();

pub fn init_rpc(rpc: InternalClient) {
    if RPC.set(rpc).is_err() {
        panic!("rpc already initialized");
    }
}

pub fn get_rpc() -> &'static InternalClient {
    RPC.get().expect("rpc not initialized")
}

pub fn flatten_rpc<T, E>(
    result: Result<Result<T, nullspace_client::internal::InternalRpcError>, E>,
) -> Result<T, String>
where
    E: std::fmt::Display,
{
    match result {
        Ok(Ok(value)) => Ok(value),
        Ok(Err(err)) => Err(err.to_string()),
        Err(err) => Err(err.to_string()),
    }
}
