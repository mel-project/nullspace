use std::sync::LazyLock;

use nullspace_rpc_pool::RpcPool;

pub static RPC_POOL: LazyLock<RpcPool> =
    LazyLock::new(|| RpcPool::builder().max_concurrency(1).build());
