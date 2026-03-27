# nullspace-dirclient

nullspace-dirclient provides a small, opinionated client for the Nullspace directory RPC. It caches headers locally and verifies SMT proofs against the signed trust anchor.

Here is a minimal example that constructs a client and fetches a listing:

```rust,no_run
use nanorpc::RpcTransport;
use sqlx::SqlitePool;
use nullspace_crypt::signing::SigningPublic;
use nullspace_dirclient::DirClient;

async fn fetch_listing<T>(
    transport: T,
    anchor_pk: SigningPublic,
    pool: SqlitePool,
) -> anyhow::Result<()>
where
    T: RpcTransport,
    T::Error: Into<anyhow::Error>,
{
    let client = DirClient::new(transport, anchor_pk, pool).await?;
    let listing = client.query_raw("example-key").await?;
    println!("present: {}", listing.is_some());
    Ok(())
}
```
