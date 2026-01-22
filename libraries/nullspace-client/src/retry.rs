use std::time::Duration;

pub async fn retry_backoff<T>(mut f: impl AsyncFnMut() -> anyhow::Result<T>) -> anyhow::Result<T> {
    let mut attempts: u32 = 0;
    loop {
        let res = f().await;
        match res {
            Ok(v) => return Ok(v),
            Err(err) => {
                if attempts < 7 {
                    let backoff = transient_backoff(attempts);
                    attempts = attempts.saturating_add(1);
                    tracing::warn!(
                        err = debug(&err),
                        backoff_ms = backoff.as_millis(),
                        "retrying error"
                    );
                    tokio::time::sleep(backoff).await;
                } else {
                    return Err(err);
                }
            }
        }
    }
}

fn transient_backoff(transient_attempt: u32) -> Duration {
    const BASE_MS: u64 = 25;
    const MAX_MS: u64 = 20_000;

    let shift = transient_attempt.min(62);
    let factor = 1u64.checked_shl(shift).unwrap_or(u64::MAX);
    let backoff_ms = BASE_MS.saturating_mul(factor).min(MAX_MS);
    Duration::from_millis(backoff_ms)
}

#[cfg(test)]
mod tests {
    use super::transient_backoff;
    use std::time::Duration;

    #[test]
    fn transient_backoff_doubles_and_caps() {
        assert_eq!(transient_backoff(0), Duration::from_millis(25));
        assert_eq!(transient_backoff(1), Duration::from_millis(50));
        assert_eq!(transient_backoff(2), Duration::from_millis(100));
        assert_eq!(transient_backoff(3), Duration::from_millis(200));
        assert_eq!(transient_backoff(6), Duration::from_millis(1600));
        assert_eq!(transient_backoff(7), Duration::from_millis(2000));
        assert_eq!(transient_backoff(1000), Duration::from_millis(2000));
    }
}
