use std::sync::Mutex;

use poll_promise::Promise;

pub struct PromiseSlot<T: Send + 'static> {
    inner: Mutex<Option<Promise<T>>>,
}

impl<T: Send + 'static> PromiseSlot<T> {
    pub fn new() -> Self {
        Self {
            inner: Mutex::new(None),
        }
    }

    pub fn start(&self, promise: Promise<T>) -> bool {
        let Ok(mut guard) = self.inner.lock() else {
            return false;
        };
        if guard.is_some() {
            return false;
        }
        *guard = Some(promise);
        true
    }

    pub fn poll(&self) -> Option<T> {
        let Ok(mut guard) = self.inner.lock() else {
            return None;
        };
        let promise = guard.take()?;
        match promise.try_take() {
            Ok(value) => Some(value),
            Err(promise) => {
                *guard = Some(promise);
                None
            }
        }
    }

    pub fn is_running(&self) -> bool {
        let Ok(guard) = self.inner.lock() else {
            return false;
        };
        guard.is_some()
    }
}

pub fn flatten_rpc<T, E>(
    result: Result<Result<T, xirtam_client::internal::InternalRpcError>, E>,
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
