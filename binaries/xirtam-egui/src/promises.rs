use std::sync::{Arc, Mutex};

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
        let Some(promise) = guard.take() else {
            return None;
        };
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

pub struct AsyncMemo<T: Send + 'static> {
    promise: Arc<Mutex<Option<Promise<T>>>>,
    value: Arc<Mutex<Option<Arc<T>>>>,
}

impl<T: Send + 'static> Clone for AsyncMemo<T> {
    fn clone(&self) -> Self {
        Self {
            promise: self.promise.clone(),
            value: self.value.clone(),
        }
    }
}

impl<T: Send + 'static> AsyncMemo<T> {
    pub fn spawn_async<Fut>(fut: Fut) -> Self
    where
        Fut: std::future::Future<Output = T> + Send + 'static,
    {
        Self {
            promise: Arc::new(Mutex::new(Some(Promise::spawn_async(fut)))),
            value: Arc::new(Mutex::new(None)),
        }
    }

    pub fn spawn_async_with<C, F, Fut>(ctx: C, f: F) -> Self
    where
        C: Send + 'static,
        F: FnOnce(C) -> Fut + Send + 'static,
        Fut: std::future::Future<Output = T> + Send + 'static,
    {
        Self::spawn_async(f(ctx))
    }

    pub fn poll(&self) -> std::task::Poll<Arc<T>> {
        if let Ok(guard) = self.value.lock() {
            if let Some(value) = guard.as_ref() {
                return std::task::Poll::Ready(value.clone());
            }
        }

        let Ok(mut promise_guard) = self.promise.lock() else {
            return std::task::Poll::Pending;
        };
        let Some(promise) = promise_guard.take() else {
            return std::task::Poll::Pending;
        };
        match promise.try_take() {
            Ok(value) => {
                let value = Arc::new(value);
                if let Ok(mut guard) = self.value.lock() {
                    *guard = Some(value.clone());
                }
                std::task::Poll::Ready(value)
            }
            Err(promise) => {
                *promise_guard = Some(promise);
                std::task::Poll::Pending
            }
        }
    }
}
